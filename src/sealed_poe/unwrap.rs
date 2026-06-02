//! Multi-recipient sealed-PoE unwrap: age-style trial-decrypt with
//! constant-time-per-slot scanning, a constant-time `slots_mac` binding, and
//! partitioning-oracle length pre-checks.
//!
//! Three caller forms, with exactly one selection:
//!
//! - **single-priv** ([`UnwrapKeys::Single`]) — the standalone-verifier path;
//!   runs the trial-decrypt loop over the slots once.
//! - **multi-priv** ([`UnwrapKeys::Multi`]) — a rotated identity holding
//!   `[current, …archived]`. The outer loop iterates private keys (newest
//!   first, the caller's ordering); the inner loop iterates slots.
//! - **bundle** ([`UnwrapKeys::Bundle`]) — the whole identity key bundle
//!   (both KEMs' secret lists). The dispatch selects the correct list from the
//!   envelope's `kem`, then runs the identical multi-priv loop.
//!
//! Constant-time-N (default `true`) applies PER private key: every slot is
//! entered regardless of where the match lands, so the inner loop's timing does
//! not leak the matched slot index. The outer loop short-circuits on the first
//! private key whose recovered CEK also passes the `slots_mac` check — this
//! intentionally leaks "which private key matched" (≈ how many rotations the
//! recipient has performed), a weak, locally-observable ordering signal that is
//! not a key or plaintext oracle.
//!
//! Both KEM branches share this control flow; only the per-slot recovery body
//! differs (X25519 ECDH vs. X-Wing decapsulation).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::kdf::hkdf_sha256;

use super::aead::xchacha20_poly1305_decrypt;
use super::errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
use super::kem::{
    mlkem768x25519_decapsulate, x25519_ecdh, x25519_public_key, KemError, MLKEM768X25519_ENC_LENGTH,
};
use super::slots::{
    join_kem_ct, slots_to_mac_cbor, Mlkem768X25519Slot, SealedEnvelope, SealedSlots, X25519Slot,
    AEAD_XCHACHA20_POLY1305, KEM_MLKEM768X25519, KEM_X25519,
};
use super::wrap::{
    CARDANO_POE_HKDF_INFO_KEK, CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
    CARDANO_POE_HKDF_INFO_SLOTS_MAC,
};

use super::aead::chacha20_poly1305_decrypt;

const ZERO_NONCE_12: [u8; 12] = [0u8; 12];
const X25519_SECRET_KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 24;
const WRAP_LENGTH: usize = 48;
const SLOTS_MAC_LENGTH: usize = 32;

/// Why a sealed-PoE unwrap did not recover the plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwrapFailureReason {
    /// No private key recovered a CEK from any slot — the recipient is not
    /// addressed by this envelope.
    WrongRecipientKey,
    /// A CEK was recovered but the recomputed `slots_mac` did not match: the
    /// on-chain slot set was tampered with.
    TamperedHeader,
    /// The CEK and `slots_mac` verified, but the content AEAD failed: the
    /// off-chain ciphertext was tampered with.
    TamperedCiphertext,
}

impl UnwrapFailureReason {
    /// The stable wire string for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            UnwrapFailureReason::WrongRecipientKey => "WRONG_RECIPIENT_KEY",
            UnwrapFailureReason::TamperedHeader => "TAMPERED_HEADER",
            UnwrapFailureReason::TamperedCiphertext => "TAMPERED_CIPHERTEXT",
        }
    }
}

/// The outcome of [`ecies_sealed_poe_unwrap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwrapResult {
    /// The plaintext was recovered.
    Matched {
        /// The recovered plaintext.
        plaintext: Vec<u8>,
    },
    /// No plaintext was recovered; `reason` says why.
    NotMatched {
        /// The failure reason.
        reason: UnwrapFailureReason,
    },
}

impl UnwrapResult {
    /// Whether the unwrap recovered a plaintext.
    #[must_use]
    pub fn matched(&self) -> bool {
        matches!(self, UnwrapResult::Matched { .. })
    }
}

/// A recipient's unified key bundle.
///
/// A read-path consumer holds BOTH the X25519 private-key chain (current plus
/// archived, for the classical KEM and rotation history) AND the X-Wing secret
/// seeds (for the hybrid KEM), without knowing which a given record was sealed
/// under. The dispatch picks the right list from the envelope's `kem`:
///
/// - `x25519` → [`x25519_private_keys`](Self::x25519_private_keys)
/// - `mlkem768x25519` → [`mlkem768x25519_secret_seeds`](Self::mlkem768x25519_secret_seeds)
///
/// Both lists are ordered newest-first (the caller's responsibility — the outer
/// trial-decrypt loop scans them in order). Either list MAY be empty when the
/// recipient holds no key for that KEM; a bundle whose selected list is empty
/// is a clean non-match without touching any KEM primitive.
#[derive(Debug, Clone, Default)]
pub struct RecipientKeyBundle {
    /// X25519 private keys, newest first.
    pub x25519_private_keys: Vec<Vec<u8>>,
    /// X-Wing secret seeds, newest first.
    pub mlkem768x25519_secret_seeds: Vec<Vec<u8>>,
}

/// The recipient-key selection for an unwrap.
///
/// Exactly one of the three forms is supplied. The bundle form resolves to a
/// flat list by dispatching on the envelope's `kem`; from there the loop is
/// identical to the multi-priv form.
pub enum UnwrapKeys<'a> {
    /// A single recipient secret key.
    Single(&'a [u8]),
    /// A flat, KEM-pre-selected list of secret keys (newest first).
    Multi(&'a [Vec<u8>]),
    /// A whole key bundle; the KEM list is dispatched from the envelope.
    Bundle(&'a RecipientKeyBundle),
}

/// Test-only instrumentation for the constant-time-N invariants.
///
/// `inner.count` tracks the inner-loop iterations entered for the current
/// private key; in the multi-priv path it is reset at the start of each outer
/// iteration and, after that key's inner loop completes, appended to
/// `inner.per_priv_counts`. `outer.count` is bumped to `k + 1` at the start of
/// each outer iteration. Production callers never construct one.
#[derive(Debug, Default, Clone)]
pub struct UnwrapProbe {
    /// Per-private-key inner-loop accounting.
    pub inner: SlotsAttempted,
    /// Outer-loop (private-key) accounting.
    pub outer: PrivsAttempted,
}

/// Inner-loop (per-slot) iteration accounting for [`UnwrapProbe`].
#[derive(Debug, Default, Clone)]
pub struct SlotsAttempted {
    /// Slots entered for the current private key.
    pub count: usize,
    /// One entry per private key entered: its final inner-loop count.
    pub per_priv_counts: Vec<usize>,
}

/// Outer-loop (private-key) iteration accounting for [`UnwrapProbe`].
#[derive(Debug, Default, Clone)]
pub struct PrivsAttempted {
    /// The highest outer-loop index entered, as `k + 1`.
    pub count: usize,
}

/// The outcome of [`ecies_sealed_poe_trial_decrypt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrialDecryptResult {
    /// A slot opened and its CEK passed the `slots_mac` check.
    Match {
        /// The index of the slot that recovered the CEK.
        slot_idx: usize,
        /// The recovered 32-byte content-encryption key.
        cek: Vec<u8>,
    },
    /// No slot opened under any private key.
    NoAeadPass,
    /// A slot opened but its CEK failed the `slots_mac` check.
    AeadPassNoMacMatch,
}

/// Select the secret-key list a bundle contributes for the envelope's KEM.
fn select_bundle_secrets<'a>(
    envelope: &SealedEnvelope,
    bundle: &'a RecipientKeyBundle,
) -> &'a [Vec<u8>] {
    if envelope.kem == KEM_X25519 {
        &bundle.x25519_private_keys
    } else {
        &bundle.mlkem768x25519_secret_seeds
    }
}

/// Validate every wire length BEFORE any KEM/AEAD primitive runs, so a
/// malformed record cannot probe per-slot failure ordering (a partitioning
/// oracle). For the hybrid branch this reassembles each slot's `kem_ct` and
/// asserts the flat enc length before any decapsulation. Shared by the unwrap
/// and trial-decrypt paths to guarantee byte-identical pre-trial behaviour.
fn assert_envelope_structure(
    envelope: &SealedEnvelope,
    multi_priv_keys: Option<&[Vec<u8>]>,
    single_priv_key: Option<&[u8]>,
) -> Result<(), EciesSealedPoeError> {
    if envelope.scheme != 1 {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::UnsupportedEncVersion,
            format!(
                "envelope.scheme={} unsupported (expected 1)",
                envelope.scheme
            ),
        ));
    }
    if envelope.aead != AEAD_XCHACHA20_POLY1305 {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::UnsupportedAeadAlg,
            format!(
                "envelope.aead={} unsupported (expected '{AEAD_XCHACHA20_POLY1305}')",
                envelope.aead
            ),
        ));
    }
    if envelope.kem != KEM_X25519 && envelope.kem != KEM_MLKEM768X25519 {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::UnsupportedKemAlg,
            format!(
                "envelope.kem={} unsupported (expected '{KEM_X25519}' or '{KEM_MLKEM768X25519}')",
                envelope.kem
            ),
        ));
    }

    let n = envelope.slots.len();
    if n < 1 {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncSlotsEmpty,
            format!("envelope.slots.len()={n} must be >= 1"),
        ));
    }
    if envelope.nonce.len() != NONCE_LENGTH {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::NonceLengthMismatch,
            format!(
                "envelope.nonce MUST be exactly {NONCE_LENGTH} bytes, got {}",
                envelope.nonce.len()
            ),
        ));
    }
    if envelope.slots_mac.len() != SLOTS_MAC_LENGTH {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncSlotsMacInvalidLength,
            format!(
                "envelope.slots_mac MUST be exactly {SLOTS_MAC_LENGTH} bytes, got {}",
                envelope.slots_mac.len()
            ),
        ));
    }

    // Per-slot length pre-checks — KEM-driven. The envelope's `kem` string is
    // validated above; the slot variant always matches the chosen KEM because
    // it can only be built that way (parsing routes on the same `kem`).
    match &envelope.slots {
        SealedSlots::X25519(slots) => {
            for (i, slot) in slots.iter().enumerate() {
                if slot.epk.len() != X25519_SECRET_KEY_LENGTH {
                    return Err(EciesSealedPoeError::new(
                        EciesSealedPoeErrorCode::KemEpkLengthMismatch,
                        format!(
                            "envelope.slots[{i}].epk MUST be exactly {X25519_SECRET_KEY_LENGTH} bytes, got {}",
                            slot.epk.len()
                        ),
                    ));
                }
                if slot.wrap.len() != WRAP_LENGTH {
                    return Err(wrap_length_error(i, slot.wrap.len()));
                }
            }
        }
        SealedSlots::Mlkem768X25519(slots) => {
            for (i, slot) in slots.iter().enumerate() {
                let enc = join_kem_ct(&slot.kem_ct);
                if enc.len() != MLKEM768X25519_ENC_LENGTH {
                    return Err(EciesSealedPoeError::new(
                        EciesSealedPoeErrorCode::KemCtLengthMismatch,
                        format!(
                            "envelope.slots[{i}].kem_ct MUST reassemble to exactly {MLKEM768X25519_ENC_LENGTH} bytes, got {}",
                            enc.len()
                        ),
                    ));
                }
                if slot.wrap.len() != WRAP_LENGTH {
                    return Err(wrap_length_error(i, slot.wrap.len()));
                }
            }
        }
    }

    if let Some(keys) = multi_priv_keys {
        for (i, key) in keys.iter().enumerate() {
            if key.len() != X25519_SECRET_KEY_LENGTH {
                return Err(EciesSealedPoeError::new(
                    EciesSealedPoeErrorCode::InvalidRecipientKey,
                    format!(
                        "recipient_secret_keys[{i}] MUST be exactly {X25519_SECRET_KEY_LENGTH} bytes, got {}",
                        key.len()
                    ),
                ));
            }
        }
    } else if let Some(key) = single_priv_key {
        if key.len() != X25519_SECRET_KEY_LENGTH {
            return Err(EciesSealedPoeError::new(
                EciesSealedPoeErrorCode::InvalidRecipientKey,
                format!(
                    "recipient_secret_key MUST be exactly {X25519_SECRET_KEY_LENGTH} bytes, got {}",
                    key.len()
                ),
            ));
        }
    }

    Ok(())
}

fn wrap_length_error(slot_idx: usize, got: usize) -> EciesSealedPoeError {
    EciesSealedPoeError::new(
        EciesSealedPoeErrorCode::WrapLengthMismatch,
        format!("envelope.slots[{slot_idx}].wrap MUST be exactly {WRAP_LENGTH} bytes, got {got}"),
    )
}

/// Classical (x25519) per-slot recovery. Returns the CEK on the first AEAD-tag
/// success; `None` otherwise. `live_slot` distinguishes the real-work path
/// (attempt the AEAD unwrap) from the constant-time-N dummy path (do the ECDH +
/// HKDF but skip the AEAD, since a CEK is already in hand). A low-order epk is
/// an RFC 7748 §6.1 rejection handled as a non-match, never a crash.
fn try_x25519_slot(
    slot: &X25519Slot,
    recipient_secret_key: &[u8],
    pub_r_local: &[u8],
    live_slot: bool,
) -> Option<Vec<u8>> {
    // A small-order epk drives the X25519 shared secret to all zeros, which the
    // KEM rejects. Such a slot could never have been produced by a conformant
    // wrap for this recipient, so it is a non-match — skip it, keeping the loop
    // shape intact for constant-time-N.
    let shared = match x25519_ecdh(recipient_secret_key, &slot.epk) {
        Ok(s) => s,
        Err(KemError::X25519LowOrderPoint) => return None,
        // The recipient key and epk lengths are guaranteed valid upstream, so
        // no other KEM error is reachable here.
        Err(_) => return None,
    };
    let mut salt = Vec::with_capacity(slot.epk.len() + pub_r_local.len());
    salt.extend_from_slice(&slot.epk);
    salt.extend_from_slice(pub_r_local);
    let mut kek = hkdf_sha256(&shared, &salt, CARDANO_POE_HKDF_INFO_KEK, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");

    if !live_slot {
        // Dummy path: the ECDH + HKDF cost is paid above; skip only the AEAD.
        kek.zeroize();
        return None;
    }
    let result =
        chacha20_poly1305_decrypt(&kek, &ZERO_NONCE_12, CARDANO_POE_HKDF_INFO_KEK, &slot.wrap).ok();
    kek.zeroize();
    result
}

/// Hybrid (mlkem768x25519) per-slot recovery. X-Wing decapsulation never throws
/// on attacker wire data (ML-KEM implicit rejection), so a wrong shared secret
/// simply yields a KEK that fails the AEAD tag. The dummy path runs the full
/// decapsulate + HKDF so matching and non-matching slots cost the same.
fn try_mlkem768x25519_slot(
    slot: &Mlkem768X25519Slot,
    recipient_secret_seed: &[u8],
    live_slot: bool,
) -> Option<Vec<u8>> {
    // kem_ct length was validated to reassemble to the enc length upstream, so
    // join + decapsulate is constant-work.
    let enc = join_kem_ct(&slot.kem_ct);
    let mut ss = mlkem768x25519_decapsulate(recipient_secret_seed, &enc)
        .expect("kem_ct reassembles to the validated enc length and the seed length is checked");
    let mut kek = hkdf_sha256(&ss, &[], CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    ss.zeroize();
    if !live_slot {
        kek.zeroize();
        return None;
    }
    let result = chacha20_poly1305_decrypt(
        &kek,
        &ZERO_NONCE_12,
        CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
        &slot.wrap,
    )
    .ok();
    kek.zeroize();
    result
}

/// Per-private-key inner trial-decrypt loop, KEM-driven, with slot-index
/// reporting. Enters every slot when `constant_time_n`; the dummy path keeps
/// per-iteration cost uniform regardless of which slot matched.
fn try_recipient_unwrap_with_idx(
    envelope: &SealedEnvelope,
    recipient_secret_key: &[u8],
    constant_time_n: bool,
    probe: Option<&mut SlotsAttempted>,
) -> Option<(Vec<u8>, usize)> {
    let mut cek: Option<Vec<u8>> = None;
    let mut matched_slot_idx = 0usize;
    let mut slots_count = 0usize;

    match &envelope.slots {
        SealedSlots::X25519(slots) => {
            let pub_r_local =
                x25519_public_key(recipient_secret_key).expect("recipient key length checked");
            for (i, slot) in slots.iter().enumerate() {
                slots_count = i + 1;
                let candidate =
                    try_x25519_slot(slot, recipient_secret_key, &pub_r_local, cek.is_none());
                if cek.is_none() {
                    if let Some(c) = candidate {
                        cek = Some(c);
                        matched_slot_idx = i;
                    }
                }
                if cek.is_some() && !constant_time_n {
                    break;
                }
            }
        }
        SealedSlots::Mlkem768X25519(slots) => {
            for (i, slot) in slots.iter().enumerate() {
                slots_count = i + 1;
                let candidate = try_mlkem768x25519_slot(slot, recipient_secret_key, cek.is_none());
                if cek.is_none() {
                    if let Some(c) = candidate {
                        cek = Some(c);
                        matched_slot_idx = i;
                    }
                }
                if cek.is_some() && !constant_time_n {
                    break;
                }
            }
        }
    }

    if let Some(p) = probe {
        p.count = slots_count;
    }
    cek.map(|c| (c, matched_slot_idx))
}

/// Recompute the `slots_mac` HMAC for a candidate CEK and compare it constant-time.
fn slots_mac_matches(cek: &[u8], slots_cbor: &[u8], expected: &[u8]) -> bool {
    let mut hmac_key = hkdf_sha256(cek, &[], CARDANO_POE_HKDF_INFO_SLOTS_MAC, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(&hmac_key).expect("HMAC accepts a key of any length");
    mac.update(slots_cbor);
    let calc = mac.finalize().into_bytes();
    hmac_key.zeroize();
    calc.ct_eq(expected).into()
}

/// Recover the plaintext from a sealed envelope and its content ciphertext.
///
/// Trial-decrypts each slot under the supplied key(s) until one yields a CEK
/// that also passes the `slots_mac` check, then decrypts the content (AAD =
/// `nonce ‖ slots_mac`). Returns [`UnwrapResult::Matched`] with the plaintext,
/// or [`UnwrapResult::NotMatched`] with the failure reason — a wrong recipient
/// key, a tampered header, or a tampered ciphertext are all structured results,
/// never errors.
///
/// # Errors
///
/// Returns an [`EciesSealedPoeError`] only for malformed input: an unsupported
/// algorithm, a wrong-length wire field (partitioning-oracle pre-check), a
/// wrong-length recipient key, or an empty flat multi-priv list.
pub fn ecies_sealed_poe_unwrap(
    envelope: &SealedEnvelope,
    ciphertext: &[u8],
    keys: UnwrapKeys<'_>,
    constant_time_n: bool,
    mut probe: Option<&mut UnwrapProbe>,
) -> Result<UnwrapResult, EciesSealedPoeError> {
    // Resolve the caller form to either a single key or a flat multi-priv list.
    // `is_bundle` distinguishes an empty bundle (a clean non-match) from an
    // empty flat list (a programmer error).
    let mut single: Option<&[u8]> = None;
    let mut multi: Option<&[Vec<u8>]> = None;
    let mut is_bundle = false;
    match keys {
        UnwrapKeys::Single(k) => single = Some(k),
        UnwrapKeys::Multi(list) => multi = Some(list),
        UnwrapKeys::Bundle(bundle) => {
            multi = Some(select_bundle_secrets(envelope, bundle));
            is_bundle = true;
        }
    }

    // A bundle whose selected list is empty is a legitimate non-match (the
    // recipient holds no key of the matching kind), not a malformed call. The
    // flat multi-priv form keeps the "empty array is a programmer error"
    // contract its low-level callers rely on.
    if let Some(list) = multi {
        if list.is_empty() {
            if is_bundle {
                return Ok(UnwrapResult::NotMatched {
                    reason: UnwrapFailureReason::WrongRecipientKey,
                });
            }
            return Err(EciesSealedPoeError::new(
                EciesSealedPoeErrorCode::InvalidRecipientKey,
                "recipient_secret_keys MUST be a non-empty list, got length 0",
            ));
        }
    }

    assert_envelope_structure(envelope, multi, single)?;

    let slots_cbor = slots_to_mac_cbor(&envelope.slots);
    let mut matched_cek: Option<Vec<u8>> = None;

    if let Some(recipient_secret_key) = single {
        let mut slots_attempted = SlotsAttempted::default();
        let candidate = try_recipient_unwrap_with_idx(
            envelope,
            recipient_secret_key,
            constant_time_n,
            Some(&mut slots_attempted),
        );
        if let Some(p) = probe.as_deref_mut() {
            p.inner.count = slots_attempted.count;
        }
        match candidate {
            None => {
                return Ok(UnwrapResult::NotMatched {
                    reason: UnwrapFailureReason::WrongRecipientKey,
                });
            }
            Some((cek, _)) => {
                if !slots_mac_matches(&cek, &slots_cbor, &envelope.slots_mac) {
                    return Ok(UnwrapResult::NotMatched {
                        reason: UnwrapFailureReason::TamperedHeader,
                    });
                }
                matched_cek = Some(cek);
            }
        }
    } else {
        let keys = multi.expect("exactly one of single/multi is set");
        let mut any_candidate_recovered = false;
        for (k, key) in keys.iter().enumerate() {
            if let Some(p) = probe.as_deref_mut() {
                p.outer.count = k + 1;
            }
            let mut slots_attempted = SlotsAttempted::default();
            let candidate = try_recipient_unwrap_with_idx(
                envelope,
                key,
                constant_time_n,
                Some(&mut slots_attempted),
            );
            if let Some(p) = probe.as_deref_mut() {
                p.inner.count = slots_attempted.count;
                p.inner.per_priv_counts.push(slots_attempted.count);
            }
            let Some((cek, _)) = candidate else {
                continue;
            };
            // The outer loop short-circuits on the first private key whose CEK
            // also passes slots_mac (documented weak cross-priv timing leak).
            if slots_mac_matches(&cek, &slots_cbor, &envelope.slots_mac) {
                matched_cek = Some(cek);
                break;
            }
            any_candidate_recovered = true;
        }
        if matched_cek.is_none() {
            return Ok(UnwrapResult::NotMatched {
                reason: if any_candidate_recovered {
                    UnwrapFailureReason::TamperedHeader
                } else {
                    UnwrapFailureReason::WrongRecipientKey
                },
            });
        }
    }

    let mut matched_cek = matched_cek.expect("matched_cek set on every non-early-return path");

    // Content AEAD AAD is `nonce || slots_mac`.
    let mut ad_content = Vec::with_capacity(envelope.nonce.len() + envelope.slots_mac.len());
    ad_content.extend_from_slice(&envelope.nonce);
    ad_content.extend_from_slice(&envelope.slots_mac);
    let result =
        match xchacha20_poly1305_decrypt(&matched_cek, &envelope.nonce, &ad_content, ciphertext) {
            Ok(plaintext) => UnwrapResult::Matched { plaintext },
            Err(_) => UnwrapResult::NotMatched {
                reason: UnwrapFailureReason::TamperedCiphertext,
            },
        };
    matched_cek.zeroize();
    Ok(result)
}

/// The recipient-key selection for a trial-decrypt.
///
/// Exactly one form. The bundle form dispatches on the envelope's `kem`; an
/// empty selected bundle list is a clean [`TrialDecryptResult::NoAeadPass`],
/// while an empty flat list stays a programmer error.
pub enum TrialDecryptKeys<'a> {
    /// A flat, KEM-pre-selected list of secret keys (newest first).
    Multi(&'a [Vec<u8>]),
    /// A whole key bundle; the KEM list is dispatched from the envelope.
    Bundle(&'a RecipientKeyBundle),
}

/// The trial-decrypt half of the unwrap: recover the CEK and slot index without
/// touching the content AEAD.
///
/// Used by an inbox-scan agent that has the on-chain envelope but fetches the
/// off-chain ciphertext only when the user invokes decrypt. Mirrors the
/// multi-priv branch of [`ecies_sealed_poe_unwrap`]: same partitioning-oracle
/// pre-checks, same per-private-key inner loop, same constant-time-N invariant
/// (default `true`, mandatory for untrusted scan agents), same constant-time
/// `slots_mac` check, same documented cross-priv short-circuit. It differs only
/// in the return shape.
///
/// # Errors
///
/// Returns an [`EciesSealedPoeError`] for malformed input (unsupported
/// algorithm, wrong-length wire field, wrong-length recipient key, or an empty
/// flat list).
pub fn ecies_sealed_poe_trial_decrypt(
    envelope: &SealedEnvelope,
    keys: TrialDecryptKeys<'_>,
    constant_time_n: bool,
    mut probe: Option<&mut UnwrapProbe>,
) -> Result<TrialDecryptResult, EciesSealedPoeError> {
    let (recipient_secret_keys, is_bundle): (&[Vec<u8>], bool) = match keys {
        TrialDecryptKeys::Multi(list) => (list, false),
        TrialDecryptKeys::Bundle(bundle) => (select_bundle_secrets(envelope, bundle), true),
    };

    if recipient_secret_keys.is_empty() {
        if is_bundle {
            return Ok(TrialDecryptResult::NoAeadPass);
        }
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::InvalidRecipientKey,
            "recipient_secret_keys MUST be a non-empty list, got length 0",
        ));
    }

    assert_envelope_structure(envelope, Some(recipient_secret_keys), None)?;

    let slots_cbor = slots_to_mac_cbor(&envelope.slots);
    let mut any_candidate_recovered = false;

    for (k, key) in recipient_secret_keys.iter().enumerate() {
        if let Some(p) = probe.as_deref_mut() {
            p.outer.count = k + 1;
        }
        let mut slots_attempted = SlotsAttempted::default();
        let candidate = try_recipient_unwrap_with_idx(
            envelope,
            key,
            constant_time_n,
            Some(&mut slots_attempted),
        );
        if let Some(p) = probe.as_deref_mut() {
            p.inner.count = slots_attempted.count;
            p.inner.per_priv_counts.push(slots_attempted.count);
        }
        let Some((cek, slot_idx)) = candidate else {
            continue;
        };
        if slots_mac_matches(&cek, &slots_cbor, &envelope.slots_mac) {
            return Ok(TrialDecryptResult::Match { slot_idx, cek });
        }
        any_candidate_recovered = true;
    }

    Ok(if any_candidate_recovered {
        TrialDecryptResult::AeadPassNoMacMatch
    } else {
        TrialDecryptResult::NoAeadPass
    })
}
