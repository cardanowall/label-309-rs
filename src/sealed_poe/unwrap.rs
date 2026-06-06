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
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::kdf::hkdf_sha256;

use super::aead::xchacha20_poly1305_decrypt;
use super::errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
use super::kem::{
    mlkem768x25519_decapsulate, mlkem768x25519_public_key_from_seed, x25519_ecdh_unvalidated,
    x25519_public_key, MLKEM768X25519_ENC_LENGTH,
};
use super::slots::{
    join_kem_ct, Mlkem768X25519Slot, SealedEnvelope, SealedSlots, X25519Slot,
    AEAD_XCHACHA20_POLY1305, KEM_MLKEM768X25519, KEM_X25519,
};
use super::transcript::{
    ad_content_slots, assert_ciphertext_within_bound, compute_slots_hash, slots_payload_key,
    xwing_kek_salt, MAX_DECODED_ENVELOPE_BYTES, MAX_SLOTS,
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
    // Resource bound: reject an envelope with more than MAX_SLOTS slots before any
    // KEM/AEAD primitive runs, so a malformed record cannot drive unbounded
    // per-slot work. Checked before the per-slot length loop below.
    if n > MAX_SLOTS {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncSlotsTooMany,
            format!("envelope.slots.len()={n} exceeds MAX_SLOTS={MAX_SLOTS}"),
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

    // Per-slot length pre-checks — KEM-driven. ALL slots are validated here,
    // before any decapsulation, so the trial-decrypt loop never observes a
    // malformed slot (partitioning-oracle-safe ordering). The envelope's `kem`
    // string is validated above; the slot variant always matches the chosen KEM
    // because it can only be built that way (parsing routes on the same `kem`).
    //
    // Per-slot KEK uniqueness is also enforced here. The zero-nonce per-slot
    // wrap is safe only because each slot draws fresh KEM randomness, so its KEK
    // is unique; two slots sharing the same KEM material derive the same KEK and
    // repeat a (KEK, zero-nonce) pair. The KEM material that fixes the KEK is the
    // `epk` (x25519) or the reassembled `kem_ct` (hybrid) — both bound into the
    // KEK salt — so a repeat of either across slots is rejected outright.
    let mut seen_kem_material: std::collections::HashSet<Vec<u8>> =
        std::collections::HashSet::new();
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
                if !seen_kem_material.insert(slot.epk.clone()) {
                    return Err(duplicate_kem_material_error(i, "epk"));
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
                if !seen_kem_material.insert(enc) {
                    return Err(duplicate_kem_material_error(i, "kem_ct"));
                }
            }
        }
    }

    // Decoded-envelope byte backstop. Every per-slot field above is validated to
    // a fixed length, so the decoded envelope's aggregate size is determined here:
    // nonce + slots_mac + per-slot (epk|kem_ct + wrap). Reject before any KEM/AEAD
    // primitive when it exceeds the bound — a tighter resource cap than MAX_SLOTS
    // for honest records, and the bound a parser that can see the decoded size
    // enforces.
    let per_slot_bytes = match &envelope.slots {
        SealedSlots::X25519(_) => X25519_SECRET_KEY_LENGTH + WRAP_LENGTH,
        SealedSlots::Mlkem768X25519(_) => MLKEM768X25519_ENC_LENGTH + WRAP_LENGTH,
    };
    let decoded_envelope_bytes = NONCE_LENGTH + SLOTS_MAC_LENGTH + n * per_slot_bytes;
    if decoded_envelope_bytes > MAX_DECODED_ENVELOPE_BYTES {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::EncEnvelopeTooLarge,
            format!(
                "decoded envelope size {decoded_envelope_bytes} exceeds MAX_DECODED_ENVELOPE_BYTES={MAX_DECODED_ENVELOPE_BYTES}"
            ),
        ));
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

fn duplicate_kem_material_error(slot_idx: usize, field: &str) -> EciesSealedPoeError {
    EciesSealedPoeError::new(
        EciesSealedPoeErrorCode::EncSlotsDuplicateKemMaterial,
        format!(
            "envelope.slots[{slot_idx}].{field} duplicates an earlier slot; per-slot KEK uniqueness is violated"
        ),
    )
}

/// Constant-time select between two 32-byte KEKs on a `Choice`: returns `a` when
/// `choice` is 1, `b` when 0, with no data-dependent branch.
fn ct_select_kek(choice: Choice, a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::conditional_select(&b[i], &a[i], choice);
    }
    out
}

/// Classical (x25519) per-slot recovery. Returns the candidate CEK on an
/// AEAD-tag success; `None` otherwise. The AEAD is attempted on EVERY slot (no
/// match-position-dependent skip), so a per-private-key scan recovers a
/// candidate CEK from each slot the recipient is addressed in — which is what
/// the inner loop's CEK-conflict detection needs. Attempting the AEAD on every
/// slot also makes the per-slot timing more uniform, not less.
///
/// Acceptance is `kem_ok AND open_ok`, with `kem_ok` folded in branchlessly.
/// `x25519-dalek` does NOT reject a small-order epk — it returns the all-zero
/// shared secret — so this path takes the spec's full ct-select shape: it
/// derives `real_KEK` from the (possibly all-zero) shared secret and a
/// `dummy_KEK` from `0^32`, constant-time-selects the KEK on `kem_ok`, and ANDs
/// `kem_ok` into the acceptance. An invalid-ECDH slot (`kem_ok = false`) thus
/// uses the dummy KEK and is forced to a non-match regardless of the AEAD tag,
/// so it can never be accepted, while paying the exact same per-slot work.
fn try_x25519_slot(
    slot: &X25519Slot,
    recipient_secret_key: &[u8],
    pub_r_local: &[u8],
) -> Option<Vec<u8>> {
    // Non-rejecting ECDH: raw shared secret plus the constant-time validity bit.
    // The recipient-key and epk lengths are guaranteed valid upstream, so the
    // only failure would be a length error, which is unreachable here.
    let (shared, kem_ok) = match x25519_ecdh_unvalidated(recipient_secret_key, &slot.epk) {
        Ok(pair) => pair,
        Err(_) => return None,
    };
    let mut salt = Vec::with_capacity(slot.epk.len() + pub_r_local.len());
    salt.extend_from_slice(&slot.epk);
    salt.extend_from_slice(pub_r_local);
    // Both KEKs are derived unconditionally so the work is identical whether or
    // not the slot is valid; the KEK actually used is selected in constant time.
    let mut real_kek = hkdf_sha256(&shared, &salt, CARDANO_POE_HKDF_INFO_KEK, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    let mut dummy_kek = hkdf_sha256(&[0u8; 32], &salt, CARDANO_POE_HKDF_INFO_KEK, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    let mut kek = ct_select_kek(kem_ok, &real_kek, &dummy_kek);
    real_kek.zeroize();
    dummy_kek.zeroize();

    // open_ok: attempt the wrap AEAD under the selected KEK. The slots_mac /
    // conflict check is performed by the caller; here we fold kem_ok so a slot
    // that failed the KEM validity check can never yield a candidate CEK even if
    // the AEAD somehow opened.
    let opened =
        chacha20_poly1305_decrypt(&kek, &ZERO_NONCE_12, CARDANO_POE_HKDF_INFO_KEK, &slot.wrap).ok();
    kek.zeroize();
    if kem_ok.unwrap_u8() == 1 {
        opened
    } else {
        None
    }
}

/// Hybrid (mlkem768x25519) per-slot recovery. X-Wing decapsulation never throws
/// on attacker wire data (ML-KEM implicit rejection), so a wrong shared secret
/// simply yields a KEK that fails the AEAD tag. As in the classical body, the
/// AEAD is attempted on EVERY slot (full decapsulate + HKDF + AEAD-open) so
/// matching and non-matching slots cost the same and a per-private-key scan
/// recovers a candidate CEK from every slot the recipient is addressed in.
///
/// `pub_r` is the recipient's own 1216-byte X-Wing public key, recomputed once
/// from the held seed — the same value the producer bound into the KEK salt.
fn try_mlkem768x25519_slot(
    slot: &Mlkem768X25519Slot,
    recipient_secret_seed: &[u8],
    pub_r: &[u8],
) -> Option<Vec<u8>> {
    // kem_ct length was validated to reassemble to the enc length upstream, so
    // join + decapsulate is constant-work.
    let enc = join_kem_ct(&slot.kem_ct);
    let mut ss = mlkem768x25519_decapsulate(recipient_secret_seed, &enc)
        .expect("kem_ct reassembles to the validated enc length and the seed length is checked");
    // The KEK salt binds the slot's own reassembled ciphertext and the
    // recipient's own X-Wing public key, exactly as the producer bound them.
    let salt = xwing_kek_salt(&enc, pub_r);
    let mut kek = hkdf_sha256(&ss, &salt, CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    ss.zeroize();
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

/// The recovered CEK plus a defence-in-depth conflict flag from a per-private-key
/// inner scan.
///
/// A producer may legitimately address the same recipient (or wrap the same CEK)
/// in several slots, so multiple matching slots are PERMITTED and the first
/// match's CEK is selected. But two matching slots recovering DIFFERENT CEKs
/// (both opening their per-slot wrap AEAD) is a commitment collision the §G4
/// assumption rules out; `cek_conflict` flags it so the caller can fail closed.
/// The compare is constant-time; the inner loop visits every slot
/// (constant-time-N), so the flag does not leak match position.
struct InnerUnwrap {
    cek: Vec<u8>,
    slot_idx: usize,
    cek_conflict: bool,
}

/// Per-private-key inner trial-decrypt loop, KEM-driven, with slot-index
/// reporting and CEK-conflict detection. Enters every slot when
/// `constant_time_n`; every slot attempts the wrap AEAD, so a recipient
/// addressed in multiple slots recovers a candidate CEK from each. The first
/// match's CEK is selected; any later match recovering a CEK that differs
/// (constant-time compare) from the selected one sets `cek_conflict`. This
/// follows the spec loop shape:
///
/// ```text
/// first        = ok AND NOT found
/// cek_conflict = cek_conflict OR (ok AND found AND NOT ct_eq(cand, selected))
/// selected_CEK = first ? cand : selected
/// found        = found OR ok
/// ```
///
/// No early break is taken when `constant_time_n`, so the conflict scan is
/// constant across the whole slot set.
fn try_recipient_unwrap_with_idx(
    envelope: &SealedEnvelope,
    recipient_secret_key: &[u8],
    constant_time_n: bool,
    probe: Option<&mut SlotsAttempted>,
) -> Option<InnerUnwrap> {
    // Fold a slot's candidate into the running state per the spec loop shape:
    //   first        = ok AND NOT found
    //   cek_conflict = cek_conflict OR (ok AND found AND NOT ct_eq(cand, sel))
    //   selected_CEK = first ? cand : selected
    fn record_match(
        cek: &mut Option<Vec<u8>>,
        matched_slot_idx: &mut usize,
        cek_conflict: &mut bool,
        candidate: Option<Vec<u8>>,
        i: usize,
    ) {
        let Some(c) = candidate else { return };
        match cek {
            None => {
                *matched_slot_idx = i;
                *cek = Some(c);
            }
            Some(selected) => {
                // A later matching slot whose recovered CEK differs from the
                // already-selected one. Fail closed.
                if c.ct_eq(selected).unwrap_u8() != 1 {
                    *cek_conflict = true;
                }
            }
        }
    }

    let mut cek: Option<Vec<u8>> = None;
    let mut matched_slot_idx = 0usize;
    let mut cek_conflict = false;
    let mut slots_count = 0usize;

    match &envelope.slots {
        SealedSlots::X25519(slots) => {
            let pub_r_local =
                x25519_public_key(recipient_secret_key).expect("recipient key length checked");
            for (i, slot) in slots.iter().enumerate() {
                slots_count = i + 1;
                let candidate = try_x25519_slot(slot, recipient_secret_key, &pub_r_local);
                record_match(
                    &mut cek,
                    &mut matched_slot_idx,
                    &mut cek_conflict,
                    candidate,
                    i,
                );
                if cek.is_some() && !constant_time_n {
                    break;
                }
            }
        }
        SealedSlots::Mlkem768X25519(slots) => {
            // Recompute the recipient's own X-Wing public key from the held seed:
            // the hybrid KEK salt binds `pub_R`, so each private key in a
            // multi-key scan MUST re-derive it (a single shared pub_R would
            // compute the wrong KEK for every key but one). A wrong-length seed
            // cannot derive a public key; such a key simply recovers no CEK
            // (a clean non-match), and the inner loop is still entered so the
            // constant-time-N slot count is reported.
            let pub_r = mlkem768x25519_public_key_from_seed(recipient_secret_key).ok();
            for (i, slot) in slots.iter().enumerate() {
                slots_count = i + 1;
                let candidate = pub_r
                    .as_ref()
                    .and_then(|pub_r| try_mlkem768x25519_slot(slot, recipient_secret_key, pub_r));
                record_match(
                    &mut cek,
                    &mut matched_slot_idx,
                    &mut cek_conflict,
                    candidate,
                    i,
                );
                if cek.is_some() && !constant_time_n {
                    break;
                }
            }
        }
    }

    if let Some(p) = probe {
        p.count = slots_count;
    }
    cek.map(|c| InnerUnwrap {
        cek: c,
        slot_idx: matched_slot_idx,
        cek_conflict,
    })
}

/// Recompute the `slots_mac` HMAC for a candidate CEK over the 32-byte
/// `slots_hash` and compare it constant-time.
fn slots_mac_matches(cek: &[u8], slots_hash: &[u8], expected: &[u8]) -> bool {
    let mut hmac_key = hkdf_sha256(cek, &[], CARDANO_POE_HKDF_INFO_SLOTS_MAC, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum");
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(&hmac_key).expect("HMAC accepts a key of any length");
    mac.update(slots_hash);
    let calc = mac.finalize().into_bytes();
    hmac_key.zeroize();
    calc.ct_eq(expected).into()
}

/// Recover the plaintext from a sealed envelope and its content ciphertext.
///
/// Trial-decrypts each slot under the supplied key(s) until one yields a CEK
/// that also passes the `slots_mac` check, then opens the content under a CEK-
/// derived `payload_key` with the structured slots-path AAD (the header re-bound
/// alongside `slots_hash` and `slots_mac`). Returns [`UnwrapResult::Matched`]
/// with the plaintext, or [`UnwrapResult::NotMatched`] with the failure reason —
/// a wrong recipient key, a tampered header, or a tampered ciphertext are all
/// structured results, never errors.
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

    // Reject a ciphertext at or above the single-shot keystream capacity before
    // any KEM/AEAD work, so an over-large blob never reaches the content open.
    assert_ciphertext_within_bound(ciphertext.len() as u64)?;

    // The slots-transcript hash is constant across both the single-priv MAC
    // check and the multi-priv outer loop — compute it ONCE, then re-key the
    // HMAC from each candidate CEK over this same 32-byte message.
    let slots_hash = compute_slots_hash(&envelope.kem, &envelope.nonce, &envelope.slots);
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
            Some(inner) => {
                // CEK-conflict defence-in-depth: a later matching slot recovered
                // a CEK that differs from the selected one. Fail closed with the
                // generic tampered-header reason (a commitment collision is an
                // anomalous slot set, not a recipient-key mismatch).
                if inner.cek_conflict {
                    return Ok(UnwrapResult::NotMatched {
                        reason: UnwrapFailureReason::TamperedHeader,
                    });
                }
                if !slots_mac_matches(&inner.cek, &slots_hash, &envelope.slots_mac) {
                    return Ok(UnwrapResult::NotMatched {
                        reason: UnwrapFailureReason::TamperedHeader,
                    });
                }
                matched_cek = Some(inner.cek);
            }
        }
    } else {
        let keys = multi.expect("exactly one of single/multi is set");
        let mut any_candidate_recovered = false;
        let mut cek_conflict = false;
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
            let Some(inner) = candidate else {
                continue;
            };
            // A per-private-key CEK conflict (two of this key's slots recovering
            // different CEKs) makes the whole record anomalous regardless of
            // which key matched the MAC — record it and fail closed after the
            // loop.
            if inner.cek_conflict {
                cek_conflict = true;
            }
            // The outer loop short-circuits on the first private key whose CEK
            // also passes slots_mac (documented weak cross-priv timing leak).
            if slots_mac_matches(&inner.cek, &slots_hash, &envelope.slots_mac) {
                matched_cek = Some(inner.cek);
                break;
            }
            any_candidate_recovered = true;
        }
        // A CEK conflict on the matching key fails the record closed, even if its
        // first-slot CEK passed slots_mac.
        if matched_cek.is_some() && cek_conflict {
            return Ok(UnwrapResult::NotMatched {
                reason: UnwrapFailureReason::TamperedHeader,
            });
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

    // Content is opened under the derived `payload_key`, with the structured
    // slots-path AAD re-binding the header plus `slots_hash` and `slots_mac`.
    let mut payload_key = slots_payload_key(&matched_cek, &envelope.nonce);
    let ad_content = ad_content_slots(
        &envelope.kem,
        &envelope.nonce,
        &slots_hash,
        &envelope.slots_mac,
    );
    let result =
        match xchacha20_poly1305_decrypt(&payload_key, &envelope.nonce, &ad_content, ciphertext) {
            Ok(plaintext) => UnwrapResult::Matched { plaintext },
            Err(_) => UnwrapResult::NotMatched {
                reason: UnwrapFailureReason::TamperedCiphertext,
            },
        };
    payload_key.zeroize();
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

    let slots_hash = compute_slots_hash(&envelope.kem, &envelope.nonce, &envelope.slots);
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
        let Some(inner) = candidate else {
            continue;
        };
        // CEK-conflict defence-in-depth: this key recovered different CEKs from
        // two matching slots — an anomalous slot set. Surface it as the generic
        // AeadPassNoMacMatch outcome (the trial-decrypt analogue of the unwrap
        // TamperedHeader rejection: a CEK opened but the slot set is not
        // trusted), never a clean match.
        if inner.cek_conflict {
            any_candidate_recovered = true;
            continue;
        }
        if slots_mac_matches(&inner.cek, &slots_hash, &envelope.slots_mac) {
            return Ok(TrialDecryptResult::Match {
                slot_idx: inner.slot_idx,
                cek: inner.cek,
            });
        }
        any_candidate_recovered = true;
    }

    Ok(if any_candidate_recovered {
        TrialDecryptResult::AeadPassNoMacMatch
    } else {
        TrialDecryptResult::NoAeadPass
    })
}
