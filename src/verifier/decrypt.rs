//! Sealed-PoE decryption (the recipient-verifier trial decrypt).
//!
//! For each `input.decryption[]` entry the verifier dispatches on the on-wire
//! `enc` shape (`slots[]` → recipient path, `passphrase` → KDF path), acquires
//! the ciphertext (caller-supplied bytes first, then `items[i].uris[]` over the
//! gateway chain), unwraps, and recomputes every committed content hash against
//! the recovered plaintext.
//!
//! This function never throws: a single malformed or unavailable item cannot
//! abort the whole report — every failure becomes a `DecryptResult { ok: false }`
//! row, and each ciphertext-fetch attempt surfaces as a `UriCheck` diagnostic.

use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::hash::{blake2b256, sha256};
use crate::poe_standard::{EncryptionEnvelope, ItemEntry, PassphraseBlock, PoeRecord, Slot};
use crate::sealed_poe::{
    ad_content_passphrase, assert_ciphertext_within_bound, ecies_sealed_poe_unwrap,
    passphrase_payload_key, sealed_envelope_from_parsed, xchacha20_poly1305_decrypt,
    ParsedEnvelope, ParsedSlot, UnwrapFailureReason, UnwrapKeys, UnwrapResult,
};

use crate::verifier::egress::GatewayFetcher;
use crate::verifier::fetch_item::{fetch_item_ciphertext, FetchItemError};
use crate::verifier::types::{
    DecryptResult, Decryption, DecryptionFailureReason, UriCheck, VerifyTxInput,
};

/// The single registered passphrase-KDF identifier in v1.
const PASSPHRASE_KDF_ARGON2ID: &str = "argon2id";

/// Maximum raw passphrase length, in UTF-8 bytes, enforced BEFORE normalization
/// and the Argon2id KDF.
///
/// An oversized passphrase would otherwise drive unbounded NFKC /
/// whitespace-collapse work and a large Argon2id input before any cost-bounded
/// primitive runs; capping the raw input closes that pre-KDF DoS. The bound is
/// byte length (`s.len()`), not code-point count, so a short string of wide
/// multi-byte characters is still measured by its encoded size. 4096 bytes is
/// far above any human-chosen passphrase. Identical across every SDK.
pub const MAX_PASSPHRASE_INPUT_BYTES: usize = 4096;

/// Walk `input.decryption[]` and produce one [`DecryptResult`] per entry, plus
/// the per-attempt [`UriCheck`] diagnostics from any ciphertext fetches.
#[must_use]
pub fn try_decryptions(
    record: &PoeRecord,
    input: &VerifyTxInput<'_>,
    fetcher: &mut GatewayFetcher<'_>,
) -> (Vec<DecryptResult>, Vec<UriCheck>) {
    let mut out = Vec::new();
    let mut uri_checks = Vec::new();
    let Some(reqs) = &input.decryption else {
        return (out, uri_checks);
    };
    let empty = Vec::new();
    let items = record.items.as_ref().unwrap_or(&empty);

    for dec in reqs {
        let item_index = dec.item_index();
        let idx = match usize::try_from(item_index) {
            Ok(i) if i < items.len() => i,
            _ => {
                out.push(fail(item_index, DecryptionFailureReason::NoEncEnvelope));
                continue;
            }
        };
        let item = &items[idx];
        let Some(enc) = &item.enc else {
            out.push(fail(item_index, DecryptionFailureReason::NoEncEnvelope));
            continue;
        };

        let is_sealed = is_sealed_envelope(enc);
        let is_kdf = is_kdf_envelope(enc);
        let req_recipient = matches!(dec, Decryption::Recipient { .. });
        let req_passphrase = matches!(dec, Decryption::Passphrase { .. });

        if is_sealed && !req_recipient {
            out.push(fail(
                item_index,
                DecryptionFailureReason::WrongDecryptionInputShape,
            ));
            continue;
        }
        if is_kdf && !req_passphrase {
            out.push(fail(
                item_index,
                DecryptionFailureReason::WrongDecryptionInputShape,
            ));
            continue;
        }
        if !is_sealed && !is_kdf {
            out.push(fail(item_index, DecryptionFailureReason::NoEncEnvelope));
            continue;
        }

        let ciphertext = match acquire_ciphertext(item, item_index, input, fetcher, &mut uri_checks)
        {
            Ok(bytes) => bytes,
            Err(reason) => {
                out.push(fail(item_index, reason));
                continue;
            }
        };

        let result = match dec {
            Decryption::Recipient {
                recipient_secret_key,
                ..
            } => try_sealed(item, enc, item_index, recipient_secret_key, &ciphertext),
            Decryption::Passphrase { passphrase, .. } => {
                try_kdf(item, enc, item_index, passphrase, &ciphertext)
            }
        };
        out.push(result);
    }

    (out, uri_checks)
}

fn fail(item_index: i64, reason: DecryptionFailureReason) -> DecryptResult {
    DecryptResult {
        item_index,
        ok: false,
        plaintext_hash_ok: None,
        reason: Some(reason),
    }
}

fn is_sealed_envelope(enc: &EncryptionEnvelope) -> bool {
    enc.slots.is_some() && enc.slots_mac.is_some()
}

fn is_kdf_envelope(enc: &EncryptionEnvelope) -> bool {
    enc.passphrase.is_some() && enc.slots.is_none() && enc.slots_mac.is_none()
}

/// Convert the typed `enc` block into the permissive [`ParsedEnvelope`] the
/// crypto layer's [`sealed_envelope_from_parsed`] consumes.
fn to_parsed_envelope(enc: &EncryptionEnvelope) -> ParsedEnvelope {
    ParsedEnvelope {
        scheme: i64::try_from(enc.scheme).ok(),
        aead: Some(enc.aead.clone()),
        kem: enc.kem.clone(),
        nonce: Some(enc.nonce.clone()),
        slots: enc.slots.as_ref().map(|slots| {
            slots
                .iter()
                .map(|s: &Slot| ParsedSlot {
                    epk: s.epk.clone(),
                    kem_ct: s.kem_ct.clone(),
                    wrap: s.wrap.clone(),
                })
                .collect()
        }),
        slots_mac: enc.slots_mac.clone(),
    }
}

fn try_sealed(
    item: &ItemEntry,
    enc: &EncryptionEnvelope,
    item_index: i64,
    recipient_secret_key: &[u8],
    ciphertext: &[u8],
) -> DecryptResult {
    let Some(envelope) = sealed_envelope_from_parsed(&to_parsed_envelope(enc)) else {
        return fail(item_index, DecryptionFailureReason::NoEncEnvelope);
    };
    // constant_time_n = true so the standalone verifier visits every slot: it
    // keeps the per-slot timing uniform AND lets the CEK-conflict defence see a
    // later slot recovering a CEK that differs from the selected one (a
    // commitment collision is rejected, never silently decrypted under the first
    // CEK). A one-shot recipient verify is not a hot loop, so the full-scan cost
    // is irrelevant here.
    let unwrap = match ecies_sealed_poe_unwrap(
        &envelope,
        ciphertext,
        UnwrapKeys::Single(recipient_secret_key),
        true,
        None,
    ) {
        Ok(u) => u,
        Err(_) => return fail(item_index, DecryptionFailureReason::NoEncEnvelope),
    };
    match unwrap {
        UnwrapResult::Matched { plaintext } => hash_check_result(item, item_index, &plaintext),
        UnwrapResult::NotMatched { reason } => {
            let r = match reason {
                UnwrapFailureReason::WrongRecipientKey => {
                    DecryptionFailureReason::WrongRecipientKey
                }
                UnwrapFailureReason::TamperedHeader => DecryptionFailureReason::TamperedHeader,
                UnwrapFailureReason::TamperedCiphertext => {
                    DecryptionFailureReason::TamperedCiphertext
                }
            };
            fail(item_index, r)
        }
    }
}

fn try_kdf(
    item: &ItemEntry,
    enc: &EncryptionEnvelope,
    item_index: i64,
    passphrase: &str,
    ciphertext: &[u8],
) -> DecryptResult {
    let Some(block) = &enc.passphrase else {
        return fail(item_index, DecryptionFailureReason::NoEncEnvelope);
    };
    if block.alg != PASSPHRASE_KDF_ARGON2ID {
        return fail(item_index, DecryptionFailureReason::KdfDerivationFailed);
    }
    // Pre-KDF input cap: reject an oversized raw passphrase before normalization
    // or Argon2id, so it cannot drive unbounded pre-KDF work. Byte length of the
    // raw UTF-8 string, not code-point count.
    if passphrase.len() > MAX_PASSPHRASE_INPUT_BYTES {
        return fail(item_index, DecryptionFailureReason::KdfDerivationFailed);
    }
    let normalised = normalise_passphrase(passphrase);
    let mut cek = match derive_kek_from_passphrase(normalised.as_bytes(), block) {
        Ok(k) => k,
        Err(()) => return fail(item_index, DecryptionFailureReason::KdfDerivationFailed),
    };
    if enc.aead != "xchacha20-poly1305" {
        cek.zeroize();
        return fail(item_index, DecryptionFailureReason::KdfDerivationFailed);
    }
    // Reject an over-large ciphertext before the single-shot AEAD open.
    if assert_ciphertext_within_bound(ciphertext.len() as u64).is_err() {
        cek.zeroize();
        return fail(item_index, DecryptionFailureReason::KdfDerivationFailed);
    }
    // Content is opened under a payload_key derived from the CEK, with a
    // structured AAD that binds the passphrase-KDF parameters: tampering with
    // `salt` or any `params` value after encryption changes the AAD and makes
    // the AEAD open fail. The normalization profile id is pinned into the AAD as
    // a scheme-fixed constant. The CEK never keys the content AEAD directly.
    let (m, t, p) = match (param(block, "m"), param(block, "t"), param(block, "p")) {
        (Some(m), Some(t), Some(p)) => (m, t, p),
        _ => {
            cek.zeroize();
            return fail(item_index, DecryptionFailureReason::KdfDerivationFailed);
        }
    };
    let mut payload_key = passphrase_payload_key(&cek, &enc.nonce);
    cek.zeroize();
    let aad = ad_content_passphrase(&enc.nonce, &block.alg, &block.salt, m, t, p);
    let result = match xchacha20_poly1305_decrypt(&payload_key, &enc.nonce, &aad, ciphertext) {
        Ok(plaintext) => hash_check_result(item, item_index, &plaintext),
        Err(_) => fail(item_index, DecryptionFailureReason::TamperedCiphertext),
    };
    payload_key.zeroize();
    result
}

/// Read a named Argon2id parameter, returning `None` when absent. The AAD binds
/// the unsigned parameter values exactly as they appear on the wire.
fn param(block: &PassphraseBlock, name: &str) -> Option<u64> {
    block
        .params
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| *v)
}

/// The 25 codepoints carrying the Unicode `White_Space` property under Unicode
/// 16.0. The passphrase normalization profile collapses every maximal run of
/// these to a single U+0020. This is an explicit set on purpose: neither a regex
/// `\s` class nor a language `is_whitespace` predicate matches this set exactly,
/// and the CEK derivation must be byte-identical across implementations. In
/// particular, `char::is_whitespace` also matches the C0 information separators
/// U+001C–U+001F, which are NOT `White_Space` and must NOT collapse here.
const UNICODE_WHITE_SPACE: [char; 25] = [
    '\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0020}', '\u{0085}', '\u{00a0}',
    '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}',
    '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}',
    '\u{3000}',
];

/// Apply the `cardano-poe-pw-norm-v1` profile: NFKC (UAX #15, Unicode 16.0),
/// collapse every maximal run of `White_Space` to a single U+0020, trim a single
/// leading/trailing space, then return the UTF-8 string. The producer applies
/// the identical transform, so a single divergence here yields a CEK that fails
/// to decrypt an honest record. Case is deliberately NOT folded — the
/// CEK-derivation path is case-sensitive.
fn normalise_passphrase(passphrase: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let nfkc: String = passphrase.nfkc().collect();
    let mut collapsed = String::with_capacity(nfkc.len());
    let mut in_run = false;
    for ch in nfkc.chars() {
        if is_normalise_whitespace(ch) {
            if !in_run {
                collapsed.push(' ');
                in_run = true;
            }
        } else {
            collapsed.push(ch);
            in_run = false;
        }
    }
    // Trim a single leading then a single trailing collapsed U+0020 (every run
    // is already a single space). Mirrors the reference `strip(" ")` over a
    // string whose only spaces are the collapsed separators.
    let after_lead = collapsed.strip_prefix(' ').unwrap_or(&collapsed);
    after_lead
        .strip_suffix(' ')
        .unwrap_or(after_lead)
        .to_string()
}

/// Whether `ch` is `White_Space` for passphrase normalisation, per the explicit
/// [`UNICODE_WHITE_SPACE`] set. `char::is_whitespace` is deliberately NOT used —
/// it includes the C0 information separators U+001C–U+001F, which are not
/// `White_Space` and would derive a different CEK from the same passphrase.
fn is_normalise_whitespace(ch: char) -> bool {
    UNICODE_WHITE_SPACE.contains(&ch)
}

/// Derive the 32-byte CEK from a normalised passphrase via Argon2id v1.3.
///
/// Returns `Err(())` for an unsupported KDF alg or any out-of-range Argon2
/// parameter (so the caller surfaces `KDF_DERIVATION_FAILED` rather than
/// panicking on untrusted record-supplied parameters).
fn derive_kek_from_passphrase(passphrase: &[u8], block: &PassphraseBlock) -> Result<[u8; 32], ()> {
    if block.alg != PASSPHRASE_KDF_ARGON2ID {
        return Err(());
    }
    let get = |name: &str| {
        block
            .params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| *v)
    };
    let m = u32::try_from(get("m").ok_or(())?).map_err(|_| ())?;
    let t = u32::try_from(get("t").ok_or(())?).map_err(|_| ())?;
    let p = u32::try_from(get("p").ok_or(())?).map_err(|_| ())?;
    let params = Params::new(m, t, p, Some(32)).map_err(|_| ())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, &block.salt, &mut out)
        .map_err(|_| ())?;
    Ok(out)
}

/// Recompute every committed content hash against the recovered plaintext.
///
/// A single mismatch (or an unrecognised hash alg) yields `ok: true,
/// plaintext_hash_ok: false, reason: URI_INTEGRITY_MISMATCH`; an all-match yields
/// `ok: true, plaintext_hash_ok: true`.
fn hash_check_result(item: &ItemEntry, item_index: i64, plaintext: &[u8]) -> DecryptResult {
    let mut any_mismatch = false;
    for (alg, claimed) in &item.hashes {
        let recomputed: Vec<u8> = match alg.as_str() {
            "sha2-256" => sha256(plaintext).to_vec(),
            "blake2b-256" => blake2b256(plaintext).to_vec(),
            _ => {
                any_mismatch = true;
                continue;
            }
        };
        if recomputed.ct_eq(claimed).unwrap_u8() != 1 {
            any_mismatch = true;
        }
    }
    if any_mismatch {
        DecryptResult {
            item_index,
            ok: true,
            plaintext_hash_ok: Some(false),
            reason: Some(DecryptionFailureReason::UriIntegrityMismatch),
        }
    } else {
        DecryptResult {
            item_index,
            ok: true,
            plaintext_hash_ok: Some(true),
            reason: None,
        }
    }
}

/// Acquire an item's ciphertext: caller-supplied bytes, then `item.uris[]` over
/// the Arweave gateway chain, then a typed failure.
/// Acquire an item's ciphertext: caller-supplied out-of-band bytes first, then
/// (when the item carries `uris[]`) the canonical [`fetch_item_ciphertext`]
/// primitive over the gateway chain, which records one [`UriCheck`] per attempt.
///
/// The error projects to the decryption verdict exactly as the reference
/// verifier does: no `uris[]` → [`DecryptionFailureReason::CiphertextUnavailable`];
/// an in-set scheme with no reachable gateway → `ContentUnavailable`; a URI whose
/// scheme is out of the fetch set → `UriTargetForbidden`.
fn acquire_ciphertext(
    item: &ItemEntry,
    item_index: i64,
    input: &VerifyTxInput<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    uri_checks: &mut Vec<UriCheck>,
) -> Result<Vec<u8>, DecryptionFailureReason> {
    if let Some(bytes_map) = &input.ciphertext_bytes {
        if let Some(bytes) = bytes_map.get(&item_index) {
            return Ok(bytes.clone());
        }
    }

    let has_uris = item.uris.as_ref().is_some_and(|u| !u.is_empty());
    if !has_uris {
        return Err(DecryptionFailureReason::CiphertextUnavailable);
    }

    let uris = item.uris.as_deref().unwrap_or(&[]);
    match fetch_item_ciphertext(
        uris,
        fetcher,
        uri_checks,
        item_index,
        input.arweave_gateway_chain.as_deref(),
        input.ipfs_gateway_chain.as_deref(),
    ) {
        Ok(bytes) => Ok(bytes),
        Err(FetchItemError::UriTargetForbidden) => Err(DecryptionFailureReason::UriTargetForbidden),
        Err(FetchItemError::ContentUnavailable(_)) => {
            Err(DecryptionFailureReason::ContentUnavailable)
        }
    }
}

#[cfg(test)]
mod cap_tests {
    //! A4 — pre-KDF passphrase length cap (4096 UTF-8 bytes), enforced before
    //! normalization / Argon2id. Exercised at the `try_kdf` function level: an
    //! over-cap passphrase is rejected as KdfDerivationFailed before any KDF
    //! work; an at-cap passphrase still decrypts.

    use super::*;
    use crate::hash::sha256;
    use crate::sealed_poe::xchacha20_poly1305_encrypt;

    // Cost-minimal Argon2id params for test speed (below the producer floor, but
    // the verifier does not re-enforce floors).
    const M: u32 = 8;
    const T: u32 = 1;
    const P: u32 = 1;

    fn passphrase_block(salt: &[u8]) -> PassphraseBlock {
        PassphraseBlock {
            alg: PASSPHRASE_KDF_ARGON2ID.to_string(),
            salt: salt.to_vec(),
            params: vec![
                ("m".to_string(), u64::from(M)),
                ("t".to_string(), u64::from(T)),
                ("p".to_string(), u64::from(P)),
            ],
        }
    }

    fn build_ciphertext(passphrase: &str, salt: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        // Producer recompute matching `try_kdf`'s derivation.
        let normalised = normalise_passphrase(passphrase);
        let params = Params::new(M, T, P, Some(32)).expect("argon2 params");
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut cek = [0u8; 32];
        argon
            .hash_password_into(normalised.as_bytes(), salt, &mut cek)
            .expect("argon2 derive");
        let payload_key = passphrase_payload_key(&cek, nonce);
        let aad = ad_content_passphrase(
            nonce,
            PASSPHRASE_KDF_ARGON2ID,
            salt,
            u64::from(M),
            u64::from(T),
            u64::from(P),
        );
        xchacha20_poly1305_encrypt(&payload_key, nonce, &aad, plaintext)
    }

    fn item_with(salt: &[u8], nonce: &[u8], plaintext: &[u8]) -> (ItemEntry, EncryptionEnvelope) {
        let item = ItemEntry {
            hashes: vec![("sha2-256".to_string(), sha256(plaintext).to_vec())],
            uris: None,
            enc: Some(EncryptionEnvelope {
                scheme: 1,
                aead: "xchacha20-poly1305".to_string(),
                nonce: nonce.to_vec(),
                kem: None,
                slots: None,
                slots_mac: None,
                passphrase: Some(passphrase_block(salt)),
            }),
        };
        let enc = item.enc.clone().expect("enc set");
        (item, enc)
    }

    #[test]
    fn cap_constant_is_4096_bytes() {
        assert_eq!(MAX_PASSPHRASE_INPUT_BYTES, 4096);
    }

    #[test]
    fn over_byte_cap_is_rejected_kdf_failed() {
        let salt = [0x42u8; 16];
        let nonce = [0x00u8; 24];
        let plaintext = b"cap test";
        let oversized = "a".repeat(MAX_PASSPHRASE_INPUT_BYTES + 1); // 4097 ASCII bytes
        let ciphertext = build_ciphertext(&oversized, &salt, &nonce, plaintext);
        let (item, enc) = item_with(&salt, &nonce, plaintext);
        let result = try_kdf(&item, &enc, 0, &oversized, &ciphertext);
        assert!(!result.ok);
        assert_eq!(
            result.reason,
            Some(DecryptionFailureReason::KdfDerivationFailed)
        );
    }

    #[test]
    fn exactly_at_cap_is_accepted() {
        let salt = [0x42u8; 16];
        let nonce = [0x00u8; 24];
        let plaintext = b"cap test";
        let at_cap = "a".repeat(MAX_PASSPHRASE_INPUT_BYTES); // 4096 ASCII bytes
        let ciphertext = build_ciphertext(&at_cap, &salt, &nonce, plaintext);
        let (item, enc) = item_with(&salt, &nonce, plaintext);
        let result = try_kdf(&item, &enc, 0, &at_cap, &ciphertext);
        assert!(result.ok, "at-cap passphrase must decrypt");
        assert_eq!(result.plaintext_hash_ok, Some(true));
    }

    #[test]
    fn cap_measures_bytes_not_code_points() {
        // U+1F680 (rocket) is 4 UTF-8 bytes per code point. 1025 of them = 4100
        // bytes but only 1025 code points — under any char-count limit, over the
        // byte cap.
        let salt = [0x42u8; 16];
        let nonce = [0x00u8; 24];
        let plaintext = b"cap test";
        let multibyte_over_cap = "\u{1F680}".repeat(1025);
        assert!(multibyte_over_cap.chars().count() < MAX_PASSPHRASE_INPUT_BYTES);
        assert!(multibyte_over_cap.len() > MAX_PASSPHRASE_INPUT_BYTES);
        let ciphertext = build_ciphertext(&multibyte_over_cap, &salt, &nonce, plaintext);
        let (item, enc) = item_with(&salt, &nonce, plaintext);
        let result = try_kdf(&item, &enc, 0, &multibyte_over_cap, &ciphertext);
        assert!(!result.ok);
        assert_eq!(
            result.reason,
            Some(DecryptionFailureReason::KdfDerivationFailed)
        );
    }
}
