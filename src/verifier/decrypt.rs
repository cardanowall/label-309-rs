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

use crate::hash::{blake2b256, sha256};
use crate::poe_standard::{EncryptionEnvelope, ItemEntry, PassphraseBlock, PoeRecord, Slot};
use crate::sealed_poe::{
    ecies_sealed_poe_unwrap, sealed_envelope_from_parsed, xchacha20_poly1305_decrypt,
    ParsedEnvelope, ParsedSlot, UnwrapFailureReason, UnwrapKeys, UnwrapResult,
};

use crate::verifier::egress::GatewayFetcher;
use crate::verifier::fetch_item::{fetch_item_ciphertext, FetchItemError};
use crate::verifier::types::{
    DecryptResult, Decryption, DecryptionFailureReason, UriCheck, VerifyTxInput,
};

/// The single registered passphrase-KDF identifier in v1.
const PASSPHRASE_KDF_ARGON2ID: &str = "argon2id";

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
    let unwrap = match ecies_sealed_poe_unwrap(
        &envelope,
        ciphertext,
        UnwrapKeys::Single(recipient_secret_key),
        false,
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
    let normalised = normalise_passphrase(passphrase);
    let cek = match derive_kek_from_passphrase(normalised.as_bytes(), block) {
        Ok(k) => k,
        Err(()) => return fail(item_index, DecryptionFailureReason::KdfDerivationFailed),
    };
    if enc.aead != "xchacha20-poly1305" {
        return fail(item_index, DecryptionFailureReason::NoEncEnvelope);
    }
    match xchacha20_poly1305_decrypt(&cek, &enc.nonce, &[], ciphertext) {
        Ok(plaintext) => hash_check_result(item, item_index, &plaintext),
        Err(_) => fail(item_index, DecryptionFailureReason::TamperedCiphertext),
    }
}

/// Normalise a passphrase: NFKC → collapse whitespace runs to one ASCII space →
/// trim. Case is deliberately NOT folded here — the CEK-derivation path is
/// case-sensitive.
///
/// The whitespace predicate matches Python `re`'s `\s` (Unicode `White_Space`
/// plus the C0 information separators U+001C–U+001F), so the derived CEK matches
/// the producer's normalisation for every input.
fn normalise_passphrase(passphrase: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let nfkc: String = passphrase.nfkc().collect();
    let mut out = String::with_capacity(nfkc.len());
    let mut in_ws = false;
    for ch in nfkc.chars() {
        if is_normalise_whitespace(ch) {
            in_ws = true;
        } else {
            if in_ws && !out.is_empty() {
                out.push(' ');
            }
            in_ws = false;
            out.push(ch);
        }
    }
    out
}

/// Whether `ch` is whitespace for passphrase normalisation: Unicode
/// `White_Space` plus the C0 information separators U+001C–U+001F. This union is
/// exactly Python `re`'s `\s`, which the producer-side normaliser relies on.
fn is_normalise_whitespace(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\u{1c}'..='\u{1f}')
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
