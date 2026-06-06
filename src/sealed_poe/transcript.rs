//! Shared, byte-critical pieces of the slots-path sealed-PoE construction that
//! the producer (wrap) and every verifier (unwrap, trial-decrypt) MUST compute
//! byte-for-byte identically:
//!
//! 1. The slots transcript and its SHA-256 hash `slots_hash`.
//! 2. The content-AEAD additional-authenticated-data object `AD_CONTENT_SLOTS`.
//! 3. The content `payload_key` derivation from the CEK.
//! 4. The hybrid (X-Wing) per-slot KEK salt.
//! 5. The passphrase-path content `payload_key` and `AD_CONTENT_PASSPHRASE`.
//! 6. The single-shot XChaCha20-Poly1305 maximum-payload guard.
//!
//! Keeping these in one module is the interop guarantee: a single divergence in
//! the canonical encoding silently yields a `slots_mac` or AEAD tag that another
//! implementation cannot reproduce, with no typed error to localise the fault.

use sha2::{Digest, Sha256};

use crate::cbor::{encode_canonical_cbor, CborValue};
use crate::kdf::hkdf_sha256;

use super::errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
use super::slots::{canonicalize_slots, SealedSlots, AEAD_XCHACHA20_POLY1305};

/// SHA-256 prefix for the slots-transcript hash `slots_hash`. 31 bytes.
pub const CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT: &[u8] = b"cardano-poe-slots-transcript-v1";

/// HKDF info for the slots-path content `payload_key`. 22 bytes.
pub const CARDANO_POE_HKDF_INFO_PAYLOAD: &[u8] = b"cardano-poe-payload-v1";

/// HKDF info for the passphrase-path content `payload_key`. 33 bytes.
pub const CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE: &[u8] = b"cardano-poe-payload-passphrase-v1";

/// SHA-256 prefix for the hybrid (X-Wing) per-slot KEK HKDF salt. 29 bytes.
pub const CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT: &[u8] = b"cardano-poe-xwing-kek-salt-v1";

/// The passphrase normalization profile identifier. A scheme-1-fixed constant
/// fed into the passphrase content AAD to pin the exact NFKC + whitespace-
/// collapse + trim + UTF-8 profile the CEK was derived under; never serialised
/// on the wire.
pub const CARDANO_POE_PW_NORM_PROFILE: &str = "cardano-poe-pw-norm-v1";

// Internal-label byte-length invariants. Each label is exact ASCII with no
// terminator and no length prefix; the assertions keep the constants in sync
// with the literals every conformant verifier hashes against.
const _: () = {
    assert!(CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT.len() == 31);
    assert!(CARDANO_POE_HKDF_INFO_PAYLOAD.len() == 22);
    assert!(CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE.len() == 33);
    assert!(CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT.len() == 29);
};

/// Maximum slot count a verifier accepts before invoking any KEM/AEAD primitive.
///
/// A deployment-pinned reference resource bound (not a wire field); deployments
/// MAY tighten it. It sits far above the ~16 KiB Cardano transaction-metadata
/// ceiling that bounds honest records, so a conformant record never trips it.
pub const MAX_SLOTS: usize = 1024;

/// Backstop on the decoded envelope's aggregate byte size (nonce + slots_mac +
/// per-slot wire fields) a verifier enforces before any KEM/AEAD primitive.
///
/// A deployment-pinned reference resource bound, tighter than [`MAX_SLOTS`] for
/// honest records.
pub const MAX_DECODED_ENVELOPE_BYTES: usize = 65536;

/// XChaCha20-Poly1305 is a single-shot AEAD over the whole plaintext; its 32-bit
/// internal block counter bounds one (key, nonce) invocation at `2^32` 64-byte
/// ChaCha20 blocks, the first of which is consumed by the Poly1305 one-time key.
/// `MAX_SEALED_PLAINTEXT` is therefore `(2^32 - 1) * 64 = 2^38 - 64` bytes; a
/// plaintext at or above it risks a counter-overflow keystream collision and
/// MUST be rejected before the AEAD is invoked on either side. Identical across
/// every conformant implementation.
pub const MAX_SEALED_PLAINTEXT: u64 = (1 << 38) - 64;

/// Poly1305 appends a 16-byte tag, so the corresponding ciphertext bound is +16.
pub const MAX_SEALED_CIPHERTEXT: u64 = MAX_SEALED_PLAINTEXT + 16;

const _: () = assert!(MAX_SEALED_PLAINTEXT == 274_877_906_880);

/// Reject a plaintext at or above the single-shot keystream capacity before any
/// AEAD call. Thrown on the producer side.
///
/// # Errors
///
/// Returns [`EciesSealedPoeErrorCode::PayloadTooLarge`] when `plaintext_len` is
/// at or above [`MAX_SEALED_PLAINTEXT`].
pub fn assert_plaintext_within_bound(plaintext_len: u64) -> Result<(), EciesSealedPoeError> {
    if plaintext_len >= MAX_SEALED_PLAINTEXT {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::PayloadTooLarge,
            format!(
                "plaintext length {plaintext_len} is at or above the maximum sealed payload size {MAX_SEALED_PLAINTEXT}"
            ),
        ));
    }
    Ok(())
}

/// Reject a ciphertext at or above the single-shot bound before any AEAD open.
/// Thrown on the verifier side. The ciphertext carries the plaintext plus a
/// 16-byte Poly1305 tag.
///
/// # Errors
///
/// Returns [`EciesSealedPoeErrorCode::PayloadTooLarge`] when `ciphertext_len` is
/// at or above [`MAX_SEALED_CIPHERTEXT`].
pub fn assert_ciphertext_within_bound(ciphertext_len: u64) -> Result<(), EciesSealedPoeError> {
    if ciphertext_len >= MAX_SEALED_CIPHERTEXT {
        return Err(EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::PayloadTooLarge,
            format!(
                "ciphertext length {ciphertext_len} is at or above the maximum sealed ciphertext size {MAX_SEALED_CIPHERTEXT}"
            ),
        ));
    }
    Ok(())
}

/// `SHA-256("cardano-poe-slots-transcript-v1" || canonicalEncode(SLOTS_TRANSCRIPT))`.
///
/// `SLOTS_TRANSCRIPT` is the closed six-key map binding the cross-KEM header
/// fields (scheme, path, aead, kem, nonce) to the canonicalised slot set, so a
/// relay that flips any header field while leaving slot shapes valid yields a
/// different `slots_hash` and the MAC fails. Computed ONCE per envelope and held
/// constant across the recipient trial-decrypt loop. The map keys are a SET —
/// their wire order is fixed by the canonical-encode sort, never hand-arranged.
#[must_use]
pub fn compute_slots_hash(kem: &str, nonce: &[u8], slots: &SealedSlots) -> [u8; 32] {
    let transcript = CborValue::Map(vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (CborValue::text("path"), CborValue::text("slots")),
        (
            CborValue::text("aead"),
            CborValue::text(AEAD_XCHACHA20_POLY1305),
        ),
        (CborValue::text("kem"), CborValue::text(kem)),
        (CborValue::text("nonce"), CborValue::Bytes(nonce.to_vec())),
        (CborValue::text("slots"), canonicalize_slots(slots)),
    ]);
    let encoded = encode_canonical_cbor(&transcript)
        .expect("the transcript map has distinct text keys, so encoding cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT);
    hasher.update(&encoded);
    hasher.finalize().into()
}

/// `canonicalEncode(AD_CONTENT_SLOTS)`: the closed seven-key content-AEAD AAD
/// for the slots path. It re-binds the slots-path header AND carries both
/// `slots_hash` (binding to the exact transcript) and `slots_mac` (tying the
/// content layer to the CEK-keyed MAC the recipient matched). Both are
/// deliberate, not redundant.
#[must_use]
pub fn ad_content_slots(kem: &str, nonce: &[u8], slots_hash: &[u8], slots_mac: &[u8]) -> Vec<u8> {
    let ad = CborValue::Map(vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (CborValue::text("path"), CborValue::text("slots")),
        (
            CborValue::text("aead"),
            CborValue::text(AEAD_XCHACHA20_POLY1305),
        ),
        (CborValue::text("kem"), CborValue::text(kem)),
        (CborValue::text("nonce"), CborValue::Bytes(nonce.to_vec())),
        (
            CborValue::text("slots_hash"),
            CborValue::Bytes(slots_hash.to_vec()),
        ),
        (
            CborValue::text("slots_mac"),
            CborValue::Bytes(slots_mac.to_vec()),
        ),
    ]);
    encode_canonical_cbor(&ad).expect("the AAD map has distinct text keys, so encoding cannot fail")
}

/// `canonicalEncode(AD_CONTENT_PASSPHRASE)`: the closed content-AEAD AAD for the
/// passphrase path. It binds the passphrase KDF parameters into the content tag,
/// so tampering with `salt` or any `params` value after encryption changes the
/// AAD and makes the AEAD open fail. The `normalization` profile id is a
/// scheme-fixed constant pinned into the AAD, never serialised on the wire.
/// There is NO `kem` key on this path.
#[must_use]
pub fn ad_content_passphrase(
    nonce: &[u8],
    alg: &str,
    salt: &[u8],
    m: u64,
    t: u64,
    p: u64,
) -> Vec<u8> {
    let passphrase = CborValue::Map(vec![
        (CborValue::text("alg"), CborValue::text(alg)),
        (CborValue::text("salt"), CborValue::Bytes(salt.to_vec())),
        (
            CborValue::text("params"),
            CborValue::Map(vec![
                (CborValue::text("m"), CborValue::Unsigned(m)),
                (CborValue::text("t"), CborValue::Unsigned(t)),
                (CborValue::text("p"), CborValue::Unsigned(p)),
            ]),
        ),
        (
            CborValue::text("normalization"),
            CborValue::text(CARDANO_POE_PW_NORM_PROFILE),
        ),
    ]);
    let ad = CborValue::Map(vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (CborValue::text("path"), CborValue::text("passphrase")),
        (
            CborValue::text("aead"),
            CborValue::text(AEAD_XCHACHA20_POLY1305),
        ),
        (CborValue::text("nonce"), CborValue::Bytes(nonce.to_vec())),
        (CborValue::text("passphrase"), passphrase),
    ]);
    encode_canonical_cbor(&ad).expect("the AAD map has distinct text keys, so encoding cannot fail")
}

/// Slots-path content key: `HKDF-SHA-256(ikm=CEK, salt=nonce, info=payload-v1)`.
///
/// The content is encrypted under this leaf of the CEK, never under the CEK
/// directly, so the wrap layer and the content layer never key the same
/// primitive on the same bytes.
#[must_use]
pub fn slots_payload_key(cek: &[u8], nonce: &[u8]) -> Vec<u8> {
    hkdf_sha256(cek, nonce, CARDANO_POE_HKDF_INFO_PAYLOAD, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum")
}

/// Passphrase-path content key:
/// `HKDF-SHA-256(ikm=CEK, salt=nonce, info=payload-passphrase-v1)`.
#[must_use]
pub fn passphrase_payload_key(cek: &[u8], nonce: &[u8]) -> Vec<u8> {
    hkdf_sha256(cek, nonce, CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE, 32)
        .expect("32-byte HKDF output is within the RFC 5869 maximum")
}

/// Hybrid (mlkem768x25519) per-slot KEK salt:
/// `SHA-256("cardano-poe-xwing-kek-salt-v1" || kem_ct || pub_R)`.
///
/// `kem_ct` is the REASSEMBLED 1120-byte X-Wing ciphertext (anchoring the KEK to
/// a slot-unique value) and `pub_R` the 1216-byte X-Wing recipient public key
/// (binding the KEK to the specific recipient) — the same two bindings the
/// classical `epk || pub_R` salt provides, expressed through a fixed-length
/// SHA-256 digest because the hybrid inputs are oversized.
#[must_use]
pub fn xwing_kek_salt(kem_ct: &[u8], pub_r: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT);
    hasher.update(kem_ct);
    hasher.update(pub_r);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_label_byte_lengths_match_the_protocol() {
        assert_eq!(CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT.len(), 31);
        assert_eq!(CARDANO_POE_HKDF_INFO_PAYLOAD.len(), 22);
        assert_eq!(CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE.len(), 33);
        assert_eq!(CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT.len(), 29);
    }

    #[test]
    fn max_sealed_plaintext_is_two_pow_38_minus_64() {
        assert_eq!(MAX_SEALED_PLAINTEXT, 274_877_906_880);
        assert_eq!(MAX_SEALED_CIPHERTEXT, 274_877_906_880 + 16);
    }

    #[test]
    fn plaintext_bound_rejects_at_or_above_max() {
        assert!(assert_plaintext_within_bound(MAX_SEALED_PLAINTEXT - 1).is_ok());
        let err = assert_plaintext_within_bound(MAX_SEALED_PLAINTEXT).unwrap_err();
        assert_eq!(err.code(), "PAYLOAD_TOO_LARGE");
        let err = assert_plaintext_within_bound(MAX_SEALED_PLAINTEXT + 1).unwrap_err();
        assert_eq!(err.code(), "PAYLOAD_TOO_LARGE");
    }

    #[test]
    fn ciphertext_bound_rejects_at_or_above_max() {
        assert!(assert_ciphertext_within_bound(MAX_SEALED_CIPHERTEXT - 1).is_ok());
        let err = assert_ciphertext_within_bound(MAX_SEALED_CIPHERTEXT).unwrap_err();
        assert_eq!(err.code(), "PAYLOAD_TOO_LARGE");
    }
}
