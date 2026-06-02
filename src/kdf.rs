//! HKDF-SHA256 key derivation (RFC 5869).
//!
//! A single HKDF-SHA256 engine that the identity layer's seed derivation and
//! the sealed-PoE key-wrapping construction both build on. The output is
//! byte-identical to the TypeScript (`@cardanowall/sdk-ts`) and Python
//! (`cardanowall-sdk`) SDKs and is pinned against the shared RFC 5869
//! known-answer-test fixtures.
//!
//! The two-stage RFC 5869 structure is exposed both as the all-in-one
//! [`hkdf_sha256`] and as the separate [`extract`] / [`expand`] stages, mirroring
//! the reference SDKs which call the combined form throughout. Empty-salt and
//! output-length semantics follow RFC 5869 exactly: an empty salt is treated as
//! a string of `HashLen` (32) zero bytes during extraction, and the expansion
//! output length may run up to 255·`HashLen` (8160) bytes.

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

/// SHA-256 produces a 32-byte digest; HKDF-SHA256's PRK and `HashLen` are both
/// this size.
const HASH_LEN: usize = 32;

/// The maximum HKDF expansion output length: RFC 5869 §2.3 caps `L` at
/// `255 * HashLen` octets.
const MAX_OUTPUT_LEN: usize = 255 * HASH_LEN;

/// Error returned when an HKDF derivation is asked for an invalid output length.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HkdfError {
    /// The requested output length exceeds RFC 5869's `255 * HashLen` ceiling
    /// (8160 bytes for SHA-256). Carries the requested length.
    #[error("hkdf-sha256: requested length {0} exceeds the {MAX_OUTPUT_LEN}-byte maximum")]
    OutputTooLong(usize),
}

/// Derive `length` bytes from input keying material via HKDF-SHA256.
///
/// This is the combined extract-then-expand of RFC 5869: it runs [`extract`]
/// over `(salt, ikm)` to obtain a pseudorandom key, then [`expand`] over
/// `(prk, info, length)`. An empty `salt` is the RFC 5869 zero-salt case and is
/// treated as `HashLen` zero bytes during extraction.
///
/// # Errors
///
/// Returns [`HkdfError::OutputTooLong`] when `length` exceeds `255 * HashLen`
/// (8160 bytes).
///
/// ```
/// use cardanowall::kdf::hkdf_sha256;
/// // RFC 5869 test case A.1 (truncated to its first derived byte).
/// let ikm = [0x0b; 22];
/// let salt: Vec<u8> = (0u8..=0x0c).collect();
/// let info: Vec<u8> = (0xf0u8..=0xf9).collect();
/// let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
/// assert_eq!(okm.len(), 42);
/// assert_eq!(okm[0], 0x3c);
/// ```
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, HkdfError> {
    let prk = extract(salt, ikm);
    expand(&prk, info, length)
}

/// HKDF-SHA256 extract stage: derive a 32-byte pseudorandom key from `salt` and
/// input keying material.
///
/// Per RFC 5869 §2.2, `PRK = HMAC-SHA256(salt, ikm)`. An empty `salt` is treated
/// as a string of 32 zero bytes (the `HashLen`-length zero salt), matching the
/// reference SDKs and the `hkdf` crate.
///
/// ```
/// use cardanowall::kdf::{extract, expand};
/// let prk = extract(&[], b"input keying material");
/// assert_eq!(prk.len(), 32);
/// // The PRK feeds the expand stage.
/// let okm = expand(&prk, b"context", 16).unwrap();
/// assert_eq!(okm.len(), 16);
/// ```
#[must_use]
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    // `Hkdf::extract` with `Some(&[])` and `None` both yield the RFC 5869
    // zero-salt PRK; pass the salt through unconditionally so an empty slice is
    // handled by the crate's zero-salt rule rather than a branch here.
    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// HKDF-SHA256 expand stage: stretch a 32-byte pseudorandom key into `length`
/// output bytes bound to `info`.
///
/// Per RFC 5869 §2.3, the output is the truncation of
/// `T(1) ‖ T(2) ‖ …` where `T(i) = HMAC-SHA256(prk, T(i-1) ‖ info ‖ i)`.
///
/// # Errors
///
/// Returns [`HkdfError::OutputTooLong`] when `length` exceeds `255 * HashLen`
/// (8160 bytes), the RFC 5869 ceiling.
pub fn expand(prk: &[u8; HASH_LEN], info: &[u8], length: usize) -> Result<Vec<u8>, HkdfError> {
    if length > MAX_OUTPUT_LEN {
        return Err(HkdfError::OutputTooLong(length));
    }
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("a 32-byte PRK is always a valid SHA-256 PRK");
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .expect("length is bounded above by the RFC 5869 maximum checked above");
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_then_expand_equals_combined() {
        let ikm = b"the quick brown fox";
        let salt = b"some salt";
        let info = b"context label";
        let combined = hkdf_sha256(ikm, salt, info, 40).unwrap();
        let prk = extract(salt, ikm);
        let staged = expand(&prk, info, 40).unwrap();
        assert_eq!(combined, staged);
    }

    #[test]
    fn empty_salt_is_the_zero_salt_case() {
        // RFC 5869 treats an absent salt as HashLen zero bytes; an explicit
        // empty slice must derive the same bytes as an explicit 32-zero salt.
        let ikm = b"input keying material";
        let info = b"info";
        let with_empty = hkdf_sha256(ikm, &[], info, 32).unwrap();
        let with_zeros = hkdf_sha256(ikm, &[0u8; 32], info, 32).unwrap();
        assert_eq!(with_empty, with_zeros);
    }

    #[test]
    fn output_length_is_respected() {
        let okm = hkdf_sha256(b"ikm", b"salt", b"info", 7).unwrap();
        assert_eq!(okm.len(), 7);
        let okm = hkdf_sha256(b"ikm", b"salt", b"info", 0).unwrap();
        assert_eq!(okm.len(), 0);
    }

    #[test]
    fn rejects_over_long_output() {
        let too_long = MAX_OUTPUT_LEN + 1;
        assert_eq!(
            hkdf_sha256(b"ikm", b"salt", b"info", too_long),
            Err(HkdfError::OutputTooLong(too_long)),
        );
        // The exact ceiling is allowed.
        assert!(hkdf_sha256(b"ikm", b"salt", b"info", MAX_OUTPUT_LEN).is_ok());
    }
}
