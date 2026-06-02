//! Authenticated encryption with associated data (AEAD) for sealed PoE.
//!
//! Two ciphers from the ChaCha20-Poly1305 family are used, and they are NOT
//! interchangeable:
//!
//! - **ChaCha20-Poly1305** (RFC 8439) with a 12-byte nonce — wraps the
//!   content-encryption key (CEK) to each recipient slot.
//! - **XChaCha20-Poly1305** (draft-irtf-cfrg-xchacha) with a 24-byte nonce —
//!   encrypts the content body. The wider nonce lets the content nonce be drawn
//!   at random without a birthday-bound concern.
//!
//! Both follow the same calling convention as the reference SDKs: `seal` takes
//! `(key, nonce, aad, plaintext)` and returns `ciphertext ‖ tag` with the
//! 16-byte Poly1305 tag appended; `open` takes `(key, nonce, aad, ciphertext)`
//! where `ciphertext` is that same appended form, and returns the recovered
//! plaintext or an [`AeadError`] on any authentication failure. Callers treat a
//! failed `open` as a non-match (wrong key / tampered data), never as a crash.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};
use thiserror::Error;

/// Failure to authenticate an AEAD ciphertext.
///
/// Raised by `open` when the Poly1305 tag does not verify under the supplied
/// key, nonce, and associated data — i.e. the ciphertext was tampered with, the
/// nonce or AAD differs from encryption, or the key is wrong. The reference SDKs
/// surface the same single verification-failure condition (`AeadVerificationError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{0} decrypt failed")]
pub struct AeadError(&'static str);

impl AeadError {
    /// The stable error code shared with the reference SDKs.
    pub const CODE: &'static str = "aead_verification_failed";

    /// The stable error code for this failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        Self::CODE
    }
}

/// Encrypt with ChaCha20-Poly1305 (RFC 8439, 12-byte nonce).
///
/// Returns `ciphertext ‖ tag`: the ciphertext with the 16-byte Poly1305 tag
/// appended. The key MUST be 32 bytes and the nonce MUST be 12 bytes; a
/// wrong-length input is caller misuse and surfaces as a panic from the typed
/// arrays, mirroring how the reference SDKs reject malformed key material.
///
/// # Panics
///
/// Panics if `key` is not 32 bytes or `nonce` is not 12 bytes. Encryption
/// itself cannot fail for in-memory buffers of valid length.
#[must_use]
pub fn chacha20_poly1305_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("chacha20-poly1305 encryption cannot fail for an in-memory buffer")
}

/// Decrypt and authenticate a ChaCha20-Poly1305 ciphertext (RFC 8439).
///
/// `ciphertext` is the `ciphertext ‖ tag` form produced by
/// [`chacha20_poly1305_encrypt`]. Returns the recovered plaintext, or
/// [`AeadError`] if the tag does not verify under `key`, `nonce`, and `aad`.
///
/// # Errors
///
/// Returns [`AeadError`] on any authentication failure (tampered ciphertext or
/// tag, wrong nonce, wrong AAD, wrong key, or a too-short input).
///
/// # Panics
///
/// Panics if `key` is not 32 bytes or `nonce` is not 12 bytes (caller misuse).
pub fn chacha20_poly1305_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError("chacha20-poly1305"))
}

/// Encrypt with XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha, 24-byte nonce).
///
/// Returns `ciphertext ‖ tag`: the ciphertext with the 16-byte Poly1305 tag
/// appended. The key MUST be 32 bytes and the nonce MUST be 24 bytes.
///
/// # Panics
///
/// Panics if `key` is not 32 bytes or `nonce` is not 24 bytes (caller misuse).
#[must_use]
pub fn xchacha20_poly1305_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("xchacha20-poly1305 encryption cannot fail for an in-memory buffer")
}

/// Decrypt and authenticate an XChaCha20-Poly1305 ciphertext.
///
/// `ciphertext` is the `ciphertext ‖ tag` form produced by
/// [`xchacha20_poly1305_encrypt`]. Returns the recovered plaintext, or
/// [`AeadError`] if the tag does not verify under `key`, `nonce`, and `aad`.
///
/// # Errors
///
/// Returns [`AeadError`] on any authentication failure (tampered ciphertext or
/// tag, wrong nonce, wrong AAD, wrong key, or a too-short input).
///
/// # Panics
///
/// Panics if `key` is not 32 bytes or `nonce` is not 24 bytes (caller misuse).
pub fn xchacha20_poly1305_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError("xchacha20-poly1305"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic, self-contained sanity checks. Cross-implementation byte
    // parity is proven by the KAT fixtures in `tests/sealed_poe_primitives.rs`.

    #[test]
    fn chacha20_roundtrips_and_appends_a_16_byte_tag() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let aad = b"cardano-poe-kek-v1";
        let plaintext = b"wrap me";
        let sealed = chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);
        assert_eq!(sealed.len(), plaintext.len() + 16);
        let opened = chacha20_poly1305_decrypt(&key, &nonce, aad, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn xchacha20_roundtrips_and_appends_a_16_byte_tag() {
        let key = [9u8; 32];
        let nonce = [4u8; 24];
        let aad = b"content-aad";
        let plaintext = b"seal the content body";
        let sealed = xchacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);
        assert_eq!(sealed.len(), plaintext.len() + 16);
        let opened = xchacha20_poly1305_decrypt(&key, &nonce, aad, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn open_rejects_a_tampered_tag() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let mut sealed = chacha20_poly1305_encrypt(&key, &nonce, b"", b"x");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(
            chacha20_poly1305_decrypt(&key, &nonce, b"", &sealed),
            Err(AeadError("chacha20-poly1305")),
        );
    }

    #[test]
    fn open_rejects_mismatched_aad() {
        let key = [5u8; 32];
        let nonce = [6u8; 24];
        let sealed = xchacha20_poly1305_encrypt(&key, &nonce, b"aad-a", b"x");
        assert!(xchacha20_poly1305_decrypt(&key, &nonce, b"aad-b", &sealed).is_err());
    }

    #[test]
    fn error_carries_the_shared_code() {
        let err = chacha20_poly1305_decrypt(&[0u8; 32], &[0u8; 12], b"", &[0u8; 16]).unwrap_err();
        assert_eq!(err.code(), "aead_verification_failed");
    }
}
