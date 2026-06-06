//! Sealed-PoE wire-shape and input-validation error taxonomy.
//!
//! These are the typed failures the wrap, unwrap, and trial-decrypt paths
//! raise *before* (and around) the cryptographic core: a bad recipient-key
//! length, an unsupported algorithm identifier, a slot field that is the wrong
//! size. They map one-to-one onto the `EciesSealedPoeError` codes the
//! TypeScript and Python SDKs raise, so cross-implementation tests can assert
//! the exact same `code` string.
//!
//! A failed *decryption* (wrong recipient key, a tampered MAC, a tampered
//! ciphertext) is NOT an error here — it is a structured non-match returned by
//! the unwrap path, never an exception. The codes below are reserved for
//! malformed input and unsupported-algorithm conditions the caller can fix.

use thiserror::Error;

/// A sealed-PoE input-validation or wire-shape failure.
///
/// The `code()` accessor yields the stable SCREAMING_SNAKE_CASE string shared
/// with the reference SDKs; the `Display` form adds a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct EciesSealedPoeError {
    /// The stable error code, identical across the TypeScript, Python, and Rust
    /// SDKs.
    pub code: EciesSealedPoeErrorCode,
    /// A human-readable description of the specific failure.
    pub message: String,
}

impl EciesSealedPoeError {
    /// Construct an error with the given code and message.
    pub(crate) fn new(code: EciesSealedPoeErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The stable code string for this error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code.as_str()
    }
}

/// The closed set of sealed-PoE error codes.
///
/// Every variant corresponds to a named code in the TypeScript and Python
/// `EciesSealedPoeErrorCode` union. Decrypt verdicts (`WRONG_RECIPIENT_KEY`,
/// `TAMPERED_HEADER`, `TAMPERED_CIPHERTEXT`) are deliberately absent: they are
/// non-match results, not errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EciesSealedPoeErrorCode {
    /// The recipient/slot count was zero; at least one recipient is required.
    EncSlotsEmpty,
    /// A required `slots` array was absent from the envelope.
    EncSlotsRequired,
    /// A required `slots_mac` field was absent from the envelope.
    EncSlotsMacRequired,
    /// The `slots_mac` was present but not exactly 32 bytes.
    EncSlotsMacInvalidLength,
    /// A recipient public key (wrap) or slot `epk` was the wrong length.
    KemEpkLengthMismatch,
    /// A hybrid slot's `kem_ct` did not reassemble to the 1120-byte X-Wing enc.
    KemCtLengthMismatch,
    /// The content-encryption key was not exactly 32 bytes.
    InvalidCekLength,
    /// The content nonce was not exactly 24 bytes.
    NonceLengthMismatch,
    /// A supplied ephemeral secret / `eseed` was the wrong length.
    InvalidEphemeralSecretLength,
    /// The count of supplied ephemeral secrets / `eseed`s did not match the
    /// recipient count, or an override was supplied for the wrong KEM.
    EphemeralSecretsCountMismatch,
    /// The envelope `scheme` was not the supported value `1`.
    UnsupportedEncVersion,
    /// The envelope `aead` was not `xchacha20-poly1305`.
    UnsupportedAeadAlg,
    /// The envelope `kem` was not `x25519` or `mlkem768x25519`.
    UnsupportedKemAlg,
    /// The parsed envelope shape was structurally invalid.
    InvalidEnvelopeShape,
    /// A recipient secret key was the wrong length, or the unwrap-args form
    /// (single / multi / bundle) was not exactly one non-empty selection.
    InvalidRecipientKey,
    /// A per-slot `wrap` field was not exactly 48 bytes.
    WrapLengthMismatch,
    /// Two slots carry identical per-slot KEM material (a duplicate `epk` for
    /// x25519, or a duplicate reassembled `kem_ct` for the hybrid path). The
    /// zero-nonce per-slot wrap is sound only under per-slot KEK uniqueness;
    /// repeated KEM material derives the same KEK and so repeats the (KEK,
    /// nonce) pair. Rejected on both the producer side (before committing to the
    /// wire) and the verifier side (before any decapsulation).
    EncSlotsDuplicateKemMaterial,
    /// The envelope carried more than `MAX_SLOTS` slots. A resource bound a
    /// public parser enforces before any KEM/AEAD primitive, so a malformed
    /// record cannot drive unbounded per-slot work.
    EncSlotsTooMany,
    /// The decoded envelope's aggregate byte size exceeded
    /// `MAX_DECODED_ENVELOPE_BYTES`. A resource backstop enforced before any
    /// KEM/AEAD primitive.
    EncEnvelopeTooLarge,
    /// A payload at or above the XChaCha20-Poly1305 single-shot keystream bound
    /// (`2^38 - 64` plaintext bytes, `+16` for the ciphertext). Enforced on both
    /// encrypt and decrypt before the AEAD primitive runs.
    PayloadTooLarge,
    /// The operating-system CSPRNG could not be read while drawing the CEK,
    /// content nonce, or per-recipient ephemeral material for a secure wrap.
    /// This is reported, never panicked: a wrap with no entropy must fail
    /// loudly rather than emit a zeroed (globally known) content key.
    ///
    /// This code has no counterpart in the TypeScript / Python SDKs, whose
    /// host runtimes expose an infallible CSPRNG; it is specific to the Rust
    /// secure-by-default wrap, which reads the OS RNG directly.
    RngUnavailable,
}

impl EciesSealedPoeErrorCode {
    /// The stable wire string for this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EncSlotsEmpty => "ENC_SLOTS_EMPTY",
            Self::EncSlotsRequired => "ENC_SLOTS_REQUIRED",
            Self::EncSlotsMacRequired => "ENC_SLOTS_MAC_REQUIRED",
            Self::EncSlotsMacInvalidLength => "ENC_SLOTS_MAC_INVALID_LENGTH",
            Self::KemEpkLengthMismatch => "KEM_EPK_LENGTH_MISMATCH",
            Self::KemCtLengthMismatch => "KEM_CT_LENGTH_MISMATCH",
            Self::InvalidCekLength => "INVALID_CEK_LENGTH",
            Self::NonceLengthMismatch => "NONCE_LENGTH_MISMATCH",
            Self::InvalidEphemeralSecretLength => "INVALID_EPHEMERAL_SECRET_LENGTH",
            Self::EphemeralSecretsCountMismatch => "EPHEMERAL_SECRETS_COUNT_MISMATCH",
            Self::UnsupportedEncVersion => "UNSUPPORTED_ENC_VERSION",
            Self::UnsupportedAeadAlg => "UNSUPPORTED_AEAD_ALG",
            Self::UnsupportedKemAlg => "UNSUPPORTED_KEM_ALG",
            Self::InvalidEnvelopeShape => "INVALID_ENVELOPE_SHAPE",
            Self::InvalidRecipientKey => "INVALID_RECIPIENT_KEY",
            Self::WrapLengthMismatch => "WRAP_LENGTH_MISMATCH",
            Self::EncSlotsDuplicateKemMaterial => "ENC_SLOTS_DUPLICATE_KEM_MATERIAL",
            Self::EncSlotsTooMany => "ENC_SLOTS_TOO_MANY",
            Self::EncEnvelopeTooLarge => "ENC_ENVELOPE_TOO_LARGE",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::RngUnavailable => "RNG_UNAVAILABLE",
        }
    }
}

impl std::fmt::Display for EciesSealedPoeErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
