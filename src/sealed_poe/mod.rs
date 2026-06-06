//! Sealed-PoE cryptographic building blocks: AEAD and the KEM operations.
//!
//! A sealed PoE encrypts content once under a random content-encryption key
//! (CEK) and then wraps that CEK to one or more recipients. This module owns the
//! two lowest layers that machinery is built on:
//!
//! - [`aead`] — the two AEAD ciphers the construction uses: ChaCha20-Poly1305
//!   (12-byte nonce, RFC 8439) for per-recipient CEK wrapping, and
//!   XChaCha20-Poly1305 (24-byte nonce, draft-irtf-cfrg-xchacha) for the
//!   content body.
//! - [`kem`] — the key-encapsulation operations: classical X25519 ECDH (RFC
//!   7748, with the all-zero/small-order rejection the standard requires) and
//!   the X-Wing hybrid KEM (ML-KEM-768 + X25519, draft-connolly-cfrg-xwing-kem,
//!   FIPS 203) used for post-quantum recipients.
//!
//! Every output here is reproduced byte-for-byte by the TypeScript
//! (`@cardanowall/sdk-ts`) and Python (`cardanowall-sdk`) SDKs and is pinned
//! against the shared cross-implementation test vectors. The per-slot wrap /
//! unwrap, the envelope and slot codecs, and the `slots_mac` computation are
//! layered on top of these primitives.

pub mod aead;
pub mod envelope;
pub mod errors;
pub mod kem;
pub mod slots;
pub mod transcript;
pub mod unwrap;
pub mod wrap;

pub use aead::{
    chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, xchacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt, AeadError,
};
pub use kem::{
    mlkem768x25519_decapsulate, mlkem768x25519_encapsulate, mlkem768x25519_public_key_from_seed,
    x25519_ecdh, x25519_ecdh_unvalidated, x25519_public_key, KemError, MLKEM768X25519_ENC_LENGTH,
    MLKEM768X25519_ESEED_LENGTH, MLKEM768X25519_PUBLIC_KEY_LENGTH,
    MLKEM768X25519_SHARED_SECRET_LENGTH, MLKEM768X25519_SK_SEED_LENGTH,
};

pub use envelope::{sealed_envelope_from_parsed, ParsedEnvelope, ParsedSlot};
pub use errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
pub use slots::{
    canonicalize_slots, chunk_kem_ct, join_kem_ct, Mlkem768X25519Slot, SealedEnvelope,
    SealedPoeOutput, SealedSlots, X25519Slot, AEAD_XCHACHA20_POLY1305, KEM_MLKEM768X25519,
    KEM_X25519,
};
pub use transcript::{
    ad_content_passphrase, ad_content_slots, assert_ciphertext_within_bound,
    assert_plaintext_within_bound, compute_slots_hash, passphrase_payload_key, slots_payload_key,
    xwing_kek_salt, CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT,
    CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT, CARDANO_POE_HKDF_INFO_PAYLOAD,
    CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE, CARDANO_POE_PW_NORM_PROFILE,
    MAX_DECODED_ENVELOPE_BYTES, MAX_SEALED_CIPHERTEXT, MAX_SEALED_PLAINTEXT, MAX_SLOTS,
};
pub use unwrap::{
    ecies_sealed_poe_trial_decrypt, ecies_sealed_poe_unwrap, PrivsAttempted, RecipientKeyBundle,
    SlotsAttempted, TrialDecryptKeys, TrialDecryptResult, UnwrapFailureReason, UnwrapKeys,
    UnwrapProbe, UnwrapResult,
};
pub use wrap::{
    ecies_sealed_poe_wrap_secure, ecies_sealed_poe_wrap_with_rng, uniform_index_ceiling,
    RandomSource, SealedKem, WrapArgs, CARDANO_POE_HKDF_INFO_KEK,
    CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, CARDANO_POE_HKDF_INFO_SLOTS_MAC,
};
