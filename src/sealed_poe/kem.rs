//! Key-encapsulation operations for sealed PoE.
//!
//! Two KEM families are supported:
//!
//! - **X25519** (RFC 7748) — classical Diffie-Hellman used by `age`-style
//!   recipient slots. The secret scalar is stored raw/unclamped; X25519 clamps
//!   internally at multiply time.
//! - **X-Wing** (`mlkem768x25519`) — the hybrid post-quantum KEM combining
//!   ML-KEM-768 (FIPS 203) and X25519 per draft-connolly-cfrg-xwing-kem. An
//!   attacker must break both components to recover the shared secret.
//!
//! Every value here matches the TypeScript and Python SDKs byte-for-byte and is
//! pinned against the shared cross-implementation KAT vectors. The X-Wing
//! combiner and the seed/eseed split orders are the highest-risk parity
//! surfaces in the whole SDK, so they are spelled out explicitly below rather
//! than delegated to a third-party crate.

use ml_kem::array::sizes::U64;
use ml_kem::array::Array;
use ml_kem::kem::Decapsulate;
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};
use sha3::digest::{ExtendableOutput, Update as _, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use x25519_dalek::x25519;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Serialized length of an X-Wing public key: ML-KEM-768 encapsulation key
/// (1184 bytes) followed by the X25519 public key (32 bytes).
pub const MLKEM768X25519_PUBLIC_KEY_LENGTH: usize = 1216;

/// Serialized length of an X-Wing ciphertext: ML-KEM-768 ciphertext (1088
/// bytes) followed by the X25519 ephemeral public key (32 bytes).
pub const MLKEM768X25519_ENC_LENGTH: usize = 1120;

/// Length of an X-Wing shared secret in bytes.
pub const MLKEM768X25519_SHARED_SECRET_LENGTH: usize = 32;

/// Length of the X-Wing secret seed (the secret key) in bytes.
pub const MLKEM768X25519_SK_SEED_LENGTH: usize = 32;

/// Length of the X-Wing encapsulation randomness (`eseed`) in bytes: the ML-KEM
/// message (32 bytes) followed by the X25519 ephemeral scalar (32 bytes).
pub const MLKEM768X25519_ESEED_LENGTH: usize = 64;

/// Length of an X25519 secret scalar or public key, in bytes.
pub const X25519_KEY_LENGTH: usize = 32;

/// Length of the FIPS 203 ML-KEM-768 encapsulation key in bytes.
const MLKEM_EK_LENGTH: usize = 1184;

/// Length of the FIPS 203 ML-KEM-768 ciphertext in bytes.
const MLKEM_CT_LENGTH: usize = 1088;

/// Length of the X-Wing SHAKE-256 seed expansion: ML-KEM keygen coins `d ‖ z`
/// (64 bytes) followed by the raw X25519 secret scalar (32 bytes).
const XWING_EXPANDED_SEED_LENGTH: usize = 96;

/// The X-Wing combiner's domain-separation label: the six ASCII bytes
/// `\.//^\` (`5c 2e 2f 2f 5e 5c`). Concatenated last into the SHA3-256 preimage,
/// it binds the derived secret to the X-Wing construction so the same component
/// secrets cannot be replayed under another KEM.
const XWING_COMBINER_LABEL: &[u8] = &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// Errors raised by the KEM operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KemError {
    /// The X25519 shared secret was the all-zero value, which RFC 7748 §6.1
    /// requires be rejected: the peer public key is a small-order (low-order)
    /// Montgomery point. Trial-decrypt treats this as a non-match, not a crash.
    #[error("x25519 ECDH rejected: peer public key is a small-order point")]
    X25519LowOrderPoint,
    /// An X25519 secret scalar or public key was not exactly 32 bytes.
    #[error("x25519 key must be 32 bytes, got {0}")]
    InvalidX25519KeyLength(usize),
    /// An X-Wing public key was not exactly [`MLKEM768X25519_PUBLIC_KEY_LENGTH`]
    /// bytes.
    #[error("mlkem768x25519 public key must be 1216 bytes, got {0}")]
    InvalidPublicKeyLength(usize),
    /// An X-Wing ciphertext (`enc`) was not exactly [`MLKEM768X25519_ENC_LENGTH`]
    /// bytes.
    #[error("mlkem768x25519 enc must be 1120 bytes, got {0}")]
    InvalidEncLength(usize),
    /// An X-Wing secret seed was not exactly [`MLKEM768X25519_SK_SEED_LENGTH`]
    /// bytes.
    #[error("mlkem768x25519 secret seed must be 32 bytes, got {0}")]
    InvalidSecretSeedLength(usize),
    /// An X-Wing `eseed` was supplied but was not exactly
    /// [`MLKEM768X25519_ESEED_LENGTH`] bytes.
    #[error("mlkem768x25519 eseed must be 64 bytes, got {0}")]
    InvalidEseedLength(usize),
    /// The ML-KEM-768 encapsulation key embedded in the X-Wing public key failed
    /// FIPS 203 modulus validation.
    #[error("mlkem768x25519 public key contains an invalid ML-KEM-768 encapsulation key")]
    InvalidMlKemEncapsulationKey,
}

/// Compute the X25519 public key for a raw 32-byte secret scalar (RFC 7748).
///
/// The scalar may be (and in this SDK is) unclamped; X25519 clamps internally
/// during the base-point multiply.
///
/// # Errors
///
/// Returns [`KemError::InvalidX25519KeyLength`] if `secret_key` is not 32 bytes.
pub fn x25519_public_key(secret_key: &[u8]) -> Result<[u8; 32], KemError> {
    let scalar =
        to_array32(secret_key).ok_or(KemError::InvalidX25519KeyLength(secret_key.len()))?;
    Ok(x25519(scalar, x25519_dalek::X25519_BASEPOINT_BYTES))
}

/// Perform an X25519 Diffie-Hellman exchange (RFC 7748).
///
/// Computes the shared secret of `secret_key` (a raw scalar) with
/// `their_public_key`. Implements the RFC 7748 §6.1 contributory check: an
/// all-zero shared secret — which a small-order peer public key produces — is
/// rejected. `x25519-dalek` does not signal this itself, so the all-zero result
/// is detected here in constant time and turned into
/// [`KemError::X25519LowOrderPoint`].
///
/// # Errors
///
/// Returns [`KemError::InvalidX25519KeyLength`] for a wrong-length input, or
/// [`KemError::X25519LowOrderPoint`] when the exchange yields the all-zero
/// shared secret.
pub fn x25519_ecdh(secret_key: &[u8], their_public_key: &[u8]) -> Result<[u8; 32], KemError> {
    let scalar =
        to_array32(secret_key).ok_or(KemError::InvalidX25519KeyLength(secret_key.len()))?;
    let point = to_array32(their_public_key)
        .ok_or(KemError::InvalidX25519KeyLength(their_public_key.len()))?;
    let shared = x25519(scalar, point);
    // RFC 7748 §6.1: a small-order peer point drives the shared secret to all
    // zeros. Reject it in constant time so the check does not leak whether a
    // given slot reached the all-zero branch.
    if shared.ct_eq(&[0u8; 32]).into() {
        return Err(KemError::X25519LowOrderPoint);
    }
    Ok(shared)
}

/// Perform an X25519 Diffie-Hellman exchange WITHOUT the RFC 7748 §6.1 all-zero
/// rejection, returning both the raw shared secret and a constant-time validity
/// bit (`kem_ok`).
///
/// `x25519-dalek` does not throw on a small-order peer point — it returns the
/// all-zero shared secret — so the trial-decrypt path can fold the validity bit
/// into the per-slot acceptance branchlessly (a dummy KEK derived from `0^32`
/// keeps the failed slot's work identical) rather than early-returning an error.
/// `kem_ok` is `false` exactly when the shared secret is all-zero. The producer
/// path uses the rejecting [`x25519_ecdh`] instead; this non-rejecting form is
/// for the verifier's constant-time slot loop.
///
/// # Errors
///
/// Returns [`KemError::InvalidX25519KeyLength`] for a wrong-length input.
pub fn x25519_ecdh_unvalidated(
    secret_key: &[u8],
    their_public_key: &[u8],
) -> Result<([u8; 32], Choice), KemError> {
    let scalar =
        to_array32(secret_key).ok_or(KemError::InvalidX25519KeyLength(secret_key.len()))?;
    let point = to_array32(their_public_key)
        .ok_or(KemError::InvalidX25519KeyLength(their_public_key.len()))?;
    let shared = x25519(scalar, point);
    // kem_ok = NOT (shared == 0^32), computed in constant time.
    let kem_ok = !shared.ct_eq(&[0u8; 32]);
    Ok((shared, kem_ok))
}

/// An X-Wing encapsulation result: the ciphertext and the derived shared secret.
///
/// The 32-byte `ss` is the secret the caller wraps the CEK under; it is wiped
/// on drop so a forgotten `Mlkem768X25519Encapsulation` does not leave the
/// shared secret in freed memory. The `enc` ciphertext is public and is not
/// zeroized (wiping it would cost 1120 bytes per drop for no secrecy gain).
#[derive(Clone, ZeroizeOnDrop)]
pub struct Mlkem768X25519Encapsulation {
    /// The 1120-byte X-Wing ciphertext (`ct_mlkem ‖ ct_x25519`).
    #[zeroize(skip)]
    pub enc: [u8; MLKEM768X25519_ENC_LENGTH],
    /// The 32-byte shared secret. Wiped on drop.
    pub ss: [u8; MLKEM768X25519_SHARED_SECRET_LENGTH],
}

/// Encapsulate to an X-Wing (`mlkem768x25519`) public key.
///
/// `public_key` is the 1216-byte X-Wing public key (`ek_mlkem ‖ pk_x25519`).
/// `eseed` is the 64-byte encapsulation randomness; when supplied the result is
/// fully deterministic (the ML-KEM message is `eseed[0..32]`, the X25519
/// ephemeral scalar is `eseed[32..64]`). Returns the 1120-byte ciphertext and
/// the 32-byte shared secret.
///
/// # Errors
///
/// Returns [`KemError::InvalidPublicKeyLength`] for a wrong-length public key,
/// [`KemError::InvalidEseedLength`] for a wrong-length `eseed`, or
/// [`KemError::InvalidMlKemEncapsulationKey`] if the embedded ML-KEM key is
/// malformed.
pub fn mlkem768x25519_encapsulate(
    public_key: &[u8],
    eseed: &[u8],
) -> Result<Mlkem768X25519Encapsulation, KemError> {
    if public_key.len() != MLKEM768X25519_PUBLIC_KEY_LENGTH {
        return Err(KemError::InvalidPublicKeyLength(public_key.len()));
    }
    if eseed.len() != MLKEM768X25519_ESEED_LENGTH {
        return Err(KemError::InvalidEseedLength(eseed.len()));
    }

    let ek_mlkem = &public_key[..MLKEM_EK_LENGTH];
    let pk_x25519 = &public_key[MLKEM_EK_LENGTH..];
    let mlkem_message = &eseed[..32];
    let mut x_ephemeral_scalar = to_array32(&eseed[32..]).expect("eseed tail is exactly 32 bytes");

    // ML-KEM-768 deterministic encapsulation against the embedded ek.
    let ek_key = <&Array<u8, _>>::try_from(ek_mlkem)
        .expect("the ML-KEM encapsulation key slice is exactly 1184 bytes");
    let ek = EncapsulationKey::<MlKem768>::new(ek_key)
        .map_err(|_| KemError::InvalidMlKemEncapsulationKey)?;
    let m: Array<u8, _> =
        Array::try_from(mlkem_message).expect("the ML-KEM message slice is exactly 32 bytes");
    let (ct_mlkem, mlkem_ss_array) = ek.encapsulate_deterministic(&m);
    // Copy the ML-KEM shared secret into a local that we wipe; the source Array
    // is owned here and goes out of scope at function end, but it carries no
    // zeroize-on-drop guarantee of its own, so wipe it explicitly too.
    let mut ss_mlkem =
        to_array32(mlkem_ss_array.as_slice()).expect("ML-KEM shared key is 32 bytes");
    let mut mlkem_ss_array = mlkem_ss_array;
    mlkem_ss_array.as_mut_slice().zeroize();

    // X25519 ephemeral against the recipient's X25519 public key. X-Wing does
    // NOT reject a small-order peer point here: a degenerate (all-zero) ss_X
    // still yields a defined hybrid secret once mixed with ss_M in the combiner,
    // and the interoperability vectors depend on this raw, non-rejecting form.
    let ct_x25519 = x25519(x_ephemeral_scalar, x25519_dalek::X25519_BASEPOINT_BYTES);
    let mut ss_x25519 = x25519(
        x_ephemeral_scalar,
        to_array32(pk_x25519).expect("pk tail is 32 bytes"),
    );
    x_ephemeral_scalar.zeroize();

    let mut enc = [0u8; MLKEM768X25519_ENC_LENGTH];
    enc[..MLKEM_CT_LENGTH].copy_from_slice(ct_mlkem.as_slice());
    enc[MLKEM_CT_LENGTH..].copy_from_slice(&ct_x25519);

    let ss = xwing_combine(&ss_mlkem, &ss_x25519, &ct_x25519, pk_x25519);
    // Wipe both component secrets; only the combined `ss` escapes.
    ss_mlkem.zeroize();
    ss_x25519.zeroize();
    Ok(Mlkem768X25519Encapsulation { enc, ss })
}

/// Recompute the 1216-byte X-Wing (`mlkem768x25519`) public key from a 32-byte
/// secret seed.
///
/// The seed is expanded with SHAKE-256 to 96 bytes, split as the ML-KEM-768
/// keygen coins `d ‖ z` (the first 64 bytes) and the raw X25519 secret scalar
/// (the last 32 bytes), per draft-connolly-cfrg-xwing-kem. The result is the
/// FIPS 203 ML-KEM-768 encapsulation key (1184 bytes) followed by the X25519
/// public key (32 bytes) — the same `pub_R` the producer bound into every hybrid
/// slot's KEK salt. The verifier recomputes it ONCE per private key in the
/// trial-decrypt scan, since the hybrid KEK salt depends on it.
///
/// # Errors
///
/// Returns [`KemError::InvalidSecretSeedLength`] when `secret_seed` is not
/// exactly [`MLKEM768X25519_SK_SEED_LENGTH`] bytes.
pub fn mlkem768x25519_public_key_from_seed(
    secret_seed: &[u8],
) -> Result<[u8; MLKEM768X25519_PUBLIC_KEY_LENGTH], KemError> {
    if secret_seed.len() != MLKEM768X25519_SK_SEED_LENGTH {
        return Err(KemError::InvalidSecretSeedLength(secret_seed.len()));
    }
    let seed = to_array32(secret_seed).expect("secret seed length checked above");
    let mut expanded = expand_xwing_seed(&seed);

    // ML-KEM-768 deterministic keygen consumes the 64-byte `d ‖ z` prefix.
    let mlkem_seed: Array<u8, U64> =
        Array::try_from(&expanded[0..64]).expect("the expansion yields a 64-byte ML-KEM seed");
    let dk = DecapsulationKey::<MlKem768>::from_seed(mlkem_seed);
    let ek_bytes = dk.encapsulation_key().to_bytes();

    // The trailing 32 bytes are the raw, unclamped X25519 scalar.
    let mut x_scalar = to_array32(&expanded[64..96]).expect("the expansion tail is 32 bytes");
    let pk_x25519 = x25519(x_scalar, x25519_dalek::X25519_BASEPOINT_BYTES);

    let mut public_key = [0u8; MLKEM768X25519_PUBLIC_KEY_LENGTH];
    public_key[..MLKEM_EK_LENGTH].copy_from_slice(ek_bytes.as_slice());
    public_key[MLKEM_EK_LENGTH..].copy_from_slice(&pk_x25519);

    expanded.zeroize();
    x_scalar.zeroize();
    Ok(public_key)
}

/// Decapsulate an X-Wing (`mlkem768x25519`) ciphertext.
///
/// `secret_seed` is the 32-byte X-Wing secret key (the root seed); `enc` is the
/// 1120-byte ciphertext. The ML-KEM decapsulation key and X25519 scalar are
/// re-expanded from the seed via SHAKE-256, then ML-KEM and X25519 are
/// decapsulated and recombined. ML-KEM's implicit rejection means a corrupted
/// ciphertext yields a pseudorandom (but deterministic) secret rather than an
/// error, so this never fails on bad ciphertext *content* — only on a
/// structurally wrong-length input.
///
/// # Errors
///
/// Returns [`KemError::InvalidSecretSeedLength`] or [`KemError::InvalidEncLength`]
/// for a wrong-length input.
pub fn mlkem768x25519_decapsulate(secret_seed: &[u8], enc: &[u8]) -> Result<[u8; 32], KemError> {
    if secret_seed.len() != MLKEM768X25519_SK_SEED_LENGTH {
        return Err(KemError::InvalidSecretSeedLength(secret_seed.len()));
    }
    if enc.len() != MLKEM768X25519_ENC_LENGTH {
        return Err(KemError::InvalidEncLength(enc.len()));
    }

    let seed = to_array32(secret_seed).expect("secret seed length checked above");
    let mut expanded = expand_xwing_seed(&seed);
    // ML-KEM keygen coins `d ‖ z` are the first 64 bytes; the raw X25519 scalar
    // is the last 32.
    let mlkem_seed: Array<u8, U64> =
        Array::try_from(&expanded[0..64]).expect("the expansion yields a 64-byte ML-KEM seed");
    let dk = DecapsulationKey::<MlKem768>::from_seed(mlkem_seed);
    let mut x_scalar = to_array32(&expanded[64..96]).expect("the expansion tail is 32 bytes");
    let pk_x25519 = x25519(x_scalar, x25519_dalek::X25519_BASEPOINT_BYTES);

    let ct_mlkem = &enc[..MLKEM_CT_LENGTH];
    let ct_x25519 = &enc[MLKEM_CT_LENGTH..];

    // ML-KEM-768 decapsulation: constant-work implicit rejection, never errors
    // on a valid-length ciphertext.
    let mlkem_ss_array = dk
        .decapsulate_slice(ct_mlkem)
        .expect("the ML-KEM ciphertext slice is exactly 1088 bytes");
    let mut ss_mlkem =
        to_array32(mlkem_ss_array.as_slice()).expect("ML-KEM shared key is 32 bytes");
    let mut mlkem_ss_array = mlkem_ss_array;
    mlkem_ss_array.as_mut_slice().zeroize();
    let mut ss_x25519 = x25519(
        x_scalar,
        to_array32(ct_x25519).expect("ct tail is 32 bytes"),
    );

    let ss = xwing_combine(&ss_mlkem, &ss_x25519, ct_x25519, &pk_x25519);

    // Wipe both component secrets and the expanded keygen material; only the
    // combined `ss` escapes.
    ss_mlkem.zeroize();
    ss_x25519.zeroize();
    expanded.zeroize();
    x_scalar.zeroize();
    Ok(ss)
}

/// The X-Wing shared-secret combiner.
///
/// Per draft-connolly-cfrg-xwing-kem, the shared secret is the **fixed-length**
/// SHA3-256 digest (NOT SHAKE-256) of
/// `ss_mlkem ‖ ss_x25519 ‖ ct_x25519 ‖ pk_x25519 ‖ label`, where `label` is the
/// six bytes [`XWING_COMBINER_LABEL`]. Only the X25519 component's ciphertext
/// and public key enter the preimage; the ML-KEM ciphertext and key are bound
/// indirectly through `ss_mlkem`.
fn xwing_combine(
    ss_mlkem: &[u8],
    ss_x25519: &[u8],
    ct_x25519: &[u8],
    pk_x25519: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, ss_mlkem);
    Digest::update(&mut hasher, ss_x25519);
    Digest::update(&mut hasher, ct_x25519);
    Digest::update(&mut hasher, pk_x25519);
    Digest::update(&mut hasher, XWING_COMBINER_LABEL);
    hasher.finalize().into()
}

/// Expand a 32-byte X-Wing root seed into the 96-byte keygen material via
/// SHAKE-256 (`d ‖ z` for ML-KEM, then the raw X25519 scalar).
fn expand_xwing_seed(seed: &[u8; 32]) -> [u8; XWING_EXPANDED_SEED_LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut expanded = [0u8; XWING_EXPANDED_SEED_LENGTH];
    reader.read(&mut expanded);
    expanded
}

/// Copy a 32-byte slice into a fixed array, returning `None` for any other
/// length.
fn to_array32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_rejects_the_all_zero_point() {
        // The all-zero u-coordinate is the order-1 point; ECDH yields the
        // all-zero shared secret, which RFC 7748 §6.1 requires be rejected.
        let secret = [9u8; 32];
        assert_eq!(
            x25519_ecdh(&secret, &[0u8; 32]),
            Err(KemError::X25519LowOrderPoint),
        );
    }

    #[test]
    fn x25519_rejects_wrong_length_keys() {
        assert_eq!(
            x25519_public_key(&[0u8; 31]),
            Err(KemError::InvalidX25519KeyLength(31))
        );
        assert_eq!(
            x25519_ecdh(&[0u8; 33], &[0u8; 32]),
            Err(KemError::InvalidX25519KeyLength(33)),
        );
    }

    #[test]
    fn x25519_roundtrips_between_two_parties() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let alice_pub = x25519_public_key(&alice).unwrap();
        let bob_pub = x25519_public_key(&bob).unwrap();
        let from_alice = x25519_ecdh(&alice, &bob_pub).unwrap();
        let from_bob = x25519_ecdh(&bob, &alice_pub).unwrap();
        assert_eq!(from_alice, from_bob);
    }

    #[test]
    fn xwing_encaps_decaps_agree() {
        // Derive an X-Wing keypair from a known seed via the documented keygen
        // path, then check that encaps + decaps recover the same secret.
        let seed = [42u8; 32];
        let expanded = expand_xwing_seed(&seed);
        let mlkem_seed: Array<u8, U64> = Array::try_from(&expanded[0..64]).unwrap();
        let dk = DecapsulationKey::<MlKem768>::from_seed(mlkem_seed);
        let ek_bytes = dk.encapsulation_key().to_bytes();
        let pk_x25519 = x25519_public_key(&expanded[64..96]).unwrap();
        let mut public_key = [0u8; MLKEM768X25519_PUBLIC_KEY_LENGTH];
        public_key[..MLKEM_EK_LENGTH].copy_from_slice(ek_bytes.as_slice());
        public_key[MLKEM_EK_LENGTH..].copy_from_slice(&pk_x25519);

        let eseed = [7u8; 64];
        let encaps = mlkem768x25519_encapsulate(&public_key, &eseed).unwrap();
        let recovered = mlkem768x25519_decapsulate(&seed, &encaps.enc).unwrap();
        assert_eq!(recovered, encaps.ss);
    }

    #[test]
    fn xwing_rejects_wrong_length_inputs() {
        assert_eq!(
            mlkem768x25519_encapsulate(&[0u8; 1215], &[0u8; 64]).err(),
            Some(KemError::InvalidPublicKeyLength(1215)),
        );
        assert_eq!(
            mlkem768x25519_encapsulate(&[0u8; 1216], &[0u8; 63]).err(),
            Some(KemError::InvalidEseedLength(63)),
        );
        assert_eq!(
            mlkem768x25519_decapsulate(&[0u8; 31], &[0u8; 1120]),
            Err(KemError::InvalidSecretSeedLength(31)),
        );
        assert_eq!(
            mlkem768x25519_decapsulate(&[0u8; 32], &[0u8; 1119]),
            Err(KemError::InvalidEncLength(1119)),
        );
    }
}
