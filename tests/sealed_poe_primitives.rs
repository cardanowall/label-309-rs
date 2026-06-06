//! Byte-parity tests for the sealed-PoE cryptographic primitives.
//!
//! Pins every vector in the shared AEAD and KEM fixtures — the same JSON the
//! TypeScript and Python SDKs load. Passing them proves this crate reproduces
//! the ChaCha20-Poly1305 / XChaCha20-Poly1305 ciphertexts, the X25519 ECDH
//! shared secrets (and the RFC 7748 §6.1 all-zero rejection), and the X-Wing
//! hybrid ciphertext + shared-secret combiner byte-for-byte. The X-Wing encaps
//! and decaps vectors are the make-or-break parity surface for the whole SDK.

mod common;

use cardanowall::hex;
use cardanowall::sealed_poe::aead::{
    chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, xchacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt,
};
use cardanowall::sealed_poe::kem::{
    mlkem768x25519_decapsulate, mlkem768x25519_encapsulate, x25519_ecdh, x25519_public_key,
    KemError,
};
use cardanowall::seed_derive::xwing_keygen;
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;
use std::path::PathBuf;

fn aead_fixture(name: &str) -> Value {
    read_fixture_json(&crypto_core_fixtures().join("aead").join(name))
}

fn kem_fixture(name: &str) -> Value {
    read_fixture_json(&crypto_core_fixtures().join("kem").join(name))
}

fn vectors(fixture: &Value) -> &Vec<Value> {
    fixture["vectors"]
        .as_array()
        .expect("fixture must carry a `vectors` array")
}

fn field<'a>(vector: &'a Value, key: &str) -> &'a str {
    vector[key]
        .as_str()
        .unwrap_or_else(|| panic!("vector field `{key}` must be a string: {vector}"))
}

fn bytes(vector: &Value, key: &str) -> Vec<u8> {
    hex::decode(field(vector, key)).unwrap_or_else(|e| panic!("bad hex in `{key}`: {e}"))
}

// --------------------------------------------------------------------------
// AEAD parity
// --------------------------------------------------------------------------

/// Drive both directions of one ChaCha20-Poly1305 vector and pin the exact
/// `ciphertext ‖ tag` and the recovered plaintext.
fn assert_chacha20_vector(vector: &Value) {
    let name = field(vector, "name");
    let key = bytes(vector, "key_hex");
    let nonce = bytes(vector, "nonce_hex");
    let aad = bytes(vector, "aad_hex");
    let plaintext = bytes(vector, "plaintext_hex");
    let expected_hex = field(vector, "expected_ciphertext_with_tag_hex");

    let sealed = chacha20_poly1305_encrypt(&key, &nonce, &aad, &plaintext);
    assert_eq!(hex::encode(&sealed), expected_hex, "{name}: ciphertext+tag");

    let opened = chacha20_poly1305_decrypt(&key, &nonce, &aad, &hex::decode(expected_hex).unwrap())
        .unwrap_or_else(|e| panic!("{name}: decrypt failed: {e}"));
    assert_eq!(
        hex::encode(&opened),
        field(vector, "plaintext_hex"),
        "{name}: plaintext"
    );
}

/// Drive both directions of one XChaCha20-Poly1305 vector.
fn assert_xchacha20_vector(vector: &Value) {
    let name = field(vector, "name");
    let key = bytes(vector, "key_hex");
    let nonce = bytes(vector, "nonce_hex");
    let aad = bytes(vector, "aad_hex");
    let plaintext = bytes(vector, "plaintext_hex");
    let expected_hex = field(vector, "expected_ciphertext_with_tag_hex");

    let sealed = xchacha20_poly1305_encrypt(&key, &nonce, &aad, &plaintext);
    assert_eq!(hex::encode(&sealed), expected_hex, "{name}: ciphertext+tag");

    let opened =
        xchacha20_poly1305_decrypt(&key, &nonce, &aad, &hex::decode(expected_hex).unwrap())
            .unwrap_or_else(|e| panic!("{name}: decrypt failed: {e}"));
    assert_eq!(
        hex::encode(&opened),
        field(vector, "plaintext_hex"),
        "{name}: plaintext"
    );
}

#[test]
fn chacha20_poly1305_rfc8439_kat() {
    let corpus = aead_fixture("chacha20-poly1305-rfc8439-kat.json");
    let vectors = vectors(&corpus);
    assert_eq!(vectors.len(), 1, "chacha20 RFC 8439 KAT vector count");
    for vector in vectors {
        assert_chacha20_vector(vector);
    }
}

#[test]
fn chacha20_poly1305_roundtrip_vectors() {
    let corpus = aead_fixture("chacha20-poly1305-roundtrip.json");
    let vectors = vectors(&corpus);
    assert_eq!(vectors.len(), 6, "chacha20 roundtrip vector count");
    for vector in vectors {
        assert_chacha20_vector(vector);
    }
}

#[test]
fn xchacha20_poly1305_draft_kat() {
    let corpus = aead_fixture("xchacha20-poly1305-draft-irtf-cfrg-xchacha-03-kat.json");
    let vectors = vectors(&corpus);
    assert_eq!(vectors.len(), 1, "xchacha20 draft KAT vector count");
    for vector in vectors {
        assert_xchacha20_vector(vector);
    }
}

#[test]
fn xchacha20_poly1305_roundtrip_vectors() {
    let corpus = aead_fixture("xchacha20-poly1305-roundtrip.json");
    let vectors = vectors(&corpus);
    assert_eq!(vectors.len(), 7, "xchacha20 roundtrip vector count");
    for vector in vectors {
        assert_xchacha20_vector(vector);
    }
}

#[test]
fn chacha20_open_rejects_every_mutation() {
    // Reproduce the reference SDK's tamper matrix against a fixed vector: any
    // change to ciphertext, tag, nonce, AAD, or key must fail authentication.
    let corpus = aead_fixture("chacha20-poly1305-rfc8439-kat.json");
    let vector = &vectors(&corpus)[0];
    let key = bytes(vector, "key_hex");
    let nonce = bytes(vector, "nonce_hex");
    let aad = bytes(vector, "aad_hex");
    let sealed = bytes(vector, "expected_ciphertext_with_tag_hex");

    // Sanity: the untouched ciphertext opens.
    assert!(chacha20_poly1305_decrypt(&key, &nonce, &aad, &sealed).is_ok());

    let flip = |buf: &[u8], i: usize| {
        let mut out = buf.to_vec();
        out[i] ^= 0x01;
        out
    };
    // Flip the first ciphertext byte and the last (tag) byte.
    assert!(chacha20_poly1305_decrypt(&key, &nonce, &aad, &flip(&sealed, 0)).is_err());
    assert!(
        chacha20_poly1305_decrypt(&key, &nonce, &aad, &flip(&sealed, sealed.len() - 1)).is_err()
    );
    // Flip the nonce, the AAD, the key.
    assert!(chacha20_poly1305_decrypt(&key, &flip(&nonce, 0), &aad, &sealed).is_err());
    assert!(chacha20_poly1305_decrypt(&key, &nonce, &flip(&aad, 0), &sealed).is_err());
    assert!(chacha20_poly1305_decrypt(&flip(&key, 0), &nonce, &aad, &sealed).is_err());
    // Truncate by one byte (loses part of the tag).
    assert!(chacha20_poly1305_decrypt(&key, &nonce, &aad, &sealed[..sealed.len() - 1]).is_err());
}

#[test]
fn xchacha20_open_rejects_every_mutation() {
    let corpus = aead_fixture("xchacha20-poly1305-draft-irtf-cfrg-xchacha-03-kat.json");
    let vector = &vectors(&corpus)[0];
    let key = bytes(vector, "key_hex");
    let nonce = bytes(vector, "nonce_hex");
    let aad = bytes(vector, "aad_hex");
    let sealed = bytes(vector, "expected_ciphertext_with_tag_hex");

    assert!(xchacha20_poly1305_decrypt(&key, &nonce, &aad, &sealed).is_ok());

    let flip = |buf: &[u8], i: usize| {
        let mut out = buf.to_vec();
        out[i] ^= 0x01;
        out
    };
    assert!(xchacha20_poly1305_decrypt(&key, &nonce, &aad, &flip(&sealed, 0)).is_err());
    assert!(
        xchacha20_poly1305_decrypt(&key, &nonce, &aad, &flip(&sealed, sealed.len() - 1)).is_err()
    );
    assert!(xchacha20_poly1305_decrypt(&key, &flip(&nonce, 0), &aad, &sealed).is_err());
    assert!(xchacha20_poly1305_decrypt(&key, &nonce, &flip(&aad, 0), &sealed).is_err());
    assert!(xchacha20_poly1305_decrypt(&flip(&key, 0), &nonce, &aad, &sealed).is_err());
    assert!(xchacha20_poly1305_decrypt(&key, &nonce, &aad, &sealed[..sealed.len() - 1]).is_err());
}

// --------------------------------------------------------------------------
// X25519 parity
// --------------------------------------------------------------------------

/// Pin both derived public keys and the shared secret (computed from BOTH
/// sides) for one X25519 KAT / roundtrip vector.
fn assert_x25519_vector(vector: &Value) {
    let name = field(vector, "name");
    let alice_secret = bytes(vector, "alice_secret_hex");
    let bob_secret = bytes(vector, "bob_secret_hex");

    let alice_public = x25519_public_key(&alice_secret).expect("alice public");
    assert_eq!(
        hex::encode(&alice_public),
        field(vector, "expected_alice_public_hex"),
        "{name}: alice public"
    );
    let bob_public = x25519_public_key(&bob_secret).expect("bob public");
    assert_eq!(
        hex::encode(&bob_public),
        field(vector, "expected_bob_public_hex"),
        "{name}: bob public"
    );

    let from_alice = x25519_ecdh(&alice_secret, &bob_public).expect("ecdh from alice");
    assert_eq!(
        hex::encode(&from_alice),
        field(vector, "expected_shared_secret_hex"),
        "{name}: shared from alice"
    );
    let from_bob = x25519_ecdh(&bob_secret, &alice_public).expect("ecdh from bob");
    assert_eq!(
        hex::encode(&from_bob),
        field(vector, "expected_shared_secret_hex"),
        "{name}: shared from bob"
    );
}

#[test]
fn x25519_rfc7748_kat() {
    let corpus = kem_fixture("x25519-rfc7748-kat.json");
    let vectors = vectors(&corpus);
    assert_eq!(vectors.len(), 1, "x25519 RFC 7748 KAT vector count");
    for vector in vectors {
        assert_x25519_vector(vector);
    }
}

#[test]
fn x25519_roundtrip_vectors() {
    let corpus = kem_fixture("x25519-roundtrip.json");
    let vectors = vectors(&corpus);
    assert_eq!(vectors.len(), 4, "x25519 roundtrip vector count");
    for vector in vectors {
        assert_x25519_vector(vector);
    }
}

#[test]
fn x25519_validation_rejects_small_order_points() {
    // Each validation vector is an attacker-supplied peer point that drives the
    // shared secret to all zeros; RFC 7748 §6.1 requires rejecting it, and the
    // SDK surfaces that as the typed low-order error.
    let corpus = kem_fixture("x25519-validation.json");
    let vectors = vectors(&corpus);
    assert_eq!(vectors.len(), 1, "x25519 validation vector count");
    for vector in vectors {
        let name = field(vector, "name");
        assert!(
            vector["expected_rejection"].as_bool().unwrap_or(false),
            "{name}: vector must mark expected_rejection"
        );
        let secret = bytes(vector, "secret_key_hex");
        let peer = bytes(vector, "peer_public_key_hex");
        assert_eq!(
            x25519_ecdh(&secret, &peer).err(),
            Some(KemError::X25519LowOrderPoint),
            "{name}: must reject the small-order peer point"
        );
    }
}

#[test]
fn x25519_rejects_wrong_length_inputs() {
    // A wrong-length key is caller misuse, distinct from the low-order rejection.
    assert_eq!(
        x25519_public_key(&[0u8; 31]).err(),
        Some(KemError::InvalidX25519KeyLength(31)),
    );
    assert_eq!(
        x25519_ecdh(&[0u8; 32], &[0u8; 31]).err(),
        Some(KemError::InvalidX25519KeyLength(31)),
    );
}

// --------------------------------------------------------------------------
// X-Wing (mlkem768x25519) parity — the make-or-break combiner surface
// --------------------------------------------------------------------------

#[test]
fn mlkem768x25519_encaps_kat() {
    let corpus = kem_fixture("mlkem768x25519-encaps-kat.json");
    let vectors = vectors(&corpus);
    assert_eq!(vectors.len(), 3, "X-Wing encaps vector count");
    for vector in vectors {
        let name = field(vector, "name");
        let public_key = bytes(vector, "pk_hex");
        let eseed = bytes(vector, "eseed_hex");

        let encaps = mlkem768x25519_encapsulate(&public_key, &eseed)
            .unwrap_or_else(|e| panic!("{name}: encapsulate failed: {e}"));
        assert_eq!(
            hex::encode(&encaps.enc),
            field(vector, "expected_enc_hex"),
            "{name}: ciphertext (ctM || ctX)"
        );
        assert_eq!(
            hex::encode(&encaps.ss),
            field(vector, "expected_ss_hex"),
            "{name}: combiner shared secret"
        );
    }
}

#[test]
fn mlkem768x25519_decaps_kat() {
    let corpus = kem_fixture("mlkem768x25519-decaps-kat.json");
    let vectors = vectors(&corpus);
    assert_eq!(vectors.len(), 3, "X-Wing decaps vector count");
    for vector in vectors {
        let name = field(vector, "name");
        let secret_seed = bytes(vector, "sk_seed_hex");
        let enc = bytes(vector, "enc_hex");

        let ss = mlkem768x25519_decapsulate(&secret_seed, &enc)
            .unwrap_or_else(|e| panic!("{name}: decapsulate failed: {e}"));
        assert_eq!(
            hex::encode(&ss),
            field(vector, "expected_ss_hex"),
            "{name}: recovered shared secret"
        );
    }
}

#[test]
fn mlkem768x25519_encaps_decaps_cross_check() {
    // The encaps and decaps fixtures share the same secret-key seed and pinned
    // shared secret per index: decapsulating the encaps fixture's ciphertext
    // under the decaps fixture's seed MUST recover the same secret. This binds
    // the two halves of the X-Wing construction together end-to-end.
    let encaps = kem_fixture("mlkem768x25519-encaps-kat.json");
    let decaps = kem_fixture("mlkem768x25519-decaps-kat.json");
    let encaps_v = vectors(&encaps);
    let decaps_v = vectors(&decaps);
    assert_eq!(
        encaps_v.len(),
        decaps_v.len(),
        "encaps/decaps vector counts must align"
    );

    for (e, d) in encaps_v.iter().zip(decaps_v) {
        assert_eq!(
            field(e, "expected_ss_hex"),
            field(d, "expected_ss_hex"),
            "encaps/decaps pinned shared secrets must match for {}",
            field(e, "name")
        );
        let recovered =
            mlkem768x25519_decapsulate(&bytes(d, "sk_seed_hex"), &bytes(e, "expected_enc_hex"))
                .expect("decapsulate the encaps fixture's ciphertext");
        assert_eq!(
            hex::encode(&recovered),
            field(e, "expected_ss_hex"),
            "cross-check shared secret for {}",
            field(e, "name")
        );
    }
}

// --------------------------------------------------------------------------
// X-Wing adversarial / degenerate-point and implicit-rejection regression pins
// --------------------------------------------------------------------------

/// A deterministic X-Wing fixture: a keypair from a fixed root seed and one
/// encapsulation against it with a fixed `eseed`. The clean shared secret and
/// ciphertext are reproduced by the Python reference SDK, so this anchors the
/// degenerate / tampered derivations below to a known-good baseline.
struct XwingFixture {
    sk_seed: [u8; 32],
    enc: [u8; 1120],
    clean_ss: [u8; 32],
}

fn xwing_fixture() -> XwingFixture {
    let sk_seed = [0x42u8; 32];
    let public_key = xwing_keygen(&sk_seed);
    let eseed = [0x07u8; 64];
    let encaps =
        mlkem768x25519_encapsulate(&public_key, &eseed).expect("encapsulate to a valid X-Wing key");
    assert_eq!(
        hex::encode(&encaps.ss),
        "6111a21cfde8684a0f3cca7f9ab02544e3e92463791423d2b58f016384342aca",
        "clean shared secret matches the Python reference"
    );
    XwingFixture {
        sk_seed,
        enc: encaps.enc,
        clean_ss: encaps.ss,
    }
}

#[test]
fn xwing_decaps_of_all_zero_ct_x25519_is_defined_and_does_not_panic() {
    // An `enc` whose X25519 ciphertext tail (bytes [1088..1120]) is all-zero is
    // a degenerate (small-order) point. X-Wing is spec-correct *non-rejecting*
    // here: ML-KEM is decapsulated as normal and the degenerate ss_X25519 is
    // mixed into the SHA3-256 combiner, yielding a DEFINED secret rather than a
    // panic. (The classical-X25519 ECDH path would reject this, and the
    // `cryptography`-backed Python build raises on it — a DoS that the Rust and
    // TS X-Wing paths deliberately avoid; this vector pins the non-rejecting,
    // DoS-resistant Rust output.)
    let f = xwing_fixture();
    let mut deg = f.enc;
    deg[1088..1120].copy_from_slice(&[0u8; 32]);
    assert_eq!(&deg[1088..1120], &[0u8; 32], "ct_x25519 tail is all-zero");

    let ss = mlkem768x25519_decapsulate(&f.sk_seed, &deg)
        .expect("decapsulating a degenerate ct_x25519 must not error");
    assert_eq!(
        hex::encode(&ss),
        "d449e24f96af2d37767ae7d3c9f780b59e72bb4122ff1c03823c08174c937509",
        "defined secret over the degenerate point"
    );
    assert_ne!(
        ss, f.clean_ss,
        "the degenerate secret differs from the clean one"
    );
}

#[test]
fn xwing_encaps_to_all_zero_pk_x25519_tail_is_defined_and_does_not_panic() {
    // Symmetric encaps case: a recipient X-Wing public key whose X25519 tail
    // (bytes [1184..1216]) is all-zero. The ephemeral-side ECDH against that
    // small-order point is degenerate, but X-Wing does not reject it: the
    // combiner still yields a defined shared secret. Pins the non-rejecting Rust
    // output (the Python `cryptography` build raises here).
    let sk_seed = [0x42u8; 32];
    let mut public_key = xwing_keygen(&sk_seed);
    public_key[1184..1216].copy_from_slice(&[0u8; 32]);
    assert_eq!(
        &public_key[1184..1216],
        &[0u8; 32],
        "pk_x25519 tail is all-zero"
    );

    let eseed = [0x07u8; 64];
    let encaps = mlkem768x25519_encapsulate(&public_key, &eseed)
        .expect("encapsulating to a degenerate pk_x25519 must not error");
    assert_eq!(
        hex::encode(&encaps.ss),
        "da5aa9792f3b9ef776481e0d79d8ca6cd2113f0ec503462c28251157682d214a",
        "defined secret over the degenerate recipient point"
    );
}

#[test]
fn xwing_tampered_ct_mlkem_yields_the_implicit_reject_secret() {
    // Flipping a byte of the ML-KEM ciphertext (ctM) triggers FIPS 203 implicit
    // rejection: decapsulation returns a deterministic pseudorandom secret —
    // never an error, never the real secret. This exact value is reproduced by
    // the Python reference SDK (the implicit-reject path is shared, degenerate
    // X25519 is not involved).
    let f = xwing_fixture();
    let mut tampered = f.enc;
    tampered[0] ^= 0x01;
    let ss = mlkem768x25519_decapsulate(&f.sk_seed, &tampered)
        .expect("tampered ctM decapsulates without error (implicit rejection)");
    assert_eq!(
        hex::encode(&ss),
        "d1d809ead50b97d3b973e8fbc7a602e08dd9a11c3cabdb24138ea9009f0df30d",
        "deterministic ML-KEM implicit-reject secret (Python-oracle byte-parity)"
    );
    assert_ne!(
        ss, f.clean_ss,
        "implicit-reject secret differs from the clean one"
    );
}

#[test]
fn xwing_tampered_ct_x25519_yields_a_defined_secret() {
    // Flipping a byte of the X25519 ciphertext (ctX, here enc[1088]) changes the
    // X25519 shared secret and therefore the combined secret, but never errors
    // and never recovers the real secret. The resulting secret matches the
    // Python reference (the flipped point stays a valid, non-degenerate point).
    let f = xwing_fixture();
    let mut tampered = f.enc;
    tampered[1088] ^= 0x01;
    let ss = mlkem768x25519_decapsulate(&f.sk_seed, &tampered)
        .expect("tampered ctX decapsulates without error");
    assert_eq!(
        hex::encode(&ss),
        "b688a9a9c5e2684ea7962da19b921bb30007ab0341a001e6d2b284635646cae3",
        "defined secret over the tampered ctX (Python-oracle byte-parity)"
    );
    assert_ne!(
        ss, f.clean_ss,
        "tampered-ctX secret differs from the clean one"
    );
}

#[test]
fn mlkem768x25519_deterministic_keygen_encaps_kat() {
    // The full deterministic chain pinned by draft-10 Appendix C: seed -> pk
    // (keygen) and eseed -> (ct, ss) (encaps). Binds keygen and encaps together
    // against the externally pinned anchor; the encaps KAT above starts from a
    // hardcoded pk and never re-derives it from the seed.
    let corpus = kem_fixture("mlkem768x25519-encaps-deterministic-draft10-kat.json");
    let vectors = vectors(&corpus);
    assert_eq!(vectors.len(), 3, "deterministic encaps vector count");
    for vector in vectors {
        let name = field(vector, "name");
        let seed: [u8; 32] = bytes(vector, "seed_hex")
            .try_into()
            .unwrap_or_else(|b: Vec<u8>| panic!("{name}: seed is {} bytes, want 32", b.len()));

        let public_key = xwing_keygen(&seed);
        assert_eq!(
            hex::encode(&public_key),
            field(vector, "expected_pk_hex"),
            "{name}: keygen public key"
        );

        let eseed = bytes(vector, "eseed_hex");
        let encaps = mlkem768x25519_encapsulate(&public_key, &eseed)
            .unwrap_or_else(|e| panic!("{name}: encapsulate failed: {e}"));
        assert_eq!(
            hex::encode(&encaps.enc),
            field(vector, "expected_enc_hex"),
            "{name}: ciphertext"
        );
        assert_eq!(
            hex::encode(&encaps.ss),
            field(vector, "expected_ss_hex"),
            "{name}: combiner shared secret"
        );
    }
}

#[test]
fn fixture_trees_resolve() {
    // Guard against a future fixture relocation silently turning the parity
    // suite into a no-op.
    let aead: PathBuf = crypto_core_fixtures().join("aead");
    let kem: PathBuf = crypto_core_fixtures().join("kem");
    assert!(aead.is_dir(), "aead fixtures missing at {}", aead.display());
    assert!(kem.is_dir(), "kem fixtures missing at {}", kem.display());
}
