//! Byte-parity tests for the seed-derivation module.
//!
//! Pins every vector in the shared seed-derivation, X-Wing keygen, and SHAKE
//! seed-expansion fixtures — the parity master for the entire identity layer.
//! These are the same JSON vectors the TypeScript and Python SDKs load, so
//! passing them proves this crate reproduces every derived key, the X-Wing
//! deterministic keygen, and the SHAKE-256 seed expansion byte-for-byte.

mod common;

use cardanowall::hex;
use cardanowall::seed_derive::{
    derive_ed25519_keypair, derive_mlkem768x25519_keypair, derive_x25519_keypair,
    expand_xwing_seed, xwing_keygen, SeedDeriveError,
};
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;

/// Decode a 32-byte X-Wing root seed from a vector's `seed_hex` field.
fn root_seed(vector: &Value, name: &str) -> [u8; 32] {
    let bytes = hex::decode(field(vector, "seed_hex"))
        .unwrap_or_else(|e| panic!("vector {name}: bad seed_hex: {e}"));
    bytes
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("vector {name}: seed is {} bytes, want 32", b.len()))
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

fn seed_bytes(vector: &Value, name: &str) -> Vec<u8> {
    hex::decode(field(vector, "seed_hex"))
        .unwrap_or_else(|e| panic!("vector {name}: bad seed_hex: {e}"))
}

/// Assert the four full derivations for one master-seed vector.
fn assert_full_seed_vector(vector: &Value) {
    let name = field(vector, "name");
    let seed = seed_bytes(vector, name);

    let ed = derive_ed25519_keypair(&seed)
        .unwrap_or_else(|e| panic!("vector {name}: ed25519 derive failed: {e}"));
    assert_eq!(
        hex::encode(&ed.secret_key),
        field(vector, "expected_ed25519_secret_hex"),
        "vector {name}: ed25519 secret"
    );
    assert_eq!(
        hex::encode(&ed.public_key),
        field(vector, "expected_ed25519_public_hex"),
        "vector {name}: ed25519 public"
    );

    let x = derive_x25519_keypair(&seed)
        .unwrap_or_else(|e| panic!("vector {name}: x25519 derive failed: {e}"));
    assert_eq!(
        hex::encode(&x.secret_key),
        field(vector, "expected_x25519_secret_hex"),
        "vector {name}: x25519 secret (must be raw/unclamped)"
    );
    assert_eq!(
        hex::encode(&x.public_key),
        field(vector, "expected_x25519_public_hex"),
        "vector {name}: x25519 public"
    );

    let xwing = derive_mlkem768x25519_keypair(&seed)
        .unwrap_or_else(|e| panic!("vector {name}: x-wing derive failed: {e}"));
    assert_eq!(
        hex::encode(&xwing.secret_seed),
        field(vector, "expected_mlkem768x25519_secret_seed_hex"),
        "vector {name}: x-wing secret seed (IS the root seed)"
    );
    assert_eq!(
        hex::encode(&xwing.public_key),
        field(vector, "expected_mlkem768x25519_public_key_hex"),
        "vector {name}: x-wing public key (1216 bytes)"
    );
}

#[test]
fn seed_from_zero_matches_fixture() {
    let path = crypto_core_fixtures().join("seed-derive/seed-from-zero.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert_eq!(vectors.len(), 1, "expected 1 seed-from-zero vector");
    for vector in vectors {
        assert_full_seed_vector(vector);
    }
}

#[test]
fn seed_from_ff_matches_fixture() {
    let path = crypto_core_fixtures().join("seed-derive/seed-from-ff.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert_eq!(vectors.len(), 1, "expected 1 seed-from-ff vector");
    for vector in vectors {
        assert_full_seed_vector(vector);
    }
}

#[test]
fn seed_from_deadbeef_matches_fixture() {
    let path = crypto_core_fixtures().join("seed-derive/seed-from-deadbeef.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert_eq!(vectors.len(), 1, "expected 1 seed-from-deadbeef vector");
    for vector in vectors {
        assert_full_seed_vector(vector);
    }
}

#[test]
fn negative_vectors_reject_wrong_seed_length() {
    let path = crypto_core_fixtures().join("seed-derive/seed-derive-negative.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty(), "seed-derive-negative fixture is empty");

    for vector in vectors {
        let name = field(vector, "name");
        let seed = seed_bytes(vector, name);
        let expected_code = field(vector, "expected_error_code");
        assert_eq!(
            expected_code, "INVALID_SEED_LENGTH",
            "vector {name}: only INVALID_SEED_LENGTH is modelled"
        );

        // Every derivation must reject the wrong-length seed identically.
        let observed = seed.len();
        let want = Some(SeedDeriveError::InvalidSeedLength(observed));
        assert_eq!(
            derive_ed25519_keypair(&seed).err(),
            want,
            "vector {name}: ed25519"
        );
        assert_eq!(
            derive_x25519_keypair(&seed).err(),
            want,
            "vector {name}: x25519"
        );
        assert_eq!(
            derive_mlkem768x25519_keypair(&seed).err(),
            want,
            "vector {name}: x-wing"
        );
    }

    assert_eq!(vectors.len(), 6, "expected 6 negative vectors");
}

#[test]
fn xwing_shake_expand_matches_fixture() {
    let path = crypto_core_fixtures().join("kem/mlkem768x25519-shake-expand-kat.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty(), "shake-expand fixture is empty");

    for vector in vectors {
        let name = field(vector, "name");
        let seed = root_seed(vector, name);
        let expanded = expand_xwing_seed(&seed);
        assert_eq!(
            hex::encode(&expanded),
            field(vector, "expected_expanded_hex"),
            "vector {name}: shake-256(seed, 96)"
        );
    }

    assert_eq!(vectors.len(), 3, "expected 3 shake-expand vectors");
}

#[test]
fn xwing_keygen_matches_fixture() {
    let path = crypto_core_fixtures().join("kem/mlkem768x25519-keygen-kat.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty(), "keygen fixture is empty");

    for vector in vectors {
        let name = field(vector, "name");
        let seed = root_seed(vector, name);

        let public_key = xwing_keygen(&seed);
        assert_eq!(
            hex::encode(&public_key),
            field(vector, "expected_pk_hex"),
            "vector {name}: x-wing public key (1216 bytes)"
        );
        // The X-Wing secret key IS the root seed verbatim.
        assert_eq!(
            hex::encode(&seed),
            field(vector, "expected_sk_seed_hex"),
            "vector {name}: x-wing secret seed == root seed"
        );
    }

    assert_eq!(vectors.len(), 3, "expected 3 keygen vectors");
}
