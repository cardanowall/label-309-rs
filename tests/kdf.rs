//! Byte-parity tests for the HKDF-SHA256 module.
//!
//! Pins every RFC 5869 known-answer-test vector in the shared
//! cross-implementation fixture. These are the same vectors the TypeScript and
//! Python SDKs load, so passing them proves this crate's HKDF engine derives
//! the exact same bytes.

mod common;

use cardanowall::hex;
use cardanowall::kdf::hkdf_sha256;
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;

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

#[test]
fn hkdf_sha256_known_answer_tests() {
    let path = crypto_core_fixtures().join("kdf/hkdf-sha256-kat.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty(), "hkdf-sha256-kat fixture is empty");

    for vector in vectors {
        let name = field(vector, "name");
        let ikm = hex::decode(field(vector, "ikm_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad ikm_hex: {e}"));
        let salt = hex::decode(field(vector, "salt_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad salt_hex: {e}"));
        let info = hex::decode(field(vector, "info_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad info_hex: {e}"));
        let length = vector["length"]
            .as_u64()
            .unwrap_or_else(|| panic!("vector {name}: `length` must be an integer"))
            as usize;

        let okm = hkdf_sha256(&ikm, &salt, &info, length)
            .unwrap_or_else(|e| panic!("vector {name}: derivation failed: {e}"));
        assert_eq!(okm.len(), length, "vector {name}: output length");
        assert_eq!(
            hex::encode(&okm),
            field(vector, "expected_hex"),
            "vector {name}"
        );
    }

    // Pin the corpus size so a silently-emptied or truncated fixture fails.
    assert_eq!(vectors.len(), 3, "expected 3 hkdf-sha256 vectors");
}

#[test]
fn hkdf_sha256_zero_length_salt_kat() {
    // Zero-length HKDF salt (RFC 5869 section 2.2 absent-salt extract): with
    // salt="", HKDF-Extract substitutes HashLen zero bytes. This is the exact
    // shape the sealed-PoE slots_mac HKDF uses (salt="" with a non-empty info
    // label), so the construction's absent-salt behaviour is pinned by a
    // byte-exact vector rather than left to the library.
    let path = crypto_core_fixtures().join("kdf/hkdf-sha256-empty-salt-kat.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(
        !vectors.is_empty(),
        "hkdf-sha256-empty-salt-kat fixture is empty"
    );

    for vector in vectors {
        let name = field(vector, "name");
        let salt_hex = field(vector, "salt_hex");
        assert_eq!(
            salt_hex, "",
            "vector {name}: empty-salt KAT must carry a zero-length salt"
        );
        let ikm = hex::decode(field(vector, "ikm_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad ikm_hex: {e}"));
        let salt =
            hex::decode(salt_hex).unwrap_or_else(|e| panic!("vector {name}: bad salt_hex: {e}"));
        let info = hex::decode(field(vector, "info_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad info_hex: {e}"));
        let length = vector["length"]
            .as_u64()
            .unwrap_or_else(|| panic!("vector {name}: `length` must be an integer"))
            as usize;

        let okm = hkdf_sha256(&ikm, &salt, &info, length)
            .unwrap_or_else(|e| panic!("vector {name}: derivation failed: {e}"));
        assert_eq!(
            hex::encode(&okm),
            field(vector, "expected_hex"),
            "vector {name}"
        );
    }
}
