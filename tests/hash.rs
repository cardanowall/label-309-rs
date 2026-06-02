//! Byte-parity tests for the hash module.
//!
//! Every vector in the shared cross-implementation known-answer-test fixtures
//! is pinned here: the SHA-256 and BLAKE2b-256 KATs, plus the dual-hash
//! equivalence corpus (both the one-shot and streaming paths). These are the
//! same JSON fixtures the TypeScript and Python SDKs load, so passing them is
//! proof that this crate reproduces the exact same digest bytes.

mod common;

use cardanowall::hash::{blake2b256, dual_hash, dual_hash_stream, sha256};
use cardanowall::hex;
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;

/// Pull the `vectors` array out of a `{ primitive, vectors: [...] }` fixture.
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
fn sha256_known_answer_tests() {
    let path = crypto_core_fixtures().join("hash/sha256-kat.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty(), "sha256-kat fixture is empty");

    for vector in vectors {
        let name = field(vector, "name");
        let input = hex::decode(field(vector, "input_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad input_hex: {e}"));
        let actual = hex::encode(&sha256(&input));
        assert_eq!(actual, field(vector, "expected_hex"), "vector {name}");
    }

    // Pin the corpus size so a silently-emptied or truncated fixture fails.
    assert_eq!(vectors.len(), 5, "expected 5 sha256 vectors");
}

#[test]
fn blake2b256_known_answer_tests() {
    let path = crypto_core_fixtures().join("hash/blake2b256-kat.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty(), "blake2b256-kat fixture is empty");

    for vector in vectors {
        let name = field(vector, "name");
        let input = hex::decode(field(vector, "input_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad input_hex: {e}"));
        let actual = hex::encode(&blake2b256(&input));
        assert_eq!(actual, field(vector, "expected_hex"), "vector {name}");
    }

    assert_eq!(vectors.len(), 5, "expected 5 blake2b256 vectors");
}

#[test]
fn dual_hash_one_shot_equivalence() {
    let path = crypto_core_fixtures().join("hash/dual-hash-equivalence.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty(), "dual-hash fixture is empty");

    for vector in vectors {
        let name = field(vector, "name");
        let input = hex::decode(field(vector, "input_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad input_hex: {e}"));
        let out = dual_hash(&input);
        assert_eq!(
            hex::encode(&out.sha256),
            field(vector, "expected_sha256_hex"),
            "vector {name} (sha256)"
        );
        assert_eq!(
            hex::encode(&out.blake2b256),
            field(vector, "expected_blake2b256_hex"),
            "vector {name} (blake2b256)"
        );
    }

    assert_eq!(vectors.len(), 100, "expected 100 dual-hash vectors");
}

#[test]
fn dual_hash_streaming_matches_fixture() {
    let path = crypto_core_fixtures().join("hash/dual-hash-equivalence.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);

    // Drive the streaming path over a 64-byte chunk size, the same boundary
    // the Python parity suite uses, then assert against the pinned digests.
    for vector in vectors {
        let name = field(vector, "name");
        let input = hex::decode(field(vector, "input_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad input_hex: {e}"));
        let chunks: Vec<&[u8]> = if input.is_empty() {
            Vec::new()
        } else {
            input.chunks(64).collect()
        };
        let out = dual_hash_stream(chunks);
        assert_eq!(
            hex::encode(&out.sha256),
            field(vector, "expected_sha256_hex"),
            "vector {name} (sha256, streamed)"
        );
        assert_eq!(
            hex::encode(&out.blake2b256),
            field(vector, "expected_blake2b256_hex"),
            "vector {name} (blake2b256, streamed)"
        );
    }
}
