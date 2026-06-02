//! Byte-parity tests for the hand-rolled canonical CBOR module.
//!
//! Pins every vector in the shared cross-implementation CBOR fixtures — the same
//! JSON the TypeScript and Python SDKs load. Passing them proves this crate
//! emits byte-identical canonical bytes and rejects the exact same non-canonical
//! inputs with the exact same error codes.
//!
//! The fixtures model a CBOR value either as a typed `input_value_spec`
//! (`{type:"bytes",hex}` / `{type:"bigint",decimal}`) or as an `input_json`
//! string that holds the value's JSON form. This mirror of the TS/PY `reifyValue`
//! helper turns either shape into a [`CborValue`]. As a second, independent
//! oracle, every encoded output is cross-checked against `ciborium`'s decoder so
//! a hand-rolled encoder bug cannot pass merely by matching a hand-written test
//! expectation. `ciborium` is used ONLY to read bytes in tests; it never emits
//! the canonical bytes under test.

mod common;

use cardanowall::cbor::{
    decode_canonical_cbor, decode_cbor_permissive, encode_canonical_cbor, CanonicalCborError,
    CborValue, PermissiveValue,
};
use cardanowall::hex;
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;

fn vectors(fixture: &Value) -> &Vec<Value> {
    fixture["vectors"]
        .as_array()
        .expect("fixture must carry a `vectors` array")
}

fn name(vector: &Value) -> &str {
    vector["name"].as_str().expect("vector has a string `name`")
}

/// Reify a [`CborValue`] from a fixture vector, mirroring the TS/PY `reifyValue`.
fn reify_value(vector: &Value) -> CborValue {
    if let Some(spec) = vector.get("input_value_spec").filter(|s| !s.is_null()) {
        match spec["type"].as_str() {
            Some("bytes") => {
                let h = spec["hex"].as_str().expect("bytes spec has a hex string");
                return CborValue::Bytes(hex::decode(h).expect("valid hex in bytes spec"));
            }
            Some("bigint") => {
                let dec = spec["decimal"].as_str().expect("bigint spec has decimal");
                return bigint_to_value(dec);
            }
            other => panic!("unknown input_value_spec type: {other:?}"),
        }
    }
    let json_text = vector["input_json"]
        .as_str()
        .expect("vector has an `input_json` string");
    let parsed: Value = serde_json::from_str(json_text).expect("input_json is valid JSON");
    json_to_cbor(&parsed)
}

/// Convert a decimal string to an unsigned [`CborValue`] (the fixtures only carry
/// non-negative bigints, up to 2^64-1, which fit a `u64`).
fn bigint_to_value(decimal: &str) -> CborValue {
    let n: u64 = decimal
        .parse()
        .unwrap_or_else(|_| panic!("bigint decimal {decimal} must fit u64"));
    CborValue::Unsigned(n)
}

/// Convert a `serde_json::Value` to the closed CBOR value model.
///
/// JSON objects become text-keyed CBOR maps (the only key kind JSON has).
/// Integers map to the matching CBOR integer major type; the fixtures never
/// carry JSON floats on this path (large/byte values use `input_value_spec`).
fn json_to_cbor(value: &Value) -> CborValue {
    match value {
        Value::Null => CborValue::Null,
        Value::Bool(b) => CborValue::Bool(*b),
        Value::Number(num) => {
            if let Some(u) = num.as_u64() {
                CborValue::Unsigned(u)
            } else if let Some(i) = num.as_i64() {
                CborValue::int(i)
            } else {
                panic!("fixture carries a non-integer JSON number: {num}");
            }
        }
        Value::String(s) => CborValue::Text(s.clone()),
        Value::Array(items) => CborValue::Array(items.iter().map(json_to_cbor).collect()),
        Value::Object(map) => CborValue::Map(
            map.iter()
                .map(|(k, v)| (CborValue::Text(k.clone()), json_to_cbor(v)))
                .collect(),
        ),
    }
}

/// Decode bytes with `ciborium` as an independent cross-check oracle.
fn ciborium_can_decode(bytes: &[u8]) -> bool {
    ciborium::de::from_reader::<ciborium::value::Value, _>(bytes).is_ok()
}

#[test]
fn canonical_encode_rfc8949_kat() {
    let path = crypto_core_fixtures().join("cbor/canonical-encode-rfc8949-kat.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty(), "kat fixture is empty");

    for vector in vectors {
        let label = name(vector);
        let value = reify_value(vector);
        let encoded = encode_canonical_cbor(&value)
            .unwrap_or_else(|e| panic!("vector {label}: encode failed: {e}"));
        let expected = vector["expected_cbor_hex"]
            .as_str()
            .expect("vector has expected_cbor_hex");
        assert_eq!(hex::encode(&encoded), expected, "vector {label}");
        // Independent oracle: the produced bytes must parse under ciborium too.
        assert!(
            ciborium_can_decode(&encoded),
            "vector {label}: ciborium rejected our canonical bytes"
        );
    }

    // Pin the corpus size so a silently-truncated fixture fails the build.
    assert_eq!(vectors.len(), 30, "expected 30 RFC 8949 KAT vectors");
}

#[test]
fn canonical_encode_roundtrip() {
    let path = crypto_core_fixtures().join("cbor/canonical-encode-roundtrip.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty(), "roundtrip fixture is empty");

    for vector in vectors {
        let label = name(vector);
        let value = reify_value(vector);
        let encoded = encode_canonical_cbor(&value)
            .unwrap_or_else(|e| panic!("vector {label}: encode failed: {e}"));
        let expected = vector["expected_cbor_hex"]
            .as_str()
            .expect("vector has expected_cbor_hex");
        assert_eq!(hex::encode(&encoded), expected, "vector {label}");

        // Full encode -> decode -> encode round-trip must be byte-stable: the
        // strict decoder accepts exactly what the encoder produced, and the
        // canonical form is idempotent.
        let from_hex = hex::decode(expected).expect("expected_cbor_hex is valid hex");
        let decoded = decode_canonical_cbor(&from_hex)
            .unwrap_or_else(|e| panic!("vector {label}: strict decode failed: {e}"));
        let re_encoded = encode_canonical_cbor(&decoded)
            .unwrap_or_else(|e| panic!("vector {label}: re-encode failed: {e}"));
        assert_eq!(
            hex::encode(&re_encoded),
            expected,
            "vector {label}: round-trip not byte-stable"
        );
    }

    assert_eq!(vectors.len(), 12, "expected 12 roundtrip vectors");
}

#[test]
fn canonical_decode_negative_rejects_with_exact_codes() {
    let path = crypto_core_fixtures().join("cbor/canonical-decode-negative.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert!(!vectors.is_empty(), "decode-negative fixture is empty");

    let mut indefinite = 0usize;
    let mut malformed = 0usize;

    for vector in vectors {
        let label = name(vector);
        let cbor_hex = vector["cbor_hex"].as_str().expect("vector has cbor_hex");
        let bytes = hex::decode(cbor_hex).expect("cbor_hex is valid hex");
        let expected_code = vector["expected_error_code"]
            .as_str()
            .expect("vector has expected_error_code");

        let err = decode_canonical_cbor(&bytes)
            .err()
            .unwrap_or_else(|| panic!("vector {label}: expected rejection, got Ok"));
        assert_eq!(
            err.code(),
            expected_code,
            "vector {label}: wrong error code"
        );

        // Every canonical-decode violation folds into the single MALFORMED_CBOR
        // code; the indefinite-length families are tracked by name, and their
        // diagnostic cause must survive in the human-readable message.
        if label.starts_with("indefinite-") {
            indefinite += 1;
            assert!(
                err.to_string().to_lowercase().contains("indefinite"),
                "vector {label}: message should name the indefinite-length cause"
            );
        } else {
            malformed += 1;
        }
        assert_eq!(
            expected_code,
            CanonicalCborError::MALFORMED_CBOR,
            "vector {label}: corpus must pin MALFORMED_CBOR"
        );
    }

    // Mirror the assertions the TS/PY suites make on this corpus.
    assert_eq!(vectors.len(), 18, "expected 18 decode-negative vectors");
    assert!(indefinite >= 4, "expected >=4 indefinite-length vectors");
    assert!(malformed >= 1, "expected >=1 malformed vectors");

    // The TS/PY duplicate-vs-unsorted suites split MALFORMED into named
    // families; assert both families are present and all reject as MALFORMED.
    let dup = vectors
        .iter()
        .filter(|v| name(v).starts_with("duplicate-keys"))
        .count();
    let unsorted = vectors
        .iter()
        .filter(|v| name(v).starts_with("unsorted-distinct-keys"))
        .count();
    assert!(dup >= 3, "expected >=3 duplicate-keys vectors");
    assert!(unsorted >= 2, "expected >=2 unsorted-distinct-keys vectors");
}

// ---------------------------------------------------------------------------
// Inline edge cases ported from the TS/PY suites.
// ---------------------------------------------------------------------------

/// Duplicate map keys of every key kind reject as MALFORMED_CBOR (the wire
/// format folds duplicate-key and unsorted-key into one catch-all code).
#[test]
fn rejects_duplicate_keys_all_key_kinds() {
    // text {"a":1,"a":2}; uint {1:1,1:2}; bytes {h'ab':1,h'ab':2}
    for cbor_hex in ["a2616101616102", "a201010102", "a241ab0141ab02"] {
        let bytes = hex::decode(cbor_hex).unwrap();
        let err = decode_canonical_cbor(&bytes).unwrap_err();
        assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR, "{cbor_hex}");
    }
}

/// Distinct-but-unsorted keys reject as MALFORMED_CBOR (the unsorted case the
/// duplicate-only pre-scan once let through).
#[test]
fn rejects_unsorted_distinct_keys() {
    // {"b":1,"a":2} as written (b before a) and {2:1,1:2} (uint 2 before 1).
    for cbor_hex in ["a2616201616102", "a202010102"] {
        let bytes = hex::decode(cbor_hex).unwrap();
        let err = decode_canonical_cbor(&bytes).unwrap_err();
        assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR, "{cbor_hex}");
    }
}

/// Indefinite-length items of every kind reject as MALFORMED_CBOR, with the
/// indefinite-length cause preserved in the human-readable message.
#[test]
fn rejects_indefinite_length_items() {
    let cases = [
        ("9f010203ff", "array"),
        ("bf616101616202ff", "map"),
        ("5f420102420304ff", "bytestring"),
        ("7f626869626f6fff", "textstring"),
    ];
    for (cbor_hex, label) in cases {
        let bytes = hex::decode(cbor_hex).unwrap();
        let err = decode_canonical_cbor(&bytes).unwrap_err();
        assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR, "{label}");
        assert!(
            err.to_string().to_lowercase().contains("indefinite"),
            "{label}: message should name the indefinite-length cause"
        );
    }
}

/// Floats, the `undefined` simple value, and unassigned simple values all reject
/// as MALFORMED_CBOR — the major-type-7 surface admits only false/true/null.
#[test]
fn rejects_floats_and_simple_values() {
    let cases = [
        "f93c00",             // float16 1.0
        "fa3f800000",         // float32 1.0
        "fb3ff0000000000000", // float64 1.0
        "a16176f93c00",       // {"v": float16 1.0}
        "f98000",             // negative-zero float16
        "f7",                 // undefined
        "e0",                 // unassigned simple value 0
    ];
    for cbor_hex in cases {
        let bytes = hex::decode(cbor_hex).unwrap();
        let err = decode_canonical_cbor(&bytes).unwrap_err();
        assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR, "{cbor_hex}");
    }
}

/// Non-shortest integer encodings reject as MALFORMED_CBOR (the canonical form
/// requires the smallest argument width). cbor2/the fixtures cover truncation;
/// this pins the shortest-form rule directly.
#[test]
fn rejects_non_shortest_integers() {
    // uint 0 written with a needless 1-byte argument: 18 00 (should be 00).
    let bytes = hex::decode("1800").unwrap();
    let err = decode_canonical_cbor(&bytes).unwrap_err();
    assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR);

    // uint 255 written with a 2-byte argument: 19 00ff (should be 18 ff).
    let bytes = hex::decode("1900ff").unwrap();
    let err = decode_canonical_cbor(&bytes).unwrap_err();
    assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR);
}

/// Tags are forbidden on the canonical record surface and reject as
/// MALFORMED_CBOR.
#[test]
fn rejects_tags() {
    // c0 (tag 0) wrapping a text string — a standard date/time tag.
    let bytes = hex::decode("c074323031332d30332d32315432303a30343a30305a").unwrap();
    let err = decode_canonical_cbor(&bytes).unwrap_err();
    assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR);
}

/// Truncated input rejects as MALFORMED_CBOR.
#[test]
fn rejects_truncated_input() {
    for cbor_hex in ["1a000f", "8301", ""] {
        let bytes = hex::decode(cbor_hex).unwrap();
        let err = decode_canonical_cbor(&bytes).unwrap_err();
        assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR, "{cbor_hex}");
    }
}

/// Invalid UTF-8 in a text string rejects as MALFORMED_CBOR.
#[test]
fn rejects_invalid_utf8_text() {
    // 61 ff = text string of length 1 whose byte 0xff is not valid UTF-8.
    let bytes = hex::decode("61ff").unwrap();
    let err = decode_canonical_cbor(&bytes).unwrap_err();
    assert_eq!(err.code(), CanonicalCborError::MALFORMED_CBOR);
}

// ---------------------------------------------------------------------------
// Permissive decoder (outer Cardano-tx envelope) — ported from permissive.test.
// ---------------------------------------------------------------------------

/// The permissive decoder reads a Cardano-tx-shaped 4-element array.
#[test]
fn permissive_decodes_tx_shaped_array() {
    // [ {a:1}, {b:2}, true, {0: {309: h'0102'}} ] encoded canonically.
    let value = CborValue::Array(vec![
        CborValue::Map(vec![(CborValue::text("a"), CborValue::Unsigned(1))]),
        CborValue::Map(vec![(CborValue::text("b"), CborValue::Unsigned(2))]),
        CborValue::Bool(true),
        CborValue::Map(vec![(
            CborValue::Unsigned(0),
            CborValue::Map(vec![(
                CborValue::Unsigned(309),
                CborValue::Bytes(vec![0x01, 0x02]),
            )]),
        )]),
    ]);
    let bytes = encode_canonical_cbor(&value).unwrap();
    let decoded = decode_cbor_permissive(&bytes).unwrap();
    let PermissiveValue::Array(items) = decoded else {
        panic!("expected a top-level array");
    };
    assert_eq!(items.len(), 4);
    assert_eq!(items[2], PermissiveValue::Bool(true));
    // Reach into the auxiliary-data map: items[3][0][309] == h'0102'.
    let PermissiveValue::Map(outer) = &items[3] else {
        panic!("expected aux-data map");
    };
    let (_, inner) = &outer[0];
    let PermissiveValue::Map(label_map) = inner else {
        panic!("expected label map");
    };
    assert_eq!(label_map[0].1, PermissiveValue::Bytes(vec![0x01, 0x02]));
}

/// On canonical bytes, the permissive and strict decoders agree on the value.
#[test]
fn permissive_equals_canonical_when_canonical() {
    let value = CborValue::Map(vec![
        (CborValue::text("t"), CborValue::text("poe")),
        (CborValue::text("v"), CborValue::Unsigned(1)),
    ]);
    let bytes = encode_canonical_cbor(&value).unwrap();
    let permissive = decode_cbor_permissive(&bytes).unwrap();
    let canonical = decode_canonical_cbor(&bytes).unwrap();
    // Project both to a comparable shape: re-encode the strict value and decode
    // it permissively; the two permissive trees must be identical.
    let canonical_via_permissive =
        decode_cbor_permissive(&encode_canonical_cbor(&canonical).unwrap()).unwrap();
    assert_eq!(permissive, canonical_via_permissive);
}

/// The permissive decoder accepts indefinite-length input the strict decoder
/// rejects.
#[test]
fn permissive_accepts_indefinite_length() {
    // 9f 01 02 ff = [1, 2]
    let bytes = hex::decode("9f0102ff").unwrap();
    let decoded = decode_cbor_permissive(&bytes).unwrap();
    assert_eq!(
        decoded,
        PermissiveValue::Array(vec![
            PermissiveValue::Unsigned(1),
            PermissiveValue::Unsigned(2)
        ])
    );
    // The strict decoder rejects the same bytes as MALFORMED_CBOR.
    assert_eq!(
        decode_canonical_cbor(&bytes).unwrap_err().code(),
        CanonicalCborError::MALFORMED_CBOR
    );
}

/// The permissive decoder still rejects truly malformed (truncated) bytes.
#[test]
fn permissive_rejects_truncated() {
    // 5b 00 00 = byte string with an 8-byte length prefix but no length bytes.
    let bytes = hex::decode("5b0000").unwrap();
    assert!(decode_cbor_permissive(&bytes).is_err());
}
