//! Byte-parity tests for the age-recipient codec.
//!
//! Pins the cross-language recipient fixture (`seed-derive/recipients.json`):
//! the canonical `age` (X25519) strings for the three identity seeds, and the
//! `age1pqc` (X-Wing) recipient prefixes. The full X-Wing string is ~1960 chars,
//! so the fixture stores only its prefix; the X-Wing case re-derives the
//! 1216-byte key from the seed, encodes it, asserts it extends the pinned
//! prefix, and round-trips it back through the parser. These are the same
//! vectors the TypeScript and Python SDKs load, so passing them proves this
//! crate addresses the same identity with the same recipient string.

mod common;

use cardanowall::hex;
use cardanowall::recipient::{
    bech32_encode_no_limit, encode_age_x25519_recipient, encode_age_xwing_recipient,
    parse_age_recipient, ParsedAgeRecipient, RecipientError, RecipientKem,
};
use cardanowall::seed_derive::derive_mlkem768x25519_keypair;
use common::{crypto_core_fixtures, read_fixture_json, sdk_py_fixtures};
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
fn recipients_fixture_pins_x25519_and_xwing_round_trips() {
    // The recipients fixture is owned by the Python mirror tree; the X-Wing
    // strings (~1960 chars) live there as prefixes only.
    let path = sdk_py_fixtures().join("seed-derive/recipients.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);
    assert_eq!(vectors.len(), 3, "expected 3 recipient vectors");

    for vector in vectors {
        let name = field(vector, "name");
        let x25519_public_hex = field(vector, "x25519_public_hex");
        let age = field(vector, "age");
        let age1pqc_prefix = field(vector, "age1pqc_prefix");

        // X25519: encoding the pinned public key reproduces the canonical `age`
        // string byte-for-byte, and parsing it recovers the exact key + KEM.
        let x25519_public = hex::decode(x25519_public_hex)
            .unwrap_or_else(|e| panic!("vector {name}: bad x25519_public_hex: {e}"));
        let encoded = encode_age_x25519_recipient(&x25519_public)
            .unwrap_or_else(|e| panic!("vector {name}: x25519 encode failed: {e}"));
        assert_eq!(encoded, age, "vector {name}: age string");

        let parsed = parse_age_recipient(age)
            .unwrap_or_else(|e| panic!("vector {name}: age parse failed: {e}"));
        assert_eq!(
            parsed,
            ParsedAgeRecipient {
                kem: RecipientKem::X25519,
                public_key: x25519_public.clone(),
            },
            "vector {name}: parsed age recipient"
        );
        assert_eq!(hex::encode(&parsed.public_key), x25519_public_hex);

        // X-Wing: re-derive the real 1216-byte key from the seed, encode it,
        // assert it extends the pinned prefix, and round-trip via the parser.
        let seed: [u8; 32] = hex::decode(field(vector, "seed_hex"))
            .unwrap_or_else(|e| panic!("vector {name}: bad seed_hex: {e}"))
            .try_into()
            .unwrap_or_else(|b: Vec<u8>| panic!("vector {name}: seed is {} bytes", b.len()));
        let xwing = derive_mlkem768x25519_keypair(&seed)
            .unwrap_or_else(|e| panic!("vector {name}: x-wing derive failed: {e}"));
        assert_eq!(xwing.public_key.len(), 1216);

        let recipient = encode_age_xwing_recipient(&xwing.public_key)
            .unwrap_or_else(|e| panic!("vector {name}: x-wing encode failed: {e}"));
        assert!(
            recipient.starts_with(age1pqc_prefix),
            "vector {name}: x-wing recipient must extend the pinned age1pqc prefix"
        );

        let parsed_xwing = parse_age_recipient(&recipient)
            .unwrap_or_else(|e| panic!("vector {name}: x-wing parse failed: {e}"));
        assert_eq!(parsed_xwing.kem, RecipientKem::MlKem768X25519);
        assert_eq!(parsed_xwing.public_key, xwing.public_key.to_vec());
    }
}

#[test]
fn recipient_strings_kat_pins_exact_encode_and_decode() {
    // Byte-exact KAT: KEM public key -> exact Bech32 string and back, for both
    // KEMs, from the shared conformance fixture the TS and Python SDKs also load.
    // Locks the HRP / visible-prefix distinction: HRP `age` renders `age1…`, HRP
    // `age1pqc` renders `age1pqc1…` (the leading `1` is the Bech32 separator).
    let path = crypto_core_fixtures().join("seed-derive/recipient-strings-kat.json");
    let fixture = read_fixture_json(&path);
    let vectors = vectors(&fixture);

    let mut saw_x25519 = false;
    let mut saw_hybrid = false;

    for vector in vectors {
        let name = field(vector, "name");
        let kem = field(vector, "kem");
        let public_key_hex = field(vector, "public_key_hex");
        let recipient = field(vector, "recipient");
        let public_key = hex::decode(public_key_hex)
            .unwrap_or_else(|e| panic!("vector {name}: bad public_key_hex: {e}"));

        let (expected_kem, encoded, visible_prefix) = match kem {
            "x25519" => {
                saw_x25519 = true;
                (
                    RecipientKem::X25519,
                    encode_age_x25519_recipient(&public_key)
                        .unwrap_or_else(|e| panic!("vector {name}: x25519 encode failed: {e}")),
                    "age1",
                )
            }
            "mlkem768x25519" => {
                saw_hybrid = true;
                (
                    RecipientKem::MlKem768X25519,
                    encode_age_xwing_recipient(&public_key)
                        .unwrap_or_else(|e| panic!("vector {name}: x-wing encode failed: {e}")),
                    "age1pqc1",
                )
            }
            other => panic!("vector {name}: unexpected kem `{other}`"),
        };

        // encode -> exact pinned string, and the visible prefix the HRP implies.
        assert_eq!(encoded, recipient, "vector {name}: encoded string");
        assert!(
            recipient.starts_with(visible_prefix),
            "vector {name}: visible prefix `{visible_prefix}`"
        );

        // decode -> exact key bytes + the KEM the HRP implies.
        let parsed = parse_age_recipient(recipient)
            .unwrap_or_else(|e| panic!("vector {name}: parse failed: {e}"));
        assert_eq!(parsed.kem, expected_kem, "vector {name}: parsed KEM");
        assert_eq!(
            hex::encode(&parsed.public_key),
            public_key_hex,
            "vector {name}: parsed public key"
        );
    }

    assert!(saw_x25519, "fixture must carry an x25519 vector");
    assert!(saw_hybrid, "fixture must carry an mlkem768x25519 vector");
}

#[test]
fn parse_round_trips_both_kems_on_synthetic_keys() {
    let x_pub = vec![7u8; 32];
    let q_pub = vec![9u8; 1216];

    let x = parse_age_recipient(&encode_age_x25519_recipient(&x_pub).unwrap()).unwrap();
    assert_eq!(x.kem, RecipientKem::X25519);
    assert_eq!(x.public_key, x_pub);

    let q = parse_age_recipient(&encode_age_xwing_recipient(&q_pub).unwrap()).unwrap();
    assert_eq!(q.kem, RecipientKem::MlKem768X25519);
    assert_eq!(q.public_key, q_pub);
}

#[test]
fn parse_tolerates_surrounding_whitespace() {
    let s = encode_age_x25519_recipient(&[1u8; 32]).unwrap();
    let parsed = parse_age_recipient(&format!("  {s}\n")).unwrap();
    assert_eq!(parsed.public_key, vec![1u8; 32]);
}

#[test]
fn parse_rejects_negative_cases() {
    // Empty string.
    assert_eq!(parse_age_recipient(""), Err(RecipientError::EmptyString));

    // Corrupted checksum (flip the final character).
    let s = encode_age_x25519_recipient(&[2u8; 32]).unwrap();
    let replacement = if s.ends_with('q') { 'p' } else { 'q' };
    let broken = format!("{}{replacement}", &s[..s.len() - 1]);
    assert_eq!(
        parse_age_recipient(&broken),
        Err(RecipientError::BadChecksum)
    );

    // Mixed case.
    let s = encode_age_x25519_recipient(&[3u8; 32]).unwrap();
    let mixed = format!("{}{}", s[..12].to_uppercase(), &s[12..]);
    assert_eq!(parse_age_recipient(&mixed), Err(RecipientError::MixedCase));

    // Checksum-valid string under an unrecognized HRP.
    let s = bech32_encode_no_limit("xyz", &[4u8; 32]).unwrap();
    assert_eq!(
        parse_age_recipient(&s),
        Err(RecipientError::UnrecognizedPrefix("xyz".to_string()))
    );

    // Correct HRP carrying the wrong key length.
    let wrong = bech32_encode_no_limit("age1pqc", &[5u8; 32]).unwrap();
    assert_eq!(
        parse_age_recipient(&wrong),
        Err(RecipientError::ParsedXWingKeyLength)
    );
}

#[test]
fn encode_rejects_wrong_key_lengths() {
    assert_eq!(
        encode_age_x25519_recipient(&[0u8; 31]),
        Err(RecipientError::X25519KeyLength)
    );
    assert_eq!(
        encode_age_x25519_recipient(&[0u8; 33]),
        Err(RecipientError::X25519KeyLength)
    );
    assert_eq!(
        encode_age_xwing_recipient(&[0u8; 1215]),
        Err(RecipientError::XWingKeyLength)
    );
    assert_eq!(
        encode_age_xwing_recipient(&[0u8; 1217]),
        Err(RecipientError::XWingKeyLength)
    );
    assert_eq!(
        bech32_encode_no_limit("", &[0u8; 32]),
        Err(RecipientError::EmptyPrefix)
    );
}
