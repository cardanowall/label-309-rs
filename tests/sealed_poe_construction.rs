//! Byte-parity tests for the sealed-PoE enc.scheme 1 construction: the
//! passphrase-path KAT, the hybrid (X-Wing) per-slot KEK salt, the construction
//! negatives, and the cross-implementation behavioural pins (the single-shot
//! payload bound, per-slot KEK-uniqueness rejection, the 25-codepoint
//! `White_Space` normalization set, and passphrase round-trip / AAD-tamper /
//! normalization-equivalence).
//!
//! Every assertion pins bytes, verdicts, or structural error codes against the
//! shared fixtures under `crypto-core/tests/fixtures/sealed-poe/`, never log
//! strings.

mod common;

use std::collections::BTreeMap;

use argon2::{Algorithm, Argon2, Params, Version};
use cardanowall::cbor::{encode_canonical_cbor, CborValue};
use cardanowall::hex;
use cardanowall::poe_standard::{EncryptionEnvelope, ItemEntry, PassphraseBlock, PoeRecord, Slot};
use cardanowall::sealed_poe::{
    ad_content_passphrase, ad_content_slots, assert_ciphertext_within_bound,
    assert_plaintext_within_bound, canonicalize_slots, chunk_kem_ct, compute_slots_hash,
    ecies_sealed_poe_unwrap, ecies_sealed_poe_wrap_with_rng, mlkem768x25519_public_key_from_seed,
    passphrase_payload_key, xchacha20_poly1305_encrypt, xwing_kek_salt, Mlkem768X25519Slot,
    SealedEnvelope, SealedSlots, UnwrapFailureReason, UnwrapKeys, UnwrapResult, WrapArgs,
    X25519Slot, AEAD_XCHACHA20_POLY1305, MAX_DECODED_ENVELOPE_BYTES, MAX_SEALED_CIPHERTEXT,
    MAX_SEALED_PLAINTEXT, MAX_SLOTS,
};
use cardanowall::seed_derive::xwing_keygen;
use cardanowall::verifier::decrypt::try_decryptions;
use cardanowall::verifier::fetch::{
    FetchOutboundOptions, FetchOutboundResult, FetchTransport, OutboundError,
};
use cardanowall::verifier::{Decryption, GatewayFetcher, VerifyTxInput};
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn fixture(name: &str) -> Value {
    read_fixture_json(&crypto_core_fixtures().join("sealed-poe").join(name))
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("field `{key}` must be a string: {v}"))
}

fn b(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(v, key)).unwrap_or_else(|e| panic!("bad hex in `{key}`: {e}"))
}

fn fill(byte: u8, n: usize) -> Vec<u8> {
    vec![byte; n]
}

/// A transport that refuses every call — every decrypt test here supplies the
/// ciphertext out-of-band, so the gateway is never consulted.
struct NoFetchTransport;

impl FetchTransport for NoFetchTransport {
    fn fetch(
        &self,
        url: &str,
        _opts: &FetchOutboundOptions,
    ) -> Result<FetchOutboundResult, OutboundError> {
        Err(OutboundError::Transport {
            url: url.to_string(),
            message: "no transport: ciphertext is supplied out-of-band".to_string(),
        })
    }
}

/// Argon2id v1.3 over the explicit (m, t, p) cost parameters — the reference
/// CEK-derivation, recomputed here so the passphrase KAT can pin the CEK→
/// payload_key→ciphertext chain end-to-end without exporting the KDF.
fn argon2id_cek(password: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> [u8; 32] {
    let params = Params::new(m, t, p, Some(32)).expect("valid Argon2 params");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .expect("Argon2id derivation");
    out
}

/// The `cardano-poe-pw-norm-v1` profile, recomputed in-test to pin the
/// normalization equivalence cases against the production normaliser without
/// depending on its internal symbol.
fn normalize_passphrase(passphrase: &str) -> Vec<u8> {
    use unicode_normalization::UnicodeNormalization;
    let white_space: [char; 25] = [
        '\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0020}', '\u{0085}',
        '\u{00a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
        '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}',
        '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
    ];
    let nfkc: String = passphrase.nfkc().collect();
    let mut collapsed = String::new();
    let mut in_run = false;
    for ch in nfkc.chars() {
        if white_space.contains(&ch) {
            if !in_run {
                collapsed.push(' ');
                in_run = true;
            }
        } else {
            collapsed.push(ch);
            in_run = false;
        }
    }
    let after_lead = collapsed.strip_prefix(' ').unwrap_or(&collapsed);
    after_lead
        .strip_suffix(' ')
        .unwrap_or(after_lead)
        .as_bytes()
        .to_vec()
}

/// Build a passphrase-path single-item record around an `enc.passphrase` block.
fn passphrase_record(
    salt: &[u8],
    m: u64,
    t: u64,
    p: u64,
    nonce: &[u8],
    digest: Vec<u8>,
) -> PoeRecord {
    PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), digest)],
            uris: None,
            enc: Some(EncryptionEnvelope {
                scheme: 1,
                aead: "xchacha20-poly1305".to_string(),
                nonce: nonce.to_vec(),
                kem: None,
                slots: None,
                slots_mac: None,
                passphrase: Some(PassphraseBlock {
                    alg: "argon2id".to_string(),
                    salt: salt.to_vec(),
                    params: vec![
                        ("m".to_string(), m),
                        ("t".to_string(), t),
                        ("p".to_string(), p),
                    ],
                }),
            }),
        }]),
        ..PoeRecord::default()
    }
}

/// Run `try_decryptions` for one passphrase entry with out-of-band ciphertext,
/// returning the single decryption row.
fn decrypt_passphrase_row(
    record: &PoeRecord,
    ciphertext: Vec<u8>,
    passphrase: &str,
) -> cardanowall::verifier::DecryptResult {
    let transport = NoFetchTransport;
    let mut fetcher = GatewayFetcher::new(&transport, None);
    let mut ciphertext_bytes = BTreeMap::new();
    ciphertext_bytes.insert(0, ciphertext);
    let input = VerifyTxInput {
        decryption: Some(vec![Decryption::Passphrase {
            item_index: 0,
            passphrase: passphrase.to_string(),
        }]),
        ciphertext_bytes: Some(ciphertext_bytes),
        ..VerifyTxInput::new("00")
    };
    let (rows, _checks) = try_decryptions(record, &input, &mut fetcher);
    rows.into_iter().next().expect("one decryption row")
}

// --------------------------------------------------------------------------
// Passphrase-path KAT (passphrase-n1.json)
// --------------------------------------------------------------------------

#[test]
fn passphrase_n1_full_kat() {
    let corpus = fixture("passphrase-n1.json");
    let v = &corpus["vector"];
    let passphrase = s(v, "passphrase");
    let salt = b(v, "salt_hex");
    let m = v["params"]["m"].as_u64().unwrap();
    let t = v["params"]["t"].as_u64().unwrap();
    let p = v["params"]["p"].as_u64().unwrap();
    let nonce = b(v, "nonce_hex");
    let plaintext = b(v, "plaintext_hex");
    let expected_ciphertext = b(v, "expected_ciphertext_hex");

    // Reproduce the producer byte recipe: CEK = Argon2id(normalize(pw));
    // payload_key = HKDF(CEK, salt=nonce, info=payload-passphrase-v1);
    // AAD = canonicalEncode(AD_CONTENT_PASSPHRASE); ct = XChaCha20-Poly1305.
    let password = normalize_passphrase(passphrase);
    let cek = argon2id_cek(
        &password,
        &salt,
        u32::try_from(m).unwrap(),
        u32::try_from(t).unwrap(),
        u32::try_from(p).unwrap(),
    );
    let payload_key = passphrase_payload_key(&cek, &nonce);
    let aad = ad_content_passphrase(&nonce, "argon2id", &salt, m, t, p);
    let ciphertext = xchacha20_poly1305_encrypt(&payload_key, &nonce, &aad, &plaintext);
    assert_eq!(
        hex::encode(&ciphertext),
        s(v, "expected_ciphertext_hex"),
        "passphrase ciphertext must match the fixture byte-for-byte"
    );

    // End-to-end through the production verifier decrypt path: the recovered
    // plaintext re-hashes to the committed digest (plaintext_hash_ok).
    let digest = cardanowall::hash::sha256(&plaintext).to_vec();
    let record = passphrase_record(&salt, m, t, p, &nonce, digest);
    let row = decrypt_passphrase_row(&record, expected_ciphertext, passphrase);
    assert!(row.ok, "passphrase decrypt should succeed");
    assert_eq!(row.plaintext_hash_ok, Some(true));
    assert!(row.reason.is_none());
}

// --------------------------------------------------------------------------
// Hybrid (X-Wing) per-slot KEK salt (hybrid-kek-salt.json)
// --------------------------------------------------------------------------

#[test]
fn hybrid_kek_salt_recomputed_from_kem_ct_and_pub_r() {
    let corpus = fixture("hybrid-kek-salt.json");
    let v = &corpus["vector"];
    let seed = b(v, "recipient_seed_hex");
    let expected_public = b(v, "recipient_public_hex");
    let kem_ct = b(v, "kem_ct_hex");
    let expected_kek_salt = b(v, "expected_kek_salt_hex");

    // pub_R is recomputed from the 32-byte seed via X-Wing keygen.
    let seed_arr: [u8; 32] = seed.clone().try_into().expect("32-byte seed");
    let pub_r = mlkem768x25519_public_key_from_seed(&seed).expect("derive pub_R");
    assert_eq!(
        hex::encode(&pub_r),
        s(v, "recipient_public_hex"),
        "pub_R recomputed from the seed must match the pinned recipient public key"
    );
    // The seed_derive keygen is the same derivation; both must agree.
    assert_eq!(xwing_keygen(&seed_arr).to_vec(), expected_public);

    // kek_salt = SHA-256("cardano-poe-xwing-kek-salt-v1" || kem_ct || pub_R).
    let salt = xwing_kek_salt(&kem_ct, &pub_r);
    assert_eq!(
        hex::encode(&salt),
        s(v, "expected_kek_salt_hex"),
        "kek_salt must match the pinned SHA-256 over kem_ct || pub_R"
    );
    assert_eq!(salt.to_vec(), expected_kek_salt);
}

// --------------------------------------------------------------------------
// Construction negatives (construction-negative.json)
// --------------------------------------------------------------------------

/// Build an x25519 `SealedEnvelope` from a fixture envelope shape.
fn x25519_envelope_from_json(env: &Value) -> SealedEnvelope {
    let slots = env["slots"]
        .as_array()
        .expect("slots array")
        .iter()
        .map(|sv| X25519Slot {
            epk: b(sv, "epk_hex"),
            wrap: b(sv, "wrap_hex"),
        })
        .collect();
    SealedEnvelope {
        scheme: env["scheme"].as_i64().expect("scheme"),
        aead: s(env, "aead").to_string(),
        kem: s(env, "kem").to_string(),
        nonce: b(env, "nonce_hex"),
        slots: SealedSlots::X25519(slots),
        slots_mac: b(env, "slots_mac_hex"),
    }
}

/// Build a hybrid `SealedEnvelope` from a fixture envelope whose slots store
/// `kem_ct` as a list of hex chunks (exact wire chunk boundaries preserved).
fn hybrid_envelope_from_chunked_json(env: &Value) -> SealedEnvelope {
    let slots = env["slots"]
        .as_array()
        .expect("slots array")
        .iter()
        .map(|sv| {
            let kem_ct = sv["kem_ct_chunks_hex"]
                .as_array()
                .expect("kem_ct_chunks_hex array")
                .iter()
                .map(|c| hex::decode(c.as_str().expect("hex chunk")).expect("valid hex"))
                .collect();
            Mlkem768X25519Slot {
                kem_ct,
                wrap: b(sv, "wrap_hex"),
            }
        })
        .collect();
    SealedEnvelope {
        scheme: env["scheme"].as_i64().expect("scheme"),
        aead: s(env, "aead").to_string(),
        kem: s(env, "kem").to_string(),
        nonce: b(env, "nonce_hex"),
        slots: SealedSlots::Mlkem768X25519(slots),
        slots_mac: b(env, "slots_mac_hex"),
    }
}

fn reason_from_str(reason: &str) -> UnwrapFailureReason {
    match reason {
        "WRONG_RECIPIENT_KEY" => UnwrapFailureReason::WrongRecipientKey,
        "TAMPERED_HEADER" => UnwrapFailureReason::TamperedHeader,
        "TAMPERED_CIPHERTEXT" => UnwrapFailureReason::TamperedCiphertext,
        other => panic!("unknown reason {other}"),
    }
}

#[test]
fn construction_negative_all_zero_shared() {
    let corpus = fixture("construction-negative.json");
    for v in corpus["all_zero_shared_vectors"]
        .as_array()
        .expect("all_zero_shared_vectors")
    {
        let name = s(v, "name");
        let envelope = x25519_envelope_from_json(&v["envelope"]);
        let ciphertext = b(v, "ciphertext_hex");
        let secret = b(v, "recipient_secret_hex");
        let result = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            UnwrapKeys::Single(&secret),
            true,
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: must be a structured non-match, not error: {e}"));
        assert_eq!(
            result,
            UnwrapResult::NotMatched {
                reason: reason_from_str(s(v, "expected_reason"))
            },
            "{name}"
        );
    }
}

#[test]
fn construction_negative_hybrid_header_binding() {
    let corpus = fixture("construction-negative.json");
    for v in corpus["hybrid_header_binding_vectors"]
        .as_array()
        .expect("hybrid_header_binding_vectors")
    {
        let name = s(v, "name");
        let envelope = hybrid_envelope_from_chunked_json(&v["envelope"]);
        let ciphertext = b(v, "ciphertext_hex");
        let seed = b(v, "recipient_seed_hex");
        let result = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            UnwrapKeys::Single(&seed),
            true,
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: must be a structured non-match, not error: {e}"));
        assert_eq!(
            result,
            UnwrapResult::NotMatched {
                reason: reason_from_str(s(v, "expected_reason"))
            },
            "{name}: a swapped nonce breaks the slots-transcript binding"
        );
    }
}

#[test]
fn construction_negative_cross_path_confusion() {
    // A slots-shaped record decrypted with a passphrase input, and a
    // passphrase-shaped record decrypted with a recipient key, MUST both be
    // refused as WRONG_DECRYPTION_INPUT_SHAPE before any AEAD.
    let corpus = fixture("construction-negative.json");
    let v = &corpus["cross_path_vectors"][0];
    let transport = NoFetchTransport;

    // Slots-shaped record, passphrase input → wrong-input-shape.
    let slots_env = &v["slots_envelope"];
    let slot = &slots_env["slots"][0];
    let record = PoeRecord {
        v: 1,
        items: Some(vec![ItemEntry {
            hashes: vec![("sha2-256".to_string(), fill(0u8, 32))],
            uris: None,
            enc: Some(EncryptionEnvelope {
                scheme: 1,
                aead: "xchacha20-poly1305".to_string(),
                nonce: b(slots_env, "nonce_hex"),
                kem: Some(s(slots_env, "kem").to_string()),
                slots: Some(vec![Slot {
                    epk: Some(b(slot, "epk_hex")),
                    kem_ct: None,
                    wrap: Some(b(slot, "wrap_hex")),
                }]),
                slots_mac: Some(b(slots_env, "slots_mac_hex")),
                passphrase: None,
            }),
        }]),
        ..PoeRecord::default()
    };
    let mut fetcher = GatewayFetcher::new(&transport, None);
    let mut ct = BTreeMap::new();
    ct.insert(0, fill(0u8, 32));
    let input = VerifyTxInput {
        decryption: Some(vec![Decryption::Passphrase {
            item_index: 0,
            passphrase: "anything".to_string(),
        }]),
        ciphertext_bytes: Some(ct),
        ..VerifyTxInput::new("00")
    };
    let (rows, _) = try_decryptions(&record, &input, &mut fetcher);
    assert_eq!(
        rows[0].reason.map(|r| r.as_str()),
        Some("WRONG_DECRYPTION_INPUT_SHAPE"),
        "slots record + passphrase input is a shape mismatch"
    );

    // Passphrase-shaped record, recipient-key input → wrong-input-shape.
    let pw_env = &v["passphrase_envelope"];
    let pw_block = &pw_env["passphrase"];
    let record = passphrase_record(
        &b(pw_block, "salt_hex"),
        pw_block["params"]["m"].as_u64().unwrap(),
        pw_block["params"]["t"].as_u64().unwrap(),
        pw_block["params"]["p"].as_u64().unwrap(),
        &b(pw_env, "nonce_hex"),
        fill(0u8, 32),
    );
    let mut fetcher = GatewayFetcher::new(&transport, None);
    let mut ct = BTreeMap::new();
    ct.insert(0, fill(0u8, 32));
    let input = VerifyTxInput {
        decryption: Some(vec![Decryption::Recipient {
            item_index: 0,
            recipient_secret_key: fill(0x11, 32),
        }]),
        ciphertext_bytes: Some(ct),
        ..VerifyTxInput::new("00")
    };
    let (rows, _) = try_decryptions(&record, &input, &mut fetcher);
    assert_eq!(
        rows[0].reason.map(|r| r.as_str()),
        Some("WRONG_DECRYPTION_INPUT_SHAPE"),
        "passphrase record + recipient key is a shape mismatch"
    );
}

// --------------------------------------------------------------------------
// Behavioural pins: single-shot payload bound
// --------------------------------------------------------------------------

#[test]
fn max_sealed_payload_constant_is_two_pow_38_minus_64() {
    assert_eq!(MAX_SEALED_PLAINTEXT, 274_877_906_880);
    assert_eq!(MAX_SEALED_PLAINTEXT, (1u64 << 38) - 64);
    assert_eq!(MAX_SEALED_CIPHERTEXT, MAX_SEALED_PLAINTEXT + 16);
}

#[test]
fn payload_and_ciphertext_bound_guards_reject_at_or_above_the_threshold() {
    // The guards operate on a LENGTH, before any keystream is drawn, so the bound
    // is pinned without allocating a multi-hundred-GB buffer: a real wrap never
    // reaches the over-bound case in a unit test, but the guard the wrap and the
    // unwrap both call is exercised directly at the boundary.
    assert!(assert_plaintext_within_bound(0).is_ok());
    assert!(assert_plaintext_within_bound(MAX_SEALED_PLAINTEXT - 1).is_ok());
    assert_eq!(
        assert_plaintext_within_bound(MAX_SEALED_PLAINTEXT)
            .unwrap_err()
            .code(),
        "PAYLOAD_TOO_LARGE",
    );
    assert_eq!(
        assert_plaintext_within_bound(MAX_SEALED_PLAINTEXT + 1)
            .unwrap_err()
            .code(),
        "PAYLOAD_TOO_LARGE",
    );

    assert!(assert_ciphertext_within_bound(MAX_SEALED_CIPHERTEXT - 1).is_ok());
    assert_eq!(
        assert_ciphertext_within_bound(MAX_SEALED_CIPHERTEXT)
            .unwrap_err()
            .code(),
        "PAYLOAD_TOO_LARGE",
    );

    // A normal-sized wrap is well below the bound and produces ciphertext =
    // plaintext + 16 (the Poly1305 tag), confirming the +16 ciphertext offset.
    let recipient_priv = fill(0x21, 32);
    let recipient_pub = cardanowall::sealed_poe::x25519_public_key(&recipient_priv).unwrap();
    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &fill(0xab, 16),
            recipient_public_keys: &[recipient_pub.to_vec()],
            cek: Some(&fill(0x33, 32)),
            nonce: Some(&fill(0x44, 24)),
            ephemeral_secrets: Some(&[fill(0x55, 32)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut |_: &mut [u8]| panic!("deterministic wrap must not draw randomness"),
    )
    .expect("wrap below the bound");
    assert_eq!(out.ciphertext.len(), 16 + 16, "16B plaintext + 16B tag");
}

// --------------------------------------------------------------------------
// Behavioural pins: per-slot KEK-uniqueness rejection (producer + verifier)
// --------------------------------------------------------------------------

#[test]
fn producer_rejects_duplicate_recipient_public_keys() {
    // Two slots wrapped to the SAME x25519 recipient public key (same epk would
    // result only from a duplicate ephemeral, but the producer also rejects the
    // duplicate epk that a repeated deterministic ephemeral would yield).
    let priv0 = fill(0x21, 32);
    let pub0 = cardanowall::sealed_poe::x25519_public_key(&priv0).unwrap();
    // Duplicate ephemeral secret across the two slots → duplicate epk → reject.
    let err = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"dup",
            recipient_public_keys: &[pub0.to_vec(), pub0.to_vec()],
            cek: Some(&fill(0x33, 32)),
            nonce: Some(&fill(0x44, 24)),
            ephemeral_secrets: Some(&[fill(0x55, 32), fill(0x55, 32)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut |_: &mut [u8]| panic!("deterministic wrap must not draw randomness"),
    )
    .expect_err("duplicate epk must be rejected at the producer");
    assert_eq!(err.code(), "ENC_SLOTS_DUPLICATE_KEM_MATERIAL");
}

#[test]
fn verifier_rejects_duplicate_epk_before_any_decapsulation() {
    let env = SealedEnvelope {
        scheme: 1,
        aead: "xchacha20-poly1305".to_string(),
        kem: "x25519".to_string(),
        nonce: fill(0u8, 24),
        slots: SealedSlots::X25519(vec![
            X25519Slot {
                epk: fill(0xab, 32),
                wrap: fill(0xcd, 48),
            },
            X25519Slot {
                epk: fill(0xab, 32),
                wrap: fill(0xef, 48),
            },
        ]),
        slots_mac: fill(0u8, 32),
    };
    let err = ecies_sealed_poe_unwrap(
        &env,
        &fill(0u8, 16),
        UnwrapKeys::Single(&fill(0x11, 32)),
        true,
        None,
    )
    .expect_err("duplicate epk must be a structural rejection");
    assert_eq!(err.code(), "ENC_SLOTS_DUPLICATE_KEM_MATERIAL");
}

#[test]
fn verifier_rejects_duplicate_kem_ct_before_any_decapsulation() {
    // Two hybrid slots whose kem_ct reassembles to identical 1120-byte enc.
    let enc = fill(0x07, 1120);
    let env = SealedEnvelope {
        scheme: 1,
        aead: "xchacha20-poly1305".to_string(),
        kem: "mlkem768x25519".to_string(),
        nonce: fill(0u8, 24),
        slots: SealedSlots::Mlkem768X25519(vec![
            Mlkem768X25519Slot {
                kem_ct: chunk_kem_ct(&enc),
                wrap: fill(0xcd, 48),
            },
            Mlkem768X25519Slot {
                kem_ct: chunk_kem_ct(&enc),
                wrap: fill(0xef, 48),
            },
        ]),
        slots_mac: fill(0u8, 32),
    };
    let err = ecies_sealed_poe_unwrap(
        &env,
        &fill(0u8, 16),
        UnwrapKeys::Single(&fill(0x11, 32)),
        true,
        None,
    )
    .expect_err("duplicate kem_ct must be a structural rejection");
    assert_eq!(err.code(), "ENC_SLOTS_DUPLICATE_KEM_MATERIAL");
}

// --------------------------------------------------------------------------
// Behavioural pins: the 25-codepoint White_Space normalization set
// --------------------------------------------------------------------------

#[test]
fn white_space_set_is_exactly_25_codepoints() {
    // These 25 are the Unicode 16.0 White_Space property set. The normaliser
    // collapses maximal runs of exactly these to one U+0020.
    let white_space: [u32; 25] = [
        0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x0085, 0x00a0, 0x1680, 0x2000, 0x2001,
        0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029,
        0x202f, 0x205f, 0x3000,
    ];
    assert_eq!(white_space.len(), 25);

    // U+200B ZERO WIDTH SPACE is NOT White_Space: a run of it does NOT collapse.
    // Two passphrases differing only by an interior U+200B normalise differently.
    let with_zwsp = normalize_passphrase("a\u{200b}b");
    let without = normalize_passphrase("ab");
    assert_eq!(
        with_zwsp,
        "a\u{200b}b".as_bytes().to_vec(),
        "U+200B is preserved verbatim, not collapsed"
    );
    assert_ne!(with_zwsp, without);

    // U+001C..U+001F (the C0 information separators) are NOT White_Space here,
    // even though `char::is_whitespace` matches them. They must survive verbatim
    // rather than collapse to a space.
    for cp in 0x1cu32..=0x1f {
        let ch = char::from_u32(cp).unwrap();
        let input = format!("a{ch}b");
        assert_eq!(
            normalize_passphrase(&input),
            input.as_bytes().to_vec(),
            "U+{cp:04X} must NOT be treated as White_Space"
        );
    }
}

// --------------------------------------------------------------------------
// Behavioural pins: passphrase round-trip + AAD tamper + normalization equiv
// --------------------------------------------------------------------------

/// Encrypt a plaintext under the passphrase path and return (record, ciphertext).
fn seal_passphrase(
    passphrase: &str,
    salt: &[u8],
    m: u64,
    t: u64,
    p: u64,
    nonce: &[u8],
    plaintext: &[u8],
) -> (PoeRecord, Vec<u8>) {
    let password = normalize_passphrase(passphrase);
    let cek = argon2id_cek(
        &password,
        salt,
        u32::try_from(m).unwrap(),
        u32::try_from(t).unwrap(),
        u32::try_from(p).unwrap(),
    );
    let payload_key = passphrase_payload_key(&cek, nonce);
    let aad = ad_content_passphrase(nonce, "argon2id", salt, m, t, p);
    let ciphertext = xchacha20_poly1305_encrypt(&payload_key, nonce, &aad, plaintext);
    let digest = cardanowall::hash::sha256(plaintext).to_vec();
    let record = passphrase_record(salt, m, t, p, nonce, digest);
    (record, ciphertext)
}

#[test]
fn passphrase_round_trip_recovers_plaintext() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    let (record, ciphertext) = seal_passphrase(
        "correct horse battery staple",
        &salt,
        8,
        1,
        1,
        &nonce,
        b"sealed body",
    );
    let row = decrypt_passphrase_row(&record, ciphertext, "correct horse battery staple");
    assert!(row.ok);
    assert_eq!(row.plaintext_hash_ok, Some(true));
}

#[test]
fn passphrase_aad_tamper_on_salt_breaks_open() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    let (mut record, ciphertext) = seal_passphrase("pw", &salt, 8, 1, 1, &nonce, b"body");
    // Flip a salt byte in the record's enc block: the AAD recomputed at decrypt
    // no longer matches the one the ciphertext was sealed under, so the AEAD
    // open fails (a tampered-ciphertext verdict).
    if let Some(block) = record.items.as_mut().unwrap()[0]
        .enc
        .as_mut()
        .unwrap()
        .passphrase
        .as_mut()
    {
        block.salt[0] ^= 0x01;
    }
    let row = decrypt_passphrase_row(&record, ciphertext, "pw");
    assert!(!row.ok, "a tampered AAD makes the AEAD open fail");
    assert_eq!(row.plaintext_hash_ok, None);
    assert_eq!(row.reason.map(|r| r.as_str()), Some("TAMPERED_CIPHERTEXT"));
}

#[test]
fn passphrase_aad_tamper_on_params_breaks_open() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    let (mut record, ciphertext) = seal_passphrase("pw", &salt, 8, 1, 1, &nonce, b"body");
    // Bump the `t` parameter in the record. This changes BOTH the derived CEK
    // (different Argon2 cost) and the AAD, so the open fails regardless.
    {
        let block = record.items.as_mut().unwrap()[0]
            .enc
            .as_mut()
            .unwrap()
            .passphrase
            .as_mut()
            .unwrap();
        for (k, val) in block.params.iter_mut() {
            if k == "t" {
                *val = 2;
            }
        }
    }
    let row = decrypt_passphrase_row(&record, ciphertext, "pw");
    assert!(
        !row.ok,
        "a changed Argon2 cost derives a different CEK / AAD"
    );
    assert_eq!(row.reason.map(|r| r.as_str()), Some("TAMPERED_CIPHERTEXT"));
}

#[test]
fn passphrase_normalization_equivalence_for_whitespace_variants() {
    let salt = fill(0x55, 16);
    let nonce = fill(0x66, 24);
    // Seal under a single-space-separated passphrase.
    let (record, ciphertext) =
        seal_passphrase("alpha beta", &salt, 8, 1, 1, &nonce, b"normalized body");

    // Each of these collapses to "alpha beta" after the profile: an NBSP, a TAB,
    // an ideographic space (U+3000), and the NEL separator (U+0085) all map to a
    // single U+0020 interior space, and leading/trailing runs are trimmed.
    for variant in [
        "alpha\u{00a0}beta",     // NBSP
        "alpha\tbeta",           // TAB
        "alpha\u{3000}beta",     // ideographic space
        "alpha\u{0085}beta",     // NEL
        "  alpha   beta  ",      // multiple ASCII spaces + trim
        "alpha \t\u{00a0} beta", // mixed run collapses to one space
    ] {
        let row = decrypt_passphrase_row(&record, ciphertext.clone(), variant);
        assert!(row.ok, "variant {variant:?} should decrypt");
        assert_eq!(
            row.plaintext_hash_ok,
            Some(true),
            "variant {variant:?} normalises to the same CEK"
        );
    }

    // An interior U+200B (NOT White_Space) changes the CEK → decrypt fails.
    let row = decrypt_passphrase_row(&record, ciphertext, "alpha\u{200b} beta");
    assert_eq!(
        row.reason.map(|r| r.as_str()),
        Some("TAMPERED_CIPHERTEXT"),
        "U+200B is not collapsed, so it derives a different CEK"
    );
}

// --------------------------------------------------------------------------
// Behavioural pin: the slots-transcript hash binds the header
// --------------------------------------------------------------------------

#[test]
fn slots_hash_changes_when_a_header_field_changes() {
    // Two envelopes with identical slots but a one-byte-different nonce produce
    // different slots_hash values (the transcript binds the header), so a relay
    // that swaps the nonce cannot keep the slots_mac valid.
    let slots = SealedSlots::X25519(vec![X25519Slot {
        epk: fill(0xab, 32),
        wrap: fill(0xcd, 48),
    }]);
    let h1 = compute_slots_hash("x25519", &fill(0x00, 24), &slots);
    let mut nonce2 = fill(0x00, 24);
    nonce2[23] = 0x10;
    let h2 = compute_slots_hash("x25519", &nonce2, &slots);
    assert_ne!(h1, h2, "the nonce is bound into the slots transcript");
    // The kem identifier is bound too.
    let h3 = compute_slots_hash("mlkem768x25519", &fill(0x00, 24), &slots);
    assert_ne!(
        h1, h3,
        "the kem identifier is bound into the slots transcript"
    );
}

// --------------------------------------------------------------------------
// Verifier resource bounds (MAX_SLOTS, MAX_DECODED_ENVELOPE_BYTES)
// --------------------------------------------------------------------------

const NONCE_LEN: usize = 24;
const SLOTS_MAC_LEN: usize = 32;
const EPK_LEN: usize = 32;
const WRAP_LEN: usize = 48;
const PER_SLOT_X25519: usize = EPK_LEN + WRAP_LEN; // 80

/// A distinct, well-formed epk per slot (the duplicate-KEM-material gate forbids
/// repeats). The bytes need not be valid points: the resource-bound checks run
/// before any KEM primitive, so a structurally-shaped envelope suffices.
fn distinct_x25519_slots(count: usize) -> Vec<X25519Slot> {
    (0..count)
        .map(|i| {
            let mut epk = vec![0u8; EPK_LEN];
            epk[0] = (i & 0xff) as u8;
            epk[1] = ((i >> 8) & 0xff) as u8;
            X25519Slot {
                epk,
                wrap: vec![0u8; WRAP_LEN],
            }
        })
        .collect()
}

fn x25519_envelope(slots: Vec<X25519Slot>) -> SealedEnvelope {
    SealedEnvelope {
        scheme: 1,
        aead: "xchacha20-poly1305".to_string(),
        kem: "x25519".to_string(),
        nonce: vec![0u8; NONCE_LEN],
        slots: SealedSlots::X25519(slots),
        slots_mac: vec![0u8; SLOTS_MAC_LEN],
    }
}

#[test]
fn resource_bound_constants_are_pinned() {
    assert_eq!(MAX_SLOTS, 1024);
    assert_eq!(MAX_DECODED_ENVELOPE_BYTES, 65536);
}

#[test]
fn rejects_more_than_max_slots() {
    // MAX_SLOTS + 1 slots trips the slot-count cap (checked before the byte cap).
    let env = x25519_envelope(distinct_x25519_slots(MAX_SLOTS + 1));
    let err = ecies_sealed_poe_unwrap(
        &env,
        &fill(0u8, 16),
        UnwrapKeys::Single(&fill(0x11, 32)),
        true,
        None,
    )
    .expect_err("more than MAX_SLOTS slots must be a structural rejection");
    assert_eq!(err.code(), "ENC_SLOTS_TOO_MANY");
}

#[test]
fn rejects_decoded_envelope_over_byte_backstop() {
    // The smallest slot count whose decoded size exceeds the byte backstop but is
    // at or below MAX_SLOTS, so the byte backstop (not the slot cap) is the
    // tripping check. floor((65536 - 56) / 80) = 818 fit; 819 exceed it.
    let over = ((MAX_DECODED_ENVELOPE_BYTES - NONCE_LEN - SLOTS_MAC_LEN) / PER_SLOT_X25519) + 1;
    assert!(over <= MAX_SLOTS);
    let env = x25519_envelope(distinct_x25519_slots(over));
    let err = ecies_sealed_poe_unwrap(
        &env,
        &fill(0u8, 16),
        UnwrapKeys::Single(&fill(0x11, 32)),
        true,
        None,
    )
    .expect_err("a decoded envelope over the byte backstop must be rejected");
    assert_eq!(err.code(), "ENC_ENVELOPE_TOO_LARGE");
}

#[test]
fn accepts_envelope_just_below_the_byte_backstop() {
    // One slot fewer than the byte-bound trip: the resource checks pass, so the
    // unwrap proceeds to the trial-decrypt loop and returns a structured
    // non-match (the slots are not real wraps) rather than a resource error.
    let just_under = (MAX_DECODED_ENVELOPE_BYTES - NONCE_LEN - SLOTS_MAC_LEN) / PER_SLOT_X25519;
    let env = x25519_envelope(distinct_x25519_slots(just_under));
    let result = ecies_sealed_poe_unwrap(
        &env,
        &fill(0u8, 16),
        UnwrapKeys::Single(&fill(0x11, 32)),
        true,
        None,
    )
    .expect("just below the byte backstop must not be a resource error");
    assert!(matches!(result, UnwrapResult::NotMatched { .. }));
}

// --------------------------------------------------------------------------
// Canonical transcript / AAD bytes (transcript-bytes.json)
// --------------------------------------------------------------------------

/// Reconstruct the raw SLOTS_TRANSCRIPT canonical bytes the same way
/// `compute_slots_hash` does internally (before prefix + SHA-256), so the
/// pre-hash byte string can be asserted directly against the pinned vector.
fn slots_transcript_bytes(kem: &str, nonce: &[u8], slots: &SealedSlots) -> Vec<u8> {
    let transcript = CborValue::Map(vec![
        (CborValue::text("scheme"), CborValue::Unsigned(1)),
        (CborValue::text("path"), CborValue::text("slots")),
        (
            CborValue::text("aead"),
            CborValue::text(AEAD_XCHACHA20_POLY1305),
        ),
        (CborValue::text("kem"), CborValue::text(kem)),
        (CborValue::text("nonce"), CborValue::Bytes(nonce.to_vec())),
        (CborValue::text("slots"), canonicalize_slots(slots)),
    ]);
    encode_canonical_cbor(&transcript).expect("transcript encodes")
}

/// Load (nonce, slots, slots_mac) from a committed wrap fixture.
fn slots_from_wrap(name: &str, kem: &str) -> (Vec<u8>, SealedSlots, Vec<u8>) {
    let v = &fixture(name)["vector"];
    let nonce = b(v, "nonce_hex");
    let slots_mac = b(v, "expected_slots_mac_hex");
    let arr = v["expected_slots"].as_array().expect("expected_slots");
    let slots = if kem == "x25519" {
        SealedSlots::X25519(
            arr.iter()
                .map(|sv| X25519Slot {
                    epk: b(sv, "epk_hex"),
                    wrap: b(sv, "wrap_hex"),
                })
                .collect(),
        )
    } else {
        SealedSlots::Mlkem768X25519(
            arr.iter()
                .map(|sv| Mlkem768X25519Slot {
                    kem_ct: chunk_kem_ct(&b(sv, "kem_ct_hex")),
                    wrap: b(sv, "wrap_hex"),
                })
                .collect(),
        )
    };
    (nonce, slots, slots_mac)
}

#[test]
fn transcript_and_aad_bytes_match_pinned_vectors() {
    // Pins the exact canonicalEncode output of SLOTS_TRANSCRIPT, AD_CONTENT_SLOTS,
    // and AD_CONTENT_PASSPHRASE so a canonical-encoding divergence localises to
    // the encoder rather than only surfacing as a downstream slots_mac / tag
    // mismatch.
    let corpus = fixture("transcript-bytes.json");
    let mut saw_x25519 = false;
    let mut saw_hybrid = false;
    let mut saw_passphrase = false;
    for v in corpus["vectors"].as_array().expect("vectors") {
        let name = s(v, "name");
        if let Some(kem) = v.get("kem").and_then(|k| k.as_str()) {
            let source = if kem == "x25519" {
                "wrap-n3.json"
            } else {
                "wrap-hybrid-n1.json"
            };
            let (nonce, slots, slots_mac) = slots_from_wrap(source, kem);
            assert_eq!(hex::encode(&nonce), s(v, "nonce_hex"), "{name}");

            let transcript = slots_transcript_bytes(kem, &nonce, &slots);
            assert_eq!(
                hex::encode(&transcript),
                s(v, "expected_slots_transcript_canonical_hex"),
                "{name}: raw SLOTS_TRANSCRIPT bytes"
            );

            let slots_hash = compute_slots_hash(kem, &nonce, &slots);
            assert_eq!(
                hex::encode(slots_hash.as_slice()),
                s(v, "expected_slots_hash_hex"),
                "{name}: slots_hash"
            );

            let ad = ad_content_slots(kem, &nonce, &slots_hash, &slots_mac);
            assert_eq!(
                hex::encode(&ad),
                s(v, "expected_ad_content_slots_canonical_hex"),
                "{name}: AD_CONTENT_SLOTS bytes"
            );
            saw_x25519 = saw_x25519 || kem == "x25519";
            saw_hybrid = saw_hybrid || kem == "mlkem768x25519";
        } else {
            let nonce = b(v, "nonce_hex");
            let salt = b(v, "salt_hex");
            let m = v["params"]["m"].as_u64().unwrap();
            let t = v["params"]["t"].as_u64().unwrap();
            let p = v["params"]["p"].as_u64().unwrap();
            let ad = ad_content_passphrase(&nonce, "argon2id", &salt, m, t, p);
            assert_eq!(
                hex::encode(&ad),
                s(v, "expected_ad_content_passphrase_canonical_hex"),
                "{name}: AD_CONTENT_PASSPHRASE bytes"
            );
            saw_passphrase = true;
        }
    }
    assert!(saw_x25519 && saw_hybrid && saw_passphrase);
}
