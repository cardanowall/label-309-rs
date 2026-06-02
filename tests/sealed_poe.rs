//! Byte-parity tests for the sealed-PoE wrap / unwrap / trial-decrypt layer.
//!
//! Pins every shared cross-implementation vector under
//! `crypto-core/tests/fixtures/sealed-poe/`: the classical and hybrid wrap KATs
//! (expected slots, slots_mac, ciphertext, nonce — reproduced byte-for-byte
//! from the fixture-supplied randomness), the unwrap KATs and negative cases,
//! and the full multi-priv trial-decrypt matrix (current / archived / no-match
//! / worst-case, plus the constant-time-N loop-count matrix). The inline
//! regression cases (slots_mac covers kem_ct, low-order epk, single-priv guard,
//! trial-decrypt-only, bundle dispatch, shuffle) are ported here too. Every
//! assertion pins bytes, plaintext, verdicts, or loop counts — never log
//! strings.

mod common;

use cardanowall::hex;
use cardanowall::sealed_poe::{
    chunk_kem_ct, ecies_sealed_poe_trial_decrypt, ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap_with_rng, join_kem_ct, Mlkem768X25519Slot, RecipientKeyBundle,
    SealedEnvelope, SealedKem, SealedPoeOutput, SealedSlots, TrialDecryptKeys, TrialDecryptResult,
    UnwrapFailureReason, UnwrapKeys, UnwrapProbe, UnwrapResult, WrapArgs, X25519Slot,
    AEAD_XCHACHA20_POLY1305,
};
use cardanowall::seed_derive::xwing_keygen;
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

fn hex_list(v: &Value, key: &str) -> Vec<Vec<u8>> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("field `{key}` must be an array: {v}"))
        .iter()
        .map(|x| hex::decode(x.as_str().expect("hex string element")).expect("valid hex"))
        .collect()
}

/// A random source that refuses to be called — used everywhere a wrap is fully
/// deterministic (every secret supplied + `skip_shuffle`).
fn no_rng() -> impl FnMut(&mut [u8]) {
    |_: &mut [u8]| panic!("deterministic wrap must not draw randomness")
}

/// A simple counter-based pseudo-random fill for the property/shuffle tests,
/// where the exact bytes do not matter, only that distinct draws occur.
fn counter_rng(mut state: u64) -> impl FnMut(&mut [u8]) {
    move |buf: &mut [u8]| {
        for byte in buf.iter_mut() {
            // xorshift-ish step; quality is irrelevant, distinctness is enough.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
    }
}

/// Deterministic 32-byte X25519 private key, matching the reference SDKs'
/// `make_priv(seed) = [(seed + i) & 0xff for i in 0..32]`.
fn make_priv(seed: u8) -> Vec<u8> {
    (0..32u16).map(|i| (u16::from(seed) + i) as u8).collect()
}

fn fill(byte: u8, n: usize) -> Vec<u8> {
    vec![byte; n]
}

/// Build a `SealedEnvelope` from a fixture JSON envelope (the
/// scheme/aead/kem/nonce_hex/slots/slots_mac_hex shape). Accepts arbitrary
/// scheme / aead / kem values so the negative vectors can be exercised.
fn envelope_from_json(env: &Value) -> SealedEnvelope {
    let scheme = env["scheme"].as_i64().expect("scheme must be an integer");
    let aead = s(env, "aead").to_string();
    let kem = s(env, "kem").to_string();
    let nonce = b(env, "nonce_hex");
    let slots_mac = b(env, "slots_mac_hex");
    let slot_values = env["slots"].as_array().expect("slots must be an array");

    // Route the slot shape on the envelope `kem`. For unknown KEMs the slot
    // array is still parsed as classical so the structure check can reject on
    // `kem` first (matching the reference, which validates kem before slots).
    let slots = if kem == "mlkem768x25519" {
        SealedSlots::Mlkem768X25519(
            slot_values
                .iter()
                .map(|sv| {
                    // Hybrid fixtures store kem_ct as a flat hex string; chunk it
                    // into the on-wire ≤64-byte chunks.
                    let kem_ct = chunk_kem_ct(&b(sv, "kem_ct_hex"));
                    Mlkem768X25519Slot {
                        kem_ct,
                        wrap: b(sv, "wrap_hex"),
                    }
                })
                .collect(),
        )
    } else {
        SealedSlots::X25519(
            slot_values
                .iter()
                .map(|sv| X25519Slot {
                    epk: b(sv, "epk_hex"),
                    wrap: b(sv, "wrap_hex"),
                })
                .collect(),
        )
    };

    SealedEnvelope {
        scheme,
        aead,
        kem,
        nonce,
        slots,
        slots_mac,
    }
}

// --------------------------------------------------------------------------
// Classical wrap KATs
// --------------------------------------------------------------------------

/// Reproduce a classical wrap vector and pin every output byte.
fn check_wrap_positive(filename: &str) {
    let corpus = fixture(filename);
    let v = &corpus["vector"];
    let recipient_publics = hex_list(v, "recipient_publics_hex");
    let ephemeral_secrets = hex_list(v, "ephemeral_secrets_hex");
    let cek = b(v, "cek_hex");
    let nonce = b(v, "nonce_hex");
    let plaintext = b(v, "plaintext_hex");

    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &plaintext,
            recipient_public_keys: &recipient_publics,
            kem: Some(SealedKem::X25519),
            cek: Some(&cek),
            nonce: Some(&nonce),
            ephemeral_secrets: Some(&ephemeral_secrets),
            eseeds: None,
            skip_shuffle: true,
        },
        &mut no_rng(),
    )
    .unwrap_or_else(|e| panic!("{filename}: wrap failed: {e}"));

    assert_eq!(out.envelope.scheme, 1, "{filename}");
    assert_eq!(out.envelope.aead, AEAD_XCHACHA20_POLY1305, "{filename}");
    assert_eq!(out.envelope.kem, "x25519", "{filename}");
    assert_eq!(
        hex::encode(&out.envelope.nonce),
        s(v, "nonce_hex"),
        "{filename}"
    );

    let expected_slots = v["expected_slots"].as_array().expect("expected_slots");
    let SealedSlots::X25519(slots) = &out.envelope.slots else {
        panic!("{filename}: expected classical slots");
    };
    assert_eq!(slots.len(), expected_slots.len(), "{filename} slot count");
    for (i, slot) in slots.iter().enumerate() {
        assert_eq!(
            hex::encode(&slot.epk),
            s(&expected_slots[i], "epk_hex"),
            "{filename} slot {i} epk"
        );
        assert_eq!(
            hex::encode(&slot.wrap),
            s(&expected_slots[i], "wrap_hex"),
            "{filename} slot {i} wrap"
        );
    }
    assert_eq!(
        hex::encode(&out.envelope.slots_mac),
        s(v, "expected_slots_mac_hex"),
        "{filename} slots_mac"
    );
    assert_eq!(
        hex::encode(&out.ciphertext),
        s(v, "expected_ciphertext_hex"),
        "{filename} ciphertext"
    );
}

#[test]
fn wrap_n1_empty() {
    check_wrap_positive("wrap-n1-empty.json");
}

#[test]
fn wrap_n3() {
    check_wrap_positive("wrap-n3.json");
}

#[test]
fn wrap_n32() {
    check_wrap_positive("wrap-n32.json");
}

#[test]
fn wrap_negative_cases() {
    let corpus = fixture("wrap-negative.json");
    for v in corpus["vectors"].as_array().expect("vectors") {
        let name = s(v, "name");
        let recipient_publics = hex_list(v, "recipient_publics_hex");
        let ephemeral_secrets = v
            .get("ephemeral_secrets_hex")
            .map(|_| hex_list(v, "ephemeral_secrets_hex"));
        let cek = v.get("cek_hex").map(|_| b(v, "cek_hex"));
        let nonce = v.get("nonce_hex").map(|_| b(v, "nonce_hex"));
        let plaintext = b(v, "plaintext_hex");

        // Some negative cases omit the cek/nonce override; the reference draws a
        // random one before reaching the failing validation, so allow the rng.
        let err = ecies_sealed_poe_wrap_with_rng(
            WrapArgs {
                plaintext: &plaintext,
                recipient_public_keys: &recipient_publics,
                kem: Some(SealedKem::X25519),
                cek: cek.as_deref(),
                nonce: nonce.as_deref(),
                ephemeral_secrets: ephemeral_secrets.as_deref(),
                eseeds: None,
                skip_shuffle: true,
            },
            &mut counter_rng(0x2222_3333),
        )
        .expect_err(name);

        let expected = s(v, "expected_error_code");
        assert_eq!(err.code(), expected, "negative case {name}");
    }
}

// --------------------------------------------------------------------------
// Hybrid (X-Wing) wrap KATs
// --------------------------------------------------------------------------

fn check_hybrid_positive(filename: &str) {
    let corpus = fixture(filename);
    let v = &corpus["vector"];
    let recipient_publics = hex_list(v, "recipient_publics_hex");
    let eseeds = hex_list(v, "eseeds_hex");
    let cek = b(v, "cek_hex");
    let nonce = b(v, "nonce_hex");
    let plaintext = b(v, "plaintext_hex");

    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &plaintext,
            recipient_public_keys: &recipient_publics,
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&cek),
            nonce: Some(&nonce),
            ephemeral_secrets: None,
            eseeds: Some(&eseeds),
            skip_shuffle: true,
        },
        &mut no_rng(),
    )
    .unwrap_or_else(|e| panic!("{filename}: hybrid wrap failed: {e}"));

    assert_eq!(out.envelope.scheme, 1, "{filename}");
    assert_eq!(out.envelope.aead, AEAD_XCHACHA20_POLY1305, "{filename}");
    assert_eq!(out.envelope.kem, "mlkem768x25519", "{filename}");
    assert_eq!(
        hex::encode(&out.envelope.nonce),
        s(v, "nonce_hex"),
        "{filename}"
    );

    let expected_slots = v["expected_slots"].as_array().expect("expected_slots");
    let SealedSlots::Mlkem768X25519(slots) = &out.envelope.slots else {
        panic!("{filename}: expected hybrid slots");
    };
    assert_eq!(slots.len(), expected_slots.len(), "{filename} slot count");
    for (i, slot) in slots.iter().enumerate() {
        // The fixture pins the flat 1120-byte enc; rejoin our chunks to compare.
        assert_eq!(
            hex::encode(&join_kem_ct(&slot.kem_ct)),
            s(&expected_slots[i], "kem_ct_hex"),
            "{filename} slot {i} kem_ct"
        );
        assert_eq!(
            hex::encode(&slot.wrap),
            s(&expected_slots[i], "wrap_hex"),
            "{filename} slot {i} wrap"
        );
    }
    assert_eq!(
        hex::encode(&out.envelope.slots_mac),
        s(v, "expected_slots_mac_hex"),
        "{filename} slots_mac"
    );
    assert_eq!(
        hex::encode(&out.ciphertext),
        s(v, "expected_ciphertext_hex"),
        "{filename} ciphertext"
    );

    // Each recipient's X-Wing secret seed unwraps back to the plaintext.
    let expected_plaintext = b(v, "expected_plaintext_hex");
    for seed_hex in v["recipient_seeds_hex"].as_array().expect("seeds") {
        let seed = hex::decode(seed_hex.as_str().expect("hex")).expect("valid hex");
        let result = ecies_sealed_poe_unwrap(
            &out.envelope,
            &out.ciphertext,
            UnwrapKeys::Single(&seed),
            true,
            None,
        )
        .expect("unwrap should not error");
        assert_eq!(
            result,
            UnwrapResult::Matched {
                plaintext: expected_plaintext.clone()
            },
            "{filename} hybrid unwrap with seed {seed_hex}"
        );
    }
}

#[test]
fn wrap_hybrid_n1() {
    check_hybrid_positive("wrap-hybrid-n1.json");
}

#[test]
fn wrap_hybrid_n3() {
    check_hybrid_positive("wrap-hybrid-n3.json");
}

#[test]
fn hybrid_unwrap_of_degenerate_kem_ct_is_a_clean_non_match_not_a_panic() {
    // Adversarial X-Wing slot: a `kem_ct` whose X25519 ciphertext tail (the last
    // 32 bytes of the 1120-byte enc) is all-zero — a degenerate small-order
    // point. The decapsulator is spec-correct *non-rejecting*: it derives a
    // DEFINED secret over that point rather than panicking. The slot is then no
    // longer the one the wrap produced, so the per-slot wrap AEAD / slots_mac
    // binding fails and the end-to-end unwrap returns a structured
    // WRONG_RECIPIENT_KEY non-match — never an error, never a panic, never the
    // plaintext. This pins the DoS-resistant behaviour end-to-end.
    let recipient_seed = [0x42u8; 32];
    let recipient_public = xwing_keygen(&recipient_seed).to_vec();
    let recipients = vec![recipient_public];
    let eseeds = vec![fill(0x07, 64)];

    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"degenerate-kem-ct regression",
            recipient_public_keys: &recipients,
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&fill(0x11, 32)),
            nonce: Some(&fill(0x22, 24)),
            ephemeral_secrets: None,
            eseeds: Some(&eseeds),
            skip_shuffle: true,
        },
        &mut no_rng(),
    )
    .expect("hybrid wrap");

    // Sanity: the untampered envelope unwraps to the plaintext.
    let clean = ecies_sealed_poe_unwrap(
        &out.envelope,
        &out.ciphertext,
        UnwrapKeys::Single(&recipient_seed),
        true,
        None,
    )
    .expect("clean unwrap");
    assert!(clean.matched(), "baseline envelope must unwrap");

    // Rebuild the envelope with slot 0's kem_ct X25519 tail zeroed out.
    let SealedSlots::Mlkem768X25519(slots) = &out.envelope.slots else {
        panic!("expected hybrid slots");
    };
    let mut enc = join_kem_ct(&slots[0].kem_ct);
    enc[1088..1120].copy_from_slice(&[0u8; 32]);
    assert_eq!(&enc[1088..1120], &[0u8; 32], "ct_x25519 tail is all-zero");
    let degenerate_slot = Mlkem768X25519Slot {
        kem_ct: chunk_kem_ct(&enc),
        wrap: slots[0].wrap.clone(),
    };
    let mut tampered = out.envelope.clone();
    tampered.slots = SealedSlots::Mlkem768X25519(vec![degenerate_slot]);

    // Decapsulating the degenerate point must not panic, and the unwrap must be
    // a structured WRONG_RECIPIENT_KEY non-match (the recovered KEK no longer
    // unwraps the CEK / the slots_mac no longer binds).
    let result = ecies_sealed_poe_unwrap(
        &tampered,
        &out.ciphertext,
        UnwrapKeys::Single(&recipient_seed),
        true,
        None,
    )
    .expect("degenerate kem_ct must be a structured non-match, not an error");
    let UnwrapResult::NotMatched { reason } = result else {
        panic!("degenerate kem_ct must NOT match");
    };
    assert_eq!(reason, UnwrapFailureReason::WrongRecipientKey);
}

// --------------------------------------------------------------------------
// Classical unwrap KATs
// --------------------------------------------------------------------------

fn check_unwrap_positive(filename: &str) {
    let corpus = fixture(filename);
    let v = &corpus["vector"];
    let envelope = envelope_from_json(&v["envelope"]);
    let ciphertext = b(v, "ciphertext_hex");
    let privs = hex_list(v, "recipient_secrets_hex");
    let expected = b(v, "expected_plaintext_hex");

    for priv_key in &privs {
        let result = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            UnwrapKeys::Single(priv_key),
            true,
            None,
        )
        .unwrap_or_else(|e| panic!("{filename}: unwrap errored: {e}"));
        assert_eq!(
            result,
            UnwrapResult::Matched {
                plaintext: expected.clone()
            },
            "{filename}"
        );
    }
}

#[test]
fn unwrap_n1_empty() {
    check_unwrap_positive("unwrap-n1-empty.json");
}

#[test]
fn unwrap_n3() {
    check_unwrap_positive("unwrap-n3.json");
}

#[test]
fn unwrap_n32() {
    check_unwrap_positive("unwrap-n32.json");
}

#[test]
fn unwrap_negative_matched_false_single_priv() {
    let corpus = fixture("unwrap-negative.json");
    for v in corpus["matched_false_vectors"]
        .as_array()
        .expect("matched_false")
    {
        // The multipriv-mac-fail vector consumes the multi-priv surface.
        if v.get("recipient_secret_hex").is_none() {
            continue;
        }
        let name = s(v, "name");
        let envelope = envelope_from_json(&v["envelope"]);
        let ciphertext = b(v, "ciphertext_hex");
        let priv_key = b(v, "recipient_secret_hex");
        let result = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            UnwrapKeys::Single(&priv_key),
            true,
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: should be a structured non-match, not error: {e}"));
        let UnwrapResult::NotMatched { reason } = result else {
            panic!("{name}: expected NotMatched");
        };
        assert_eq!(reason.as_str(), s(v, "expected_reason"), "{name}");
    }
}

#[test]
fn unwrap_negative_raise_single_priv() {
    let corpus = fixture("unwrap-negative.json");
    for v in corpus["raise_vectors"].as_array().expect("raise_vectors") {
        let name = s(v, "name");
        // Single-priv raise cases only.
        if v.get("recipient_secret_hex").is_none() || v.get("recipient_secret_keys_hex").is_some() {
            continue;
        }
        let envelope = envelope_from_json(&v["envelope"]);
        let ciphertext = b(v, "ciphertext_hex");
        let priv_key = b(v, "recipient_secret_hex");
        let err = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            UnwrapKeys::Single(&priv_key),
            true,
            None,
        )
        .expect_err(name);
        assert_eq!(err.code(), s(v, "expected_error_code"), "{name}");
    }
}

#[test]
fn unwrap_negative_multipriv_mac_fail() {
    let corpus = fixture("unwrap-negative.json");
    let v = corpus["matched_false_vectors"]
        .as_array()
        .expect("matched_false")
        .iter()
        .find(|x| s(x, "name") == "multipriv-mac-fail")
        .expect("multipriv-mac-fail vector");
    let envelope = envelope_from_json(&v["envelope"]);
    let ciphertext = b(v, "ciphertext_hex");
    let privs = hex_list(v, "recipient_secret_keys_hex");
    let result = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        UnwrapKeys::Multi(&privs),
        true,
        None,
    )
    .expect("structured non-match");
    assert_eq!(
        result,
        UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::TamperedHeader
        }
    );
}

#[test]
fn unwrap_negative_multipriv_input_validation() {
    let corpus = fixture("unwrap-negative.json");
    // empty / both-forms / neither-form / wrong-length all map to
    // INVALID_RECIPIENT_KEY in the reference; reproduce the ones the typed
    // Rust API can express via the multi-priv list.
    let v = corpus["raise_vectors"]
        .as_array()
        .expect("raise_vectors")
        .iter()
        .find(|x| s(x, "name") == "multipriv-element-wrong-length")
        .expect("multipriv-element-wrong-length");
    let envelope = envelope_from_json(&v["envelope"]);
    let ciphertext = b(v, "ciphertext_hex");
    let privs = hex_list(v, "recipient_secret_keys_hex");
    let err = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        UnwrapKeys::Multi(&privs),
        true,
        None,
    )
    .expect_err("wrong-length element");
    assert_eq!(err.code(), "INVALID_RECIPIENT_KEY");

    // Empty flat list is a programmer error.
    let any = corpus["matched_false_vectors"].as_array().unwrap()[0].clone();
    let envelope = envelope_from_json(&any["envelope"]);
    let ciphertext = b(&any, "ciphertext_hex");
    let empty: Vec<Vec<u8>> = Vec::new();
    let err = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        UnwrapKeys::Multi(&empty),
        true,
        None,
    )
    .expect_err("empty flat list");
    assert_eq!(err.code(), "INVALID_RECIPIENT_KEY");
}

// --------------------------------------------------------------------------
// Multi-priv unwrap matrix
// --------------------------------------------------------------------------

struct MultiprivCase {
    envelope: SealedEnvelope,
    ciphertext: Vec<u8>,
    privs: Vec<Vec<u8>>,
    vector: Value,
}

fn load_multipriv(filename: &str) -> MultiprivCase {
    let corpus = fixture(filename);
    let v = corpus["vector"].clone();
    MultiprivCase {
        envelope: envelope_from_json(&v["envelope"]),
        ciphertext: b(&v, "ciphertext_hex"),
        privs: hex_list(&v, "recipient_privs_hex"),
        vector: v,
    }
}

#[test]
fn unwrap_multipriv_current_match() {
    let c = load_multipriv("unwrap-multipriv-current-match.json");
    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &c.envelope,
        &c.ciphertext,
        UnwrapKeys::Multi(&c.privs),
        true,
        Some(&mut probe),
    )
    .expect("unwrap");
    assert_eq!(
        result,
        UnwrapResult::Matched {
            plaintext: b(&c.vector, "expected_plaintext_hex")
        }
    );
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
    let inner = c.vector["expected_inner_loop_count_per_priv"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(probe.inner.per_priv_counts, vec![inner]);
}

#[test]
fn unwrap_multipriv_archived_match() {
    let c = load_multipriv("unwrap-multipriv-archived-match.json");
    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &c.envelope,
        &c.ciphertext,
        UnwrapKeys::Multi(&c.privs),
        true,
        Some(&mut probe),
    )
    .expect("unwrap");
    assert_eq!(
        result,
        UnwrapResult::Matched {
            plaintext: b(&c.vector, "expected_plaintext_hex")
        }
    );
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
    let inner = c.vector["expected_inner_loop_count_per_priv"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(probe.inner.per_priv_counts, vec![inner, inner, inner]);
}

#[test]
fn unwrap_multipriv_no_match() {
    let c = load_multipriv("unwrap-multipriv-no-match.json");
    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &c.envelope,
        &c.ciphertext,
        UnwrapKeys::Multi(&c.privs),
        true,
        Some(&mut probe),
    )
    .expect("unwrap");
    assert_eq!(
        result,
        UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::WrongRecipientKey
        }
    );
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
    let inner = c.vector["expected_inner_loop_count_per_priv"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(probe.inner.per_priv_counts, vec![inner; 4]);
}

#[test]
fn unwrap_multipriv_n32_k10_worst_case() {
    let c = load_multipriv("unwrap-multipriv-n32-k10-worst-case.json");
    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &c.envelope,
        &c.ciphertext,
        UnwrapKeys::Multi(&c.privs),
        true,
        Some(&mut probe),
    )
    .expect("unwrap");
    assert_eq!(
        result,
        UnwrapResult::Matched {
            plaintext: b(&c.vector, "expected_plaintext_hex")
        }
    );
    assert_eq!(probe.outer.count, 10);
    assert_eq!(probe.inner.per_priv_counts.len(), 10);
    assert!(probe.inner.per_priv_counts.iter().all(|&c| c == 32));
    assert_eq!(probe.inner.per_priv_counts.iter().sum::<usize>(), 320);
}

#[test]
fn unwrap_multipriv_ac9_constant_time_n_matrix() {
    let scenarios: &[(&str, usize, usize, bool)] = &[
        ("unwrap-multipriv-ac9-priv0-slot0.json", 1, 1, true),
        ("unwrap-multipriv-ac9-priv0-slot31.json", 1, 1, true),
        ("unwrap-multipriv-ac9-priv4-slot0.json", 5, 5, true),
        ("unwrap-multipriv-ac9-priv4-slot31.json", 5, 5, true),
        ("unwrap-multipriv-ac9-no-match.json", 5, 5, false),
    ];
    for (filename, expected_outer, n_privs_entered, matched) in scenarios {
        let c = load_multipriv(filename);
        let mut probe = UnwrapProbe::default();
        let result = ecies_sealed_poe_unwrap(
            &c.envelope,
            &c.ciphertext,
            UnwrapKeys::Multi(&c.privs),
            true,
            Some(&mut probe),
        )
        .expect("unwrap");
        if *matched {
            assert_eq!(
                result,
                UnwrapResult::Matched {
                    plaintext: b(&c.vector, "expected_plaintext_hex")
                },
                "{filename}"
            );
        } else {
            assert_eq!(
                result,
                UnwrapResult::NotMatched {
                    reason: UnwrapFailureReason::WrongRecipientKey
                },
                "{filename}"
            );
        }
        assert_eq!(probe.outer.count, *expected_outer, "{filename} outer");
        // Constant-time-N: every entered priv ran all 32 slots.
        assert_eq!(
            probe.inner.per_priv_counts,
            vec![32usize; *n_privs_entered],
            "{filename} inner"
        );
    }
}

// --------------------------------------------------------------------------
// Trial-decrypt-only (no content AEAD)
// --------------------------------------------------------------------------

#[test]
fn trial_decrypt_current_match_reports_slot_index() {
    let c = load_multipriv("unwrap-multipriv-current-match.json");
    let mut probe = UnwrapProbe::default();
    let res = ecies_sealed_poe_trial_decrypt(
        &c.envelope,
        TrialDecryptKeys::Multi(&c.privs),
        true,
        Some(&mut probe),
    )
    .expect("trial decrypt");
    match res {
        TrialDecryptResult::Match { slot_idx, cek } => {
            assert_eq!(slot_idx, 0);
            assert_eq!(cek.len(), 32);
        }
        other => panic!("expected match, got {other:?}"),
    }
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
    assert_eq!(
        probe.inner.count as u64,
        c.vector["expected_inner_loop_count_per_priv"]
            .as_u64()
            .unwrap()
    );
}

#[test]
fn trial_decrypt_archived_match_constant_time_inner() {
    let c = load_multipriv("unwrap-multipriv-archived-match.json");
    let mut probe = UnwrapProbe::default();
    let res = ecies_sealed_poe_trial_decrypt(
        &c.envelope,
        TrialDecryptKeys::Multi(&c.privs),
        true,
        Some(&mut probe),
    )
    .expect("trial decrypt");
    assert!(matches!(res, TrialDecryptResult::Match { .. }));
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
    let inner = c.vector["expected_inner_loop_count_per_priv"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(probe.inner.per_priv_counts, vec![inner, inner, inner]);
}

#[test]
fn trial_decrypt_no_match_exhausts_all_privs() {
    let c = load_multipriv("unwrap-multipriv-no-match.json");
    let mut probe = UnwrapProbe::default();
    let res = ecies_sealed_poe_trial_decrypt(
        &c.envelope,
        TrialDecryptKeys::Multi(&c.privs),
        true,
        Some(&mut probe),
    )
    .expect("trial decrypt");
    assert_eq!(res, TrialDecryptResult::NoAeadPass);
    assert_eq!(
        probe.outer.count as u64,
        c.vector["expected_outer_loop_count"].as_u64().unwrap()
    );
}

#[test]
fn trial_decrypt_n32_k10_enters_320_slots() {
    let c = load_multipriv("unwrap-multipriv-n32-k10-worst-case.json");
    let mut probe = UnwrapProbe::default();
    let res = ecies_sealed_poe_trial_decrypt(
        &c.envelope,
        TrialDecryptKeys::Multi(&c.privs),
        true,
        Some(&mut probe),
    )
    .expect("trial decrypt");
    assert!(matches!(res, TrialDecryptResult::Match { .. }));
    assert_eq!(probe.outer.count, 10);
    assert_eq!(probe.inner.per_priv_counts.len(), 10);
    assert!(probe.inner.per_priv_counts.iter().all(|&c| c == 32));
    assert_eq!(probe.inner.per_priv_counts.iter().sum::<usize>(), 320);
}

#[test]
fn trial_decrypt_ac9_matrix_constant_time_n() {
    let scenarios: &[(&str, bool)] = &[
        ("unwrap-multipriv-ac9-priv0-slot0.json", true),
        ("unwrap-multipriv-ac9-priv0-slot31.json", true),
        ("unwrap-multipriv-ac9-priv4-slot0.json", true),
        ("unwrap-multipriv-ac9-priv4-slot31.json", true),
        ("unwrap-multipriv-ac9-no-match.json", false),
    ];
    for (filename, matched) in scenarios {
        let c = load_multipriv(filename);
        let mut probe = UnwrapProbe::default();
        let res = ecies_sealed_poe_trial_decrypt(
            &c.envelope,
            TrialDecryptKeys::Multi(&c.privs),
            true,
            Some(&mut probe),
        )
        .expect("trial decrypt");
        if *matched {
            assert!(
                matches!(res, TrialDecryptResult::Match { .. }),
                "{filename}"
            );
        } else {
            assert_eq!(res, TrialDecryptResult::NoAeadPass, "{filename}");
        }
        assert!(
            probe.inner.per_priv_counts.iter().all(|&c| c == 32),
            "{filename} constant-time-N"
        );
    }
}

#[test]
fn trial_decrypt_forged_slots_mac_surfaces_aead_pass_no_mac_match() {
    let recipient_priv = fill(0x7a, 32);
    let recipient_pub = cardanowall::sealed_poe::x25519_public_key(&recipient_priv).unwrap();
    let mut wrapped = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &fill(0xab, 16),
            recipient_public_keys: &[recipient_pub.to_vec()],
            cek: Some(&fill(0x33, 32)),
            nonce: Some(&fill(0x44, 24)),
            ephemeral_secrets: Some(&[fill(0x55, 32)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");
    // Forge the slots_mac: an honest slot opens (AEAD-pass) but the MAC fails.
    wrapped.envelope.slots_mac[0] ^= 0xff;
    let res = ecies_sealed_poe_trial_decrypt(
        &wrapped.envelope,
        TrialDecryptKeys::Multi(&[recipient_priv]),
        true,
        None,
    )
    .expect("trial decrypt");
    assert_eq!(res, TrialDecryptResult::AeadPassNoMacMatch);
}

#[test]
fn trial_decrypt_rejects_empty_flat_list() {
    let c = load_multipriv("unwrap-multipriv-current-match.json");
    let empty: Vec<Vec<u8>> = Vec::new();
    let err =
        ecies_sealed_poe_trial_decrypt(&c.envelope, TrialDecryptKeys::Multi(&empty), true, None)
            .expect_err("empty flat list");
    assert_eq!(err.code(), "INVALID_RECIPIENT_KEY");
}

#[test]
fn trial_decrypt_partitioning_oracle_nonce_check() {
    let c = load_multipriv("unwrap-multipriv-current-match.json");
    let mut bad = c.envelope.clone();
    bad.nonce = vec![0u8; 20];
    let err = ecies_sealed_poe_trial_decrypt(&bad, TrialDecryptKeys::Multi(&c.privs), true, None)
        .expect_err("bad nonce");
    assert_eq!(err.code(), "NONCE_LENGTH_MISMATCH");
}

// --------------------------------------------------------------------------
// Partitioning-oracle pre-check ordering (single-priv)
// --------------------------------------------------------------------------

#[test]
fn partitioning_oracle_pre_check_order() {
    let priv_key = make_priv(0xaa);
    let valid_epk = cardanowall::sealed_poe::x25519_public_key(&make_priv(0xbb)).unwrap();
    let valid_wrap = fill(0xcc, 48);
    let valid_nonce = vec![0u8; 24];
    let valid_mac = fill(0xdd, 32);
    let valid_ct = fill(0xee, 16);

    let base = |slots: SealedSlots, nonce: Vec<u8>, mac: Vec<u8>| SealedEnvelope {
        scheme: 1,
        aead: AEAD_XCHACHA20_POLY1305.to_string(),
        kem: "x25519".to_string(),
        nonce,
        slots,
        slots_mac: mac,
    };

    // 1. empty slots
    let env = base(
        SealedSlots::X25519(vec![]),
        valid_nonce.clone(),
        valid_mac.clone(),
    );
    assert_eq!(
        ecies_sealed_poe_unwrap(&env, &valid_ct, UnwrapKeys::Single(&priv_key), true, None)
            .unwrap_err()
            .code(),
        "ENC_SLOTS_EMPTY"
    );

    // 2. nonce wrong length
    let env = base(
        SealedSlots::X25519(vec![X25519Slot {
            epk: valid_epk.to_vec(),
            wrap: valid_wrap.clone(),
        }]),
        vec![0u8; 12],
        valid_mac.clone(),
    );
    assert_eq!(
        ecies_sealed_poe_unwrap(&env, &valid_ct, UnwrapKeys::Single(&priv_key), true, None)
            .unwrap_err()
            .code(),
        "NONCE_LENGTH_MISMATCH"
    );

    // 3. slots_mac wrong length
    let env = base(
        SealedSlots::X25519(vec![X25519Slot {
            epk: valid_epk.to_vec(),
            wrap: valid_wrap.clone(),
        }]),
        valid_nonce.clone(),
        fill(0xdd, 16),
    );
    assert_eq!(
        ecies_sealed_poe_unwrap(&env, &valid_ct, UnwrapKeys::Single(&priv_key), true, None)
            .unwrap_err()
            .code(),
        "ENC_SLOTS_MAC_INVALID_LENGTH"
    );

    // 4. epk wrong length
    let env = base(
        SealedSlots::X25519(vec![X25519Slot {
            epk: fill(0xbb, 16),
            wrap: valid_wrap.clone(),
        }]),
        valid_nonce.clone(),
        valid_mac.clone(),
    );
    assert_eq!(
        ecies_sealed_poe_unwrap(&env, &valid_ct, UnwrapKeys::Single(&priv_key), true, None)
            .unwrap_err()
            .code(),
        "KEM_EPK_LENGTH_MISMATCH"
    );

    // 5. wrap wrong length
    let env = base(
        SealedSlots::X25519(vec![X25519Slot {
            epk: valid_epk.to_vec(),
            wrap: fill(0xcc, 32),
        }]),
        valid_nonce,
        valid_mac,
    );
    assert_eq!(
        ecies_sealed_poe_unwrap(&env, &valid_ct, UnwrapKeys::Single(&priv_key), true, None)
            .unwrap_err()
            .code(),
        "WRAP_LENGTH_MISMATCH"
    );
}

// --------------------------------------------------------------------------
// Single-priv regression guard: multi-priv outer counter stays untouched
// --------------------------------------------------------------------------

#[test]
fn single_priv_does_not_enter_the_multi_priv_outer_loop() {
    let corpus = fixture("unwrap-n32.json");
    let v = &corpus["vector"];
    let envelope = envelope_from_json(&v["envelope"]);
    let ciphertext = b(v, "ciphertext_hex");
    let privs = hex_list(v, "recipient_secrets_hex");
    let expected = b(v, "expected_plaintext_hex");

    let mut probe = UnwrapProbe::default();
    let result = ecies_sealed_poe_unwrap(
        &envelope,
        &ciphertext,
        UnwrapKeys::Single(&privs[0]),
        true,
        Some(&mut probe),
    )
    .expect("unwrap");
    assert_eq!(
        result,
        UnwrapResult::Matched {
            plaintext: expected
        }
    );
    // Constant-time-N: every slot entered.
    assert_eq!(probe.inner.count, 32);
    // The single-priv path must NOT enter the multi-priv outer loop.
    assert_eq!(probe.outer.count, 0);
}

// --------------------------------------------------------------------------
// Low-order epk regression: a non-match, never a crash
// --------------------------------------------------------------------------

const LOW_ORDER_EPKS: &[&str] = &[
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

fn wrap_two_recipients(plaintext: &[u8]) -> SealedPoeOutput {
    let r0 = make_priv(0x20);
    let r1 = make_priv(0x60);
    let pubs = vec![
        cardanowall::sealed_poe::x25519_public_key(&r0)
            .unwrap()
            .to_vec(),
        cardanowall::sealed_poe::x25519_public_key(&r1)
            .unwrap()
            .to_vec(),
    ];
    ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext,
            recipient_public_keys: &pubs,
            skip_shuffle: true,
            ..Default::default()
        },
        &mut counter_rng(0xabcd_ef01),
    )
    .expect("wrap")
}

#[test]
fn low_order_epk_is_a_non_match_never_a_throw() {
    for epk_hex in LOW_ORDER_EPKS {
        let low_order = hex::decode(epk_hex).unwrap();

        // All-low-order envelope: no slot can open → clean non-match.
        let r0 = make_priv(0x11);
        let r1 = make_priv(0x55);
        let pubs = vec![
            cardanowall::sealed_poe::x25519_public_key(&r0)
                .unwrap()
                .to_vec(),
            cardanowall::sealed_poe::x25519_public_key(&r1)
                .unwrap()
                .to_vec(),
        ];
        let out = ecies_sealed_poe_wrap_with_rng(
            WrapArgs {
                plaintext: b"all-low-order",
                recipient_public_keys: &pubs,
                skip_shuffle: true,
                ..Default::default()
            },
            &mut counter_rng(0x1234_5678),
        )
        .expect("wrap");
        let SealedSlots::X25519(slots) = &out.envelope.slots else {
            unreachable!()
        };
        let all_low: Vec<X25519Slot> = slots
            .iter()
            .map(|s| X25519Slot {
                epk: low_order.clone(),
                wrap: s.wrap.clone(),
            })
            .collect();
        let env = SealedEnvelope {
            slots: SealedSlots::X25519(all_low),
            ..out.envelope.clone()
        };
        let stranger = make_priv(0x99);
        let res = ecies_sealed_poe_unwrap(
            &env,
            &out.ciphertext,
            UnwrapKeys::Single(&stranger),
            true,
            None,
        )
        .expect("must not error");
        assert!(!res.matched(), "{epk_hex}: all-low-order should not match");

        // Multi-priv form, all-low-order, still no match.
        let res = ecies_sealed_poe_unwrap(
            &env,
            &out.ciphertext,
            UnwrapKeys::Multi(&[make_priv(0x99), make_priv(0xcd)]),
            true,
            None,
        )
        .expect("must not error");
        assert!(!res.matched(), "{epk_hex}: multi-priv all-low-order");

        // Trial-decrypt all-low-order → no_aead_pass.
        let res = ecies_sealed_poe_trial_decrypt(
            &env,
            TrialDecryptKeys::Multi(&[make_priv(0x99)]),
            true,
            None,
        )
        .expect("must not error");
        assert_eq!(res, TrialDecryptResult::NoAeadPass, "{epk_hex}");

        // Legitimate slot 0 + low-order slot 1: CEK recovered but slots_mac
        // disagrees → TAMPERED_HEADER (not a crash, not WRONG_RECIPIENT_KEY).
        let out = wrap_two_recipients(b"low-order-epk-regression");
        let SealedSlots::X25519(slots) = &out.envelope.slots else {
            unreachable!()
        };
        let clobbered: Vec<X25519Slot> = slots
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i == 1 {
                    X25519Slot {
                        epk: low_order.clone(),
                        wrap: s.wrap.clone(),
                    }
                } else {
                    s.clone()
                }
            })
            .collect();
        let env = SealedEnvelope {
            slots: SealedSlots::X25519(clobbered),
            ..out.envelope.clone()
        };
        let mut probe = UnwrapProbe::default();
        let res = ecies_sealed_poe_unwrap(
            &env,
            &out.ciphertext,
            UnwrapKeys::Single(&make_priv(0x20)),
            true,
            Some(&mut probe),
        )
        .expect("must not error");
        assert_eq!(
            res,
            UnwrapResult::NotMatched {
                reason: UnwrapFailureReason::TamperedHeader
            },
            "{epk_hex}: clobbered sibling slot"
        );
        // Constant-time-N still enters every slot even past the match.
        assert_eq!(probe.inner.count, env.slots.len(), "{epk_hex}");
    }
}

// --------------------------------------------------------------------------
// Bundle dispatch
// --------------------------------------------------------------------------

#[test]
fn bundle_dispatch_classical_envelope() {
    let recipient_priv = fill(0x21, 32);
    let recipient_pub = cardanowall::sealed_poe::x25519_public_key(&recipient_priv).unwrap();
    let sealed = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"bundle-dispatch-roundtrip",
            recipient_public_keys: &[recipient_pub.to_vec()],
            cek: Some(&fill(0x33, 32)),
            nonce: Some(&fill(0x44, 24)),
            ephemeral_secrets: Some(&[fill(0x55, 32)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");

    // Unwraps from x25519_private_keys; a non-matching hybrid seed is ignored.
    let res = ecies_sealed_poe_unwrap(
        &sealed.envelope,
        &sealed.ciphertext,
        UnwrapKeys::Bundle(&RecipientKeyBundle {
            x25519_private_keys: vec![recipient_priv.clone()],
            mlkem768x25519_secret_seeds: vec![fill(0xfe, 32)],
        }),
        true,
        None,
    )
    .expect("unwrap");
    assert_eq!(
        res,
        UnwrapResult::Matched {
            plaintext: b"bundle-dispatch-roundtrip".to_vec()
        }
    );

    // Bundle trial-decrypt == flat-list trial-decrypt, byte-for-byte.
    let flat = ecies_sealed_poe_trial_decrypt(
        &sealed.envelope,
        TrialDecryptKeys::Multi(std::slice::from_ref(&recipient_priv)),
        true,
        None,
    )
    .expect("trial");
    let bundled = ecies_sealed_poe_trial_decrypt(
        &sealed.envelope,
        TrialDecryptKeys::Bundle(&RecipientKeyBundle {
            x25519_private_keys: vec![recipient_priv.clone()],
            mlkem768x25519_secret_seeds: vec![],
        }),
        true,
        None,
    )
    .expect("trial");
    assert_eq!(flat, bundled);
    assert!(matches!(bundled, TrialDecryptResult::Match { .. }));

    // Empty x25519 list (archived-only identity) → clean non-match.
    let res = ecies_sealed_poe_unwrap(
        &sealed.envelope,
        &sealed.ciphertext,
        UnwrapKeys::Bundle(&RecipientKeyBundle {
            x25519_private_keys: vec![],
            mlkem768x25519_secret_seeds: vec![fill(0x01, 32)],
        }),
        true,
        None,
    )
    .expect("unwrap");
    assert_eq!(
        res,
        UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::WrongRecipientKey
        }
    );
    let trial = ecies_sealed_poe_trial_decrypt(
        &sealed.envelope,
        TrialDecryptKeys::Bundle(&RecipientKeyBundle::default()),
        true,
        None,
    )
    .expect("trial");
    assert_eq!(trial, TrialDecryptResult::NoAeadPass);
}

#[test]
fn bundle_dispatch_hybrid_envelope() {
    let seed = fill(0x11, 32);
    let seed_arr: [u8; 32] = seed.clone().try_into().unwrap();
    let public_key = xwing_keygen(&seed_arr);
    let sealed = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"bundle-dispatch-roundtrip",
            recipient_public_keys: &[public_key.to_vec()],
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&fill(0xab, 32)),
            nonce: Some(&fill(0xcd, 24)),
            eseeds: Some(&[fill(0xe0, 64)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");

    // Unwraps from mlkem768x25519_secret_seeds; classical privs irrelevant.
    let res = ecies_sealed_poe_unwrap(
        &sealed.envelope,
        &sealed.ciphertext,
        UnwrapKeys::Bundle(&RecipientKeyBundle {
            x25519_private_keys: vec![fill(0x99, 32)],
            mlkem768x25519_secret_seeds: vec![seed.clone()],
        }),
        true,
        None,
    )
    .expect("unwrap");
    assert_eq!(
        res,
        UnwrapResult::Matched {
            plaintext: b"bundle-dispatch-roundtrip".to_vec()
        }
    );

    // Empty hybrid seed list facing a hybrid record → no_aead_pass.
    let trial = ecies_sealed_poe_trial_decrypt(
        &sealed.envelope,
        TrialDecryptKeys::Bundle(&RecipientKeyBundle {
            x25519_private_keys: vec![fill(0x21, 32)],
            mlkem768x25519_secret_seeds: vec![],
        }),
        true,
        None,
    )
    .expect("trial");
    assert_eq!(trial, TrialDecryptResult::NoAeadPass);
}

// --------------------------------------------------------------------------
// Hybrid slots_mac covers kem_ct (regression)
// --------------------------------------------------------------------------

#[test]
fn hybrid_slots_mac_covers_kem_ct() {
    let seed_a = fill(0x11, 32);
    let seed_b = fill(0x22, 32);
    let pub_a = xwing_keygen(&seed_a.clone().try_into().unwrap());
    let pub_b = xwing_keygen(&seed_b.clone().try_into().unwrap());

    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"hybrid-slots-mac-kem-ct-coverage",
            recipient_public_keys: &[pub_a.to_vec(), pub_b.to_vec()],
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&fill(0xab, 32)),
            nonce: Some(&fill(0xcd, 24)),
            eseeds: Some(&[fill(0xe1, 64), fill(0xe2, 64)]),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");

    // Sanity: recipient A opens cleanly before tampering.
    let clean = ecies_sealed_poe_unwrap(
        &out.envelope,
        &out.ciphertext,
        UnwrapKeys::Single(&seed_a),
        true,
        None,
    )
    .expect("unwrap");
    assert!(clean.matched());

    // Flip a byte of slot 1's first kem_ct chunk; slot 0 (recipient A) untouched.
    let SealedSlots::Mlkem768X25519(slots) = &out.envelope.slots else {
        unreachable!()
    };
    let mut tampered_chunks = slots[1].kem_ct.clone();
    tampered_chunks[0][0] ^= 0x01;
    let tampered = SealedEnvelope {
        slots: SealedSlots::Mlkem768X25519(vec![
            slots[0].clone(),
            Mlkem768X25519Slot {
                kem_ct: tampered_chunks,
                wrap: slots[1].wrap.clone(),
            },
        ]),
        ..out.envelope.clone()
    };
    let res = ecies_sealed_poe_unwrap(
        &tampered,
        &out.ciphertext,
        UnwrapKeys::Single(&seed_a),
        true,
        None,
    )
    .expect("unwrap");
    assert_eq!(
        res,
        UnwrapResult::NotMatched {
            reason: UnwrapFailureReason::TamperedHeader
        }
    );
}

#[test]
fn hybrid_kem_ct_length_mismatch_is_rejected_before_decap() {
    let corpus = fixture("wrap-hybrid-n1.json");
    let v = &corpus["vector"];
    let recipient_publics = hex_list(v, "recipient_publics_hex");
    let eseeds = hex_list(v, "eseeds_hex");
    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: b"",
            recipient_public_keys: &recipient_publics,
            kem: Some(SealedKem::Mlkem768X25519),
            cek: Some(&b(v, "cek_hex")),
            nonce: Some(&b(v, "nonce_hex")),
            eseeds: Some(&eseeds),
            skip_shuffle: true,
            ..Default::default()
        },
        &mut no_rng(),
    )
    .expect("wrap");

    let seed_hex = v["recipient_seeds_hex"][0].as_str().unwrap();
    let secret_seed = hex::decode(seed_hex).unwrap();

    let SealedSlots::Mlkem768X25519(slots) = &out.envelope.slots else {
        unreachable!()
    };
    let good = &slots[0];

    for bad_flat in [
        // Under-length: drop the last byte of the last chunk.
        {
            let mut flat = join_kem_ct(&good.kem_ct);
            flat.pop();
            flat
        },
        // Over-length: append a byte.
        {
            let mut flat = join_kem_ct(&good.kem_ct);
            flat.push(0u8);
            flat
        },
    ] {
        let tampered = SealedEnvelope {
            slots: SealedSlots::Mlkem768X25519(vec![Mlkem768X25519Slot {
                kem_ct: chunk_kem_ct(&bad_flat),
                wrap: good.wrap.clone(),
            }]),
            ..out.envelope.clone()
        };
        let err = ecies_sealed_poe_unwrap(
            &tampered,
            &out.ciphertext,
            UnwrapKeys::Single(&secret_seed),
            true,
            None,
        )
        .expect_err("kem_ct length mismatch");
        assert_eq!(err.code(), "KEM_CT_LENGTH_MISMATCH");
    }
}

// --------------------------------------------------------------------------
// Production-path roundtrip + shuffle property
// --------------------------------------------------------------------------

#[test]
fn production_roundtrip_every_recipient_with_shuffle() {
    let privs = [make_priv(0x11), make_priv(0x55), make_priv(0x99)];
    let pubs: Vec<Vec<u8>> = privs
        .iter()
        .map(|p| {
            cardanowall::sealed_poe::x25519_public_key(p)
                .unwrap()
                .to_vec()
        })
        .collect();
    let plaintext = b"shuffle production path roundtrip";
    let out = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext,
            recipient_public_keys: &pubs,
            ..Default::default()
        },
        &mut counter_rng(0x9999_1234),
    )
    .expect("wrap");
    for priv_key in &privs {
        let res = ecies_sealed_poe_unwrap(
            &out.envelope,
            &out.ciphertext,
            UnwrapKeys::Single(priv_key),
            true,
            None,
        )
        .expect("unwrap");
        assert_eq!(
            res,
            UnwrapResult::Matched {
                plaintext: plaintext.to_vec()
            }
        );
    }
}

#[test]
fn shuffle_permutes_recipient_positions_across_runs() {
    let privs = [make_priv(0x11), make_priv(0x55), make_priv(0x99)];
    let pubs: Vec<Vec<u8>> = privs
        .iter()
        .map(|p| {
            cardanowall::sealed_poe::x25519_public_key(p)
                .unwrap()
                .to_vec()
        })
        .collect();
    let mut rng = counter_rng(0xfeed_face_dead_beef);
    let mut orderings = std::collections::HashSet::new();
    for _ in 0..1000 {
        let out = ecies_sealed_poe_wrap_with_rng(
            WrapArgs {
                plaintext: b"shuffle-by-recipient-position",
                recipient_public_keys: &pubs,
                ..Default::default()
            },
            &mut rng,
        )
        .expect("wrap");
        let positions = recipient_positions(&out, &privs);
        orderings.insert(positions);
        if orderings.len() >= 4 {
            break;
        }
    }
    assert!(orderings.len() >= 2, "shuffle should permute slot order");
}

/// For each recipient priv, find the slot index it opens (test-only probe).
fn recipient_positions(out: &SealedPoeOutput, privs: &[Vec<u8>]) -> Vec<i32> {
    let SealedSlots::X25519(slots) = &out.envelope.slots else {
        unreachable!()
    };
    let mut positions = vec![-1i32; privs.len()];
    for (slot_idx, slot) in slots.iter().enumerate() {
        for (r, priv_key) in privs.iter().enumerate() {
            if positions[r] != -1 {
                continue;
            }
            // Trial-open this single slot via the single-priv unwrap over a
            // one-slot envelope built around it.
            let single_env = SealedEnvelope {
                slots: SealedSlots::X25519(vec![slot.clone()]),
                ..out.envelope.clone()
            };
            // slots_mac won't match the single-slot projection, but a CEK is
            // still recovered if the slot opens — detect via trial-decrypt.
            let res = ecies_sealed_poe_trial_decrypt(
                &single_env,
                TrialDecryptKeys::Multi(std::slice::from_ref(priv_key)),
                true,
                None,
            )
            .expect("trial");
            if !matches!(res, TrialDecryptResult::NoAeadPass) {
                positions[r] = slot_idx as i32;
                break;
            }
        }
    }
    positions
}

// --------------------------------------------------------------------------
// Cross-SDK shared KAT — kem_ct chunking-invariance of slots_mac
// --------------------------------------------------------------------------

/// Build a hybrid envelope from a fixture envelope that stores each slot's
/// `kem_ct` as a list of hex chunks (`kem_ct_chunks_hex`), preserving the exact
/// — possibly non-canonical — chunk boundaries on the wire. This is distinct
/// from `envelope_from_json`, which re-chunks a flat `kem_ct_hex`; here the
/// whole point is to NOT re-chunk, so the slots_mac canonicalization is what
/// makes the MAC verify.
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

#[test]
fn unwrap_hybrid_rechunked_shared_kat() {
    let corpus = fixture("unwrap-hybrid-rechunked.json");

    // matched_true: a record re-served with non-canonical kem_ct chunk
    // boundaries still authenticates (slots_mac canonicalizes to 64B first) and
    // recovers the plaintext.
    for v in corpus["matched_true_vectors"]
        .as_array()
        .expect("matched_true_vectors")
    {
        let name = s(v, "name");
        let envelope = hybrid_envelope_from_chunked_json(&v["envelope"]);
        let ciphertext = b(v, "ciphertext_hex");
        let seed = hex_list(v, "recipient_seeds_hex")
            .into_iter()
            .next()
            .expect("a recipient seed");
        let expected_plaintext = b(&v["expected"], "plaintext_hex");

        let result = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            UnwrapKeys::Single(&seed),
            true,
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: unwrap errored: {e}"));
        assert_eq!(
            result,
            UnwrapResult::Matched {
                plaintext: expected_plaintext
            },
            "{name}: rechunked record must authenticate and recover plaintext"
        );
    }

    // matched_false: the byte-flipped twin still fails slots_mac despite the
    // same chunking treatment.
    for v in corpus["matched_false_vectors"]
        .as_array()
        .expect("matched_false_vectors")
    {
        let name = s(v, "name");
        let envelope = hybrid_envelope_from_chunked_json(&v["envelope"]);
        let ciphertext = b(v, "ciphertext_hex");
        let seed = hex_list(v, "recipient_seeds_hex")
            .into_iter()
            .next()
            .expect("a recipient seed");
        let expected_reason = match s(&v["expected"], "reason") {
            "TAMPERED_HEADER" => UnwrapFailureReason::TamperedHeader,
            "TAMPERED_CIPHERTEXT" => UnwrapFailureReason::TamperedCiphertext,
            "WRONG_RECIPIENT_KEY" => UnwrapFailureReason::WrongRecipientKey,
            other => panic!("{name}: unknown reason {other}"),
        };

        let result = ecies_sealed_poe_unwrap(
            &envelope,
            &ciphertext,
            UnwrapKeys::Single(&seed),
            true,
            None,
        )
        .unwrap_or_else(|e| panic!("{name}: unwrap errored: {e}"));
        assert_eq!(
            result,
            UnwrapResult::NotMatched {
                reason: expected_reason
            },
            "{name}: tampered record must be rejected with the fixture reason"
        );
    }
}
