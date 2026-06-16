//! Cross-implementation parity tests for the RFC 9162 §2.1.1 SHA-256 Merkle
//! subsystem and the canonical-CBOR leaves-list codec.
//!
//! The known-answer vectors (roots, audit-path siblings, leaves-list CBOR
//! bytes) live in the shared conformance corpus and are loaded here, so a single
//! source of truth drives every SDK rather than each one carrying its own copy.
//! The leaves-list reject taxonomy has its own shared fixture
//! (`merkle/leaves-list-negative.json`) that every SDK decodes and asserts the
//! same error code against.

mod common;

use cardanowall::hash::sha256;
use cardanowall::hex;
use cardanowall::merkle::{
    decode_leaves_list, encode_leaves_list, merkle_inclusion_proof, merkle_root, verify_inclusion,
    MerkleError, MerkleLeavesListErrorCode, LEAVES_LIST_FORMAT_V1, MERKLE_ALG_ID,
};
use serde_json::Value;

/// The reference leaf input for index `i`: `SHA-256("merkle-leaf-{i}")`. Used by
/// the negative-path and forged-payload tests that need fresh leaf digests.
fn leaf_d(i: usize) -> [u8; 32] {
    sha256(format!("merkle-leaf-{i}").as_bytes())
}

/// The reference wide-tree leaf for index `i`: `SHA-256("wide-{i}")`.
fn wide_leaf(i: usize) -> [u8; 32] {
    sha256(format!("wide-{i}").as_bytes())
}

/// Lower-case hex of a 32-byte digest.
fn hx(b: [u8; 32]) -> String {
    hex::encode(&b)
}

fn proof_hex(proof: &[[u8; 32]]) -> Vec<String> {
    proof.iter().map(|s| hex::encode(s)).collect()
}

/// Decode a hex digest from a JSON string value into a 32-byte array.
fn digest32(value: &Value) -> [u8; 32] {
    let bytes = hex::decode(value.as_str().expect("digest hex string")).expect("digest hex");
    let mut out = [0u8; 32];
    assert_eq!(bytes.len(), 32, "digest must be 32 bytes");
    out.copy_from_slice(&bytes);
    out
}

/// Decode an array of hex digests from a JSON array value.
fn digest_list(value: &Value) -> Vec<[u8; 32]> {
    value
        .as_array()
        .expect("digest array")
        .iter()
        .map(digest32)
        .collect()
}

#[test]
fn algorithm_identifier_is_canonical() {
    assert_eq!(MERKLE_ALG_ID, "rfc9162-sha256");
}

// === Root known-answer vectors (sizes 1,2,3,4,5,7) ===
#[test]
fn root_kat_reproduces_every_pinned_root() {
    let corpus = common::read_fixture_json(
        &common::label309_conformance().join("merkle/rfc9162-sha256-root-kat.json"),
    );
    let vectors = corpus["vectors"].as_array().expect("root-kat vectors");
    assert!(!vectors.is_empty(), "the root KAT carries vectors");

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        let leaves = digest_list(&vector["leaves"]);
        let leaf_count = vector["leaf_count"].as_u64().expect("leaf_count") as usize;
        assert_eq!(
            leaf_count,
            leaves.len(),
            "{name}: leaf_count == leaves.len()"
        );

        let root = merkle_root(&leaves).unwrap();
        assert_eq!(
            hx(root),
            vector["root"].as_str().expect("root hex"),
            "{name}: root"
        );

        // A single-leaf root is SHA-256(0x00 || d_0), never the bare leaf digest
        // (CVE-2012-2459 prefix separation).
        if leaves.len() == 1 {
            assert_ne!(hx(root), hx(leaves[0]), "{name}: leaf-prefix separation");
        }

        // Every leaf's own inclusion proof recomputes to this root.
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = merkle_inclusion_proof(&leaves, i).unwrap();
            assert!(
                verify_inclusion(leaf, i, leaves.len(), &proof, &root),
                "{name}: leaf {i} did not verify"
            );
        }
    }
}

// === Inclusion-proof known-answer vectors (sibling paths per position) ===
#[test]
fn inclusion_proof_kat_reproduces_every_pinned_sibling_path() {
    let corpus = common::read_fixture_json(
        &common::label309_conformance().join("merkle/rfc9162-sha256-inclusion-proof-kat.json"),
    );
    let trees = corpus["trees"].as_array().expect("inclusion-proof trees");
    assert!(!trees.is_empty(), "the inclusion-proof KAT carries trees");

    for tree in trees {
        let name = tree["name"].as_str().expect("tree name");
        let leaves = digest_list(&tree["leaves"]);
        let tree_size = tree["tree_size"].as_u64().expect("tree_size") as usize;
        assert_eq!(tree_size, leaves.len(), "{name}: tree_size == leaves.len()");

        let root = merkle_root(&leaves).unwrap();
        assert_eq!(
            hx(root),
            tree["root"].as_str().expect("tree root"),
            "{name}: root"
        );

        for inclusion in tree["inclusions"].as_array().expect("inclusions") {
            let index = inclusion["index"].as_u64().expect("index") as usize;
            let expected_leaf = digest32(&inclusion["leaf"]);
            assert_eq!(leaves[index], expected_leaf, "{name}[{index}]: leaf");

            let expected_path: Vec<String> = inclusion["proof"]
                .as_array()
                .expect("proof array")
                .iter()
                .map(|v| v.as_str().expect("proof sibling hex").to_string())
                .collect();

            let proof = merkle_inclusion_proof(&leaves, index).unwrap();
            assert_eq!(
                proof_hex(&proof),
                expected_path,
                "{name}[{index}]: audit path"
            );
            assert!(
                verify_inclusion(&leaves[index], index, leaves.len(), &proof, &root),
                "{name}[{index}]: did not verify"
            );
        }
    }
}

// === 16-leaf round-trip (power-of-2 wide tree) ===
#[test]
fn sixteen_leaf_round_trip() {
    let leaves: Vec<[u8; 32]> = (0..16).map(wide_leaf).collect();
    let root = merkle_root(&leaves).unwrap();
    for i in 0..16 {
        let proof = merkle_inclusion_proof(&leaves, i).unwrap();
        assert_eq!(proof.len(), 4, "16-leaf audit path is log2(16) == 4");
        assert!(verify_inclusion(&leaves[i], i, leaves.len(), &proof, &root));
    }
}

// === Input validation: root + inclusion proof ===
#[test]
fn root_rejects_empty_leaf_list() {
    assert_eq!(merkle_root(&[]).unwrap_err(), MerkleError::EmptyTree);
}

#[test]
fn inclusion_proof_rejects_empty_leaf_list() {
    assert_eq!(
        merkle_inclusion_proof(&[], 0).unwrap_err(),
        MerkleError::EmptyTree
    );
}

#[test]
fn inclusion_proof_rejects_index_out_of_range() {
    let leaves = [leaf_d(0), leaf_d(1)];
    assert_eq!(
        merkle_inclusion_proof(&leaves, 2).unwrap_err(),
        MerkleError::IndexOutOfRange {
            index: 2,
            tree_size: 2,
        }
    );
}

// === Negative verifier cases ===
#[test]
fn verify_rejects_wrong_leaf() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let root = merkle_root(&leaves).unwrap();
    let proof = merkle_inclusion_proof(&leaves, 1).unwrap();
    let wrong_leaf = sha256(b"not-in-tree");
    assert!(!verify_inclusion(&wrong_leaf, 1, 4, &proof, &root));
}

#[test]
fn verify_rejects_tampered_proof() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let root = merkle_root(&leaves).unwrap();
    let mut proof = merkle_inclusion_proof(&leaves, 1).unwrap();
    proof[0][0] ^= 0xff;
    assert!(!verify_inclusion(&leaves[1], 1, 4, &proof, &root));
}

#[test]
fn verify_rejects_tampered_root() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let root = merkle_root(&leaves).unwrap();
    let proof = merkle_inclusion_proof(&leaves, 1).unwrap();
    let mut tampered = root;
    tampered[0] ^= 0xff;
    assert!(!verify_inclusion(&leaves[1], 1, 4, &proof, &tampered));
}

#[test]
fn verify_rejects_swapped_index() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let root = merkle_root(&leaves).unwrap();
    // Proof built for index 1; reusing it at index 2 must fail.
    let proof = merkle_inclusion_proof(&leaves, 1).unwrap();
    assert!(!verify_inclusion(&leaves[2], 2, 4, &proof, &root));
}

#[test]
fn verify_rejects_index_out_of_range_for_tree_size() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let root = merkle_root(&leaves).unwrap();
    let proof = merkle_inclusion_proof(&leaves, 1).unwrap();
    assert!(!verify_inclusion(&leaves[1], 4, 4, &proof, &root));
}

#[test]
fn verify_rejects_wrong_length_leaf_root_or_sibling() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let root = merkle_root(&leaves).unwrap();
    let proof = merkle_inclusion_proof(&leaves, 1).unwrap();

    // 31-byte leaf.
    assert!(!verify_inclusion(&[0u8; 31], 1, 4, &proof, &root));
    // 31-byte root.
    assert!(!verify_inclusion(&leaves[1], 1, 4, &proof, &[0u8; 31]));
    // A sibling with the wrong contents (the equivalent of a malformed
    // sibling) still fails the fold; length is type-guaranteed for `[u8; 32]`
    // siblings, so a corrupt sibling is the observable analogue here.
    let mut bad_proof = proof.clone();
    bad_proof[0] = [0u8; 32];
    assert!(!verify_inclusion(&leaves[1], 1, 4, &bad_proof, &root));
}

#[test]
fn verify_rejects_nonempty_single_leaf_proof() {
    let leaf = leaf_d(0);
    let root = merkle_root(&[leaf]).unwrap();
    assert!(!verify_inclusion(&leaf, 0, 1, &[[0u8; 32]], &root));
}

#[test]
fn verify_rejects_proof_shorter_than_depth() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let root = merkle_root(&leaves).unwrap();
    let proof = merkle_inclusion_proof(&leaves, 1).unwrap();
    assert!(!verify_inclusion(&leaves[1], 1, 4, &proof[..1], &root));
}

#[test]
fn verify_rejects_proof_longer_than_depth() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let root = merkle_root(&leaves).unwrap();
    let proof = merkle_inclusion_proof(&leaves, 1).unwrap();
    let mut too_long = proof.clone();
    too_long.push([0u8; 32]);
    assert!(!verify_inclusion(&leaves[1], 1, 4, &too_long, &root));
}

// ---------------------------------------------------------------------------
// Leaves-list codec
// ---------------------------------------------------------------------------

#[test]
fn leaves_list_format_constant() {
    assert_eq!(LEAVES_LIST_FORMAT_V1, "cardano-poe-merkle-leaves-v1");
}

// === Leaves-list canonical-CBOR known-answer vectors ===
//
// Each vector pins the canonical encoding both with and without the optional
// `leaf_alg` key; the encoder must reproduce both byte-for-byte, and the decoder
// must round-trip each back to the same fields.
#[test]
fn leaves_list_kat_encodes_and_decodes_pinned_bytes() {
    let corpus = common::read_fixture_json(
        &common::label309_conformance().join("merkle/leaves-list-kat.json"),
    );
    let vectors = corpus["vectors"].as_array().expect("leaves-list vectors");
    assert!(!vectors.is_empty(), "the leaves-list KAT carries vectors");

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        let leaves = digest_list(&vector["leaves"]);
        let leaf_count = vector["leaf_count"].as_u64().expect("leaf_count") as usize;
        assert_eq!(
            leaf_count,
            leaves.len(),
            "{name}: leaf_count == leaves.len()"
        );
        let leaf_alg = vector["leaf_alg"].as_str().expect("leaf_alg");

        let root = merkle_root(&leaves).unwrap();
        assert_eq!(
            hx(root),
            vector["root"].as_str().expect("root hex"),
            "{name}: root"
        );

        // Encode matches the pinned bytes, both without and with the optional
        // leaf_alg key.
        let no_alg = encode_leaves_list(&leaves, &root, None).unwrap();
        assert_eq!(
            hex::encode(&no_alg),
            vector["cbor_hex_no_leaf_alg"]
                .as_str()
                .expect("cbor_hex_no_leaf_alg"),
            "{name}: encode without leaf_alg"
        );
        let with_alg = encode_leaves_list(&leaves, &root, Some(leaf_alg)).unwrap();
        assert_eq!(
            hex::encode(&with_alg),
            vector["cbor_hex_with_leaf_alg"]
                .as_str()
                .expect("cbor_hex_with_leaf_alg"),
            "{name}: encode with leaf_alg"
        );

        // Decode of the pinned bytes recomputes the root and recovers the fields.
        let decoded_no_alg = decode_leaves_list(&no_alg).unwrap();
        assert_eq!(decoded_no_alg.format, LEAVES_LIST_FORMAT_V1);
        assert_eq!(decoded_no_alg.tree_alg, "rfc9162-sha256");
        assert_eq!(decoded_no_alg.root, root, "{name}: decoded root (no alg)");
        assert_eq!(decoded_no_alg.leaf_count, leaf_count);
        assert_eq!(decoded_no_alg.leaf_alg, None);
        assert_eq!(
            decoded_no_alg.leaves, leaves,
            "{name}: decoded leaves (no alg)"
        );

        let decoded_with_alg = decode_leaves_list(&with_alg).unwrap();
        assert_eq!(
            decoded_with_alg.root, root,
            "{name}: decoded root (with alg)"
        );
        assert_eq!(decoded_with_alg.leaf_count, leaf_count);
        assert_eq!(decoded_with_alg.leaf_alg.as_deref(), Some(leaf_alg));
        assert_eq!(
            decoded_with_alg.leaves, leaves,
            "{name}: decoded leaves (with alg)"
        );

        // encode(decode(cbor)) == cbor: re-encoding the decoded form is stable.
        let reencoded = encode_leaves_list(
            &decoded_with_alg.leaves,
            &decoded_with_alg.root,
            decoded_with_alg.leaf_alg.as_deref(),
        )
        .unwrap();
        assert_eq!(
            reencoded, with_alg,
            "{name}: encode(decode(cbor)) round-trip"
        );
    }
}

#[test]
fn encode_decode_round_trip_without_leaf_alg() {
    let leaves = [leaf_d(0)];
    let root = merkle_root(&leaves).unwrap();
    let bytes = encode_leaves_list(&leaves, &root, None).unwrap();
    let decoded = decode_leaves_list(&bytes).unwrap();
    assert_eq!(decoded.leaf_alg, None);
    assert_eq!(decoded.leaf_count, 1);
    assert_eq!(decoded.root, root);
}

#[test]
fn encode_decode_round_trip_with_leaf_alg() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let root = merkle_root(&leaves).unwrap();
    let bytes = encode_leaves_list(&leaves, &root, Some("sha2-256")).unwrap();
    let decoded = decode_leaves_list(&bytes).unwrap();
    assert_eq!(decoded.format, LEAVES_LIST_FORMAT_V1);
    assert_eq!(decoded.tree_alg, "rfc9162-sha256");
    assert_eq!(decoded.leaf_count, 4);
    assert_eq!(decoded.leaf_alg.as_deref(), Some("sha2-256"));
    assert_eq!(decoded.root, root);
    assert_eq!(decoded.leaves.len(), 4);
    for (i, leaf) in leaves.iter().enumerate() {
        assert_eq!(decoded.leaves[i], *leaf);
    }
}

#[test]
fn encode_decode_round_trip_sixteen_leaves() {
    let leaves: Vec<[u8; 32]> = (0..16).map(wide_leaf).collect();
    let root = merkle_root(&leaves).unwrap();
    let bytes = encode_leaves_list(&leaves, &root, None).unwrap();
    let decoded = decode_leaves_list(&bytes).unwrap();
    assert_eq!(decoded.leaf_count, 16);
    assert_eq!(decoded.root, root);
}

// === encode validation ===
#[test]
fn encode_rejects_empty_leaves() {
    let root = [0u8; 32];
    let err = encode_leaves_list(&[], &root, None).unwrap_err();
    assert_eq!(err.code(), MerkleLeavesListErrorCode::Malformed);
    assert_eq!(err.code_str(), "SCHEMA_MERKLE_LEAVES_MALFORMED");
}

// === decode schema rejection ===
//
// To forge malformed payloads we encode arbitrary canonical-CBOR maps via the
// SDK's own encoder, then assert the decoder's typed rejection code.
use cardanowall::cbor::{encode_canonical_cbor, CborValue};

fn encode_map(pairs: Vec<(CborValue, CborValue)>) -> Vec<u8> {
    encode_canonical_cbor(&CborValue::Map(pairs)).unwrap()
}

fn leaf_bytes(i: usize) -> CborValue {
    CborValue::bytes(leaf_d(i).to_vec())
}

#[test]
fn decode_rejects_unknown_format() {
    let leaves = [leaf_d(0)];
    let root = merkle_root(&leaves).unwrap();
    let bytes = encode_map(vec![
        (
            CborValue::text("format"),
            CborValue::text("cardano-poe-merkle-leaves-v0"),
        ),
        (CborValue::text("tree_alg"), CborValue::text(MERKLE_ALG_ID)),
        (CborValue::text("root"), CborValue::bytes(root.to_vec())),
        (
            CborValue::text("leaves"),
            CborValue::Array(vec![leaf_bytes(0)]),
        ),
        (CborValue::text("leaf_count"), CborValue::Unsigned(1)),
    ]);
    let err = decode_leaves_list(&bytes).unwrap_err();
    assert_eq!(err.code(), MerkleLeavesListErrorCode::FormatUnsupported);
    assert_eq!(err.code_str(), "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED");
}

#[test]
fn decode_rejects_leaf_count_mismatch() {
    let leaves = [leaf_d(0), leaf_d(1)];
    let root = merkle_root(&leaves).unwrap();
    let bytes = encode_map(vec![
        (
            CborValue::text("format"),
            CborValue::text(LEAVES_LIST_FORMAT_V1),
        ),
        (CborValue::text("tree_alg"), CborValue::text(MERKLE_ALG_ID)),
        (CborValue::text("root"), CborValue::bytes(root.to_vec())),
        (
            CborValue::text("leaves"),
            CborValue::Array(vec![leaf_bytes(0), leaf_bytes(1)]),
        ),
        (CborValue::text("leaf_count"), CborValue::Unsigned(3)), // mismatch
    ]);
    let err = decode_leaves_list(&bytes).unwrap_err();
    assert_eq!(err.code(), MerkleLeavesListErrorCode::LeafCountMismatch);
    assert_eq!(err.code_str(), "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH");
}

#[test]
fn decode_rejects_root_mismatch() {
    let bytes = encode_map(vec![
        (
            CborValue::text("format"),
            CborValue::text(LEAVES_LIST_FORMAT_V1),
        ),
        (CborValue::text("tree_alg"), CborValue::text(MERKLE_ALG_ID)),
        (
            CborValue::text("root"),
            CborValue::bytes(vec![0xab; 32]), // not the real root
        ),
        (
            CborValue::text("leaves"),
            CborValue::Array(vec![leaf_bytes(0), leaf_bytes(1)]),
        ),
        (CborValue::text("leaf_count"), CborValue::Unsigned(2)),
    ]);
    let err = decode_leaves_list(&bytes).unwrap_err();
    assert_eq!(err.code(), MerkleLeavesListErrorCode::RootMismatch);
    assert_eq!(err.code_str(), "MERKLE_ROOT_MISMATCH");
}

#[test]
fn decode_rejects_non_map_top_level() {
    let bytes =
        encode_canonical_cbor(&CborValue::Array(vec![CborValue::text("not-a-map")])).unwrap();
    let err = decode_leaves_list(&bytes).unwrap_err();
    assert_eq!(err.code(), MerkleLeavesListErrorCode::Malformed);
    assert_eq!(err.code_str(), "SCHEMA_MERKLE_LEAVES_MALFORMED");
}

#[test]
fn decode_rejects_empty_leaves_array() {
    let bytes = encode_map(vec![
        (
            CborValue::text("format"),
            CborValue::text(LEAVES_LIST_FORMAT_V1),
        ),
        (CborValue::text("tree_alg"), CborValue::text(MERKLE_ALG_ID)),
        (CborValue::text("root"), CborValue::bytes(vec![0u8; 32])),
        (CborValue::text("leaves"), CborValue::Array(vec![])),
        (CborValue::text("leaf_count"), CborValue::Unsigned(0)),
    ]);
    let err = decode_leaves_list(&bytes).unwrap_err();
    assert_eq!(err.code(), MerkleLeavesListErrorCode::Malformed);
}

#[test]
fn decode_rejects_wrong_length_root() {
    let bytes = encode_map(vec![
        (
            CborValue::text("format"),
            CborValue::text(LEAVES_LIST_FORMAT_V1),
        ),
        (CborValue::text("tree_alg"), CborValue::text(MERKLE_ALG_ID)),
        (CborValue::text("root"), CborValue::bytes(vec![0u8; 31])),
        (
            CborValue::text("leaves"),
            CborValue::Array(vec![leaf_bytes(0)]),
        ),
        (CborValue::text("leaf_count"), CborValue::Unsigned(1)),
    ]);
    let err = decode_leaves_list(&bytes).unwrap_err();
    assert_eq!(err.code(), MerkleLeavesListErrorCode::Malformed);
}

#[test]
fn decode_rejects_wrong_length_leaf() {
    let bytes = encode_map(vec![
        (
            CborValue::text("format"),
            CborValue::text(LEAVES_LIST_FORMAT_V1),
        ),
        (CborValue::text("tree_alg"), CborValue::text(MERKLE_ALG_ID)),
        (CborValue::text("root"), CborValue::bytes(vec![0u8; 32])),
        (
            CborValue::text("leaves"),
            CborValue::Array(vec![CborValue::bytes(vec![0u8; 31])]),
        ),
        (CborValue::text("leaf_count"), CborValue::Unsigned(1)),
    ]);
    let err = decode_leaves_list(&bytes).unwrap_err();
    assert_eq!(err.code(), MerkleLeavesListErrorCode::Malformed);
}

#[test]
fn leaves_list_negative_shared_kat() {
    // Every vector pins the single error code the leaves-list decoder must
    // emit. The fixture is shared byte-identically across the SDKs.
    let corpus = common::read_fixture_json(
        &common::crypto_core_fixtures().join("merkle/leaves-list-negative.json"),
    );
    for v in corpus["vectors"].as_array().expect("vectors array") {
        let name = v["name"].as_str().expect("vector name");
        let bytes = hex::decode(v["cbor_hex"].as_str().expect("cbor_hex")).expect("valid hex");
        let expected = v["expected_error_code"]
            .as_str()
            .expect("expected_error_code");

        let err = decode_leaves_list(&bytes)
            .err()
            .unwrap_or_else(|| panic!("{name}: expected reject, got Ok"));
        assert_eq!(
            err.code_str(),
            expected,
            "{name}: emitted {} != expected {expected}",
            err.code_str()
        );
    }
}
