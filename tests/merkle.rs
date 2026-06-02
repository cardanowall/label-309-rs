//! Cross-implementation parity tests for the RFC 9162 §2.1.1 SHA-256 Merkle
//! subsystem and the canonical-CBOR leaves-list codec.
//!
//! Most known-answer vectors (roots, audit-path siblings, leaves-list CBOR
//! bytes) are inlined in the TypeScript and Python reference suites and ported
//! here byte-for-byte. The leaves-list reject taxonomy additionally has a shared
//! JSON fixture (`merkle/leaves-list-negative.json`) that every SDK decodes and
//! asserts the same error code against.

mod common;

use cardanowall::hash::sha256;
use cardanowall::hex;
use cardanowall::merkle::{
    decode_leaves_list, encode_leaves_list, merkle_inclusion_proof, merkle_root, verify_inclusion,
    MerkleError, MerkleLeavesListErrorCode, LEAVES_LIST_FORMAT_V1, MERKLE_ALG_ID,
};

/// The reference leaf input for index `i`: `SHA-256("merkle-leaf-{i}")`.
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

// Pinned d_i leaf inputs (i = 0..6) from the reference KAT.
const PINNED_DI: [&str; 7] = [
    "b5e62a21038c1c2fdf28ad4d39ba6502e0568591c8647cac6998bfff67a25b3c",
    "986aad6d251d450b9e7cd0c811e65bc95f95688060d963a83ab6505da350be56",
    "27f4c2b7157b2e28b1a08e47fce1c3fa27a0f2c8a6760f5995c8a83c9cd1cacc",
    "49707d9c71d5ebf72aaa3ada7a34e152d41811b345366681fc09849e8c634076",
    "e1599f1d13ee839f0fe64c2d5697b9d098ea947053f2fd8033e93b5ea1da8970",
    "7777a46ef6264ec24caf8239bea80bd6b3b1e38e9d3dc4f9daf6ce3722e8ba02",
    "741c8f1001d6e807fac74c182d15f01fba2ed98375ca7a7cdc6257fdae97b621",
];

#[test]
fn algorithm_identifier_is_canonical() {
    assert_eq!(MERKLE_ALG_ID, "rfc9162-sha256");
}

#[test]
fn leaf_inputs_match_pinned_d_i() {
    for (i, &pinned) in PINNED_DI.iter().enumerate() {
        assert_eq!(hx(leaf_d(i)), pinned, "d_{i} mismatch");
    }
}

// === 1-leaf tree ===
#[test]
fn one_leaf_tree() {
    let leaves = [leaf_d(0)];
    let expected_root = "b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc";
    let root = merkle_root(&leaves).unwrap();
    assert_eq!(hx(root), expected_root);

    let proof = merkle_inclusion_proof(&leaves, 0).unwrap();
    assert_eq!(proof.len(), 0);
    assert!(verify_inclusion(&leaves[0], 0, 1, &proof, &root));

    // A single-leaf root is SHA-256(0x00 || d_0), never the bare leaf digest
    // (CVE-2012-2459 prefix separation).
    assert_ne!(hx(root), hx(leaf_d(0)));
}

// === 2-leaf tree ===
#[test]
fn two_leaf_tree() {
    let leaves = [leaf_d(0), leaf_d(1)];
    let expected_root = "f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee";
    let expected_proofs: [Vec<&str>; 2] = [
        vec!["7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5"],
        vec!["b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc"],
    ];
    let root = merkle_root(&leaves).unwrap();
    assert_eq!(hx(root), expected_root);

    for i in 0..2 {
        let proof = merkle_inclusion_proof(&leaves, i).unwrap();
        assert_eq!(proof_hex(&proof), expected_proofs[i]);
        assert!(verify_inclusion(&leaves[i], i, leaves.len(), &proof, &root));
    }
}

// === 3-leaf tree (split 3 -> 2+1) ===
#[test]
fn three_leaf_tree() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2)];
    let expected_root = "2c5230105235655a072f552fddcbc78bf5a76e16476c882e8199f9fce20a8f55";
    let l0 = "b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc";
    let l1 = "7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5";
    let l2 = "807ffa56924d0647034b00f8ce5517917ab065335048a1ea53f920c2274a2890";
    let h01 = "f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee";
    let expected_proofs: [Vec<&str>; 3] = [vec![l1, l2], vec![l0, l2], vec![h01]];
    let root = merkle_root(&leaves).unwrap();
    assert_eq!(hx(root), expected_root);

    for i in 0..3 {
        let proof = merkle_inclusion_proof(&leaves, i).unwrap();
        assert_eq!(proof_hex(&proof), expected_proofs[i]);
        assert!(verify_inclusion(&leaves[i], i, leaves.len(), &proof, &root));
    }
}

// === 4-leaf tree (baseline, split 4 -> 2+2) ===
#[test]
fn four_leaf_tree() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let expected_root = "93a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee";
    let l0 = "b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc";
    let l1 = "7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5";
    let l2 = "807ffa56924d0647034b00f8ce5517917ab065335048a1ea53f920c2274a2890";
    let l3 = "2c03e3ac9e4cf8ec8b505361e892e257ca59d91fa6a3b4741de9cd5962b62737";
    let h01 = "f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee";
    let h23 = "1e4e22ce45fea38703a4c93994677fdb3b2602650c835bb7448c81a68a561363";
    let expected_proofs: [Vec<&str>; 4] =
        [vec![l1, h23], vec![l0, h23], vec![l3, h01], vec![l2, h01]];
    let root = merkle_root(&leaves).unwrap();
    assert_eq!(hx(root), expected_root);

    for i in 0..4 {
        let proof = merkle_inclusion_proof(&leaves, i).unwrap();
        assert_eq!(proof_hex(&proof), expected_proofs[i]);
        assert!(verify_inclusion(&leaves[i], i, leaves.len(), &proof, &root));
    }
}

// === 5-leaf tree (split 5 -> 4+1, odd recursion edge) ===
#[test]
fn five_leaf_tree() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3), leaf_d(4)];
    let expected_root = "03928445a6003ca5f6a925cddb04a508116b06cf80037dca9e579ed41122fb9f";
    let l0 = "b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc";
    let l1 = "7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5";
    let l2 = "807ffa56924d0647034b00f8ce5517917ab065335048a1ea53f920c2274a2890";
    let l3 = "2c03e3ac9e4cf8ec8b505361e892e257ca59d91fa6a3b4741de9cd5962b62737";
    let l4 = "57fe46aac0fcd5d1392884b3523724bd145dcf9f70aa176318808ea56a9f8009";
    let h01 = "f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee";
    let h23 = "1e4e22ce45fea38703a4c93994677fdb3b2602650c835bb7448c81a68a561363";
    let h0123 = "93a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee";
    let expected_proofs: [Vec<&str>; 5] = [
        vec![l1, h23, l4],
        vec![l0, h23, l4],
        vec![l3, h01, l4],
        vec![l2, h01, l4],
        vec![h0123],
    ];
    let root = merkle_root(&leaves).unwrap();
    assert_eq!(hx(root), expected_root);

    for i in 0..5 {
        let proof = merkle_inclusion_proof(&leaves, i).unwrap();
        assert_eq!(proof_hex(&proof), expected_proofs[i]);
        assert!(verify_inclusion(&leaves[i], i, leaves.len(), &proof, &root));
    }
}

// === 7-leaf tree (split 7 -> 4+3; right subtree splits 3 -> 2+1) ===
#[test]
fn seven_leaf_tree() {
    let leaves = [
        leaf_d(0),
        leaf_d(1),
        leaf_d(2),
        leaf_d(3),
        leaf_d(4),
        leaf_d(5),
        leaf_d(6),
    ];
    let expected_root = "90306bf5dca8f89e7b253471148f3795e7a6c857f04924c8309d81375e79d987";
    let l0 = "b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc";
    let l1 = "7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5";
    let l2 = "807ffa56924d0647034b00f8ce5517917ab065335048a1ea53f920c2274a2890";
    let l3 = "2c03e3ac9e4cf8ec8b505361e892e257ca59d91fa6a3b4741de9cd5962b62737";
    let l4 = "57fe46aac0fcd5d1392884b3523724bd145dcf9f70aa176318808ea56a9f8009";
    let l5 = "f03cea80d0e99780698a755e4684555e821c2af821f97058926caf8e2d7d2969";
    let l6 = "5bd8bd33c7e3c41a98511068b7dfea418b5a6c84ff53767a1c7c0565efb651f4";
    let h01 = "f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee";
    let h23 = "1e4e22ce45fea38703a4c93994677fdb3b2602650c835bb7448c81a68a561363";
    let h45 = "02c09225565b2fb10fd263edc6951200c743b9121192f68ba7967ffc8a6f1128";
    let h0123 = "93a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee";
    // The right-subtree (leaves 4,5,6) root that hangs off the top-level node.
    let h456 = "32f86b4111e8859b214cf501d1091023da954f169d8916dce42aa469c5795d17";
    let expected_proofs: [Vec<&str>; 7] = [
        vec![l1, h23, h456],
        vec![l0, h23, h456],
        vec![l3, h01, h456],
        vec![l2, h01, h456],
        vec![l5, l6, h0123],
        vec![l4, l6, h0123],
        vec![h45, h0123],
    ];
    let root = merkle_root(&leaves).unwrap();
    assert_eq!(hx(root), expected_root);

    for i in 0..7 {
        let proof = merkle_inclusion_proof(&leaves, i).unwrap();
        assert_eq!(proof_hex(&proof), expected_proofs[i], "proof[{i}]");
        assert!(verify_inclusion(&leaves[i], i, leaves.len(), &proof, &root));
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

// Pinned 275-byte canonical-CBOR leaves-list for the 4-leaf fixture.
const PINNED_CBOR_HEX: &str = concat!(
    "a664726f6f74582093a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee",
    "66666f726d6174781c63617264616e6f2d706f652d6d65726b6c652d6c65617665732d7631666c65",
    "61766573845820b5e62a21038c1c2fdf28ad4d39ba6502e0568591c8647cac6998bfff67a25b3c58",
    "20986aad6d251d450b9e7cd0c811e65bc95f95688060d963a83ab6505da350be56582027f4c2b715",
    "7b2e28b1a08e47fce1c3fa27a0f2c8a6760f5995c8a83c9cd1cacc582049707d9c71d5ebf72aaa3a",
    "da7a34e152d41811b345366681fc09849e8c634076686c6561665f616c6768736861322d32353668",
    "747265655f616c676e726663393136322d7368613235366a6c6561665f636f756e7404",
);

const PINNED_ROOT_HEX: &str = "93a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee";

#[test]
fn leaves_list_format_constant() {
    assert_eq!(LEAVES_LIST_FORMAT_V1, "cardano-poe-merkle-leaves-v1");
}

#[test]
fn encode_leaves_list_matches_pinned_bytes() {
    let leaves = [leaf_d(0), leaf_d(1), leaf_d(2), leaf_d(3)];
    let root = merkle_root(&leaves).unwrap();
    assert_eq!(hx(root), PINNED_ROOT_HEX);

    let bytes = encode_leaves_list(&leaves, &root, Some("sha2-256")).unwrap();
    assert_eq!(bytes.len(), 275);
    assert_eq!(hex::encode(&bytes), PINNED_CBOR_HEX);
}

#[test]
fn decode_leaves_list_parses_pinned_bytes() {
    let decoded = decode_leaves_list(&hex::decode(PINNED_CBOR_HEX).unwrap()).unwrap();
    assert_eq!(decoded.format, LEAVES_LIST_FORMAT_V1);
    assert_eq!(decoded.tree_alg, "rfc9162-sha256");
    assert_eq!(hx(decoded.root), PINNED_ROOT_HEX);
    assert_eq!(decoded.leaf_count, 4);
    assert_eq!(decoded.leaf_alg.as_deref(), Some("sha2-256"));
    assert_eq!(decoded.leaves.len(), 4);
    let expected_leaves = [
        "b5e62a21038c1c2fdf28ad4d39ba6502e0568591c8647cac6998bfff67a25b3c",
        "986aad6d251d450b9e7cd0c811e65bc95f95688060d963a83ab6505da350be56",
        "27f4c2b7157b2e28b1a08e47fce1c3fa27a0f2c8a6760f5995c8a83c9cd1cacc",
        "49707d9c71d5ebf72aaa3ada7a34e152d41811b345366681fc09849e8c634076",
    ];
    for (i, &expected) in expected_leaves.iter().enumerate() {
        assert_eq!(hx(decoded.leaves[i]), expected);
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
