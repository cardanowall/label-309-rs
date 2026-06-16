//! Cross-implementation byte-parity anchor for the Label 309 inclusion
//! certificate.
//!
//! This loads the shared known-answer vector and reproduces, from the same
//! inputs, the three byte-pinned interoperability surfaces every conforming
//! implementation MUST match: the RFC 9162 tree root, the COSE / RFC 9162
//! aligned inclusion-certificate-proof CBOR map, and the bare IETF
//! inclusion-proof CBOR (`[tree_size, leaf_index, inclusion_path]`). The
//! TypeScript and Python certificate twins reproduce these exact bytes.

mod common;

use cardanowall::certificate::{
    build_inclusion_certificate, encode_cose_inclusion_proof, encode_ietf_inclusion_proof,
    CertificateAnchor, CertificateMerkle, CertificateTarget,
};
use cardanowall::hex;
use cardanowall::merkle::merkle_root;

/// Decode a 32-byte digest from hex, panicking on a malformed or wrong-length
/// value so a corrupt vector surfaces immediately.
fn digest32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("digest hex decodes");
    let mut out = [0u8; 32];
    assert_eq!(bytes.len(), 32, "digest must be 32 bytes");
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn inclusion_certificate_kat_reproduces_root_cose_and_ietf_bytes() {
    let corpus = common::read_fixture_json(
        &common::label309_conformance().join("certificate/inclusion-certificate-kat.json"),
    );
    let vectors = corpus["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "the certificate KAT carries vectors");

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        let input = &vector["input"];
        let expected = &vector["expected"];

        // The leaves are the on-chain content hashes, in tree order.
        let leaves: Vec<[u8; 32]> = input["leaves"]
            .as_array()
            .expect("input.leaves array")
            .iter()
            .map(|v| digest32(v.as_str().expect("leaf hex")))
            .collect();
        let tree_size = input["tree_size"].as_u64().expect("tree_size") as usize;
        assert_eq!(tree_size, leaves.len(), "{name}: tree_size == leaves.len()");

        // The on-chain anchor facts.
        let anchor_in = &input["anchor"];
        let anchor = CertificateAnchor {
            chain: anchor_in["chain"]
                .as_str()
                .expect("anchor.chain")
                .to_string(),
            network: anchor_in["network"]
                .as_str()
                .expect("anchor.network")
                .to_string(),
            tx_hash: anchor_in["tx_hash"]
                .as_str()
                .expect("anchor.tx_hash")
                .to_string(),
            metadata_label: anchor_in["metadata_label"]
                .as_u64()
                .expect("anchor.metadata_label"),
            block_time: anchor_in["block_time"].as_i64().expect("anchor.block_time"),
            block_height: None,
            slot: None,
            confirmations_at_generation: None,
            explorer_urls: None,
        };

        // The certified target: the leaf at the pinned index, carrying its
        // advisory leaf algorithm.
        let target_in = &vector["input"]["target"];
        let target_index = target_in["index"].as_u64().expect("target.index") as usize;
        let leaf_alg = target_in["leaf_alg"].as_str().map(str::to_string);

        let merkle = CertificateMerkle {
            tree_alg: "rfc9162-sha256".to_string(),
            root: merkle_root(&leaves).expect("merkle root"),
            tree_size: leaves.len(),
            leaves_list_uri: None,
            leaves_list_url: None,
        };

        // The root the leaves produce must equal the pinned root.
        assert_eq!(
            hex::encode(&merkle.root),
            expected["root"].as_str().expect("expected.root"),
            "{name}: merkle root"
        );

        let target = CertificateTarget {
            leaf: leaves[target_index],
            leaf_alg,
            label: None,
        };

        let cert = build_inclusion_certificate(
            &anchor,
            &merkle,
            &leaves,
            &[target],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .expect("certificate builds");
        let item = &cert.items[0];
        assert!(item.verified, "{name}: the target item verifies");
        assert_eq!(item.index as usize, target_index, "{name}: item index");
        assert_eq!(
            item.leaf,
            expected["leaf"].as_str().expect("expected.leaf"),
            "{name}: committed leaf hex"
        );

        // The item's sibling path matches the pinned inclusion path.
        let expected_path: Vec<&str> = expected["inclusion_path"]
            .as_array()
            .expect("expected.inclusion_path")
            .iter()
            .map(|v| v.as_str().expect("path sibling hex"))
            .collect();
        assert_eq!(item.proof, expected_path, "{name}: inclusion path");

        // The full COSE / RFC 9162 inclusion-certificate-proof CBOR map.
        let cose = encode_cose_inclusion_proof(item, &merkle, &anchor).expect("COSE encodes");
        assert_eq!(
            hex::encode(&cose),
            expected["cose_inclusion_proof_cbor_hex"]
                .as_str()
                .expect("expected.cose_inclusion_proof_cbor_hex"),
            "{name}: COSE inclusion-proof CBOR bytes"
        );

        // The bare IETF inclusion proof is the `bstr .cbor` byte string the
        // encoder returns (a CBOR byte string wrapping the
        // `[tree_size, leaf_index, inclusion_path]` array). The shared vector
        // pins that byte string directly.
        let ietf_bstr = encode_ietf_inclusion_proof(item, &merkle).expect("IETF proof encodes");
        assert_eq!(
            hex::encode(&ietf_bstr),
            expected["ietf_inclusion_proof_cbor_hex"]
                .as_str()
                .expect("expected.ietf_inclusion_proof_cbor_hex"),
            "{name}: bare IETF inclusion-proof bstr .cbor bytes"
        );
    }
}
