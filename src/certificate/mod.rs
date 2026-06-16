//! Label 309 Inclusion Certificate — a self-contained, standalone-verifiable
//! proof of inclusion.
//!
//! An inclusion certificate proves that one or more content hashes were
//! committed as leaves of an RFC 9162 (Certificate Transparency) SHA-256 Merkle
//! tree whose root was published on Cardano under metadata label 309. Each item
//! embeds its full sibling path, so the artifact re-verifies forever from the
//! file alone — no network, no storage gateway, no trust in any issuer. The
//! timestamp authority is the Cardano transaction's block time, asserted by the
//! public blockchain (via explorers), not by any key the issuer holds.
//!
//! Everything here is pure and I/O-free: callers fetch any external bytes (e.g.
//! the off-chain leaves-list) with the platform's own transport and pass the
//! decoded leaves in; the crypto path performs no network access.
//!
//! Surface:
//!
//! - [`build_inclusion_certificate`] — compute + self-verify per-target proofs
//!   and emit the JSON certificate object.
//! - [`verify_inclusion_certificate`] — pure re-verification of a certificate
//!   from its own bytes; reports per-item verdicts and echoes the anchor to
//!   confirm on-chain separately.
//! - [`encode_cose_inclusion_proof`] / [`encode_ietf_inclusion_proof`] — the
//!   per-item COSE / RFC 9162 aligned CBOR proof, and the bare IETF
//!   inclusion-proof byte string on its own.
//! - the format / claim / verification string constants, emitted verbatim.
//!
//! Every byte these functions emit is reproduced by the TypeScript
//! (`@cardanowall/sdk-ts`) and Python (`cardanowall-sdk`) certificate twins and
//! is pinned against the shared cross-implementation test vectors.

mod build;
mod constants;
mod cose;
mod types;
mod verify;

pub use build::{build_inclusion_certificate, BuildCertificateError};
pub use constants::{
    CERTIFICATE_CLAIM, CERTIFICATE_INDEPENDENT_TOOLS, CERTIFICATE_TIME_ASSERTED_BY,
    CERTIFICATE_TREE_ALG, CERTIFICATE_VERIFICATION_METHOD, INCLUSION_CERTIFICATE_FORMAT_V1,
    METADATA_LABEL_309, VDS_RFC9162_SHA256,
};
pub use cose::{encode_cose_inclusion_proof, encode_ietf_inclusion_proof, CoseInclusionProofError};
pub use types::{
    CertificateAnchor, CertificateMerkle, CertificateTarget, InclusionCertificateAnchor,
    InclusionCertificateItem, InclusionCertificateItemVerdict, InclusionCertificateMerkle,
    InclusionCertificateV1, InclusionCertificateVerification, InclusionCertificateVerifyResult,
};
pub use verify::verify_inclusion_certificate;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{decode_canonical_cbor, CborValue};
    use crate::hash::sha256;
    use crate::hex::{decode as hex_to_bytes, encode as bytes_to_hex};
    use crate::merkle::merkle_root;

    /// Deterministic leaf: SHA-256 of a single byte. Reused by the parity vector.
    fn leaf_of(i: u8) -> [u8; 32] {
        sha256(&[i])
    }

    fn make_leaves(n: u8) -> Vec<[u8; 32]> {
        (0..n).map(leaf_of).collect()
    }

    fn anchor_for(network: &str) -> CertificateAnchor {
        CertificateAnchor {
            chain: "cardano".to_string(),
            network: network.to_string(),
            tx_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            metadata_label: 309,
            block_time: 1_718_539_200,
            block_height: Some(12_345_678),
            slot: Some(123_456_789),
            confirmations_at_generation: None,
            explorer_urls: None,
        }
    }

    fn merkle_for(leaves: &[[u8; 32]]) -> CertificateMerkle {
        CertificateMerkle {
            tree_alg: "rfc9162-sha256".to_string(),
            root: merkle_root(leaves).unwrap(),
            tree_size: leaves.len(),
            leaves_list_uri: None,
            leaves_list_url: None,
        }
    }

    fn target(leaf: [u8; 32], leaf_alg: Option<&str>, label: Option<&str>) -> CertificateTarget {
        CertificateTarget {
            leaf,
            leaf_alg: leaf_alg.map(str::to_string),
            label: label.map(str::to_string),
        }
    }

    #[test]
    fn builds_and_reverifies_several_targets_to_ok_true() {
        let leaves = make_leaves(8);
        let merkle = merkle_for(&leaves);
        let targets = vec![
            target(leaves[0], None, Some("first")),
            target(leaves[3], Some("sha2-256"), None),
            target(leaves[7], None, None),
        ];

        let cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &targets,
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();

        assert_eq!(cert.items.len(), 3);
        assert!(cert.items.iter().all(|it| it.verified));
        assert_eq!(
            cert.items.iter().map(|it| it.index).collect::<Vec<_>>(),
            vec![0, 3, 7]
        );
        // anchor camelCase -> snake_case with derived ISO time.
        assert_eq!(cert.anchor.metadata_label, 309);
        assert_eq!(cert.anchor.block_time_iso, "2024-06-16T12:00:00.000Z");
        assert_eq!(cert.anchor.block_height, Some(12_345_678));

        let result = verify_inclusion_certificate(&cert);
        assert!(result.ok);
        assert_eq!(
            result.items.iter().map(|v| v.verified).collect::<Vec<_>>(),
            vec![true, true, true]
        );
        assert_eq!(result.anchor_claim.tx_hash, anchor_for("mainnet").tx_hash);
        assert_eq!(result.anchor_claim.block_time, 1_718_539_200);
    }

    #[test]
    fn tamper_flips_item_to_false() {
        let leaves = make_leaves(8);
        let merkle = merkle_for(&leaves);
        let mut cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[2], None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();

        // Corrupt the first sibling: the item must no longer verify.
        let mut sibling = hex_to_bytes(&cert.items[0].proof[0]).unwrap();
        sibling[0] ^= 0xff;
        cert.items[0].proof[0] = bytes_to_hex(&sibling);

        let result = verify_inclusion_certificate(&cert);
        assert!(!result.items[0].verified);
        assert!(!result.ok);
    }

    #[test]
    fn corrupt_root_flips_every_item_to_false() {
        let leaves = make_leaves(8);
        let merkle = merkle_for(&leaves);
        let mut cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None), target(leaves[1], None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();

        let mut bad_root = hex_to_bytes(&cert.merkle.root).unwrap();
        bad_root[0] ^= 0xff;
        cert.merkle.root = bytes_to_hex(&bad_root);

        let result = verify_inclusion_certificate(&cert);
        assert!(result.items.iter().all(|v| !v.verified));
        assert!(!result.ok);
    }

    #[test]
    fn single_leaf_tree_has_empty_proof() {
        let leaves = make_leaves(1);
        let merkle = merkle_for(&leaves);
        let cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();
        assert!(cert.items[0].proof.is_empty());
        assert!(cert.items[0].verified);
        assert!(verify_inclusion_certificate(&cert).ok);
    }

    #[test]
    fn absent_target_is_a_non_failing_miss() {
        let leaves = make_leaves(4);
        let merkle = merkle_for(&leaves);
        let stranger = sha256(&[0xaa, 0xbb]); // not any leaf_of(i)
        let cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[
                target(leaves[1], None, None),
                target(stranger, None, Some("missing.pdf")),
            ],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();

        assert_eq!(cert.items.len(), 2);
        assert!(cert.items[0].verified);
        let miss = &cert.items[1];
        assert!(!miss.verified);
        assert_eq!(miss.index, -1);
        assert!(miss.error.as_deref().is_some_and(|e| !e.is_empty()));
        assert_eq!(miss.label.as_deref(), Some("missing.pdf"));

        // The miss makes the whole certificate not-ok, and the error survives.
        let result = verify_inclusion_certificate(&cert);
        assert!(!result.ok);
        assert!(!result.items[1].verified);
        assert_eq!(result.items[1].error, miss.error);
    }

    #[test]
    fn build_rejects_tree_size_mismatch() {
        let leaves = make_leaves(4);
        let merkle = CertificateMerkle {
            tree_alg: "rfc9162-sha256".to_string(),
            root: merkle_root(&leaves).unwrap(),
            tree_size: 5,
            leaves_list_uri: None,
            leaves_list_url: None,
        };
        let err = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None)],
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BuildCertificateError::TreeSizeMismatch {
                tree_size: 5,
                leaves_len: 4
            }
        ));
    }

    #[test]
    fn build_rejects_unsupported_tree_alg() {
        let leaves = make_leaves(4);
        let merkle = CertificateMerkle {
            tree_alg: "blake2b-merkle".to_string(),
            root: merkle_root(&leaves).unwrap(),
            tree_size: 4,
            leaves_list_uri: None,
            leaves_list_url: None,
        };
        let err = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None)],
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BuildCertificateError::UnsupportedTreeAlg { .. }
        ));
    }

    #[test]
    fn build_rejects_root_that_is_not_the_tree_root() {
        let leaves = make_leaves(4);
        let mut reversed = make_leaves(4);
        reversed.reverse();
        let wrong_root = merkle_root(&reversed).unwrap();
        let merkle = CertificateMerkle {
            tree_alg: "rfc9162-sha256".to_string(),
            root: wrong_root,
            tree_size: 4,
            leaves_list_uri: None,
            leaves_list_url: None,
        };
        let err = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None)],
            None,
        )
        .unwrap_err();
        assert_eq!(err, BuildCertificateError::RootMismatch);
    }

    fn base_cert() -> InclusionCertificateV1 {
        let leaves = make_leaves(4);
        let merkle = merkle_for(&leaves);
        build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap()
    }

    #[test]
    fn verify_rejects_unknown_format_with_anchor_echoed() {
        let mut cert = base_cert();
        cert.format = "something-else".to_string();
        let result = verify_inclusion_certificate(&cert);
        assert!(!result.ok);
        assert!(result.error.is_some());
        assert!(result.items.is_empty());
        assert_eq!(result.anchor_claim.tx_hash, anchor_for("mainnet").tx_hash);
    }

    #[test]
    fn verify_rejects_unsupported_tree_alg() {
        let mut cert = base_cert();
        cert.merkle.tree_alg = "rfc9162-blake2b".to_string();
        let result = verify_inclusion_certificate(&cert);
        assert!(!result.ok);
        assert!(result.error.is_some());
    }

    #[test]
    fn verify_rejects_forged_oversized_tree_size_without_panicking() {
        let mut cert = base_cert();
        // 2^32 is past the 32-bit fold boundary the primitive can verify exactly.
        cert.merkle.tree_size = 0x1_0000_0000;
        let result = verify_inclusion_certificate(&cert);
        assert!(!result.ok);
        assert!(result.error.is_some());
    }

    #[test]
    fn verify_rejects_out_of_range_item_index() {
        let mut cert = base_cert();
        cert.items[0].index = 999;
        let result = verify_inclusion_certificate(&cert);
        assert!(!result.ok);
        assert!(!result.items[0].verified);
        assert!(result.items[0].error.is_some());
    }

    #[test]
    fn verify_rejects_non_cardano_label_309_anchor_echoing_claim() {
        let mut wrong_chain = base_cert();
        wrong_chain.anchor.chain = "bitcoin".to_string();
        let result = verify_inclusion_certificate(&wrong_chain);
        assert!(!result.ok);
        assert!(result.error.is_some());
        assert_eq!(result.anchor_claim.chain, "bitcoin");

        let mut wrong_label = base_cert();
        wrong_label.anchor.metadata_label = 721;
        let result = verify_inclusion_certificate(&wrong_label);
        assert!(!result.ok);
        assert!(result.error.is_some());
        assert_eq!(result.anchor_claim.metadata_label, 721);
    }

    #[test]
    fn ietf_and_cose_proofs_decode_to_the_expected_shape() {
        let leaves = make_leaves(8);
        let merkle = merkle_for(&leaves);
        let anchor = anchor_for("mainnet");
        let cert = build_inclusion_certificate(
            &anchor,
            &merkle,
            &leaves,
            &[target(leaves[6], Some("sha2-256"), None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();
        let item = &cert.items[0];

        // The bare IETF inclusion-proof is a `bstr .cbor [...]`.
        let bstr_bytes = encode_ietf_inclusion_proof(item, &merkle).unwrap();
        let inner_array_bytes = match decode_canonical_cbor(&bstr_bytes).unwrap() {
            CborValue::Bytes(b) => b,
            other => panic!("expected a byte string, got {other:?}"),
        };
        let inner = match decode_canonical_cbor(&inner_array_bytes).unwrap() {
            CborValue::Array(items) => items,
            other => panic!("expected an array, got {other:?}"),
        };
        assert_eq!(inner[0], CborValue::Unsigned(merkle.tree_size as u64));
        assert_eq!(inner[1], CborValue::Unsigned(item.index as u64));
        let siblings = match &inner[2] {
            CborValue::Array(s) => s,
            other => panic!("expected siblings array, got {other:?}"),
        };
        let sibling_hex: Vec<String> = siblings
            .iter()
            .map(|s| match s {
                CborValue::Bytes(b) => bytes_to_hex(b),
                other => panic!("expected a sibling byte string, got {other:?}"),
            })
            .collect();
        assert_eq!(sibling_hex, item.proof);

        // Full COSE map.
        let cose_bytes = encode_cose_inclusion_proof(item, &merkle, &anchor).unwrap();
        let cose = match decode_canonical_cbor(&cose_bytes).unwrap() {
            CborValue::Map(pairs) => pairs,
            other => panic!("expected a map, got {other:?}"),
        };
        let get = |key: &str| {
            cose.iter().find_map(|(k, v)| match k {
                CborValue::Text(t) if t == key => Some(v),
                _ => None,
            })
        };
        assert_eq!(get("vds"), Some(&CborValue::Unsigned(1)));
        assert_eq!(
            get("root"),
            Some(&CborValue::Bytes(hex_to_bytes(&cert.merkle.root).unwrap()))
        );
        assert_eq!(
            get("leaf"),
            Some(&CborValue::Bytes(hex_to_bytes(&item.leaf).unwrap()))
        );
        assert_eq!(get("leaf_alg"), Some(&CborValue::text("sha2-256")));

        // The map's inclusion_proof field is the same array bytes the bare IETF
        // helper wraps in a bstr.
        assert_eq!(
            get("inclusion_proof"),
            Some(&CborValue::Bytes(inner_array_bytes.clone()))
        );
        // And the on-wire bstr appears verbatim inside the COSE map bytes.
        assert!(bytes_to_hex(&cose_bytes).contains(&bytes_to_hex(&bstr_bytes)));
    }

    #[test]
    fn encoders_refuse_non_inclusion_items() {
        let leaves = make_leaves(4);
        let merkle = merkle_for(&leaves);
        let stranger = sha256(&[0x99, 0x88]);
        let cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None), target(stranger, None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();
        let proven = cert.items[0].clone();
        let miss = cert.items[1].clone();

        // A miss has an error and verified:false — both encoders refuse it.
        assert!(matches!(
            encode_cose_inclusion_proof(&miss, &merkle, &anchor_for("mainnet")),
            Err(CoseInclusionProofError::ItemError(_))
        ));
        assert!(matches!(
            encode_ietf_inclusion_proof(&miss, &merkle),
            Err(CoseInclusionProofError::ItemError(_))
        ));

        // An otherwise-proven item forced to verified:false is refused.
        let mut unverified = proven.clone();
        unverified.verified = false;
        assert!(matches!(
            encode_cose_inclusion_proof(&unverified, &merkle, &anchor_for("mainnet")),
            Err(CoseInclusionProofError::Unverified)
        ));

        // An out-of-range index on a proven-shaped item is refused.
        let mut bad_index = proven;
        bad_index.index = 4;
        assert!(matches!(
            encode_cose_inclusion_proof(&bad_index, &merkle, &anchor_for("mainnet")),
            Err(CoseInclusionProofError::IndexOutOfRange { .. })
        ));
    }

    #[test]
    fn cose_omits_leaf_alg_when_absent() {
        let leaves = make_leaves(4);
        let merkle = merkle_for(&leaves);
        let cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();
        let cose = match decode_canonical_cbor(
            &encode_cose_inclusion_proof(&cert.items[0], &merkle, &anchor_for("mainnet")).unwrap(),
        )
        .unwrap()
        {
            CborValue::Map(pairs) => pairs,
            other => panic!("expected a map, got {other:?}"),
        };
        let has_leaf_alg = cose
            .iter()
            .any(|(k, _)| matches!(k, CborValue::Text(t) if t == "leaf_alg"));
        assert!(!has_leaf_alg);
    }

    // --- hex case-insensitivity and malformed-hex handling ----------------

    fn uppercase_hex_fields(cert: &InclusionCertificateV1) -> InclusionCertificateV1 {
        let mut out = cert.clone();
        out.merkle.root = out.merkle.root.to_uppercase();
        for item in &mut out.items {
            item.leaf = item.leaf.to_uppercase();
            item.proof = item.proof.iter().map(|s| s.to_uppercase()).collect();
        }
        out
    }

    #[test]
    fn verifies_uppercase_hex_identically_to_lowercase() {
        let leaves = make_leaves(8);
        let merkle = merkle_for(&leaves);
        let cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None), target(leaves[5], None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();

        let lower = verify_inclusion_certificate(&cert);
        let upper = verify_inclusion_certificate(&uppercase_hex_fields(&cert));

        assert!(upper.ok);
        assert_eq!(upper.ok, lower.ok);
        assert_eq!(
            upper.items.iter().map(|v| v.verified).collect::<Vec<_>>(),
            lower.items.iter().map(|v| v.verified).collect::<Vec<_>>()
        );
        assert_eq!(
            upper.items.iter().map(|v| v.verified).collect::<Vec<_>>(),
            vec![true, true]
        );
    }

    #[test]
    fn verify_returns_false_without_panicking_on_hex_with_embedded_space() {
        let leaves = make_leaves(4);
        let merkle = merkle_for(&leaves);
        let mut cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[1], None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();
        let leaf_hex = cert.items[0].leaf.clone();
        cert.items[0].leaf = format!("{} {}", &leaf_hex[..10], &leaf_hex[11..]);

        let result = verify_inclusion_certificate(&cert);
        assert!(!result.ok);
        assert!(!result.items[0].verified);
        assert!(result.items[0].error.is_some());
    }

    #[test]
    fn cose_accepts_uppercase_hex_and_emits_same_bytes() {
        let leaves = make_leaves(4);
        let merkle = merkle_for(&leaves);
        let anchor = anchor_for("mainnet");
        let cert = build_inclusion_certificate(
            &anchor,
            &merkle,
            &leaves,
            &[target(leaves[2], Some("sha2-256"), None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();
        let lower = encode_cose_inclusion_proof(&cert.items[0], &merkle, &anchor).unwrap();

        let mut upper_item = cert.items[0].clone();
        upper_item.leaf = upper_item.leaf.to_uppercase();
        upper_item.proof = upper_item.proof.iter().map(|s| s.to_uppercase()).collect();
        let mut upper_anchor = anchor.clone();
        upper_anchor.tx_hash = upper_anchor.tx_hash.to_uppercase();
        let upper = encode_cose_inclusion_proof(&upper_item, &merkle, &upper_anchor).unwrap();

        assert_eq!(upper, lower);
    }

    // --- wrong-length hex fields match the canonical TypeScript result shape

    #[test]
    fn wrong_length_root_keeps_items_no_cert_error_ok_false() {
        let leaves = make_leaves(8);
        let merkle = merkle_for(&leaves);
        let mut cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None), target(leaves[3], None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();
        // 31 bytes of valid hex — decodes fine but is not a 32-byte root.
        cert.merkle.root.truncate(62);

        let result = verify_inclusion_certificate(&cert);
        assert!(!result.ok);
        assert!(result.error.is_none());
        assert_eq!(result.items.len(), 2);
        assert!(result.items.iter().all(|v| !v.verified));
        assert!(result.items.iter().all(|v| v.error.is_none()));
    }

    #[test]
    fn wrong_length_sibling_keeps_item_no_item_error_ok_false() {
        let leaves = make_leaves(8);
        let merkle = merkle_for(&leaves);
        let mut cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[2], None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();
        // 31 bytes of valid hex for the first sibling.
        cert.items[0].proof[0].truncate(62);

        let result = verify_inclusion_certificate(&cert);
        assert!(!result.ok);
        assert!(result.error.is_none());
        assert_eq!(result.items.len(), 1);
        assert!(!result.items[0].verified);
        assert!(result.items[0].error.is_none());
    }

    // --- block_time range guard in the builder ----------------------------

    #[test]
    fn builder_renders_fixed_iso_for_in_range_epoch() {
        let leaves = make_leaves(4);
        let merkle = merkle_for(&leaves);
        let cert = build_inclusion_certificate(
            &anchor_for("mainnet"),
            &merkle,
            &leaves,
            &[target(leaves[0], None, None)],
            Some("2026-06-16T12:00:00.000Z"),
        )
        .unwrap();
        assert_eq!(cert.anchor.block_time_iso, "2024-06-16T12:00:00.000Z");
    }

    #[test]
    fn builder_rejects_negative_block_time() {
        let leaves = make_leaves(4);
        let merkle = merkle_for(&leaves);
        let mut anchor = anchor_for("mainnet");
        anchor.block_time = -1;
        let err = build_inclusion_certificate(
            &anchor,
            &merkle,
            &leaves,
            &[target(leaves[0], None, None)],
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BuildCertificateError::BlockTimeOutOfRange { block_time: -1 }
        ));
    }

    #[test]
    fn builder_rejects_block_time_beyond_year_9999() {
        let leaves = make_leaves(4);
        let merkle = merkle_for(&leaves);
        let mut anchor = anchor_for("mainnet");
        anchor.block_time = 253_402_300_800;
        let err = build_inclusion_certificate(
            &anchor,
            &merkle,
            &leaves,
            &[target(leaves[0], None, None)],
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BuildCertificateError::BlockTimeOutOfRange {
                block_time: 253_402_300_800
            }
        ));
    }
}
