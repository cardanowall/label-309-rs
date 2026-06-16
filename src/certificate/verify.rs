//! Pure re-verification of a Label 309 inclusion certificate.
//!
//! [`verify_inclusion_certificate`] recomputes each item's Merkle proof from the
//! certificate alone — no Arweave fetch, no chain query — and reports a verdict.
//! It proves the *inclusion* claim (each leaf is at its stated index of a tree
//! with the embedded root). It does NOT and cannot prove the *anchoring* claim:
//! that `merkle.root` actually appears in the Label 309 record of
//! `anchor.tx_hash` on chain. The anchor is echoed as `anchor_claim` for the
//! caller to confirm on any public Cardano explorer as a separate step.
//!
//! This function never errors on attacker-controlled input: a forged or
//! malformed certificate (bad format, tree algorithm, anchor fixed fields, or an
//! out-of-range `tree_size` / index) is reported as `ok: false` with a clear
//! error, never a panic.

use crate::hex::decode as hex_to_bytes;
use crate::merkle::verify_inclusion;

use super::constants::{CERTIFICATE_TREE_ALG, INCLUSION_CERTIFICATE_FORMAT_V1, METADATA_LABEL_309};
use super::types::{
    CertificateAnchor, InclusionCertificateItem, InclusionCertificateItemVerdict,
    InclusionCertificateV1, InclusionCertificateVerifyResult, DIGEST_LENGTH,
};

/// The verify primitive is only exact while `tree_size` stays within the 32-bit
/// fold domain (the on-chain commitment caps `leaf_count` at the same value). A
/// certificate claiming a larger `tree_size` is forged; it is rejected here so
/// the primitive's range guard is never reached from this path.
const MAX_TREE_SIZE: u64 = 0xffff_ffff;

/// Re-verify an inclusion certificate purely from its own bytes.
///
/// For every item this recomputes the RFC 9162 inclusion proof and records the
/// verdict. `ok` is true only when every item verifies. The stored `verified`
/// flag in the certificate is never trusted — this recomputes it.
///
/// The certificate as a whole is rejected (returns `ok: false` with an `error`,
/// never panics) when its `format`, `merkle.tree_alg`, anchor fixed fields, or
/// `merkle.tree_size` are unsupported / out of range.
///
/// The returned `anchor_claim` echoes the certificate's *claimed* anchor
/// verbatim. It must be confirmed on a public Cardano explorer; this function
/// does no chain I/O and asserts nothing about the anchor beyond its structural
/// shape.
#[must_use]
pub fn verify_inclusion_certificate(
    cert: &InclusionCertificateV1,
) -> InclusionCertificateVerifyResult {
    let anchor_claim = anchor_claim_of(cert);

    if cert.format != INCLUSION_CERTIFICATE_FORMAT_V1 {
        return reject(
            anchor_claim,
            format!("unsupported certificate format '{}'", cert.format),
        );
    }
    if cert.merkle.tree_alg != CERTIFICATE_TREE_ALG {
        return reject(
            anchor_claim,
            format!("unsupported tree_alg '{}'", cert.merkle.tree_alg),
        );
    }

    // The anchor's fixed fields are part of the format, not explorer-asserted
    // facts: a certificate that does not name Cardano / metadata label 309 is
    // not a Label 309 inclusion certificate.
    if cert.anchor.chain != "cardano" {
        return reject(
            anchor_claim,
            format!("unsupported anchor.chain '{}'", cert.anchor.chain),
        );
    }
    if cert.anchor.metadata_label != METADATA_LABEL_309 {
        return reject(
            anchor_claim,
            format!(
                "unsupported anchor.metadata_label '{}'",
                cert.anchor.metadata_label
            ),
        );
    }

    let tree_size = cert.merkle.tree_size;
    if tree_size < 1 || tree_size as u64 > MAX_TREE_SIZE {
        return reject(
            anchor_claim,
            format!("merkle.tree_size {tree_size} out of range"),
        );
    }

    // Decode the root without gating on length: a valid-hex-but-wrong-length
    // root is not a certificate-level rejection — it flows into the verify
    // primitive, which returns `false` for a non-32-byte root, so every item
    // becomes a non-verifying verdict (no item-level error). Only a root that is
    // not even-length hex (non-hex character or odd length) is a malformed
    // certificate. This matches the canonical TypeScript verifier exactly.
    let root = match hex_to_bytes(&cert.merkle.root) {
        Ok(bytes) => bytes,
        Err(err) => {
            return reject(anchor_claim, format!("malformed merkle.root: {err}"));
        }
    };

    let items: Vec<InclusionCertificateItemVerdict> = cert
        .items
        .iter()
        .map(|item| verify_item(item, tree_size, &root))
        .collect();
    let ok = !items.is_empty() && items.iter().all(|v| v.verified);

    InclusionCertificateVerifyResult {
        ok,
        items,
        anchor_claim,
        error: None,
    }
}

/// Build a whole-certificate rejection result with the anchor still echoed.
fn reject(anchor_claim: CertificateAnchor, error: String) -> InclusionCertificateVerifyResult {
    InclusionCertificateVerifyResult {
        ok: false,
        items: Vec::new(),
        anchor_claim,
        error: Some(error),
    }
}

/// Re-verify one item, carrying any build-time error through to the verdict and
/// pre-validating the index so the primitive's range guard is never reached.
fn verify_item(
    item: &InclusionCertificateItem,
    tree_size: usize,
    root: &[u8],
) -> InclusionCertificateItemVerdict {
    // A build-time error (e.g. "leaf not found") is carried through so a
    // re-verifier sees why a miss is a miss.
    if let Some(error) = &item.error {
        return InclusionCertificateItemVerdict {
            index: item.index,
            leaf: item.leaf.clone(),
            verified: false,
            error: Some(error.clone()),
        };
    }

    // Pre-validate the per-item index: an out-of-range index is a non-verifying
    // item with an explicit reason, not a forged `true`.
    if item.index < 0 || item.index as u64 >= tree_size as u64 {
        return InclusionCertificateItemVerdict {
            index: item.index,
            leaf: item.leaf.clone(),
            verified: false,
            error: Some(format!(
                "index {} out of range [0, {tree_size})",
                item.index
            )),
        };
    }
    let index = item.index as usize;

    let leaf = match hex_to_bytes(&item.leaf) {
        Ok(bytes) => bytes,
        Err(err) => {
            return InclusionCertificateItemVerdict {
                index: item.index,
                leaf: item.leaf.clone(),
                verified: false,
                error: Some(format!("malformed leaf: {err}")),
            };
        }
    };

    // A sibling that is not even-length hex (non-hex character or odd length) is
    // a malformed item with an explicit error. A sibling that is valid hex but
    // not 32 bytes is NOT an error: the verify primitive returns `false` for a
    // wrong-length sibling, so such an item is simply a non-verifying verdict
    // (verified: false, no error) — matching the canonical TypeScript verifier,
    // which folds the wrong-length sibling through the same `false`-returning
    // primitive. The fixed-size proof array cannot hold a non-32-byte sibling, so
    // we reproduce that verdict directly rather than calling the primitive.
    let mut proof: Vec<[u8; DIGEST_LENGTH]> = Vec::with_capacity(item.proof.len());
    for (i, sibling_hex) in item.proof.iter().enumerate() {
        match hex_to_bytes(sibling_hex) {
            Ok(bytes) if bytes.len() == DIGEST_LENGTH => {
                let mut arr = [0u8; DIGEST_LENGTH];
                arr.copy_from_slice(&bytes);
                proof.push(arr);
            }
            Ok(_) => {
                return InclusionCertificateItemVerdict {
                    index: item.index,
                    leaf: item.leaf.clone(),
                    verified: false,
                    error: None,
                };
            }
            Err(err) => {
                return InclusionCertificateItemVerdict {
                    index: item.index,
                    leaf: item.leaf.clone(),
                    verified: false,
                    error: Some(format!("malformed proof[{i}]: {err}")),
                };
            }
        }
    }

    let verified = verify_inclusion(&leaf, index, tree_size, &proof, root);
    InclusionCertificateItemVerdict {
        index: item.index,
        leaf: item.leaf.clone(),
        verified,
        error: None,
    }
}

/// Echo the certificate's *claimed* anchor verbatim into a [`CertificateAnchor`].
///
/// This is a faithful echo of the claimed anchor — never a fabrication and never
/// a validation; [`verify_inclusion_certificate`] validates the fixed fields
/// separately and the byte facts are confirmed on a public explorer.
fn anchor_claim_of(cert: &InclusionCertificateV1) -> CertificateAnchor {
    let a = &cert.anchor;
    CertificateAnchor {
        chain: a.chain.clone(),
        network: a.network.clone(),
        tx_hash: a.tx_hash.clone(),
        metadata_label: a.metadata_label,
        block_time: a.block_time,
        block_height: a.block_height,
        slot: a.slot,
        confirmations_at_generation: a.confirmations_at_generation,
        explorer_urls: a.explorer_urls.clone(),
    }
}
