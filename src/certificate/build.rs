//! Builder for the Label 309 inclusion certificate (the JSON form).
//!
//! [`build_inclusion_certificate`] takes the decoded Merkle leaves and a set of
//! targets, locates each target leaf, computes and self-verifies its inclusion
//! proof, and emits the typed JSON object. The output serialises directly to the
//! on-disk certificate; the parity twins reproduce the same field values.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::hex::encode as bytes_to_hex;
use crate::merkle::{merkle_inclusion_proof, merkle_root, verify_inclusion};

use super::constants::{
    CERTIFICATE_CLAIM, CERTIFICATE_INDEPENDENT_TOOLS, CERTIFICATE_TIME_ASSERTED_BY,
    CERTIFICATE_TREE_ALG, CERTIFICATE_VERIFICATION_METHOD, INCLUSION_CERTIFICATE_FORMAT_V1,
    METADATA_LABEL_309,
};
use super::types::{
    CertificateAnchor, CertificateMerkle, CertificateTarget, InclusionCertificateAnchor,
    InclusionCertificateItem, InclusionCertificateMerkle, InclusionCertificateV1,
    InclusionCertificateVerification, DIGEST_LENGTH,
};

/// `block_time` is POSIX seconds. It must be a non-negative integer that maps to
/// a calendar year in `1..=9999`, so `block_time_iso` renders the same fixed
/// `YYYY-MM-DDTHH:MM:SS.000Z` shape across every producer. 253402300800 is the
/// POSIX second of 10000-01-01T00:00:00Z (the first instant past year 9999).
const MAX_BLOCK_TIME_EXCLUSIVE: i64 = 253_402_300_800;

/// Structural-misuse rejection raised by [`build_inclusion_certificate`].
///
/// These are caller-side mistakes about the *inputs*, not honest "leaf not in
/// the tree" misses (which become a non-throwing item with `verified: false`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildCertificateError {
    /// `merkle.tree_alg` is not the supported `"rfc9162-sha256"`.
    #[error(
        "unsupported tree_alg '{tree_alg}' (only '{}' is supported)",
        CERTIFICATE_TREE_ALG
    )]
    UnsupportedTreeAlg {
        /// The offending tree algorithm identifier.
        tree_alg: String,
    },

    /// `merkle.tree_size` does not equal the number of leaves supplied.
    #[error("merkle.tree_size ({tree_size}) != leaves.len() ({leaves_len})")]
    TreeSizeMismatch {
        /// The declared tree size.
        tree_size: usize,
        /// The number of leaves actually supplied.
        leaves_len: usize,
    },

    /// `merkle.root` is not the root the supplied leaves actually produce.
    #[error("merkle.root does not match the root recomputed from leaves")]
    RootMismatch,

    /// `anchor.block_time` is negative or maps to a calendar year outside
    /// `1..=9999`, so `block_time_iso` could not render the fixed shape.
    #[error("anchor.block_time {block_time} out of range [0, {MAX_BLOCK_TIME_EXCLUSIVE}) (must map to a year in 1..=9999)")]
    BlockTimeOutOfRange {
        /// The offending POSIX-seconds value.
        block_time: i64,
    },

    /// The Merkle primitive rejected the leaf set (e.g. an empty tree).
    #[error("merkle error while recomputing the root: {0}")]
    Merkle(#[from] crate::merkle::MerkleError),
}

/// Build an inclusion certificate over the given leaves for the given targets.
///
/// For each target this finds the leaf's index in `leaves`, computes its sibling
/// path, re-verifies the path against `merkle.root`, and records the verdict. A
/// target not present in `leaves` is still emitted as an item with
/// `verified: false` and an `error` string — the certificate stays honest about
/// misses rather than dropping them.
///
/// `generated_at` is written verbatim to the certificate's `generated_at` field;
/// supply a fixed value to make the emitted JSON reproducible (the parity
/// vectors pin it). When `None`, the current UTC time is used. `generated_at` is
/// purely informational and never trusted by a verifier.
///
/// # Errors
///
/// Returns [`BuildCertificateError`] only on structural misuse of the inputs:
/// an unsupported `tree_alg`, a `tree_size` that disagrees with the leaf count,
/// a `root` that does not match the root recomputed from `leaves`, or a
/// `block_time` outside `[0, 253402300800)` (i.e. not mapping to a year in
/// `1..=9999`). (`root` being exactly 32 bytes is guaranteed at the type level
/// by `[u8; 32]`.)
pub fn build_inclusion_certificate(
    anchor: &CertificateAnchor,
    merkle: &CertificateMerkle,
    leaves: &[[u8; DIGEST_LENGTH]],
    targets: &[CertificateTarget],
    generated_at: Option<&str>,
) -> Result<InclusionCertificateV1, BuildCertificateError> {
    if merkle.tree_alg != CERTIFICATE_TREE_ALG {
        return Err(BuildCertificateError::UnsupportedTreeAlg {
            tree_alg: merkle.tree_alg.clone(),
        });
    }
    if merkle.tree_size != leaves.len() {
        return Err(BuildCertificateError::TreeSizeMismatch {
            tree_size: merkle.tree_size,
            leaves_len: leaves.len(),
        });
    }
    // The declared root must be the root the given leaves actually produce.
    // Building proofs against a root the leaves do not hash to would emit a
    // certificate every item of which fails verification — a structural misuse,
    // not an honest miss, so we refuse it up front.
    let recomputed_root = merkle_root(leaves)?;
    if !ct_eq(&recomputed_root, &merkle.root) {
        return Err(BuildCertificateError::RootMismatch);
    }
    if anchor.block_time < 0 || anchor.block_time >= MAX_BLOCK_TIME_EXCLUSIVE {
        return Err(BuildCertificateError::BlockTimeOutOfRange {
            block_time: anchor.block_time,
        });
    }

    let items: Vec<InclusionCertificateItem> = targets
        .iter()
        .map(|target| build_item(target, leaves, &merkle.root))
        .collect();

    Ok(InclusionCertificateV1 {
        format: INCLUSION_CERTIFICATE_FORMAT_V1.to_string(),
        generated_at: match generated_at {
            Some(value) => value.to_string(),
            None => now_iso8601(),
        },
        anchor: build_anchor(anchor),
        merkle: build_merkle(merkle),
        items,
        claim: CERTIFICATE_CLAIM.to_string(),
        verification: InclusionCertificateVerification {
            method: CERTIFICATE_VERIFICATION_METHOD.to_string(),
            independent_tools: CERTIFICATE_INDEPENDENT_TOOLS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            requires_trust_in_cardanowall: false,
            time_asserted_by: CERTIFICATE_TIME_ASSERTED_BY.to_string(),
        },
    })
}

/// Build one certificate item: locate the leaf, compute + self-verify its proof.
fn build_item(
    target: &CertificateTarget,
    leaves: &[[u8; DIGEST_LENGTH]],
    root: &[u8; DIGEST_LENGTH],
) -> InclusionCertificateItem {
    // The target leaf is always a 32-byte digest here (`[u8; 32]`), so the only
    // honest miss is "leaf not found in the committed leaf set".
    match find_leaf_index(leaves, &target.leaf) {
        None => InclusionCertificateItem {
            leaf: bytes_to_hex(&target.leaf),
            leaf_alg: target.leaf_alg.clone(),
            // Sentinel index for a target absent from the tree; this item is
            // never encoded to CBOR (the COSE encoder refuses a missed item).
            index: -1,
            proof: Vec::new(),
            verified: false,
            label: target.label.clone(),
            error: Some("leaf not found in the committed leaf set".to_string()),
        },
        Some(index) => {
            // The index came from a found leaf, so the proof is always available.
            let siblings = merkle_inclusion_proof(leaves, index)
                .expect("a found leaf index is always in range for its own tree");
            let proof: Vec<String> = siblings.iter().map(|s| bytes_to_hex(s)).collect();
            let verified = verify_inclusion(&target.leaf, index, leaves.len(), &siblings, root);
            InclusionCertificateItem {
                leaf: bytes_to_hex(&target.leaf),
                leaf_alg: target.leaf_alg.clone(),
                index: index as i64,
                proof,
                verified,
                label: target.label.clone(),
                error: None,
            }
        }
    }
}

/// Index of the first leaf byte-equal to `target`, or `None`.
fn find_leaf_index(leaves: &[[u8; DIGEST_LENGTH]], target: &[u8; DIGEST_LENGTH]) -> Option<usize> {
    leaves.iter().position(|leaf| ct_eq(leaf, target))
}

/// Map the camelCase input anchor onto the snake_case JSON anchor, deriving the
/// ISO time and omitting absent optional fields.
fn build_anchor(anchor: &CertificateAnchor) -> InclusionCertificateAnchor {
    InclusionCertificateAnchor {
        chain: anchor.chain.clone(),
        network: anchor.network.clone(),
        tx_hash: anchor.tx_hash.clone(),
        metadata_label: METADATA_LABEL_309,
        block_time: anchor.block_time,
        block_time_iso: unix_seconds_to_iso8601(anchor.block_time),
        block_height: anchor.block_height,
        slot: anchor.slot,
        confirmations_at_generation: anchor.confirmations_at_generation,
        explorer_urls: anchor.explorer_urls.clone(),
    }
}

/// Map the input Merkle block onto the JSON Merkle block (hex root).
fn build_merkle(merkle: &CertificateMerkle) -> InclusionCertificateMerkle {
    InclusionCertificateMerkle {
        tree_alg: merkle.tree_alg.clone(),
        root: bytes_to_hex(&merkle.root),
        tree_size: merkle.tree_size,
        leaves_list_uri: merkle.leaves_list_uri.clone(),
        leaves_list_url: merkle.leaves_list_url.clone(),
    }
}

/// Constant-time equality of two 32-byte digests.
fn ct_eq(a: &[u8; DIGEST_LENGTH], b: &[u8; DIGEST_LENGTH]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).unwrap_u8() == 1
}

/// The current UTC instant as an ISO-8601 string with millisecond precision and
/// a trailing `Z`, matching JavaScript's `Date.toISOString()`.
fn now_iso8601() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    format_iso8601(secs, millis)
}

/// Render POSIX seconds as a UTC ISO-8601 instant with millisecond precision and
/// a trailing `Z` (e.g. `1718539200` -> `"2024-06-16T12:00:00.000Z"`).
///
/// This mirrors `new Date(blockTime * 1000).toISOString()`: always three
/// fractional-second digits and the `Z` suffix.
fn unix_seconds_to_iso8601(secs: i64) -> String {
    format_iso8601(secs, 0)
}

/// Shared civil-date formatter producing `YYYY-MM-DDTHH:MM:SS.mmmZ` in UTC.
fn format_iso8601(secs: i64, millis: u32) -> String {
    // Split into whole days and the seconds within the day, flooring toward
    // negative infinity so pre-epoch instants render correctly.
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Convert a count of days since the Unix epoch to a `(year, month, day)` civil
/// date, using Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    // Shift the epoch from 1970-01-01 to 0000-03-01 so leap-day handling becomes
    // a uniform 400-year cycle.
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], starting from March
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_time_iso_matches_javascript_to_iso_string() {
        // 1718539200 == 2024-06-16T12:00:00.000Z, the value the parity vector
        // pins. The format carries millisecond precision and a trailing `Z`.
        assert_eq!(
            unix_seconds_to_iso8601(1_718_539_200),
            "2024-06-16T12:00:00.000Z"
        );
        assert_eq!(unix_seconds_to_iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            unix_seconds_to_iso8601(1_700_000_000),
            "2023-11-14T22:13:20.000Z"
        );
    }
}
