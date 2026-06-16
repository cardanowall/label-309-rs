//! Type surface for the Label 309 Inclusion Certificate.
//!
//! An inclusion certificate is a downloadable, self-contained, standalone-
//! verifiable proof that one or more content hashes were committed as leaves of
//! an RFC 9162 (Certificate Transparency) SHA-256 Merkle tree whose root was
//! published on Cardano under metadata label 309. Each item embeds its full
//! sibling path, so the artifact re-verifies forever from the file alone — no
//! network, no storage gateway, no trust in any issuer.
//!
//! Two kinds of value live here:
//!
//! - the *input* shapes ([`CertificateAnchor`], [`CertificateMerkle`],
//!   [`CertificateTarget`]) the builder consumes, with raw byte values; and
//! - the *output* JSON shape ([`InclusionCertificateV1`] and friends) the
//!   builder emits, with lowercase-hex string values and snake_case keys, so it
//!   serialises directly to the on-disk certificate.

use serde::{Deserialize, Serialize};

/// Length in bytes of every leaf digest and the Merkle root (SHA-256).
pub(crate) const DIGEST_LENGTH: usize = 32;

/// The blockchain anchor: the Cardano transaction whose Label 309 record carries
/// the Merkle root.
///
/// Every time/height/slot value here is asserted by the public blockchain (via
/// explorers), never cryptographically bound by the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAnchor {
    /// The anchoring chain identifier; only `"cardano"` is a conforming value.
    pub chain: String,
    /// Cardano network name, e.g. `"mainnet"` or `"preprod"`.
    pub network: String,
    /// Transaction hash, 64 lowercase hex characters.
    pub tx_hash: String,
    /// The Cardano metadata label; `309` for a conforming certificate.
    pub metadata_label: u64,
    /// Block time in POSIX seconds, as asserted by the explorer.
    pub block_time: i64,
    /// Optional block height, explorer-asserted.
    pub block_height: Option<i64>,
    /// Optional slot number, explorer-asserted.
    pub slot: Option<i64>,
    /// Confirmation count snapshot at generation; informational, not a claim.
    pub confirmations_at_generation: Option<i64>,
    /// Optional explorer URLs for the anchoring transaction.
    pub explorer_urls: Option<Vec<String>>,
}

/// The Merkle commitment the certificate proves inclusion against.
///
/// `root` is the raw 32-byte tree head; `tree_size` is the on-chain
/// `leaf_count`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMerkle {
    /// Tree algorithm identifier; only `"rfc9162-sha256"` is supported.
    pub tree_alg: String,
    /// The raw 32-byte tree root.
    pub root: [u8; DIGEST_LENGTH],
    /// Number of leaves in the tree (the on-chain `leaf_count`).
    pub tree_size: usize,
    /// Optional `ar://` source reference for the off-chain leaves-list.
    pub leaves_list_uri: Option<String>,
    /// Optional convenience HTTPS mirror of the leaves-list.
    pub leaves_list_url: Option<String>,
}

/// One target the caller wants proven: a committed content hash (a leaf) plus an
/// optional human label and the algorithm used to hash a file into the leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateTarget {
    /// The 32-byte content hash that was committed as a leaf.
    pub leaf: [u8; DIGEST_LENGTH],
    /// How a file is hashed to reproduce `leaf` (e.g. `"sha2-256"`).
    pub leaf_alg: Option<String>,
    /// Optional user note / filename.
    pub label: Option<String>,
}

/// The anchor block of the emitted JSON certificate (snake_case, hex strings).
///
/// Optional fields are omitted from the serialised JSON rather than emitted as
/// `null`, matching the TypeScript and Python twins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionCertificateAnchor {
    /// The anchoring chain, echoed verbatim from the input anchor.
    pub chain: String,
    /// The Cardano network name.
    pub network: String,
    /// The anchoring transaction hash (64 lowercase hex).
    pub tx_hash: String,
    /// The Cardano metadata label (`309`).
    pub metadata_label: u64,
    /// Block time in POSIX seconds.
    pub block_time: i64,
    /// Block time rendered as a UTC ISO-8601 instant, derived from `block_time`.
    pub block_time_iso: String,
    /// Optional block height.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<i64>,
    /// Optional slot number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<i64>,
    /// Optional confirmation snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations_at_generation: Option<i64>,
    /// Optional explorer URLs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_urls: Option<Vec<String>>,
}

/// The Merkle block of the emitted JSON certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionCertificateMerkle {
    /// The tree algorithm identifier.
    pub tree_alg: String,
    /// Lowercase hex of the raw 32-byte root.
    pub root: String,
    /// Number of leaves in the tree.
    pub tree_size: usize,
    /// Optional `ar://` source reference for the leaves-list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaves_list_uri: Option<String>,
    /// Optional convenience HTTPS mirror of the leaves-list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaves_list_url: Option<String>,
}

/// One certificate item: a leaf, its position, and the sibling path that
/// recomputes the root.
///
/// `verified` records the builder's recomputation at generation time; an
/// independent verifier MUST recompute it and not trust this stored boolean. A
/// target absent from the tree is still emitted, with `verified: false` and an
/// explanatory `error`.
///
/// Fields are declared in the normative key order so the serialised JSON is
/// stable across the parity twins: `leaf`, `leaf_alg?`, `index`, `proof`,
/// `verified`, `label?`, `error?`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionCertificateItem {
    /// Lowercase hex of the committed content hash.
    pub leaf: String,
    /// Optional algorithm used to hash a file into `leaf`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_alg: Option<String>,
    /// The leaf's position in the tree, or `-1` for a target not in the tree.
    pub index: i64,
    /// Sibling hashes, leaf→root order, lowercase hex; empty for a single leaf.
    pub proof: Vec<String>,
    /// The builder's generation-time verdict; never trusted on re-verification.
    pub verified: bool,
    /// Optional user note / filename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Present only when the target could not be proven (e.g. not in the tree).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Human/machine-readable statement of what the certificate proves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionCertificateVerification {
    /// The verification method, recorded verbatim.
    pub method: String,
    /// The independent tools that re-verify the certificate without the issuer.
    pub independent_tools: Vec<String>,
    /// Always `false`: verification needs no trust in the issuer.
    pub requires_trust_in_cardanowall: bool,
    /// Who asserts the certificate's time value (the chain).
    pub time_asserted_by: String,
}

/// The full Label 309 inclusion certificate (the JSON form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionCertificateV1 {
    /// The format literal (`label-309-inclusion-certificate-v1`).
    pub format: String,
    /// Generation timestamp; informational only, never trusted by a verifier.
    pub generated_at: String,
    /// The blockchain anchor block.
    pub anchor: InclusionCertificateAnchor,
    /// The Merkle commitment block.
    pub merkle: InclusionCertificateMerkle,
    /// One item per target, in input order.
    pub items: Vec<InclusionCertificateItem>,
    /// The plain-language claim.
    pub claim: String,
    /// The verification block.
    pub verification: InclusionCertificateVerification,
}

/// Per-item verdict from a pure re-verification of a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionCertificateItemVerdict {
    /// The leaf's claimed index, echoed from the certificate.
    pub index: i64,
    /// Lowercase hex of the leaf, echoed from the certificate.
    pub leaf: String,
    /// Whether the item's proof recomputes to the embedded root.
    pub verified: bool,
    /// Present when the item could not be verified, with the reason.
    pub error: Option<String>,
}

/// Result of [`verify_inclusion_certificate`](super::verify_inclusion_certificate).
///
/// `ok` is true only when every item's proof recomputes to the embedded root.
/// `anchor_claim` is echoed from the certificate and MUST be confirmed on a
/// public Cardano explorer separately — re-verification proves inclusion math,
/// never the anchoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionCertificateVerifyResult {
    /// `true` only when every item verified.
    pub ok: bool,
    /// The per-item verdicts, in certificate order.
    pub items: Vec<InclusionCertificateItemVerdict>,
    /// The certificate's claimed anchor, echoed for separate on-chain confirmation.
    pub anchor_claim: CertificateAnchor,
    /// Present when the whole certificate was rejected (bad format / tree alg).
    pub error: Option<String>,
}
