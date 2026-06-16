//! Fixed string constants embedded verbatim in every inclusion certificate.
//!
//! These are part of the on-disk format: the parity twins in the TypeScript and
//! Python SDKs reproduce them byte-for-byte, so they are defined once here and
//! never templated or localised.

/// The `format` literal stamped into every v1 inclusion certificate.
pub const INCLUSION_CERTIFICATE_FORMAT_V1: &str = "label-309-inclusion-certificate-v1";

/// RFC 9162 (Certificate Transparency) SHA-256, IANA verifiable-data-structure
/// codepoint 1; the only `tree_alg` the certificate supports.
pub const CERTIFICATE_TREE_ALG: &str = "rfc9162-sha256";

/// Cardano metadata label that carries Label 309 records.
pub const METADATA_LABEL_309: u64 = 309;

/// IANA "COSE Verifiable Data Structures" codepoint for RFC9162_SHA256.
pub const VDS_RFC9162_SHA256: u64 = 1;

/// The plain-language statement of what the certificate proves.
pub const CERTIFICATE_CLAIM: &str = concat!(
    "Each listed hash was included in a Merkle tree whose root was published on ",
    "the Cardano blockchain in the referenced transaction under metadata label ",
    "309; therefore each hash provably existed on or before the stated block time."
);

/// The human/machine-readable verification method recorded in the certificate.
pub const CERTIFICATE_VERIFICATION_METHOD: &str = concat!(
    "RFC 9162 (Certificate Transparency) SHA-256 inclusion proof. For each item, ",
    "recompute the Merkle root from leaf+index+tree_size+proof and compare to ",
    "merkle.root; then confirm merkle.root equals the merkle[].root in the ",
    "Label 309 record of anchor.tx_hash on any public Cardano explorer."
);

/// The independent tools that can re-verify the certificate without trusting
/// the issuer, listed verbatim in the certificate's `verification` block.
pub const CERTIFICATE_INDEPENDENT_TOOLS: &[&str] = &[
    "cardanowall certificate verify <file>",
    "cardanowall merkle verify (per item)",
    "any RFC 9162 / COSE verifiable-data-structure verifier",
];

/// Who asserts the certificate's time value (the chain, never the issuer).
pub const CERTIFICATE_TIME_ASSERTED_BY: &str =
    "Cardano blockchain (block time), via public explorers";
