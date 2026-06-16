//! The per-item COSE / RFC 9162 aligned CBOR inclusion proof.
//!
//! The inner `inclusion-proof` structure is byte-identical to the IETF COSE
//! Merkle-tree-proofs encoding, so third-party COSE / SCITT verifiers read the
//! proof math directly:
//!
//! ```text
//! inclusion-proof = bstr .cbor [ tree_size: uint, leaf_index: uint, [ + bstr ] ]
//! ```
//!
//! Note the `bstr .cbor` wrapper: the standalone IETF value is a CBOR *byte
//! string* whose contents are the canonical-CBOR encoding of the
//! `[tree_size, leaf_index, inclusion-path]` array.
//!
//! That bstr is wrapped in a `cw-inclusion-proof` map that carries the
//! blockchain anchor in place of the COSE_Sign1 signature an IETF Receipt would
//! hold — the proof is deliberately unsigned-and-blockchain-anchored (the
//! timestamp authority is the Cardano transaction, not a key we control):
//!
//! ```text
//! cw-inclusion-proof = {
//!   "vds":             1,                 ; RFC9162_SHA256 (IANA value 1)
//!   "inclusion_proof": inclusion-proof,   ; the IETF bstr.cbor array
//!   "root":            bytes .size 32,
//!   "anchor": { "chain", "network", "tx_hash": bytes, "metadata_label": 309 },
//!   "leaf":            bytes .size 32,
//!   ? "leaf_alg":      tstr
//! }
//! ```
//!
//! The CBOR artifact exists only for a *proven* inclusion: a missing or
//! unverified item has no valid proof to encode, so the encoders refuse it
//! rather than emit a sentinel that decodes to a malformed proof.
//!
//! All encoding goes through the shared canonical-CBOR codec (RFC 8949
//! §4.2.1), whose encoder re-sorts map keys into canonical order — so the
//! on-wire bytes match the TypeScript and Python twins regardless of the order
//! the map is constructed in.

use crate::cbor::{encode_canonical_cbor, CborValue};
use crate::hex::decode as hex_to_bytes;

use super::constants::{METADATA_LABEL_309, VDS_RFC9162_SHA256};
use super::types::{CertificateAnchor, CertificateMerkle, InclusionCertificateItem, DIGEST_LENGTH};

/// The verify primitive's safe `tree_size` domain, mirrored here so the COSE
/// encoder refuses a proof it could not also re-verify.
const MAX_TREE_SIZE: u64 = 0xffff_ffff;

/// An item could not be encoded as a COSE / IETF inclusion proof.
///
/// The COSE artifact must never be produced for anything but a valid proof, so
/// every refusal — a miss, an unverified item, an out-of-range index, or a
/// leaf/root/sibling that is not exactly 32 bytes — surfaces as this error
/// rather than a malformed proof.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoseInclusionProofError {
    /// The item carries a build-time error (e.g. a "leaf not found" miss).
    #[error("refusing to encode an item with error '{0}'")]
    ItemError(String),

    /// The item's stored `verified` flag is not `true`.
    #[error("refusing to encode an unverified item")]
    Unverified,

    /// The item's index is negative or beyond the tree's leaf range.
    #[error("index {index} out of range for tree_size {tree_size}")]
    IndexOutOfRange {
        /// The item's claimed index.
        index: i64,
        /// The tree size the index is checked against.
        tree_size: usize,
    },

    /// `merkle.tree_size` is outside the safe `[1, 2^32 - 1]` fold domain.
    #[error("tree_size {0} out of range [1, {MAX_TREE_SIZE}]")]
    TreeSizeOutOfRange(usize),

    /// A hex field (`leaf` or a `proof[]` sibling) did not decode to 32 bytes.
    #[error("{field} must be {DIGEST_LENGTH} bytes, got {got}")]
    BadDigestLength {
        /// Which field failed (`"leaf"`, `"proof[i]"`).
        field: String,
        /// The byte length actually decoded.
        got: usize,
    },

    /// A hex field could not be decoded at all.
    #[error("malformed {field}: {detail}")]
    MalformedHex {
        /// Which field failed.
        field: String,
        /// The hex-decode error detail.
        detail: String,
    },
}

/// A proven item's path components, decoded to raw bytes ready for CBOR.
struct ProvenPath {
    siblings: Vec<Vec<u8>>,
    tree_size: usize,
    index: usize,
}

/// Decode + validate a proven inclusion item's path into raw bytes for CBOR.
///
/// Refuses anything that is not a proven inclusion: a miss (`item.error` set),
/// an unverified item, an out-of-range index, or any sibling that is not exactly
/// 32 bytes. (`leaf` is decoded separately by the COSE map builder so the leaf
/// is validated on every encode path, including the bare IETF helper, which
/// folds through here.)
fn decode_proven_path(
    item: &InclusionCertificateItem,
    merkle: &CertificateMerkle,
) -> Result<ProvenPath, CoseInclusionProofError> {
    if let Some(error) = &item.error {
        return Err(CoseInclusionProofError::ItemError(error.clone()));
    }
    if !item.verified {
        return Err(CoseInclusionProofError::Unverified);
    }
    if merkle.tree_size < 1 || merkle.tree_size as u64 > MAX_TREE_SIZE {
        return Err(CoseInclusionProofError::TreeSizeOutOfRange(
            merkle.tree_size,
        ));
    }
    if item.index < 0 || item.index as u64 >= merkle.tree_size as u64 {
        return Err(CoseInclusionProofError::IndexOutOfRange {
            index: item.index,
            tree_size: merkle.tree_size,
        });
    }
    // Decode the leaf too, so the bare IETF helper (which only needs the path)
    // still rejects a non-32-byte leaf, matching the canonical TypeScript twin.
    decode32(&item.leaf, "leaf")?;

    let mut siblings = Vec::with_capacity(item.proof.len());
    for (i, sibling_hex) in item.proof.iter().enumerate() {
        siblings.push(decode32(sibling_hex, &format!("proof[{i}]"))?);
    }
    Ok(ProvenPath {
        siblings,
        tree_size: merkle.tree_size,
        index: item.index as usize,
    })
}

/// Decode a hex string and assert it is exactly 32 bytes.
fn decode32(hex: &str, field: &str) -> Result<Vec<u8>, CoseInclusionProofError> {
    let bytes = hex_to_bytes(hex).map_err(|err| CoseInclusionProofError::MalformedHex {
        field: field.to_string(),
        detail: err.to_string(),
    })?;
    if bytes.len() != DIGEST_LENGTH {
        return Err(CoseInclusionProofError::BadDigestLength {
            field: field.to_string(),
            got: bytes.len(),
        });
    }
    Ok(bytes)
}

/// The canonical-CBOR bytes of the bare `[tree_size, leaf_index, [siblings]]`
/// array — the *contents* the IETF `bstr .cbor` wraps.
fn encode_inclusion_path_array(
    item: &InclusionCertificateItem,
    merkle: &CertificateMerkle,
) -> Result<Vec<u8>, CoseInclusionProofError> {
    let proven = decode_proven_path(item, merkle)?;
    let array = CborValue::Array(vec![
        CborValue::Unsigned(proven.tree_size as u64),
        CborValue::Unsigned(proven.index as u64),
        CborValue::Array(proven.siblings.into_iter().map(CborValue::Bytes).collect()),
    ]);
    Ok(encode_canonical_cbor(&array)
        .expect("canonical CBOR of an inclusion-path array never fails"))
}

/// Encode the bare IETF `inclusion-proof` value for one item.
///
/// The result is a CBOR byte string whose contents are the canonical CBOR of
/// `[tree_size, leaf_index, [ ...siblings ]]` (the `bstr .cbor [...]` form).
/// This is exactly the value a pure COSE / RFC 9162 verifier consumes — decode
/// it as a byte string, then decode those bytes as the array. Refuses
/// non-inclusion items.
///
/// # Errors
///
/// Returns [`CoseInclusionProofError`] if `item` is not a proven inclusion.
pub fn encode_ietf_inclusion_proof(
    item: &InclusionCertificateItem,
    merkle: &CertificateMerkle,
) -> Result<Vec<u8>, CoseInclusionProofError> {
    let array_bytes = encode_inclusion_path_array(item, merkle)?;
    // Wrap the array bytes as a CBOR byte string (the `bstr .cbor` envelope).
    Ok(encode_canonical_cbor(&CborValue::Bytes(array_bytes))
        .expect("canonical CBOR of a byte string never fails"))
}

/// Encode the full `cw-inclusion-proof` CBOR map for one item.
///
/// The map carries the IETF inclusion-proof bstr plus the root, the blockchain
/// anchor, the committed leaf, and the optional leaf algorithm. Canonical CBOR;
/// the parity twins reproduce the bytes exactly. Refuses non-inclusion items.
///
/// # Errors
///
/// Returns [`CoseInclusionProofError`] if `item` is not a proven inclusion.
pub fn encode_cose_inclusion_proof(
    item: &InclusionCertificateItem,
    merkle: &CertificateMerkle,
    anchor: &CertificateAnchor,
) -> Result<Vec<u8>, CoseInclusionProofError> {
    // The map stores the *array bytes* as a byte string; the encoder renders
    // that as a bstr, so `inclusion_proof` is byte-identical to
    // `encode_ietf_inclusion_proof`'s inner array bytes.
    let inclusion_path_array = encode_inclusion_path_array(item, merkle)?;
    let leaf = decode32(&item.leaf, "leaf")?;

    let tx_hash =
        hex_to_bytes(&anchor.tx_hash).map_err(|err| CoseInclusionProofError::MalformedHex {
            field: "anchor.tx_hash".to_string(),
            detail: err.to_string(),
        })?;

    let anchor_map = CborValue::Map(vec![
        (CborValue::text("chain"), CborValue::text(&anchor.chain)),
        (CborValue::text("network"), CborValue::text(&anchor.network)),
        (CborValue::text("tx_hash"), CborValue::Bytes(tx_hash)),
        (
            CborValue::text("metadata_label"),
            CborValue::Unsigned(METADATA_LABEL_309),
        ),
    ]);

    let mut pairs = vec![
        (
            CborValue::text("vds"),
            CborValue::Unsigned(VDS_RFC9162_SHA256),
        ),
        (
            CborValue::text("inclusion_proof"),
            CborValue::Bytes(inclusion_path_array),
        ),
        (
            CborValue::text("root"),
            CborValue::Bytes(merkle.root.to_vec()),
        ),
        (CborValue::text("anchor"), anchor_map),
        (CborValue::text("leaf"), CborValue::Bytes(leaf)),
    ];
    if let Some(leaf_alg) = &item.leaf_alg {
        pairs.push((CborValue::text("leaf_alg"), CborValue::text(leaf_alg)));
    }

    Ok(encode_canonical_cbor(&CborValue::Map(pairs))
        .expect("canonical CBOR of the cw-inclusion-proof map never fails"))
}
