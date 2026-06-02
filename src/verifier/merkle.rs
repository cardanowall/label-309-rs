//! Merkle list-commitment verification.
//!
//! For each `record.merkle[i]` the verifier acquires the leaves-list document
//! (caller-supplied bytes first, then the first in-set `merkle[i].uris[]` over the
//! gateway chain), decodes it, re-folds the canonical RFC 9162 root, and compares
//! it constant-time to the on-record root. A root mismatch / leaf-count mismatch /
//! unsupported format is error-severity; an unfetchable leaves blob is
//! warning-severity (the on-chain root alone remains structurally valid).

use subtle::ConstantTimeEq;

use crate::merkle::{
    decode_leaves_list, merkle_root, MerkleLeavesListErrorCode, LEAVES_LIST_FORMAT_V1,
};
use crate::poe_standard::{ErrorCode, MerkleCommit, PoeRecord};

use crate::verifier::egress::GatewayFetcher;
use crate::verifier::fetch::{FetchOutboundOptions, HttpMethod, HttpPurpose};
use crate::verifier::types::{
    MerkleCheck, MerkleCheckReason, PathSegment, VerifierIssue, VerifyTxInput,
};

/// The single registered Merkle tree algorithm in v1.
const MERKLE_TREE_ALG_RFC9162: &str = "rfc9162-sha256";

/// The default Arweave gateway rotation, tried in order.
const ARWEAVE_DEFAULTS: [&str; 3] = [
    "https://arweave.net",
    "https://ar-io.net",
    "https://g8way.io",
];

/// The digest length of a Merkle leaf / root.
const DIGEST_LENGTH: usize = 32;

/// Walk `record.merkle[]`, re-fold each commitment, and return the per-commit
/// outcomes plus any `URI_FETCH_FAILED` / `MERKLE_LEAVES_INFORMATIVE_FORM`
/// warnings to merge into the report.
#[must_use]
pub fn check_merkle_commitments(
    record: &PoeRecord,
    input: &VerifyTxInput<'_>,
    fetcher: &mut GatewayFetcher<'_>,
) -> (Vec<MerkleCheck>, Vec<VerifierIssue>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    let empty = Vec::new();
    let merkle_arr = record.merkle.as_ref().unwrap_or(&empty);

    for (i, commit) in merkle_arr.iter().enumerate() {
        out.push(check_one(i, commit, input, fetcher, &mut warnings));
    }

    (out, warnings)
}

fn check_one(
    index: usize,
    commit: &MerkleCommit,
    input: &VerifyTxInput<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    warnings: &mut Vec<VerifierIssue>,
) -> MerkleCheck {
    if commit.alg != MERKLE_TREE_ALG_RFC9162 {
        return MerkleCheck {
            merkle_index: index,
            alg: commit.alg.clone(),
            root_ok: None,
            reason: Some(MerkleCheckReason::MerkleUnsupported),
        };
    }

    // Leaves acquisition: caller-supplied bytes first, then `merkle[i].uris[]`.
    let leaves_bytes = if let Some(bytes) = input.merkle_leaves.as_ref().and_then(|m| m.get(&index))
    {
        bytes.clone()
    } else {
        let uris = commit.uris.as_deref().unwrap_or(&[]);
        if uris.is_empty() {
            return unavailable(index, commit);
        }
        match fetch_leaves(uris, input, fetcher, warnings, index) {
            Ok(bytes) => bytes,
            Err(()) => return unavailable(index, commit),
        }
    };

    // Decode the leaves list. CBOR is the normative wire form; on a malformed
    // CBOR decode we try the informative JSON projection.
    let (leaves, file_leaf_count, alg_id) = match decode_leaves_list(&leaves_bytes) {
        Ok(decoded) => (decoded.leaves, decoded.leaf_count, decoded.tree_alg),
        Err(e) if e.code() == MerkleLeavesListErrorCode::FormatUnsupported => {
            return MerkleCheck {
                merkle_index: index,
                alg: commit.alg.clone(),
                root_ok: None,
                reason: Some(MerkleCheckReason::SchemaMerkleLeavesFormatUnsupported),
            };
        }
        Err(_) => match decode_leaves_json(&leaves_bytes) {
            Some(json) => {
                if json.format != LEAVES_LIST_FORMAT_V1 {
                    return MerkleCheck {
                        merkle_index: index,
                        alg: commit.alg.clone(),
                        root_ok: None,
                        reason: Some(MerkleCheckReason::SchemaMerkleLeavesFormatUnsupported),
                    };
                }
                warnings.push(VerifierIssue::new(
                    ErrorCode::MerkleLeavesInformativeForm,
                    vec![PathSegment::Key("merkle".to_string()), PathSegment::Index(index)],
                    "fetched leaves-list returned JSON; CBOR is the normative wire form for the leaves list",
                ));
                (json.leaves, json.leaf_count, json.tree_alg)
            }
            None => return unavailable(index, commit),
        },
    };

    if alg_id != MERKLE_TREE_ALG_RFC9162 {
        return MerkleCheck {
            merkle_index: index,
            alg: commit.alg.clone(),
            root_ok: None,
            reason: Some(MerkleCheckReason::SchemaMerkleLeavesFormatUnsupported),
        };
    }

    let commit_leaf_count = usize::try_from(commit.leaf_count).unwrap_or(usize::MAX);
    if commit_leaf_count != file_leaf_count {
        return MerkleCheck {
            merkle_index: index,
            alg: commit.alg.clone(),
            root_ok: None,
            reason: Some(MerkleCheckReason::SchemaMerkleLeafCountMismatch),
        };
    }

    // Defence-in-depth: re-fold the root and pin the on-chain commitment to it.
    let Ok(recomputed) = merkle_root(&leaves) else {
        return unavailable(index, commit);
    };
    let ok = recomputed
        .as_slice()
        .ct_eq(commit.root.as_slice())
        .unwrap_u8()
        == 1;
    MerkleCheck {
        merkle_index: index,
        alg: commit.alg.clone(),
        root_ok: Some(ok),
        reason: if ok {
            None
        } else {
            Some(MerkleCheckReason::MerkleRootMismatch)
        },
    }
}

fn unavailable(index: usize, commit: &MerkleCommit) -> MerkleCheck {
    MerkleCheck {
        merkle_index: index,
        alg: commit.alg.clone(),
        root_ok: None,
        reason: Some(MerkleCheckReason::MerkleLeavesUnavailable),
    }
}

/// Fetch a leaves-list blob from the first in-set `merkle[i].uris[]` over the
/// Arweave gateway chain. Per-attempt failures are warnings; chain exhaustion,
/// a malformed Arweave txid, an out-of-set scheme, and an unconfigured IPFS chain
/// all return `Err(())` (which the caller maps to `MERKLE_LEAVES_UNAVAILABLE`).
fn fetch_leaves(
    uris: &[Vec<String>],
    input: &VerifyTxInput<'_>,
    fetcher: &mut GatewayFetcher<'_>,
    warnings: &mut Vec<VerifierIssue>,
    index: usize,
) -> Result<Vec<u8>, ()> {
    let selected = uris
        .iter()
        .map(|chunks| chunks.concat())
        .find(|u| u.starts_with("ar://") || u.starts_with("ipfs://"));
    let Some(selected) = selected else {
        return Err(());
    };

    if let Some(txid) = selected.strip_prefix("ar://") {
        if !is_arweave_txid(txid) {
            return Err(());
        }
        let default_gateways: Vec<String> =
            ARWEAVE_DEFAULTS.iter().map(|s| (*s).to_string()).collect();
        let gateways = match &input.arweave_gateway_chain {
            Some(g) if !g.is_empty() => g.as_slice(),
            _ => &default_gateways,
        };
        for gw in gateways {
            let opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Arweave);
            match fetcher.fetch(&format!("{gw}/{txid}"), &opts) {
                Ok(res) if res.status == 200 => return Ok(res.bytes),
                Ok(res) => warnings.push(merkle_warning(
                    index,
                    format!("gateway {gw} returned status {} for {selected}", res.status),
                )),
                Err(e) => warnings.push(merkle_warning(
                    index,
                    format!("gateway {gw} failed for {selected}: {e}"),
                )),
            }
        }
        return Err(());
    }

    // ipfs:// — v1 ships no default gateway chain.
    Err(())
}

fn merkle_warning(index: usize, message: String) -> VerifierIssue {
    VerifierIssue::new(
        ErrorCode::UriFetchFailed,
        vec![
            PathSegment::Key("merkle".to_string()),
            PathSegment::Index(index),
        ],
        message,
    )
}

fn is_arweave_txid(txid: &str) -> bool {
    txid.len() == 43
        && txid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The informative JSON projection of a leaves list (a fallback when CBOR
/// decode fails).
struct LeavesJson {
    format: String,
    tree_alg: String,
    leaves: Vec<[u8; DIGEST_LENGTH]>,
    leaf_count: usize,
}

/// Parse the informative JSON projection of the leaves list.
///
/// Returns `None` on any parse failure, a non-object root, a non-32-byte hex
/// leaf, or a missing `format`/`leaves` field, so the caller records
/// `MERKLE_LEAVES_UNAVAILABLE`.
fn decode_leaves_json(blob: &[u8]) -> Option<LeavesJson> {
    let value: serde_json::Value = serde_json::from_slice(blob).ok()?;
    let obj = value.as_object()?;
    let format = obj.get("format")?.as_str()?.to_string();
    let leaves_raw = obj.get("leaves")?.as_array()?;
    let mut leaves = Vec::with_capacity(leaves_raw.len());
    for leaf in leaves_raw {
        let hex = leaf.as_str()?;
        let bytes = crate::hex::decode(hex).ok()?;
        let arr: [u8; DIGEST_LENGTH] = bytes.as_slice().try_into().ok()?;
        leaves.push(arr);
    }
    let leaf_count = obj
        .get("leaf_count")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(leaves.len());
    let tree_alg = obj
        .get("tree_alg")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| MERKLE_TREE_ALG_RFC9162.to_string(), str::to_string);
    Some(LeavesJson {
        format,
        tree_alg,
        leaves,
        leaf_count,
    })
}
