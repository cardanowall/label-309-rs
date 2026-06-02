//! The public verifier primitive for fetching an item's ciphertext.
//!
//! Given a record item's (or Merkle entry's) chunked `uris[]` list, this
//! reconstructs the first in-set URI, dispatches it to the matching gateway chain
//! (`ar://` → Arweave HTTPS rotation, `ipfs://` → caller-supplied IPFS rotation),
//! and returns the raw bytes of the first 200 response. Each attempt appends one
//! [`UriCheck`] to the caller's sink; a fully exhausted chain raises
//! [`FetchItemError::ContentUnavailable`], and a URI naming no in-set scheme
//! raises [`FetchItemError::UriTargetForbidden`].
//!
//! The decrypt and Merkle subsystems use their own inline acquisition (which
//! records `URI_FETCH_FAILED` *warnings* instead of `uri_checks`); this primitive
//! is the standalone public surface a recipient verifier calls directly.

use crate::verifier::egress::GatewayFetcher;
use crate::verifier::fetch::{FetchOutboundOptions, HttpMethod, HttpPurpose};
use crate::verifier::types::{UriCheck, UriFailureReason};

/// The default Arweave gateway rotation, tried in order.
const ARWEAVE_DEFAULTS: [&str; 3] = [
    "https://arweave.net",
    "https://ar-io.net",
    "https://g8way.io",
];

/// A terminal failure fetching an item's ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchItemError {
    /// No reconstructed URI named an in-set retrieval scheme (`ar://`/`ipfs://`).
    #[error("URI_TARGET_FORBIDDEN: no in-set URI scheme in uris[]")]
    UriTargetForbidden,
    /// An in-set URI was selected but no gateway returned its bytes.
    #[error("CONTENT_UNAVAILABLE: {0}")]
    ContentUnavailable(String),
}

/// Fetch an item's ciphertext from the first in-set URI in `uris`.
///
/// `uris` is the chunked URI list (each entry reconstructs to one absolute URI).
/// Each gateway attempt appends one [`UriCheck`] to `uri_checks_out`: a failed
/// attempt records `ok: false` with a reason, the winning attempt records
/// `ok: true`.
///
/// # Errors
///
/// Returns [`FetchItemError::UriTargetForbidden`] when no URI names an in-set
/// scheme, or [`FetchItemError::ContentUnavailable`] on a malformed Arweave txid,
/// an exhausted gateway chain, or an unconfigured IPFS gateway chain.
pub fn fetch_item_ciphertext(
    uris: &[Vec<String>],
    fetcher: &mut GatewayFetcher<'_>,
    uri_checks_out: &mut Vec<UriCheck>,
    item_index: i64,
    arweave_gateways: Option<&[String]>,
    ipfs_gateways: Option<&[String]>,
) -> Result<Vec<u8>, FetchItemError> {
    let reconstructed: Vec<String> = uris.iter().map(|chunks| chunks.concat()).collect();
    let candidate = reconstructed
        .iter()
        .find(|u| u.starts_with("ar://") || u.starts_with("ipfs://"));
    let Some(candidate) = candidate.cloned() else {
        for u in &reconstructed {
            uri_checks_out.push(UriCheck {
                item_index,
                uri: u.clone(),
                ok: false,
                reason: Some(UriFailureReason::UriTargetForbidden),
            });
        }
        return Err(FetchItemError::UriTargetForbidden);
    };

    if let Some(txid) = candidate.strip_prefix("ar://") {
        if !is_arweave_txid(txid) {
            uri_checks_out.push(UriCheck {
                item_index,
                uri: candidate.clone(),
                ok: false,
                reason: Some(UriFailureReason::ContentUnavailable),
            });
            return Err(FetchItemError::ContentUnavailable(format!(
                "malformed arweave txid: {txid}"
            )));
        }
        let default_gateways: Vec<String> =
            ARWEAVE_DEFAULTS.iter().map(|s| (*s).to_string()).collect();
        let gateways = match arweave_gateways {
            Some(g) if !g.is_empty() => g,
            _ => &default_gateways,
        };
        for gw in gateways {
            let opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Arweave);
            match fetcher.fetch(&format!("{gw}/{txid}"), &opts) {
                Ok(res) if res.status == 200 => {
                    uri_checks_out.push(UriCheck {
                        item_index,
                        uri: candidate.clone(),
                        ok: true,
                        reason: None,
                    });
                    return Ok(res.bytes);
                }
                Ok(_) | Err(_) => uri_checks_out.push(UriCheck {
                    item_index,
                    uri: candidate.clone(),
                    ok: false,
                    reason: Some(UriFailureReason::UriFetchFailed),
                }),
            }
        }
        return Err(FetchItemError::ContentUnavailable(
            "all arweave gateways exhausted".to_string(),
        ));
    }

    // ipfs:// — the caller MUST configure an IPFS gateway chain.
    let cid_part = candidate.trim_start_matches("ipfs://");
    let ipfs_cid = cid_part
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(cid_part);
    let gateways = match ipfs_gateways {
        Some(g) if !g.is_empty() => g,
        _ => {
            uri_checks_out.push(UriCheck {
                item_index,
                uri: candidate.clone(),
                ok: false,
                reason: Some(UriFailureReason::ContentUnavailable),
            });
            return Err(FetchItemError::ContentUnavailable(
                "no ipfs gateway configured".to_string(),
            ));
        }
    };
    for gw in gateways {
        let sep = if gw.ends_with('/') { "" } else { "/" };
        let url = format!("{gw}{sep}ipfs/{ipfs_cid}");
        let opts = FetchOutboundOptions::new(HttpMethod::Get, HttpPurpose::Ipfs);
        match fetcher.fetch(&url, &opts) {
            Ok(res) if res.status == 200 => {
                uri_checks_out.push(UriCheck {
                    item_index,
                    uri: candidate.clone(),
                    ok: true,
                    reason: None,
                });
                return Ok(res.bytes);
            }
            Ok(_) | Err(_) => uri_checks_out.push(UriCheck {
                item_index,
                uri: candidate.clone(),
                ok: false,
                reason: Some(UriFailureReason::UriFetchFailed),
            }),
        }
    }
    Err(FetchItemError::ContentUnavailable(
        "all ipfs gateways exhausted".to_string(),
    ))
}

fn is_arweave_txid(txid: &str) -> bool {
    txid.len() == 43
        && txid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
