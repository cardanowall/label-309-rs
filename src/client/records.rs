//! The `client.records.*` namespace: the open-standard indexer read surface.
//!
//! Paths below are relative to the configured `base_url`, which carries the
//! gateway's version segment (e.g. `https://host/api/vN`):
//!
//! - `GET  /records` → [`list`](RecordsNamespace::list)
//! - `GET  /records/count` → [`count`](RecordsNamespace::count)
//! - `GET  /records/{tx_hash}` → [`get`](RecordsNamespace::get)
//!
//! Auth is optional — chain data is public. When an API key is configured it is
//! forwarded as `Authorization: Bearer …` so owner-only fields (currently
//! `account_id`) surface for the caller's own rows, and so the `sealed` list
//! filter can resolve records addressed to the caller.

use crate::client::http::{decode, json_headers, send, ClientError, NamespaceConfig};
use crate::client::transport::RequestBody;
use crate::client::types::{
    RecordResource, RecordsCountInput, RecordsCountResponse, RecordsListInput, RecordsListResponse,
};
use crate::verifier::fetch::HttpMethod;

/// The `client.records.*` namespace.
pub struct RecordsNamespace<'t> {
    config: NamespaceConfig<'t>,
}

impl<'t> RecordsNamespace<'t> {
    /// Construct the namespace over a resolved config.
    #[must_use]
    pub fn new(config: NamespaceConfig<'t>) -> Self {
        Self { config }
    }

    /// List records as a paginated [`RecordsListResponse`] whose `data[]`
    /// entries are the same [`RecordResource`] projection [`get`](Self::get)
    /// returns.
    ///
    /// Pass `RecordsListInput { sealed: Some(true), .. }` to restrict the page
    /// to sealed records addressed to the authenticated caller (the gateway
    /// resolves the recipient from the bearer identity); omit it to list every
    /// record the caller may read. Page with `cursor = previous.next_cursor`
    /// until `has_more` is `false`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ClientError`] on any non-2xx response.
    pub fn list(
        &self,
        input: Option<&RecordsListInput>,
    ) -> Result<RecordsListResponse, ClientError> {
        let mut query: Vec<(String, String)> = Vec::new();
        if let Some(input) = input {
            if input.sealed == Some(true) {
                query.push(("sealed".to_string(), "true".to_string()));
            }
            if let Some(limit) = input.limit {
                query.push(("limit".to_string(), limit.to_string()));
            }
            if let Some(cursor) = &input.cursor {
                query.push(("cursor".to_string(), cursor.clone()));
            }
        }
        let url = if query.is_empty() {
            format!("{}/records", self.config.base_url)
        } else {
            format!("{}/records?{}", self.config.base_url, encode_query(&query))
        };
        let headers = json_headers(self.config.api_key.as_deref(), None);
        let response = send(
            self.config.transport,
            &url,
            HttpMethod::Get,
            &headers,
            &RequestBody::None,
        )?;
        let mut page: RecordsListResponse = decode(&response.body)?;
        if page.tip_block_height.is_none() {
            page.tip_block_height = derive_tip_block_height(&page.data);
        }
        Ok(page)
    }

    /// Count the records matching a publisher-scoped filter.
    ///
    /// The count must be scoped to a `signer` (the gateway 422s without one): a
    /// count's cost is the cardinality of the match, which only a signer key
    /// bounds. The remaining filters (`scheme`, `sealed`, the block / time
    /// windows) narrow the count but do not bound it, and share the list route's
    /// grammar.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ClientError`] on any non-2xx response — notably a 422
    /// `validation-failed` if `signer` is absent or not 64 lowercase-hex
    /// characters.
    pub fn count(&self, input: &RecordsCountInput) -> Result<RecordsCountResponse, ClientError> {
        let mut query: Vec<(String, String)> = vec![("signer".to_string(), input.signer.clone())];
        if let Some(scheme) = input.scheme {
            query.push(("scheme".to_string(), scheme.to_string()));
        }
        if input.sealed == Some(true) {
            query.push(("sealed".to_string(), "true".to_string()));
        }
        if let Some(from_block) = input.from_block {
            query.push(("from_block".to_string(), from_block.to_string()));
        }
        if let Some(to_block) = input.to_block {
            query.push(("to_block".to_string(), to_block.to_string()));
        }
        if let Some(from_time) = &input.from_time {
            query.push(("from_time".to_string(), from_time.clone()));
        }
        if let Some(to_time) = &input.to_time {
            query.push(("to_time".to_string(), to_time.clone()));
        }
        let url = format!(
            "{}/records/count?{}",
            self.config.base_url,
            encode_query(&query)
        );
        let headers = json_headers(self.config.api_key.as_deref(), None);
        let response = send(
            self.config.transport,
            &url,
            HttpMethod::Get,
            &headers,
            &RequestBody::None,
        )?;
        decode(&response.body)
    }

    /// Fetch a record by Cardano transaction hash.
    ///
    /// # Errors
    ///
    /// Returns [`HttpErrorKind::RecordNotFound`](crate::client::HttpErrorKind::RecordNotFound)
    /// for tx hashes the indexer has not seen (or un-anchored rows the caller
    /// does not own), and other typed errors on any non-2xx response.
    pub fn get(&self, tx_hash: &str) -> Result<RecordResource, ClientError> {
        let url = format!(
            "{}/records/{}",
            self.config.base_url,
            encode_path_segment(tx_hash)
        );
        // The records namespace emits `content-type: application/json` on the GET
        // (matching the reference), unlike the inbox namespace which sends only
        // accept + bearer. `json_headers` produces content-type + accept + bearer.
        let headers = json_headers(self.config.api_key.as_deref(), None);
        let response = send(
            self.config.transport,
            &url,
            HttpMethod::Get,
            &headers,
            &RequestBody::None,
        )?;
        decode(&response.body)
    }
}

/// Derive the chain tip from a record page as `max(block_height +
/// num_confirmations - 1)` over the rows that carry a block height. Returns
/// `None` for an empty page or one with no anchored rows.
///
/// Saturating arithmetic keeps a hostile gateway row (e.g.
/// `{block_height: 0, num_confirmations: 0}`) from underflowing — it clamps to
/// `0` rather than panicking in debug or wrapping to `u64::MAX` in release.
fn derive_tip_block_height(records: &[RecordResource]) -> Option<u64> {
    records
        .iter()
        .filter_map(|r| {
            r.block_height
                .map(|bh| bh.saturating_add(r.num_confirmations).saturating_sub(1))
        })
        .max()
}

/// Encode an ordered query into a `key=value&…` string, percent-encoding values
/// the way `URLSearchParams` does (space → `+`, reserved chars escaped).
fn encode_query(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                encode_query_component(k),
                encode_query_component(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encode a query component (`URLSearchParams`-style: ` ` → `+`).
fn encode_query_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b' ' => out.push('+'),
            b if b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
                ) =>
            {
                out.push(b as char);
            }
            b => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// Percent-encode a path segment the way the reference's `encodeURIComponent`
/// does for the characters that occur in a tx hash (hex). Hex digits never
/// require escaping, but a defensive encoder keeps a non-hex caller safe.
fn encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        let unreserved = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            );
        if unreserved {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}
