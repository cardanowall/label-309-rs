//! The `client.account.*` namespace: the account read surface.
//!
//! The path below is relative to the configured `base_url`, which carries the
//! gateway's version segment (e.g. `https://host/api/vN`):
//!
//! - `GET /account/balance` → [`balance`](AccountNamespace::balance)
//!
//! Auth is required (Bearer with the `account:read` scope, or a session cookie
//! when the gateway is browser-fronted). The configured opaque bearer key is
//! forwarded as `Authorization: Bearer …`.
//!
//! The balance is USD micro-cents carried as a decimal string on the wire
//! (`balance_usd_micros`). It is deserialized into [`AccountBalance`] as a
//! `String` and never parsed into a numeric type, so the bigint value survives
//! without precision loss.

use crate::client::http::{decode, json_headers, send, ClientError, NamespaceConfig};
use crate::client::transport::RequestBody;
use crate::client::types::AccountBalance;
use crate::verifier::fetch::HttpMethod;

/// The `client.account.*` namespace.
pub struct AccountNamespace<'t> {
    config: NamespaceConfig<'t>,
}

impl<'t> AccountNamespace<'t> {
    /// Construct the namespace over a resolved config.
    #[must_use]
    pub fn new(config: NamespaceConfig<'t>) -> Self {
        Self { config }
    }

    /// Fetch the caller's current prepaid USD balance.
    ///
    /// Returns [`AccountBalance`], whose `balance_usd_micros` field is the USD
    /// micro-cents value as a decimal string preserved verbatim — never parsed
    /// into a numeric type, so no precision is lost. An account with no ledger
    /// activity yet reads `"0"`.
    ///
    /// # Errors
    ///
    /// Returns [`HttpErrorKind::Unauthorized`](crate::client::HttpErrorKind::Unauthorized)
    /// when the caller is anonymous and
    /// [`HttpErrorKind::InsufficientScope`](crate::client::HttpErrorKind::InsufficientScope)
    /// when the Bearer key lacks the `account:read` scope, plus other typed
    /// errors on any non-2xx response.
    pub fn balance(&self) -> Result<AccountBalance, ClientError> {
        let url = format!("{}/account/balance", self.config.base_url);
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
