//! The verify pipeline's shared outbound egress.
//!
//! [`GatewayFetcher`] is the single thing the resolver, the decryptor, and the
//! Merkle subsystem reach for when they need bytes from a Cardano, Arweave, or
//! IPFS gateway. It owns the audit trail every call appends to (which becomes
//! `VerifyReport.http_calls`) and applies the deny-host policy, the protocol /
//! method allowlist, and the body cap through the canonical
//! [`wrap_fetch_outbound`] primitive.
//!
//! Determinism: the retry clock and jitter are injected so a test transport
//! reproduces the golden `duration_ms` and audit shape exactly. The default
//! production path uses the real reqwest transport.

#[cfg(feature = "client")]
use crate::verifier::fetch::ReqwestTransport;
use crate::verifier::fetch::{
    wrap_fetch_outbound, Clock, FetchOutboundOptions, FetchOutboundResult, FetchTransport,
    HttpCallRecord, Jitter, OutboundError, RetryConfig, WrapFetchOutboundConfig,
};

/// A no-op clock used when retries are disabled (the verifier default), so the
/// egress never touches the system timer.
struct NoSleepClock;

impl Clock for NoSleepClock {
    fn sleep(&self, _duration: std::time::Duration) {}
}

/// A fixed jitter that always returns `1.0`; unused while retries are disabled.
struct UnitJitter;

impl Jitter for UnitJitter {
    fn multiplier(&self, _attempt_index: usize) -> f64 {
        1.0
    }
}

/// The verify pipeline's shared outbound fetcher.
///
/// Holds a borrowed [`FetchTransport`], the deny-host configuration, and a
/// mutable audit trail. Every [`fetch`](Self::fetch) call records one
/// [`HttpCallRecord`] on the audit and returns the bounded result (or a typed
/// [`OutboundError`]). The verifier owns one of these per `verify_tx` call and
/// hands `&mut` references down into resolve / decrypt / merkle.
pub struct GatewayFetcher<'a> {
    transport: &'a dyn FetchTransport,
    config: WrapFetchOutboundConfig,
    audit: Vec<HttpCallRecord>,
    clock: NoSleepClock,
    jitter: UnitJitter,
}

impl<'a> GatewayFetcher<'a> {
    /// Build a fetcher over `transport` with the given deny-host patterns.
    ///
    /// Retries are disabled (single attempt), matching the verifier default in
    /// the TypeScript and Python twins, so the injected no-op clock is never
    /// engaged.
    #[must_use]
    pub fn new(transport: &'a dyn FetchTransport, deny_hosts: Option<&[String]>) -> Self {
        Self {
            transport,
            config: WrapFetchOutboundConfig {
                deny_hosts: deny_hosts.map(<[String]>::to_vec).unwrap_or_default(),
                retry: RetryConfig {
                    retries: 0,
                    ..RetryConfig::default()
                },
            },
            audit: Vec::new(),
            clock: NoSleepClock,
            jitter: UnitJitter,
        }
    }

    /// Perform one outbound fetch, recording it on the audit trail.
    ///
    /// # Errors
    ///
    /// Returns the typed [`OutboundError`] for a deny-host short circuit, a
    /// protocol/method rejection, an over-cap body, or a transport failure.
    pub fn fetch(
        &mut self,
        url: &str,
        opts: &FetchOutboundOptions,
    ) -> Result<FetchOutboundResult, OutboundError> {
        wrap_fetch_outbound(
            self.transport,
            &mut self.audit,
            &self.config,
            &self.clock,
            &self.jitter,
            url,
            opts,
        )
    }

    /// Consume the fetcher and return the accumulated audit trail.
    #[must_use]
    pub fn into_audit(self) -> Vec<HttpCallRecord> {
        self.audit
    }

    /// Borrow the current audit trail (e.g. to snapshot it on an early return).
    #[must_use]
    pub fn audit(&self) -> &[HttpCallRecord] {
        &self.audit
    }
}

/// Build the default production reqwest transport.
///
/// Callers that want the default must hold the returned [`ReqwestTransport`]
/// alive for the fetcher's lifetime and pass it to [`GatewayFetcher::new`]. This
/// helper documents the production wiring; tests inject their own transport via
/// [`GatewayFetcher::new`]. Available only with the `client` feature; without it,
/// a caller supplies its own [`FetchTransport`].
#[cfg(feature = "client")]
#[must_use]
pub fn default_transport() -> ReqwestTransport {
    ReqwestTransport::new()
}
