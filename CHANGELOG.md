# Changelog

All notable changes to the Label 309 Rust SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall` is pre-1.0. The API, wire format, and
> conformance vectors may change in backward-incompatible ways until a 1.0
> release. Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [0.8.0] - 2026-07-02

### Breaking

- `AssertWebhookUrlSafeOptions` now carries two independent loosening axes instead of one. `allow_http_scheme` permits `http://` targets and nothing else; resolved addresses are still range-checked against the blocked-IP list. `allow_private_for_tests` relaxes only the loopback/private/link-local/metadata IP blocklist; `https` is still required. Previously the single opt-in silently disabled the entire blocklist as soon as a caller needed plain HTTP. Migration: if you set the old flag to reach a local listener in tests, set `allow_private_for_tests: true`; if you set it to reach a plain-HTTP endpoint, set `allow_http_scheme: true`.

### Changed

- The `OutboundError::WebhookPurposeRejected` message now points at `assert_webhook_url_safe` plus a pinned connection instead of a `fetch_webhook` function that does not exist in this crate.

## [0.7.1] - 2026-06-18

### Fixed

- Arweave content retrieval now fetches through the `turbo-gateway.com` fast-finality gateway and follows the gateway's same-domain sandbox-subdomain redirects. The redirect follow is SSRF-safe: it only targets the same registrable domain, re-checks the deny-host list on every hop, requires `https`, and caps the chain at three hops. The dead default gateways `ar-io.net` and `g8way.io` are removed.

## [0.7.0] - 2026-06-16

### Added

- Label 309 **inclusion certificates**: build and verify a self-contained, standalone-verifiable proof that a content hash was committed as a leaf of an RFC 9162 SHA-256 Merkle tree whose root was published on Cardano under metadata label 309, plus the COSE / RFC 9162-aligned CBOR proof and the bare IETF inclusion-proof encoding — byte-identical with the TypeScript and Python SDKs.
- Streaming sealed-PoE seal/open for the segmented `chacha20-poly1305-stream64k` content layer, and a resumable upload client with progress, cancel, and abandon.

### Breaking

- Client base URLs now carry the full versioned API root (e.g. `https://gateway.example.com/api/v1`); the client appends only bare resource suffixes. Update your configuration to include the version segment.
- `records::verify` has been removed. A Label 309 verdict must never require trusting a gateway; use this crate's standalone verifier instead.

### Changed

- Dependencies modernized: `sha3` 0.11 → 0.12 (with the `shake` XOF), `getrandom` 0.2 → 0.4, and `toml` 0.8 → 1.x, plus patch bumps to `zeroize`, `uuid`, and `rust_decimal`. No API or wire-format change.

## [0.6.0] - 2026-06-13

### Fixed

- Mixed-case CIDv1 URIs are rejected. The multibase body is decoded verbatim against the case its prefix advertises (`b`/`B` base32, `f`/`F` base16) instead of being case-folded, so a non-canonical CID no longer validates — keeping the verdict in lockstep with the TypeScript and Python SDKs.

## [0.5.0] - 2026-06-12

### Breaking

- `records::verify` no longer accepts `decryption` entries. Recipient verification — decrypting sealed items and re-checking plaintext hashes — is a local operation of the verifier; the HTTP client never transmits decryption credentials to any gateway. Hosted verify endpoints act as public verifiers only.

### Fixed

- `verify_uris` was never accepted by conforming gateways; the verify request now carries the correct `fetch_content` flag.

## [0.4.0] - 2026-06-11

### Changed

- **BREAKING (wire format):** The sealed-PoE construction is finalized: nonce-salted key derivation, a content-hash-bound slot transcript, segmented STREAM content encryption (`chacha20-poly1305-stream64k`), an in-ciphertext passphrase commitment, and passphrase normalization pinned to Unicode 16.0 NFKC. Records sealed by earlier releases do not decrypt or verify under 0.4.0, and vice versa.
- **BREAKING (wire format):** Record fields are de-chunked: `kem_ct` is a single byte string, URIs are plain text strings, and COSE fields are single byte strings. The only remaining chunking is the ledger-imposed ≤64-byte segmentation of the whole record body for transport.
- **BREAKING (verifier):** The verifier returns a four-state verdict (`valid` | `pending` | `unverifiable` | `failed`) and a reworked report schema (camelCase fields, positional `items`/`merkle` results, severity-tagged issues). It enforces transaction-hash and auxiliary-data binding, never fabricates confirmation depth, never follows redirects, and treats a deny-host violation as terminal on the resolve path and per-attempt on the content path. Bytes that fail a URI's own content address are attributed to the provider as `URI_PROVIDER_INTEGRITY_MISMATCH`, distinct from a content-hash failure.
- The structural validator accepts options — supported critical extensions, verifier role, resource bounds, and a passphrase-parameter ceiling — and the error-code registry now holds 76 codes.
- Conformance vectors regenerated under the finalized wire format; transaction vectors are fully bound (transaction hash and auxiliary-data hash).

### Added

- Identity-seed string encoding: `encode_identity_seed` / `parse_identity_seed` for the checksummed `L309-SEED-1…` form (HRP `l309-seed-`, rendered uppercase), with raw-hex input accepted; pinned by a cross-SDK conformance vector.
- New conformance families: carriage, Cardano, KDF, Unicode normalization, seed encoding, and recipient-scan negatives.

## [0.3.0] - 2026-06-06

### Changed

- **BREAKING (wire format):** Implemented the finalized sealed-PoE scheme-1 construction: `slots_mac` now authenticates a header-bound slots transcript hash, content is encrypted under an HKDF-derived `payload_key` (never the CEK directly) with structured AAD on both the recipient-slots and passphrase paths, and the X-Wing per-slot KEK salt binds the reassembled `kem_ct` and the recipient public key. Envelopes sealed under 0.2.0 do not decrypt under 0.3.0.
- **BREAKING:** `slots_to_mac_cbor()` is replaced by the new `sealed_poe::transcript` module (`canonicalize_slots`, `compute_slots_hash`, `ad_content_slots`, `ad_content_passphrase`, `slots_payload_key`, `passphrase_payload_key`, `xwing_kek_salt`).
- Hardened recipient decryption: explicit all-zero X25519 shared-secret rejection folded into a constant-time `kem_ok` bit, CEK-conflict detection across matching slots, per-slot KEK-uniqueness checks, and slot-count / envelope-size bounds enforced before any cryptographic work.
- Passphrase decryption pins the `cardano-poe-pw-norm-v1` normalization profile (NFKC, Unicode 16.0 `White_Space` collapse, trim) and enforces a 4096-byte pre-KDF input cap.

### Added

- A default-on `client` cargo feature gating the HTTP transport: `--no-default-features` yields a transport-free SDK (callers supply their own fetch transport) and drops the `reqwest` dependency.
- Error codes `ENC_SLOTS_DUPLICATE_KEM_MATERIAL`, `ENC_SLOTS_TOO_MANY`, and `ENC_ENVELOPE_TOO_LARGE`, with structural-validator checks that mirror the decrypt-layer bounds.
- Conformance coverage for the finalized construction: transcript, hybrid-KEK-salt, and passphrase-path KATs plus duplicate-KEM-material negatives, byte-identical with the TypeScript and Python SDKs.

## [0.2.0] - 2026-06-04

### Changed

- **BREAKING:** Public API renamed `Cip309*` → `Label309*` (`Cip309Client` → `Label309Client`, `build_cip309_sig_structure` → `build_label309_sig_structure`, `cose_sign1_cip309_*` → `cose_sign1_label309_*`), matching the standard's rename to **Label 309**. No wire-format changes.

## [0.1.0] - 2026-06-02

### Added

- Initial public release of the Label 309 Rust SDK (crate `cardanowall`).
- Byte-parity with the TypeScript and Python SDKs against the shared conformance vectors.
