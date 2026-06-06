# Changelog

All notable changes to the Label 309 Rust SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall` is pre-1.0. The API, wire format, and
> conformance vectors may change in backward-incompatible ways until a 1.0
> release. Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

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
