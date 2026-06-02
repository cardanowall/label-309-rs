# Changelog

All notable changes to the CIP-309 Rust SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall` is pre-1.0. The API, wire format, and
> conformance vectors may change in backward-incompatible ways until a 1.0
> release. Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial public release of the CIP-309 Rust SDK: structural validator, public
  verifier, recipient verifier with sealed-PoE decryption, gateway-agnostic
  blocking HTTP client, seed-derived identity helpers, and the cryptographic
  building blocks (hash, KDF, COSE, sealed-PoE, Merkle, recipient encoding).
- Byte-parity with the TypeScript and Python SDKs, proven against the shared
  cross-implementation conformance vectors.
