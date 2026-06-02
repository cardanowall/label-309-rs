# wallet-cose fixtures — Python mirror

**This directory is a byte-identical mirror.** Do not author fixtures here
directly.

The canonical source is the `@cardanowall/sdk-ts` wallet-cose fixture tree. The
regenerator on the TypeScript side (`_build-tampered-fixtures.test.ts`) writes
the 18 tamper variants byte-identically to both trees in one shot.

Positive fixtures are real wallet captures recorded via the TypeScript stack's
dev-only wallet-capture page; mirror them across byte-for-byte. Then verify
with the cross-language parity check.

See the `@cardanowall/sdk-ts` wallet-cose README for the full capture protocol,
JSON schema, synthetic-tamper construction rules, determinism-freeze rule, and
re-capture workflow on wallet updates.
