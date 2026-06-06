//! Sealed envelope and per-slot wire shapes, plus the two codec seams the
//! producer (wrap) and the verifier (unwrap) MUST agree on byte-for-byte:
//!
//! 1. How the 1120-byte X-Wing `enc` is split into the ≤ 64-byte byte-string
//!    chunks the Cardano ledger requires (`kem_ct`), and the inverse join.
//! 2. The canonical slot-array structure the slots transcript commits to
//!    ([`canonicalize_slots`]).
//!
//! Keeping both here means wrap, unwrap, and the downstream record encoder
//! cannot diverge on the bytes the transcript commits to — the single highest
//! correctness risk for the hybrid branch, since a divergence would leave the
//! ML-KEM ciphertext unauthenticated.

use crate::cbor::CborValue;

/// The envelope-level KEM discriminator string for the classical age-style path.
pub const KEM_X25519: &str = "x25519";

/// The envelope-level KEM discriminator string for the X-Wing hybrid path.
pub const KEM_MLKEM768X25519: &str = "mlkem768x25519";

/// The only supported content AEAD algorithm identifier.
pub const AEAD_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";

/// The Cardano ledger CDDL caps every `transaction_metadatum` byte string at 64
/// bytes, so any longer value is carried as an array of ≤ 64-byte chunks
/// (`bytes-chunk-array`). This is the identical split rule the record encoder
/// applies to chunked COSE bytes.
const CHUNK_MAX_BYTES: usize = 64;

/// A classical (`x25519`) recipient slot: an age-style ECIES stanza.
///
/// `epk` is the 32-byte ephemeral X25519 public key; `wrap` is the 48-byte
/// AEAD-wrapped CEK (32-byte CEK + 16-byte Poly1305 tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519Slot {
    /// The 32-byte ephemeral X25519 public key.
    pub epk: Vec<u8>,
    /// The 48-byte AEAD-wrapped content-encryption key.
    pub wrap: Vec<u8>,
}

/// A hybrid (`mlkem768x25519`) recipient slot.
///
/// `kem_ct` is the 1120-byte X-Wing ciphertext (`enc`) carried as an array of
/// ≤ 64-byte byte-string chunks (there is no per-slot `epk` and no per-slot
/// `kem` field — the KEM identifier is hoisted to envelope scope). `wrap` is the
/// 48-byte AEAD-wrapped CEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mlkem768X25519Slot {
    /// The X-Wing `enc` as ≤ 64-byte chunks (the on-wire chunked byte string).
    pub kem_ct: Vec<Vec<u8>>,
    /// The 48-byte AEAD-wrapped content-encryption key.
    pub wrap: Vec<u8>,
}

/// The per-KEM slot array of a sealed envelope.
///
/// A sealed envelope carries homogeneous slots — every slot uses the same KEM,
/// named by the envelope's `kem` field. This enum keeps the two concrete slot
/// shapes separate so consumers branch on the KEM once and then touch only the
/// KEM-relevant fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedSlots {
    /// Classical age-style slots (`{ epk, wrap }`).
    X25519(Vec<X25519Slot>),
    /// X-Wing hybrid slots (`{ kem_ct, wrap }`).
    Mlkem768X25519(Vec<Mlkem768X25519Slot>),
}

impl SealedSlots {
    /// The number of recipient slots.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            SealedSlots::X25519(s) => s.len(),
            SealedSlots::Mlkem768X25519(s) => s.len(),
        }
    }

    /// Whether the slot array is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An in-memory sealed envelope.
///
/// The field names mirror the on-wire `enc` map exactly: `scheme`, `aead`,
/// `kem`, `nonce`, `slots`, `slots_mac`. The algorithm-identifier fields are
/// stored raw (an `i64` scheme, owned strings for `aead` and `kem`) rather than
/// as Rust enums so that an envelope carrying an unsupported algorithm can be
/// constructed and then rejected with the correct typed error by the unwrap
/// path — the structural validation lives in one place, not in the type system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    /// The envelope scheme version. The only supported value is `1`.
    pub scheme: i64,
    /// The content AEAD algorithm identifier (`xchacha20-poly1305`).
    pub aead: String,
    /// The KEM algorithm identifier (`x25519` or `mlkem768x25519`).
    pub kem: String,
    /// The 24-byte XChaCha20-Poly1305 content nonce.
    pub nonce: Vec<u8>,
    /// The per-recipient slots.
    pub slots: SealedSlots,
    /// The 32-byte HMAC-SHA256 over the slots-transcript hash `slots_hash`,
    /// keyed by an HKDF expansion of the CEK.
    pub slots_mac: Vec<u8>,
}

/// The output of a sealed-PoE wrap: the in-memory envelope plus the content
/// ciphertext that lands off-chain (e.g. on Arweave).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPoeOutput {
    /// The sealed envelope (the on-chain header material).
    pub envelope: SealedEnvelope,
    /// The XChaCha20-Poly1305 content ciphertext (`ciphertext ‖ tag`).
    pub ciphertext: Vec<u8>,
}

/// Split a logical byte string into ≤ 64-byte chunks for the X-Wing
/// `enc` → `kem_ct` wire form.
///
/// Refuses an empty input (an empty `kem_ct` would be malformed on the wire).
/// This is the identical split rule the record encoder applies to chunked COSE
/// bytes; 1120 bytes splits as seventeen 64-byte chunks plus one 32-byte chunk
/// (18 chunks).
///
/// # Panics
///
/// Panics if `value` is empty — `chunk_kem_ct` is only ever called on the
/// 1120-byte X-Wing `enc`, so an empty input is an internal contract violation.
#[must_use]
pub fn chunk_kem_ct(value: &[u8]) -> Vec<Vec<u8>> {
    assert!(
        !value.is_empty(),
        "chunk_kem_ct: refusing to chunk an empty byte string",
    );
    value.chunks(CHUNK_MAX_BYTES).map(<[u8]>::to_vec).collect()
}

/// Concatenate a chunked `kem_ct` back into the flat X-Wing `enc`.
///
/// Performs NO length validation: the caller (unwrap) gates the reassembled
/// length against the 1120-byte X-Wing `enc` length before any decapsulation.
#[must_use]
pub fn join_kem_ct(chunks: &[Vec<u8>]) -> Vec<u8> {
    chunks.iter().flatten().copied().collect()
}

/// The canonical slot-array structure the slots transcript commits to.
///
/// - `x25519`: each slot → `{ epk: bstr, wrap: bstr }`.
/// - `mlkem768x25519`: each slot → `{ kem_ct: [ bstr, … ], wrap: bstr }`,
///   which encodes on-wire as `{ wrap, kem_ct }` (canonical key order:
///   `wrap` (4-byte key) sorts before `kem_ct` (6-byte key) per RFC 8949
///   §4.2.1).
///
/// The hybrid form re-chunks `kem_ct` into its canonical ≤ 64-byte sequence so
/// the transcript commits to the ciphertext BYTES, not the wire chunk
/// boundaries. The on-wire `kem_ct` array is a transport detail (the Cardano
/// ledger's 64-byte metadatum cap); a hostile or non-canonical chunking
/// reassembles to the SAME bytes, so the commitment must be invariant to it.
/// Committing to the verbatim wire chunks would let an attacker re-chunk an
/// honest envelope and break the slots_mac match for an honest recipient.
/// Honest (already 64-byte-chunked) records are unchanged; a real byte flip
/// still changes the reassembled bytes and is still rejected.
///
/// Returns the slot-array [`CborValue`] (NOT encoded) so the caller can embed it
/// under the `slots` key of the larger slots-transcript map before a single
/// canonical encode.
#[must_use]
pub fn canonicalize_slots(slots: &SealedSlots) -> CborValue {
    match slots {
        SealedSlots::X25519(slots) => CborValue::Array(
            slots
                .iter()
                .map(|s| {
                    CborValue::Map(vec![
                        (CborValue::text("epk"), CborValue::Bytes(s.epk.clone())),
                        (CborValue::text("wrap"), CborValue::Bytes(s.wrap.clone())),
                    ])
                })
                .collect(),
        ),
        SealedSlots::Mlkem768X25519(slots) => CborValue::Array(
            slots
                .iter()
                .map(|s| {
                    let canonical = chunk_kem_ct(&join_kem_ct(&s.kem_ct));
                    let chunks = CborValue::Array(
                        canonical
                            .iter()
                            .map(|c| CborValue::Bytes(c.clone()))
                            .collect(),
                    );
                    // Insertion order is irrelevant — the canonical encoder
                    // sorts keys, placing `wrap` before `kem_ct`.
                    CborValue::Map(vec![
                        (CborValue::text("kem_ct"), chunks),
                        (CborValue::text("wrap"), CborValue::Bytes(s.wrap.clone())),
                    ])
                })
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::encode_canonical_cbor;

    #[test]
    fn chunk_then_join_is_the_identity_for_1120_bytes() {
        let enc: Vec<u8> = (0..1120u32).map(|i| (i & 0xff) as u8).collect();
        let chunks = chunk_kem_ct(&enc);
        assert_eq!(chunks.len(), 18);
        for c in &chunks[..17] {
            assert_eq!(c.len(), 64);
        }
        assert_eq!(chunks[17].len(), 32);
        assert_eq!(join_kem_ct(&chunks), enc);
    }

    #[test]
    #[should_panic(expected = "refusing to chunk an empty byte string")]
    fn chunk_rejects_empty() {
        let _ = chunk_kem_ct(&[]);
    }

    #[test]
    fn hybrid_slot_encodes_wrap_before_kem_ct() {
        // A single hybrid slot encodes its map as {wrap, kem_ct}: the map header
        // a2, then key "wrap" (64 77 72 61 70) before key "kem_ct".
        let slots = SealedSlots::Mlkem768X25519(vec![Mlkem768X25519Slot {
            kem_ct: vec![vec![0xaa; 4]],
            wrap: vec![0xbb; 48],
        }]);
        let bytes = encode_canonical_cbor(&canonicalize_slots(&slots))
            .expect("slot byte strings never collide as duplicate map keys");
        // Outer: array(1) = 0x81, then map(2) = 0xa2, then text(4)="wrap".
        assert_eq!(bytes[0], 0x81);
        assert_eq!(bytes[1], 0xa2);
        assert_eq!(&bytes[2..7], b"\x64wrap");
    }
}
