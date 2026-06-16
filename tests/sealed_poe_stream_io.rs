//! Byte-parity tests for the streaming sealed-PoE seal / unwrap
//! (`ecies_sealed_poe_seal_stream` / `ecies_sealed_poe_unwrap_stream`).
//!
//! The streaming path MUST produce byte-identical ciphertext to the buffered
//! `ecies_sealed_poe_wrap_*` path for the same CEK / nonce, and recover the same
//! plaintext on unwrap. Two oracles pin this with ZERO new crypto vectors:
//!
//! 1. The shared cross-SDK `wrap-*` vectors: stream-sealing a vector's plaintext
//!    (fed in odd-sized reads) must equal its `expected_ciphertext_hex`, and
//!    stream-unwrapping that ciphertext must recover `expected_plaintext_hex`.
//! 2. The buffered `ecies_sealed_poe_wrap_with_rng`: across the chunk-boundary
//!    size matrix the streamed ciphertext must equal the buffered ciphertext for
//!    the same deterministic inputs (this is what exercises the R1 EOF-lookahead:
//!    a full-size final chunk, an exact multiple of 64 KiB with no trailing empty
//!    chunk, and the empty-final case — none of which a source read boundary can
//!    be relied on to expose).

mod common;

use std::collections::BTreeMap;
use std::io::Read;

use cardanowall::hex;
use cardanowall::sealed_poe::{
    ecies_sealed_poe_seal_stream_with_rng, ecies_sealed_poe_unwrap_stream,
    ecies_sealed_poe_wrap_with_rng, x25519_public_key, SealedKem, StreamSealArgs, StreamUnwrapArgs,
    StreamUnwrapOutcome, UnwrapFailureReason, UnwrapKeys, WrapArgs, CHUNK_SIZE,
};
use common::{crypto_core_fixtures, read_fixture_json};
use serde_json::Value;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn fixture(name: &str) -> Value {
    read_fixture_json(&crypto_core_fixtures().join("sealed-poe").join(name))
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("field `{key}` must be a string: {v}"))
}

fn b(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(v, key)).unwrap_or_else(|e| panic!("bad hex in `{key}`: {e}"))
}

fn hex_list(v: &Value, key: &str) -> Vec<Vec<u8>> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("field `{key}` must be an array: {v}"))
        .iter()
        .map(|e| hex::decode(e.as_str().expect("hex string")).expect("valid hex"))
        .collect()
}

fn hashes_from(v: &Value) -> BTreeMap<String, Vec<u8>> {
    v["hashes"]
        .as_object()
        .unwrap_or_else(|| panic!("field `hashes` must be an object: {v}"))
        .iter()
        .map(|(alg, digest)| {
            (
                alg.clone(),
                hex::decode(digest.as_str().expect("hex digest")).expect("valid hex"),
            )
        })
        .collect()
}

/// A `Read` that hands back at most `chunk` bytes per call, so the streaming
/// re-chunker is driven across source-read boundaries that do not line up with
/// the 64 KiB STREAM grid. A `chunk` of 0 is treated as 1 (a reader must make
/// progress).
struct OddReader<'a> {
    data: &'a [u8],
    pos: usize,
    chunk: usize,
}

impl<'a> OddReader<'a> {
    fn new(data: &'a [u8], chunk: usize) -> Self {
        Self {
            data,
            pos: 0,
            chunk: chunk.max(1),
        }
    }
}

impl Read for OddReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.data.len() - self.pos;
        let n = remaining.min(self.chunk).min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// A panicking RNG: the deterministic paths supply every secret and disable the
/// shuffle, so randomness must never be drawn. A draw means a determinism bug.
fn no_rng(_buf: &mut [u8]) {
    panic!("a deterministic streaming seal must not draw randomness");
}

/// Stream-seal `plaintext` to the vector's recipients/CEK/nonce, feeding the
/// reader in `read_chunk`-sized reads. Returns the sealed STREAM bytes.
#[allow(clippy::too_many_arguments)]
fn stream_seal_det(
    plaintext: &[u8],
    recipients: &[Vec<u8>],
    hashes: &BTreeMap<String, Vec<u8>>,
    kem: Option<SealedKem>,
    cek: &[u8],
    nonce: &[u8],
    ephemeral_secrets: Option<&[Vec<u8>]>,
    eseeds: Option<&[Vec<u8>]>,
    read_chunk: usize,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let reader = OddReader::new(plaintext, read_chunk);
    let mut rng = no_rng;
    ecies_sealed_poe_seal_stream_with_rng(
        StreamSealArgs {
            plaintext: reader,
            ciphertext_out: &mut out,
            recipient_public_keys: recipients,
            hashes,
            kem,
            cek: Some(cek),
            nonce: Some(nonce),
            ephemeral_secrets,
            eseeds,
            skip_shuffle: true,
            cancel: None,
        },
        &mut rng,
    )
    .expect("streaming seal");
    out
}

// --------------------------------------------------------------------------
// Oracle 1: the shared cross-SDK wrap-* vectors (zero new vectors)
// --------------------------------------------------------------------------

/// Drive the streaming seal + unwrap over one `wrap-*` vector at several odd
/// producer read sizes; the streamed ciphertext must equal the pinned
/// `expected_ciphertext_hex` and the unwrap must recover `expected_plaintext_hex`.
fn assert_wrap_vector_streams(name: &str, kem: Option<SealedKem>, x25519_secret_keys: bool) {
    let v = &fixture(name)["vector"];
    let recipients = hex_list(v, "recipient_publics_hex");
    let hashes = hashes_from(v);
    let cek = b(v, "cek_hex");
    let nonce = b(v, "nonce_hex");
    let plaintext = b(v, "plaintext_hex");
    let expected_ct = s(v, "expected_ciphertext_hex");

    let ephemeral_secrets = v
        .get("ephemeral_secrets_hex")
        .map(|_| hex_list(v, "ephemeral_secrets_hex"));
    let eseeds = v.get("eseeds_hex").map(|_| hex_list(v, "eseeds_hex"));

    // Several odd read sizes plus a one-shot read: every one must produce the
    // exact pinned ciphertext, proving the re-chunker is independent of source
    // read granularity.
    for read_chunk in [1usize, 7, 31, plaintext.len().max(1)] {
        let sealed = stream_seal_det(
            &plaintext,
            &recipients,
            &hashes,
            kem,
            &cek,
            &nonce,
            ephemeral_secrets.as_deref(),
            eseeds.as_deref(),
            read_chunk,
        );
        assert_eq!(
            hex::encode(&sealed),
            expected_ct,
            "{name}: streamed ciphertext at read_chunk={read_chunk} must equal the vector"
        );
    }

    // Rebuild the envelope the buffered way (byte-identical to the streaming
    // envelope) and stream-unwrap the pinned ciphertext under the recipient's
    // secret. The vector's recipient secret is an X25519 scalar (classical,
    // `recipient_secrets_hex`) or an X-Wing seed (hybrid, `recipient_seeds_hex`);
    // both are the `Single` unwrap key.
    let sealed_ct = hex::decode(expected_ct).expect("hex");
    let secrets_field = if x25519_secret_keys {
        "recipient_secrets_hex"
    } else {
        "recipient_seeds_hex"
    };
    let secret = hex_list(v, secrets_field)
        .into_iter()
        .next()
        .expect("at least one recipient secret");

    let envelope = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &plaintext,
            recipient_public_keys: &recipients,
            hashes: &hashes,
            kem,
            cek: Some(&cek),
            nonce: Some(&nonce),
            ephemeral_secrets: ephemeral_secrets.as_deref(),
            eseeds: eseeds.as_deref(),
            skip_shuffle: true,
        },
        &mut no_rng,
    )
    .expect("buffered wrap for the envelope")
    .envelope;

    for read_chunk in [1usize, 7, 65_537, sealed_ct.len().max(1)] {
        let mut recovered: Vec<u8> = Vec::new();
        let reader = OddReader::new(&sealed_ct, read_chunk);
        let outcome = ecies_sealed_poe_unwrap_stream(StreamUnwrapArgs {
            envelope: &envelope,
            ciphertext: reader,
            plaintext_out: &mut recovered,
            hashes: &hashes,
            keys: UnwrapKeys::Single(&secret),
            cancel: None,
        })
        .expect("streaming unwrap");
        assert_eq!(outcome, StreamUnwrapOutcome::Matched, "{name}: matched");
        assert_eq!(
            hex::encode(&recovered),
            s(v, "expected_plaintext_hex"),
            "{name}: streamed plaintext at read_chunk={read_chunk} must equal the vector"
        );
    }
}

#[test]
fn wrap_x25519_vectors_seal_and_unwrap_byte_identically_when_streamed() {
    // n3 (32-byte plaintext, 3 recipients) and n1-empty (the empty-plaintext
    // single-zero-length-final-chunk form) — the byte-parity anchors.
    assert_wrap_vector_streams("wrap-n3.json", None, true);
    assert_wrap_vector_streams("wrap-n1-empty.json", None, true);
    assert_wrap_vector_streams("wrap-n32.json", None, true);
}

#[test]
fn wrap_hybrid_vectors_seal_and_unwrap_byte_identically_when_streamed() {
    assert_wrap_vector_streams(
        "wrap-hybrid-n1.json",
        Some(SealedKem::Mlkem768X25519),
        false,
    );
    assert_wrap_vector_streams(
        "wrap-hybrid-n3.json",
        Some(SealedKem::Mlkem768X25519),
        false,
    );
}

// --------------------------------------------------------------------------
// Oracle 2: chunk-boundary size matrix vs the buffered wrap (R1 lookahead)
// --------------------------------------------------------------------------

/// The deterministic classical inputs for the size-matrix equivalence: one
/// recipient, a fixed CEK / nonce / ephemeral so the buffered and streamed wraps
/// are directly comparable.
struct MatrixInputs {
    recipients: Vec<Vec<u8>>,
    cek: Vec<u8>,
    nonce: Vec<u8>,
    ephemeral: Vec<u8>,
    hashes: BTreeMap<String, Vec<u8>>,
}

fn size_matrix_inputs() -> MatrixInputs {
    let recipient = x25519_public_key(&[0x09u8; 32]).unwrap().to_vec();
    let mut hashes = BTreeMap::new();
    hashes.insert("sha2-256".to_string(), vec![0x11u8; 32]);
    MatrixInputs {
        recipients: vec![recipient],
        cek: vec![0x5au8; 32],
        nonce: vec![0x42u8; 24],
        ephemeral: vec![0x07u8; 32],
        hashes,
    }
}

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn streamed_ciphertext_equals_buffered_across_the_chunk_boundary_matrix() {
    // The R1 cases: empty, one byte, exactly one full chunk (final chunk is
    // full-size), exactly two full chunks (exact multiple — no trailing empty
    // chunk), one below / one above a chunk, and a multi-chunk interior length.
    let MatrixInputs {
        recipients,
        cek,
        nonce,
        ephemeral,
        hashes,
    } = size_matrix_inputs();
    let eph_list = vec![ephemeral];

    let sizes = [
        0usize,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        2 * CHUNK_SIZE,
        2 * CHUNK_SIZE + 4242,
    ];
    // Producer read granularities that deliberately cut across the 64 KiB grid:
    // tiny, just-below, just-above, and exact-grid reads.
    let read_chunks = [1usize, 65_535, 65_537, CHUNK_SIZE, 2 * CHUNK_SIZE];

    for &size in &sizes {
        let plaintext = patterned(size);

        // The buffered oracle: a vector-pinned, deterministic wrap.
        let buffered = ecies_sealed_poe_wrap_with_rng(
            WrapArgs {
                plaintext: &plaintext,
                recipient_public_keys: &recipients,
                hashes: &hashes,
                kem: None,
                cek: Some(&cek),
                nonce: Some(&nonce),
                ephemeral_secrets: Some(&eph_list),
                eseeds: None,
                skip_shuffle: true,
            },
            &mut no_rng,
        )
        .expect("buffered wrap");

        for &read_chunk in &read_chunks {
            let streamed = stream_seal_det(
                &plaintext,
                &recipients,
                &hashes,
                None,
                &cek,
                &nonce,
                Some(&eph_list),
                None,
                read_chunk,
            );
            assert_eq!(
                streamed, buffered.ciphertext,
                "size={size} read_chunk={read_chunk}: streamed ciphertext must equal buffered"
            );
        }

        // And it must round-trip through the streaming unwrap back to the
        // plaintext, at odd read granularities on the ciphertext too.
        for &read_chunk in &read_chunks {
            let mut recovered: Vec<u8> = Vec::new();
            let reader = OddReader::new(&buffered.ciphertext, read_chunk);
            let outcome = ecies_sealed_poe_unwrap_stream(StreamUnwrapArgs {
                envelope: &buffered.envelope,
                ciphertext: reader,
                plaintext_out: &mut recovered,
                hashes: &hashes,
                keys: UnwrapKeys::Single(&[0x09u8; 32]),
                cancel: None,
            })
            .expect("streaming unwrap");
            assert_eq!(
                outcome,
                StreamUnwrapOutcome::Matched,
                "size={size}: matched"
            );
            assert_eq!(
                recovered, plaintext,
                "size={size} read_chunk={read_chunk}: streamed unwrap must recover the plaintext"
            );
        }
    }
}

// --------------------------------------------------------------------------
// Tamper + wrong-key outcomes
// --------------------------------------------------------------------------

#[test]
fn a_flipped_ciphertext_byte_streams_to_tampered_ciphertext() {
    let MatrixInputs {
        recipients,
        cek,
        nonce,
        ephemeral,
        hashes,
    } = size_matrix_inputs();
    let eph_list = vec![ephemeral];
    let plaintext = patterned(CHUNK_SIZE + 33);

    let built = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &plaintext,
            recipient_public_keys: &recipients,
            hashes: &hashes,
            kem: None,
            cek: Some(&cek),
            nonce: Some(&nonce),
            ephemeral_secrets: Some(&eph_list),
            eseeds: None,
            skip_shuffle: true,
        },
        &mut no_rng,
    )
    .expect("buffered wrap");

    // Flip a byte in the final chunk's tag: the header still trial-decrypts (the
    // CEK is intact), but the content STREAM open fails its tag mid-stream.
    let mut tampered = built.ciphertext.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let mut recovered: Vec<u8> = Vec::new();
    let reader = OddReader::new(&tampered, 65_537);
    let outcome = ecies_sealed_poe_unwrap_stream(StreamUnwrapArgs {
        envelope: &built.envelope,
        ciphertext: reader,
        plaintext_out: &mut recovered,
        hashes: &hashes,
        keys: UnwrapKeys::Single(&[0x09u8; 32]),
        cancel: None,
    })
    .expect("streaming unwrap is a structured outcome, never an error");
    assert_eq!(
        outcome,
        StreamUnwrapOutcome::NotMatched {
            reason: UnwrapFailureReason::TamperedCiphertext
        },
        "a flipped tag byte must be TamperedCiphertext"
    );
}

#[test]
fn a_truncated_final_chunk_streams_to_tampered_ciphertext() {
    // Drop the last byte of the (full-size) final chunk: the tail no longer
    // verifies, so the streaming open rejects it as tampered rather than matching.
    let MatrixInputs {
        recipients,
        cek,
        nonce,
        ephemeral,
        hashes,
    } = size_matrix_inputs();
    let eph_list = vec![ephemeral];
    let plaintext = patterned(2 * CHUNK_SIZE);

    let built = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &plaintext,
            recipient_public_keys: &recipients,
            hashes: &hashes,
            kem: None,
            cek: Some(&cek),
            nonce: Some(&nonce),
            ephemeral_secrets: Some(&eph_list),
            eseeds: None,
            skip_shuffle: true,
        },
        &mut no_rng,
    )
    .expect("buffered wrap");

    let truncated = &built.ciphertext[..built.ciphertext.len() - 1];
    let mut recovered: Vec<u8> = Vec::new();
    let reader = OddReader::new(truncated, 4242);
    let outcome = ecies_sealed_poe_unwrap_stream(StreamUnwrapArgs {
        envelope: &built.envelope,
        ciphertext: reader,
        plaintext_out: &mut recovered,
        hashes: &hashes,
        keys: UnwrapKeys::Single(&[0x09u8; 32]),
        cancel: None,
    })
    .expect("structured outcome");
    assert_eq!(
        outcome,
        StreamUnwrapOutcome::NotMatched {
            reason: UnwrapFailureReason::TamperedCiphertext
        },
        "a truncated final chunk must be TamperedCiphertext"
    );
}

#[test]
fn a_wrong_recipient_key_streams_to_wrong_recipient_key_with_nothing_written() {
    let MatrixInputs {
        recipients,
        cek,
        nonce,
        ephemeral,
        hashes,
    } = size_matrix_inputs();
    let eph_list = vec![ephemeral];
    let plaintext = patterned(100);

    let built = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &plaintext,
            recipient_public_keys: &recipients,
            hashes: &hashes,
            kem: None,
            cek: Some(&cek),
            nonce: Some(&nonce),
            ephemeral_secrets: Some(&eph_list),
            eseeds: None,
            skip_shuffle: true,
        },
        &mut no_rng,
    )
    .expect("buffered wrap");

    // A different secret key is not addressed by the envelope: the header trial
    // decrypt finds no slot, so nothing is written and the outcome is the
    // wrong-key non-match.
    let wrong_secret = [0xAAu8; 32];
    let mut recovered: Vec<u8> = Vec::new();
    let outcome = ecies_sealed_poe_unwrap_stream(StreamUnwrapArgs {
        envelope: &built.envelope,
        ciphertext: OddReader::new(&built.ciphertext, 17),
        plaintext_out: &mut recovered,
        hashes: &hashes,
        keys: UnwrapKeys::Single(&wrong_secret),
        cancel: None,
    })
    .expect("structured outcome");
    assert_eq!(
        outcome,
        StreamUnwrapOutcome::NotMatched {
            reason: UnwrapFailureReason::WrongRecipientKey
        }
    );
    assert!(
        recovered.is_empty(),
        "a wrong-key non-match must write no plaintext"
    );
}

// --------------------------------------------------------------------------
// Cancellation
// --------------------------------------------------------------------------

#[test]
fn seal_cancellation_returns_cancelled() {
    let MatrixInputs {
        recipients,
        cek,
        nonce,
        ephemeral,
        hashes,
    } = size_matrix_inputs();
    let eph_list = vec![ephemeral];
    let plaintext = patterned(2 * CHUNK_SIZE);

    let mut out: Vec<u8> = Vec::new();
    let cancel = || true;
    let mut rng = no_rng;
    let err = ecies_sealed_poe_seal_stream_with_rng(
        StreamSealArgs {
            plaintext: OddReader::new(&plaintext, CHUNK_SIZE),
            ciphertext_out: &mut out,
            recipient_public_keys: &recipients,
            hashes: &hashes,
            kem: None,
            cek: Some(&cek),
            nonce: Some(&nonce),
            ephemeral_secrets: Some(&eph_list),
            eseeds: None,
            skip_shuffle: true,
            cancel: Some(&cancel),
        },
        &mut rng,
    )
    .expect_err("a cancel-true predicate must abort the seal");
    assert_eq!(err.code(), "CANCELLED");
}

#[test]
fn unwrap_cancellation_returns_cancelled() {
    let MatrixInputs {
        recipients,
        cek,
        nonce,
        ephemeral,
        hashes,
    } = size_matrix_inputs();
    let eph_list = vec![ephemeral];
    let plaintext = patterned(2 * CHUNK_SIZE);

    let built = ecies_sealed_poe_wrap_with_rng(
        WrapArgs {
            plaintext: &plaintext,
            recipient_public_keys: &recipients,
            hashes: &hashes,
            kem: None,
            cek: Some(&cek),
            nonce: Some(&nonce),
            ephemeral_secrets: Some(&eph_list),
            eseeds: None,
            skip_shuffle: true,
        },
        &mut no_rng,
    )
    .expect("buffered wrap");

    let mut recovered: Vec<u8> = Vec::new();
    let cancel = || true;
    let err = ecies_sealed_poe_unwrap_stream(StreamUnwrapArgs {
        envelope: &built.envelope,
        ciphertext: OddReader::new(&built.ciphertext, CHUNK_SIZE + 16),
        plaintext_out: &mut recovered,
        hashes: &hashes,
        keys: UnwrapKeys::Single(&[0x09u8; 32]),
        cancel: Some(&cancel),
    })
    .expect_err("a cancel-true predicate must abort the unwrap");
    assert_eq!(err.code(), "CANCELLED");
}
