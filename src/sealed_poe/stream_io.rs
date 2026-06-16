//! Streaming sealed-PoE seal and unwrap over [`Read`]/[`Write`].
//!
//! These are bounded-memory wrappers around the public
//! [`StreamSealer`](super::stream::StreamSealer) /
//! [`StreamOpener`](super::stream::StreamOpener) chunk machines and the buffered
//! wrap/unwrap envelope logic. They exist so a host (the desktop, a CLI) can seal
//! or open a multi-GiB sealed PoE without ever holding the whole plaintext or the
//! whole ciphertext in memory — peak memory is one 64 KiB plaintext chunk plus
//! one 64 KiB + 16 sealed chunk.
//!
//! The output is **byte-identical** to the buffered
//! [`ecies_sealed_poe_wrap_secure`](super::wrap::ecies_sealed_poe_wrap_secure)
//! for the same CEK / nonce, because the envelope (slots + `slots_mac`) and the
//! content `payload_key` are a pure function of the CEK, nonce, recipients, and
//! the item's `hashes` — not of the plaintext — so they are resolved up front,
//! then the body is driven through the exact same chunk machine the buffered
//! `stream_seal` uses.
//!
//! ## Source read boundaries are not STREAM chunk boundaries
//!
//! A [`Read`] (or any producer) may hand back any number of bytes per call, with
//! no relation to the 64 KiB STREAM chunk grid. The STREAM final flag lives in
//! the per-chunk nonce, and a final chunk may itself be **full size**
//! (`stream_seal` makes the last 64 KiB the final chunk with NO trailing empty
//! chunk; an exact multiple of 64 KiB therefore has no empty final chunk). So
//! both directions re-chunk with a one-chunk lookahead:
//!
//! - **Seal** accumulates input into an exactly-64 KiB buffer and keeps one full
//!   chunk *pending*, only sealing it with `last = true` once the next read
//!   returns EOF. An empty plaintext is the sole empty-final case: one
//!   `seal_chunk(&[], true)`.
//! - **Unwrap** reads the ciphertext in [`SEALED_CHUNK_SIZE`] units and keeps one
//!   sealed chunk *pending*, opening it as `last = true` on EOF even when it is
//!   exactly [`SEALED_CHUNK_SIZE`]. A trailing sealed length of `1..=TAG_SIZE-1`
//!   cannot form a final chunk and is rejected.
//!
//! ## Released plaintext is TENTATIVE
//!
//! Per-chunk Poly1305 plus the final-flag give per-segment integrity and
//! truncation resistance, but they do NOT establish that the recovered plaintext
//! matches the record's content-hash claim. The whole-item hash recompute is the
//! caller's release gate and is **not** performed here (it is per-item,
//! caller-owned). [`ecies_sealed_poe_unwrap_stream`] therefore returns a
//! [`StreamUnwrapOutcome`] the caller MUST inspect, and the bytes written to
//! `plaintext_out` are tentative until that caller-side recompute passes. A host
//! writes them to an encrypted quarantine, never to a final destination, until
//! the hash matches.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use zeroize::Zeroize;

use super::errors::{EciesSealedPoeError, EciesSealedPoeErrorCode};
use super::slots::SealedEnvelope;
use super::stream::{StreamOpener, StreamSealer, CHUNK_SIZE, SEALED_CHUNK_SIZE, TAG_SIZE};
use super::transcript::slots_payload_key;
use super::unwrap::{
    ecies_sealed_poe_trial_decrypt, TrialDecryptKeys, TrialDecryptResult, UnwrapFailureReason,
    UnwrapKeys,
};
use super::wrap::{wrap_envelope_with_rng, RandomSource, SealedKem, WrapArgs};

/// Inputs to the streaming sealed-PoE seal
/// ([`ecies_sealed_poe_seal_stream`]).
///
/// The plaintext is consumed from `plaintext` and the sealed STREAM is written
/// to `ciphertext_out`, one 64 KiB chunk at a time; neither is ever fully
/// buffered. `recipient_public_keys`, `hashes`, and `kem` carry the same meaning
/// as on [`WrapArgs`]. `cek`, `nonce`, `ephemeral_secrets`, `eseeds`, and
/// `skip_shuffle` are the deterministic overrides used to reproduce
/// known-answer vectors; production callers leave them `None` / `false` so the
/// OS CSPRNG draws fresh material.
pub struct StreamSealArgs<'a, R: Read, W: Write> {
    /// The plaintext source, streamed and never fully buffered.
    pub plaintext: R,
    /// The sink the sealed STREAM is written to, 64 KiB (+16) at a time.
    pub ciphertext_out: W,
    /// One recipient public key per slot (32 B for x25519, 1216 B for X-Wing).
    pub recipient_public_keys: &'a [Vec<u8>],
    /// The item's content-hash map, bound into the slots transcript.
    pub hashes: &'a BTreeMap<String, Vec<u8>>,
    /// The KEM branch. Defaults to [`SealedKem::X25519`] when `None`.
    pub kem: Option<SealedKem>,
    /// Deterministic 32-byte CEK override (vectors only).
    pub cek: Option<&'a [u8]>,
    /// Deterministic 24-byte nonce override (vectors only).
    pub nonce: Option<&'a [u8]>,
    /// Deterministic X25519 ephemeral scalars (classical branch only).
    pub ephemeral_secrets: Option<&'a [Vec<u8>]>,
    /// Deterministic X-Wing encapsulation seeds (hybrid branch only).
    pub eseeds: Option<&'a [Vec<u8>]>,
    /// When `true`, skip the anonymity shuffle so slot order is deterministic.
    pub skip_shuffle: bool,
    /// Cooperative cancellation: checked once per chunk before it is sealed. When
    /// it returns `true` the seal stops and returns
    /// [`EciesSealedPoeErrorCode::Cancelled`].
    pub cancel: Option<&'a dyn Fn() -> bool>,
}

impl<'a, R: Read, W: Write> StreamSealArgs<'a, R, W> {
    /// Construct seal args with the required fields, every override defaulted.
    pub fn new(
        plaintext: R,
        ciphertext_out: W,
        recipient_public_keys: &'a [Vec<u8>],
        hashes: &'a BTreeMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            plaintext,
            ciphertext_out,
            recipient_public_keys,
            hashes,
            kem: None,
            cek: None,
            nonce: None,
            ephemeral_secrets: None,
            eseeds: None,
            skip_shuffle: false,
            cancel: None,
        }
    }
}

/// Seal a plaintext stream to one or more recipients, drawing every secret from
/// the operating-system CSPRNG (unless an override is supplied). **This is the
/// primary streaming wrap API.**
///
/// The sealed envelope is built first (it does not depend on the plaintext) and
/// returned after the body has been streamed to `args.ciphertext_out`. The bytes
/// written equal [`ecies_sealed_poe_wrap_secure`](super::wrap::ecies_sealed_poe_wrap_secure)'s
/// ciphertext for the same CEK / nonce.
///
/// # Errors
///
/// Returns an [`EciesSealedPoeError`] for the same wrap-input failures as
/// [`ecies_sealed_poe_wrap_with_rng`](super::wrap::ecies_sealed_poe_wrap_with_rng)
/// (empty recipient list, wrong-length key, wrong-length / wrong-count override),
/// [`EciesSealedPoeErrorCode::RngUnavailable`] if the OS CSPRNG cannot be read,
/// [`EciesSealedPoeErrorCode::IoError`] if a read or write fails, or
/// [`EciesSealedPoeErrorCode::Cancelled`] if `cancel` returns `true`.
pub fn ecies_sealed_poe_seal_stream<R: Read, W: Write>(
    args: StreamSealArgs<'_, R, W>,
) -> Result<SealedEnvelope, EciesSealedPoeError> {
    // Mirror the secure-by-default wrap: an OS-RNG read failure is surfaced as a
    // typed error rather than silently emitting a zeroed (globally known) CEK.
    let mut rng_error: Option<EciesSealedPoeError> = None;
    let mut fill = |buf: &mut [u8]| {
        if rng_error.is_some() {
            return;
        }
        if let Err(e) = getrandom::fill(buf) {
            rng_error = Some(EciesSealedPoeError::new(
                EciesSealedPoeErrorCode::RngUnavailable,
                format!("operating-system CSPRNG is unavailable: {e}"),
            ));
        }
    };
    let result = ecies_sealed_poe_seal_stream_with_rng(args, &mut fill);
    if let Some(e) = rng_error {
        return Err(e);
    }
    result
}

/// The deterministic / injected-entropy variant of
/// [`ecies_sealed_poe_seal_stream`], kept for known-answer-test and HSM flows.
///
/// `rng` carries the whole confidentiality guarantee and MUST be a CSPRNG unless
/// every secret is supplied via the [`StreamSealArgs`] overrides with
/// `skip_shuffle` set, in which case it is never consulted. See
/// [`RandomSource`](super::wrap::RandomSource).
///
/// # Errors
///
/// As [`ecies_sealed_poe_seal_stream`], minus `RngUnavailable` (this variant does
/// not read the OS CSPRNG itself).
pub fn ecies_sealed_poe_seal_stream_with_rng<R: Read, W: Write>(
    mut args: StreamSealArgs<'_, R, W>,
    rng: RandomSource<'_>,
) -> Result<SealedEnvelope, EciesSealedPoeError> {
    // The envelope + content key are a pure function of CEK / nonce / recipients
    // / hashes — never the plaintext — so they are resolved up front through the
    // exact same validated path the buffered wrap uses. This is what makes the
    // streamed ciphertext byte-identical to the buffered one.
    let wrap_args = WrapArgs {
        plaintext: &[],
        recipient_public_keys: args.recipient_public_keys,
        hashes: args.hashes,
        kem: args.kem,
        cek: args.cek,
        nonce: args.nonce,
        ephemeral_secrets: args.ephemeral_secrets,
        eseeds: args.eseeds,
        skip_shuffle: args.skip_shuffle,
    };
    let built = wrap_envelope_with_rng(&wrap_args, rng)?;
    let mut payload_key = built.payload_key;

    let seal_result = drive_seal(
        &mut args.plaintext,
        &mut args.ciphertext_out,
        &payload_key,
        args.cancel,
    );
    payload_key.zeroize();
    seal_result?;
    Ok(built.envelope)
}

/// Drive the [`StreamSealer`] over `reader`, re-chunked to exactly
/// [`CHUNK_SIZE`] with a one-chunk EOF lookahead, writing each sealed chunk to
/// `writer`.
///
/// One full chunk is held *pending* so the final chunk is sealed with
/// `last = true` only once the next read confirms EOF — a full-size final chunk
/// is valid and an exact multiple of [`CHUNK_SIZE`] has no trailing empty chunk.
/// An empty plaintext seals as exactly one zero-length final chunk.
fn drive_seal<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    payload_key: &[u8],
    cancel: Option<&dyn Fn() -> bool>,
) -> Result<(), EciesSealedPoeError> {
    let mut sealer = StreamSealer::new(payload_key);

    // The single pending full chunk: `Some` once a 64 KiB chunk has been filled
    // but not yet sealed, because we do not yet know whether it is the last.
    let mut pending: Option<Vec<u8>> = None;

    loop {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let filled = read_full_chunk(reader, &mut chunk)?;

        if filled == CHUNK_SIZE {
            // A full chunk. If one is already pending it is definitely not the
            // last (this one follows it), so flush it as non-final first.
            if let Some(prev) = pending.take() {
                check_cancel(cancel)?;
                write_all(writer, &sealer.seal_chunk(&prev, false))?;
            }
            pending = Some(chunk);
            continue;
        }

        // The end of the stream. Two shapes:
        if filled == 0 {
            // No remainder after the last full chunk. The pending full chunk —
            // if any — IS the final chunk (a full-size final chunk is valid and
            // an exact multiple of CHUNK_SIZE has NO trailing empty chunk). With
            // no pending chunk at all this is the empty plaintext: one zero-length
            // final chunk.
            check_cancel(cancel)?;
            let final_chunk = pending.take().unwrap_or_default();
            write_all(writer, &sealer.seal_chunk(&final_chunk, true))?;
            return Ok(());
        }

        // A non-empty short remainder is the final chunk. Flush any pending full
        // chunk as non-final first, then seal the remainder as the final chunk.
        chunk.truncate(filled);
        if let Some(prev) = pending.take() {
            check_cancel(cancel)?;
            write_all(writer, &sealer.seal_chunk(&prev, false))?;
        }
        check_cancel(cancel)?;
        write_all(writer, &sealer.seal_chunk(&chunk, true))?;
        chunk.zeroize();
        return Ok(());
    }
}

/// The outcome of [`ecies_sealed_poe_unwrap_stream`].
///
/// `Matched` means a slot's CEK reproduced `slots_mac` AND every content chunk
/// opened: the plaintext written to `plaintext_out` is complete and
/// integrity-checked per chunk — but still **tentative** until the caller's
/// whole-item hash recompute passes. `NotMatched` carries the reason and means
/// the caller must discard whatever was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamUnwrapOutcome {
    /// A CEK was accepted and the whole content STREAM opened. The bytes written
    /// to `plaintext_out` are tentative until the caller re-hashes them.
    Matched,
    /// No plaintext was recovered; `reason` says why. Anything written to
    /// `plaintext_out` is partial and MUST be discarded.
    NotMatched {
        /// Why the unwrap did not recover the plaintext.
        reason: UnwrapFailureReason,
    },
}

/// Inputs to the streaming sealed-PoE unwrap
/// ([`ecies_sealed_poe_unwrap_stream`]).
///
/// The ciphertext is consumed from `ciphertext` and the recovered plaintext is
/// written to `plaintext_out` chunk by chunk; neither is fully buffered. `keys`
/// selects the recipient key(s) exactly as the buffered
/// [`ecies_sealed_poe_unwrap`](super::unwrap::ecies_sealed_poe_unwrap) does
/// (single / multi / bundle).
pub struct StreamUnwrapArgs<'a, R: Read, W: Write> {
    /// The sealed envelope (the on-chain header material).
    pub envelope: &'a SealedEnvelope,
    /// The sealed STREAM ciphertext source, streamed and never fully buffered.
    pub ciphertext: R,
    /// The sink each verified-per-chunk plaintext chunk is written to. The bytes
    /// are TENTATIVE until the caller's whole-item hash recompute passes.
    pub plaintext_out: W,
    /// The item's content-hash map, bound into the slots transcript.
    pub hashes: &'a BTreeMap<String, Vec<u8>>,
    /// The recipient key selection (single / multi / bundle).
    pub keys: UnwrapKeys<'a>,
    /// Cooperative cancellation: checked once per chunk before it is opened. When
    /// it returns `true` the unwrap stops and returns
    /// [`EciesSealedPoeErrorCode::Cancelled`].
    pub cancel: Option<&'a dyn Fn() -> bool>,
}

/// Recover a plaintext stream from a sealed envelope and its content ciphertext.
///
/// The header is trial-decrypted first (no content I/O); on a slot match the
/// content `payload_key` is derived and the [`StreamOpener`] is driven over the
/// ciphertext re-chunked to [`SEALED_CHUNK_SIZE`] with a one-chunk EOF lookahead.
/// Each opened chunk is written to `args.plaintext_out` immediately.
///
/// Returns a [`StreamUnwrapOutcome`] the caller MUST inspect:
///
/// - `NotMatched { WrongRecipientKey }` / `{ TamperedHeader }` — the trial
///   decrypt failed; nothing is written.
/// - `NotMatched { TamperedCiphertext }` — a content chunk failed its tag or the
///   chunk layout was malformed mid-stream; the partial bytes already written
///   MUST be discarded (a host quarantines, never finalises).
/// - `Matched` — every chunk opened; the written plaintext is complete but
///   tentative until the caller re-hashes it.
///
/// # Errors
///
/// Returns an [`EciesSealedPoeError`] only for malformed input (the same
/// structural / partitioning-oracle pre-checks as the buffered unwrap), an I/O
/// failure ([`EciesSealedPoeErrorCode::IoError`]), or cancellation
/// ([`EciesSealedPoeErrorCode::Cancelled`]). A wrong key / tampered header /
/// tampered ciphertext are structured `NotMatched` outcomes, never errors.
pub fn ecies_sealed_poe_unwrap_stream<R: Read, W: Write>(
    mut args: StreamUnwrapArgs<'_, R, W>,
) -> Result<StreamUnwrapOutcome, EciesSealedPoeError> {
    // The trial-decrypt is header-only and runs the identical structural
    // pre-checks, per-slot acceptance fold, and constant-time-across-slots
    // invariant as the buffered unwrap. Resolve the caller's key form to the
    // trial-decrypt key form (single collapses to a one-element multi list).
    let single_vec;
    let trial_keys = match &args.keys {
        UnwrapKeys::Single(k) => {
            single_vec = vec![k.to_vec()];
            TrialDecryptKeys::Multi(&single_vec)
        }
        UnwrapKeys::Multi(list) => TrialDecryptKeys::Multi(list),
        UnwrapKeys::Bundle(bundle) => TrialDecryptKeys::Bundle(bundle),
    };

    let mut cek =
        match ecies_sealed_poe_trial_decrypt(args.envelope, args.hashes, trial_keys, None)? {
            TrialDecryptResult::Match { cek, .. } => cek,
            // The trial-decrypt's NoMatch collapses every non-acceptance to one
            // shape. A header that wrap-opens but fails the MAC fold is not
            // distinguished from a wrong key here — both are a clean non-match on the
            // recipient-blind streaming path, surfaced as WrongRecipientKey.
            TrialDecryptResult::NoMatch => {
                return Ok(StreamUnwrapOutcome::NotMatched {
                    reason: UnwrapFailureReason::WrongRecipientKey,
                });
            }
        };

    let mut payload_key = slots_payload_key(&cek, &args.envelope.nonce);
    cek.zeroize();

    let outcome = drive_open(
        &mut args.ciphertext,
        &mut args.plaintext_out,
        &payload_key,
        args.cancel,
    );
    payload_key.zeroize();
    outcome
}

/// Drive the [`StreamOpener`] over `reader`, re-chunked to exactly
/// [`SEALED_CHUNK_SIZE`] with a one-chunk EOF lookahead, writing each opened
/// chunk to `writer`.
///
/// One sealed chunk is held *pending* so the final chunk is opened with
/// `last = true` only once the next read confirms EOF — even when the final
/// sealed chunk is exactly [`SEALED_CHUNK_SIZE`]. A mid-stream tag failure or a
/// malformed layout (a non-final chunk that is not full, or a trailing sealed
/// length of `1..=TAG_SIZE-1`) yields `NotMatched { TamperedCiphertext }`.
fn drive_open<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    payload_key: &[u8],
    cancel: Option<&dyn Fn() -> bool>,
) -> Result<StreamUnwrapOutcome, EciesSealedPoeError> {
    let mut opener = StreamOpener::new(payload_key);

    // The single pending sealed chunk: `Some` once a SEALED_CHUNK_SIZE chunk has
    // been read but not yet opened, because we do not yet know if it is the last.
    let mut pending: Option<Vec<u8>> = None;

    loop {
        let mut sealed = vec![0u8; SEALED_CHUNK_SIZE];
        let filled = read_full_chunk(reader, &mut sealed)?;

        if filled == SEALED_CHUNK_SIZE {
            // A full sealed chunk. A pending one before it cannot be the last, so
            // open it as non-final first.
            if let Some(prev) = pending.take() {
                check_cancel(cancel)?;
                match open_chunk(&mut opener, writer, &prev, false)? {
                    OpenStep::Ok => {}
                    OpenStep::Tampered => return Ok(tampered()),
                }
            }
            pending = Some(sealed);
            continue;
        }

        // The tail. A trailing length of 1..=TAG_SIZE-1 cannot form a final
        // chunk; reject as tampered (mirrors `stream_open`).
        sealed.truncate(filled);
        let final_chunk = match (pending.take(), filled) {
            // No bytes at all after the last full chunk (or no chunks at all):
            // the pending full chunk, if any, IS the final chunk.
            (Some(prev), 0) => prev,
            (None, 0) => {
                // Empty ciphertext: not even one tag. A sealed STREAM is always at
                // least a 16-byte final tag, so this is malformed.
                return Ok(tampered());
            }
            (prev, _len) => {
                // A non-empty tail follows. Flush a pending full chunk as
                // non-final, then this tail is the final chunk.
                if let Some(prev) = prev {
                    check_cancel(cancel)?;
                    match open_chunk(&mut opener, writer, &prev, false)? {
                        OpenStep::Ok => {}
                        OpenStep::Tampered => return Ok(tampered()),
                    }
                }
                if filled < TAG_SIZE {
                    // A tail too short to carry a tag is malformed ciphertext.
                    return Ok(tampered());
                }
                sealed
            }
        };

        check_cancel(cancel)?;
        match open_chunk(&mut opener, writer, &final_chunk, true)? {
            OpenStep::Ok => return Ok(StreamUnwrapOutcome::Matched),
            OpenStep::Tampered => return Ok(tampered()),
        }
    }
}

/// The disposition of one [`StreamOpener::open_chunk`] call: the chunk opened and
/// was written, or it failed its tag / layout and the stream is tampered.
enum OpenStep {
    Ok,
    Tampered,
}

/// Open one sealed chunk and write its plaintext, mapping a [`StreamError`] to
/// [`OpenStep::Tampered`]. An I/O write failure is a hard error.
fn open_chunk<W: Write>(
    opener: &mut StreamOpener,
    writer: &mut W,
    sealed: &[u8],
    last: bool,
) -> Result<OpenStep, EciesSealedPoeError> {
    match opener.open_chunk(sealed, last) {
        Ok(mut plaintext) => {
            let write_result = write_all(writer, &plaintext);
            plaintext.zeroize();
            write_result?;
            Ok(OpenStep::Ok)
        }
        Err(_) => Ok(OpenStep::Tampered),
    }
}

/// The `NotMatched { TamperedCiphertext }` outcome.
fn tampered() -> StreamUnwrapOutcome {
    StreamUnwrapOutcome::NotMatched {
        reason: UnwrapFailureReason::TamperedCiphertext,
    }
}

/// Fill `buf` from `reader` to its full length, returning the number of bytes
/// actually read (less than `buf.len()` only at EOF).
///
/// A single [`Read::read`] may return fewer bytes than requested with more still
/// available, so this loops until the buffer is full or the reader signals EOF.
/// That is what lets a source with arbitrary read granularity be re-chunked onto
/// the fixed STREAM grid.
fn read_full_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, EciesSealedPoeError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(EciesSealedPoeError::new(
                    EciesSealedPoeErrorCode::IoError,
                    format!("reading the stream failed: {e}"),
                ));
            }
        }
    }
    Ok(filled)
}

/// Write a whole buffer, mapping an I/O failure to a typed error.
fn write_all<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), EciesSealedPoeError> {
    writer.write_all(bytes).map_err(|e| {
        EciesSealedPoeError::new(
            EciesSealedPoeErrorCode::IoError,
            format!("writing the stream failed: {e}"),
        )
    })
}

/// Return `Cancelled` when the caller's cancel closure reports `true`.
fn check_cancel(cancel: Option<&dyn Fn() -> bool>) -> Result<(), EciesSealedPoeError> {
    if let Some(cancel) = cancel {
        if cancel() {
            return Err(EciesSealedPoeError::new(
                EciesSealedPoeErrorCode::Cancelled,
                "the streaming operation was cancelled by the caller",
            ));
        }
    }
    Ok(())
}
