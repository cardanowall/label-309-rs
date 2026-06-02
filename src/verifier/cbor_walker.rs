//! Position-aware CBOR walker for byte-faithful label-309 metadata extraction.
//!
//! The verifier MUST fetch raw transaction CBOR and locate the label-309 value
//! and the transaction body / witness-set slices VERBATIM, never via a
//! decode-then-re-encode pass. A re-encode would silently launder a
//! non-conformant on-chain record into a conformant one (the canonical decoder
//! sorts map keys, collapses indefinite-length items, …); the structural
//! validator's canonical-CBOR check only catches the violation when it sees the
//! producer's original bytes.
//!
//! Byte-faithfulness is also load-bearing for the transaction-level description:
//! `blake2b256(tx_body)` equals the on-chain transaction hash only when the body
//! bytes are exactly as produced, so each vkey witness verifies against the
//! sliced body. The walk therefore slices rather than decodes.
//!
//! Pure walker (no permissive-decoder dependency for the slicing path). It
//! rejects indefinite-length encodings, which canonical CBOR forbids; the
//! structural validator downstream performs the remaining deterministic-encoding
//! checks.

/// CBOR tag 259 wraps post-Alonzo auxiliary data (CIP-29).
const CARDANO_AUX_DATA_TAG: u64 = 259;

/// The PoE metadata label.
const POE_LABEL: i64 = 309;

/// An error peeling the transaction CBOR to its label-309 value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtractError {
    /// The transaction CBOR was malformed (not a 4-element array, truncated, …).
    #[error("MALFORMED_CBOR: {0}")]
    Malformed(String),
}

/// A decoded CBOR head: major type, additional-info bits, the byte offset where
/// the payload begins, and the head's unsigned argument value.
struct CborHead {
    mt: u8,
    ai: u8,
    payload_start: usize,
    value_u64: u64,
}

/// Read one CBOR head at `pos`, rejecting indefinite-length and reserved
/// additional-info encodings (canonical CBOR forbids both).
fn read_head(bytes: &[u8], pos: usize) -> Result<CborHead, ExtractError> {
    let head = *bytes
        .get(pos)
        .ok_or_else(|| ExtractError::Malformed("truncated input (no head byte)".to_string()))?;
    let mt = head >> 5;
    let ai = head & 0x1f;
    let mut p = pos + 1;
    let value_u64: u64;

    if ai < 24 {
        value_u64 = u64::from(ai);
    } else if ai == 24 {
        let b = *bytes
            .get(p)
            .ok_or_else(|| ExtractError::Malformed("truncated 1-byte argument".to_string()))?;
        value_u64 = u64::from(b);
        p += 1;
    } else if ai == 25 {
        let slice = bytes
            .get(p..p + 2)
            .ok_or_else(|| ExtractError::Malformed("truncated 2-byte argument".to_string()))?;
        value_u64 = u64::from(u16::from_be_bytes([slice[0], slice[1]]));
        p += 2;
    } else if ai == 26 {
        let slice = bytes
            .get(p..p + 4)
            .ok_or_else(|| ExtractError::Malformed("truncated 4-byte argument".to_string()))?;
        value_u64 = u64::from(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]));
        p += 4;
    } else if ai == 27 {
        let slice = bytes
            .get(p..p + 8)
            .ok_or_else(|| ExtractError::Malformed("truncated 8-byte argument".to_string()))?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(slice);
        value_u64 = u64::from_be_bytes(arr);
        p += 8;
    } else if ai == 31 {
        return Err(ExtractError::Malformed(
            "indefinite-length encoding (ai=31) not allowed under canonical CBOR".to_string(),
        ));
    } else {
        return Err(ExtractError::Malformed(format!(
            "reserved additional info ai={ai}"
        )));
    }

    Ok(CborHead {
        mt,
        ai,
        payload_start: p,
        value_u64,
    })
}

/// Return the byte offset immediately past the CBOR item that begins at `pos`.
fn skip_cbor_item(bytes: &[u8], pos: usize) -> Result<usize, ExtractError> {
    let h = read_head(bytes, pos)?;
    let mut p = h.payload_start;
    match h.mt {
        0 | 1 => Ok(p),
        2 | 3 => {
            let len = usize::try_from(h.value_u64)
                .map_err(|_| ExtractError::Malformed("string length out of range".to_string()))?;
            let end = p
                .checked_add(len)
                .ok_or_else(|| ExtractError::Malformed("string length overflow".to_string()))?;
            if end > bytes.len() {
                return Err(ExtractError::Malformed(format!(
                    "truncated {} string payload",
                    if h.mt == 2 { "byte" } else { "text" }
                )));
            }
            Ok(end)
        }
        4 => {
            for _ in 0..h.value_u64 {
                p = skip_cbor_item(bytes, p)?;
            }
            Ok(p)
        }
        5 => {
            for _ in 0..(h.value_u64 * 2) {
                p = skip_cbor_item(bytes, p)?;
            }
            Ok(p)
        }
        6 => skip_cbor_item(bytes, p),
        7 => {
            if h.ai < 24 {
                return Ok(p);
            }
            if h.ai == 24 {
                if p + 1 > bytes.len() {
                    return Err(ExtractError::Malformed(
                        "truncated simple value".to_string(),
                    ));
                }
                return Ok(p + 1);
            }
            if h.ai == 25 || h.ai == 26 || h.ai == 27 {
                return Ok(p);
            }
            Err(ExtractError::Malformed(format!(
                "unsupported major-7 ai={}",
                h.ai
            )))
        }
        other => Err(ExtractError::Malformed(format!(
            "unknown major type {other}"
        ))),
    }
}

/// Byte-faithful components of a Cardano transaction, located by walking the tx
/// CBOR without a decode-then-re-encode pass.
///
/// `tx_body` and `witness_set` are EXACT on-chain byte slices: `blake2b256(tx_body)`
/// equals the transaction hash, and the witness set decodes to the vkey
/// witnesses that authorised the transaction. `label_309` is the reassembled
/// label-309 value (chunked-bytes concatenated), `None` when auxiliary_data is
/// null/undefined or label 309 is absent. `aux_metadata_labels` is the
/// ascending-sorted list of every integer key in the auxiliary metadata map
/// (empty when aux is null).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxComponents {
    /// The reassembled label-309 record body, ready for the structural validator.
    pub label_309: Option<Vec<u8>>,
    /// The exact on-chain transaction-body bytes.
    pub tx_body: Vec<u8>,
    /// The exact on-chain witness-set bytes.
    pub witness_set: Vec<u8>,
    /// The ascending-sorted auxiliary metadata label keys.
    pub aux_metadata_labels: Vec<i64>,
}

/// Walk the transaction CBOR once and return its byte-faithful components.
///
/// The body and witness-set slices are the producer's ORIGINAL bytes; `label_309`
/// carries the same byte-faithful guarantee (no decode-then-re-encode, so
/// non-canonical encodings reach the structural validator unchanged).
///
/// # Errors
///
/// Returns [`ExtractError::Malformed`] when the bytes do not decode to a CBOR
/// array of at least four elements, when the walk hits an indefinite-length or
/// truncated item, or when a label-309 chunk array carries a non-bytes element.
pub fn slice_tx_components(tx_cbor: &[u8]) -> Result<TxComponents, ExtractError> {
    let tx_head = read_head(tx_cbor, 0)?;
    if tx_head.mt != 4 {
        return Err(ExtractError::Malformed(format!(
            "tx CBOR is not a CBOR array (major type {})",
            tx_head.mt
        )));
    }
    if tx_head.value_u64 < 4 {
        return Err(ExtractError::Malformed(format!(
            "tx CBOR array has {} elements; expected >= 4 (post-Conway: [body, witness_set, is_valid, auxiliary_data])",
            tx_head.value_u64
        )));
    }

    let body_start = tx_head.payload_start;
    let body_end = skip_cbor_item(tx_cbor, body_start)?;
    let witness_set_start = body_end;
    let witness_set_end = skip_cbor_item(tx_cbor, witness_set_start)?;
    let pos = skip_cbor_item(tx_cbor, witness_set_end)?; // skip is_valid

    let tx_body = tx_cbor[body_start..body_end].to_vec();
    let witness_set = tx_cbor[witness_set_start..witness_set_end].to_vec();

    if pos >= tx_cbor.len() {
        return Err(ExtractError::Malformed(
            "truncated tx (auxiliary_data missing)".to_string(),
        ));
    }
    let aux_first_byte = tx_cbor[pos];
    if aux_first_byte == 0xf6 || aux_first_byte == 0xf7 {
        return Ok(TxComponents {
            label_309: None,
            tx_body,
            witness_set,
            aux_metadata_labels: Vec::new(),
        });
    }

    let mut aux_map_pos = pos;
    let aux_head = read_head(tx_cbor, pos)?;
    if aux_head.mt == 6 {
        if aux_head.value_u64 != CARDANO_AUX_DATA_TAG {
            return Err(ExtractError::Malformed(format!(
                "auxiliary_data carries unexpected CBOR tag {}; expected {CARDANO_AUX_DATA_TAG} or bare map",
                aux_head.value_u64
            )));
        }
        aux_map_pos = aux_head.payload_start;
    }

    let map_head = read_head(tx_cbor, aux_map_pos)?;
    if map_head.mt != 5 {
        return Err(ExtractError::Malformed(format!(
            "auxiliary_data is not a CBOR map (major type {})",
            map_head.mt
        )));
    }

    // Disambiguate the tagged (post-Alonzo `{0 => metadata, 1 => ...}`) and the
    // bare (pre-Alonzo: the map IS the metadata map) shapes by walking the map
    // keys: any int key in {0,1,2,3} marks the post-Alonzo shape (find key 0);
    // otherwise the whole map is the metadata map. Conway txs are always
    // tag-259 wrapped, but synthetic fixtures emit the post-Alonzo shape bare,
    // so both are accepted without forcing producers to add the tag.
    let metadata_map_pos: Option<usize> = {
        let mut entry_pos = map_head.payload_start;
        let mut saw_aux_key = false;
        let mut found_metadata_at: Option<usize> = None;
        for _ in 0..map_head.value_u64 {
            let key_head = read_head(tx_cbor, entry_pos)?;
            if key_head.mt == 0 && key_head.value_u64 <= 3 {
                saw_aux_key = true;
                if key_head.value_u64 == 0 {
                    found_metadata_at = Some(key_head.payload_start);
                }
            }
            entry_pos = skip_cbor_item(tx_cbor, entry_pos)?; // skip key
            entry_pos = skip_cbor_item(tx_cbor, entry_pos)?; // skip value
        }
        if saw_aux_key || aux_head.mt == 6 {
            found_metadata_at
        } else {
            Some(aux_map_pos)
        }
    };

    let Some(metadata_map_pos) = metadata_map_pos else {
        return Ok(TxComponents {
            label_309: None,
            tx_body,
            witness_set,
            aux_metadata_labels: Vec::new(),
        });
    };

    let meta_head = read_head(tx_cbor, metadata_map_pos)?;
    if meta_head.mt != 5 {
        return Err(ExtractError::Malformed(format!(
            "metadata is not a CBOR map (major type {})",
            meta_head.mt
        )));
    }
    let mut labels: Vec<i64> = Vec::new();
    let mut label_309: Option<Vec<u8>> = None;
    let mut pair_pos = meta_head.payload_start;
    for _ in 0..meta_head.value_u64 {
        let key_head = read_head(tx_cbor, pair_pos)?;
        let key_val = decode_int_key(&key_head)?;
        labels.push(key_val);
        let value_start = skip_cbor_item(tx_cbor, pair_pos)?;
        let value_end = skip_cbor_item(tx_cbor, value_start)?;
        if key_val == POE_LABEL {
            label_309 = Some(reassemble_label_309_value(tx_cbor, value_start, value_end)?);
        }
        pair_pos = value_end;
    }
    labels.sort_unstable();
    Ok(TxComponents {
        label_309,
        tx_body,
        witness_set,
        aux_metadata_labels: labels,
    })
}

/// Extract the byte-faithful label-309 record from raw transaction bytes.
///
/// Returns `Ok(Some(bytes))` with the reassembled record body, `Ok(None)` when
/// the transaction carries no auxiliary data or no label-309 metadata, or
/// [`ExtractError::Malformed`] when the transaction CBOR is structurally invalid.
///
/// # Errors
///
/// Returns [`ExtractError::Malformed`] for the structural-violation cases
/// documented on [`slice_tx_components`].
pub fn extract_label_309_metadata(tx_cbor: &[u8]) -> Result<Option<Vec<u8>>, ExtractError> {
    Ok(slice_tx_components(tx_cbor)?.label_309)
}

/// Reassemble the label-309 value into the canonical-CBOR record body.
///
/// Cardano caps individual metadata `bstr`/`tstr` values at 64 bytes, so a PoE
/// record (typically several hundred bytes of canonical CBOR) is emitted as a
/// `bytes-chunk-array` — `[ bstr .size (1..64), … ]`. The chunks are
/// byte-concatenated IN ORDER (returned raw, never re-encoded), yielding the
/// inner record body. A small record MAY be a single `bstr` (its contents are
/// the body) or, for some synthetic fixtures, a bare CBOR map (passed through
/// verbatim).
fn reassemble_label_309_value(
    tx_cbor: &[u8],
    value_start: usize,
    value_end: usize,
) -> Result<Vec<u8>, ExtractError> {
    let head = read_head(tx_cbor, value_start)?;
    match head.mt {
        // Array → bytes-chunk-array; concatenate inner bstr items.
        4 => {
            let mut out: Vec<u8> = Vec::new();
            let mut chunk_pos = head.payload_start;
            for i in 0..head.value_u64 {
                let chunk_head = read_head(tx_cbor, chunk_pos)?;
                if chunk_head.mt != 2 {
                    return Err(ExtractError::Malformed(format!(
                        "label-309 value is a CBOR array but element {i} has major type {}; expected byte string (chunked-bytes shape)",
                        chunk_head.mt
                    )));
                }
                let len = usize::try_from(chunk_head.value_u64).map_err(|_| {
                    ExtractError::Malformed("label-309 chunk length out of range".to_string())
                })?;
                let chunk_start = chunk_head.payload_start;
                let chunk_end = chunk_start
                    .checked_add(len)
                    .filter(|e| *e <= tx_cbor.len())
                    .ok_or_else(|| {
                        ExtractError::Malformed("truncated label-309 chunk payload".to_string())
                    })?;
                out.extend_from_slice(&tx_cbor[chunk_start..chunk_end]);
                chunk_pos = chunk_end;
            }
            Ok(out)
        }
        // Single bstr → its CONTENTS are the canonical record body.
        2 => {
            let len = usize::try_from(head.value_u64).map_err(|_| {
                ExtractError::Malformed("label-309 byte string length out of range".to_string())
            })?;
            let end = head
                .payload_start
                .checked_add(len)
                .filter(|e| *e <= tx_cbor.len())
                .ok_or_else(|| {
                    ExtractError::Malformed("truncated label-309 byte string payload".to_string())
                })?;
            Ok(tx_cbor[head.payload_start..end].to_vec())
        }
        // Map → bare-canonical shape; pass through unchanged (synthetic fixtures).
        5 => Ok(tx_cbor[value_start..value_end].to_vec()),
        other => Err(ExtractError::Malformed(format!(
            "label-309 value has major type {other}; expected array (chunked), byte string, or map"
        ))),
    }
}

/// Decode an integer metadata map key (unsigned or negative).
fn decode_int_key(h: &CborHead) -> Result<i64, ExtractError> {
    match h.mt {
        0 => i64::try_from(h.value_u64)
            .map_err(|_| ExtractError::Malformed("metadata map key out of range".to_string())),
        1 => i64::try_from(h.value_u64)
            .map(|n| -1 - n)
            .map_err(|_| ExtractError::Malformed("metadata map key out of range".to_string())),
        other => Err(ExtractError::Malformed(format!(
            "metadata map key has major type {other}; expected unsigned integer"
        ))),
    }
}
