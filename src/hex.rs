//! Hexadecimal encode/decode helpers.
//!
//! A single, shared hex codec so the verifier, the wire serialiser, and the
//! publish client all emit byte-identical hex. The cross-implementation
//! fixtures and the TypeScript / Python parity twins depend on this exact
//! form: lowercase digits, two per byte, zero-padded, with no `0x` prefix and
//! no separators.

use thiserror::Error;

/// Error returned when a hex string cannot be decoded into bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HexError {
    /// The input has an odd number of hex digits, so it cannot split into
    /// whole bytes. Carries the offending length.
    #[error("hex: input has odd length {0}")]
    OddLength(usize),

    /// The input contains a character outside the hex alphabet
    /// (`0-9`, `a-f`, `A-F`). Carries the byte position of the first
    /// invalid character.
    #[error("hex: invalid character at index {0}")]
    InvalidCharacter(usize),
}

/// Encode bytes as a lowercase hex string with no `0x` prefix and no
/// separators.
///
/// Each byte becomes exactly two lowercase hex digits, zero-padded. Empty
/// input encodes to the empty string. This matches the TypeScript
/// `bytesToHex` and Python `bytes.hex()` output byte-for-byte.
///
/// ```
/// use cardanowall::hex::encode;
/// assert_eq!(encode(&[0x00, 0xab, 0xff]), "00abff");
/// assert_eq!(encode(&[]), "");
/// ```
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode a hex string into bytes.
///
/// Accepts both lowercase and uppercase digits (the canonical encoder only
/// ever emits lowercase, but decoding is case-insensitive to match the
/// permissive `bytes.fromhex` / crate behaviour the other SDKs rely on). No
/// `0x` prefix, whitespace, or separators are permitted — the input must be a
/// contiguous run of hex digits with even length.
///
/// # Errors
///
/// Returns [`HexError::OddLength`] when the input length is odd, and
/// [`HexError::InvalidCharacter`] when a non-hex character is present.
///
/// ```
/// use cardanowall::hex::{decode, HexError};
/// assert_eq!(decode("00abff").unwrap(), vec![0x00, 0xab, 0xff]);
/// assert_eq!(decode("00ABFF").unwrap(), vec![0x00, 0xab, 0xff]);
/// assert_eq!(decode("abc"), Err(HexError::OddLength(3)));
/// assert_eq!(decode("0g"), Err(HexError::InvalidCharacter(1)));
/// ```
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    hex::decode(s).map_err(|e| match e {
        hex::FromHexError::OddLength => HexError::OddLength(s.len()),
        hex::FromHexError::InvalidHexCharacter { index, .. } => HexError::InvalidCharacter(index),
        // The slice-length variant only arises from the fixed-size
        // `decode_to_slice` API, which this function never calls.
        hex::FromHexError::InvalidStringLength => HexError::OddLength(s.len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_lowercase_no_prefix_no_separators() {
        assert_eq!(encode(&[0x00, 0xab, 0xff, 0x10]), "00abff10");
    }

    #[test]
    fn empty_round_trips() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn round_trips_full_byte_range() {
        let all: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn decode_is_case_insensitive() {
        assert_eq!(decode("00ABFF").unwrap(), decode("00abff").unwrap());
        assert_eq!(decode("DeadBeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rejects_odd_length() {
        assert_eq!(decode("abc"), Err(HexError::OddLength(3)));
        assert_eq!(decode("f"), Err(HexError::OddLength(1)));
    }

    #[test]
    fn rejects_non_hex_characters() {
        assert_eq!(decode("0g"), Err(HexError::InvalidCharacter(1)));
        assert_eq!(decode("zz"), Err(HexError::InvalidCharacter(0)));
        // A `0x` prefix is not stripped; the `x` is rejected as a digit.
        assert_eq!(decode("0xff"), Err(HexError::InvalidCharacter(1)));
    }
}
