//! Bech32 codec and `age`/`age1pqc` recipient string encode/decode.
//!
//! A sender addresses a sealed-PoE record to a recipient by their bech32
//! recipient string; the human-readable prefix (HRP) makes the string
//! self-describing, so a parser routes to the right KEM purely from the prefix:
//!
//! * X25519 (32 bytes)                          → `age1…`
//! * X-Wing / ML-KEM-768 + X25519 (1216 bytes)  → `age1pqc…`
//!
//! The bech32 implementation is inlined per BIP-173 rather than pulled from a
//! general-purpose base-encoding crate, keeping the dependency graph to a small
//! audited set. It deviates from BIP-173 in two deliberate ways: the 90-char
//! length cap is removed (an X-Wing recipient is ~1960 characters) and the HRP
//! separator is the *last* `1` in the string, so an HRP that itself contains a
//! `1` (the `age1pqc` prefix) round-trips. Output is byte-identical to a
//! standard bech32 encoder used with the no-length-limit flag, and to the
//! TypeScript (`@cardanowall/crypto-core`) and Python (`cardanowall`) codecs.
//!
//! The `age1pqc` HRP is chosen for the hybrid key because upstream age v1.3.0
//! claims the shorter `age1pq` HRP for the same X-Wing primitive; `age1pqc`
//! avoids colliding with that wire identifier.

use thiserror::Error;

/// The bech32 character set in value order (BIP-173).
const BECH32_ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The five bech32 polymod generator constants (BIP-173).
const POLYMOD_GENERATORS: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// BIP-173 bech32 (not bech32m). The checksum constant `1` distinguishes the
/// two encodings.
const ENCODING_CONST: u32 = 1;

const X25519_HRP: &str = "age";
const XWING_HRP: &str = "age1pqc";
const X25519_PUBLIC_KEY_BYTES: usize = 32;
const XWING_PUBLIC_KEY_BYTES: usize = 1216;

/// Errors raised while encoding to, or decoding from, the bech32 recipient form.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecipientError {
    /// The HRP supplied to the encoder was empty.
    #[error("bech32: empty prefix")]
    EmptyPrefix,

    /// An HRP character is outside the printable range `33..=126` BIP-173
    /// permits. Carries the offending prefix.
    #[error("bech32: invalid prefix ({0})")]
    InvalidPrefix(String),

    /// The input string was empty.
    #[error("bech32: empty string")]
    EmptyString,

    /// The string mixes upper- and lowercase, which bech32 forbids.
    #[error("bech32: mixed-case string")]
    MixedCase,

    /// No HRP separator was found, or it sat at position 0 (an empty HRP).
    #[error("bech32: missing human-readable prefix")]
    MissingPrefix,

    /// Fewer than six data characters follow the separator, so there is no room
    /// for the checksum.
    #[error("bech32: data too short for checksum")]
    DataTooShort,

    /// An HRP character is outside the printable range `33..=126`.
    #[error("bech32: invalid prefix character")]
    InvalidPrefixCharacter,

    /// A data character is not in the bech32 alphabet.
    #[error("bech32: invalid data character")]
    InvalidDataCharacter,

    /// The bech32 checksum did not verify.
    #[error("bech32: bad checksum")]
    BadChecksum,

    /// The decoded data carried trailing padding that was not the canonical
    /// `<5` zero bits the encoder emits.
    #[error("bech32: non-canonical padding")]
    NonCanonicalPadding,

    /// An X25519 public key was not exactly 32 bytes when encoding.
    #[error("encodeAgeX25519Recipient: publicKey must be exactly 32 bytes")]
    X25519KeyLength,

    /// An X-Wing public key was not exactly 1216 bytes when encoding.
    #[error("encodeAgeXWingRecipient: publicKey must be exactly 1216 bytes")]
    XWingKeyLength,

    /// An `age` recipient decoded to a payload that was not 32 bytes.
    #[error("parseAgeRecipient: age recipient must carry a 32-byte X25519 key")]
    ParsedX25519KeyLength,

    /// An `age1pqc` recipient decoded to a payload that was not 1216 bytes.
    #[error("parseAgeRecipient: age1pqc recipient must carry a 1216-byte X-Wing key")]
    ParsedXWingKeyLength,

    /// The decoded HRP matched neither `age` nor `age1pqc`. Carries the HRP.
    #[error("parseAgeRecipient: unrecognized recipient prefix \"{0}\"")]
    UnrecognizedPrefix(String),
}

/// The KEM a recipient string addresses, inferred from its bech32 HRP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientKem {
    /// Classical X25519 (32-byte public key, `age1…`).
    X25519,
    /// Hybrid X-Wing / ML-KEM-768 + X25519 (1216-byte public key, `age1pqc…`).
    MlKem768X25519,
}

/// A recipient string decoded to its raw KEM public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAgeRecipient {
    /// The KEM the recipient's HRP implies.
    pub kem: RecipientKem,
    /// The raw KEM public-key bytes (32 for X25519, 1216 for X-Wing).
    pub public_key: Vec<u8>,
}

/// Apply one step of the bech32 checksum polymod (BIP-173).
fn polymod_step(pre: u32) -> u32 {
    let b = pre >> 25;
    let mut chk = (pre & 0x01ff_ffff) << 5;
    for (i, gen) in POLYMOD_GENERATORS.iter().enumerate() {
        if (b >> i) & 1 == 1 {
            chk ^= gen;
        }
    }
    chk
}

/// 8-bit bytes → 5-bit words, padding the final partial group with zero bits.
fn bytes_to_words(bytes: &[u8]) -> Vec<u8> {
    let mut words = Vec::new();
    let mut carry: u32 = 0;
    let mut pos: u32 = 0;
    for &n in bytes {
        carry = (carry << 8) | u32::from(n);
        pos += 8;
        while pos >= 5 {
            pos -= 5;
            words.push(((carry >> pos) & 0x1f) as u8);
        }
        carry &= (1 << pos) - 1;
    }
    if pos > 0 {
        words.push(((carry << (5 - pos)) & 0x1f) as u8);
    }
    words
}

/// Compute the six-character bech32 checksum suffix over an HRP + data words.
fn checksum(prefix: &str, words: &[u8]) -> Result<String, RecipientError> {
    let mut chk: u32 = 1;
    for c in prefix.bytes() {
        if !(33..=126).contains(&c) {
            return Err(RecipientError::InvalidPrefix(prefix.to_string()));
        }
        chk = polymod_step(chk) ^ u32::from(c >> 5);
    }
    chk = polymod_step(chk);
    for c in prefix.bytes() {
        chk = polymod_step(chk) ^ u32::from(c & 0x1f);
    }
    for &v in words {
        chk = polymod_step(chk) ^ u32::from(v);
    }
    for _ in 0..6 {
        chk = polymod_step(chk);
    }
    chk ^= ENCODING_CONST;
    let mut out = String::with_capacity(6);
    for i in 0..6 {
        let idx = ((chk >> (5 * (5 - i))) & 31) as usize;
        out.push(BECH32_ALPHABET[idx] as char);
    }
    Ok(out)
}

/// Encode raw bytes to a bech32 string with **no** length limit.
///
/// `prefix` is the human-readable part (HRP). The output is byte-identical to a
/// standard bech32 encoder used with the no-length-limit flag, the inverse of
/// [`bech32_decode_no_limit`].
///
/// # Errors
///
/// Returns [`RecipientError::EmptyPrefix`] for an empty HRP, or
/// [`RecipientError::InvalidPrefix`] for an HRP carrying a character outside the
/// printable range `33..=126`.
pub fn bech32_encode_no_limit(prefix: &str, bytes: &[u8]) -> Result<String, RecipientError> {
    if prefix.is_empty() {
        return Err(RecipientError::EmptyPrefix);
    }
    let words = bytes_to_words(bytes);
    let lowered = prefix.to_lowercase();
    let mut payload = String::with_capacity(words.len());
    for &w in &words {
        payload.push(BECH32_ALPHABET[w as usize] as char);
    }
    let check = checksum(&lowered, &words)?;
    Ok(format!("{lowered}1{payload}{check}"))
}

/// Recompute the polymod over the HRP + every data word (the trailing six being
/// the checksum) and test it against the encoding constant.
fn checksum_valid(prefix: &str, words: &[u8]) -> bool {
    let mut chk: u32 = 1;
    for c in prefix.bytes() {
        chk = polymod_step(chk) ^ u32::from(c >> 5);
    }
    chk = polymod_step(chk);
    for c in prefix.bytes() {
        chk = polymod_step(chk) ^ u32::from(c & 0x1f);
    }
    for &v in words {
        chk = polymod_step(chk) ^ u32::from(v);
    }
    chk == ENCODING_CONST
}

/// 5-bit words → 8-bit bytes (the inverse of [`bytes_to_words`]). Rejects
/// non-canonical padding: any leftover must be fewer than 5 bits and all zero,
/// matching the zero-fill the encoder applies to a final partial group.
fn words_to_bytes(words: &[u8]) -> Result<Vec<u8>, RecipientError> {
    let mut out = Vec::new();
    let mut carry: u32 = 0;
    let mut pos: u32 = 0;
    for &w in words {
        carry = (carry << 5) | u32::from(w);
        pos += 5;
        while pos >= 8 {
            pos -= 8;
            out.push(((carry >> pos) & 0xff) as u8);
        }
        carry &= (1 << pos) - 1;
    }
    if pos >= 5 || carry != 0 {
        return Err(RecipientError::NonCanonicalPadding);
    }
    Ok(out)
}

/// Decode a bech32 string with **no** length limit, verifying the checksum.
///
/// Returns the lower-cased HRP and the decoded data bytes — the inverse of
/// [`bech32_encode_no_limit`]. The separator is the last `1` in the string, so
/// HRPs that themselves contain a `1` (e.g. `age1pqc`) round-trip correctly.
///
/// # Errors
///
/// Returns a [`RecipientError`] variant for an empty string, mixed case, a
/// missing or empty HRP, too few checksum characters, an out-of-range HRP
/// character, an out-of-alphabet data character, a bad checksum, or
/// non-canonical trailing padding.
pub fn bech32_decode_no_limit(input: &str) -> Result<(String, Vec<u8>), RecipientError> {
    if input.is_empty() {
        return Err(RecipientError::EmptyString);
    }
    let has_lower = input != input.to_uppercase();
    let has_upper = input != input.to_lowercase();
    if has_lower && has_upper {
        return Err(RecipientError::MixedCase);
    }
    let s = input.to_lowercase();
    let sep = match s.rfind('1') {
        Some(i) => i,
        None => return Err(RecipientError::MissingPrefix),
    };
    if sep < 1 {
        return Err(RecipientError::MissingPrefix);
    }
    if s.len() - sep - 1 < 6 {
        return Err(RecipientError::DataTooShort);
    }
    let hrp = &s[..sep];
    for c in hrp.bytes() {
        if !(33..=126).contains(&c) {
            return Err(RecipientError::InvalidPrefixCharacter);
        }
    }
    let mut words: Vec<u8> = Vec::new();
    for ch in s[sep + 1..].bytes() {
        match BECH32_ALPHABET.iter().position(|&a| a == ch) {
            Some(v) => words.push(v as u8),
            None => return Err(RecipientError::InvalidDataCharacter),
        }
    }
    if !checksum_valid(hrp, &words) {
        return Err(RecipientError::BadChecksum);
    }
    let data = words_to_bytes(&words[..words.len() - 6])?;
    Ok((hrp.to_string(), data))
}

/// Encode a 32-byte X25519 public key to its `age1…` recipient string.
///
/// # Errors
///
/// Returns [`RecipientError::X25519KeyLength`] unless the key is exactly 32
/// bytes.
pub fn encode_age_x25519_recipient(public_key: &[u8]) -> Result<String, RecipientError> {
    if public_key.len() != X25519_PUBLIC_KEY_BYTES {
        return Err(RecipientError::X25519KeyLength);
    }
    bech32_encode_no_limit(X25519_HRP, public_key)
}

/// Encode a 1216-byte X-Wing public key to its `age1pqc…` recipient string.
///
/// # Errors
///
/// Returns [`RecipientError::XWingKeyLength`] unless the key is exactly 1216
/// bytes.
pub fn encode_age_xwing_recipient(public_key: &[u8]) -> Result<String, RecipientError> {
    if public_key.len() != XWING_PUBLIC_KEY_BYTES {
        return Err(RecipientError::XWingKeyLength);
    }
    bech32_encode_no_limit(XWING_HRP, public_key)
}

/// Decode an age-style recipient string back to its raw KEM public key, routing
/// on the bech32 HRP.
///
/// The inverse of [`encode_age_x25519_recipient`] / [`encode_age_xwing_recipient`]:
/// a sender takes a recipient string a peer shared and recovers the exact public
/// key (and which KEM it belongs to) needed to seal a record to them. Surrounding
/// whitespace is tolerated so pasted strings parse.
///
/// # Errors
///
/// Returns a [`RecipientError`] variant on an unknown HRP, a bad checksum, or a
/// key length that does not match the HRP's KEM.
pub fn parse_age_recipient(recipient: &str) -> Result<ParsedAgeRecipient, RecipientError> {
    let (hrp, bytes) = bech32_decode_no_limit(recipient.trim())?;
    if hrp == X25519_HRP {
        if bytes.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(RecipientError::ParsedX25519KeyLength);
        }
        return Ok(ParsedAgeRecipient {
            kem: RecipientKem::X25519,
            public_key: bytes,
        });
    }
    if hrp == XWING_HRP {
        if bytes.len() != XWING_PUBLIC_KEY_BYTES {
            return Err(RecipientError::ParsedXWingKeyLength);
        }
        return Ok(ParsedAgeRecipient {
            kem: RecipientKem::MlKem768X25519,
            public_key: bytes,
        });
    }
    Err(RecipientError::UnrecognizedPrefix(hrp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_recipient_round_trips() {
        let pub_key = [7u8; 32];
        let s = encode_age_x25519_recipient(&pub_key).unwrap();
        assert!(s.starts_with("age1"));
        let parsed = parse_age_recipient(&s).unwrap();
        assert_eq!(parsed.kem, RecipientKem::X25519);
        assert_eq!(parsed.public_key, pub_key);
    }

    #[test]
    fn xwing_recipient_round_trips() {
        let pub_key = vec![9u8; 1216];
        let s = encode_age_xwing_recipient(&pub_key).unwrap();
        assert!(s.starts_with("age1pqc1"));
        let parsed = parse_age_recipient(&s).unwrap();
        assert_eq!(parsed.kem, RecipientKem::MlKem768X25519);
        assert_eq!(parsed.public_key, pub_key);
    }

    #[test]
    fn encode_rejects_wrong_key_length() {
        assert_eq!(
            encode_age_x25519_recipient(&[0u8; 31]),
            Err(RecipientError::X25519KeyLength)
        );
        assert_eq!(
            encode_age_x25519_recipient(&[0u8; 33]),
            Err(RecipientError::X25519KeyLength)
        );
        assert_eq!(
            encode_age_xwing_recipient(&[0u8; 1215]),
            Err(RecipientError::XWingKeyLength)
        );
        assert_eq!(
            encode_age_xwing_recipient(&[0u8; 1217]),
            Err(RecipientError::XWingKeyLength)
        );
    }

    #[test]
    fn bech32_empty_prefix_is_rejected() {
        assert_eq!(
            bech32_encode_no_limit("", &[0u8; 32]),
            Err(RecipientError::EmptyPrefix)
        );
    }

    #[test]
    fn parse_tolerates_surrounding_whitespace() {
        let s = encode_age_x25519_recipient(&[1u8; 32]).unwrap();
        let parsed = parse_age_recipient(&format!("  {s}\n")).unwrap();
        assert_eq!(parsed.public_key, vec![1u8; 32]);
    }

    #[test]
    fn parse_rejects_empty_string() {
        assert_eq!(parse_age_recipient(""), Err(RecipientError::EmptyString));
    }

    #[test]
    fn parse_rejects_corrupted_checksum() {
        let s = encode_age_x25519_recipient(&[2u8; 32]).unwrap();
        let last = s.chars().last().unwrap();
        let replacement = if last == 'q' { 'p' } else { 'q' };
        let broken: String = s[..s.len() - 1].to_string() + &replacement.to_string();
        assert_eq!(
            parse_age_recipient(&broken),
            Err(RecipientError::BadChecksum)
        );
    }

    #[test]
    fn parse_rejects_mixed_case() {
        let s = encode_age_x25519_recipient(&[3u8; 32]).unwrap();
        let mixed = s[..12].to_uppercase() + &s[12..];
        assert_eq!(parse_age_recipient(&mixed), Err(RecipientError::MixedCase));
    }

    #[test]
    fn parse_rejects_unrecognized_hrp() {
        let s = bech32_encode_no_limit("xyz", &[4u8; 32]).unwrap();
        assert_eq!(
            parse_age_recipient(&s),
            Err(RecipientError::UnrecognizedPrefix("xyz".to_string()))
        );
    }

    #[test]
    fn parse_rejects_correct_hrp_with_wrong_length() {
        let wrong = bech32_encode_no_limit("age1pqc", &[5u8; 32]).unwrap();
        assert_eq!(
            parse_age_recipient(&wrong),
            Err(RecipientError::ParsedXWingKeyLength)
        );
    }
}
