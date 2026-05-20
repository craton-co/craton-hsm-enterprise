// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Shared hex encoding / decoding utilities.
//!
//! Provides a fast lookup-table encoder and a nibble-table decoder used
//! throughout the certified crate.  Having one canonical implementation
//! removes the previous duplicated copies in `binary_sign`, `test_harness`,
//! and `acvp`.

use crate::error::{CertError, CertResult};

/// Lookup table for nibble → ASCII hex digit.
const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Reverse table — ASCII byte → nibble (0..15) or `0xFF` if invalid.
const HEX_REVERSE: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    let mut i = 0u8;
    while i < 10 {
        t[(b'0' + i) as usize] = i;
        i += 1;
    }
    let mut i = 0u8;
    while i < 6 {
        t[(b'a' + i) as usize] = 10 + i;
        t[(b'A' + i) as usize] = 10 + i;
        i += 1;
    }
    t
};

/// Encode `bytes` as a lowercase hex string.
///
/// Uses a pre-computed lookup table instead of `format!("{:02x}", b)` to
/// avoid per-byte heap allocations.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode a hex string into bytes via a nibble lookup table.
///
/// Returns `Err(CertError::HexDecode)` if the string has an odd length or
/// contains non-hex characters.
pub(crate) fn hex_decode(hex: &str) -> CertResult<Vec<u8>> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(CertError::HexDecode(format!(
            "odd-length hex string (len={})",
            bytes.len()
        )));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = HEX_REVERSE[bytes[i] as usize];
        let lo = HEX_REVERSE[bytes[i + 1] as usize];
        if hi == 0xFF || lo == 0xFF {
            return Err(CertError::HexDecode(format!(
                "invalid hex byte at offset {i}"
            )));
        }
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// Truncate a byte slice's hex representation to at most `max_chars`
/// characters (the default short-form used in test result messages).
pub(crate) fn short_hex(bytes: &[u8], max_chars: usize) -> String {
    let full = hex_encode(bytes);
    if full.len() <= max_chars {
        full
    } else {
        full[..max_chars].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bytes = [0x00u8, 0x0f, 0x10, 0xff, 0xab, 0xcd];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "000f10ffabcd");
        assert_eq!(hex_decode(&hex).unwrap(), bytes);
    }

    #[test]
    fn empty_input() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn odd_length_rejected() {
        let err = hex_decode("abc").unwrap_err();
        assert!(matches!(err, CertError::HexDecode(_)));
    }

    #[test]
    fn invalid_char_rejected() {
        assert!(hex_decode("0xgg").is_err());
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn uppercase_input_accepted() {
        assert_eq!(hex_decode("ABCDEF").unwrap(), vec![0xab, 0xcd, 0xef]);
    }

    #[test]
    fn all_zero_bytes() {
        let bytes = [0u8; 32];
        assert_eq!(hex_encode(&bytes), "0".repeat(64));
    }

    #[test]
    fn short_hex_truncates() {
        let bytes = vec![0xAB; 32];
        assert_eq!(short_hex(&bytes, 8), "abababab");
        assert_eq!(short_hex(&[0xab], 8), "ab");
    }
}
