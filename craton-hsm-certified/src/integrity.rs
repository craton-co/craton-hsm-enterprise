// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Binary integrity verification using HMAC-SHA256.
//!
//! Provides functions to compute and verify HMAC-SHA256 tags over arbitrary data
//! and binary files, enabling integrity verification of certified builds.

use crate::error::{CertError, CertResult};
use aws_lc_rs::hmac;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Minimum HMAC key length in bytes (NIST SP 800-107 recommends at least
/// the output length of the underlying hash, which is 32 bytes for SHA-256).
pub const MIN_HMAC_KEY_BYTES: usize = 32;

/// Internal helper that enforces the minimum-key-length policy and constructs
/// the underlying [`hmac::Key`].
fn make_key(key: &[u8]) -> CertResult<hmac::Key> {
    if key.len() < MIN_HMAC_KEY_BYTES {
        return Err(CertError::key_too_short(key.len(), MIN_HMAC_KEY_BYTES));
    }
    Ok(hmac::Key::new(hmac::HMAC_SHA256, key))
}

/// HMAC-SHA256 tag length in bytes.
pub const HMAC_SHA256_TAG_LEN: usize = 32;

/// Copy a slice that is expected to be exactly 32 bytes into a fixed
/// `[u8; 32]`.
#[inline]
fn tag_array_from(slice: &[u8]) -> [u8; HMAC_SHA256_TAG_LEN] {
    let mut out = [0u8; HMAC_SHA256_TAG_LEN];
    // The aws-lc-rs HMAC-SHA256 primitive always produces exactly 32 bytes,
    // so this length match is a guaranteed invariant on the caller side.
    debug_assert_eq!(slice.len(), HMAC_SHA256_TAG_LEN);
    out.copy_from_slice(slice);
    out
}

/// Compute an HMAC-SHA256 tag over `data` using the given `key`.
///
/// Returns `Err` if the key is shorter than [`MIN_HMAC_KEY_BYTES`] (32 bytes).
/// The returned tag is always 32 bytes.
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> CertResult<[u8; HMAC_SHA256_TAG_LEN]> {
    let s_key = make_key(key)?;
    let tag = hmac::sign(&s_key, data);
    Ok(tag_array_from(tag.as_ref()))
}

/// Compute an HMAC-SHA256 tag over a sequence of byte slices, in order.
///
/// Equivalent to `compute_hmac_sha256(key, &concat(parts))` but performs
/// **no allocation** of an intermediate concatenated buffer. The returned
/// tag is always 32 bytes.
pub fn compute_hmac_sha256_parts(
    key: &[u8],
    parts: &[&[u8]],
) -> CertResult<[u8; HMAC_SHA256_TAG_LEN]> {
    let s_key = make_key(key)?;
    let mut ctx = hmac::Context::with_key(&s_key);
    for p in parts {
        ctx.update(p);
    }
    Ok(tag_array_from(ctx.sign().as_ref()))
}

/// Verify an HMAC-SHA256 tag using constant-time comparison.
///
/// Returns `Ok(())` on a successful verification, [`CertError::HmacMismatch`]
/// on tag mismatch, or [`CertError::KeyTooShort`] if the key is too short.
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected: &[u8]) -> CertResult<()> {
    let s_key = make_key(key)?;
    hmac::verify(&s_key, data, expected).map_err(|_| CertError::HmacMismatch)
}

/// Constant-time comparison of a freshly computed tag against an
/// `expected` slice that may be of a different length than the tag.
///
/// If the lengths differ, we still perform a constant-time comparison
/// against a zeroed buffer of the *computed* tag's length so that the
/// total work done — and the branch profile — is identical to a length
/// match. The result is then unconditionally an error, but no
/// information about the expected length leaks via wall-clock timing.
#[inline]
fn constant_time_verify_with_len_check(
    computed: &[u8; HMAC_SHA256_TAG_LEN],
    expected: &[u8],
) -> CertResult<()> {
    if expected.len() == HMAC_SHA256_TAG_LEN {
        aws_lc_rs::constant_time::verify_slices_are_equal(computed.as_slice(), expected)
            .map_err(|_| CertError::HmacMismatch)
    } else {
        // Compare to a zero buffer of the *computed* length so the
        // wall-clock cost of the mismatch path is independent of the
        // (untrusted) `expected.len()`.
        let zero = [0u8; HMAC_SHA256_TAG_LEN];
        let _ =
            aws_lc_rs::constant_time::verify_slices_are_equal(computed.as_slice(), zero.as_slice());
        Err(CertError::HmacMismatch)
    }
}

/// Verify an HMAC over a sequence of byte slices.
pub fn verify_hmac_sha256_parts(key: &[u8], parts: &[&[u8]], expected: &[u8]) -> CertResult<()> {
    let computed = compute_hmac_sha256_parts(key, parts)?;
    constant_time_verify_with_len_check(&computed, expected)
}

/// Stream a file through an HMAC-SHA256 context without loading it fully
/// into memory.
fn hmac_file(key: &[u8], path: &Path) -> CertResult<[u8; HMAC_SHA256_TAG_LEN]> {
    let s_key = make_key(key)?;
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut ctx = hmac::Context::with_key(&s_key);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(tag_array_from(ctx.sign().as_ref()))
}

/// Read a binary file and compute its HMAC-SHA256 integrity tag.
///
/// Streams the file through the HMAC context in 64 KiB chunks; the file is
/// **not** read fully into memory. The returned tag is always 32 bytes.
pub fn compute_binary_integrity(
    binary_path: &Path,
    hmac_key: &[u8],
) -> CertResult<[u8; HMAC_SHA256_TAG_LEN]> {
    hmac_file(hmac_key, binary_path)
}

/// Verify the integrity of a binary file against an expected HMAC-SHA256 tag.
///
/// Returns `Ok(())` on success, [`CertError::HmacMismatch`] on tag mismatch.
/// Uses a constant-time comparison even when `expected.len() != 32` so the
/// length-mismatch path does not leak via timing.
pub fn verify_binary_integrity(
    binary_path: &Path,
    hmac_key: &[u8],
    expected: &[u8],
) -> CertResult<()> {
    let computed = hmac_file(hmac_key, binary_path)?;
    constant_time_verify_with_len_check(&computed, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 32-byte test key (meets the minimum length requirement).
    const VALID_KEY: &[u8] = b"test-hmac-key-for-fips-32bytes!!";

    #[test]
    fn hmac_roundtrip() {
        let data = b"hello certified world";
        let tag = compute_hmac_sha256(VALID_KEY, data).unwrap();
        assert_eq!(tag.len(), 32);
        verify_hmac_sha256(VALID_KEY, data, &tag).unwrap();
    }

    #[test]
    fn parts_match_concatenated() {
        let parts: &[&[u8]] = &[b"foo", b"bar", b"baz"];
        let concat = b"foobarbaz";
        let tag_parts = compute_hmac_sha256_parts(VALID_KEY, parts).unwrap();
        let tag_concat = compute_hmac_sha256(VALID_KEY, concat).unwrap();
        assert_eq!(tag_parts, tag_concat);
        verify_hmac_sha256_parts(VALID_KEY, parts, &tag_concat).unwrap();
    }

    #[test]
    fn wrong_key_rejected() {
        let wrong_key = b"wrong-key-value-that-is-32bytes!";
        let data = b"some data";
        let tag = compute_hmac_sha256(VALID_KEY, data).unwrap();
        assert!(matches!(
            verify_hmac_sha256(wrong_key, data, &tag),
            Err(CertError::HmacMismatch)
        ));
    }

    #[test]
    fn tampered_data_detected() {
        let data = b"original data";
        let tampered = b"tampered data";
        let tag = compute_hmac_sha256(VALID_KEY, data).unwrap();
        assert!(verify_hmac_sha256(VALID_KEY, tampered, &tag).is_err());
    }

    #[test]
    fn short_key_rejected() {
        let short_key = b"too-short";
        let data = b"some data";
        assert!(matches!(
            compute_hmac_sha256(short_key, data),
            Err(CertError::KeyTooShort { .. })
        ));
        assert!(matches!(
            verify_hmac_sha256(short_key, data, &[]),
            Err(CertError::KeyTooShort { .. })
        ));
    }

    #[test]
    fn key_exactly_32_bytes_accepted() {
        let key_32 = b"exactly-32-byte-key-for-testing!";
        assert_eq!(key_32.len(), 32);
        let data = b"data";
        assert!(compute_hmac_sha256(key_32, data).is_ok());
    }

    #[test]
    fn binary_integrity_with_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test_binary");
        std::fs::write(&file_path, b"binary content for integrity check").unwrap();

        let tag = compute_binary_integrity(&file_path, VALID_KEY).unwrap();
        verify_binary_integrity(&file_path, VALID_KEY, &tag).unwrap();

        // Tamper with the file
        std::fs::write(&file_path, b"tampered binary content").unwrap();
        assert!(verify_binary_integrity(&file_path, VALID_KEY, &tag).is_err());
    }

    #[test]
    fn binary_integrity_short_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test_binary");
        std::fs::write(&file_path, b"some content").unwrap();

        let short_key = b"short";
        assert!(matches!(
            compute_binary_integrity(&file_path, short_key),
            Err(CertError::KeyTooShort { .. })
        ));
        assert!(matches!(
            verify_binary_integrity(&file_path, short_key, &[]),
            Err(CertError::KeyTooShort { .. })
        ));
    }

    #[test]
    fn streaming_handles_large_file() {
        // Larger than the internal 64 KiB buffer to exercise multi-chunk reads.
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("big_binary");
        let chunk = vec![0xAAu8; 200_000];
        std::fs::write(&file_path, &chunk).unwrap();

        let tag_file = compute_binary_integrity(&file_path, VALID_KEY).unwrap();
        let tag_mem = compute_hmac_sha256(VALID_KEY, &chunk).unwrap();
        assert_eq!(tag_file, tag_mem);
    }
}
