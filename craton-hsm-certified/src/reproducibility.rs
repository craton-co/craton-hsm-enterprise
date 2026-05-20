// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Build reproducibility checking using SHA-256.
//!
//! Verifies that independent builds of the same source produce identical
//! binaries by comparing their SHA-256 hashes. Files are streamed through
//! the digest in 64 KiB chunks so artifacts of arbitrary size can be hashed
//! without loading them fully into memory, and a fast-path size check
//! short-circuits comparison when two files differ in length.

use crate::error::CertResult;
use crate::hex_util::hex_encode;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

const STREAM_BUF_SIZE: usize = 64 * 1024;

/// Stream a file through a SHA-256 context, returning the raw 32-byte digest.
fn sha256_file(path: &Path) -> CertResult<[u8; 32]> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(STREAM_BUF_SIZE, file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; STREAM_BUF_SIZE];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// Compute the SHA-256 hash of a binary file, returned as a lowercase hex
/// string.
pub fn compute_build_hash(binary_path: &Path) -> CertResult<String> {
    Ok(hex_encode(&sha256_file(binary_path)?))
}

/// Compare two binary files by their SHA-256 hashes.
///
/// Returns `true` if both files produce the same hash. As a fast path, if
/// the two files differ in length, the function returns `false` without
/// hashing either.
pub fn compare_binary_hashes(path_a: &Path, path_b: &Path) -> CertResult<bool> {
    let len_a = std::fs::metadata(path_a)?.len();
    let len_b = std::fs::metadata(path_b)?.len();
    if len_a != len_b {
        return Ok(false);
    }
    let hash_a = sha256_file(path_a)?;
    let hash_b = sha256_file(path_b)?;
    Ok(hash_a == hash_b)
}

/// Verify that all builds in the slice are reproducible (identical SHA-256).
///
/// Returns `true` for empty or single-element slices. Hashes the reference
/// file once and compares each subsequent file's hash against it,
/// short-circuiting on size mismatch.
pub fn verify_reproducible_build(builds: &[&Path]) -> CertResult<bool> {
    if builds.len() <= 1 {
        return Ok(true);
    }
    let ref_len = std::fs::metadata(builds[0])?.len();
    let reference_hash = sha256_file(builds[0])?;
    for path in &builds[1..] {
        if std::fs::metadata(path)?.len() != ref_len {
            return Ok(false);
        }
        if sha256_file(path)? != reference_hash {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_files_match() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("build_a");
        let b = dir.path().join("build_b");
        let content = b"identical binary content";
        std::fs::write(&a, content).unwrap();
        std::fs::write(&b, content).unwrap();

        assert!(compare_binary_hashes(&a, &b).unwrap());
    }

    #[test]
    fn different_files_dont_match() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("build_a");
        let b = dir.path().join("build_b");
        std::fs::write(&a, b"content version 1").unwrap();
        std::fs::write(&b, b"content version 2").unwrap();

        assert!(!compare_binary_hashes(&a, &b).unwrap());
    }

    #[test]
    fn size_mismatch_short_circuits() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"short").unwrap();
        std::fs::write(&b, b"a much longer payload than the first").unwrap();
        assert!(!compare_binary_hashes(&a, &b).unwrap());
    }

    #[test]
    fn multiple_identical_builds_pass() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"reproducible build output";
        let paths: Vec<_> = (0..4)
            .map(|i| {
                let p = dir.path().join(format!("build_{}", i));
                std::fs::write(&p, content).unwrap();
                p
            })
            .collect();
        let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();

        assert!(verify_reproducible_build(&refs).unwrap());
    }

    #[test]
    fn one_different_build_fails() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"reproducible build output";
        let mut paths: Vec<_> = (0..3)
            .map(|i| {
                let p = dir.path().join(format!("build_{}", i));
                std::fs::write(&p, content).unwrap();
                p
            })
            .collect();
        let divergent = dir.path().join("build_divergent");
        std::fs::write(&divergent, b"different output").unwrap();
        paths.push(divergent);

        let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
        assert!(!verify_reproducible_build(&refs).unwrap());
    }

    #[test]
    fn hash_is_valid_hex_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("test_bin");
        std::fs::write(&p, b"test").unwrap();
        let hash = compute_build_hash(&p).unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn streaming_handles_large_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big");
        let content = vec![0xCDu8; 200_000];
        std::fs::write(&p, &content).unwrap();
        let h = compute_build_hash(&p).unwrap();

        // Compare against a one-shot hash for sanity
        let mut hasher = Sha256::new();
        hasher.update(&content);
        assert_eq!(h, hex_encode(&hasher.finalize()));
    }

    #[test]
    fn empty_and_single_slice_are_reproducible() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("only");
        std::fs::write(&p, b"x").unwrap();
        assert!(verify_reproducible_build(&[]).unwrap());
        assert!(verify_reproducible_build(&[p.as_path()]).unwrap());
    }
}
