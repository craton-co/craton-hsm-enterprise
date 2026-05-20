// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! DigestInfo prefixes for PKCS#1 v1.5 signing of pre-computed digests.
//!
//! When signing a pre-computed digest with `CKM_RSA_PKCS` (raw PKCS#1 v1.5),
//! the input must be the ASN.1 `DigestInfo` structure:
//!
//! ```text
//! DigestInfo ::= SEQUENCE {
//!     digestAlgorithm DigestAlgorithmIdentifier,
//!     digest          OCTET STRING
//! }
//! ```
//!
//! These constants are the DER encoding of the `digestAlgorithm` field plus
//! the OCTET STRING tag and length, ready to be concatenated with the raw
//! digest bytes. They match RFC 8017 §9.2 step 2 (Notes 1) exactly.

use craton_hsm::crypto::sign::HashAlg;

/// SHA-256 DigestInfo prefix (19 bytes). Followed by 32 bytes of digest.
pub const SHA256_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// SHA-384 DigestInfo prefix (19 bytes). Followed by 48 bytes of digest.
pub const SHA384_PREFIX: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];

/// SHA-512 DigestInfo prefix (19 bytes). Followed by 64 bytes of digest.
pub const SHA512_PREFIX: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Build a DER-encoded `DigestInfo` value for the given hash algorithm + raw
/// digest bytes. Returns `None` if `digest` has the wrong length for the
/// algorithm.
pub fn build_digest_info(hash_alg: HashAlg, digest: &[u8]) -> Option<Vec<u8>> {
    let (prefix, expected_len) = match hash_alg {
        HashAlg::Sha256 => (SHA256_PREFIX, 32usize),
        HashAlg::Sha384 => (SHA384_PREFIX, 48),
        HashAlg::Sha512 => (SHA512_PREFIX, 64),
    };
    if digest.len() != expected_len {
        return None;
    }
    let mut out = Vec::with_capacity(prefix.len() + digest.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(digest);
    Some(out)
}

/// Validate that a pre-computed digest has the correct length for the
/// algorithm. Used by the prehashed PSS / ECDSA paths which sign the raw
/// digest directly (no DigestInfo wrapping).
pub fn expected_digest_len(hash_alg: HashAlg) -> usize {
    match hash_alg {
        HashAlg::Sha256 => 32,
        HashAlg::Sha384 => 48,
        HashAlg::Sha512 => 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_have_expected_lengths() {
        assert_eq!(SHA256_PREFIX.len(), 19);
        assert_eq!(SHA384_PREFIX.len(), 19);
        assert_eq!(SHA512_PREFIX.len(), 19);
    }

    #[test]
    fn build_sha256() {
        let digest = [0xAA; 32];
        let info = build_digest_info(HashAlg::Sha256, &digest).unwrap();
        assert_eq!(info.len(), 51);
        assert_eq!(&info[..19], SHA256_PREFIX);
        assert_eq!(&info[19..], &digest[..]);
    }

    #[test]
    fn build_sha384() {
        let digest = [0xBB; 48];
        let info = build_digest_info(HashAlg::Sha384, &digest).unwrap();
        assert_eq!(info.len(), 67);
        assert_eq!(&info[..19], SHA384_PREFIX);
    }

    #[test]
    fn build_sha512() {
        let digest = [0xCC; 64];
        let info = build_digest_info(HashAlg::Sha512, &digest).unwrap();
        assert_eq!(info.len(), 83);
        assert_eq!(&info[..19], SHA512_PREFIX);
    }

    #[test]
    fn build_rejects_wrong_length() {
        assert!(build_digest_info(HashAlg::Sha256, &[0u8; 31]).is_none());
        assert!(build_digest_info(HashAlg::Sha256, &[0u8; 33]).is_none());
        assert!(build_digest_info(HashAlg::Sha384, &[0u8; 32]).is_none());
        assert!(build_digest_info(HashAlg::Sha512, &[0u8; 0]).is_none());
    }

    #[test]
    fn known_prefix_bytes_match_rfc8017() {
        // Spot-check the OID encoding in each prefix.
        // SHA-256 OID: 2.16.840.1.101.3.4.2.1 → DER 06 09 60 86 48 01 65 03 04 02 01
        assert_eq!(
            &SHA256_PREFIX[4..15],
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
        );
        // SHA-384 OID ends in 0x02 0x02
        assert_eq!(SHA384_PREFIX[14], 0x02);
        // SHA-512 OID ends in 0x02 0x03
        assert_eq!(SHA512_PREFIX[14], 0x03);
    }

    #[test]
    fn expected_digest_len_matches_hash() {
        assert_eq!(expected_digest_len(HashAlg::Sha256), 32);
        assert_eq!(expected_digest_len(HashAlg::Sha384), 48);
        assert_eq!(expected_digest_len(HashAlg::Sha512), 64);
    }
}
