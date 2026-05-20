// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Unified error type for the certified crate.
//!
//! Replaces the previous `Result<_, String>` pattern with a typed enum so
//! callers can match on specific failure modes (key length, I/O, hex decode,
//! HMAC verification failure, malformed footer, …) and so we can preserve
//! source errors via `?`.

use thiserror::Error;

/// Result alias for the certified crate.
pub type CertResult<T> = Result<T, CertError>;

/// All errors produced by the `craton-hsm-certified` crate.
#[derive(Debug, Error)]
pub enum CertError {
    /// HMAC key shorter than [`crate::integrity::MIN_HMAC_KEY_BYTES`].
    #[error("HMAC key too short: {actual} bytes (minimum {minimum})")]
    KeyTooShort {
        /// Length of the supplied key, in bytes.
        actual: usize,
        /// Minimum acceptable key length, in bytes.
        minimum: usize,
    },

    /// HMAC verification failed (tag mismatch).
    #[error("HMAC verification failed")]
    HmacMismatch,

    /// Hex decoding failed.
    #[error("hex decode error: {0}")]
    HexDecode(String),

    /// Underlying I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Signed-binary envelope is malformed (truncated, magic missing,
    /// declared length out of range, nested footer, …).
    #[error("malformed signed-binary envelope: {0}")]
    BadEnvelope(&'static str),

    /// Configuration validation failed; the inner vector contains one
    /// human-readable description per violation.
    #[error("configuration is invalid: {} violation(s)", .0.len())]
    InvalidConfig(Vec<String>),

    /// Backend cryptographic operation failed.
    #[error("backend error: {0}")]
    Backend(String),

    /// Generic catch-all for cases that should not occur in practice.
    #[error("{0}")]
    Other(String),
}

impl CertError {
    /// Convenience constructor for [`CertError::KeyTooShort`].
    pub fn key_too_short(actual: usize, minimum: usize) -> Self {
        CertError::KeyTooShort { actual, minimum }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_too_short_display() {
        let e = CertError::key_too_short(8, 32);
        assert!(e.to_string().contains("8"));
        assert!(e.to_string().contains("32"));
    }

    #[test]
    fn invalid_config_count_in_message() {
        let e = CertError::InvalidConfig(vec!["a".into(), "b".into(), "c".into()]);
        assert!(e.to_string().contains("3 violation"));
    }

    #[test]
    fn from_io_error_works() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let e: CertError = io.into();
        assert!(matches!(e, CertError::Io(_)));
    }

    #[test]
    fn hmac_mismatch_display() {
        let e = CertError::HmacMismatch;
        assert_eq!(e.to_string(), "HMAC verification failed");
    }
}
