// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Tenant data model for multi-tenant HSM deployments.

use serde::{Deserialize, Serialize};

/// Maximum length for a `TenantId` string (bytes).
const MAX_TENANT_ID_LEN: usize = 64;

/// Unique tenant identifier.
///
/// Valid tenant IDs consist only of ASCII alphanumeric characters, hyphens,
/// underscores, and dots (`[A-Za-z0-9._-]+`), must be 1–64 bytes long, must
/// start with an alphanumeric character, and may not contain the `..`
/// substring. Dots are permitted so domain-style identifiers (e.g.
/// `acme.com`, extracted from RFC 822 email SANs) round-trip. The
/// alphanumeric-leading rule keeps `../etc` style payloads out, and the
/// explicit `..` rejection blocks consecutive-dot path-traversal lookalikes
/// even when wrapped in a benign prefix. Other invalid characters (`/`,
/// `:`, NUL, whitespace, etc.) are still rejected, preserving the
/// path-traversal, log-injection, and LDAP-injection guards.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(String);

impl TenantId {
    /// Create a `TenantId` from a trusted string.
    ///
    /// Audit fix 1.3 -- previously this function silently replaced
    /// invalid input with the literal sentinel `"invalid"`, so an
    /// attacker-controlled tenant claim could route many tenants to a
    /// shared bucket. The function now returns `Result<Self, String>`
    /// so the caller is forced to handle malformed input explicitly.
    /// For test scaffolding that knows the literal is well-formed,
    /// see `TenantId::new_or_panic` (only available in test builds).
    pub fn new(id: impl Into<String>) -> Result<Self, String> {
        let s = id.into();
        Self::validate_str(&s)?;
        Ok(Self(s))
    }

    /// Test-only constructor that panics on invalid input. Use only
    /// for static, hard-coded tenant IDs in unit tests where the input
    /// is guaranteed valid by the surrounding code; production code
    /// must always use [`TenantId::new`] or [`TenantId::try_new`].
    #[cfg(test)]
    pub fn new_or_panic(id: impl Into<String>) -> Self {
        let s = id.into();
        match Self::validate_str(&s) {
            Ok(()) => Self(s),
            Err(e) => panic!(
                "TenantId::new_or_panic called with invalid ID {:?}: {}",
                s, e
            ),
        }
    }

    /// Create a validated `TenantId` from user-supplied input.
    ///
    /// Returns `Err` if the ID is empty, exceeds `MAX_TENANT_ID_LEN`,
    /// contains characters outside `[A-Za-z0-9._-]`, does not start with an
    /// alphanumeric character, or contains a `..` substring.
    pub fn try_new(id: impl Into<String>) -> Result<Self, String> {
        let s = id.into();
        Self::validate_str(&s)?;
        Ok(Self(s))
    }

    /// Returns the tenant ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate a raw string as a tenant ID.
    fn validate_str(s: &str) -> Result<(), String> {
        if s.is_empty() {
            return Err("tenant ID must not be empty".to_string());
        }
        if s.len() > MAX_TENANT_ID_LEN {
            return Err(format!(
                "tenant ID exceeds maximum length ({} > {} bytes)",
                s.len(),
                MAX_TENANT_ID_LEN
            ));
        }
        // Must start with an alphanumeric character
        if !s.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            return Err("tenant ID must start with an alphanumeric character".to_string());
        }
        // All characters must be in [A-Za-z0-9._-]. Dots are accepted so
        // domain-style tenant IDs (extracted from email/DNS SANs) round-trip;
        // path-separator and injection-relevant characters remain rejected.
        if let Some(bad) = s
            .chars()
            .find(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.'))
        {
            return Err(format!(
                "tenant ID contains invalid character {:?} — only [A-Za-z0-9._-] are allowed",
                bad
            ));
        }
        // Reject consecutive dots: blocks path-traversal lookalikes like
        // `acme..corp` even when prefixed with a legitimate component.
        if s.contains("..") {
            return Err("tenant ID may not contain consecutive dots".to_string());
        }
        Ok(())
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Cryptographic algorithm mechanisms permitted for a tenant.
///
/// Using an explicit enum prevents misconfiguration from typos in algorithm
/// name strings (`"AES-256-CBB"` would silently be treated as unknown and
/// ignored, potentially allowing stronger algorithms than the operator intended).
/// Each variant maps to a PKCS#11 mechanism category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum AllowedAlgorithm {
    /// AES-256-GCM (authenticated encryption).
    #[serde(alias = "AES-GCM", alias = "aes-gcm", alias = "aes-256-gcm")]
    Aes256Gcm,
    /// AES-256-CBC (unauthenticated; prefer AES-GCM for new deployments).
    #[serde(alias = "AES-CBC", alias = "aes-cbc")]
    Aes256Cbc,
    /// AES-256-CTR (unauthenticated, malleable; use only for streaming protocols).
    #[serde(alias = "AES-CTR", alias = "aes-ctr")]
    Aes256Ctr,
    /// RSA-2048 or larger for sign/verify and key wrapping.
    #[serde(alias = "RSA", alias = "rsa")]
    Rsa,
    /// ECDSA with NIST P-256 or P-384.
    #[serde(alias = "ECDSA", alias = "ecdsa")]
    Ecdsa,
    /// Ed25519 EdDSA signing.
    #[serde(alias = "ED25519", alias = "ed25519")]
    Ed25519,
    /// HMAC-SHA-256 for message authentication.
    #[serde(alias = "HMAC-SHA256", alias = "hmac-sha256")]
    HmacSha256,
}

impl std::fmt::Display for AllowedAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AllowedAlgorithm::Aes256Gcm => "AES-256-GCM",
            AllowedAlgorithm::Aes256Cbc => "AES-256-CBC",
            AllowedAlgorithm::Aes256Ctr => "AES-256-CTR",
            AllowedAlgorithm::Rsa => "RSA",
            AllowedAlgorithm::Ecdsa => "ECDSA",
            AllowedAlgorithm::Ed25519 => "ED25519",
            AllowedAlgorithm::HmacSha256 => "HMAC-SHA256",
        };
        f.write_str(s)
    }
}

/// Configuration for a single tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Maximum number of keys this tenant can store.
    pub max_keys: usize,
    /// Maximum number of concurrent sessions.
    pub max_sessions: u64,
    /// Allowed algorithm mechanisms (if None, all are allowed).
    ///
    /// Using a validated enum prevents misconfiguration from algorithm name typos.
    pub allowed_algorithms: Option<Vec<AllowedAlgorithm>>,
}

impl Default for TenantConfig {
    fn default() -> Self {
        Self {
            max_keys: 10_000,
            max_sessions: 100,
            allowed_algorithms: None,
        }
    }
}

/// A tenant in a multi-tenant HSM deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique identifier.
    pub id: TenantId,
    /// Human-readable name.
    pub name: String,
    /// Tenant configuration (quotas, policies).
    pub config: TenantConfig,
    /// Whether this tenant is active.
    pub enabled: bool,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_tenant_ids() {
        for id in &[
            "acme",
            "acme-corp",
            "acme_corp",
            "tenant123",
            "T1",
            "a",
            // Domain-style IDs extracted from email/DNS SANs.
            "acme.com",
            "sub.acme.io",
        ] {
            assert!(TenantId::try_new(*id).is_ok(), "should accept {:?}", id);
        }
    }

    #[test]
    fn consecutive_dots_rejected() {
        for id in &["acme..corp", "a..", "1..2"] {
            assert!(TenantId::try_new(*id).is_err(), "should reject {:?}", id);
        }
    }

    /// Audit fix 1.3 -- `TenantId::new` now returns `Result` so callers
    /// must handle malformed input rather than silently routing it to a
    /// shared sentinel bucket.
    #[test]
    fn new_returns_error_on_invalid_input() {
        // Path-traversal payload that previously collapsed to "invalid".
        let res = TenantId::new("../etc/passwd");
        assert!(res.is_err(), "new must reject path-traversal payload");
        // Valid input still yields Ok.
        let ok = TenantId::new("acme-corp").expect("valid id must succeed");
        assert_eq!(ok.as_str(), "acme-corp");
    }

    /// `new_or_panic` is the test-only convenience that mirrors the old
    /// `new` behaviour for static literals; it must accept valid input
    /// and panic loudly on invalid input.
    #[test]
    #[should_panic(expected = "new_or_panic")]
    fn new_or_panic_panics_on_invalid_input() {
        let _ = TenantId::new_or_panic("");
    }

    #[test]
    fn empty_tenant_id_rejected() {
        assert!(TenantId::try_new("").is_err());
    }

    #[test]
    fn too_long_tenant_id_rejected() {
        let long = "a".repeat(MAX_TENANT_ID_LEN + 1);
        assert!(TenantId::try_new(long).is_err());
    }

    #[test]
    fn invalid_chars_rejected() {
        for id in &[
            "acme corp",
            "acme/corp",
            "acme:corp",
            "acme\0corp",
            "../etc",
        ] {
            assert!(TenantId::try_new(*id).is_err(), "should reject {:?}", id);
        }
    }

    #[test]
    fn must_start_with_alphanumeric() {
        assert!(TenantId::try_new("-acme").is_err());
        assert!(TenantId::try_new("_acme").is_err());
    }

    #[test]
    fn exact_max_length_accepted() {
        let id = "a".repeat(MAX_TENANT_ID_LEN);
        assert!(TenantId::try_new(id).is_ok());
    }

    #[test]
    fn allowed_algorithm_serde_roundtrip() {
        let algs = vec![AllowedAlgorithm::Aes256Gcm, AllowedAlgorithm::Ed25519];
        let json = serde_json::to_string(&algs).unwrap();
        let parsed: Vec<AllowedAlgorithm> = serde_json::from_str(&json).unwrap();
        assert_eq!(algs, parsed);
    }

    #[test]
    fn allowed_algorithm_alias_deserialization() {
        // Test that lowercase aliases deserialize correctly
        let json = r#""aes-gcm""#;
        let alg: AllowedAlgorithm = serde_json::from_str(json).unwrap();
        assert_eq!(alg, AllowedAlgorithm::Aes256Gcm);
    }

    #[test]
    fn tenant_config_default_allows_all_algorithms() {
        let cfg = TenantConfig::default();
        assert!(
            cfg.allowed_algorithms.is_none(),
            "default should allow all algorithms"
        );
    }
}
