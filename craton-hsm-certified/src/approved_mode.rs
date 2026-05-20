// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! FIPS approved-mode configuration enforcement.
//!
//! Defines the approved algorithm policy for FIPS 140-3 certified operation
//! and validates configurations against that policy.

use crate::error::{CertError, CertResult};
use serde::{Deserialize, Serialize};

/// Configuration defining which algorithms and parameters are permitted
/// in FIPS approved mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedModeConfig {
    /// Minimum RSA key size in bits (FIPS requires >= 2048).
    pub min_rsa_key_bits: u32,
    /// List of approved hash algorithm names (e.g., "SHA-256", "SHA-384", "SHA-512").
    pub allowed_hash_algorithms: Vec<String>,
    /// Allowed symmetric key sizes in bytes (e.g., 24 for AES-192, 32 for AES-256).
    pub allowed_symmetric_key_sizes: Vec<usize>,
    /// Whether SHA-1 is permitted (generally disallowed for signing in FIPS mode).
    pub allow_sha1: bool,
    /// Whether Ed25519 is permitted (not FIPS-approved as of 140-3).
    pub allow_ed25519: bool,
    /// Whether prehashed signing (multi-part `C_SignUpdate`/`C_SignFinal`)
    /// is permitted. Strict-mode policies disable this because the caller
    /// supplies the digest, which precludes the module from enforcing the
    /// hash algorithm itself.
    pub allow_prehashed_signing: bool,
    /// Whether ECDSA-P256 is permitted. Defaults to `true` (FIPS-approved).
    #[serde(default = "default_true")]
    pub allow_ecdsa_p256: bool,
    /// Whether ECDSA-P384 is permitted. Defaults to `true` (FIPS-approved).
    #[serde(default = "default_true")]
    pub allow_ecdsa_p384: bool,
}

fn default_true() -> bool {
    true
}

/// Returns a conservative FIPS 140-3 approved-mode configuration.
///
/// - RSA minimum 2048 bits
/// - SHA-256, SHA-384, SHA-512 only
/// - AES-192 (24 bytes) and AES-256 (32 bytes) only — AES-128 is FIPS-
///   approved by FIPS 197 but is excluded here in favour of stricter
///   conservative defaults
/// - No SHA-1, no Ed25519, no prehashed signing
pub fn default_fips_config() -> ApprovedModeConfig {
    ApprovedModeConfig {
        min_rsa_key_bits: 2048,
        allowed_hash_algorithms: vec![
            "SHA-256".to_string(),
            "SHA-384".to_string(),
            "SHA-512".to_string(),
        ],
        allowed_symmetric_key_sizes: vec![24, 32],
        allow_sha1: false,
        allow_ed25519: false,
        allow_prehashed_signing: false,
        allow_ecdsa_p256: true,
        allow_ecdsa_p384: true,
    }
}

/// The set of hash algorithm names accepted in `allowed_hash_algorithms`.
///
/// Anything outside this set is a configuration violation — `validate_config`
/// rejects values such as `MD5` or `SHA-1` even if a caller mistakenly added
/// them to the list.
const APPROVED_HASH_NAMES: &[&str] = &[
    "SHA-256", "SHA-384", "SHA-512", "SHA2-256", "SHA2-384", "SHA2-512",
];

/// Conservative upper bound on `min_rsa_key_bits`. Anything beyond this is
/// almost certainly a configuration error rather than an intentional choice.
const MAX_REASONABLE_RSA_BITS: u32 = 16384;

/// Validate an approved-mode configuration against FIPS 140-3 policy.
///
/// Returns `Ok(())` if compliant, or [`CertError::InvalidConfig`] containing
/// one human-readable description per policy violation.
pub fn validate_config(config: &ApprovedModeConfig) -> CertResult<()> {
    let mut violations = Vec::new();

    if config.min_rsa_key_bits < 2048 {
        violations.push(format!(
            "RSA minimum key size {} is below FIPS minimum of 2048 bits",
            config.min_rsa_key_bits
        ));
    }
    if config.min_rsa_key_bits > MAX_REASONABLE_RSA_BITS {
        violations.push(format!(
            "RSA minimum key size {} exceeds reasonable upper bound of {} bits",
            config.min_rsa_key_bits, MAX_REASONABLE_RSA_BITS
        ));
    }

    if config.allow_sha1 {
        violations.push("SHA-1 is not approved for signing in FIPS 140-3".to_string());
    }

    if config.allow_ed25519 {
        violations.push("Ed25519 is not a FIPS-approved algorithm".to_string());
    }

    if config.allowed_hash_algorithms.is_empty() {
        violations.push("at least one approved hash algorithm must be configured".to_string());
    }
    // Reject any hash that isn't in the FIPS-approved set. This prevents an
    // operator from sneaking in MD5, SHA-1, or a typo'd custom name.
    for name in &config.allowed_hash_algorithms {
        let upper = name.to_uppercase();
        if !APPROVED_HASH_NAMES.iter().any(|a| *a == upper.as_str()) {
            violations.push(format!(
                "hash algorithm {:?} is not in the FIPS-approved set ({})",
                name,
                APPROVED_HASH_NAMES.join(", ")
            ));
        }
    }

    if config.allowed_symmetric_key_sizes.is_empty() {
        violations.push("at least one approved symmetric key size must be configured".to_string());
    }

    // AES-128 (16-byte keys) is excluded from this strict profile.
    if config.allowed_symmetric_key_sizes.contains(&16) {
        violations
            .push("AES-128 (16-byte keys) is excluded from the strict FIPS profile".to_string());
    }

    // Prehashed signing is conservatively disallowed in strict mode because
    // the caller supplies a digest the module did not compute.
    if config.allow_prehashed_signing {
        violations.push(
            "prehashed signing is disabled in strict FIPS mode (digest is supplied externally)"
                .to_string(),
        );
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(CertError::InvalidConfig(violations))
    }
}

/// The set of supported algorithm mechanisms.
///
/// Returned by [`classify_mechanism`] so callers (and the policy check)
/// don't have to repeat the same string parsing logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// SHA-1 — only approved when `allow_sha1` is set.
    Sha1,
    /// Any SHA-2 hash in `allowed_hash_algorithms`.
    HashApproved,
    /// AES with the given key length in bytes (16/24/32).
    Aes(usize),
    /// RSA with the given modulus size in bits.
    Rsa(u32),
    /// ECDSA over NIST P-256.
    EcdsaP256,
    /// ECDSA over NIST P-384.
    EcdsaP384,
    /// Ed25519 signature scheme.
    Ed25519,
    /// Multi-part / prehashed signing variant of any of the above.
    Prehashed,
    /// Mechanism name did not match any recognised algorithm; treated as
    /// not-approved by [`is_algorithm_approved`].
    Unknown,
}

/// Classify a mechanism string into a [`Mechanism`].
///
/// Mechanism names are matched case-insensitively. The `*-PREHASHED`
/// suffix marks the multi-part-signing variant which is gated by the
/// `allow_prehashed_signing` policy flag.
pub fn classify_mechanism(mechanism: &str, config: &ApprovedModeConfig) -> Mechanism {
    let m = mechanism.to_uppercase();

    if let Some(stripped) = m.strip_suffix("-PREHASHED") {
        // Recurse to classify the underlying algorithm; if the underlying
        // algorithm is itself unknown we surface Unknown so the caller
        // doesn't get a false positive.
        let inner = classify_mechanism(stripped, config);
        return match inner {
            Mechanism::Unknown => Mechanism::Unknown,
            _ => Mechanism::Prehashed,
        };
    }

    if m == "SHA-1" || m == "SHA1" {
        return Mechanism::Sha1;
    }
    // SHA-2 family — but only if it's a bare hash, not a composite like
    // "SHA-256-WITH-RSA" which is a signature mechanism.
    if (m.starts_with("SHA-") || m.starts_with("SHA2-"))
        && !m.contains("WITH")
        && config
            .allowed_hash_algorithms
            .iter()
            .any(|a| a.to_uppercase() == m)
    {
        return Mechanism::HashApproved;
    }
    if m == "ED25519" {
        return Mechanism::Ed25519;
    }
    if let Some(rest) = m.strip_prefix("RSA-") {
        if let Ok(bits) = rest.parse::<u32>() {
            return Mechanism::Rsa(bits);
        }
    }
    if let Some(rest) = m.strip_prefix("AES-") {
        return match rest {
            "128" => Mechanism::Aes(16),
            "192" => Mechanism::Aes(24),
            "256" => Mechanism::Aes(32),
            _ => Mechanism::Unknown,
        };
    }
    if m == "ECDSA-P256" {
        return Mechanism::EcdsaP256;
    }
    if m == "ECDSA-P384" {
        return Mechanism::EcdsaP384;
    }
    Mechanism::Unknown
}

/// Check whether a given algorithm mechanism name is approved under the
/// config. Mechanism names are matched case-insensitively.
///
/// Supported mechanisms:
/// - Hashes: `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512`
/// - Symmetric: `AES-128`, `AES-192`, `AES-256`
/// - Asymmetric: `RSA-2048`, `RSA-3072`, `RSA-4096`, `ECDSA-P256`,
///   `ECDSA-P384`, `Ed25519`
/// - Multi-part variants: append `-PREHASHED` to any of the above
pub fn is_algorithm_approved(mechanism: &str, config: &ApprovedModeConfig) -> bool {
    match classify_mechanism(mechanism, config) {
        Mechanism::Sha1 => config.allow_sha1,
        Mechanism::HashApproved => true,
        Mechanism::Aes(bytes) => config.allowed_symmetric_key_sizes.contains(&bytes),
        Mechanism::Rsa(bits) => bits >= config.min_rsa_key_bits,
        Mechanism::EcdsaP256 => config.allow_ecdsa_p256,
        Mechanism::EcdsaP384 => config.allow_ecdsa_p384,
        Mechanism::Ed25519 => config.allow_ed25519,
        Mechanism::Prehashed => config.allow_prehashed_signing,
        Mechanism::Unknown => false,
    }
}

/// Reason returned by [`enforce_approved_mode`] when a mechanism is
/// rejected. Exposed so callers can distinguish "not-approved" from
/// "unknown-algorithm" in audit logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovedModeRejection {
    /// Algorithm name was recognised but the module's approved-mode config
    /// does not permit it (wrong key size, disabled hash, etc.).
    NotApproved {
        /// The mechanism name that was rejected.
        mechanism: String,
    },
    /// Algorithm name was not recognised at all; fail-closed.
    UnknownAlgorithm {
        /// The mechanism name that did not match any known algorithm.
        mechanism: String,
    },
}

impl std::fmt::Display for ApprovedModeRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApproved { mechanism } => {
                write!(
                    f,
                    "mechanism '{mechanism}' is not approved in the current FIPS mode"
                )
            }
            Self::UnknownAlgorithm { mechanism } => {
                write!(
                    f,
                    "unknown mechanism '{mechanism}' rejected in approved mode"
                )
            }
        }
    }
}

impl std::error::Error for ApprovedModeRejection {}

/// Check whether `mechanism` is approved under `config` and return an error
/// describing the rejection reason if it is not. Backends are expected to
/// call this **before** dispatching any approved-mode crypto operation so
/// that an accidentally permissive backend cannot process a non-approved
/// mechanism regardless of whether the policy layer happened to check
/// first.
///
/// Returns `Ok(())` if the mechanism is approved by `config`, otherwise an
/// [`ApprovedModeRejection`] describing why. This addresses audit finding M3
/// (validator present, no enforcement hook).
///
/// # In-crate use
///
/// This function is wired into the certified-crate's own KAT suite via
/// [`crate::test_harness::approved_mode_preflight`], which calls it for
/// every mechanism the KATs will exercise before any backend dispatch
/// happens. That gives the test harness a single, in-crate proof that the
/// `check_mechanism_approved` policy is being honoured even when no
/// downstream backend has wired it in yet.
///
/// # Backend responsibility
///
/// The `craton-hsm-certified` crate intentionally does not reach into
/// backend crates. Each backend that ships an approved-mode operating
/// posture is also responsible for invoking this function before performing
/// any cryptographic operation in approved mode. Wiring it into the
/// OpenSSL, AWS-LC, NXP, and Infineon backends is tracked in the
/// workspace README.
///
/// `#[must_use]` is set so that an accidental discard of the result
/// (which would silently bypass the check) trips a compiler warning.
///
/// # Example
///
/// ```
/// use craton_hsm_certified::approved_mode::{
///     check_mechanism_approved, default_fips_config, ApprovedModeRejection,
/// };
///
/// let cfg = default_fips_config();
///
/// // Approved primitives pass.
/// check_mechanism_approved("AES-256-GCM", &cfg).expect("AES-256-GCM approved");
///
/// // SHA-1 is rejected under the default FIPS configuration.
/// assert!(matches!(
///     check_mechanism_approved("SHA-1", &cfg),
///     Err(ApprovedModeRejection::NotApproved { .. })
/// ));
/// ```
#[must_use = "the return value indicates whether the mechanism is approved; \
              ignoring it bypasses the approved-mode policy check"]
pub fn check_mechanism_approved(
    mechanism: &str,
    config: &ApprovedModeConfig,
) -> Result<(), ApprovedModeRejection> {
    match classify_mechanism(mechanism, config) {
        Mechanism::Unknown => Err(ApprovedModeRejection::UnknownAlgorithm {
            mechanism: mechanism.to_string(),
        }),
        _ => {
            if is_algorithm_approved(mechanism, config) {
                Ok(())
            } else {
                Err(ApprovedModeRejection::NotApproved {
                    mechanism: mechanism.to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_passes_validation() {
        assert!(validate_config(&default_fips_config()).is_ok());
    }

    #[test]
    fn sha1_rejected_when_not_allowed() {
        let config = default_fips_config();
        assert!(!config.allow_sha1);
        assert!(!is_algorithm_approved("SHA-1", &config));
        assert!(!is_algorithm_approved("SHA1", &config));
    }

    #[test]
    fn sha1_allowed_fails_validation() {
        let mut config = default_fips_config();
        config.allow_sha1 = true;
        let err = validate_config(&config).unwrap_err();
        match err {
            CertError::InvalidConfig(v) => assert!(v.iter().any(|m| m.contains("SHA-1"))),
            _ => panic!(),
        }
    }

    #[test]
    fn rsa_below_2048_rejected() {
        let config = default_fips_config();
        assert!(!is_algorithm_approved("RSA-1024", &config));

        let mut lax = default_fips_config();
        lax.min_rsa_key_bits = 1024;
        assert!(validate_config(&lax).is_err());
    }

    #[test]
    fn rsa_2048_and_above_approved() {
        let config = default_fips_config();
        assert!(is_algorithm_approved("RSA-2048", &config));
        assert!(is_algorithm_approved("RSA-3072", &config));
        assert!(is_algorithm_approved("RSA-4096", &config));
    }

    #[test]
    fn aes_128_rejected_in_strict_mode() {
        let config = default_fips_config();
        assert!(!is_algorithm_approved("AES-128", &config));

        let mut lax = default_fips_config();
        lax.allowed_symmetric_key_sizes.push(16);
        assert!(validate_config(&lax).is_err());
    }

    #[test]
    fn aes_192_and_256_approved() {
        let config = default_fips_config();
        assert!(is_algorithm_approved("AES-192", &config));
        assert!(is_algorithm_approved("AES-256", &config));
    }

    #[test]
    fn ed25519_rejected_by_default() {
        let config = default_fips_config();
        assert!(!is_algorithm_approved("Ed25519", &config));
    }

    #[test]
    fn ecdsa_approved_by_default() {
        let config = default_fips_config();
        assert!(is_algorithm_approved("ECDSA-P256", &config));
        assert!(is_algorithm_approved("ECDSA-P384", &config));
    }

    #[test]
    fn ecdsa_can_be_disabled() {
        let mut config = default_fips_config();
        config.allow_ecdsa_p256 = false;
        assert!(!is_algorithm_approved("ECDSA-P256", &config));
        assert!(is_algorithm_approved("ECDSA-P384", &config));

        config.allow_ecdsa_p384 = false;
        assert!(!is_algorithm_approved("ECDSA-P384", &config));
    }

    #[test]
    fn approved_hash_algorithms() {
        let config = default_fips_config();
        assert!(is_algorithm_approved("SHA-256", &config));
        assert!(is_algorithm_approved("SHA-384", &config));
        assert!(is_algorithm_approved("SHA-512", &config));
    }

    #[test]
    fn prehashed_signing_disabled_by_default() {
        let config = default_fips_config();
        assert!(!is_algorithm_approved("RSA-2048-PREHASHED", &config));
        assert!(!is_algorithm_approved("ECDSA-P256-PREHASHED", &config));
    }

    #[test]
    fn prehashed_signing_enabled_when_flag_set() {
        let mut config = default_fips_config();
        config.allow_prehashed_signing = true;
        // Validation now rejects this in strict mode...
        assert!(validate_config(&config).is_err());
        // ...but the runtime check honours the flag.
        assert!(is_algorithm_approved("RSA-2048-PREHASHED", &config));
    }

    #[test]
    fn unknown_mechanism_rejected() {
        let config = default_fips_config();
        assert!(!is_algorithm_approved("BOGUS-FOO", &config));
        assert!(!is_algorithm_approved("AES-99", &config));
    }

    #[test]
    fn composite_signature_mechanism_not_misclassified_as_hash() {
        // Edge case from the security review.
        let config = default_fips_config();
        assert!(!is_algorithm_approved("SHA-256-WITH-RSA", &config));
    }

    #[test]
    fn validation_rejects_md5_in_allowed_hashes() {
        let mut config = default_fips_config();
        config.allowed_hash_algorithms.push("MD5".to_string());
        let err = validate_config(&config).unwrap_err();
        match err {
            CertError::InvalidConfig(v) => {
                assert!(v.iter().any(|m| m.contains("MD5")));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn validation_rejects_sha1_in_allowed_hashes() {
        // Listing SHA-1 explicitly is a violation regardless of allow_sha1.
        let mut config = default_fips_config();
        config.allowed_hash_algorithms.push("SHA-1".to_string());
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn validation_accepts_sha2_prefixed_names() {
        let mut config = default_fips_config();
        config.allowed_hash_algorithms = vec!["SHA2-256".to_string(), "SHA2-384".to_string()];
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn validation_rejects_unreasonably_large_rsa_minimum() {
        let mut config = default_fips_config();
        config.min_rsa_key_bits = 32_768;
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("violation"));
    }

    #[test]
    fn enforce_approved_mode_accepts_approved() {
        let config = default_fips_config();
        assert!(check_mechanism_approved("AES-256", &config).is_ok());
        assert!(check_mechanism_approved("SHA-256", &config).is_ok());
        assert!(check_mechanism_approved("RSA-2048", &config).is_ok());
    }

    #[test]
    fn enforce_approved_mode_rejects_disallowed() {
        let config = default_fips_config();
        match check_mechanism_approved("Ed25519", &config) {
            Err(ApprovedModeRejection::NotApproved { mechanism }) => {
                assert_eq!(mechanism, "Ed25519");
            }
            other => panic!("expected NotApproved, got {other:?}"),
        }
    }

    #[test]
    fn enforce_approved_mode_rejects_unknown() {
        let config = default_fips_config();
        match check_mechanism_approved("BOGUS", &config) {
            Err(ApprovedModeRejection::UnknownAlgorithm { mechanism }) => {
                assert_eq!(mechanism, "BOGUS");
            }
            other => panic!("expected UnknownAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn classify_mechanism_returns_expected_variants() {
        let config = default_fips_config();
        assert!(matches!(
            classify_mechanism("SHA-256", &config),
            Mechanism::HashApproved
        ));
        assert!(matches!(
            classify_mechanism("AES-256", &config),
            Mechanism::Aes(32)
        ));
        assert!(matches!(
            classify_mechanism("RSA-2048", &config),
            Mechanism::Rsa(2048)
        ));
        assert!(matches!(
            classify_mechanism("ECDSA-P256", &config),
            Mechanism::EcdsaP256
        ));
        assert!(matches!(
            classify_mechanism("ECDSA-P384", &config),
            Mechanism::EcdsaP384
        ));
        assert!(matches!(
            classify_mechanism("Ed25519", &config),
            Mechanism::Ed25519
        ));
        assert!(matches!(
            classify_mechanism("RSA-2048-PREHASHED", &config),
            Mechanism::Prehashed
        ));
        assert!(matches!(
            classify_mechanism("BOGUS", &config),
            Mechanism::Unknown
        ));
    }
}
