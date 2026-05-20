// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! CMVP artifact generation scaffolding.
//!
//! Provides types and functions for generating Cryptographic Module Validation
//! Program (CMVP) submission artifacts, including module manifests and test
//! evidence packages.

use crate::error::{CertError, CertResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level CMVP module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmvpConfig {
    /// Name of the cryptographic module (e.g., "Craton HSM").
    pub module_name: String,
    /// Module version string.
    pub module_version: String,
    /// Vendor / organization name.
    pub vendor_name: String,
    /// FIPS 140-3 security level (1-4).
    pub fips_level: u8,
    /// Algorithms included in the module.
    pub algorithms: Vec<CmvpAlgorithm>,
}

/// A single algorithm entry in the CMVP module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmvpAlgorithm {
    /// Algorithm name (e.g., "AES-GCM", "SHA-256", "RSA").
    pub name: String,
    /// CAVP certificate number, if already certified.
    pub cavp_cert_number: Option<String>,
    /// Supported key sizes in bits.
    pub key_sizes: Vec<u32>,
}

/// Result of a single certification test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Name of the test (e.g., "SHA-256 KAT").
    pub test_name: String,
    /// Whether the test passed.
    pub passed: bool,
    /// Human-readable details or error message.
    pub details: String,
}

/// Validate a [`CmvpConfig`], collecting every violation into a single
/// [`CertError::InvalidConfig`].
///
/// Checks performed:
/// - `fips_level` is in the inclusive range 1..=4
/// - `module_name`, `vendor_name`, `module_version` are non-empty after trim
/// - `algorithms` is non-empty
/// - each algorithm has a non-empty `name`
/// - any declared `key_sizes` are non-zero
pub fn validate_cmvp_config(config: &CmvpConfig) -> CertResult<()> {
    let mut violations = Vec::new();
    if !(1..=4).contains(&config.fips_level) {
        violations.push(format!(
            "invalid fips_level {}: must be between 1 and 4 inclusive",
            config.fips_level
        ));
    }
    if config.module_name.trim().is_empty() {
        violations.push("module_name must not be empty".to_string());
    }
    if config.vendor_name.trim().is_empty() {
        violations.push("vendor_name must not be empty".to_string());
    }
    if config.module_version.trim().is_empty() {
        violations.push("module_version must not be empty".to_string());
    }
    if config.algorithms.is_empty() {
        violations.push("at least one algorithm must be configured".to_string());
    }
    for (i, alg) in config.algorithms.iter().enumerate() {
        if alg.name.trim().is_empty() {
            violations.push(format!("algorithm[{i}].name must not be empty"));
        }
        for (j, &bits) in alg.key_sizes.iter().enumerate() {
            if bits == 0 {
                violations.push(format!(
                    "algorithm[{i}] ({}) has zero-bit key_size at index {j}",
                    alg.name
                ));
            }
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(CertError::InvalidConfig(violations))
    }
}

/// Generate a JSON manifest string for the CMVP module configuration.
///
/// Returns `Err` if the configuration is invalid (see [`validate_cmvp_config`]).
pub fn generate_artifact_manifest(config: &CmvpConfig) -> CertResult<String> {
    validate_cmvp_config(config)?;
    Ok(serde_json::to_string_pretty(config)?)
}

/// Write a file with restrictive permissions (0o600 on Unix) so submission
/// artifacts are not world-readable. On Windows the file inherits ACLs from
/// the parent directory; this is the best we can do portably.
fn write_restricted(path: &Path, contents: &[u8]) -> CertResult<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Write CMVP test evidence to the given output directory.
///
/// Creates two files:
/// - `manifest.json` — the module configuration
/// - `results.json` — the test results array
///
/// On Unix, both files are written with mode `0o600` so credentials embedded in
/// the configuration are not world-readable.
///
/// Returns `Err` if the config is invalid or any file I/O fails.
pub fn package_test_evidence(
    output_dir: &Path,
    config: &CmvpConfig,
    results: &[TestResult],
) -> CertResult<()> {
    validate_cmvp_config(config)?;

    std::fs::create_dir_all(output_dir)?;

    let manifest_json = serde_json::to_vec_pretty(config)?;
    write_restricted(&output_dir.join("manifest.json"), &manifest_json)?;

    let results_json = serde_json::to_vec_pretty(results)?;
    write_restricted(&output_dir.join("results.json"), &results_json)?;

    Ok(())
}

/// Returns a default CMVP configuration template for Craton HSM.
pub fn default_cmvp_config() -> CmvpConfig {
    CmvpConfig {
        module_name: "Craton HSM".to_string(),
        module_version: env!("CARGO_PKG_VERSION").to_string(),
        vendor_name: "Craton Software Company".to_string(),
        fips_level: 1,
        algorithms: vec![
            CmvpAlgorithm {
                name: "AES-GCM".to_string(),
                cavp_cert_number: None,
                key_sizes: vec![192, 256],
            },
            CmvpAlgorithm {
                name: "SHA-256".to_string(),
                cavp_cert_number: None,
                key_sizes: vec![],
            },
            CmvpAlgorithm {
                name: "SHA-384".to_string(),
                cavp_cert_number: None,
                key_sizes: vec![],
            },
            CmvpAlgorithm {
                name: "SHA-512".to_string(),
                cavp_cert_number: None,
                key_sizes: vec![],
            },
            CmvpAlgorithm {
                name: "RSA".to_string(),
                cavp_cert_number: None,
                key_sizes: vec![2048, 3072, 4096],
            },
            CmvpAlgorithm {
                name: "ECDSA".to_string(),
                cavp_cert_number: None,
                key_sizes: vec![256, 384],
            },
            CmvpAlgorithm {
                name: "HMAC-SHA256".to_string(),
                cavp_cert_number: None,
                key_sizes: vec![],
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_generation_produces_valid_json() {
        let config = default_cmvp_config();
        let json = generate_artifact_manifest(&config).unwrap();

        // Must parse back successfully
        let parsed: CmvpConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.module_name, "Craton HSM");
        assert_eq!(parsed.fips_level, 1);
        assert!(!parsed.algorithms.is_empty());
    }

    #[test]
    fn fips_level_zero_rejected() {
        let mut config = default_cmvp_config();
        config.fips_level = 0;
        assert!(generate_artifact_manifest(&config).is_err());
        assert!(validate_cmvp_config(&config).is_err());
    }

    #[test]
    fn fips_level_five_rejected() {
        let mut config = default_cmvp_config();
        config.fips_level = 5;
        assert!(generate_artifact_manifest(&config).is_err());
    }

    #[test]
    fn fips_level_four_accepted() {
        let mut config = default_cmvp_config();
        config.fips_level = 4;
        assert!(validate_cmvp_config(&config).is_ok());
    }

    #[test]
    fn empty_module_name_rejected() {
        let mut config = default_cmvp_config();
        config.module_name = "  ".to_string();
        assert!(validate_cmvp_config(&config).is_err());
    }

    #[test]
    fn empty_vendor_name_rejected() {
        let mut config = default_cmvp_config();
        config.vendor_name = "".to_string();
        assert!(validate_cmvp_config(&config).is_err());
    }

    #[test]
    fn default_module_version_matches_crate_version() {
        let config = default_cmvp_config();
        assert_eq!(config.module_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_evidence_packaging_writes_expected_files() {
        let dir = tempfile::tempdir().unwrap();
        let config = default_cmvp_config();
        let results = vec![
            TestResult {
                test_name: "SHA-256 KAT".to_string(),
                passed: true,
                details: "Known-answer test passed".to_string(),
            },
            TestResult {
                test_name: "AES-GCM roundtrip".to_string(),
                passed: true,
                details: "Encrypt/decrypt roundtrip succeeded".to_string(),
            },
        ];

        package_test_evidence(dir.path(), &config, &results).unwrap();

        let manifest_path = dir.path().join("manifest.json");
        let results_path = dir.path().join("results.json");

        assert!(manifest_path.exists());
        assert!(results_path.exists());

        // Verify manifest content
        let manifest_content = std::fs::read_to_string(&manifest_path).unwrap();
        let parsed_config: CmvpConfig = serde_json::from_str(&manifest_content).unwrap();
        assert_eq!(parsed_config.module_name, "Craton HSM");

        // Verify results content
        let results_content = std::fs::read_to_string(&results_path).unwrap();
        let parsed_results: Vec<TestResult> = serde_json::from_str(&results_content).unwrap();
        assert_eq!(parsed_results.len(), 2);
        assert!(parsed_results[0].passed);
    }

    #[cfg(unix)]
    #[test]
    fn evidence_files_are_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let config = default_cmvp_config();
        package_test_evidence(dir.path(), &config, &[]).unwrap();
        for name in ["manifest.json", "results.json"] {
            let mode = std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode, 0o600,
                "{} permissions should be 0o600, got {:o}",
                name, mode
            );
        }
    }

    #[test]
    fn invalid_config_rejected_by_package_test_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = default_cmvp_config();
        config.fips_level = 0;
        assert!(package_test_evidence(dir.path(), &config, &[]).is_err());
    }

    #[test]
    fn empty_algorithms_rejected() {
        let mut config = default_cmvp_config();
        config.algorithms.clear();
        let err = validate_cmvp_config(&config).unwrap_err();
        match err {
            CertError::InvalidConfig(v) => {
                assert!(v.iter().any(|m| m.contains("at least one algorithm")));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn algorithm_with_empty_name_rejected() {
        let mut config = default_cmvp_config();
        config.algorithms[0].name = "  ".to_string();
        assert!(validate_cmvp_config(&config).is_err());
    }

    #[test]
    fn algorithm_with_zero_key_size_rejected() {
        let mut config = default_cmvp_config();
        config.algorithms[0].key_sizes.push(0);
        let err = validate_cmvp_config(&config).unwrap_err();
        match err {
            CertError::InvalidConfig(v) => {
                assert!(v.iter().any(|m| m.contains("zero-bit")));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn validation_collects_multiple_violations() {
        let mut config = default_cmvp_config();
        config.fips_level = 0;
        config.module_name = String::new();
        config.algorithms.clear();
        let err = validate_cmvp_config(&config).unwrap_err();
        match err {
            CertError::InvalidConfig(v) => assert!(v.len() >= 3),
            _ => panic!(),
        }
    }

    #[test]
    fn default_config_has_required_algorithms() {
        let config = default_cmvp_config();
        let names: Vec<&str> = config.algorithms.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"AES-GCM"));
        assert!(names.contains(&"SHA-256"));
        assert!(names.contains(&"RSA"));
        assert!(names.contains(&"ECDSA"));
    }
}
