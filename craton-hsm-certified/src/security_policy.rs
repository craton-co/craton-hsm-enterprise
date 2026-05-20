// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! FIPS 140-3 Security Policy document generator.
//!
//! Generates the Security Policy document required for CMVP submission.
//! The Security Policy describes the cryptographic module's specification,
//! interfaces, roles, services, physical security, and operational environment.

use crate::error::{CertError, CertResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Security Policy section identifiers per FIPS 140-3 / ISO 19790.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityPolicySection {
    /// Module Specification — boundary, version, validated config.
    ModuleSpecification,
    /// Cryptographic Module — hardware, firmware, software components.
    CryptographicModule,
    /// Module Interfaces — data, control, status, and power ports.
    ModuleInterfaces,
    /// Roles, Services, and Authentication.
    RolesAndServices,
    /// Physical Security — tamper evidence/response requirements.
    PhysicalSecurity,
    /// Operational Environment — non-modifiable / modifiable OE rules.
    OperationalEnvironment,
    /// Cryptographic Key Management — generation, distribution, zeroisation.
    CryptographicKeyManagement,
    /// Self-Tests — power-on, conditional, and periodic tests.
    SelfTests,
    /// Design Assurance — configuration management, delivery, guidance.
    DesignAssurance,
    /// Mitigation of Other Attacks — non-invasive, side-channel countermeasures.
    MitigationOfOtherAttacks,
    /// Life-Cycle Assurance — process, secure operation, vendor testing.
    LifeCycleAssurance,
}

impl SecurityPolicySection {
    /// Return the human-readable title for this section.
    pub fn title(&self) -> &'static str {
        match self {
            Self::ModuleSpecification => "Module Specification",
            Self::CryptographicModule => "Cryptographic Module",
            Self::ModuleInterfaces => "Module Interfaces",
            Self::RolesAndServices => "Roles and Services",
            Self::PhysicalSecurity => "Physical Security",
            Self::OperationalEnvironment => "Operational Environment",
            Self::CryptographicKeyManagement => "Cryptographic Key Management",
            Self::SelfTests => "Self-Tests",
            Self::DesignAssurance => "Design Assurance",
            Self::MitigationOfOtherAttacks => "Mitigation of Other Attacks",
            Self::LifeCycleAssurance => "Life-Cycle Assurance",
        }
    }

    /// All sections in the canonical order.
    pub fn all() -> &'static [SecurityPolicySection] {
        &[
            Self::ModuleSpecification,
            Self::CryptographicModule,
            Self::ModuleInterfaces,
            Self::RolesAndServices,
            Self::PhysicalSecurity,
            Self::OperationalEnvironment,
            Self::CryptographicKeyManagement,
            Self::SelfTests,
            Self::DesignAssurance,
            Self::MitigationOfOtherAttacks,
            Self::LifeCycleAssurance,
        ]
    }
}

/// Algorithm entry for the Security Policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAlgorithm {
    /// Algorithm name (e.g. `"AES-GCM"`).
    pub name: String,
    /// Standard or specification reference (e.g. `"FIPS 197"`).
    pub standard: String,
    /// Approved key sizes, in bits.
    pub key_sizes: Vec<u32>,
    /// CAVP certificate number, if issued.
    pub cavp_cert: Option<String>,
}

/// Role definition for FIPS 140-3 roles and services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRole {
    /// Role name (e.g. `"Crypto Officer"`).
    pub name: String,
    /// Human-readable role description.
    pub description: String,
    /// Services this role is authorized to invoke.
    pub services: Vec<String>,
}

/// Port/interface definition for the module boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInterface {
    /// Interface name.
    pub name: String,
    /// Interface category (control, data in, data out, status).
    pub interface_type: String,
    /// Human-readable description.
    pub description: String,
}

/// Self-test definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySelfTest {
    /// Self-test name.
    pub name: String,
    /// Test category (e.g. KAT, integrity, pairwise consistency).
    pub test_type: String,
    /// Algorithm exercised by the test.
    pub algorithm: String,
}

/// Configuration for generating the FIPS 140-3 Security Policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicyConfig {
    /// Module name (e.g., "Craton HSM").
    pub module_name: String,
    /// Module version.
    pub module_version: String,
    /// Vendor name.
    pub vendor_name: String,
    /// FIPS 140-3 security level (1-4).
    pub fips_level: u8,
    /// Module type description.
    pub module_type: String,
    /// Approved algorithms.
    pub algorithms: Vec<PolicyAlgorithm>,
    /// Logical/physical interfaces.
    pub interfaces: Vec<PolicyInterface>,
    /// Defined roles.
    pub roles: Vec<PolicyRole>,
    /// Self-tests.
    pub self_tests: Vec<PolicySelfTest>,
    /// Physical security description.
    pub physical_security: String,
    /// Operational environment description.
    pub operational_environment: String,
}

/// A generated Security Policy document.
#[derive(Debug, Clone)]
pub struct SecurityPolicyDocument {
    /// Document title.
    pub title: String,
    /// Section entries, each paired with its rendered body text.
    pub sections: Vec<(SecurityPolicySection, String)>,
}

impl SecurityPolicyDocument {
    /// Render the Security Policy as a Markdown string.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# {}\n\n", self.title));

        for (i, (section, content)) in self.sections.iter().enumerate() {
            md.push_str(&format!("## {}. {}\n\n", i + 1, section.title()));
            md.push_str(content);
            md.push_str("\n\n");
        }
        md
    }
}

// ---------------------------------------------------------------------------
// Default config for Craton HSM Level 1
// ---------------------------------------------------------------------------

/// Returns a default Security Policy configuration for Craton HSM Level 1.
pub fn default_security_policy_config() -> SecurityPolicyConfig {
    SecurityPolicyConfig {
        module_name: "Craton HSM".to_string(),
        module_version: env!("CARGO_PKG_VERSION").to_string(),
        vendor_name: "Craton Software Company".to_string(),
        fips_level: 1,
        module_type: "Software".to_string(),
        algorithms: vec![
            PolicyAlgorithm {
                name: "AES-GCM".to_string(),
                standard: "FIPS 197 / SP 800-38D".to_string(),
                key_sizes: vec![192, 256],
                cavp_cert: None,
            },
            PolicyAlgorithm {
                name: "SHA-256".to_string(),
                standard: "FIPS 180-4".to_string(),
                key_sizes: vec![],
                cavp_cert: None,
            },
            PolicyAlgorithm {
                name: "SHA-384".to_string(),
                standard: "FIPS 180-4".to_string(),
                key_sizes: vec![],
                cavp_cert: None,
            },
            PolicyAlgorithm {
                name: "SHA-512".to_string(),
                standard: "FIPS 180-4".to_string(),
                key_sizes: vec![],
                cavp_cert: None,
            },
            PolicyAlgorithm {
                name: "RSA".to_string(),
                standard: "FIPS 186-5".to_string(),
                key_sizes: vec![2048, 3072, 4096],
                cavp_cert: None,
            },
            PolicyAlgorithm {
                name: "ECDSA".to_string(),
                standard: "FIPS 186-5".to_string(),
                key_sizes: vec![256, 384],
                cavp_cert: None,
            },
            PolicyAlgorithm {
                name: "HMAC-SHA256".to_string(),
                standard: "FIPS 198-1".to_string(),
                key_sizes: vec![],
                cavp_cert: None,
            },
        ],
        interfaces: vec![
            PolicyInterface {
                name: "PKCS#11 API".to_string(),
                interface_type: "Data Input/Output".to_string(),
                description: "Logical interface for cryptographic service requests and responses via PKCS#11 C_* function calls.".to_string(),
            },
            PolicyInterface {
                name: "Control Input".to_string(),
                interface_type: "Control".to_string(),
                description: "Commands for module initialization, self-test invocation, and zeroization.".to_string(),
            },
            PolicyInterface {
                name: "Status Output".to_string(),
                interface_type: "Status".to_string(),
                description: "Module status indicators including operational state and error conditions.".to_string(),
            },
        ],
        roles: vec![
            PolicyRole {
                name: "Crypto Officer".to_string(),
                description: "Responsible for module initialization, configuration, and key management operations.".to_string(),
                services: vec![
                    "Module initialization".to_string(),
                    "Key generation".to_string(),
                    "Key import/export".to_string(),
                    "Self-test invocation".to_string(),
                    "Zeroization".to_string(),
                ],
            },
            PolicyRole {
                name: "User".to_string(),
                description: "Performs cryptographic operations using keys managed by the Crypto Officer.".to_string(),
                services: vec![
                    "Encryption/Decryption".to_string(),
                    "Signing/Verification".to_string(),
                    "Hashing".to_string(),
                    "Key wrapping/unwrapping".to_string(),
                ],
            },
        ],
        self_tests: vec![
            PolicySelfTest {
                name: "SHA-256 KAT".to_string(),
                test_type: "Known Answer Test".to_string(),
                algorithm: "SHA-256".to_string(),
            },
            PolicySelfTest {
                name: "SHA-384 KAT".to_string(),
                test_type: "Known Answer Test".to_string(),
                algorithm: "SHA-384".to_string(),
            },
            PolicySelfTest {
                name: "SHA-512 KAT".to_string(),
                test_type: "Known Answer Test".to_string(),
                algorithm: "SHA-512".to_string(),
            },
            PolicySelfTest {
                name: "AES-256-GCM KAT".to_string(),
                test_type: "Known Answer Test".to_string(),
                algorithm: "AES-GCM".to_string(),
            },
            PolicySelfTest {
                name: "HMAC-SHA256 integrity".to_string(),
                test_type: "Software Integrity Test".to_string(),
                algorithm: "HMAC-SHA256".to_string(),
            },
        ],
        physical_security: "Not applicable. Craton HSM is a Level 1 software-only cryptographic module with no physical security mechanisms. The module relies on the security of the operational environment.".to_string(),
        operational_environment: "The module operates in a modifiable operational environment consisting of a general-purpose computer running a supported operating system. The operating system must enforce single-operator mode and restrict process memory access.".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

fn generate_module_specification(config: &SecurityPolicyConfig) -> String {
    format!(
        "**Module Name:** {}\n\n\
         **Module Version:** {}\n\n\
         **Vendor:** {}\n\n\
         **Module Type:** {}\n\n\
         **FIPS 140-3 Overall Security Level:** {}\n\n\
         This document defines the Security Policy for the {} cryptographic module.",
        config.module_name,
        config.module_version,
        config.vendor_name,
        config.module_type,
        config.fips_level,
        config.module_name,
    )
}

fn generate_cryptographic_module(config: &SecurityPolicyConfig) -> String {
    let mut s = format!(
        "The {} is a {} cryptographic module validated at FIPS 140-3 Level {}.\n\n",
        config.module_name, config.module_type, config.fips_level
    );
    s.push_str("**Approved Algorithms:**\n\n");
    s.push_str("| Algorithm | Standard | Key Sizes | CAVP Cert |\n");
    s.push_str("|-----------|----------|-----------|----------|\n");
    for alg in &config.algorithms {
        let sizes = if alg.key_sizes.is_empty() {
            "N/A".to_string()
        } else {
            alg.key_sizes
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let cert = alg.cavp_cert.as_deref().unwrap_or("Pending");
        s.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            alg.name, alg.standard, sizes, cert
        ));
    }
    s
}

fn generate_module_interfaces(config: &SecurityPolicyConfig) -> String {
    let mut s = String::from("The module defines the following logical interfaces:\n\n");
    for iface in &config.interfaces {
        s.push_str(&format!(
            "- **{} ({}):** {}\n",
            iface.name, iface.interface_type, iface.description
        ));
    }
    s
}

fn generate_roles_and_services(config: &SecurityPolicyConfig) -> String {
    let mut s = String::from("The module supports the following roles:\n\n");
    for role in &config.roles {
        s.push_str(&format!(
            "### {}\n\n{}\n\n**Services:**\n\n",
            role.name, role.description
        ));
        for svc in &role.services {
            s.push_str(&format!("- {}\n", svc));
        }
        s.push('\n');
    }
    s
}

fn generate_self_tests(config: &SecurityPolicyConfig) -> String {
    let mut s = String::from(
        "The module performs the following self-tests at power-up and on demand:\n\n\
         | Test Name | Type | Algorithm |\n\
         |-----------|------|----------|\n",
    );
    for test in &config.self_tests {
        s.push_str(&format!(
            "| {} | {} | {} |\n",
            test.name, test.test_type, test.algorithm
        ));
    }
    s.push_str("\nIf any self-test fails, the module enters the Error state and disables all cryptographic services.\n");
    s
}

/// Generate a complete Security Policy document from the given configuration.
pub fn generate_security_policy(config: &SecurityPolicyConfig) -> SecurityPolicyDocument {
    let sections = vec![
        (SecurityPolicySection::ModuleSpecification, generate_module_specification(config)),
        (SecurityPolicySection::CryptographicModule, generate_cryptographic_module(config)),
        (SecurityPolicySection::ModuleInterfaces, generate_module_interfaces(config)),
        (SecurityPolicySection::RolesAndServices, generate_roles_and_services(config)),
        (SecurityPolicySection::PhysicalSecurity, config.physical_security.clone()),
        (SecurityPolicySection::OperationalEnvironment, config.operational_environment.clone()),
        (
            SecurityPolicySection::CryptographicKeyManagement,
            format!(
                "All cryptographic keys are generated using FIPS-approved random number generators. \
                 Keys are stored in volatile memory and zeroized when the module is powered off or \
                 when zeroization is explicitly invoked. Key import and export use FIPS-approved \
                 key wrapping mechanisms (AES Key Wrap per SP 800-38F)."
            ),
        ),
        (SecurityPolicySection::SelfTests, generate_self_tests(config)),
        (
            SecurityPolicySection::DesignAssurance,
            format!(
                "The {} module follows a secure development lifecycle with configuration management, \
                 code review, and automated testing. The source code is maintained in a version-controlled \
                 repository with access controls.",
                config.module_name,
            ),
        ),
        (
            SecurityPolicySection::MitigationOfOtherAttacks,
            "The module does not claim mitigation of any attacks beyond the scope of FIPS 140-3.".to_string(),
        ),
        (
            SecurityPolicySection::LifeCycleAssurance,
            format!(
                "The {} module employs reproducible builds to ensure binary integrity. \
                 Build artifacts are verified via HMAC-SHA256 integrity tags. \
                 The module version and build metadata are embedded in signed binaries.",
                config.module_name,
            ),
        ),
    ];

    SecurityPolicyDocument {
        title: format!("{} FIPS 140-3 Security Policy", config.module_name),
        sections,
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a [`SecurityPolicyConfig`].
///
/// Mirrors the validation pattern used by [`crate::cmvp::validate_cmvp_config`]:
/// collects every violation into a single [`CertError::InvalidConfig`] so the
/// caller sees the full picture instead of one-error-at-a-time.
pub fn validate_security_policy_config(config: &SecurityPolicyConfig) -> CertResult<()> {
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
    if config.module_version.trim().is_empty() {
        violations.push("module_version must not be empty".to_string());
    }
    if config.vendor_name.trim().is_empty() {
        violations.push("vendor_name must not be empty".to_string());
    }
    if config.module_type.trim().is_empty() {
        violations.push("module_type must not be empty".to_string());
    }
    if config.algorithms.is_empty() {
        violations.push("at least one approved algorithm must be configured".to_string());
    }
    for (i, alg) in config.algorithms.iter().enumerate() {
        if alg.name.trim().is_empty() {
            violations.push(format!("algorithm[{i}].name must not be empty"));
        }
        if alg.standard.trim().is_empty() {
            violations.push(format!("algorithm[{i}].standard must not be empty"));
        }
    }
    if config.roles.is_empty() {
        violations.push("at least one role must be defined".to_string());
    }
    for (i, role) in config.roles.iter().enumerate() {
        if role.name.trim().is_empty() {
            violations.push(format!("role[{i}].name must not be empty"));
        }
        if role.services.is_empty() {
            violations.push(format!("role[{i}] ({}) has no services", role.name));
        }
    }
    if config.interfaces.is_empty() {
        violations.push("at least one interface must be defined".to_string());
    }
    if config.self_tests.is_empty() {
        violations.push("at least one self-test must be defined".to_string());
    }
    if config.physical_security.trim().is_empty() {
        violations.push("physical_security description must not be empty".to_string());
    }
    if config.operational_environment.trim().is_empty() {
        violations.push("operational_environment description must not be empty".to_string());
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(CertError::InvalidConfig(violations))
    }
}

// ---------------------------------------------------------------------------
// Packaging
// ---------------------------------------------------------------------------

/// Generate the Security Policy from `config` and write it to
/// `output_dir/security_policy.md`. The directory is created if it does not
/// exist.
///
/// Returns the path of the written file on success.
///
/// On Unix the file is written with mode `0o644`; the Security Policy is a
/// public document and is intentionally world-readable, unlike the CMVP
/// evidence files which contain configuration metadata and are written
/// `0o600`.
pub fn package_security_policy(
    output_dir: &Path,
    config: &SecurityPolicyConfig,
) -> CertResult<std::path::PathBuf> {
    validate_security_policy_config(config)?;
    std::fs::create_dir_all(output_dir)?;

    let doc = generate_security_policy(config);
    let path = output_dir.join("security_policy.md");
    std::fs::write(&path, doc.to_markdown())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms)?;
    }

    Ok(path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_sections_generated() {
        let config = default_security_policy_config();
        let doc = generate_security_policy(&config);
        let generated_sections: Vec<_> = doc.sections.iter().map(|(s, _)| *s).collect();
        for section in SecurityPolicySection::all() {
            assert!(
                generated_sections.contains(section),
                "missing section: {:?}",
                section
            );
        }
    }

    #[test]
    fn markdown_rendering_has_title() {
        let config = default_security_policy_config();
        let doc = generate_security_policy(&config);
        let md = doc.to_markdown();
        assert!(md.starts_with("# Craton HSM FIPS 140-3 Security Policy\n"));
    }

    #[test]
    fn markdown_rendering_has_all_section_headers() {
        let config = default_security_policy_config();
        let doc = generate_security_policy(&config);
        let md = doc.to_markdown();
        for section in SecurityPolicySection::all() {
            assert!(
                md.contains(section.title()),
                "markdown missing section: {}",
                section.title()
            );
        }
    }

    #[test]
    fn markdown_contains_module_name() {
        let config = default_security_policy_config();
        let doc = generate_security_policy(&config);
        let md = doc.to_markdown();
        assert!(md.contains("Craton HSM"));
        assert!(md.contains("Craton Software Company"));
    }

    #[test]
    fn custom_module_name() {
        let mut config = default_security_policy_config();
        config.module_name = "CustomHSM".to_string();
        config.vendor_name = "Custom Vendor".to_string();
        let doc = generate_security_policy(&config);
        assert_eq!(doc.title, "CustomHSM FIPS 140-3 Security Policy");
        let md = doc.to_markdown();
        assert!(md.contains("CustomHSM"));
        assert!(md.contains("Custom Vendor"));
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = default_security_policy_config();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SecurityPolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.module_name, config.module_name);
        assert_eq!(parsed.fips_level, config.fips_level);
        assert_eq!(parsed.algorithms.len(), config.algorithms.len());
        assert_eq!(parsed.roles.len(), config.roles.len());
    }

    #[test]
    fn section_titles_unique() {
        let all = SecurityPolicySection::all();
        let titles: Vec<_> = all.iter().map(|s| s.title()).collect();
        let mut deduped = titles.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            titles.len(),
            deduped.len(),
            "duplicate section titles found"
        );
    }

    #[test]
    fn algorithms_table_in_markdown() {
        let config = default_security_policy_config();
        let doc = generate_security_policy(&config);
        let md = doc.to_markdown();
        // The cryptographic module section should contain a markdown table
        assert!(md.contains("| Algorithm |"));
        assert!(md.contains("AES-GCM"));
        assert!(md.contains("SHA-256"));
        assert!(md.contains("RSA"));
    }

    #[test]
    fn self_tests_table_in_markdown() {
        let config = default_security_policy_config();
        let doc = generate_security_policy(&config);
        let md = doc.to_markdown();
        assert!(md.contains("| Test Name |"));
        assert!(md.contains("Known Answer Test"));
        assert!(md.contains("Software Integrity Test"));
    }

    // -- validation -----------------------------------------------------------

    #[test]
    fn default_config_passes_validation() {
        assert!(validate_security_policy_config(&default_security_policy_config()).is_ok());
    }

    #[test]
    fn invalid_fips_level_rejected() {
        let mut config = default_security_policy_config();
        config.fips_level = 0;
        assert!(validate_security_policy_config(&config).is_err());
        config.fips_level = 5;
        assert!(validate_security_policy_config(&config).is_err());
    }

    #[test]
    fn empty_module_name_rejected() {
        let mut config = default_security_policy_config();
        config.module_name = "  ".to_string();
        let err = validate_security_policy_config(&config).unwrap_err();
        assert!(err.to_string().contains("violation"));
    }

    #[test]
    fn empty_algorithms_rejected() {
        let mut config = default_security_policy_config();
        config.algorithms.clear();
        assert!(validate_security_policy_config(&config).is_err());
    }

    #[test]
    fn empty_role_services_rejected() {
        let mut config = default_security_policy_config();
        config.roles[0].services.clear();
        let err = validate_security_policy_config(&config).unwrap_err();
        match err {
            CertError::InvalidConfig(v) => {
                assert!(v.iter().any(|m| m.contains("no services")));
            }
            _ => panic!("expected InvalidConfig"),
        }
    }

    #[test]
    fn validation_collects_all_violations() {
        let mut config = default_security_policy_config();
        config.fips_level = 9;
        config.module_name = String::new();
        config.algorithms.clear();
        let err = validate_security_policy_config(&config).unwrap_err();
        match err {
            CertError::InvalidConfig(v) => assert!(v.len() >= 3),
            _ => panic!(),
        }
    }

    // -- packaging ------------------------------------------------------------

    #[test]
    fn package_security_policy_writes_markdown() {
        let dir = tempfile::tempdir().unwrap();
        let config = default_security_policy_config();
        let path = package_security_policy(dir.path(), &config).unwrap();
        assert!(path.exists());
        assert_eq!(path.file_name().unwrap(), "security_policy.md");
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("# Craton HSM FIPS 140-3 Security Policy"));
        assert!(contents.contains("Module Specification"));
        assert!(contents.contains("Self-Tests"));
    }

    #[test]
    fn package_security_policy_rejects_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = default_security_policy_config();
        config.fips_level = 0;
        assert!(package_security_policy(dir.path(), &config).is_err());
        // Must not create the file when validation fails.
        assert!(!dir.path().join("security_policy.md").exists());
    }
}
