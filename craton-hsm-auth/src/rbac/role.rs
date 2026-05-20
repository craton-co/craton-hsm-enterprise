// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! HSM roles and operations for RBAC.
//!
//! Extends the PKCS#11 CKU_USER/CKU_SO model with enterprise roles.
//! Through the C ABI, CKU_USER maps to `HsmRole::User` and CKU_SO maps
//! to `HsmRole::So`. Extended roles (Auditor, KeyManager, Operator) are
//! assignable only through the gRPC layer or external auth.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Enterprise HSM roles.
///
/// `User` and `So` map directly to PKCS#11's CKU_USER and CKU_SO.
/// The remaining roles are vendor extensions accessible via gRPC or
/// external authentication providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HsmRole {
    /// Standard user — full crypto + key management (PKCS#11 CKU_USER).
    User,
    /// Security Officer — token init, PIN management (PKCS#11 CKU_SO).
    So,
    /// Auditor — read-only access to audit logs, no crypto operations.
    Auditor,
    /// Key Manager — key lifecycle only (generate, import, export, destroy, wrap/unwrap).
    KeyManager,
    /// Operator — crypto operations only (sign, verify, encrypt, decrypt).
    Operator,
}

impl HsmRole {
    /// Human-readable name for audit logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "User",
            Self::So => "SO",
            Self::Auditor => "Auditor",
            Self::KeyManager => "KeyManager",
            Self::Operator => "Operator",
        }
    }
}

impl std::fmt::Display for HsmRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Operations that can be governed by RBAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HsmOperation {
    // Crypto operations
    /// `C_Sign` / `C_SignRecover` family.
    Sign,
    /// `C_Verify` / `C_VerifyRecover` family.
    Verify,
    /// `C_Encrypt` family.
    Encrypt,
    /// `C_Decrypt` family.
    Decrypt,
    /// `C_Digest` / `C_DigestUpdate` family.
    Digest,

    // Key management
    /// `C_GenerateKey` — generate a symmetric key.
    GenerateKey,
    /// `C_GenerateKeyPair` — generate an asymmetric key pair.
    GenerateKeyPair,
    /// `C_DestroyObject` — permanently remove an object.
    DestroyObject,
    /// `C_WrapKey` — wrap a key for export.
    WrapKey,
    /// `C_UnwrapKey` — import a wrapped key.
    UnwrapKey,
    /// `C_DeriveKey` — derive a key from a base key.
    DeriveKey,
    /// Import plaintext key material.
    ImportKey,
    /// Export plaintext key material (gated by `extractable` attribute).
    ExportKey,
    /// `C_CreateObject` — create a non-key object (cert, data).
    CreateObject,
    /// `C_CopyObject` — copy an existing object.
    CopyObject,
    /// `C_SetAttributeValue` — mutate a non-immutable attribute.
    SetAttribute,

    // Admin operations
    /// `C_InitToken` — initialise a token (zeroises all objects).
    InitToken,
    /// `C_InitPIN` — set the initial user PIN.
    InitPin,
    /// `C_SetPIN` — change the calling user's PIN.
    SetPin,

    // Audit
    /// Read the security-relevant audit log.
    ReadAuditLog,

    // Random
    /// `C_GenerateRandom` / `C_SeedRandom` family.
    GenerateRandom,
}

impl HsmOperation {
    /// Human-readable name for audit logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sign => "Sign",
            Self::Verify => "Verify",
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
            Self::Digest => "Digest",
            Self::GenerateKey => "GenerateKey",
            Self::GenerateKeyPair => "GenerateKeyPair",
            Self::DestroyObject => "DestroyObject",
            Self::WrapKey => "WrapKey",
            Self::UnwrapKey => "UnwrapKey",
            Self::DeriveKey => "DeriveKey",
            Self::ImportKey => "ImportKey",
            Self::ExportKey => "ExportKey",
            Self::CreateObject => "CreateObject",
            Self::CopyObject => "CopyObject",
            Self::SetAttribute => "SetAttribute",
            Self::InitToken => "InitToken",
            Self::InitPin => "InitPin",
            Self::SetPin => "SetPin",
            Self::ReadAuditLog => "ReadAuditLog",
            Self::GenerateRandom => "GenerateRandom",
        }
    }
}

/// Returns the default set of permitted operations for a role.
///
/// These defaults ensure backward compatibility: `HsmRole::User` has
/// all permissions that CKU_USER has today, and `HsmRole::So` has all
/// permissions that CKU_SO has today.
pub fn default_permissions(role: HsmRole) -> HashSet<HsmOperation> {
    use HsmOperation::*;
    match role {
        HsmRole::User => [
            Sign,
            Verify,
            Encrypt,
            Decrypt,
            Digest,
            GenerateKey,
            GenerateKeyPair,
            DestroyObject,
            WrapKey,
            UnwrapKey,
            DeriveKey,
            ImportKey,
            ExportKey,
            CreateObject,
            CopyObject,
            SetAttribute,
            GenerateRandom,
        ]
        .into_iter()
        .collect(),

        HsmRole::So => [InitToken, InitPin, SetPin, ReadAuditLog]
            .into_iter()
            .collect(),

        HsmRole::Auditor => [ReadAuditLog].into_iter().collect(),

        HsmRole::KeyManager => [
            GenerateKey,
            GenerateKeyPair,
            DestroyObject,
            WrapKey,
            UnwrapKey,
            DeriveKey,
            ImportKey,
            ExportKey,
            CreateObject,
            CopyObject,
            SetAttribute,
        ]
        .into_iter()
        .collect(),

        HsmRole::Operator => [Sign, Verify, Encrypt, Decrypt, Digest, GenerateRandom]
            .into_iter()
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_has_all_crypto_permissions() {
        let perms = default_permissions(HsmRole::User);
        assert!(perms.contains(&HsmOperation::Sign));
        assert!(perms.contains(&HsmOperation::Encrypt));
        assert!(perms.contains(&HsmOperation::GenerateKey));
        assert!(perms.contains(&HsmOperation::DestroyObject));
    }

    #[test]
    fn test_so_cannot_sign() {
        let perms = default_permissions(HsmRole::So);
        assert!(!perms.contains(&HsmOperation::Sign));
        assert!(perms.contains(&HsmOperation::InitToken));
    }

    #[test]
    fn test_auditor_read_only() {
        let perms = default_permissions(HsmRole::Auditor);
        assert_eq!(perms.len(), 1);
        assert!(perms.contains(&HsmOperation::ReadAuditLog));
    }

    #[test]
    fn test_operator_no_key_management() {
        let perms = default_permissions(HsmRole::Operator);
        assert!(perms.contains(&HsmOperation::Sign));
        assert!(!perms.contains(&HsmOperation::GenerateKey));
        assert!(!perms.contains(&HsmOperation::DestroyObject));
    }

    #[test]
    fn test_key_manager_no_crypto() {
        let perms = default_permissions(HsmRole::KeyManager);
        assert!(!perms.contains(&HsmOperation::Sign));
        assert!(perms.contains(&HsmOperation::GenerateKey));
        assert!(perms.contains(&HsmOperation::DestroyObject));
    }
}
