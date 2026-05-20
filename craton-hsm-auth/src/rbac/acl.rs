// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Per-key access control lists (ACLs).
//!
//! Each key can optionally carry an ACL that restricts which roles may
//! perform which operations on it. Keys without an ACL use the default
//! role-based permissions from [`super::role::default_permissions`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::role::{HsmOperation, HsmRole};

/// Access control list for a single key or object.
///
/// Stored as a vendor-defined attribute (`CKA_VENDOR_ACL`) on the
/// `StoredObject`. Serialized as JSON for PKCS#11 attribute transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAcl {
    /// List of access control entries.
    pub entries: Vec<AclEntry>,
}

/// A single ACL entry granting a role specific operations on the key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    /// The role this entry applies to.
    pub role: HsmRole,
    /// Operations this role is allowed to perform on the key.
    pub allowed_operations: HashSet<HsmOperation>,
}

impl KeyAcl {
    /// Check if a role is allowed to perform a specific operation.
    pub fn is_allowed(&self, role: HsmRole, operation: HsmOperation) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.role == role && entry.allowed_operations.contains(&operation))
    }

    /// Create a default ACL that grants User, KeyManager, and Operator
    /// their default permissions on this key.
    pub fn default_key_acl() -> Self {
        use super::role::default_permissions;
        let user_ops = default_permissions(HsmRole::User);
        let km_ops = default_permissions(HsmRole::KeyManager);
        let op_ops = default_permissions(HsmRole::Operator);

        Self {
            entries: vec![
                AclEntry {
                    role: HsmRole::User,
                    allowed_operations: user_ops,
                },
                AclEntry {
                    role: HsmRole::KeyManager,
                    allowed_operations: km_ops,
                },
                AclEntry {
                    role: HsmRole::Operator,
                    allowed_operations: op_ops,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_acl_allows_user_sign() {
        let acl = KeyAcl::default_key_acl();
        assert!(acl.is_allowed(HsmRole::User, HsmOperation::Sign));
    }

    #[test]
    fn test_default_acl_denies_auditor() {
        let acl = KeyAcl::default_key_acl();
        assert!(!acl.is_allowed(HsmRole::Auditor, HsmOperation::Sign));
    }

    #[test]
    fn test_custom_acl() {
        let acl = KeyAcl {
            entries: vec![AclEntry {
                role: HsmRole::Operator,
                allowed_operations: [HsmOperation::Sign, HsmOperation::Verify]
                    .into_iter()
                    .collect(),
            }],
        };
        assert!(acl.is_allowed(HsmRole::Operator, HsmOperation::Sign));
        assert!(!acl.is_allowed(HsmRole::Operator, HsmOperation::Encrypt));
        assert!(!acl.is_allowed(HsmRole::User, HsmOperation::Sign));
    }
}
