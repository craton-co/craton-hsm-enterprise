// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Role-Based Access Control (RBAC) for enterprise HSM deployments.
//!
//! Extends the PKCS#11 User/SO model with fine-grained roles (Auditor,
//! KeyManager, Operator), per-key ACLs, and a policy engine that enforces
//! permissions at every operation dispatch point.

pub mod acl;
pub mod approval;
pub mod identity;
pub mod policy;
pub mod role;
