// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! OASIS KMIP 2.1 server implementation for Craton HSM.
//!
//! Provides Tag-Type-Length-Value (TTLV) encoding, core KMIP types,
//! key lifecycle operations, and a message-level server dispatcher.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod acl;
pub mod operations;
pub mod server;
pub mod ttlv;
pub mod types;

pub use acl::{AllowAll, KmipAcl, KmipAclDecision};
