// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]
#![warn(unreachable_pub)]
#![deny(missing_docs)]

//! FIPS 140-3 certification tooling for Craton HSM builds
//!
//! This crate provides the tooling and verification for producing
//! FIPS 140-3 Level 1 certifiable binaries of Craton HSM, including:
//!
//! - Binary integrity verification via HMAC-SHA256
//! - Build reproducibility checking via SHA-256 comparison
//! - FIPS approved-mode configuration enforcement
//! - CMVP submission artifact scaffolding
//! - Certification test harness with known-answer tests
//!
//! # License
//!
//! Licensed under the Business Source License 1.1. See LICENSE-BSL.

pub mod acvp;
pub mod approved_mode;
pub mod approved_mode_wrapper;
pub mod binary_sign;
pub mod cmvp;
pub mod error;
pub mod fsm;
pub(crate) mod hex_util;
pub mod integrity;
pub mod power_on_self_test;
pub mod reproducibility;
pub mod security_policy;
pub mod test_harness;

pub use error::{CertError, CertResult};
