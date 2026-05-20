// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Enterprise authentication, RBAC, and multi-tenancy for Craton HSM.
//!
//! # Lint policy
//!
//! Production code in this crate is held to an elevated bar because it
//! forms part of the HSM authentication surface.  Panicking helpers like
//! `.unwrap()`, `.expect(..)`, and `panic!(..)` are denied at the crate
//! level so a malformed bind, JWT, or claim can never crash the server
//! process.  `unreachable!()` is denied for the same reason.  Tests are
//! exempt.
//!
//! If you *must* use one of these (e.g. internal invariant that would
//! indicate a programming error, not a user-supplied-data bug), allow it
//! locally with `#[allow(clippy::unwrap_used)]` and leave a comment
//! explaining why the invariant cannot be violated.

#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unreachable))]
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
#![deny(missing_docs)]

pub mod auth;
pub mod error;
pub mod rbac;
pub mod tenant;
