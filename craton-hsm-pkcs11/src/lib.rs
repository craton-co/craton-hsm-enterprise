// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! # `craton-hsm-pkcs11` — PKCS#11 passthrough backend for craton-hsm
//!
//! This crate implements the [`craton_hsm::crypto::backend::CryptoBackend`] trait
//! on top of a vendor PKCS#11 library (Thales Luna, Entrust nShield, AWS
//! CloudHSM, YubiHSM, SoftHSM2, etc.), turning craton-hsm into a unified
//! abstraction layer with audit logging and session management sitting on
//! top of a hardware root of trust. PQC algorithms are not delegated through
//! this backend — they are handled in software by `craton-hsm-core` and are
//! not exposed by the underlying PKCS#11 mechanism set.
//!
//! ## Architecture
//!
//! ```text
//!                    ┌──────────────────────────────────────┐
//!                    │        Pkcs11PassthroughBackend      │
//!                    │  ┌────────────────────────────────┐  │
//!                    │  │          SessionPool           │  │
//!                    │  │                                │  │
//!                    │  │  Mutex<PooledSession>  ─┐      │  │
//!                    │  │  Mutex<PooledSession>  ─┼─ N   │  │
//!                    │  │  Mutex<PooledSession>  ─┘      │  │
//!                    │  │     (each owns a KeyCache)     │  │
//!                    │  └────────────────────────────────┘  │
//!                    └──────────────────────────────────────┘
//!                                      │
//!                                      ▼
//!                          cryptoki::Pkcs11 (Arc, shared)
//!                                      │
//!                                      ▼
//!                             vendor .so / .dll
//! ```
//!
//! ## Security properties
//!
//! - **No TOCTOU on imported-key handles.** Each `PooledSession` owns its own
//!   [`cache::KeyCache`]; lookup + crypto call are sequential under one
//!   mutex, so a cached handle cannot be destroyed between check and use.
//! - **No string-matching of error types.** Verification uses the typed
//!   [`error::VerifyOutcome`] decoder — see [`error::classify_verify_result`].
//! - **AES-GCM nonce-reuse bound enforced per key (per process).** Each
//!   imported-key fingerprint tracks the number of encryptions performed
//!   in the current process and refuses further ones past the configured
//!   ceiling (default `2^32`, per NIST SP 800-38D §8.3). NOTE: the counter
//!   lives in [`pool::PoolGcmCounters`], which is process-local: it resets
//!   to zero on backend restart. Persistent durable counters across
//!   process restarts are out of scope for this crate (the imported-key
//!   material must be rotated on operator policy if a restart could
//!   plausibly approach the budget for any single key).
//! - **PIN material minimized.** [`config::Pkcs11PassthroughConfig`] holds
//!   the PIN in `Zeroizing<String>`; the [`pool::SessionPool`] hands
//!   exactly one owned copy to `AuthPin` per login.
//! - **Fail-closed software fallbacks.** Key generation only falls back to
//!   software when the operator explicitly sets
//!   `allow_software_keygen_fallback = true`.
//! - **Domain-separated fingerprints.** All cache keys are derived with a
//!   per-key-type domain tag and length-prefixed parts to prevent
//!   cross-type or concatenation collisions.
//!
//! ## Public surface
//!
//! The crate exposes two types: [`Pkcs11PassthroughBackend`] and
//! [`Pkcs11PassthroughConfig`]. Everything else is implementation
//! detail. The submodules are kept reachable for in-tree white-box
//! tests, but they are marked `#[doc(hidden)]` so they do NOT form
//! part of the public, SemVer-stable API surface. Renaming or
//! removing items inside them is not a breaking change. Depending on
//! anything from these modules in downstream code is unsupported.

#[doc(hidden)]
pub mod backend;
#[doc(hidden)]
pub mod cache;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod digest_info;
#[doc(hidden)]
pub mod error;
#[doc(hidden)]
pub mod pool;

pub use backend::Pkcs11PassthroughBackend;
pub use config::Pkcs11PassthroughConfig;
pub use pool::SessionToken;
