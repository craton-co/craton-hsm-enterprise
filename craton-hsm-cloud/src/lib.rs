// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Cloud-native integrations for Craton HSM.
//!
//! Provides Kubernetes CSI driver, HashiCorp Vault transit backend,
//! AWS CloudHSM shim, and Azure Key Vault shim implementations.
//!
//! # Mock backends
//!
//! Each module ships with an in-memory mock implementation that uses **fake
//! cryptography** and is suitable only for development and integration tests.
//! Mock backends are gated behind the `mock-insecure-do-not-ship` Cargo
//! feature; the feature name is intentionally alarming so it surfaces in
//! `cargo tree` output and dependency audits.
//!
//! Even when the feature is enabled, every mock constructor performs a
//! runtime opt-in check via [`mock_guard::check`] which requires the
//! environment variable `CRATON_HSM_ALLOW_MOCK=1`. Without this variable the
//! constructors panic with a loud diagnostic. This double-locking prevents
//! mock backends from being instantiated in production binaries that were
//! accidentally compiled with the feature enabled.

#![deny(unsafe_code)]
#![deny(missing_docs)]
// Register the cfg emitted by build.rs so newer rustc (with -Wunexpected_cfgs)
// accepts mentions of `mock_crypto_allowed` throughout the crate.

// Audit foot-gun (cloud shims compiled unconditionally): each shim is now
// gated behind its own Cargo feature. The defaults in `Cargo.toml` enable all
// four so existing callers don't need any change; downstream crates that only
// need one or two can use `default-features = false` and re-list.
#[cfg(feature = "aws")]
pub mod aws_shim;
#[cfg(feature = "azure")]
pub mod azure_shim;
#[cfg(feature = "csi")]
pub mod k8s_csi;
#[cfg(feature = "vault")]
pub mod vault_plugin;

#[cfg(any(test, mock_crypto_allowed))]
pub mod mock_crypto;

/// Common error surface every cloud shim implements. Audit finding DESIGN:
/// `is_retriable` + `provider` collapse per-backend retry matches in calling
/// code into a single trait-object call.
pub trait CloudError {
    /// `true` if the error is worth retrying (transient backend hiccups,
    /// upstream rate limits). Per-finding review: `Internal` covers
    /// programming errors and invariant violations that will reproduce
    /// deterministically — those are **not retriable**. Only domain-specific
    /// transient variants (e.g. `k8s-csi`'s `HsmFetchFailed`) return `true`.
    fn is_retriable(&self) -> bool;

    /// Stable, lowercase backend tag (`"aws"`, `"azure"`, `"vault"`,
    /// `"k8s-csi"`). Safe to use as a Prometheus label.
    fn provider(&self) -> &'static str;
}

#[cfg(feature = "aws")]
impl CloudError for aws_shim::AwsHsmError {
    fn is_retriable(&self) -> bool {
        // `Internal` is no longer treated as retriable — it surfaces logic
        // bugs / invariant breaks that will reproduce. AWS shim has no
        // transient variants yet, so this is always `false`.
        false
    }
    fn provider(&self) -> &'static str {
        "aws"
    }
}

#[cfg(feature = "azure")]
impl CloudError for azure_shim::AzureKvError {
    fn is_retriable(&self) -> bool {
        // `Internal` is no longer retriable; Azure shim exposes no transient
        // error variants of its own.
        false
    }
    fn provider(&self) -> &'static str {
        "azure"
    }
}

#[cfg(feature = "vault")]
impl CloudError for vault_plugin::VaultError {
    fn is_retriable(&self) -> bool {
        // `Internal` is no longer retriable. The transit backend has no
        // dedicated transient variant; embedders that surface upstream HTTP
        // 5xx should map them to a future variant rather than `Internal`.
        false
    }
    fn provider(&self) -> &'static str {
        "vault"
    }
}

#[cfg(feature = "csi")]
impl CloudError for k8s_csi::CsiError {
    fn is_retriable(&self) -> bool {
        // Only the dedicated transient variant is retriable;
        // `Internal` collapses programming errors and must not be retried.
        matches!(self, k8s_csi::CsiError::HsmFetchFailed(_))
    }
    fn provider(&self) -> &'static str {
        "k8s-csi"
    }
}

/// Runtime opt-in guard for mock backends.
///
/// Centralised here so the four module-level guards do not drift out of sync.
/// Compiled under `cfg(test)` as well because the per-module mock types are
/// exposed under `cfg(any(test, feature = "mock-insecure-do-not-ship"))` and
/// need the guard's length-cap helper.
#[cfg(any(test, feature = "mock-insecure-do-not-ship"))]
pub mod mock_guard {
    /// Environment variable required to instantiate any mock backend.
    pub const MOCK_OPT_IN_VAR: &str = "CRATON_HSM_ALLOW_MOCK";
    /// Second-line-of-defence env var required in release builds (audit
    /// findings M3/M4/M5). In debug builds `MOCK_OPT_IN_VAR` alone is enough;
    /// in release builds we require the operator to *also* set this variable
    /// so the guard trips twice before any insecure mock backend boots.
    pub const MOCK_RELEASE_OPT_IN_VAR: &str = "CRATON_HSM_ACCEPT_MOCK_IN_RELEASE";
    /// Hard upper bound on any key material passed into a mock backend.
    /// Audit findings M3/M4/M5: the mocks are trivially forgeable, so if a
    /// caller accidentally hands one a real 4096-bit RSA key or a long-lived
    /// wrapping secret the blast radius is much larger than it needs to be.
    /// Capping every mock key at 32 bytes keeps the exposure window small.
    pub const MAX_MOCK_KEY_BYTES: usize = 32;

    /// Verify that the runtime opt-in is set; panic with a loud diagnostic if
    /// not. Called from every mock constructor.
    ///
    /// # Panics
    ///
    /// - If `CRATON_HSM_ALLOW_MOCK` is not set to `"1"`.
    /// - In release builds, if `CRATON_HSM_ACCEPT_MOCK_IN_RELEASE` is not set
    ///   to `"1"` as well.
    pub fn check(component: &str) {
        match std::env::var(MOCK_OPT_IN_VAR) {
            Ok(v) if v == "1" => {
                tracing::warn!(
                    component = component,
                    "INSECURE MOCK BACKEND INSTANTIATED — uses fake crypto, do not ship"
                );
            }
            _ => {
                eprintln!(
                    "FATAL: craton-hsm-cloud mock backend '{component}' was instantiated without\n\
                     {var}=1.  Mock backends use trivially forgeable cryptography and must\n\
                     never run outside of tests or local development.\n\
                     If this is a test, set the environment variable. If this is production,\n\
                     remove the 'mock-insecure-do-not-ship' Cargo feature.",
                    var = MOCK_OPT_IN_VAR
                );
                panic!("craton-hsm-cloud: mock backend opt-in not set");
            }
        }

        // Second gate: release builds additionally require an explicit
        // opt-in.  This prevents a production binary that was accidentally
        // compiled with the `mock-insecure-do-not-ship` feature — and that
        // happens to have `CRATON_HSM_ALLOW_MOCK=1` in its environment from a
        // shared deployment template — from silently booting the mock.
        if !cfg!(debug_assertions) {
            match std::env::var(MOCK_RELEASE_OPT_IN_VAR) {
                Ok(v) if v == "1" => {
                    tracing::error!(
                        component = component,
                        "MOCK BACKEND ACCEPTED IN RELEASE BUILD — this must never \
                         happen in production; verify your deployment"
                    );
                }
                _ => {
                    eprintln!(
                        "FATAL: craton-hsm-cloud mock backend '{component}' was about to be\n\
                         instantiated in a release build without {var}=1.  This is almost\n\
                         certainly a deployment mistake.  If you really, really need to run a\n\
                         mock backend in a release build (e.g. integration testing), set the\n\
                         environment variable.  Otherwise, rebuild without the\n\
                         'mock-insecure-do-not-ship' Cargo feature.",
                        var = MOCK_RELEASE_OPT_IN_VAR
                    );
                    panic!("craton-hsm-cloud: mock release-mode opt-in not set");
                }
            }
        }
    }

    /// Reject key material longer than [`MAX_MOCK_KEY_BYTES`].  Audit
    /// findings M3/M4/M5: mocks use fake cryptography and must never hold
    /// long-lived production key material, so we refuse to even accept it.
    pub fn check_mock_key_len(len: usize) -> Result<(), String> {
        if len > MAX_MOCK_KEY_BYTES {
            return Err(format!(
                "mock backend refuses key material longer than \
                 {MAX_MOCK_KEY_BYTES} bytes (got {len}); mocks use fake \
                 crypto and must not hold production keys"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod mock_guard_tests {
    use super::mock_guard::{check_mock_key_len, MAX_MOCK_KEY_BYTES};

    #[test]
    fn rejects_keys_above_cap() {
        let err = check_mock_key_len(MAX_MOCK_KEY_BYTES + 1).unwrap_err();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn accepts_keys_at_and_below_cap() {
        check_mock_key_len(0).unwrap();
        check_mock_key_len(16).unwrap();
        check_mock_key_len(MAX_MOCK_KEY_BYTES).unwrap();
    }

    /// Audit finding C4 / scope: gate is fail-closed even in a fresh
    /// environment with no mock opt-in vars. We snapshot and restore the env
    /// vars to avoid clobbering parallel tests in the same process, and we
    /// hold the global env-mutation mutex for the entire critical section so
    /// no parallel test can race a `set_var` into the same window.
    #[test]
    fn gate_fails_closed_without_env_vars() {
        let _g = super::mock_env_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let prev_allow = std::env::var("CRATON_HSM_ALLOW_MOCK").ok();
        let prev_release = std::env::var("CRATON_HSM_ACCEPT_MOCK_IN_RELEASE").ok();
        std::env::remove_var("CRATON_HSM_ALLOW_MOCK");
        std::env::remove_var("CRATON_HSM_ACCEPT_MOCK_IN_RELEASE");

        let result = std::panic::catch_unwind(|| {
            super::mock_guard::check("gate_fails_closed_without_env_vars");
        });

        if let Some(v) = prev_allow {
            std::env::set_var("CRATON_HSM_ALLOW_MOCK", v);
        }
        if let Some(v) = prev_release {
            std::env::set_var("CRATON_HSM_ACCEPT_MOCK_IN_RELEASE", v);
        }

        assert!(result.is_err(), "gate must fail-closed without env vars");
    }
}

#[cfg(test)]
fn _enable_mock_for_tests() {
    // Tests run inside the same process so we set the variable once. This is
    // a no-op in production builds (the function is `cfg(test)`).
    //
    // Audit finding (mock env mutation flakiness): `set_var` mutates
    // process-global state. The `mock_guard_tests::gate_fails_closed…` test
    // *removes* these variables and asserts the gate panics, so two threads
    // racing through `_enable_mock_for_tests` and that test could observe
    // each other's writes and flip an assertion. We serialise every env-var
    // poke through a single global Mutex so the writes are at least totally
    // ordered. A real `serial_test` attribute would be preferable but the
    // crate cannot grow new dev-dependencies in this sweep.
    let _g = mock_env_lock().lock().unwrap_or_else(|p| p.into_inner());
    std::env::set_var("CRATON_HSM_ALLOW_MOCK", "1");
    // Release-mode test builds (`cargo test --release`) also need the
    // second-gate opt-in introduced in audit finding M3/M4/M5.
    std::env::set_var("CRATON_HSM_ACCEPT_MOCK_IN_RELEASE", "1");
}

/// Global mutex guarding any mutation of the `CRATON_HSM_*` env vars from
/// inside tests. Exposed via accessor so tests in the env-clearing path can
/// share it. Compiled under `cfg(test)` only.
#[cfg(test)]
pub(crate) fn mock_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}
