// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Power-on self-test latch (audit finding V10).
//!
//! FIPS 140-3 (§7.10.2) requires that the module run a defined set of
//! known-answer tests at power-on, and that cryptographic services remain
//! **disabled** until those KATs complete successfully. A re-entrant or
//! concurrent caller must see the same cached pass/fail verdict — the
//! KATs run *once*, and subsequent callers observe the latched result.
//!
//! [`PowerOnSelfTestLatch`] wraps the "did we run them" bookkeeping.
//! Callers invoke [`PowerOnSelfTestLatch::run_once_or_get`] at every
//! entry point into the crypto boundary; after the first call the latch
//! short-circuits to the cached verdict without reinvoking the backend.

use crate::error::CertResult;
use crate::test_harness::{run_all_kats_with_default_config, verify_all_pass};
use craton_hsm::crypto::backend::CryptoBackend;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

/// One-shot latch recording whether the power-on self-test suite has
/// been run and what its verdict was.
pub struct PowerOnSelfTestLatch {
    /// `true` once the KAT suite has been driven to completion — whether
    /// it passed or failed. Acts as the early-out flag so concurrent
    /// callers know not to run the KATs again.
    ran: AtomicBool,
    /// Latched verdict, set exactly once. `OnceLock` gives us a write-
    /// once guarantee without an extra mutex in the hot path.
    passed: OnceLock<bool>,
    /// Serializes the first-caller path so `ran` / `passed` are
    /// populated atomically even under thread contention.
    run_lock: Mutex<()>,
}

impl Default for PowerOnSelfTestLatch {
    fn default() -> Self {
        Self::new()
    }
}

impl PowerOnSelfTestLatch {
    /// Construct a fresh latch. No KATs are executed until
    /// [`Self::run_once_or_get`] is called.
    pub const fn new() -> Self {
        Self {
            ran: AtomicBool::new(false),
            passed: OnceLock::new(),
            run_lock: Mutex::new(()),
        }
    }

    /// Whether the latch has been populated at all.
    pub fn has_run(&self) -> bool {
        self.ran.load(Ordering::Acquire)
    }

    /// Read the latched verdict without triggering a run.
    pub fn verdict(&self) -> Option<bool> {
        self.passed.get().copied()
    }

    /// Run the KAT suite exactly once. If the suite has already been run,
    /// return the cached verdict without touching the backend.
    ///
    /// Returns `Ok(true)` when every KAT passed, `Ok(false)` when at
    /// least one KAT failed. Propagates any error from the evidence
    /// packager (currently none, but future iterations may capture
    /// evidence here).
    pub fn run_once_or_get(&self, backend: &mut dyn CryptoBackend) -> CertResult<bool> {
        if let Some(&v) = self.passed.get() {
            return Ok(v);
        }
        // Serialize the first-run path so only one thread drives the KATs.
        let _guard = self.run_lock.lock().expect("POST latch mutex poisoned");
        // Double-check after acquiring the mutex: another thread may
        // have populated the OnceLock while we waited.
        if let Some(&v) = self.passed.get() {
            return Ok(v);
        }

        let results = run_all_kats_with_default_config(backend);
        let verdict = verify_all_pass(&results);
        // OnceLock::set returns Err if someone else beat us — we held the
        // mutex, so that can only happen if a call recurses, which would
        // be a caller bug. Use `get_or_init` semantics by ignoring the
        // Err and re-reading.
        let _ = self.passed.set(verdict);
        self.ran.store(true, Ordering::Release);
        Ok(*self.passed.get().expect("verdict just set"))
    }
}

/// Drive the FIPS power-on self-test latch through a concrete backend and,
/// if every KAT passed, invoke `mark_passed` on that backend so the backend
/// can flip its internal "POST passed" flag.
///
/// The closure indirection deliberately avoids requiring an orphan-`impl`
/// between the certified crate and the per-backend crates: each backend
/// crate defines its own `mark_fips_post_passed(&self)` helper, and the
/// embedder wires them together at the call site:
///
/// ```ignore
/// let latch = PowerOnSelfTestLatch::new();
/// let mut be = AwsLcBackend::new_fips()?;
/// run_fips_post_for_backend(&latch, &mut be, |b| b.mark_fips_post_passed())?;
/// ```
///
/// Returns `Ok(true)` when every KAT in the suite passed (and `mark_passed`
/// was therefore invoked), `Ok(false)` when one or more KATs failed (and
/// `mark_passed` was **not** invoked). Propagates errors from the latch.
///
/// The closure is invoked at most once per call. If the latch had already
/// been driven by a prior call and it had passed previously, `mark_passed`
/// is still invoked here — embedders may use that to gate replicas /
/// per-thread state, where each backend instance needs its flag flipped.
pub fn run_fips_post_for_backend<B>(
    latch: &PowerOnSelfTestLatch,
    backend: &mut B,
    mark_passed: impl FnOnce(&mut B),
) -> CertResult<bool>
where
    B: CryptoBackend,
{
    let verdict = latch.run_once_or_get(backend)?;
    if verdict {
        mark_passed(backend);
    }
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use craton_hsm::crypto::awslc_backend::AwsLcBackend;

    #[test]
    fn latch_short_circuits_on_second_call() {
        let latch = PowerOnSelfTestLatch::new();
        let mut backend = AwsLcBackend;
        assert!(!latch.has_run());
        let first = latch.run_once_or_get(&mut backend).unwrap();
        assert!(latch.has_run());
        assert_eq!(latch.verdict(), Some(first));
        let second = latch.run_once_or_get(&mut backend).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn fresh_latch_has_no_verdict() {
        let latch = PowerOnSelfTestLatch::new();
        assert!(!latch.has_run());
        assert_eq!(latch.verdict(), None);
    }
}
