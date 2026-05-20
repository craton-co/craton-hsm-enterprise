// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Build script that emits `cargo:rustc-cfg=mock_crypto_allowed` **only** when
//! both of the following hold:
//!
//! 1. The `mock-insecure-do-not-ship` Cargo feature is active
//!    (`CARGO_FEATURE_MOCK_INSECURE_DO_NOT_SHIP=1`).
//! 2. The crate is still at a dev-band version — i.e. `CARGO_PKG_VERSION`
//!    starts with `0.` (pre-1.0). Once the workspace bumps to `1.0.0+`, the
//!    cfg is **never** emitted and the mock backends disappear from the crate
//!    even if the feature is accidentally enabled.
//!
//! This is the compile-time half of the mock gate. The runtime half lives in
//! `src/lib.rs::mock_guard::check` which additionally requires the operator
//! to set `CRATON_HSM_ALLOW_MOCK=1` (and, in release builds,
//! `CRATON_HSM_ACCEPT_MOCK_IN_RELEASE=1`). A release binary therefore has to
//! get past *three* independent gates to instantiate a mock backend.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MOCK_INSECURE_DO_NOT_SHIP");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");

    // Register the cfg we optionally emit so newer rustc (with
    // -Wunexpected_cfgs) accepts it.
    println!("cargo:rustc-check-cfg=cfg(mock_crypto_allowed)");

    let feature_on = std::env::var_os("CARGO_FEATURE_MOCK_INSECURE_DO_NOT_SHIP").is_some();
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let is_dev_band = version.starts_with("0.");

    if feature_on && is_dev_band {
        println!("cargo:rustc-cfg=mock_crypto_allowed");
        println!(
            "cargo:warning=craton-hsm-cloud: mock_crypto_allowed ENABLED \
             (feature=mock-insecure-do-not-ship, version={version}); \
             do not ship this binary"
        );
    } else if feature_on && !is_dev_band {
        // Loud failure: someone left the mock feature on after the crate was
        // promoted past 0.x. This is almost certainly a Bad Day waiting to
        // happen; fail the build instead of silently producing a release.
        panic!(
            "craton-hsm-cloud: feature `mock-insecure-do-not-ship` is enabled \
             but crate version {version} is no longer in the dev band (0.y.z). \
             The mock backends must not ship in a stable release. Remove the \
             feature from your build configuration."
        );
    }
}
