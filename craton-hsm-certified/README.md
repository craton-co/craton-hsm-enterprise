# craton-hsm-certified

Tooling to support FIPS 140-3 certification of Craton HSM builds.

## What it does

Provides the machinery a module vendor needs when preparing a FIPS 140-3
Level 1 submission: an approved-mode finite state machine, ACVP test-
vector runner, CMVP artifact packaging, reproducible-build verification,
and HMAC-SHA256 binary signing with tamper-evident metadata envelopes.

> **Status.** This crate provides the *tooling*. The Craton HSM module
> itself is **not yet FIPS 140-3 certified** — validation is a process
> involving a CMVP-accredited lab, not a property of this code alone.

## Modules

- **`fsm`** — Models the FIPS 140-3 module states (`PowerOff`,
  `PowerOn`, `SelfTest`, `CryptoOfficerMode`, `UserMode`, `ErrorState`,
  `Zeroization`) and validates the transition graph. Enforces:
  - `SelfTest` is the only path out of `PowerOn`;
  - `ErrorState` can only go to `Zeroization` or `PowerOff`;
  - operational states must pass through `Zeroization` before
    `PowerOff` (FIPS 140-3 §7.9 zeroization-on-shutdown);
  - no unreachable or dead states (other than `PowerOff` as the
    terminal state).
- **`acvp`** — ACVP / CAVP test vector runner. Parses NIST ACVP JSON,
  runs Known-Answer, Monte-Carlo, and Algorithm-Functional tests
  against a `CryptoBackend`, and emits ACVP response JSON. Coverage:
  AES-GCM, AES-CBC, SHA-2 (256/384/512), HMAC, RSA, ECDSA.
- **`cmvp`** — Packages CMVP submission artifacts (test results,
  security policy, known-answer-test logs).
- **`security_policy`** — Structured FIPS security-policy document
  generation.
- **`integrity`** — HMAC-SHA256 power-on integrity check helpers.
- **`reproducibility`** — SHA-256-based reproducible-build verification
  (same source + same toolchain → identical binary).
- **`approved_mode`** — Runtime enforcement of approved-mode
  configuration.
- **`test_harness`** — Certification test harness with known-answer
  tests, instantiated against the FIPS-validated `aws-lc-rs` backend.
- **`binary_sign`** — Signs binaries with HMAC-SHA256 and embeds a
  canonical-JSON metadata footer. Envelope layout:

  ```text
  [original binary bytes]
  [FOOTER_MAGIC = "RHSMSIGN"]   (8 bytes)
  [FOOTER_VERSION]              (u8)
  [original_len]                (u64 LE)
  [metadata_json]               (canonical JSON of BinaryMetadata)
  [metadata_len]                (u32 LE)
  [integrity_tag]               (HMAC-SHA256 over everything above)
  ```

  The tag covers every preceding byte, so inserting/removing bytes
  between the original binary and the footer, or nesting an old footer
  inside a new one, is detected.

## Feature flags

This crate currently exposes no Cargo features. The dependency
`craton-hsm` is pulled in with `features = ["awslc-backend"]` so the
test harness can run ACVP vectors against FIPS-validated primitives.

## MSRV

Rust **1.75+**.

## Safety (FFI / `unsafe`)

`#![deny(unsafe_code)]` at the crate root. No `unsafe` blocks.

## Security considerations

- Binary signing uses HMAC-SHA256 over the whole pre-footer content plus
  the footer metadata; any insertion between binary and footer is caught.
- Reproducible-build verification is SHA-256 equality; producing
  byte-reproducible binaries is a build-system concern (frozen `rustc`,
  `RUSTFLAGS`, `SOURCE_DATE_EPOCH`, locked `Cargo.lock`).
- ACVP runner drives the FIPS-validated `aws-lc-rs` backend; known-answer
  and Monte-Carlo tests run against real FIPS primitives.

## Error types

Each module has a dedicated error type (`FsmError`, `AcvpError`,
`IntegrityError`, `SignError`, etc.) — see the module docs.

A runnable KAT-runner example lives at `examples/run_kats.rs`:

```text
cargo run --example run_kats -p craton-hsm-certified
```

It exercises [`run_all_kats_with_default_config`] against the AWS-LC
backend and exits non-zero on any KAT failure. The module-level tests
under `src/*/tests.rs` exercise each subsystem in finer detail.

[`run_all_kats_with_default_config`]: ./src/test_harness.rs

## Approved-mode enforcement (backend responsibility)

`craton-hsm-certified::approved_mode::check_mechanism_approved` is the
public hook a backend should call before performing any operation in
approved mode. The certified crate does not depend on any backend crate
and so cannot wire this in itself; each backend must call the function
in its operation entry points.

**Status (truthful):** at the time of writing, **no backend in this
workspace currently invokes `check_mechanism_approved`.** Wiring it into
the OpenSSL, AWS-LC, NXP, and Infineon backends is tracked separately;
until that is done the approved-mode policy lives only in the
configuration layer.

## Usage

```rust,no_run
use craton_hsm_certified::binary_sign::sign_binary_file;
use craton_hsm_certified::fsm::{default_fips_fsm, validate_fsm, ModuleFsm, ModuleState};

// 1. Build the canonical FIPS-140-3 state-machine model and validate it.
let model = default_fips_fsm();
validate_fsm(&model)?;

// 2. Construct the runtime atomic-state FSM seeded with the model.
let fsm = ModuleFsm::new(model);
assert_eq!(fsm.current_state(), ModuleState::PowerOff);

// 3. Sign a built module binary on disk; the returned BinaryMetadata
//    is suitable for embedding into a CMVP submission.
let key: [u8; 32] = [0u8; 32]; // in practice, a zeroizing secret loaded out-of-band.
let _meta = sign_binary_file(
    std::path::Path::new("target/release/craton-hsmd"),
    &key,
    /* module_version */ "0.1.0",
    /* build_timestamp */ "2026-03-26T00:00:00Z",
    /* git_commit */ "0000000",
    /* hmac_key_id */ "k1",
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Requirements

- Rust 1.75+.
- `craton-hsm` core crate with the `awslc-backend` feature enabled.
- `aws-lc-rs` (pulled in transitively) for the FIPS-validated
  primitives used by the test harness.
- For ACVP submissions: NIST ACVP test-vector JSON files; there are no
  bundled vectors in this repo.
- `#![deny(unsafe_code)]` at the crate root.

## Limitations and caveats

- **The module is not yet FIPS-certified.** This crate is scaffolding
  that produces artifacts useful to a CMVP lab; it does not confer
  validation by itself.
- **Binary signing is HMAC-SHA256**, a symmetric primitive. The key
  distribution model is out of scope for this crate — typical use is
  to keep the HMAC key in a signing HSM and verify at module load.
- **Reproducible-build verification** depends on a deterministic
  toolchain (frozen `rustc` version, `RUSTFLAGS`, `SOURCE_DATE_EPOCH`,
  locked `Cargo.lock`). The crate checks SHA-256 equality; producing
  reproducible binaries is a build-system concern.
- **ACVP coverage is partial.** Algorithms covered are listed above;
  additional algorithms (KAS, KDFs beyond HKDF, DRBG-specific
  validations) are on the roadmap.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-certified:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
