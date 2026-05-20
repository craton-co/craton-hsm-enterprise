# craton-hsm-nxp

NXP HSE (Hardware Security Engine) backend for Craton HSM.

## What it does

Implements the `CryptoBackend` trait from `craton-hsm-core` for NXP's HSE
firmware running on S32G / S32R / S32K3 automotive SoCs. Crypto requests
are dispatched through the Messaging Unit (MU) to the HSE core, which
holds all key material in hardware.

## Hardware support

- NXP **S32G274A** (GoldBox)
- NXP **S32G399A**
- NXP **S32K344** / **S32K358**

Other S32 family parts with compatible HSE firmware may work but have
not been exercised.

## Feature flags

| Flag        | Default | Effect |
|-------------|---------|--------|
| `hw`        | off     | Enable real HSE hardware calls via the Messaging Unit. |
| `stub`      | off     | Explicit development build — every `CryptoBackend` op returns `FunctionNotSupported`. Required alongside (or instead of) `hw`; the crate refuses to compile with neither set. |
| `test-stub` | off     | Implies `stub`. Enables `new_stub_for_test`, `with_backend`, and the trait-dispatching `CryptoBackend` impl on top of `MockHseBackend` so integration tests can inject a fake FFI layer. |

A feature-less build is intentionally rejected by a `compile_error!`
at the top of `src/lib.rs` (audit finding NXP-1).

### Stub-mode runtime guard

`NxpHseBackend::try_new()` in stub mode also requires the
`CRATON_HSM_ALLOW_STUB_NXP` (or `CRATON_HSM_ALLOW_MOCK`) environment
variable to be set to a non-empty value. Without it the constructor
returns `HsmError::FunctionNotSupported` to prevent silent deployment
of a non-functional backend. See `src/lib.rs::try_new` for details.

### Unsupported under `hw`

Even with `--features hw`, the following `CryptoBackend` methods
return `HsmError::FunctionNotSupported` because the HSE firmware does
not expose them through the Messaging Unit (or the surface is
deferred — see audit V6 for the `RawKeyMaterial` plumbing gap):

- `rsa_oaep_encrypt` / `rsa_oaep_decrypt`
- `ecdh_p256` / `ecdh_p384`
- `aes_key_wrap` / `aes_key_unwrap`
- `generate_aes_key`, `generate_rsa_key_pair`, `generate_ec_p256_key_pair`, `generate_ec_p384_key_pair`, `generate_ed25519_key_pair`
- `compute_digest`, `digest_output_len`, `create_hasher`

Ed25519 is similarly unsupported and returns `HsmError::MechanismInvalid`.

Release notes for this crate live in the workspace-level
[CHANGELOG.md](../CHANGELOG.md), prefixed `craton-hsm-nxp:`.

## MSRV

Rust **1.75+**.

## Safety (FFI / `unsafe`)

`unsafe` is denied at crate level (`#![deny(unsafe_code)]`) and
explicitly opted-in for the FFI bridge with SAFETY comments. The
opt-in is scoped to two sites — `backend_trait.rs` (the `HseFfiBackend`
impl that wraps `extern "C"` calls) and `ffi.rs` (the `extern "C"`
declarations themselves) — both carrying `#[allow(unsafe_code)]` and
documented invariants for every pointer argument.

## Security considerations

- All key material is held in the HSE hardware under `hw`; nothing leaves
  the HSE core via this crate.
- The default stub build is intentionally non-functional so that
  accidentally depending on this crate without configuring hardware fails
  loudly rather than silently falling back to software crypto.
- Ed25519 is not part of the HSE crypto menu on current-generation parts
  and returns `HsmError::MechanismInvalid` under `hw`.

## Error types

Failures surface through `craton_hsm::error::HsmError`.
`NxpHseBackend::is_stub()` reports the build mode at runtime.

## Usage

```rust
use craton_hsm_nxp::NxpHseBackend;
use craton_hsm::crypto::backend::CryptoBackend;

// Stub build — requires CRATON_HSM_ALLOW_STUB_NXP=1 in the env.
// `try_new` is the fallible production constructor; `new` panics and
// is kept only for backward compatibility (audit V7).
let backend = NxpHseBackend::try_new().expect("env-allowed stub or hw build");
assert!(NxpHseBackend::is_stub());

// With --features hw and the NXP HSE SDK linked in, the same code
// dispatches crypto calls to the HSE core via the Messaging Unit.
```

No runnable examples are shipped in `examples/`.

Add to `Cargo.toml`:

```toml
[dependencies]
craton-hsm-nxp = { path = "../craton-hsm-nxp", features = ["hw"] }
```

## Requirements

- Rust 1.75+.
- `craton-hsm-core` as a workspace dependency.
- **For `hw` builds only**: the NXP HSE firmware image flashed on the
  target SoC, and NXP's HSE host driver / SDK headers available to the
  Rust `ffi` module. These are distributed by NXP under separate terms.
- Target OS: typically an RTOS (AUTOSAR / FreeRTOS) or Linux running on
  the Cortex-A / Cortex-M cores of the target SoC. The crate is
  `#![deny(unsafe_code)]` in the default stub build; the `hw` path
  relies on the vendor SDK's own FFI layer.

## Limitations and caveats

- **Pre-release**. The `hw` feature is not yet validated end-to-end
  against production HSE firmware. Interfaces may change.
- Hardware integration requires the NXP HSE SDK, which is distributed
  under a separate NDA / license agreement with NXP. This crate does
  not bundle vendor headers or firmware.
- The default build is intentionally non-functional so that accidentally
  depending on this crate without configuring hardware fails loudly
  rather than silently falling back to software crypto.
- Ed25519 is not part of the HSE crypto menu on current-generation parts
  and will return an appropriate error under `hw`.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-nxp:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
