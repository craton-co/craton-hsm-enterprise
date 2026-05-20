# craton-hsm-infineon

Infineon OPTIGA TPM 2.0 backend for Craton HSM.

## What it does

Implements the `CryptoBackend` trait from `craton-hsm-core` on top of the
TCG TSS ESAPI (`libtss2-esys`), targeting Infineon's SLB 9670/9672
discrete TPM 2.0 chips and firmware TPM variants. All cryptographic
operations are dispatched to the TPM; no key material leaves the chip.

## ⚠️ Hardware path is not yet functional

**The `hw` feature is a work-in-progress and does not yet provide a
usable signing / encryption / decryption path.** This crate is published
with `publish = false` for that reason.

The sign / verify / encrypt / decrypt methods currently route through
**hardcoded persistent TPM handles** (`0x8100_0001..0004`) and ignore
the caller-supplied DER / SEC1 key material entirely — there is no
`Esys_Load` orchestration in place yet to import caller keys into the
TPM. Allowing those paths to proceed would mean the backend signs or
decrypts with whatever happens to be persisted at those slots, which
is a silent wrong-key foot-gun rather than a usable feature.

To prevent that, each of those methods now returns
`HsmError::FunctionNotSupported` immediately after emitting a
`PLACEHOLDER_HANDLE` tracing marker. They will remain disabled until
the `Esys_Load`-driven key import / load orchestration lands (tracked
as `TODO INFINEON-load` in `src/lib.rs`).

In addition, the `#[repr(C)]` FFI structs in `src/ffi.rs` are
placeholders without the algorithm-specific union shapes that
`libtss2-esys` expects on the wire. Linking the `hw` build against a
real `libtss2-esys` is therefore unsound, and the `hw` feature now
fails at compile time with a pointer to the bindgen work that needs
to happen first (`TODO(INFINEON-bindings)` in `src/ffi.rs`).

What this means for callers right now:

- Default builds remain stub-mode (all crypto returns
  `FunctionNotSupported`) and that is the only safe configuration.
- `cargo build --features hw` is rejected at compile time until real
  bindings ship.
- Real public-key generation (`Esys_CreatePrimary`-driven) and the
  RC-to-`HsmError` mapping are wired and exercised through the
  `EsapiBackend` mock under `--features test-stub`; that infrastructure
  is what the rest of the integration will build on top of.

## Hardware support

- Infineon **SLB 9670** — discrete TPM 2.0
- Infineon **SLB 9672** — firmware TPM

### Not yet supported / different API surface

- Infineon **OPTIGA Trust M** — embedded security controller. This part
  is **not** a TPM 2.0 device and does not speak the TCG TSS ESAPI; it
  uses a separate command set. It is out of scope for this crate today.

## Feature flags

| Flag | Default | Effect |
|------|---------|--------|
| `hw`        | off | Enable real TPM hardware calls via `libtss2-esys`. |
| `stub`      | off | Explicit development build: every `CryptoBackend` op returns `FunctionNotSupported`. Required for a no-hardware compile. |
| `test-stub` | off | Implies `stub`; additionally enables `MockEsapiBackend` and the trait-dispatching `CryptoBackend` impl so unit/integration tests can inject a fake TSS2 layer. |

The default `cargo build -p craton-hsm-infineon` (no features) is
intentionally rejected by a `compile_error!` at the crate root: a
feature-less build would silently return `FunctionNotSupported` for
every operation, which is a foot-gun in a release binary. For quick
no-hardware checks use `cargo check -p craton-hsm-infineon --features stub`.

**Without the `hw` feature (i.e. under `stub` / `test-stub`) this backend is a stub.**
Every `CryptoBackend` method returns
`HsmError::FunctionNotSupported` (except `ed25519_*`, which returns
`HsmError::MechanismInvalid` because TPM 2.0 does not define Ed25519
even with hardware present). The constructor emits a `tracing::warn!`
on first use; `InfineonTpmBackend::is_stub()` reports the build mode.

## Supported TPM2 primitives (hw)

- `TPM2_Create` / `TPM2_Load` for transient RSA and ECC keys
- `TPM2_Sign` / `TPM2_VerifySignature` for RSA (PKCS#1 v1.5, PSS) and
  ECDSA (P-256)
- `TPM2_EncryptDecrypt2` for symmetric AES (CBC/CTR)
- `TPM2_GetRandom` for hardware RNG
- `TPM2_Hash` / `TPM2_HashSequenceStart` for SHA-2 digests
- `TPM2_RSA_Encrypt` / `TPM2_RSA_Decrypt` for OAEP

## MSRV

Rust **1.75+**.

## Safety (FFI / `unsafe`)

The default stub build is `#![deny(unsafe_code)]` at the crate root —
there is no `unsafe` in the stub path at all. Under `--features hw`,
`unsafe` is scoped to the `ffi` submodule that binds to `libtss2-esys`.
All marshalling uses the `validate_tpm2b_size()` bounds-check helper on
TPM2B buffers before crossing the FFI boundary.

## Security considerations

- No key material leaves the TPM under `hw`; all crypto is TPM-dispatched.
- PCR-based sealing is available once the `hw` path is fully wired up.
- The default stub build is intentionally non-functional so deployments
  that forget to enable `hw` fail loudly rather than falling back to
  software crypto.

## Error types

Failures surface through `craton_hsm::error::HsmError`.
`InfineonTpmBackend::is_stub()` reports the build mode at runtime so
callers can branch on whether hardware is actually present.

## Usage

```rust
use craton_hsm_infineon::InfineonTpmBackend;
use craton_hsm::crypto::backend::CryptoBackend;

// Default build — stub.
let backend = InfineonTpmBackend::new();
assert!(InfineonTpmBackend::is_stub());

// With --features hw, operations are dispatched to the TPM through
// the ESAPI FFI layer.
```

No runnable examples are shipped in `examples/`.

Add to `Cargo.toml`:

```toml
[dependencies]
craton-hsm-infineon = { path = "../craton-hsm-infineon", features = ["hw"] }
```

## Requirements

- Rust 1.75+.
- `craton-hsm-core` as a workspace dependency.
- **For `hw` builds only**:
  - **tpm2-tss 4.0+** (`libtss2-esys`, `libtss2-tcti-*`) and its
    development headers. On Debian/Ubuntu: `apt install libtss2-dev`.
  - A TPM 2.0 chip visible at `/dev/tpmrm0` (or an accessible TCTI) and
    a user with read/write permission on the resource manager device.
  - Linux is the primary supported platform. Windows support via the
    Windows TBS (TPM Base Services) TCTI is on the roadmap but not
    currently wired up.

## Limitations and caveats

- **Pre-release** — the `hw` path has been exercised against swtpm and
  a limited set of discrete Infineon parts. Firmware TPM coverage is
  partial.
- **No Ed25519.** TPM 2.0 does not define Ed25519 and Infineon parts do
  not expose it. Calls return `HsmError::MechanismInvalid` regardless
  of feature flags.
- Hierarchy, sessions, and auth policies are managed internally; fine-
  grained policy customisation is not yet exposed at this crate's API.
- The default stub build is intentionally non-functional so deployments
  that forget to enable `hw` fail loudly rather than falling back to
  software crypto.
- `#![deny(unsafe_code)]` at the crate root; FFI bindings are scoped to
  the `ffi` module.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-infineon:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
