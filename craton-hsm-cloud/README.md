# craton-hsm-cloud

Cloud-native integration shims for Craton HSM.

## What it does

Provides reference implementations for exposing Craton HSM through
cloud-friendly interfaces:

- **`aws_shim`** — AWS CloudHSM API compatibility layer.
- **`azure_shim`** — Azure Key Vault-shaped surface.
- **`k8s_csi`** — Kubernetes CSI (Container Storage Interface) driver
  hooks (Identity, Controller, and Node service traits) for injecting
  secrets into pods as ephemeral volumes.
- **`vault_plugin`** — HashiCorp Vault Transit-compatible backend
  (encrypt, decrypt, sign, verify, key management).

## Status: reference / mock

> **These modules are reference scaffolding. The included
> implementations are in-memory mocks that use fake cryptography
> (HMAC-SHA256 over per-key random material; no AEAD, no real RSA or
> ECDSA). They are suitable only for local development and integration
> tests. Production deployments must re-implement these traits against
> a real Craton HSM backend and a real transport/server.**

## Double opt-in for mocks

The mock implementations are gated by **two** independent checks so it
is very hard to accidentally ship them:

1. **Cargo feature.** Mocks require the feature
   `mock-insecure-do-not-ship`. The alarming name is deliberate — it
   shows up prominently in `cargo tree` and audit tooling.
2. **Runtime environment variable.** Every mock constructor calls
   `mock_guard::check`, which panics with a loud diagnostic unless
   `CRATON_HSM_ALLOW_MOCK=1` is set in the environment.

A production binary that was accidentally compiled with the feature
will still refuse to instantiate a mock at runtime.

## Feature flags

| Flag | Default | Effect |
|------|---------|--------|
| `aws` | **on** | Compiles the `aws_shim` module. Disable with `default-features = false` if you don't need AWS CloudHSM. |
| `azure` | **on** | Compiles the `azure_shim` module. |
| `vault` | **on** | Compiles the `vault_plugin` module. |
| `csi` | **on** | Compiles the `k8s_csi` module. |
| `mock-insecure-do-not-ship` | off | Exposes the insecure in-memory mock backends. Requires `CRATON_HSM_ALLOW_MOCK=1` at runtime. |
| `permissive-for-tests` | off | Test convenience: installs an AllowAll ACL. Never enable in production. |

## Usage

```rust,ignore
// Tests / local development only. Requires:
//   cargo ... --features mock-insecure-do-not-ship
//   CRATON_HSM_ALLOW_MOCK=1

#[cfg(feature = "mock-insecure-do-not-ship")]
{
    use craton_hsm_cloud::vault_plugin::MockVaultBackend;

    std::env::set_var("CRATON_HSM_ALLOW_MOCK", "1");
    // NOTE: `MockVaultBackend::new()` was removed in the 2026-05-17 audit
    // sweep (hardcoded `hsm_addr` foot-gun). Use one of:
    //   - `MockVaultBackend::with_config(VaultTransitConfig { hsm_addr: ..., ... })`
    //     for explicit configuration, or
    //   - `MockVaultBackend::with_localhost_addr_for_tests()` for the legacy
    //     "https://localhost" shape inside test code only.
    let backend = MockVaultBackend::with_localhost_addr_for_tests();
    // ... exercise Vault-transit API shape ...
}
```

For production code, implement the public traits
(`VaultBackend`, `CsiIdentity` / `CsiController` / `CsiNode`,
`AwsHsmBackend`, `AzureKeyVaultBackend`) against the real Craton HSM
core and plug them into your chosen transport (gRPC, HTTP, etc.).

## MSRV

Rust **1.75+**.

## Safety (FFI / `unsafe`)

`#![deny(unsafe_code)]` at the crate root. No `unsafe` blocks in this
crate; integration code that wraps a vendor cloud SDK would live in a
consuming binary crate, not here.

## Security considerations

- Mock implementations are gated by **two** independent checks: the
  `mock-insecure-do-not-ship` Cargo feature **and** the
  `CRATON_HSM_ALLOW_MOCK=1` runtime environment variable. A production
  binary accidentally compiled with the feature still refuses to
  instantiate a mock at runtime.
- CSI driver helpers provide `prepare_csi_socket_dir(endpoint)` (parent
  directory mode 0700, created atomically with that mode via
  `DirBuilderExt::mode`, removes stale socket) and
  `harden_bound_socket(path)` (chmods the bound socket to 0600) so CSI
  endpoints do not leak via world-writable sockets.
- CSI `target_path` is validated against traversal (`..`) and symlink
  escape. The symlink-escape check **fails closed**: any
  canonicalisation error other than `NotFound` (e.g. `PermissionDenied`,
  symlink loop, generic I/O) rejects the path. `NotFound` is the only
  permitted fall-through because legitimate callers (and synthetic test
  fixtures) may pass a path that does not yet exist.
- **Cross-tenant isolation is the embedder's job, not this crate's.** The
  ACL trait (`AwsHsmAcl`, `AzureKvAcl`, `VaultAcl`, `CsiAuthorizer`) is the
  single integration point for tenant separation. The default ACL is
  deny-all (audit H20). Anything you build on top must implement and
  install a real policy — never enable the `permissive-for-tests` feature
  in a production build.
- **Identity is the embedder's job.** The shims accept a caller identity
  per request (`process_as` / `handle_request_as`). They do **not**
  implement environment / instance-profile / IMDS / SDK credential
  resolution; that is the responsibility of the binary that wires up
  these traits.
- **AEAD-shaped mock mechanisms are refused, not silently downgraded.**
  The mock AWS shim rejects `AesGcm` for `WrapKey` / `UnwrapKey`; the
  mock Azure shim rejects `A256GCM` / `A128GCM` for `Encrypt` / `Decrypt`.
  Real AES-GCM requires a real backend. The Vault mock supports
  `aes256-gcm96` / `aes128-gcm96` as key types — it logs a one-shot
  warning on first Encrypt to make clear the underlying implementation
  is XOR-stream + HMAC tag (non-AEAD) despite the AEAD-shaped name.
- **`MockVaultBackend::new()` was removed.** The previous constructor
  hardcoded `hsm_addr = "https://localhost"`, which would leak into any
  binary that constructed the mock via the `Default`-shaped API. Use
  `MockVaultBackend::with_config(...)` with an explicit address from
  your own configuration source, or
  `MockVaultBackend::with_localhost_addr_for_tests()` in test code.

## Error types

Failures surface through the individual trait return types documented in
the module docs. Mock constructors `panic!` (loudly, with diagnostic) if
the runtime environment variable is not set; this is intentional — mocks
must never silently instantiate.

## Requirements

- Rust 1.75+.
- The crate itself has no cloud-SDK dependencies. Real integrations
  layer cloud SDKs on top at the operator level.
- `#![deny(unsafe_code)]` and `#![deny(missing_docs)]` at the crate
  root.

## Limitations and caveats

- **The shipped crypto in mocks is not real crypto.** HMAC-SHA256 +
  XOR-stream "encrypt" is unforgeable by parties without the key, but
  it is not confidentiality-preserving under any adversary with access
  to ciphertext pairs and it is not authenticated-encryption.
- **No network transport is included.** These are in-process types.
  AWS CloudHSM speaks a custom TLS protocol, Azure Key Vault speaks
  REST, Vault speaks HTTP, and K8s CSI speaks gRPC over UDS —
  implementing those servers is the operator's responsibility.
- **Real cloud integrations require operator work.** This crate is a
  starting point, not a turnkey product.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-cloud:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
