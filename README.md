# Craton HSM Enterprise

[![CI](https://github.com/craton-co/craton-hsm-enterprise/actions/workflows/ci.yml/badge.svg)](https://github.com/craton-co/craton-hsm-enterprise/actions/workflows/ci.yml)
![License: BSL-1.1](https://img.shields.io/badge/license-BSL--1.1-blue)
![Source-available](https://img.shields.io/badge/source--available-yes-orange)
![MSRV: 1.75+](https://img.shields.io/badge/MSRV-1.75%2B-brightgreen)
![FIPS: planned](https://img.shields.io/badge/FIPS%20140--3-planned-yellow)
[![docs.rs](https://img.shields.io/badge/docs.rs-craton--hsm-blue)](https://docs.rs/craton-hsm)
[![codecov](https://img.shields.io/badge/codecov-pending-lightgrey)](https://codecov.io/gh/craton-co/craton-hsm-enterprise)
[![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF%20Scorecard-pending-lightgrey)](https://securityscorecards.dev/viewer/?uri=github.com/craton-co/craton-hsm-enterprise)

> **License**: Source-available under [Business Source License 1.1](LICENSE-BSL). This is **not** an OSI-approved open-source license. Competing uses (HSM/KMS products, managed crypto services, FIPS-validated services) require a commercial license from Craton Software Company Each version auto-converts to Apache 2.0 four years after release (or 2030-05-19, whichever is earlier).

Vendor-specific hardware backends, enterprise auth, clustering, and cloud integrations for [Craton HSM](https://github.com/craton-co/craton-hsm).

## Building from Source

Craton HSM Enterprise depends on the open core library `craton-hsm-core`, which lives in a separate repository. To build this workspace:

```bash
git clone https://github.com/craton-co/craton-hsm-core ../craton-hsm-core
git clone https://github.com/craton-co/craton-hsm-enterprise
cd craton-hsm-enterprise
cargo build --workspace
```

Both repositories must be checked out as siblings. See [BUILDING.md](BUILDING.md) for platform prerequisites.

## Quick Start

```rust,no_run
use craton_hsm_awslc::AwsLcBackend;
use craton_hsm::CryptoBackend;

// FIPS mode on
let backend = AwsLcBackend::new_fips();

// Generate an AES-256 key
let key = backend.generate_aes_key(256)?;

// Encrypt data
let plaintext = b"hello world";
let aad = b"";
let ciphertext = backend.aes_256_gcm_encrypt(&key, &plaintext[..], &aad[..])?;
# Ok::<(), craton_hsm::HsmError>(())
```

See [BUILDING.md](BUILDING.md) for full build instructions and feature flag reference.

> **FIPS Note**: In FIPS mode, prehashed signing operations are not available (they use non-FIPS RustCrypto internally and return `MechanismInvalid`). SHA-1 is also rejected. AES-128 key generation is permitted in FIPS mode (AES-128/192/256 are all FIPS-approved), though AES-256 is recommended for new keys. See [FIPS_CERTIFICATION_PLAN.md](FIPS_CERTIFICATION_PLAN.md) for the full FIPS boundary definition.
>
> **Module certification status**: `craton-hsm-awslc` links against the AWS-LC FIPS-validated module (NIST CMVP certificate **#4759** for AWS-LC). The Craton HSM module *itself* is **not yet** FIPS 140-3 certified — CMVP submission is planned (see [FIPS_CERTIFICATION_PLAN.md](FIPS_CERTIFICATION_PLAN.md)). Statements about FIPS validation in this workspace refer to the underlying AWS-LC library; do not infer module-level certification.

## Known Limitations

These are the headline gaps in `0.1.x` that operators must be aware of before deployment. Each item links to the canonical reference.

1. **FIPS 140-3 module certification is in progress, not yet awarded.** AWS-LC (the underlying crypto library) is FIPS-validated (CMVP #4759); the Craton HSM module itself has not yet been submitted to CMVP. See [FIPS_CERTIFICATION_PLAN.md](FIPS_CERTIFICATION_PLAN.md).
2. **NXP HSE backend (`craton-hsm-nxp`)** is 🚧 in progress. The `hw` feature is non-functional — `key_import_private` and most other hardware operations return `FunctionNotSupported`. The crate ships `publish = false` and must not be relied on for production.
3. **Infineon TPM2 backend (`craton-hsm-infineon`)** is 🚧 in progress. The `hw` feature uses placeholder TPM handles and placeholder `#[repr(C)]` FFI structs in `src/ffi.rs`; linking against a real `libtss2-esys` is undefined behavior until the FFI is finished. The crate ships `publish = false`.
4. **KMIP server (`craton-hsm-kmip`)** implements a **15-operation subset** of KMIP 2.1 §6 (Create, Get, Activate, Revoke, Destroy, Query, GetAttributes, Register, Locate, Check, AddAttribute, ModifyAttribute, DeleteAttribute, DeriveKey, RNG_Retrieve). Encrypt/Decrypt/Sign/SignatureVerify/MAC/MACVerify/CreateKeyPair return `OperationNotSupported`. Full OASIS KMIP 2.1 conformance is not claimed.
5. **PKCS#11 client (`craton-hsm-pkcs11`)** is a passthrough that delegates to a vendor PKCS#11 library. AES-CTR returns `CKR_FUNCTION_NOT_SUPPORTED` (blocked on the upstream `cryptoki` crate ≥ 0.8).
6. **Cluster crate (`craton-hsm-cluster`)** implements single-server membership change; **joint-consensus membership change is not implemented**. The crate bundles an `MTlsTransport` implementation; consumers may also plug in their own transport.
7. **CNG Ed25519** is provided via the RustCrypto `ed25519-dalek` carve-out because Windows CNG does not expose Ed25519 natively. Ed25519 sits outside the CNG FIPS boundary and is **rejected when FIPS mode is enabled**.

## Crates

| Crate | Description | Status |
|-------|-------------|--------|
| `craton-hsm-awslc` | Crypto backend using AWS-LC (FIPS-validated library — CMVP #4759 covers AWS-LC; module certification is separate) | **Available** |
| `craton-hsm-openssl` | OpenSSL crypto backend (non-FIPS) | **Available** |
| `craton-hsm-pkcs11` | PKCS#11 hardware HSM passthrough (AES-CTR not yet supported — blocked on `cryptoki` ≥ 0.8) | **Available** |
| `craton-hsm-auth` | RBAC, LDAP/cert/MFA/OIDC auth (`oidc-auth` feature), dual-control, tenant management | **Available** |
| `craton-hsm-cluster` | Raft consensus and replication (single-server membership change; joint-consensus not yet implemented) | **Available** |
| `craton-hsm-kmip` | KMIP 2.1 key-lifecycle server (TTLV wire format; **15-operation subset** — see Known Limitations) | **Available** |
| `craton-hsm-cloud` | Kubernetes CSI, AWS/Azure/Vault shims | **Available** |
| `craton-hsm-nxp` | Backend for NXP HSE (S32G/S32K3) — 🚧 `hw` feature returns `FunctionNotSupported`; not published | 🚧 **In progress** (non-functional) |
| `craton-hsm-infineon` | Backend for Infineon SLB 9670/9672 (TPM 2.0) — 🚧 `hw` feature uses placeholder handles/FFI; not published | 🚧 **In progress** (non-functional) |
| `craton-hsm-cng` | Windows CNG/BCrypt crypto backend (native BCrypt + `BCRYPT_PROV_DISPATCH` in FIPS mode; Ed25519 via RustCrypto, rejected in FIPS mode) | **Available** (Windows only) |
| `craton-hsm-certified` | Certified build tooling and verification (reproducible builds, CMVP artifacts, CAVP/ACVP harness). The Craton HSM module itself is *not yet* FIPS-validated. | **Available** |

## Architecture

These crates implement the `CryptoBackend` trait defined in [craton-hsm](https://github.com/craton-co/craton-hsm), delegating cryptographic operations to vendor-specific hardware rather than software implementations.

`craton-hsm-auth` provides enterprise authentication (RBAC, LDAP, certificates, MFA, OIDC via the `oidc-auth` feature) with multi-tenant management including per-tenant key quotas and isolation.

```
Application
    |
    v
craton-hsm (Apache-2.0)     <-- PKCS#11 C ABI, session/token/audit
    |
    +-- CryptoBackend trait
         |
         +-- RustCryptoBackend   (in craton-hsm, Apache-2.0) -- pure software
         +-- AwsLcBackend        (this repo, BSL 1.1)      -- FIPS software
         +-- NxpHseBackend       (this repo, BSL 1.1)      -- NXP HSE hardware
         +-- InfineonSlbBackend  (this repo, BSL 1.1)      -- Infineon TPM hardware
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full enterprise roadmap including:
- **Phase E1**: Hardware vendor backends (NXP HSE, Infineon TPM)
- **Phase E2**: FIPS 140-3 CMVP certification tooling
- **Phase E3**: HSM clustering/HA, KMIP protocol, cloud-native integrations
- **Phase E4**: Managed Craton HSM Cloud (SaaS)

## License

Copyright 2026 Craton Software Company Licensed under the [Business Source License 1.1](LICENSE-BSL).

**Competing use** (building or offering HSMs, KMS, cryptographic appliances, FIPS-validated crypto services, or professional services around this software) requires a commercial license from Craton Software Company

Each version automatically converts to [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) four years after its first public release.

See [LICENSE-CHANGE](LICENSE-CHANGE) for details.

## Getting Started

```bash
# Clone (core library must be a sibling directory)
git clone https://github.com/craton-co/craton-hsm-core ../craton-hsm-core
git clone https://github.com/craton-co/craton-hsm-enterprise
cd craton-hsm-enterprise

# Build and test
cargo build --workspace
cargo test --workspace
```

> **Note:** Some crates require feature flags for full functionality (e.g., `--features hw` for hardware backends, `--features mock-insecure-do-not-ship` for cloud mocks). See [BUILDING.md](BUILDING.md) for details.

See [BUILDING.md](BUILDING.md) for platform-specific prerequisites, FIPS build instructions, feature flags, cross-compilation, and troubleshooting.

## Requirements

- Rust 1.75+
- Go 1.21+ (required for FIPS builds with `craton-hsm-awslc`)
- [craton-hsm-core](https://github.com/craton-co/craton-hsm-core) checked out as a sibling directory
- Vendor-specific SDKs (optional, for `hw` feature):
  - **NXP**: HSE firmware SDK, S32 Design Studio or GCC ARM toolchain
  - **Infineon**: TSS ESAPI library (`libtss2-esys`), tpm2-tools

## Testing

```bash
# Run all tests
cargo test --workspace

# Test without cloud mocks (mocks are not default; use the line below to opt in)
cargo test -p craton-hsm-cloud

# Run lints
cargo clippy --workspace -- -D warnings

# Run security audit
cargo audit
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the pull request workflow, DCO sign-off requirement, and code style guide.

## Security

See [SECURITY.md](SECURITY.md) to report vulnerabilities and review known limitations.
Release artefacts are signed with cosign and accompanied by SBOM + SLSA
build provenance — see [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) for verification
steps.

## Documentation

| Document | Description |
|----------|-------------|
| [BUILDING.md](BUILDING.md) | Build instructions, feature flags, cross-compilation |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, FIPS boundary, dependency graph |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, known limitations |
| [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) | Release signing, SBOM, SLSA provenance, PGP key ceremony |
| [HARDENING.md](HARDENING.md) | Production security hardening guide |
| [OPERATIONS.md](OPERATIONS.md) | Operational runbooks (key rotation, CRL, cluster, backup) |
| [THREAT_MODEL.md](THREAT_MODEL.md) | STRIDE threat model and risk analysis |
| [FIPS_CERTIFICATION_PLAN.md](FIPS_CERTIFICATION_PLAN.md) | FIPS 140-3 certification roadmap and plan |
| [ROADMAP.md](ROADMAP.md) | Product roadmap (Phases E1-E4) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines and DCO |
| [CHANGELOG.md](CHANGELOG.md) | Version history and security fixes |
| [MAINTAINERS.md](MAINTAINERS.md) | Project maintainers and review ownership |
| [SUPPORT.md](SUPPORT.md) | Support policy, SLAs, and getting help |
| [COMPATIBILITY_MATRIX.md](COMPATIBILITY_MATRIX.md) | Supported OS, SDK, and library versions |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Consolidated troubleshooting guide |
