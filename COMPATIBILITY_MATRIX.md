# Compatibility Matrix

Supported and tested platforms, toolchains, SDKs, and hardware for `craton-hsm-enterprise 0.1.2`.

## Terminology

- **Tested**: CI has a matrix entry that builds and runs the relevant test subset on this platform for every PR.
- **Supported**: We accept bug reports against this configuration and will prioritize fixes as part of the normal triage process. Not every supported configuration is covered by CI.
- **Best-effort**: Builds are known to work but are not regularly exercised; bugs are triaged as low priority.
- **Unsupported**: Not covered; issues will be closed as out of scope.

Only the latest `0.1.x` release is supported. See [SUPPORT.md](SUPPORT.md) for the full policy.

> **CI vs. matrix note (2026-04-18)**: `.github/workflows/ci.yml` currently
> uses GitHub's `ubuntu-latest`, `windows-latest`, and `macos-latest`
> runners, which resolve to a single version per family at any given
> time (Ubuntu 24.04, Windows Server 2022, macOS 14 at time of writing).
> Entries in the tables below marked **Tested** for multiple versions
> within a family (e.g. Ubuntu 22.04 *and* 24.04, macOS 13/14/15) are
> exercised pre-release against the listed versions but are **not** all
> covered by per-PR CI. Treat the "Tested" label on a non-`latest`
> version as equivalent to "Supported" for CI-coverage purposes until CI
> pins explicit versions in a future matrix expansion.

## Operating Systems

| OS | Version | Kernel | Arch | Status |
|----|---------|--------|------|--------|
| Ubuntu | 22.04 LTS (Jammy) | 5.15+ | x86_64, aarch64 | Tested |
| Ubuntu | 24.04 LTS (Noble) | 6.8+ | x86_64, aarch64 | Tested |
| Debian | 12 (Bookworm) | 6.1+ | x86_64, aarch64 | Supported |
| Debian | 13 (Trixie) | 6.x | x86_64, aarch64 | Best-effort |
| RHEL / Rocky / AlmaLinux | 9.x | 5.14+ | x86_64, aarch64 | Supported |
| RHEL / Rocky / AlmaLinux | 8.x | 4.18+ | x86_64 | Best-effort |
| Amazon Linux | 2023 | 6.1+ | x86_64, aarch64 | Supported |
| Windows Server | 2022 | 10.0.20348 | x86_64 | Tested (CNG backend only) |
| Windows Server | 2019 | 10.0.17763 | x86_64 | Best-effort |
| macOS | 13 (Ventura) | Darwin 22 | x86_64, aarch64 | Development only |
| macOS | 14 (Sonoma) | Darwin 23 | aarch64 | Development only |
| macOS | 15 (Sequoia) | Darwin 24 | aarch64 | Development only |

macOS is for development and CI of non-FIPS builds only. **Do not deploy production HSM workloads on macOS.** FIPS builds on macOS are not validated.

Windows production deployments cover the `craton-hsm-cng` backend; Linux-only crates (`craton-hsm-nxp`, `craton-hsm-infineon`) are excluded on Windows. See [BUILDING.md](BUILDING.md#windows-cng-backend-craton-hsm-cng).

## Rust Toolchain (MSRV)

| Component | Version | Notes |
|-----------|---------|-------|
| Minimum supported Rust | 1.75.0 | Enforced by `rust-version` in every `Cargo.toml` |
| Tested toolchains | stable, 1.75.0 (pinned) | CI runs both |
| Edition | 2021 | All crates |

MSRV bumps are a breaking change for consumers and require two core-team approvals (see [MAINTAINERS.md](MAINTAINERS.md)). Nightly is not supported; do not file bugs against nightly-only compilation failures.

## Go Toolchain (FIPS builds only)

The `craton-hsm-awslc` crate with the `fips` feature requires Go for the AWS-LC FIPS module build.

| Component | Version | Notes |
|-----------|---------|-------|
| Go | 1.21+ | Required by aws-lc-rs FIPS module build scripts |
| Go | 1.18–1.20 | Best-effort; older toolchains may fail on newer aws-lc-rs releases |

Go is only needed at build time. The produced binary has no Go runtime dependency.

## Crypto Backends

| Backend | Library | Version | Status |
|---------|---------|---------|--------|
| `craton-hsm-awslc` (FIPS) | `aws-lc-rs` | =1.16.2 (pinned) | Tested |
| `craton-hsm-openssl` | system OpenSSL | 3.0.x, 3.2.x | Tested on Ubuntu 22.04 / 24.04 |
| `craton-hsm-openssl` | system OpenSSL | 1.1.1 | Best-effort (EOL upstream) |
| `craton-hsm-cng` | Windows CNG / BCrypt | OS-provided | Tested on Windows Server 2022 |

## PKCS#11 Libraries (`craton-hsm-pkcs11`)

The passthrough crate itself has no version gate; compatibility is with the vendor library binding against the PKCS#11 v2.40 / v3.0 spec.

| Vendor / Library | Version | Status | Notes |
|------------------|---------|--------|-------|
| SoftHSM | 2.6.0+ | Tested | CI uses SoftHSM as the default PKCS#11 fixture |
| SoftHSM | 2.5.x | Best-effort | |
| YubiHSM2 SDK | 2023.08+ | Supported | Requires `yubihsm-connector` running |
| Thales Luna Client | 10.x | Supported | HSM firmware 7.x series; mTLS to appliance |
| Utimaco CryptoServer | Se-Series (CP5) | Supported | CryptoServer SDK 4.40+ |
| nCipher nShield | Security World 13.x | Best-effort | Requires `hardserver` |
| AWS CloudHSM | Client 5.x | Best-effort | |

Only SoftHSM is exercised by CI. Other vendor libraries are validated pre-release against the listed versions; regression risk between our releases is low but not zero.

## Hardware Vendor SDKs

| Crate | Vendor | Hardware | SDK / Firmware | Status |
|-------|--------|----------|----------------|--------|
| `craton-hsm-nxp` | NXP | S32G2 (S32G274A) | HSE firmware 1.x | 🚧 In progress[^hw] |
| `craton-hsm-nxp` | NXP | S32G3 (S32G399A) | HSE firmware 1.x | 🚧 In progress[^hw] |
| `craton-hsm-nxp` | NXP | S32K3 (S32K344) | HSE firmware 1.x | 🚧 In progress[^hw] |
| `craton-hsm-nxp` | NXP | S32G1 / legacy S32K | — | Unsupported |
| `craton-hsm-infineon` | Infineon | SLB 9670 TPM 2.0 | tpm2-tss 4.0+ | 🚧 In progress[^hw] |
| `craton-hsm-infineon` | Infineon | SLB 9672 TPM 2.0 | tpm2-tss 4.0+ | 🚧 In progress[^hw] |
| `craton-hsm-infineon` | Infineon | SLB 9665 TPM 1.2 | — | Unsupported (TPM 1.2 out of scope) |

[^hw]: The `hw` feature is **non-functional** in `0.1.x`. NXP operations return `HsmError::FunctionNotSupported` (`key_import_private` and other `--features hw` paths are stubs). Infineon operations use hardcoded placeholder TPM handles (`0x8100_0001..0x8100_0004`) and placeholder `#[repr(C)]` FFI structs in `src/ffi.rs`; linking against a real `libtss2-esys` is undefined behavior until the FFI wiring lands. Both crates ship `publish = false` in their `Cargo.toml`. See [ROADMAP.md](ROADMAP.md#phase-e1--hardware-vendor-backends-pre-release).

Without the `hw` feature, NXP and Infineon crates build as software stubs on any platform supported by the rest of the workspace. See [BUILDING.md](BUILDING.md#hardware-backend-builds) for SDK acquisition and build steps.

## KMIP Protocol (`craton-hsm-kmip`)

| Spec | Version | Status |
|------|---------|--------|
| OASIS KMIP | 2.1 (subset — 15 ops) | Wire format tested; **not OASIS-conformant** |
| OASIS KMIP | 1.4 | Best-effort (intersection with the 2.1 subset only) |
| OASIS KMIP | 3.0 | Unsupported in `0.1.x` |

Implemented operations (15): `Create`, `Get`, `Activate`, `Revoke`, `Destroy`, `Query`, `GetAttributes`, `Register`, `Locate`, `Check`, `AddAttribute`, `ModifyAttribute`, `DeleteAttribute`, `DeriveKey`, `RNG_Retrieve`.

Operations that explicitly return `OperationNotSupported`: `Encrypt`, `Decrypt`, `Sign`, `SignatureVerify`, `MAC`, `MACVerify`, `CreateKeyPair`. Many other KMIP 2.1 §6 operations are not yet modeled. **Full OASIS KMIP 2.1 conformance is not claimed.** See [CHANGELOG.md](CHANGELOG.md) for additions per release.

## Authentication Providers (`craton-hsm-auth`)

| Provider | Requirement | Status |
|----------|-------------|--------|
| LDAP / LDAPS | LDAPv3, TLS 1.2+ | Supported via `ldap-auth` feature |
| OIDC | OIDC Core 1.0, RS256 / RS384 / RS512 / ES256 / ES384 | Supported via `oidc-auth` feature |
| X.509 certificate | PKCS#7 / PEM / DER, static CRL | Supported via `cert-auth` feature |
| TOTP (MFA) | RFC 6238; SHA-1 and SHA-256 | Supported |
| Local PIN store | — | Dev/test only; not supported in production |

OCSP and HTTP CRL Distribution Point fetching are not implemented in `0.1.x` (see [SECURITY.md](SECURITY.md)).

## Cluster (`craton-hsm-cluster`)

| Component | Requirement |
|-----------|-------------|
| Raft peers | Minimum 3 for fault tolerance; odd numbers recommended |
| Message integrity | HMAC-SHA256 (mandatory unless `insecure-no-cluster-secret` feature is on) |
| Wire encryption | Bundled `MTlsTransport` (or plug your own transport implementation) |
| Clock skew tolerance | ±30s default (configurable via `max_message_age_ms`) |
| Membership change | Single-server change only; **joint-consensus is not implemented** |

## Cloud Integrations (`craton-hsm-cloud`)

| Integration | API Version | Status |
|-------------|-------------|--------|
| Kubernetes CSI | CSI v1.8+ | Supported |
| AWS KMS shim | AWS SDK for Rust | Shim only; no production validation |
| Azure Key Vault shim | Azure SDK for Rust | Shim only; no production validation |
| HashiCorp Vault shim | KV v2, Transit | Shim only; no production validation |

Mock implementations are gated behind `mock-insecure-do-not-ship`; they are explicitly not for production use.

## Container and Orchestrator Targets

| Platform | Version | Status |
|----------|---------|--------|
| Docker / Docker Engine | 24.x, 25.x | Supported |
| Podman | 4.x, 5.x | Best-effort |
| Kubernetes | 1.28, 1.29, 1.30, 1.31 | Supported |
| Kubernetes | 1.27 and earlier | Unsupported (upstream EOL) |
| OpenShift | 4.14+ | Best-effort |

PodSecurity admission at the `restricted` level is required for the manifests in [DEPLOYMENT.md](DEPLOYMENT.md).

## Cross-crate operation coverage

The table below summarises which `CryptoBackend` trait methods are
actually implemented (rather than stubbed) by each backend crate. It is
intended for embedders picking a backend per operation, not as a
substitute for reading the per-crate README.

Legend:

- supported — implemented and exercised by the crate's own tests.
- stubbed — entry point exists but rejects with `HsmError::FunctionNotSupported` or a similar refusal. Documented inline in the crate.
- not applicable — the operation is meaningless for the backend (e.g. the PKCS#11 passthrough never owns key material directly).
- in progress — the hardware/FFI path is not yet wired (`publish = false`).

| Operation | awslc | openssl | cng | pkcs11 | nxp | infineon |
|---|---|---|---|---|---|---|
| rsa_pkcs1v15_sign / verify | supported | supported | supported | supported | in progress | in progress |
| rsa_pkcs1v15_sign_prehashed / verify_prehashed | supported (non-FIPS RustCrypto; rejected in FIPS) | supported (non-FIPS RustCrypto; rejected in FIPS) | supported | supported | in progress | in progress |
| rsa_pss_sign / verify | supported | supported | supported | supported | in progress | in progress |
| rsa_pss_sign_prehashed / verify_prehashed | supported (non-FIPS RustCrypto; rejected in FIPS) | supported (non-FIPS RustCrypto; rejected in FIPS) | supported | supported | in progress | in progress |
| rsa_oaep_encrypt / decrypt | supported | supported | supported | supported | in progress | in progress |
| ecdsa_p256_sign / verify | supported | supported | supported | supported | in progress | in progress |
| ecdsa_p384_sign / verify | supported | supported | supported | supported | in progress | in progress |
| ecdsa_p256_sign_prehashed / verify_prehashed | supported (non-FIPS) | supported (non-FIPS) | supported | supported | in progress | in progress |
| ecdsa_p384_sign_prehashed / verify_prehashed | supported (non-FIPS) | supported (non-FIPS) | supported | supported | in progress | in progress |
| ed25519_sign / verify | supported | supported | supported (refused in FIPS — RustCrypto) | supported | in progress | in progress |
| aes_256_gcm_encrypt / decrypt | supported | supported | supported | supported | in progress | in progress |
| aes_cbc_encrypt / decrypt | supported | supported | supported | supported | in progress | in progress |
| aes_ctr_encrypt / decrypt | supported | supported | supported | stubbed (cryptoki 0.7 lacks `Mechanism::AesCtr`; rejects with `FunctionNotSupported`) | in progress | in progress |
| aes_key_wrap / unwrap | supported | supported | supported | supported | in progress | in progress |
| ecdh_p256 / ecdh_p384 | supported | supported | supported | supported | in progress | in progress |
| generate_aes_key | supported | supported | supported | supported | in progress | in progress |
| generate_rsa_key_pair | supported | supported | supported | supported | in progress | in progress |
| generate_ec_p256_key_pair / generate_ec_p384_key_pair | supported | supported | supported | supported | in progress | in progress |
| generate_ed25519_key_pair | supported | supported | supported (refused in FIPS) | supported | in progress | in progress |
| compute_digest | supported | supported | supported | supported | in progress | in progress |
| create_hasher | supported | supported | supported | supported | in progress | in progress |
| digest_output_len | supported | supported | supported | supported | in progress | in progress |

PQC trait methods on `CryptoBackend` (`ml_kem_*`, `ml_dsa_*`, `slh_dsa_*`, hybrid KEM/signature) carry default implementations that return `HsmError::FunctionNotSupported`; none of the backends in this workspace override them yet. They are tracked in the workspace [ROADMAP.md](ROADMAP.md).

## What "Unsupported" Means

Issues filed against Unsupported configurations will be closed with a pointer to this document. Commercial support contracts (`support@craton.io`) can, on a case-by-case basis, expand the supported set for a specific customer environment.
