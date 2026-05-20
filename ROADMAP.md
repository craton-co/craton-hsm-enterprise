# Craton HSM Enterprise Roadmap

**Status legend:** ✅ shipped · 🚧 in progress · 📋 planned

## Current (v0.1.2 — Available)

### craton-hsm-awslc — FIPS-Validated Crypto Backend ✅
- Full `CryptoBackend` trait implementation (26 methods) using aws-lc-rs
- FIPS 140-3 validated library (AWS-LC)
- RSA (PKCS#1v15, PSS, OAEP), ECDSA (P-256, P-384), Ed25519, AES-GCM/CBC/CTR
- Key generation, key wrap/unwrap, ECDH key derivation
- SHA-1/256/384/512, SHA3-256/384/512 digest support
- Self-contained prehashed signing (no delegation to core)

### craton-hsm-openssl — OpenSSL Crypto Backend ✅
- Non-FIPS OpenSSL 3 backend with parallel algorithm coverage
- Optional file-backed persistent AES-GCM counter

### craton-hsm-pkcs11 — PKCS#11 Hardware Passthrough ✅
- Session pool, LRU key cache, GCM counter high-water persistence across eviction
- Vendor-library-agnostic (SoftHSM, Thales Luna, YubiHSM, Utimaco, nCipher, CloudHSM)

### craton-hsm-auth — Enterprise Auth & Multi-Tenancy ✅
- RBAC, LDAP, OIDC, X.509 certificate, TOTP MFA, dual-control approvals, tenants

### craton-hsm-cng — Windows CNG Backend ✅
- Native Windows BCrypt integration with FIPS-dispatch provider mode

### craton-hsm-cluster — HSM Clustering & HA ✅
- Raft consensus (term tracking, log replication, leader election)
- Key replication protocol (SHA-256 checksummed entries, sequence tracking)
- Cluster health monitoring (split-brain detection, quorum checks)
- HMAC-SHA256 authenticated RPCs, per-peer `RequestVote` rate limiter
- Authenticated snapshots (HMAC footer), leader-lease gating for linearizable reads
- Bounded replication log (`max_payload_bytes`, `max_log_entries`)
- 🚧 Online membership change protocol (joint consensus)
- 📋 Active-active deployment mode, distributed key generation (threshold crypto)

### craton-hsm-kmip — KMIP Protocol Server ✅
- KMIP 2.1 wire encoding (TTLV), **subset of operations (15 ops)** implemented; codec with depth + size limits
- Operations implemented: Create, Get, Activate, Revoke, Destroy, Query, GetAttributes, Register, Locate, Check, AddAttribute, ModifyAttribute, DeleteAttribute, DeriveKey, RNG_Retrieve
- Operations explicitly returning `OperationNotSupported`: Encrypt, Decrypt, Sign, SignatureVerify, MAC, MACVerify, CreateKeyPair
- **OASIS KMIP 2.1 conformance is not claimed**; many other §6 operations are not modeled
- Static-token auth double-gated behind `insecure-static-token` feature + env var
- 🚧 Interoperability validation (VMware vSphere, NetApp, Dell EMC)
- 📋 KMIP 2.1 extended profiles (split keys, PGP, certificate chains)

### craton-hsm-cloud — Cloud-Native Shims ✅ (reference / mocks)
- 🚧 Kubernetes CSI driver hooks (Identity, Controller, Node)
- 🚧 HashiCorp Vault transit plugin surface
- 🚧 AWS CloudHSM API shim
- 🚧 Azure Key Vault REST compatibility layer
- Mocks double-gated: `mock-insecure-do-not-ship` feature + `CRATON_HSM_ALLOW_MOCK=1`

### craton-hsm-certified — FIPS Certification Tooling ✅
- Deterministic / reproducible builds (SHA-256 comparison)
- Binary integrity HMAC-SHA256
- CMVP submission artifact generation
- Approved-mode-only configuration enforcement
- ACVP test vector runner (multi-algorithm)
- Security Policy document generator (all 11 FIPS sections)
- Finite State Machine validation (Graphviz DOT export)
- Binary signing with canonical-JSON metadata footer
- Power-on self-tests (POST) for all approved algorithms
- 📋 Module itself is not yet FIPS-certified — see Phase E2

---

## Phase E1 — Hardware Vendor Backends (Pre-release)

### craton-hsm-nxp — NXP HSE Hardware Security Engine 🚧
- **Target hardware**: NXP S32G274A (GoldBox), S32G399A, S32K344/S32K358
- HSE firmware communication via Messaging Unit (MU)
- Key provisioning into HSE key catalog
- Hardware-accelerated AES, RSA, ECDSA
- Secure boot chain integration
- **Prerequisites**: NXP HSE firmware SDK, S32 Design Studio or GCC ARM toolchain
- Default build is a software stub; `hw` feature flag enables hardware path (pre-release)
- **Current `0.1.x` gap (🚧 in progress):** the `--features hw` path is non-functional. `key_import_private` returns `HsmError::FunctionNotSupported`; every other `hw`-gated cryptographic op is a stub. The crate ships `publish = false` in `Cargo.toml` until the HSE FFI wiring lands.

### craton-hsm-infineon — Infineon OPTIGA TPM 2.0 🚧
- **Target hardware**: Infineon SLB 9670 (discrete TPM), SLB 9672 (firmware TPM), OPTIGA Trust M
- TSS ESAPI communication layer (`libtss2-esys`)
- Key provisioning into TPM NV storage
- RSA, ECDSA, AES operations delegated to TPM
- PCR-based key sealing
- Platform attestation support
- **Prerequisites**: TSS ESAPI library, tpm2-tools
- Default build is a software stub; `hw` feature flag enables hardware path (pre-release)
- **Current `0.1.x` gap (🚧 in progress):** under `--features hw`, sign/verify/encrypt use hardcoded placeholder TPM handles (`0x8100_0001..0x8100_0004`) **and** the `#[repr(C)]` FFI structs in `src/ffi.rs` are placeholders. Linking against a real `libtss2-esys` against the current FFI definitions is undefined behavior. The crate ships `publish = false` until the FFI is reconciled with upstream `tpm2-tss`.

---

## Phase E2 — FIPS 140-3 Certification 📋

Submission of the `craton-hsm` module to a CMVP-accredited lab. The tooling in `craton-hsm-certified` (shipped above) produces the artifacts; the validation itself is a 6–12 month external process.

- 📋 Select CMVP testing laboratory
- 📋 Submit Implementation Under Test (IUT)
- 📋 Algorithm testing (CAVP/ACVP)
- 📋 Security Policy review
- 📋 Issuance of validation certificate
- **Estimated cost**: $50K-$200K for CMVP Level 1 validation

---

## Phase E3 — Deferred Enterprise Features 📋

Items originally planned for E3 that are not yet shipped:

- 📋 Windows certificate store integration in `craton-hsm-cng`
- 📋 TPM 2.0 via Windows Platform Crypto Provider in `craton-hsm-cng`
- 📋 Threshold cryptography / distributed key generation in `craton-hsm-cluster`
- 📋 Full KMIP 2.1 profile coverage in `craton-hsm-kmip`
- 📋 Production-grade (non-mock) cloud integrations in `craton-hsm-cloud`

---

## Phase E4 — Managed Service (Craton HSM Cloud)

### SaaS Offering
- Multi-tenant HSM-as-a-Service
- Per-tenant key isolation with namespace separation
- Usage-based billing (API calls, key operations, storage)
- SOC 2 Type II compliance
- Geographic key residency controls
- REST API + gRPC API + PKCS#11 over network

### Enterprise Support Tiers
- **Standard**: Business-hours email support, 48h SLA
- **Professional**: 24/5 support, 4h SLA, dedicated Slack channel
- **Enterprise**: 24/7 support, 1h SLA, named engineer, on-site consulting

---

## Revenue Model

| Phase | Revenue Source | Target Market |
|-------|---------------|---------------|
| E1 | Hardware backend licenses | Automotive, IoT, embedded |
| E2 | FIPS certification + certified builds | Government, finance, healthcare |
| E3 | Enterprise feature licenses + support | Large enterprises, cloud providers |
| E4 | SaaS subscriptions | SMBs, startups, regulated industries |

## Timeline

| Phase | Target | Dependencies |
|-------|--------|-------------|
| E1 | When hardware partnerships secured | Vendor SDK access |
| E2 | After CMVP lab engagement | $50K-$200K budget, 6-12 month process |
| E3 | When enterprise customers demand it | Core repo stability (v1.0) |
| E4 | After E2+E3 mature | Infrastructure investment |
