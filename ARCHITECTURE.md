# Architecture

This document describes the high-level architecture of Craton HSM Enterprise.

## Overview

Craton HSM uses a **trait-based backend system**. The `craton-hsm-core` crate
(Apache-2.0, separate repository) defines the `CryptoBackend` trait and provides
a pure-software RustCrypto implementation. This enterprise repository supplies
additional backends, enterprise services, and cloud integrations under BSL 1.1.

Every backend implements the same `CryptoBackend` trait, so application code is
backend-agnostic: swap `RustCryptoBackend` for `AwsLcBackend` to gain FIPS
validation, or for `Pkcs11PassthroughBackend` to delegate to hardware.

## Backend Hierarchy

```
CryptoBackend (trait, defined in craton-hsm-core)
|
+-- RustCryptoBackend     (craton-hsm-core)      Pure software, no FIPS
|
+-- Software backends (this repo)
|   +-- AwsLcBackend      (craton-hsm-awslc)     FIPS 140-3 via aws-lc-rs
|   +-- OpenSslBackend    (craton-hsm-openssl)    OpenSSL, non-FIPS
|   +-- CngBackend        (craton-hsm-cng)        Windows CNG (native BCrypt with FIPS dispatch; Ed25519 intentionally delegated to RustCrypto outside the CNG FIPS boundary)
|
+-- Hardware backends (this repo, require `hw` feature)
    +-- NxpHseBackend       (craton-hsm-nxp)      NXP S32G/S32K3 HSE — 🚧 hw feature is non-functional in 0.1.x
    +-- InfineonTpmBackend  (craton-hsm-infineon)  Infineon SLB 9670/9672 TPM 2.0 — 🚧 placeholder handles/FFI in 0.1.x
    +-- Pkcs11PassthroughBackend (craton-hsm-pkcs11)  Any PKCS#11 token (passthrough; AES-CTR not yet supported)
```

The two hardware-backend entries above are 🚧 **in progress** — they are not usable today. NXP `--features hw` operations return `HsmError::FunctionNotSupported`. The Infineon `--features hw` path uses placeholder TPM handles and placeholder `#[repr(C)]` FFI structs in `src/ffi.rs`; linking against a real `libtss2-esys` is undefined behavior. Both crates ship `publish = false`. See [ROADMAP.md](ROADMAP.md#phase-e1--hardware-vendor-backends-pre-release) for the wiring plan.

**Algorithms supported** (varies by backend): RSA (PKCS#1 v1.5, PSS, OAEP),
ECDSA (P-256, P-384), Ed25519, AES (GCM, CBC, CTR), AES key wrap, ECDH
(P-256, P-384), SHA-2 family, HKDF.

## Enterprise Services Layer

Beyond crypto backends, the enterprise repo provides four service crates:

| Crate | Purpose |
|---|---|
| `craton-hsm-auth` | RBAC, LDAP, OIDC, certificate, MFA authentication; multi-tenant management with per-tenant key quotas and isolation |
| `craton-hsm-cluster` | Raft consensus, leader election, key replication, snapshots, health monitoring for HA deployments. Bundles an `MTlsTransport`; single-server membership change (joint-consensus is not implemented). |
| `craton-hsm-kmip` | KMIP 2.1 server with TTLV wire encoding, a **15-operation subset** of KMIP 2.1 §6 (not OASIS-conformant), and a message dispatcher. See [COMPATIBILITY_MATRIX.md](COMPATIBILITY_MATRIX.md#kmip-protocol-craton-hsm-kmip) for the operation list. |
| `craton-hsm-cloud` | Kubernetes CSI driver, HashiCorp Vault transit plugin, AWS CloudHSM shim, Azure Key Vault shim |

Additionally:

| Crate | Purpose |
|---|---|
| `craton-hsm-certified` | FIPS 140-3 certification tooling: binary integrity (HMAC-SHA256), reproducible builds, CMVP artifacts, CAVP/ACVP test harness |

## FIPS Boundary

The FIPS 140-3 *intended* module boundary is defined by `craton-hsm-awslc`,
which links against a FIPS-validated build of AWS-LC.

> **Certification status:** AWS-LC (the cryptographic library) is independently
> FIPS-validated under CMVP certificate **#4759**. The Craton HSM module
> *itself* is **not yet** FIPS 140-3 certified — submission to CMVP is planned
> (see [FIPS_CERTIFICATION_PLAN.md](FIPS_CERTIFICATION_PLAN.md)). When this
> document or others use the phrase "FIPS-validated" without further
> qualification, it refers to the AWS-LC library, not to a module-level
> certificate.

### Inside the FIPS boundary

- Key generation (AES, RSA, EC, Ed25519) via aws-lc-rs
- Signing and verification (RSA PKCS#1v1.5, RSA-PSS, ECDSA, Ed25519)
- Encryption and decryption (AES-GCM, AES-CBC, AES-CTR, RSA-OAEP)
- Hashing (SHA-256, SHA-384, SHA-512) via aws-lc-rs
- Key wrap/unwrap (AES-KW)
- Key agreement (ECDH P-256, P-384)
- HKDF key derivation

### Outside the FIPS boundary

- **Prehashed signing**: aws-lc-rs does not expose prehashed APIs. The 8
  prehashed methods use RustCrypto (`rsa`, `p256`, `p384`) for the signature
  math. When `fips_mode = true`, prehashed operations are rejected.
- All authentication logic (craton-hsm-auth)
- Cluster consensus and replication (craton-hsm-cluster)
- KMIP protocol handling (craton-hsm-kmip)
- Cloud integration shims (craton-hsm-cloud)
- Session management and audit logging (craton-hsm-core)

## Tenant Isolation Model

`craton-hsm-auth` implements multi-tenant isolation:

- Each tenant has a unique ID, display name, and status (active/suspended)
- Per-tenant key quotas enforce resource limits
- Tenant context is propagated through sessions; key operations are scoped to
  the authenticated tenant
- Suspended tenants cannot perform cryptographic operations
- RBAC policies are evaluated per-tenant: a role grant in tenant A does not
  confer access in tenant B

## Security Design Principles

1. **Fail-closed**: Unknown states and unexpected errors reject the operation.
   FIPS mode backends reject all operations if the underlying library cannot
   confirm FIPS validation. The CNG stub rejects all ops when `fips_mode = true`.

2. **Constant-time comparisons**: PIN verification and signature verification
   use the `subtle` crate for constant-time equality checks to prevent timing
   side channels.

3. **Zeroization**: Key material is wrapped in `Zeroizing<T>` (from the
   `zeroize` crate) and wiped on drop. PIN material in PKCS#11 configs uses
   `Zeroizing<String>`.

4. **AES-GCM nonce budget**: Per-key encryption counters enforce the NIST
   SP 800-38D 2^32 nonce-reuse bound. Keys that exhaust their budget are
   permanently poisoned (AwsLcBackend, OpenSslBackend).

5. **Fail-closed software fallbacks**: PKCS#11 key generation only falls back
   to software when explicitly opted in via
   `allow_software_keygen_fallback = true`.

6. **Domain-separated fingerprints**: PKCS#11 cache keys use per-key-type
   domain tags with length-prefixed parts to prevent cross-type collisions.

7. **Mock backend double-lock**: Cloud integration mocks require both a
   compile-time Cargo feature (`mock-insecure-do-not-ship`) and a runtime
   environment variable (`CRATON_HSM_ALLOW_MOCK=1`).

## Data Flow

```
                    Application / gRPC Client
                             |
                             v
               +----------------------------+
               |     craton-hsm-core        |
               |  PKCS#11 C ABI + Sessions  |
               |  Audit log, key store      |
               +----------------------------+
                    |              |
        +-----------+              +-----------+
        v                                      v
+----------------+                  +-------------------+
| craton-hsm-auth|                  |  CryptoBackend    |
| AuthManager    |                  |  (trait dispatch)  |
| RBAC, tenants  |                  +-------------------+
| MFA, LDAP/OIDC |                   |    |    |    |
+----------------+        +----------+    |    |    +----------+
                          v               v    v               v
                   AwsLcBackend    OpenSSL  PKCS#11    NXP/Infineon
                   (aws-lc-rs)     Backend  Passthrough  HW backends
                   FIPS 140-3              (vendor .so)
```

Cluster and cloud integrations sit alongside the core:

```
+-------------------+     +-------------------+     +-------------------+
| craton-hsm-cluster|     |  craton-hsm-kmip  |     |  craton-hsm-cloud |
| Raft consensus    |     |  KMIP 2.1 server  |     |  K8s CSI driver   |
| Key replication   |     |  TTLV codec       |     |  Vault plugin     |
| Snapshots, health |     |  Key lifecycle    |     |  AWS/Azure shims  |
+-------------------+     +-------------------+     +-------------------+
         |                         |                         |
         +-------------------------+-------------------------+
                                   |
                                   v
                          craton-hsm-core
```

## Crate Dependency Graph

```
craton-hsm-core (external, Apache-2.0)
  ^       ^       ^       ^       ^
  |       |       |       |       |
  |       |       |       |       +-- craton-hsm-cng
  |       |       |       +-- craton-hsm-openssl
  |       |       +-- craton-hsm-awslc -------> aws-lc-rs (FIPS)
  |       +-- craton-hsm-nxp                    rsa, p256, p384 (prehashed)
  +-- craton-hsm-infineon
  |
  +-- craton-hsm-pkcs11 ---------> cryptoki
  |
  +-- craton-hsm-auth ------------> ldap3, jsonwebtoken, x509-parser
  |                                 (optional, behind feature flags)
  |
  +-- craton-hsm-cluster ---------> tokio (async runtime)
  |
  +-- craton-hsm-kmip
  |
  +-- craton-hsm-cloud -----------> (mock-guarded integration shims)
  |
  +-- craton-hsm-certified -------> (CMVP/CAVP/ACVP tooling)
```

All crates share workspace-level pinned dependency versions (see root
`Cargo.toml`) to ensure reproducible builds. Common transitive dependencies:
`zeroize`, `subtle`, `tracing`, `dashmap`, `serde`, `parking_lot`.
