# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing **security@craton.com.ar**. Include:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- Affected versions
- Any suggested mitigations

You will receive an acknowledgement within **2 business days** and a detailed response within **7 days**.

### PGP Key

The canonical PGP public key for encrypting sensitive reports is published in
this repository at [`.well-known/security-key.asc`](.well-known/security-key.asc)
(served via GitHub Pages at the repository root). This is the **single
authoritative source**; older references to `craton.io/security.asc` are
deprecated and no longer maintained.

**Key metadata** (verify before use):

| Field        | Value                                              |
|--------------|----------------------------------------------------|
| User ID      | `Craton Security <security@craton.com.ar>`             |
| Key type     | RSA 4096                                           |
| Fingerprint  | *Pending publication — see below*                  |
| Rotation     | Annually, or immediately on suspected compromise   |

> **Status:** At the time this repository was first published, the security
> PGP key had not yet been generated through Craton's offline key-ceremony
> process. The fingerprint will be filled in, and the placeholder in
> `.well-known/security-key.asc` replaced with the real armored key, as part
> of the 0.1.x release signing kick-off. Until then, reporters may use plain
> TLS-to-`security@craton.com.ar` for the initial contact; the Craton security
> team will arrange encrypted follow-up if the report contains exploit
> details or other sensitive material. This is tracked publicly so that its
> absence cannot be used to stage a key-substitution attack.

Before encrypting a report, fetch the key over HTTPS from
`.well-known/security-key.asc`, verify the fingerprint out-of-band — against
the fingerprint published in this repository's tagged release notes **and**
the fingerprint in a signed Git tag annotation of the release you intend to
report against — and only then import it into your keyring. Do not encrypt
to a key whose fingerprint you have not independently verified.

The key-generation runbook that produces this material is summarised in
[`SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md#security-pgp-key-ceremony); the real
ceremony happens on an offline maintainer device.

### What qualifies as a security report

Report privately, not in public issues:

- Authentication bypass, privilege escalation, or cross-tenant data access
- Cryptographic weaknesses (key recovery, padding-oracle, nonce reuse, timing
  side channels on verification)
- FIPS-mode bypass or approved-mode FSM state confusion
- Remote-unauthenticated crashes or resource exhaustion (DoS) in the KMIP
  server, Raft transport, or PKCS#11 backend
- Memory-safety issues (unsound `unsafe`, use-after-free, data races)
- Supply-chain tampering (suspicious commits, compromised dependencies)

General bug reports (build failures, API ergonomics, documentation typos)
belong in public GitHub issues.

### Responsible Disclosure Timeline

| Milestone | Target |
|-----------|--------|
| Initial acknowledgement | 2 business days |
| Vulnerability assessment | 7 days |
| Patch development | 30 days (critical), 90 days (others) |
| Public disclosure | After patch release, coordinated with reporter |

We follow a **90-day disclosure policy**. If a fix requires more time, we will negotiate an extension with the reporter.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

We support only the latest published version. Users are encouraged to stay up to date.

## Scope

This policy covers the Rust crates in this repository:

- `craton-hsm-awslc`
- `craton-hsm-openssl`
- `craton-hsm-pkcs11`
- `craton-hsm-auth`
- `craton-hsm-cluster`
- `craton-hsm-kmip`
- `craton-hsm-cloud`
- `craton-hsm-infineon`
- `craton-hsm-nxp`
- `craton-hsm-cng`
- `craton-hsm-certified`

## Known Security Limitations

### FIPS Module Certification Status

Statements about FIPS validation in this repository refer to the underlying
AWS-LC cryptographic library, which is independently FIPS 140-3 validated
under NIST CMVP certificate **#4759**. The Craton HSM module *itself* has
**not yet** been submitted to or approved by CMVP — module-level
certification is planned (see [FIPS_CERTIFICATION_PLAN.md](FIPS_CERTIFICATION_PLAN.md)).
Deployments with regulatory requirements that depend on a *module-level*
CMVP certificate should treat this as an unfulfilled requirement until the
Craton HSM module appears on the [NIST validated modules list](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules).

### craton-hsm-awslc / craton-hsm-openssl

- **Prehashed signing operations** are not FIPS-validated when `fips_mode` is enabled. These return `HsmError::MechanismInvalid` in FIPS mode.
- **AES-GCM nonce counter**: Enforced at 2^32 encryptions per key (NIST SP 800-38D). Applications must rotate keys before this limit. Optional persistent on-disk counter journal (HMAC-authenticated, atomic write-temp-then-rename flush) survives process restarts.
- **RSA minimum key size**: 2048-bit minimum enforced for verification.

### craton-hsm-pkcs11

- Security depends on the underlying PKCS#11 library and HSM. The passthrough layer cannot validate HSM-internal operations.
- **AES-CTR** is not yet supported through the passthrough; calls return `CKR_FUNCTION_NOT_SUPPORTED`. Re-enabling this is blocked on the upstream `cryptoki` crate reaching ≥ 0.8.
- `generate_aes_key` extracts AES key material out of the HSM as a caller-visible behavior; if your threat model requires the symmetric key never to leave the HSM, generate keys via the vendor's PKCS#11 surface directly rather than through this passthrough.

### craton-hsm-auth

- **Authentication rate limiting**: All auth providers (LDAP, OIDC, certificate) support configurable rate limiting with per-key failure tracking and automatic lockout. Default: 5 failures per 5-minute window, 15-minute lockout. See [HARDENING.md](HARDENING.md) for configuration.
- **LDAP integration**: Requires correct server-side configuration with TLS and access controls. Connection pool is bounded to prevent resource exhaustion.
- **Dual-control approvals**: Both requester and approver must have valid user IDs. Anonymous approvals are rejected.
- **Local PIN store**: Intended for testing and development only. Use LDAP or certificate authentication in production.
- **Certificate revocation (authoritative statement)**: Only static (pre-loaded) DER-encoded CRLs are supported in `0.1.x`. HTTP-based CRL distribution point (CDP) fetching and OCSP (RFC 6960) are **not implemented** — neither live nor stapled. Operators must refresh CRL data out-of-band (cron, config-management, sidecar) and restart / reload the auth service to pick up new revocations. CRL cryptographic signatures are verified against configured trusted roots; CRL freshness is enforced via `thisUpdate`/`nextUpdate` validation. Expired CRLs and CRLs with unverifiable signatures are rejected (fail-closed). See [OPERATIONS.md §3](OPERATIONS.md) for refresh procedures. This is the single canonical statement; [HARDENING.md](HARDENING.md) and [DEPLOYMENT.md](DEPLOYMENT.md) link here rather than restating it.

### craton-hsm-cluster

- **Raft transport authentication**: HMAC-SHA256 cluster message authentication is a basic integrity mechanism. A bundled `MTlsTransport` is provided; deployments may also plug in their own transport implementation.
- **Replication encryption**: Use the bundled `MTlsTransport` (or another TLS-bearing transport) for payload confidentiality. Without TLS, deploy on an isolated network or use a VPN.
- **ReplicationLog `cluster_secret`**: A `cluster_secret` is required by default. Without one, the cluster refuses to initialize unless the `insecure-no-cluster-secret` Cargo feature is enabled (CI/test only). When operating in insecure mode, log entry checksums use plain SHA-256 (unauthenticated). Always configure `cluster_secret` in multi-node deployments.
- **Snapshot integrity**: Snapshots carry a `CRATON-SNAP-v1` HMAC-SHA256 footer; loading without a matching `cluster_secret` fails closed with `StorageError::SnapshotIntegrityFailure`.
- **Vote rate limit**: per-peer `RequestVote` token-bucket rate limiter (default 3 / 5 s) prevents Sybil-style election flooding.
- **Leader lease**: `RaftNode::leader_lease_is_valid(now_ms)` gates linearizable reads using a monotonic clock; stale partitioned-out leaders no longer serve reads. Term arithmetic saturates rather than panicking.
- **Membership change**: single-server membership change is implemented (`propose_config_change`, etc.). **Joint-consensus membership change is not implemented in `0.1.x`.**

### craton-hsm-infineon / craton-hsm-nxp

- These crates are 🚧 **in progress** in `0.1.x` and ship `publish = false`. Both must not be used as a basis for production security guarantees yet.
- `craton-hsm-nxp`: every `--features hw` cryptographic operation is a stub today. `key_import_private` and friends return `HsmError::FunctionNotSupported`. The non-`hw` build returns `HSE_ERR_NOT_IMPLEMENTED`.
- `craton-hsm-infineon`: sign/verify/encrypt under `--features hw` use hardcoded placeholder TPM handles (`0x8100_0001..0x8100_0004`). The `#[repr(C)]` FFI structs in `src/ffi.rs` are placeholders; linking against a real `libtss2-esys` is undefined behavior until the FFI is finished.
- Full hardware integration requires vendor SDKs **and** independent security review.

### craton-hsm-cng

- **craton-hsm-cng**: Implements cryptographic operations via the native Windows CNG/BCrypt API. FIPS mode is supported via `CngBackend::new_fips()`, which opens BCrypt algorithm providers with the `BCRYPT_PROV_DISPATCH` flag — this restricts algorithm selection to FIPS-approved primitives provided by the Windows CNG FIPS module. Requires Windows with FIPS mode enabled via Group Policy for full FIPS compliance.
- **Ed25519** is delegated to the RustCrypto `ed25519-dalek` crate (CNG does not expose Ed25519 natively). Ed25519 sits **outside the CNG FIPS boundary** and is rejected when `CngBackend::new_fips()` is in effect. The non-FIPS constructor permits Ed25519 sign/verify.
- A separate FIPS-validated *module* certificate for Craton HSM is not yet held (see [FIPS_CERTIFICATION_PLAN.md](FIPS_CERTIFICATION_PLAN.md)); CNG FIPS mode provides library-level approved-algorithm enforcement only.

### craton-hsm-cloud

- Mock implementations (`feature = "mock-insecure-do-not-ship"`) are for testing only and must not be used in production.

### craton-hsm-kmip

- **KMIP 2.1 subset**: the server implements a 15-operation subset of KMIP 2.1 §6 (Create, Get, Activate, Revoke, Destroy, Query, GetAttributes, Register, Locate, Check, AddAttribute, ModifyAttribute, DeleteAttribute, DeriveKey, RNG_Retrieve). Encrypt/Decrypt/Sign/SignatureVerify/MAC/MACVerify/CreateKeyPair explicitly return `OperationNotSupported`. **OASIS KMIP 2.1 conformance is not claimed.**
- **Static auth token** (`KmipServerConfig::auth_token`) is gated behind the
  `insecure-static-token` cargo feature. Production builds should leave that
  feature off and integrate the KMIP server with `craton-hsm-auth` (mTLS
  client certs or an external IdP) for per-identity authentication.

## Release Artifact Integrity

For the authoritative verification workflow — commands, Sigstore identity
regexps, SBOM inspection, and SLSA provenance — see
[SUPPLY_CHAIN.md](SUPPLY_CHAIN.md). The summary below is provided for
convenience.

Release builds are signed with [`cosign`](https://github.com/sigstore/cosign)
using keyless (OIDC) signing backed by the Sigstore public transparency log
(Rekor). Each release includes:

- `*.sig` — cosign signature
- `*.pem` — ephemeral certificate with the OIDC subject
  (`https://github.com/craton-co/craton-hsm-enterprise/...`)
- `sbom.spdx.json` — SBOM generated by [Syft](https://github.com/anchore/syft)
- `sbom.spdx.json.sig` — cosign signature over the SBOM

Verify a release artifact:

```bash
cosign verify-blob \
  --certificate craton-hsm-<version>.tar.gz.pem \
  --signature   craton-hsm-<version>.tar.gz.sig \
  --certificate-identity-regexp '^https://github\\.com/craton-co/craton-hsm-enterprise' \
  --certificate-oidc-issuer-regexp '^https://token\\.actions\\.githubusercontent\\.com' \
  craton-hsm-<version>.tar.gz
```

The release workflow ([.github/workflows/release.yml](.github/workflows/release.yml))
is the single source of truth for what gets signed and how.
