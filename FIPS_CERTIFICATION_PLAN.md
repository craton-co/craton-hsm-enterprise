# FIPS 140-3 Certification Plan

> **Status disclaimer:** This document describes the **plan** to pursue FIPS
> 140-3 validation of the Craton HSM module. The module **is not yet FIPS
> 140-3 certified** and has not been submitted to a CMVP-accredited
> laboratory. AWS-LC (the underlying cryptographic library) is independently
> FIPS-validated under NIST CMVP certificate **#4759** — references to "FIPS
> validated" in the table below refer to that library, not to a module-level
> certificate for Craton HSM. Treat any current statement of FIPS compliance
> in this workspace as describing **library-level** approved-algorithm
> enforcement, not module-level certification.

## 1. Module Overview

| Field | Value |
|-------|-------|
| Module Name | Craton HSM Enterprise Cryptographic Module |
| Module Version | 0.1.2 |
| Module Type | Software |
| Target Security Level | Level 1 (software module) — *target*, not yet achieved |
| Cryptographic Library | AWS-LC (aws-lc-rs v1.16.2, FIPS-validated under CMVP #4759) |
| Operating Environment | Linux (x86_64, aarch64), Windows (x86_64) |
| Current CMVP status | **Not yet submitted** — see Phase 1 below |

## 2. FIPS Boundary Definition

### Inside the Cryptographic Boundary
| Component | Implementation | CAVP Algorithm |
|-----------|---------------|----------------|
| AES-GCM (128/192/256) | aws-lc-rs | AES #TBD |
| AES-CBC (128/192/256) | aws-lc-rs | AES #TBD |
| AES-CTR (128/192/256) | aws-lc-rs | AES #TBD |
| AES-KW (128/192/256) | aws-lc-rs | AES #TBD |
| RSA Sign/Verify (PKCS#1v1.5, PSS) | aws-lc-rs | RSA #TBD |
| RSA-OAEP Encrypt/Decrypt | aws-lc-rs | RSA #TBD |
| ECDSA Sign/Verify (P-256, P-384) | aws-lc-rs | ECDSA #TBD |
| Ed25519 Sign/Verify | aws-lc-rs | EdDSA #TBD |
| SHA-256, SHA-384, SHA-512 | aws-lc-rs | SHA #TBD |
| HMAC-SHA256 | aws-lc-rs | HMAC #TBD |
| HKDF (SHA-256) | aws-lc-rs | KDF #TBD |
| ECDH (P-256, P-384) | aws-lc-rs | KAS #TBD |
| DRBG (CTR_DRBG) | aws-lc-rs | DRBG #TBD |

### Outside the Cryptographic Boundary
- Authentication logic (LDAP, OIDC, certificate, MFA)
- Cluster consensus (Raft) and replication
- KMIP protocol handling
- Cloud integrations
- Session management
- Audit logging

### Excluded Algorithms (Non-Approved)
- SHA-1 (rejected in FIPS mode)
- Prehashed signing (uses RustCrypto, rejected in FIPS mode)

Note: AES-128 key generation is **permitted** in FIPS mode — AES-128/192/256 are all FIPS 140-3 approved. AES-256 is recommended for new keys but AES-128 is not rejected.

## 3. Certification Phases

### Phase 1: Pre-Engagement (Current)
**Status**: In Progress
**Duration**: 2-3 months

- [x] Define FIPS boundary
- [x] Implement approved-mode enforcement
- [x] Implement binary integrity verification (HMAC-SHA256)
- [x] Implement reproducible build verification
- [ ] Complete ACVP test vector runner
- [ ] Complete FIPS Finite State Machine
- [ ] Complete Security Policy document generator
- [ ] Complete power-on self-tests (POST)
- [ ] Select CMVP testing laboratory
- [ ] Budget approval ($50K-$200K)

### Phase 2: Laboratory Engagement
**Duration**: 3-6 months
**Estimated Cost**: $50K-$100K (laboratory fees)

- [ ] Submit Implementation Under Test (IUT) to laboratory
- [ ] Laboratory review of Security Policy document
- [ ] Algorithm testing (CAVP/ACVP)
- [ ] Finite State Machine review
- [ ] Source code review by laboratory
- [ ] Operational testing
- [ ] Address laboratory findings

### Phase 3: CMVP Validation
**Duration**: 3-12 months (CMVP queue dependent)
**Estimated Cost**: $0-$50K (if re-testing required)

- [ ] Laboratory submits validation report to CMVP
- [ ] CMVP review and feedback
- [ ] Address any CMVP comments
- [ ] Receive validation certificate
- [ ] Publish to NIST CMVP validated modules list

### Phase 4: Maintenance
**Ongoing**

- [ ] Monitor for algorithm deprecation
- [ ] Plan for FIPS 140-3 transition requirements
- [ ] Update module for security patches
- [ ] Re-validation for significant changes

## 4. Required Documentation

### Security Policy (11 Sections per FIPS 140-3)
1. **Cryptographic Module Specification**: Module name, version, hardware/software/firmware description
2. **Cryptographic Module Interfaces**: Data input/output, control input, status output, power interfaces
3. **Roles, Services, and Authentication**: Operator roles, services available, authentication mechanisms
4. **Software/Firmware Security**: Software integrity, approved integrity techniques
5. **Operational Environment**: OS requirements, single-operator mode
6. **Physical Security**: N/A for software-only module (Level 1)
7. **Non-Invasive Security**: N/A for Level 1
8. **Sensitive Security Parameter Management**: Key generation, storage, zeroization, transport
9. **Self-Tests**: Power-on self-tests, conditional self-tests, descriptions
10. **Life-Cycle Assurance**: CM system, design, development, delivery, operation, end-of-life
11. **Mitigation of Other Attacks**: AES-GCM nonce management, timing attacks, side-channels

### ACVP/CAVP Test Evidence
- Algorithm Validation Protocol (AVP) test results for each approved algorithm
- Known Answer Test (KAT) vectors and responses
- Monte Carlo Test (MCT) results where applicable

### Additional Documents
- Finite State Machine diagram (Graphviz DOT format)
- Module architecture diagram
- Build environment documentation
- Test plan and results

## 5. Self-Test Requirements

### Power-On Self-Tests (POST)
Run automatically on module initialization:

| Test | Algorithm | Type |
|------|-----------|------|
| AES-GCM KAT | AES-256-GCM | Encrypt + Decrypt |
| AES-CBC KAT | AES-256-CBC | Encrypt + Decrypt |
| RSA Sign/Verify KAT | RSA-2048 PKCS#1v1.5 | Sign + Verify |
| ECDSA Sign/Verify KAT | ECDSA P-256 | Sign + Verify |
| SHA-256 KAT | SHA-256 | Hash |
| HMAC-SHA256 KAT | HMAC-SHA256 | MAC |
| DRBG Health Test | CTR_DRBG | Generate + Verify |
| Software Integrity | HMAC-SHA256 | Binary hash verification |

### Conditional Self-Tests
Run on specific operations:

| Trigger | Test |
|---------|------|
| Key generation | Pair-wise consistency test (sign + verify) |
| RNG output | Continuous random number generator test |
| Key import | Key validation check |

### Self-Test Failure Behavior
On any self-test failure:
1. Transition to **Error** state
2. Log critical error
3. Reject all cryptographic service requests
4. Require module restart to retry self-tests

## Workspace POST gate coverage

This table consolidates the per-crate POST gate wiring (see each
backend's README "FIPS POST gating coverage" section for the
authoritative per-method list). It is the workspace-level view used
when reasoning about the FIPS boundary: only the *gated entry points*
refuse to run until `mark_fips_post_passed()` has been latched by
`craton-hsm-certified`, while the *ungated* entry points are
intentionally permitted to run before POST has been driven so that the
bring-up harness can validate the very public-key material it depends
on.

| Crate | Module status | POST-gated entry points | Ungated entry points | Rationale |
|---|---|---|---|---|
| craton-hsm-awslc | FIPS-validated library (CMVP #4759); module-level POST driven through `craton-hsm-certified` | `*_sign[_prehashed]`, `rsa_oaep_decrypt`, `aes_256_gcm_encrypt/decrypt`, `aes_cbc_encrypt/decrypt`, `aes_ctr_encrypt/decrypt`, `aes_key_wrap/unwrap`, `generate_*`, `ecdh_p256/p384` | `*_verify[_prehashed]`, `rsa_oaep_encrypt`, `compute_digest`, `create_hasher` | Public-key verification operates on public material only and must run during the boot path (CA chain validation) before any KAT has executed. |
| craton-hsm-openssl | OpenSSL provider posture probed at construction; module-level POST driven through `craton-hsm-certified` | `rsa_pkcs1v15_sign[_prehashed]`, `rsa_pss_sign[_prehashed]`, `ecdsa_p256_sign[_prehashed]`, `ecdsa_p384_sign[_prehashed]`, `ed25519_sign`, `aes_256_gcm_encrypt/decrypt`, `aes_cbc_encrypt/decrypt`, `aes_ctr_encrypt/decrypt`, `rsa_oaep_decrypt` | `*_verify[_prehashed]`, `rsa_oaep_encrypt`, `aes_key_wrap/unwrap` (delegated to core), `generate_*` / `ecdh_*` / `compute_digest` / `create_hasher` (delegated to core) | Same rationale as AWS-LC; key-wrap and key-gen gating is applied at the dispatcher layer in `craton-hsm-core`. |
| craton-hsm-cng | Native Windows BCrypt + FIPS dispatch flag; module-level POST driven through `craton-hsm-certified` | `rsa_pkcs1v15_sign[_prehashed]`, `rsa_pss_sign[_prehashed]`, `ecdsa_p256_sign[_prehashed]`, `ecdsa_p384_sign[_prehashed]`, `aes_256_gcm_encrypt/decrypt`, `aes_cbc_encrypt/decrypt`, `aes_ctr_encrypt/decrypt`, `aes_key_wrap/unwrap`, `ecdh_p256/p384`, `rsa_oaep_decrypt`, `generate_aes_key`, `generate_rsa_key_pair`, `generate_ec_p256/p384_key_pair`, `generate_ed25519_key_pair` (refused in FIPS), `compute_digest` | `*_verify[_prehashed]`, `rsa_oaep_encrypt`, `ed25519_sign`/`ed25519_verify` (refused in FIPS — RustCrypto, outside the validated boundary), `create_hasher`, `digest_output_len` | Same public-key carve-out as AWS-LC/OpenSSL. Ed25519 is provided by RustCrypto on Windows because CNG does not expose Ed25519 natively, so the FIPS-mode constructor refuses both sign and verify rather than gating them. |
| craton-hsm-pkcs11 | Passthrough — vendor token enforces its own FIPS posture | — (no module-internal POST; the loaded token's own POST is authoritative) | — (delegated to the token) | The PKCS#11 backend is a thin shim over a vendor module; that module's own FIPS state machine and self-tests are what CMVP would evaluate, not anything in this crate. |
| craton-hsm-nxp | 🚧 hardware path not yet wired (`publish = false`) | — | — | Stub today; POST coverage will be defined when the FFI shim is connected to a real EdgeLock SE05x. |
| craton-hsm-infineon | 🚧 hardware path not yet wired (`publish = false`) | — | — | Stub today; POST coverage will be defined when the OPTIGA Trust M FFI bring-up lands. |
| craton-hsm-cloud | No FIPS posture (mocks + RPC adapters only) | — | — | The cloud shims live outside the cryptographic module boundary; they delegate every operation to a remote service (or, for `mock-insecure-do-not-ship`, to a forgeable in-memory mock). |

## 6. FIPS Finite State Machine

```
                    ┌──────────┐
                    │ Power Off│
                    └────┬─────┘
                         │ power on
                         v
                    ┌──────────┐
              ┌─────│ Self Test│
              │     └────┬─────┘
              │          │ all pass
              │          v
     fail     │    ┌────────────┐
              │    │ Operational│◄────────┐
              │    └─────┬──────┘         │
              │          │                │
              │          │ critical error  │ re-init
              │          v                │
              │    ┌──────────┐           │
              └───>│   Error  │───────────┘
                   └────┬─────┘
                        │ zeroize command
                        v
                   ┌────────────┐
                   │Zeroization │
                   └────┬───────┘
                        │ complete
                        v
                   ┌──────────┐
                   │ Power Off│
                   └──────────┘
```

### State Transitions
| From | To | Trigger |
|------|----|---------|
| PowerOff | SelfTest | Module initialization |
| SelfTest | Operational | All self-tests pass |
| SelfTest | Error | Any self-test fails |
| Operational | Error | Critical error detected |
| Operational | Zeroization | Zeroize command received |
| Error | SelfTest | Re-initialization requested |
| Error | Zeroization | Zeroize command received |
| Zeroization | PowerOff | Zeroization complete |

## 7. Laboratory Selection Criteria

| Criterion | Requirement |
|-----------|-------------|
| NVLAP accreditation | Current accreditation for FIPS 140-3 |
| Software module experience | Previous validations of software-only modules |
| Rust/C expertise | Familiarity with Rust crate ecosystem and C libraries |
| Timeline | Ability to begin testing within 3 months |
| Cost | Within $50K-$100K budget for laboratory fees |
| Location | US-based (preferred for CMVP coordination) |

### Candidate Laboratories
(To be evaluated during Phase 1)
- Leidos (formerly SAIC)
- UL (formerly InfoGard)
- Gossamer Security Solutions
- Lightship Security
- atsec information security

## 8. Budget Estimate

| Item | Low Estimate | High Estimate |
|------|-------------|---------------|
| Laboratory testing fees | $50,000 | $100,000 |
| CMVP submission fee | $0 | $0 |
| Internal engineering (preparation) | $30,000 | $50,000 |
| Re-testing (if required) | $0 | $50,000 |
| **Total** | **$80,000** | **$200,000** |

## 9. Timeline

| Milestone | Target Date | Dependencies |
|-----------|-------------|--------------|
| Complete ACVP test harness | TBD | Engineering resources |
| Complete self-test implementation | TBD | Engineering resources |
| Generate Security Policy draft | TBD | ACVP + self-tests complete |
| Select testing laboratory | TBD | Budget approval |
| Submit IUT to laboratory | TBD | Laboratory contract signed |
| Complete algorithm testing | TBD + 3 months | Laboratory availability |
| Complete module testing | TBD + 6 months | Algorithm testing complete |
| CMVP validation | TBD + 12 months | CMVP queue (variable) |

## 10. Risk Factors

| Risk | Impact | Mitigation |
|------|--------|------------|
| CMVP queue delays | 6-12 month additional wait | Plan for longer timeline |
| aws-lc-rs FIPS validation expires | Must use validated version | Pin dependency version |
| Algorithm deprecation (during process) | Re-testing required | Monitor NIST announcements |
| Significant code changes after submission | May require re-testing | Feature freeze during testing |
| Budget overrun | Delay or reduced scope | Build contingency into budget |
