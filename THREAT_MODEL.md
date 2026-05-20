# Craton HSM Enterprise Threat Model

## 1. Overview

This document defines the threat model for Craton HSM Enterprise, identifying assets, threat actors, attack surfaces, and mitigations. It follows the STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

## 2. Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Cryptographic keys (AES, RSA, EC) | **Critical** | In-memory (zeroized), hardware HSM, or encrypted storage |
| Master wrapping keys | **Critical** | Hardware HSM or FIPS-validated software module |
| Authentication credentials (PINs, LDAP passwords) | **High** | Transit only (never stored in plaintext); PBKDF2 hashes for MFA |
| TOTP shared secrets | **High** | In-memory (zeroized), registered per-user |
| Cluster secrets (HMAC keys) | **High** | Configuration files (must be encrypted at rest) |
| Audit logs | **High** | On-disk, tamper-evident via HMAC |
| Session tokens | **Medium** | In-memory, per-session |
| Configuration files | **Medium** | On-disk |
| TLS certificates and private keys | **High** | File system or certificate store |

## 3. Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| **External attacker** | Network access, no credentials | Steal keys, disrupt service |
| **Compromised client application** | Valid credentials, limited role | Escalate privileges, access other tenants' keys |
| **Malicious insider (operator)** | Physical/logical access to server | Exfiltrate keys, tamper with audit logs |
| **Compromised peer node** | Cluster membership, network access | Inject malicious Raft entries, split-brain attacks |
| **Supply chain attacker** | Modify dependencies or build artifacts | Backdoor crypto operations |

## 4. Attack Surfaces

### 4.1 PKCS#11 API Interface
- **Threats**: Unauthorized key operations, session hijacking, buffer overflow
- **Mitigations**:
  - RBAC enforcement on all operations (`PolicyEngine::check_permission`)
  - Per-key ACLs (`AclEntry::is_allowed`)
  - Session-bound authentication
  - Input validation on all PKCS#11 parameters

### 4.2 Authentication Providers
- **Threats**: Credential stuffing, brute-force, token replay, LDAP injection
- **Mitigations**:
  - Rate limiting on all auth providers (max 5 attempts / 5 min, 15 min lockout)
  - RFC 4515 LDAP filter escaping, RFC 4514 DN value escaping
  - HTTPS-only enforcement for OIDC
  - TOTP replay protection with constant-time comparison
  - PBKDF2-HMAC-SHA256 (600K iterations) for PIN hashing
  - MFA enforcement for destructive operations

### 4.3 Cluster Communication
- **Threats**: Message injection, replay attacks, split-brain, eavesdropping, Sybil-style election flooding, unilateral membership change, snapshot tampering, clock-skew abuse
- **Mitigations**:
  - HMAC-SHA256 authentication on all Raft RPCs (request *and* reply) with domain separation
  - Bounded replay cache (16,384 entries, age-based eviction on every insert) — freshness check precedes cache check
  - Message freshness window (default 30 s past, 1 s future); config validator rejects setups where future skew could survive a clock regression
  - Pre-vote scaffold suppresses disruptive elections from partitioned nodes
  - Per-peer `RequestVote` token-bucket rate limiter (default 3 / 5 s, scales with cluster size)
  - Monotonic leader lease with `RaftNode::leader_lease_is_valid(now_ms)` gate for linearizable reads; `Term + u64` saturates rather than panicking
  - Authenticated snapshots: `CRATON-SNAP-v1` HMAC-SHA256 footer; `FileStorage::with_cluster_secret` required, otherwise fails closed
  - `RaftLog::truncate_after` returns `RaftInvariantError::TruncateBelowApplied` instead of panicking; converts to `success=false` at RPC ingress
  - `ConfigChange` membership-change proposal requires a majority of current voters to sign (domain-tag-0x04 HMAC) — a single rogue secret holder cannot add itself unilaterally
  - Fail-closed: `cluster_secret` required by default (the `insecure-no-cluster-secret` Cargo feature is the only escape hatch and is CI/test only)
  - Bundled `MTlsTransport` provides transport-level confidentiality; consumers may plug in their own transport
  - **Out of scope:** joint-consensus membership change (single-server change is implemented)

### 4.4 Certificate Revocation
- **Threats**: Use of revoked certificates, CRL forgery
- **Mitigations**:
  - CRL signature verification against trusted roots
  - CRL `thisUpdate`/`nextUpdate` freshness enforcement
  - Fail-closed when no CRL covers the certificate issuer
  - Fail-closed on corrupt or unparseable CRLs

### 4.5 Key Storage
- **Threats**: Key extraction from memory, disk, or backups
- **Mitigations**:
  - `zeroize::Zeroizing<T>` wrapper on all key material
  - Atomic file writes (tmp + rename + fsync) for cluster state
  - Documented requirement for encrypted volumes
  - AES-GCM nonce exhaustion tracking (2^32 limit per key)

### 4.6 Multi-Tenant Isolation
- **Threats**: Cross-tenant key access, quota bypass, tenant ID injection
- **Mitigations**:
  - `TenantId` validation prevents path traversal and injection
  - Atomic quota enforcement via `fetch_update` (no TOCTOU)
  - Cross-tenant approval blocking in dual-control workflows
  - Tenant-scoped key namespacing

### 4.7 Supply Chain
- **Threats**: Compromised dependencies, tampered binaries
- **Mitigations**:
  - `cargo-audit` and `cargo-deny` in CI
  - Pinned dependency versions in workspace
  - Binary integrity verification (HMAC-SHA256)
  - Reproducible build verification
  - FIPS module self-tests on initialization

## 5. STRIDE Analysis

### Spoofing
| Threat | Risk | Mitigation |
|--------|------|------------|
| Impersonate another user | High | Authentication required for all sessions; MFA for destructive ops |
| Forge cluster messages | High | HMAC-SHA256 with domain separation; cluster_secret required |
| Replay TOTP codes | Medium | Per-user step tracking with constant-time comparison |
| Present revoked certificate | Medium | CRL checking with signature and freshness validation |

### Tampering
| Threat | Risk | Mitigation |
|--------|------|------------|
| Modify Raft log entries | High | HMAC-SHA256 integrity on all entries; quorum-based commit |
| Tamper with binary | Medium | HMAC-SHA256 binary integrity check; FIPS self-tests |
| Modify CRL to hide revocation | Medium | CRL signature verification against trusted roots |

### Repudiation
| Threat | Risk | Mitigation |
|--------|------|------------|
| Deny performing key operation | Medium | Audit logging with hashed user IDs |
| Deny approval in dual-control | Medium | Approval queue with timestamps and approver IDs |

### Information Disclosure
| Threat | Risk | Mitigation |
|--------|------|------------|
| Key material in logs | Critical | Hashed usernames; no key material in log output |
| Key material in memory dumps | High | Zeroize on drop for all sensitive types |
| Timing side-channels | Medium | Constant-time HMAC comparison; constant-time TOTP verification |
| Username enumeration | Low | Hashed usernames in logs; uniform error responses |

### Denial of Service
| Threat | Risk | Mitigation |
|--------|------|------------|
| Auth brute-force | Medium | Rate limiting with lockout |
| Connection pool exhaustion | Medium | Bounded LDAP connection pool |
| TOTP replay set memory exhaustion | Low | Periodic pruning of expired steps |
| AES-GCM nonce exhaustion | Low | Counter tracking with throttled warnings |
| Oversized RSA keys | Low | Maximum 16384-bit modulus limit |

### Elevation of Privilege
| Threat | Risk | Mitigation |
|--------|------|------------|
| Role escalation via LDAP groups | Medium | Deterministic role mapping; highest-privilege selection |
| Cross-tenant access | High | Tenant isolation with validated TenantId |
| Bypass MFA for destructive ops | Medium | MFA check on all destructive operation paths |
| Quota bypass | Medium | Atomic quota enforcement (no TOCTOU) |

## 6. Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│            Intended FIPS Boundary                 │
│  ┌──────────────────────────────────────────┐    │
│  │ aws-lc-rs (library FIPS-validated,        │    │
│  │ CMVP #4759 covers the AWS-LC library)    │    │
│  │  AES-GCM/CBC/CTR, RSA, ECDSA, Ed25519,  │    │
│  │  SHA-2, HKDF, AES-KW, ECDH, RSA-OAEP   │    │
│  └──────────────────────────────────────────┘    │
│  Note: the Craton HSM module itself is NOT yet   │
│  FIPS-validated (CMVP submission planned — see   │
│  FIPS_CERTIFICATION_PLAN.md).                     │
│  Prehashed signing uses RustCrypto (non-FIPS) and │
│  is rejected in FIPS mode.                        │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│              Application Boundary                 │
│  Auth, RBAC, Cluster, KMIP, Cloud integrations   │
│  (outside FIPS boundary)                          │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│              Network Boundary                     │
│  LDAP, OIDC issuers, cluster peers, clients      │
│  (untrusted; validate all inputs)                 │
└─────────────────────────────────────────────────┘
```

## 7. Residual Risks

| Risk | Severity | Mitigation Status |
|------|----------|-------------------|
| LDAP server compromise | High | Out of scope; document TLS requirement |
| OIDC issuer compromise | High | Out of scope; rely on issuer's security |
| Physical access to hardware HSM | High | Hardware tamper resistance (vendor responsibility) |
| OS-level compromise on HSM host | Critical | Out of scope; recommend hardened OS, SELinux/AppArmor |
| Side-channel attacks on software crypto | Medium | Use FIPS-validated aws-lc-rs; constant-time operations |
| Deployment foot-gun: `insecure-static-token` (craton-hsm-kmip) | High | **CI/test only.** Enables a single shared bearer token. Double-gated (cargo feature + `CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN=1`). CI/test builds with this feature MUST NOT be promoted to production; production must use mTLS / IdP via `craton-hsm-auth`. |
| Deployment foot-gun: `insecure-no-cluster-secret` (craton-hsm-cluster) | High | **CI/test only.** Allows `RaftNode::new` without a cluster HMAC secret. CI/test builds with this feature MUST NOT be promoted to production; release builds require a real cluster secret. |

## 8. Review Schedule

This threat model should be reviewed:
- Before each major version release
- When new features are added to the attack surface
- After any security incident
- At least annually
