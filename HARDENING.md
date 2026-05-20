# Craton HSM Enterprise Security Hardening Guide

## 1. Pre-Deployment Checklist

- [ ] FIPS mode enabled (`AwsLcBackend::new_fips()`)
- [ ] Cluster secret configured (minimum 32 bytes, hex-encoded)
- [ ] TLS/mTLS configured for all network communication
- [ ] Authentication provider configured (LDAP with TLS, OIDC, or certificate)
- [ ] Rate limiting enabled on authentication providers
- [ ] MFA required for destructive operations
- [ ] Audit logging enabled and forwarded to SIEM
- [ ] Key backup procedures documented and tested
- [ ] CRL distribution configured and automated
- [ ] Encrypted volumes for all persistent state

## 2. FIPS Mode Configuration

### Enable FIPS Mode
```rust
// Always use the FIPS constructor for production
let backend = AwsLcBackend::new_fips();
```

### FIPS Mode Restrictions
When FIPS mode is enabled:
- SHA-1 is rejected for all operations
- Prehashed signing operations return `MechanismInvalid`
- Only FIPS-approved algorithms are available

AES-128, AES-192, and AES-256 key generation are all permitted in FIPS mode. **Use AES-256 for new keys** unless interoperability or protocol constraints require otherwise.

### Verify FIPS Mode
```rust
assert!(backend.is_fips_mode());
```

## 3. Authentication Hardening

### LDAP Configuration
```json
{
  "provider": "ldap",
  "ldap": {
    "url": "ldaps://ldap.example.com:636",
    "tls_mode": "ldaps",
    "base_dn": "dc=example,dc=com",
    "bind_dn_template": "uid={},ou=users,dc=example,dc=com",
    "timeout_secs": 10,
    "pool_size": 4,
    "max_connections": 6,
    "rate_limit": {
      "max_attempts": 5,
      "window_secs": 300,
      "lockout_secs": 900
    }
  }
}
```

**Critical**: Always use `ldaps` or `starttls` TLS mode. Never use `none` in production.

### OIDC Configuration
```json
{
  "provider": "oidc",
  "oidc": {
    "issuer_url": "https://auth.example.com",
    "audience": "craton-hsm",
    "role_claim": "groups",
    "clock_skew_secs": 30,
    "stale_cache_max_age_secs": 3600,
    "rate_limit": {
      "max_attempts": 10,
      "window_secs": 60,
      "lockout_secs": 300
    }
  }
}
```

### Certificate Authentication
```json
{
  "provider": "certificate",
  "cert": {
    "trusted_roots": ["<DER-encoded CA cert>"],
    "revocation": {
      "enabled": true,
      "crls": ["<DER-encoded CRL>"]
    }
  }
}
```

**Critical**: Always enable revocation checking in production. CRLs must be updated regularly. Only static (pre-loaded) DER CRLs are supported in `0.1.x`; HTTP CDP fetching and OCSP are not implemented. See [SECURITY.md — Certificate revocation](SECURITY.md#craton-hsm-auth) for the authoritative statement and [OPERATIONS.md §3](OPERATIONS.md) for refresh procedure.

### MFA Configuration
- Set `require_mfa_for_destructive: true` in auth config
- Use TOTP with SHA-256 for new deployments (`hash_algorithm: Sha256`)
- Set TOTP skew to 0 or 1 (wider windows increase replay risk)

## 4. Cluster Hardening

### Cluster Secret
Generate a 32-byte random secret:
```bash
openssl rand -hex 32
```

Configure in cluster config:
```json
{
  "cluster_secret": "<64-char hex string>",
  "allow_insecure": false
}
```

**Critical**: Never set `allow_insecure: true` in production. The cluster will reject initialization without a secret unless this flag is explicitly set.

### Transport Security
The cluster HMAC-SHA256 authentication provides message integrity but NOT confidentiality. For production:
1. Deploy cluster nodes on an isolated network segment (VLAN)
2. Use mutual TLS between all cluster peers
3. Configure firewall rules to restrict cluster port access

### Cluster Configuration
```json
{
  "node_id": "node-1",
  "listen_addr": "10.0.1.1:9443",
  "peers": [
    { "id": "node-2", "addr": "10.0.1.2:9443" },
    { "id": "node-3", "addr": "10.0.1.3:9443" }
  ],
  "election_timeout_ms": 1500,
  "heartbeat_interval_ms": 500,
  "max_message_age_ms": 30000
}
```

- Minimum 3 nodes for fault tolerance
- `heartbeat_interval_ms` must be less than `election_timeout_ms`
- `max_message_age_ms` limits replay window (lower = more secure, higher = more tolerant of latency)

## 5. Key Management

### Key Lifecycle
1. **Generation**: Use FIPS-approved algorithms only. Minimum key sizes:
   - AES: 256 bits
   - RSA: 2048 bits (3072+ recommended)
   - ECDSA: P-256 or P-384
2. **Storage**: Keys are held in memory with `Zeroizing<T>` wrappers. For persistent storage, use encrypted volumes.
3. **Rotation**: Rotate keys before AES-GCM nonce exhaustion (2^32 encryptions per key). Monitor nonce counter warnings.
4. **Destruction**: Key material is zeroized on drop. For hardware HSMs, use the vendor's secure erase.

### Key Backup Procedures
1. Export wrapped keys using AES-KW (Key Wrap)
2. Store wrapped keys on encrypted, offline media
3. Test restoration procedure quarterly
4. Maintain at least 2 geographically separated copies

### Key Ceremony
For production key generation:
1. Require dual-control (minimum 2 approvers)
2. Generate in a physically secured room
3. Document all participants and timestamps
4. Verify key material via KAT before deployment

## 6. Network Security

### TLS Configuration
- Minimum TLS 1.2 (TLS 1.3 preferred)
- Disable weak cipher suites
- Enable mutual TLS for client authentication
- Use certificates from a private CA for internal communication

### Firewall Rules
| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 9443 | TCP | Cluster peers only | Raft consensus |
| 8443 | TCP | Application servers | PKCS#11 API |
| 5696 | TCP | KMIP clients | KMIP protocol |

### LDAP Network Security
- Use dedicated service account with minimal privileges
- Restrict LDAP bind to read-only access
- Monitor LDAP connection pool size

## 7. Monitoring and Alerting

### Critical Alerts
- Authentication failure rate exceeding threshold (rate limiter activation)
- Cluster leader election (potential network partition)
- AES-GCM nonce counter warnings (50%, 75%, 90%, 95%, 99%)
- CRL expiry approaching
- Binary integrity check failure
- FIPS self-test failure

### Log Management
- Forward all logs to a centralized SIEM
- Usernames are SHA-256 hashed in logs (correlation without PII exposure)
- Retain logs for minimum 1 year (regulatory dependent)
- Protect log storage integrity (append-only, signed)

## 8. Operating System Hardening

### Linux
- Use SELinux or AppArmor in enforcing mode
- Mount data partitions with `noexec,nosuid`
- Enable ASLR and stack protector
- Disable core dumps: `ulimit -c 0`
- Use encrypted file systems (LUKS) for all persistent state

### Windows
- Enable Windows CNG FIPS mode via Group Policy
- Use BitLocker for disk encryption
- Restrict service account privileges
- Enable Windows Event Forwarding for audit logs

## 9. Incident Response

### Key Compromise
1. Immediately revoke the compromised key
2. Generate replacement key via key ceremony
3. Re-encrypt all data protected by the compromised key
4. Update CRLs if certificate-based authentication is affected
5. Notify affected tenants
6. Conduct root cause analysis

### Cluster Compromise
1. Isolate the compromised node
2. Rotate the cluster secret on all remaining nodes
3. Rebuild the compromised node from a clean image
4. Verify Raft log integrity
5. Rejoin the rebuilt node to the cluster

## 10. Compliance Mapping

| Requirement | FIPS 140-3 | PCI DSS 4.0 | SOC 2 |
|-------------|------------|-------------|-------|
| Key generation | IG 7.1 | 3.6.1 | CC6.1 |
| Key storage | IG 7.7 | 3.5.1 | CC6.1 |
| Access control | IG 3.1 | 7.1 | CC6.1 |
| Audit logging | IG 2.1 | 10.2 | CC7.2 |
| Self-tests | IG 9.1 | N/A | CC8.1 |
| Incident response | N/A | 12.10 | CC7.3 |

> **FIPS 140-3 row caveat:** the IGs above describe the controls Craton HSM
> implements toward FIPS 140-3 conformance. The Craton HSM module itself is
> **not yet** FIPS 140-3 certified — see [FIPS_CERTIFICATION_PLAN.md](FIPS_CERTIFICATION_PLAN.md)
> and [SECURITY.md](SECURITY.md#fips-module-certification-status).
> AWS-LC's library-level FIPS validation (CMVP #4759) covers the underlying
> cryptographic primitives only.

## 11. Audit-Fix Log (cross-reference)

This section summarises hardening sweeps already merged. For per-change
detail see [CHANGELOG.md](CHANGELOG.md).

### 2026-04-17 → 2026-05-10 sweeps (consolidated in `0.1.2`)

Cluster (`craton-hsm-cluster`):

- Pre-vote scaffold to suppress disruptive elections from partitioned nodes.
- HMAC-SHA256 reply authentication on RequestVote / AppendEntries / InstallSnapshot.
- Monotonic leader lease with clock-skew rejection (`Term + u64` arithmetic saturates rather than panicking).
- Authenticated snapshots — `CRATON-SNAP-v1` HMAC-SHA256 footer; `FileStorage::with_cluster_secret(&[u8])` required.
- Per-peer `RequestVote` token-bucket rate limiter (default 3 / 5 s; scales with cluster size).
- Bounded replay cache (16,384 entries, age-based eviction; full-eviction metric).
- `ConfigChange` membership-change proposal requires a majority of current voters to sign (domain-tag-0x04 HMAC).
- `RaftLog::truncate_after` returns `RaftInvariantError::TruncateBelowApplied` instead of panicking.
- Snapshot footer integrity check; fail-closed on mismatch.

`craton-hsm-awslc` / `craton-hsm-openssl`:

- Persistent on-disk AES-GCM nonce counter with HMAC-authenticated journal.
- Journal flush is **write-temp-then-atomic-rename** (`craton-hsm-openssl` 0.1.2) so a crash mid-flush cannot reset the counter on next start; the same model is used in `craton-hsm-awslc`.
- Per-key flush-failure streak counter; after 5 consecutive failures the key is poisoned on disk.
- Versioned journal header (`craton-hsm-gcm-journal v1`); unknown versions refuse to load.
- MAC-key derivation mixes in OS file-identity (unix `dev+ino`, Windows file-index) to bind the journal to its physical file.

`craton-hsm-auth`:

- LDAP pool migrated to `parking_lot::Mutex` so a panic does not poison the pool.
- OIDC `alg: "none"` explicitly rejected in JWK→Algorithm mapping.
- Dual-control approval rejects empty-string `user_id` (was previously only rejecting `None`).
- MFA challenge IDs, PIN salts, and approval IDs draw from `OsRng` (was `thread_rng`).

`craton-hsm-kmip`:

- 15-operation subset documented and OASIS-conformance claim withdrawn.
- TTLV decoder with explicit `max_depth` (32), `max_items` (10k), `max_bytes` budgets.
- Auth rate limiter uses a monotonic `Instant` clock.
- ACL trait (`KmipAcl`, default `AllowAll`) consulted by Destroy/Revoke/Activate/Get/GetAttributes/AddAttribute. ACL denials are flattened to `ObjectNotFound` to avoid a cross-tenant key-existence oracle.
- `validate_for_production()` rejects weak / short (< 32 B) static tokens and known placeholder values.

`craton-hsm-cng`:

- FIPS mode opens BCrypt providers with `BCRYPT_PROV_DISPATCH` (provider-dispatch FIPS flag), restricting algorithm selection to FIPS-approved primitives.
- Ed25519 carve-out via RustCrypto `ed25519-dalek`; rejected under `CngBackend::new_fips()`.
- NTSTATUS → `HsmError` mapping expanded from 5 to 13+ codes; unknown NTSTATUS values surface raw hex + decoded severity/facility/code.

`craton-hsm-cloud`:

- `mock-insecure-do-not-ship` additionally gated by `CRATON_HSM_ACCEPT_MOCK_IN_RELEASE=1` under `cfg(not(debug_assertions))`.
- Mocks reject key material > 32 B; Vault key names > 256 B / NUL-containing / leading-`/` rejected at dispatch.

`craton-hsm-infineon` / `craton-hsm-nxp`:

- Explicit `SAFETY:` justifications at every `unsafe { ffi::... }` call site.
- NXP non-`hw` stubs now return `HSE_ERR_NOT_IMPLEMENTED`.
- Infineon wrappers validate TPM handles before FFI dispatch.

These changes are reflected in [THREAT_MODEL.md](THREAT_MODEL.md) §4.3
(Cluster) and §4.7 (Supply Chain).
