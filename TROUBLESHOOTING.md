# Troubleshooting

Symptom-indexed debugging guide for `craton-hsm-enterprise`. Entries follow the pattern: **symptom** → **diagnostic commands** → **fix**. For runbook-level operational procedures (key rotation, CRL refresh, failover, backup/restore) see [OPERATIONS.md](OPERATIONS.md). For hardening context see [HARDENING.md](HARDENING.md).

---

## 1. Build Failures

### 1.1 `error: failed to read .../craton-hsm-core/Cargo.toml`

**Symptom**: `cargo check` / `cargo build` fails immediately with a missing-manifest error pointing at `../craton-hsm-core`.

**Diagnostic**:
```bash
ls -la ..                          # confirm the sibling directory
cat Cargo.toml | grep craton-hsm   # confirms path = "../craton-hsm-core"
```

**Fix**: the core library must be checked out as a sibling. From one level above this repo:
```bash
git clone https://github.com/craton-co/craton-hsm-core
```
Expected layout:
```
craton-hsm/
  craton-hsm-core/
  craton-hsm-enterprise/
```
See [BUILDING.md](BUILDING.md#troubleshooting).

### 1.2 `aws-lc-rs` build failure — CMake / Go / NASM missing

**Symptom (Linux)**: `CMake Error: CMAKE_ASM_NASM_COMPILER not set`, or `go: command not found`, or `bindgen ... clang not found`.

**Diagnostic**:
```bash
cmake --version && go version && clang --version && nasm -v
```

**Fix**:
```bash
# Debian/Ubuntu
sudo apt-get install -y build-essential cmake clang nasm golang-go pkg-config libssl-dev
# RHEL/Rocky/Alma
sudo dnf install -y gcc gcc-c++ cmake clang nasm golang pkgconfig openssl-devel
```
Go 1.21+ is required for FIPS builds (see [COMPATIBILITY_MATRIX.md](COMPATIBILITY_MATRIX.md#go-toolchain-fips-builds-only)).

### 1.3 Windows MSVC / NASM missing

**Symptom**: `error: Microsoft Visual C++ 14.0 or greater is required`, or `link.exe not found`, or `aws-lc-rs` asm build fails.

**Diagnostic** (PowerShell):
```powershell
where.exe cl.exe
where.exe nasm.exe
go version
```

**Fix**: Install Visual Studio 2022 with the "Desktop development with C++" workload, NASM from `https://www.nasm.us/`, and Go 1.21+. Launch builds from a "x64 Native Tools Command Prompt for VS 2022", or ensure `cl.exe` and `nasm.exe` are on `PATH`. See [BUILDING.md](BUILDING.md#windows).

### 1.4 `libtss2-esys` not found (`craton-hsm-infineon --features hw`)

**Symptom**: `pkg-config could not find tss2-esys`.

**Fix**:
```bash
sudo apt-get install -y libtss2-dev libtss2-esys-3.0.2-0
# or build tpm2-tss 4.0+ from source
```

### 1.5 `cargo check --workspace` succeeds but individual crate fails

**Symptom**: Per-crate `cargo check -p <crate>` fails while workspace build succeeds (or vice versa), typically on Windows with path-length issues.

**Diagnostic**:
```bash
cargo check -p craton-hsm-awslc -vv 2>&1 | head -80
```

**Fix**: Enable Windows long-path support (`git config --global core.longpaths true`; `gpedit.msc` → Local Computer Policy → Enable Win32 long paths), move the clone closer to the filesystem root, or use WSL.

---

## 2. PKCS#11 Runtime Failures

### 2.1 `CKR_TOKEN_NOT_PRESENT` / `CKR_SLOT_ID_INVALID`

**Symptom**: `HsmError::Pkcs11(CKR_TOKEN_NOT_PRESENT)` on session open.

**Diagnostic**:
```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-token-slots
```

**Fix**:
- SoftHSM: initialize the token (`softhsm2-util --init-token --slot 0 --label craton --so-pin <SO-PIN> --pin <user-PIN>`).
- YubiHSM2: confirm `yubihsm-connector` is running and the key is inserted.
- Luna / Utimaco: confirm the HSM partition is assigned to the client certificate used, and the client package is installed and registered.

### 2.2 `CKR_PIN_INCORRECT` loops

**Symptom**: Repeated `CKR_PIN_INCORRECT`; eventually `CKR_PIN_LOCKED`.

**Fix**: Unlock the token per vendor procedure (SO-PIN reset). Do not store the user PIN in `Debug`-printed structs — `craton-hsm-pkcs11` redacts the PIN from `Debug` output as of `0.1.1`; custom wrappers should too.

### 2.3 PKCS#11 verify returns `Err` instead of `Ok(false)`

**Symptom**: Code that used to match `Ok(false)` on invalid signatures now sees `Err(HsmError::Pkcs11(...))`.

**Fix**: Handle both arms:
```rust
match backend.verify(...) {
    Ok(true) => { /* valid */ }
    Ok(false) => { /* truly invalid */ }
    Err(e) => { /* session / hardware problem */ }
}
```

---

## 3. KMIP Failures

### 3.1 KMIP TLS handshake errors (`bad_certificate`, `unknown_ca`, `certificate_required`)

**Symptom**: KMIP client cannot establish TLS. Server log shows `alert bad certificate` or `no client certificate`.

**Diagnostic**:
```bash
openssl s_client -connect <host>:5696 -showcerts -cert client.pem -key client.key -CAfile ca.pem
```

**Fix**:
- Confirm the client cert is signed by a CA in the server's trust store.
- Confirm the client cert is not revoked (see §6 below).
- Confirm client key/cert match (`openssl x509 -in client.pem -modulus -noout | md5sum` vs `openssl rsa -in client.key -modulus -noout | md5sum`).
- TLS 1.2 minimum; TLS 1.3 preferred.

### 3.2 `TtlvError::SizeExceeded` on Register / Create

**Symptom**: Large KMIP payloads fail with `SizeExceeded`.

**Explanation**: `0.1.1` enforces a 1 MiB per-value TTLV limit to prevent allocation DoS.

**Fix**: Split the payload. Legitimate keys never exceed this size; request payloads larger than 1 MiB indicate a client bug or abuse.

### 3.3 `OperationFailed` on Destroy of an Active key

**Symptom**: KMIP Destroy rejected with "must be deactivated first".

**Explanation**: KMIP 2.1 §4.8 requires Revoke before Destroy; enforced in `0.1.1`.

**Fix**: Issue `Revoke` (with an appropriate `RevocationReason`), then `Destroy`.

### 3.4 `PermissionDenied` on Activate / Revoke / Destroy

**Symptom**: A KMIP client can `Get` an object but cannot modify it.

**Explanation**: `0.1.1` enforces owner ACL on Activate / Revoke / Destroy. Only the original creator (owner) may modify owner-protected objects.

**Fix**: Authenticate as the owner identity, or re-register the object under the correct owner.

---

## 4. Cluster Failures

### 4.1 Repeated leader elections / flapping

**Symptom**: Logs show frequent `became candidate` / `election timeout` entries; KMIP writes time out.

**Diagnostic**:
```bash
# On each node
journalctl -u craton-hsmd -n 200 | grep -E 'election|leader|heartbeat'
# Network RTT between peers
ping -c 20 <peer-ip>
```

**Fix**:
- Ensure `heartbeat_interval_ms` (default 500) is well below `election_timeout_ms` (default 1500).
- Increase `election_timeout_ms` if inter-peer RTT or OS scheduling jitter exceeds 300 ms.
- Check for clock skew: `max_message_age_ms` rejects messages older than its threshold; ensure NTP is healthy (`chronyc tracking`, `timedatectl`).
- Confirm all nodes see each other on port 9443 (`ss -tn | grep :9443`).

### 4.2 Node refuses to start — "cluster_secret not configured"

**Symptom**: Startup fails with "cluster_secret is required; set allow_insecure: true to override".

**Explanation**: `0.1.1` requires an authenticated `cluster_secret` unless the operator explicitly opts into unauthenticated mode.

**Fix**: Generate and install a secret on every node:
```bash
openssl rand -hex 32 > /etc/craton-hsm/creds/cluster_secret
```
Never enable `allow_insecure: true` outside of a single-node dev environment. See [HARDENING.md §4](HARDENING.md#cluster-hardening).

### 4.3 HMAC replay / "message too old"

**Symptom**: Follower rejects leader's AppendEntries with "message age exceeds max".

**Fix**: Synchronize clocks via NTP. `max_message_age_ms` (default 30000) defines the allowed replay window; do not raise it above 60s.

### 4.4 Split-brain recovery

**Symptom**: Two partitions each believe they are leader (rare; should not happen with quorum intact, but can occur under pathological network conditions or misconfiguration).

**Diagnostic**:
```bash
for node in node-1 node-2 node-3; do
    curl -sk "https://$node:8443/clusterz" | jq '.node_id, .leader, .term'
done
```
Check which term is higher and which partition holds quorum.

**Fix**: The partition with strict majority quorum is authoritative. For the minority side:
1. Stop `craton-hsmd` on all minority nodes.
2. Backup their `/var/lib/craton-hsm`.
3. Remove the local Raft state (directory content, keeping the mountpoint).
4. Restart; they rejoin as followers and pull the authoritative log from the leader.

If quorum cannot be determined, escalate via `security@craton.com.ar` with full cluster logs; do not attempt manual log reconciliation. See [OPERATIONS.md](OPERATIONS.md).

---

## 5. Authentication Failures

### 5.1 LDAP bind errors (`InvalidCredentials`, `ServerDown`)

**Symptom**: All LDAP authentications fail.

**Diagnostic**:
```bash
ldapsearch -x -H ldaps://ldap.example.com:636 \
    -D "uid=svc-craton,ou=services,dc=example,dc=com" -W \
    -b "dc=example,dc=com" -s base
```

**Fix**:
- `ServerDown`: firewall, DNS, or TLS failure. Verify with `openssl s_client -connect ldap.example.com:636`.
- `InvalidCredentials`: wrong bind DN template. The template must use a single `{}` placeholder, e.g. `uid={},ou=users,dc=example,dc=com`.
- `tls_mode: none` is rejected in production configs. Use `ldaps` or `starttls`.
- Rate-limiter lockout: after repeated failures, the identity is locked for `lockout_secs` (default 900). Wait or adjust in config.

### 5.2 OIDC JWKS fetch failures

**Symptom**: OIDC auth intermittently fails with `JwksFetchFailed` or `KeyNotFound`.

**Diagnostic**:
```bash
curl -v "https://auth.example.com/.well-known/openid-configuration"
curl -v "$(curl -s https://auth.example.com/.well-known/openid-configuration | jq -r .jwks_uri)"
```

**Fix**:
- Confirm egress to the IdP is allowed by `NetworkPolicy` / firewall.
- `stale_cache_max_age_secs` (default 3600) allows fallback to a stale JWKS on transient fetch failures; set it if your IdP is known to have brief outages.
- Ensure clock skew tolerance (`clock_skew_secs`, default 30) covers your worst-case NTP drift.
- `KeyNotFound`: the IdP rotated keys and the cache is stale; a fresh fetch on next request typically resolves it.

### 5.3 Certificate authentication rejected despite valid cert

**Symptom**: `CertificateRejected` or `CertificateRevoked` on a cert that chains to a trusted root.

**Diagnostic**:
```bash
openssl verify -CAfile ca-bundle.pem -crl_check -CRLfile crl.pem client.pem
openssl crl -in crl.pem -noout -lastupdate -nextupdate
```

**Fix**:
- Confirm the cert is not in the CRL.
- Confirm CRL `nextUpdate` has not passed. Expired CRLs fail-closed in `0.1.1`; refresh via the OPERATIONS runbook.
- Confirm CRL signature chains to the same root as the client cert.
- If CRL file is malformed: `0.1.1` returns an error (was warn-and-skip in `0.1.0`). Fix the CRL; do not downgrade.

### 5.4 CRL signature verification failure

**Symptom**: Startup or reload log: `CRL signature verification failed`.

**Fix**: The CRL must be signed by a CA present in `trusted_roots`. Re-issue the CRL from the correct issuer, or add the issuer's certificate to the trusted roots if it was previously missing.

### 5.5 TOTP replay / "code already used"

**Symptom**: Valid TOTP codes are rejected.

**Fix**: Constant-time comparison and anti-replay are enforced (`subtle::ConstantTimeEq`, window tracking). Ensure TOTP clock skew (`skew`) is 0 or 1; wider windows permit replay. See [HARDENING.md §3](HARDENING.md#authentication-hardening).

---

## 6. FIPS-Mode Rejections (Correct Behavior)

In FIPS mode (`AwsLcBackend::new_fips()` or `CngBackend::new_fips()`), the following return `HsmError::MechanismInvalid`. **This is correct, not a bug.** Filing an issue against this will be closed with a pointer to this section.

> **Module-vs-library reminder:** "FIPS mode" here means library-level
> approved-algorithm enforcement against AWS-LC (CMVP #4759) or against
> Windows CNG (BCrypt) opened with `BCRYPT_PROV_DISPATCH`. The Craton
> HSM module itself is not yet FIPS 140-3 certified — see
> [SECURITY.md](SECURITY.md#fips-module-certification-status).

| Operation | Reason |
|-----------|--------|
| SHA-1 digest / HMAC-SHA-1 signing | SHA-1 is not FIPS-approved for new signatures |
| Ed25519 sign / verify | Not in the FIPS 140-3 boundary for `0.1.x` |
| Prehashed signatures (`sign_prehashed`, `verify_prehashed`) | Uses RustCrypto internals outside the FIPS module |
| RSA with modulus < 2048 bits | Below FIPS-approved minimum |
| ECDSA with curves other than P-256 / P-384 / P-521 | Others not in the boundary |

AES-128 key generation is **allowed** in FIPS mode as of `0.1.1` (it was previously rejected; this was the `0.1.0` bug). AES-GCM nonce counter is still enforced at 2^32 per key.

See [FIPS_CERTIFICATION_PLAN.md](FIPS_CERTIFICATION_PLAN.md) for the full boundary.

---

## 7. Certificate and CRL Problems

### 7.1 CRL expired at runtime

**Symptom**: `/readyz` reports degraded; logs show `CRL nextUpdate has passed`.

**Fix**: Load a fresh CRL. The `0.1.x` series does not support HTTP CDP or OCSP fetching; operators must refresh CRLs out of band and reload. See [OPERATIONS.md](OPERATIONS.md) for the refresh procedure and [SECURITY.md](SECURITY.md) for the known limitation.

### 7.2 Cert chain does not verify despite apparent validity

**Diagnostic**:
```bash
openssl verify -verbose -show_chain -CAfile ca-bundle.pem client.pem
openssl x509 -in client.pem -noout -issuer -subject
openssl x509 -in ca-intermediate.pem -noout -subject -issuer
```

**Fix**: An intermediate is typically missing from the bundle. Concatenate all intermediates plus the root into a single PEM and point `trusted_roots` or `ca-bundle` at it.

---

## 8. Observability Quick Reference

| Goal | Command / Setting |
|------|-------------------|
| Verbose Rust logs | `RUST_LOG=debug` (or `RUST_LOG=craton_hsm_cluster=trace`) |
| Panic backtrace | `RUST_BACKTRACE=1` (`full` for inline source) |
| FIPS self-test result | Grep startup log for `fips self-test` |
| Cluster state | `GET https://<node>:8443/clusterz` |
| Health | `GET https://<node>:8443/readyz` |
| Nonce counter warnings | Grep for `aes-gcm nonce counter` |
| Rate limiter lockouts | Grep for `auth lockout` |

Always redact keys, PINs, bind DNs, and tenant identifiers before sharing logs on public issues. See [SUPPORT.md](SUPPORT.md#filing-a-good-bug-report).
