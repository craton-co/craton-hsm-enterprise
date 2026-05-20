# Craton HSM Enterprise Operations Runbook

> **Note:** This runbook references two illustrative binaries that are **not shipped in this workspace**:
> - `craton-hsmd` — an illustrative aggregator daemon. Replace with your embedding application.
> - `craton-hsm-cli` — a **planned** operator CLI. Until it ships, substitute the equivalent crate-level API call, library example, or your application's admin command.
>
> The runbook procedures below describe intent and expected behavior; you must wire them to whatever binary embeds these crates in your environment.

## 1. FIPS Mode Enablement and Validation

### Enable FIPS Mode
```rust
use craton_hsm_awslc::AwsLcBackend;

let backend = AwsLcBackend::new_fips();
assert!(backend.is_fips_mode(), "FIPS mode must be active");
```

### Verify FIPS at Runtime
1. Check that `is_fips_mode()` returns `true`
2. Verify self-tests pass on initialization
3. Confirm SHA-1 operations are rejected
4. Confirm AES-128/192/256 key generation all succeed (all three are FIPS-approved; AES-256 is recommended for new keys)

### Troubleshooting FIPS
| Symptom | Cause | Resolution |
|---------|-------|------------|
| `MechanismInvalid` on prehashed signing | Expected: prehashed ops use non-FIPS RustCrypto | Use standard (non-prehashed) signing |
| `MechanismInvalid` on SHA-1 | Expected: SHA-1 rejected in FIPS mode | Use SHA-256 or higher |
| Self-test failure | Binary integrity compromised or build issue | Rebuild from source; verify binary hash |

## 2. Key Rotation Procedures

### Symmetric Key Rotation (AES)
1. Generate a new AES-256 key:
   ```rust
   let new_key = backend.generate_aes_key(256)?;
   ```
2. Re-wrap existing data keys with the new master key
3. Update key references in all dependent services
4. Verify decryption with the new key succeeds
5. Schedule destruction of the old key after a grace period

### Asymmetric Key Rotation (RSA/EC)
1. Generate new key pair:
   ```rust
   let (pub_key, priv_key) = backend.generate_rsa_key_pair(3072)?;
   ```
2. Distribute the new public key to all verifiers
3. Sign a transition document with both old and new keys
4. Update certificate if applicable (re-issue from CA)
5. Grace period: accept signatures from both keys
6. Destroy old private key after grace period

### AES-GCM Nonce Exhaustion
Monitor the nonce counter warnings:
- **50%**: Begin planning key rotation
- **75%**: Schedule key rotation
- **90%**: Urgent: rotate immediately
- **95%+**: Critical: stop encryption, rotate now

By default the counter is held in memory only and resets on process
restart. For long-lived keys, opt into the file-backed persistent
counter (`PersistentGcmCounter::file_backed` in `craton-hsm-awslc`
and `craton-hsm-openssl`):

- Counter state is HMAC-authenticated on disk (`craton-hsm-gcm-journal v1`
  versioned header).
- Flushes use **write-temp-then-atomic-rename + fsync** so a crash mid-flush
  cannot revert the counter; the next start sees either the prior good
  state or the new committed state, never a torn write.
- Five consecutive flush failures poison the key on disk — further
  encrypts refuse rather than silently restarting at a lower counter.
- MAC-key derivation mixes in OS file-identity (unix `dev+ino`,
  Windows file-index) so the journal is bound to its physical file;
  copying the file to a different inode is detected.

If you opt out of the persistent counter, you must implement external
tracking for long-lived keys.

## 3. CRL Management

### Initial CRL Setup
1. Obtain CRLs from your CA(s) in DER format
2. Configure in cert auth:
   ```json
   {
     "revocation": {
       "enabled": true,
       "crls": ["<base64 or file path to DER CRL>"]
     }
   }
   ```

### CRL Update Procedure
1. Download fresh CRL from CA distribution point
2. Verify CRL signature matches trusted root
3. Check `nextUpdate` field is in the future
4. Replace CRL in configuration
5. Restart the auth service to load new CRL
6. Verify: attempt authentication with a revoked certificate (should fail)

### CRL Automation
Set up a cron job to refresh CRLs:
```bash
#!/bin/bash
# Run daily or per CA's CRL update schedule
curl -o /etc/craton-hsm/crl/ca.crl.der https://ca.example.com/crl/ca.crl
# Validate the CRL was downloaded successfully
openssl crl -in /etc/craton-hsm/crl/ca.crl.der -inform DER -noout
if [ $? -eq 0 ]; then
    systemctl reload craton-hsm
else
    echo "CRL download/validation failed" | mail -s "CRL Alert" ops@example.com
fi
```

### CRL Troubleshooting
| Symptom | Cause | Resolution |
|---------|-------|------------|
| All cert auth rejected | CRL expired (`nextUpdate` in past) | Update CRL from CA |
| "No CRL found for issuer" | CRL issuer doesn't match cert issuer | Add CRL from the correct CA |
| "CRL signature verification failed" | CRL not signed by trusted root | Verify CRL source; check trusted_roots config |
| "CRL thisUpdate is in the future" | Clock skew between HSM and CA | Synchronize NTP; check CA clock |

## 4. Cluster Operations

### Time Synchronisation (Mandatory)

Raft's HMAC-authenticated RPCs carry a wall-clock timestamp and are
rejected if they fall outside the freshness window:

- `max_message_age_ms` (past window, default 30 000 ms)
- `max_future_skew_ms` (future window, default 1 000 ms)

Both values live in the cluster config and are enforced at RPC ingress. The
config validator rejects a setup where `max_future_skew_ms * 2 >=
max_message_age_ms` so an attacker cannot craft a future-dated message that
survives long enough to be re-admitted after a clock regression.

Operators **must** run NTP (or PTP for sub-millisecond accuracy) on every
cluster node. Target drift budget:

| Deployment | Clock sync | Drift budget |
|------------|-----------|-------------|
| Standard | NTP (chrony / systemd-timesyncd) | < 100 ms |
| Regulated / low-latency | PTP (ptp4l, hardware timestamping) | < 10 ms |

A regressing clock on a follower will silently drop incoming heartbeats; a
regressing clock on the leader fails the `leader_lease_is_valid` gate and
linearizable reads start returning `LeaderLeaseExpired`.

### Cluster Secret Sources (Preference Order)

Sources are tried in this order; the first one that resolves wins:

1. `cluster_secret_file` — path to a file mode 0600 (or 0400) on Unix.
   **Preferred for production** — the filesystem permission check is
   enforced at load time.
2. `cluster_secret_env` — name of an env var holding the hex secret.
   **Startup emits a warning**: env-var values are visible in
   `/proc/<pid>/environ` on Unix (any same-UID process or root can read
   them) and to same-user processes via `GetEnvironmentStrings` on Windows.
   Acceptable for container orchestrators that inject short-lived secrets,
   not for long-running bare-metal deployments.
3. `cluster_secret_hex` — inline hex in the config file. Only for local
   development — the secret ends up in backups, config-management systems,
   and shell history.

### Initial Cluster Setup
1. Generate cluster secret:
   ```bash
   openssl rand -hex 32 > /etc/craton-hsm/cluster_secret
   chmod 0600 /etc/craton-hsm/cluster_secret
   ```
2. Distribute secret to all nodes (use encrypted channel)
3. Configure each node (prefer `cluster_secret_file`):
   ```json
   {
     "node_id": "node-1",
     "listen_addr": "10.0.1.1:9443",
     "cluster_secret_file": "/etc/craton-hsm/cluster_secret",
     "peers": [...]
   }
   ```
4. Start nodes (order doesn't matter; Raft handles election)
5. Verify cluster health:
   - Leader elected
   - All peers connected
   - Replication active
   - NTP drift below the budget above

### Cluster Secret Rotation
1. Generate new secret on the leader node
2. Update configuration on ALL nodes (do not restart yet)
3. Rolling restart: restart one node at a time
   - Start with followers, end with leader
   - Wait for each node to rejoin and sync before proceeding
4. Verify HMAC authentication with new secret

### Node Replacement
1. Remove the failed node from cluster config on remaining nodes
2. Provision a new node with the same (or new) node ID
3. Configure the new node with current cluster secret and peer list
4. Start the new node; it will receive a snapshot from the leader
5. Verify the node is caught up (check replication lag)

### Split-Brain Recovery
1. Identify which partition has quorum (majority of nodes)
2. The partition with quorum continues as authoritative
3. Nodes in the minority partition will not accept writes
4. Once network is restored, minority nodes will sync from the leader
5. If both partitions have equal nodes, manual intervention required:
   - Stop all nodes
   - Identify the node with the most recent committed log
   - Designate it as the new leader
   - Restart with updated configuration

## 5. Backup and Restore

### What to Back Up
| Data | Location | Frequency | Method |
|------|----------|-----------|--------|
| Cluster state (Raft log) | `data_dir/hard_state.json`, `log.jsonl` | Continuous (snapshot) | File copy + encrypt |
| Configuration | `/etc/craton-hsm/` | On change | Version control |
| Cluster secret | Config file | On rotation | Encrypted offline storage |
| CRLs | CRL directory | On update | Include in config backup |
| TLS certificates | Cert directory | On renewal | Encrypted offline storage |

### Backup Procedure
```bash
#!/bin/bash
BACKUP_DIR="/backup/craton-hsm/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Stop writes (optional, for consistency)
# craton-hsm-cli cluster pause-writes

# Copy state
cp -r /var/lib/craton-hsm/data "$BACKUP_DIR/data"
cp -r /etc/craton-hsm "$BACKUP_DIR/config"

# Encrypt
tar czf - "$BACKUP_DIR" | gpg --encrypt --recipient backup@example.com > "$BACKUP_DIR.tar.gz.gpg"

# Verify
gpg --decrypt "$BACKUP_DIR.tar.gz.gpg" | tar tzf - > /dev/null

# Resume writes
# craton-hsm-cli cluster resume-writes

echo "Backup completed: $BACKUP_DIR.tar.gz.gpg"
```

### Restore Procedure
1. Stop the Craton HSM service
2. Decrypt and extract backup:
   ```bash
   gpg --decrypt backup.tar.gz.gpg | tar xzf -
   ```
3. Restore data directory and configuration
4. Verify file integrity
5. Start the service
6. Verify: test key operations, check cluster health

## 6. Monitoring

### Health Check Endpoints
| Check | Command | Expected |
|-------|---------|----------|
| Service alive | `craton-hsm-cli status` | "operational" |
| FIPS mode | `craton-hsm-cli fips-status` | "enabled" |
| Cluster health | `craton-hsm-cli cluster health` | All peers "healthy" |
| Auth provider | `craton-hsm-cli auth test` | "connected" |

### Key Metrics
| Metric | Warning | Critical |
|--------|---------|----------|
| Auth failure rate | > 10/min | > 50/min |
| Auth lockouts | > 5/hour | > 20/hour |
| Cluster replication lag | > 1000 entries | > 10000 entries |
| AES-GCM nonce usage | > 50% | > 90% |
| CRL time to expiry | < 7 days | < 1 day |
| Disk usage | > 80% | > 95% |
| Memory usage | > 80% | > 95% |

### Log Levels
| Level | Use |
|-------|-----|
| ERROR | Security events (auth failures, CRL issues, integrity failures) |
| WARN | Degraded operation (stale cache, connection retry, nonce warnings) |
| INFO | Normal operations (auth success, key generation, cluster events) |
| DEBUG | Detailed diagnostics (connection pool, cache refresh) |

Set `RUST_LOG=craton_hsm=info` for production. Use `debug` only for troubleshooting.

## 7. Disaster Recovery

### Recovery Time Objectives
| Scenario | RTO | RPO |
|----------|-----|-----|
| Single node failure | 30 seconds (automatic failover) | 0 (synchronous replication) |
| Quorum loss | Manual intervention required | Last committed entry |
| Complete cluster loss | Restore from backup | Last backup |
| Key compromise | Immediate rotation | N/A |

### Recovery Priorities
1. **Restore service availability** (new leader election or manual failover)
2. **Verify data integrity** (check Raft log checksums)
3. **Rotate credentials** if compromise suspected
4. **Restore full redundancy** (add replacement nodes)
5. **Post-incident review** (root cause analysis, update procedures)

### Disaster Recovery Drill

Run this drill at least quarterly in a non-production environment to keep
recovery muscle memory fresh and catch regressions in the backup pipeline
before you need it.

1. **Pick a recent encrypted backup** from the offsite location (not the
   local copy) and download it to a clean DR host.
2. **Verify backup integrity**: `gpg --decrypt <backup>.tar.gz.gpg | tar tzf - > /dev/null` — must exit 0.
3. **Stand up a fresh node** with no prior state (`data_dir` empty, fresh
   cluster secret or the archived one if the drill covers secret recovery).
4. **Restore** per the "Restore Procedure" above; start the service.
5. **Smoke-test** a read-only operation (`craton-hsm-cli cluster health`,
   fetch a known key's metadata); confirm the key UUIDs and tenant IDs
   match the pre-backup inventory.
6. **Perform one encrypt/decrypt round-trip** against a restored key;
   output must match the pre-backup plaintext.
7. **Verify audit log continuity** — the restored log must contain the
   last event recorded before backup was taken.
8. **Record RTO achieved** (wall-clock from step 3 to step 6) and compare
   against the target in the Recovery Time Objectives table.
9. **Tear down the DR host** (destroy the restored key material; do not
   leave drill artefacts running).
10. **File the drill report** in ops tracker with RTO/RPO achieved,
    failures encountered, and any procedure updates needed.

### TLS Certificate Rotation

TLS material (cluster peers, KMIP, PKCS#11 front end) should rotate on a
90-day cadence; shorter for certs issued by ACME-style short-lived CAs.

1. **Issue the new cert** from your internal CA with the same SANs
   (`craton-hsmd-{0,1,2}.craton-hsm-peers.<domain>` plus the external
   KMIP FQDN) and at least 30 days overlap with the current cert.
2. **Stage both certs** on each node: copy new cert/key alongside the
   existing ones (`server.crt.new`, `server.key.new`, mode `0600`,
   owner `craton-hsm`).
3. **Validate the new material offline**:
   `openssl x509 -in server.crt.new -noout -dates -text` — verify SANs,
   issuer chain, and `notAfter` ≥ 90 days.
4. **Rolling swap**: on one follower at a time, atomically rename
   `.new` → active path and `systemctl reload craton-hsmd` (SIGHUP
   picks up new cert without restart). Wait for `cluster health` to
   report the node as healthy again before moving to the next node.
5. **Rotate the leader last**; accept a brief leader election when the
   leader reloads.
6. **Re-enroll client cert thumbprints** in `craton-hsm-auth`'s
   certificate provider if you also rotated the client CA chain.
7. **Add the old cert's serial to the CRL** via your CA (see *CRL Update
   Procedure* above). Publish the updated CRL before the old cert's
   `notAfter`.
8. **Verify**: `openssl s_client -connect <node>:8443 -showcerts` must
   return the new chain; fresh mTLS clients must succeed; an old cert
   (if still trusted at the TLS layer) must be rejected by the CRL check.

### Leader Failover (No Partition)

Used when you want to drain the current Raft leader for planned
maintenance (kernel patch, hardware swap) without triggering a timeout-
driven election.

1. **Identify the leader**:
   `curl -sk https://<node>:8443/clusterz | jq .leader_id`.
2. **Verify quorum is healthy** (all followers caught up, replication
   lag < 100 entries).
3. **Cordon writes to the leader** (if your deployment has a load
   balancer / service-mesh weighting, shift client traffic to
   followers first).
4. **Pick the target successor** — usually the follower with the lowest
   replication lag and on a different failure domain.
5. **Issue the transfer**:
   `craton-hsm-cli cluster transfer-leadership --to <successor-id>`.
   This uses the Raft leadership-transfer extension; the current leader
   stops accepting new proposals and waits for the target to catch up
   to its `match_index`, then sends `TimeoutNow`.
6. **Confirm the new leader** within 1–2 seconds:
   `curl -sk https://<any>:8443/clusterz | jq .leader_id` should return
   the successor.
7. **Proceed with maintenance** on the drained node (restart, patch,
   reboot). Leader lease guarantees stale-leader reads are gated out.
8. **Bring the drained node back in** as a follower; watch replication
   lag converge.
9. **Optional**: schedule a rebalance if the successor placement left
   an odd failure-domain distribution.

### KMIP Server Troubleshooting

| Symptom | Diagnosis | Fix |
|---------|-----------|-----|
| Client returns `Permission Denied` on first `Create` | mTLS client cert accepted at TLS but identity not mapped to an RBAC role in `craton-hsm-auth`. | Enroll the cert's SPKI hash against a role in `craton-hsm-auth`; restart auth service to reload. |
| `Authentication Not Successful` on every request | `insecure-static-token` feature enabled but `CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN=1` not set (double-gate kicks in). | Set the env var, or (recommended) disable the feature and migrate to `craton-hsm-auth` mTLS. |
| TTLV parse error `DepthExceeded` or `ValueTooLarge` | Malicious or pathological client message exceeded 32-level nesting / 1 MiB per-value limits. | Expected rejection; investigate client; no server-side change. |
| Destroy returns `Item Not Found` for a key that exists | ACL hardening: owner-only Destroy, and ACL denials are reported as `ObjectNotFound` to avoid a cross-tenant key-existence oracle. | Have the owner's principal issue the Destroy, or rotate ownership via Register/GetAttributes. |
| `Activate` → `Item Not Found` on a key you just created | Same as above: owner-only Activate/Revoke/Destroy + ACL-denial flattened to ObjectNotFound. | Use the owning principal. |
| Connection resets during bulk Locate | Per-token rate limiter tripped after too many auth-adjacent failures in the sliding window. | Slow the client; verify the client is reusing the same authenticated session rather than re-logging per op. |
| Server refuses to start, logs "static token too short (< 32 B)" | `validate_for_production()` rejected a weak token. | Generate a ≥ 32-byte random token (`openssl rand -hex 32`), or switch to `craton-hsm-auth`. |
| Server refuses to start, logs "static token matches known placeholder" | Token equals a known-bad placeholder (`changeme`, test defaults). | Replace with a freshly generated token. |
| `Get` returns an Active key but ciphertext rejects on decrypt elsewhere | Possible cross-tenant key mix-up. | Check `tenant_id` on the returned object; confirm the consumer is scoped to the same tenant. |

### Development / Test Opt-In Environment Variables

Insecure or stub code paths are gated by two layers: a Cargo feature at
build time, and one of these opt-in environment variables at runtime. A
production deployment should have **none** of them set.

| Variable | Consumers | Effect |
|----------|-----------|--------|
| `CRATON_HSM_ALLOW_MOCK=1` | `craton-hsm-cloud` (AWS/Azure/Vault mock shims, K8s CSI mock), `craton-hsm-nxp`, `craton-hsm-infineon` | Unlocks mock / stub backends once the relevant Cargo feature is also present. Accepted by the hardware stubs as an alias for `CRATON_HSM_ALLOW_STUB_*`. |
| `CRATON_HSM_ALLOW_STUB_NXP=1` | `craton-hsm-nxp` | Specific alias; either this or `CRATON_HSM_ALLOW_MOCK` unlocks the NXP HSE stub. |
| `CRATON_HSM_ALLOW_STUB_INFINEON=1` | `craton-hsm-infineon` | Specific alias; either this or `CRATON_HSM_ALLOW_MOCK` unlocks the Infineon TPM stub. |
| `CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN=1` | `craton-hsm-kmip` | Re-checked on every request; must be combined with the `insecure-static-token` Cargo feature and a production-strength token (≥ 32 bytes, no known placeholders). |

A CI or runbook check that greps the process environment for any of these
variables is a cheap way to catch accidental production exposure.
