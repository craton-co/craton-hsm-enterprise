# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-05-19

### Security
- Multi-agent audit and fix sweep across 11 crates: reply-HMAC enforcement in cluster, RSA CRT import template for pkcs11, FIPS POST gate extension in cng, file-locked GCM journal in awslc, monotonic clocks for cluster/auth, KMIP 2.1 conformance fixes, mock test placeholders replaced in cloud, GitHub Action SHA-pinning, OpenSSF Scorecard.
- `craton-hsm-kmip`: static-token runtime allowlist (`CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN`) is now re-checked on every request instead of cached at `KmipServer::new()`; clearing the env var takes effect on the next call.
- `craton-hsm-kmip`: new public `KmipAcl` trait (default `AllowAll`) consulted by `Destroy`, `Revoke`, `Activate`, `Get`, `GetAttributes`, `AddAttribute`. Wire via `KmipServer::with_acl()`; recipe for bridging to `craton-hsm-auth` in the module docs.
- `craton-hsm-kmip`: TTLV decoder gained explicit `max_depth` (32), `max_items` (10k), and `max_bytes` budgets plumbed from `KmipServerConfig::max_message_size`; deeply-nested and high-cardinality decode bombs now fail before allocation.
- `craton-hsm-kmip`: `AuthRateLimiter` now uses a monotonic `Instant` clock so wall-clock backjumps cannot reset the failure window.
- `craton-hsm-cluster`: `RaftNode::from_config` fails construction when `cluster_secret` is missing unless the new `insecure-no-cluster-secret` feature is enabled (tests/demos only). Release builds can no longer boot without HMAC material.
- `craton-hsm-cluster`: `ReplayCache` time-evicts on every insert (previously every 64), freshness check precedes cache check, capacity raised to 16 384. New `replay_cache_full_evictions` metric.
- `craton-hsm-cluster`: per-peer vote rate limiter now scales with cluster size — `refill_interval_ms = clamp(5000 / n, 500, 5000)`; exposed via `VoteRateLimiterConfig`.
- `craton-hsm-cluster`: membership changes require a *majority of current voters* to sign a `ConfigChangeProposal` (new domain-tag-0x04 HMAC) before a leader will commit the change. A single rogue secret holder can no longer add itself unilaterally.
- `craton-hsm-cluster`: `RaftLog::truncate_after` returns `RaftInvariantError::TruncateBelowApplied` instead of panicking; RPC handlers convert to a `success=false` response.
- `craton-hsm-awslc`: GCM counter journal format now carries a `craton-hsm-gcm-journal v1\n` version marker (legacy journals upgrade on next write; unknown versions refuse to load).
- `craton-hsm-awslc`: GCM counter MAC key derivation canonicalizes the path and mixes in OS file-identity (unix `dev+ino`, Windows file-index); legacy key derivation retained as transparent fallback for old journals.
- `craton-hsm-awslc`: GCM eviction flush failures now increment a per-key streak counter; after 5 consecutive failures the key is poisoned on disk and further encrypts refuse.
- `craton-hsm-awslc`: malformed journal records are logged at `warn` with line number + hex prefix; loads with > 16 corrupted records fail rather than silently dropping state.
- `craton-hsm-cloud`: `mock-insecure-do-not-ship` now requires `CRATON_HSM_ACCEPT_MOCK_IN_RELEASE=1` when running under `cfg(not(debug_assertions))`; mocks additionally reject key material longer than 32 B.
- `craton-hsm-cloud` (Vault): key names longer than 256 B, containing NUL, or starting with `/` are rejected at request dispatch.
- `craton-hsm-auth`: LDAP connection pool migrated to `parking_lot::Mutex`; a panic in one thread no longer poisons the entire pool.
- `craton-hsm-infineon` / `craton-hsm-nxp`: added explicit `SAFETY:` justifications at every `unsafe { ffi::... }` call site; NXP stubs (when the `hw` feature is off) now return `HSE_ERR_NOT_IMPLEMENTED` rather than success; Infineon wrappers validate TPM handles before FFI.
- `craton-hsm-cng`: unknown NTSTATUS values are now emitted with their raw hex code and decoded severity/facility/code so operators can triage driver returns.
- `craton-hsm-kmip`: `kmip-insecure-static-token` and `cluster-insecure-no-cluster-secret` feature flags documented in `BUILDING.md`.
- Repository: workspace SPDX identifier harmonized from the non-standard `LicenseRef-BSL-1.1` to the official `BUSL-1.1`.

### Documentation
- New `SUPPLY_CHAIN.md` — release artefact inventory, end-to-end verification commands (cosign, gh attestation, SBOM), dependency policy, and the offline PGP key-ceremony runbook.
- New `.well-known/security-key.asc` placeholder with a visible note explaining why the real key is absent pre-ceremony (prevents silent key-substitution attacks).
- `SECURITY.md` PGP section rewritten — fingerprint placeholder replaced with a status disclosure; verification now requires three-way fingerprint cross-check.
  public release" ambiguity resolved; Change Date- `LICENSE-CHANGE` rewritten — "first public release" ambiguity resolved; Change Date is now explicitly the earlier of (release-tag + 4 years) or the 2030-03-13 hard cap. Product name corrected from "RustHSM Enterprise" to "Craton HSM Enterprise".
- AES-128 FIPS-mode status corrected across `README.md`, `HARDENING.md`, `FIPS_CERTIFICATION_PLAN.md`, `OPERATIONS.md`, `SUPPORT.md` — keygen is *permitted* in FIPS mode (aligning docs with the 0.1.1 code fix).
- `OPERATIONS.md` gained runbooks for: Disaster Recovery Drill, TLS Certificate Rotation, Leader Failover without Partition, KMIP Server Troubleshooting.
- `MAINTAINERS.md` gained sections for: Release Process, Backport Policy, Dependency Update Authority, Revert Policy.
- Per-crate `README.md` files (`pkcs11`, `auth`, `cng`, `infineon`, `nxp`, `cloud`, `cluster`, `kmip`, `awslc`, `certified`) brought to parity on MSRV, Safety, Error types, Feature flag tables, and examples.
- CRL/OCSP scope centralized in `SECURITY.md`; `HARDENING.md` and `DEPLOYMENT.md` now link rather than restate.
- ROADMAP status icons (✅/🚧/📋) applied uniformly; `craton-hsm-cluster` and siblings reconciled with the `Available` status in `README.md`.
- `CONTRIBUTING.md` gained a Review Gates & Branch Protection section covering CODEOWNERS enforcement.
- New `.github/FUNDING.yml`.

- `craton-hsm-kmip`: `KmipServerConfig::auth_token` (shared static bearer) is now double-gated — the `insecure-static-token` cargo feature must be enabled at build time *and* `CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN=1` must be set at process start. Added `validate_for_production()` which rejects weak/short (< 32 B) tokens and known placeholder values.
- `craton-hsm-cluster`: snapshots are now HMAC-SHA256-authenticated with a `CRATON-SNAP-v1` footer; `FileStorage::with_cluster_secret(&[u8])` required for snapshot I/O, otherwise fails closed. New `StorageError::SnapshotIntegrityFailure` variant.
- `craton-hsm-cluster`: per-peer `RequestVote` token-bucket rate limiter (default 3 / 5 s) prevents Sybil-style election flooding. Tunable via `ClusterConfig::vote_rate_limit_{capacity,refill_interval_ms}`.
- `craton-hsm-cluster`: added `RaftNode::leader_lease_is_valid(now_ms)` for linearizable-read gating; stale partitioned-out leaders no longer serve reads.
- `craton-hsm-awslc`, `craton-hsm-openssl`: optional persistent AES-GCM message counter (`PersistentGcmCounter::file_backed`). Survives process restarts, HMAC-integrity-checked journal, fail-closed on I/O errors.
- `craton-hsm-pkcs11`: GCM message counter high-water map lifted to a non-evictable `counters` map; a key evicted from the LRU and re-imported now resumes counting from its prior mark instead of silently resetting to zero.
- `craton-hsm-auth`: RNG for MFA challenge IDs, PIN salts, and approval IDs switched from `thread_rng` to `OsRng` so the cryptographic source is unambiguous.
- `craton-hsm-auth`: OIDC `alg: "none"` explicitly rejected in JWK→Algorithm mapping (defence-in-depth on top of jsonwebtoken's built-in rejection).
- `craton-hsm-auth`: dual-control approval now rejects empty-string `user_id` as well as `None`, preventing multiple anonymous callers from collapsing into a single principal that bypasses the self-approval check.
- `craton-hsm-cng`: NTSTATUS→HsmError mapping expanded from 5 to 13+ documented codes (invalid handle, host memory, not found, access denied, invalid key, buffer overflow, device busy, etc.).
- `craton-hsm-cloud`: K8s CSI gained `prepare_csi_socket_dir(endpoint)` (parent mode 0700, removes stale socket) and `harden_bound_socket(path)` (chmods bound socket 0600).

### Added
- Release workflow now generates Syft SPDX + CycloneDX SBOMs, signs artefacts with cosign keyless, and emits SLSA build provenance + SBOM attestations.
- 8 per-crate `README.md` files (openssl, nxp, infineon, cng, cluster, kmip, cloud, certified).
- New root docs: `MAINTAINERS.md`, `SUPPORT.md`, `DEPLOYMENT.md` (systemd + Docker + K8s StatefulSet), `COMPATIBILITY_MATRIX.md`, `TROUBLESHOOTING.md`, `.editorconfig`.
- `KeyCache::record_gcm_counter`, `persisted_gcm_counter`, `compact_counters` (pkcs11).
- 50+ new tests across crates covering KMIP negative/lifecycle, TTLV depth/size bombs, Raft split-brain and membership change, MFA operation-binding, cross-tenant approval rejection, CNG NTSTATUS mapping, CSI socket hardening, PKCS#11 GCM counter persistence across cache eviction, persistent GCM counter round-trip.

### Changed
- `craton-hsm-pkcs11` `DEFAULT_POOL_SIZE` raised from 4 to 8.
- `craton-hsm-nxp`, `craton-hsm-infineon`, `craton-hsm-cng` marked `publish = false` in `Cargo.toml`.
- KMIP Cargo description corrected to "KMIP 2.1 wire encoding, subset of operations" to match the implemented operation surface (TTLV wire format follows OASIS KMIP 2.1; not all 2.1 operations are implemented).
- `SECURITY.md` now documents the release signing + SBOM verification workflow.
- `LICENSE-BSL` product name updated from "RustHSM Enterprise 0.1.0" to "Craton HSM Enterprise 0.1.1".
- `README.md` now explicitly frames the project as **source-available** (not OSI open-source) with the competing-use carve-out called out in the header.

## [0.1.1] - 2026-04-06

### Security
- Fixed missing ACL enforcement on KMIP Activate, Revoke, and Destroy operations — only the owner may now modify owner-protected objects
- Added secure zeroization of key material on KMIP Destroy using `zeroize` crate to prevent recovery from memory dumps
- Added TTLV value size limit (1 MB) to prevent allocation-based denial of service from malicious KMIP messages
- Fixed PKCS#11 verify methods silently swallowing session errors as signature-invalid; now only CKR_SIGNATURE_INVALID returns Ok(false)
- Added HMAC replay protection to Raft cluster messages with configurable timestamp-based freshness check
- Fixed Infineon backend `is_stub()` returning false when hw feature enabled despite all operations being unimplemented
- Added algorithm validation to KMIP Create operation — unsupported algorithms and mismatched key lengths are now rejected
- Wrapped KMIP server auth token in `Zeroizing<String>` to prevent plaintext persistence in process memory
- Added EcParams to PKCS#11 ECDSA sign operations for compatibility with hardware HSMs
- Fixed FIPS mode incorrectly rejecting AES-128 key generation (allowed per FIPS 140-3)
- Added RSA minimum modulus check (2048-bit) to OpenSSL sign operations (previously only enforced on verify)
- LDAP DN/filter injection prevention via input escaping in `craton-hsm-auth`
- Certificate chain validation against trusted root anchors in `craton-hsm-auth`
- TOTP constant-time comparison using `subtle::ConstantTimeEq` in `craton-hsm-auth`
- AES-256-GCM nonce counter enforcement (NIST SP 800-38D 2^32 limit) in `craton-hsm-awslc` and `craton-hsm-openssl`
- Self-approval bypass fix in dual-control approval workflow (`craton-hsm-auth`)
- RSA minimum 2048-bit key size enforcement for verification operations
- PKCS#11 PIN redaction from `Debug` output in `craton-hsm-pkcs11`
- Key zeroization for temporary private key buffers using `zeroize::Zeroizing`
- FIPS runtime enforcement: prehashed signing methods return `MechanismInvalid` in FIPS mode
- Fixed CRL parse failure being warn-and-skip (fail-open); now returns error to prevent revoked certs authenticating when CRL is unreadable (`craton-hsm-auth`)
- Fixed KMIP Destroy allowing destruction of Active keys without prior deactivation (KMIP 2.1 §4.8)
- Fixed TOCTOU window in dual-control `consume_approved`: peek-then-remove replaces remove-check-reinsert
- Fixed TTLV encoder returning infallible `Vec<u8>` despite internal size checks; now returns `Result` and propagates errors
- Fixed AES-GCM usage counter using `Relaxed` ordering; upgraded to `AcqRel` for correct cross-thread visibility
- Fixed OIDC HTTP client silently swallowing build errors via `unwrap_or_default`
- Fixed OIDC `ensure_cache` returning error on transient I/O failure when stale cache is available

### Added
- Added OIDC ECDSA algorithm support (ES256, ES384) for OpenID Connect authentication
- Added TOTP SHA-256 hash algorithm option alongside SHA-1 default
- Added LDAP connection pool with configurable pool size (default: 4)
- Added automatic GCM nonce counter eviction when map exceeds 10,000 entries
- Added KMIP ResponseHeader with protocol version (2.1), timestamp, and batch count
- Added cluster node_id validation to reject empty identifiers
- Added replication log append-lock to prevent race conditions under concurrency
- Added RaftLog HashMap index for O(1) log entry lookup
- Upgraded PKCS#11 key cache from FIFO to LRU eviction policy
- `is_stub() -> bool` method on `InfineonTpmBackend` and `NxpHseBackend`
- `validate_tpm2b_size()` bounds-checking helper in `craton-hsm-infineon::ffi`
- `mock` feature flag in `craton-hsm-cloud` to gate mock implementations
- `try_reserve_key()` atomic quota enforcement in `craton-hsm-auth` tenant manager
- TTLV recursion depth limit (default 32) with `TtlvError::DepthExceeded` in `craton-hsm-kmip`
- CSI target path traversal prevention in `craton-hsm-cloud`
- RBAC disabled startup warning in `craton-hsm-auth`
- HMAC-SHA256 cluster message authentication in `craton-hsm-cluster`
- Bounded replication log (`max_payload_bytes`, `max_log_entries`) in `craton-hsm-cluster`
- KMIP operations: Query, GetAttributes, Register, Locate in `craton-hsm-kmip`
- CI jobs: security audit (`cargo-audit`), documentation build, feature matrix
- GitHub issue and PR templates
- `SECURITY.md`, `CONTRIBUTING.md`, `BUILDING.md`, `CODE_OF_CONDUCT.md`
- Workspace package metadata: `authors`, `keywords`, `categories`, `homepage`, `documentation`
- One-time warning when `ReplicationLog` is used without a `cluster_secret` (unauthenticated checksums)

### Fixed
- PKCS#11 cache deadlock: `cache_order` lock is released before acquiring `session` lock
- PKCS#11 error context preserved via `tracing::debug!` logging instead of silent discard
- Auth provider fail-fast: unknown provider name returns `FunctionNotSupported` instead of silent fallback
- Salted PIN hashing in MFA challenge/response
- Eliminated redundant read→write lock pair in `ReplicationLog::append` (single write lock)
- Eliminated unnecessary `LogEntry` clone in `RaftLog::append`

## [0.1.0] - 2026-03-13

### Added
- Initial release of enterprise HSM crates
- `craton-hsm-awslc`: FIPS-validated crypto backend using `aws-lc-rs`
- `craton-hsm-openssl`: OpenSSL crypto backend (non-FIPS)
- `craton-hsm-pkcs11`: PKCS#11 hardware HSM passthrough with LRU key cache
- `craton-hsm-auth`: RBAC, LDAP/certificate/MFA authentication, dual-control approvals, tenant management
- `craton-hsm-cluster`: Raft consensus and replication protocol
- `craton-hsm-kmip`: KMIP key lifecycle server with TTLV encoding
- `craton-hsm-cloud`: Kubernetes CSI, AWS/Azure/Vault shims
- `craton-hsm-infineon`: Infineon TPM 2.0 stub backend (TCG ESAPI)
- `craton-hsm-nxp`: NXP HSE stub backend
- `craton-hsm-cng`: Windows CNG backend stub

[Unreleased]: https://github.com/craton-co/craton-hsm-enterprise/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/craton-co/craton-hsm-enterprise/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/craton-co/craton-hsm-enterprise/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/craton-co/craton-hsm-enterprise/releases/tag/v0.1.0
