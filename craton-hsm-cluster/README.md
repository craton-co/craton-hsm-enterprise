# craton-hsm-cluster

Raft-based clustering, replication, and high availability for Craton HSM.

## What it does

Implements a multi-node HSM cluster with Raft consensus, authenticated
inter-node RPCs, durable log and snapshot storage, and a health
subsystem. Tenants, keys, roles, and configuration changes are replicated
as state-machine events so every node converges on the same view.

## Modules

- `raft` — leader election, log replication, commit index tracking.
- `replication` — higher-level key-replication events (`KeyCreated`,
  `KeyUpdated`, `KeyDeleted`, `KeyRotated`, `ConfigChanged`) with
  per-event SHA-256 checksums.
- `state_machine` — applies committed log entries to the tenant / key
  state that the rest of the HSM reads from.
- `storage` — Raft `HardState` (current term, voted-for) and log
  persistence. Ships two impls:
  - `InMemoryStorage` for tests,
  - `FileStorage` for single-process production use with atomic
    write-rename and `fsync` on every hard-state flush.
- `config` — cluster configuration struct (peers, listen address, TLS
  material, `cluster_secret_hex`, `allow_insecure`, timeouts).
- `health` — per-peer liveness tracking and cluster-wide quorum health.

## Security properties

- **Authenticated RPCs.** Every RPC carries an HMAC-SHA256 tag keyed
  with the cluster secret. Peers without the secret are silently
  ignored (no reply is returned), preventing unauthenticated nodes from
  provoking state changes or exfiltrating state.
- **Replay protection.** RPCs include nonces / monotonic sequence
  numbers that peers track per-source.
- **Bounded log.** Any single log entry larger than
  `MAX_LOG_ENTRY_BYTES` (16 MiB) is rejected at read time — a corrupt
  or forged file cannot OOM the node.
- **Bounded snapshots.** Snapshots larger than `MAX_SNAPSHOT_BYTES`
  (1 GiB) are rejected before being mapped into memory.
- **Fail-closed secret.** If `cluster_secret_hex` is not set and
  `allow_insecure` is `false` (the default), cluster construction
  fails with a diagnostic. Insecure mode exists for local development
  and must be explicitly opted into.
- **`#![deny(unsafe_code)]`** at the crate root.
- Secrets (`cluster_secret`) are held in `Zeroizing<[u8; 32]>`.

## Feature flags

| Flag | Default | Effect |
|------|---------|--------|
| `insecure-no-cluster-secret` | off | Allows `RaftNode::new` / `from_config` to construct a node without a cluster secret. Intended for tests, demos, and development tooling only — never for production. Without this feature the constructor fails closed if `cluster_secret_hex` is unset and `allow_insecure` is `false`. |

## MSRV

Rust **1.75+**.

## Safety (FFI / `unsafe`)

`#![deny(unsafe_code)]` at the crate root. No `unsafe` blocks.

## Usage

```rust
use craton_hsm_cluster::config::{ClusterConfig, PeerConfig};
use craton_hsm_cluster::storage::FileStorage;
use craton_hsm_cluster::raft::RaftNode;
use std::path::PathBuf;

let cfg = ClusterConfig {
    node_id: "node-a".into(),
    peers: vec![
        PeerConfig { id: "node-b".into(), address: "10.0.0.2:7700".into() },
        PeerConfig { id: "node-c".into(), address: "10.0.0.3:7700".into() },
    ],
    cluster_secret_hex: Some(std::env::var("CRATON_CLUSTER_SECRET")?),
    allow_insecure: false,
    ..ClusterConfig::default()
};
cfg.validate()?;  // Fails fast if secret is missing and allow_insecure=false.

let storage = FileStorage::open(PathBuf::from("/var/lib/craton/raft"))?;
let node = RaftNode::new(cfg, storage)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Requirements

- Rust 1.75+.
- A filesystem that supports `fsync` for `FileStorage`.
- A tokio runtime (this crate depends on `tokio` with `rt-multi-thread`,
  `macros`, `sync`, and `time`).

## Limitations and caveats

- **Transport is pluggable; an mTLS transport is bundled.** The crate
  defines the [`ReplicationTransport`] trait and the authenticated
  message format, and ships an [`MTlsTransport`] (`replication.rs`) for
  production use. Applications may swap in their own implementation by
  implementing the trait — wire it up with `tokio::net` or a higher-level
  framework in your binary crate.
- **Single-process `FileStorage`.** Two processes writing to the same
  Raft directory will corrupt it; use a single node process per state
  directory.
- **Single-server-change membership protocol is implemented;
  joint-consensus is not.** Online reconfiguration via
  `propose_config_change` / `record_config_change_approval` /
  `commit_config_change_proposal` adds or removes one voter at a time
  under quorum approval. Multi-voter atomic membership changes (joint
  consensus, §4 of Ongaro's thesis) are not yet supported.
- **Snapshot compaction** is manual: the state machine is responsible
  for deciding when to snapshot and truncate.

A minimal `examples/single_node.rs` smoke-tests a one-node Raft
cluster end-to-end:

```text
cargo run --example single_node -p craton-hsm-cluster
```

Multi-node walk-throughs would require a transport implementation and
are not shipped as runnable examples — see the integration tests under
`tests/` for paired-node and quorum scenarios.

## Error types

Failures surface as `StorageError` (including the
`SnapshotIntegrityFailure` variant for HMAC mismatch on snapshot load)
and `ClusterError` at the higher layer. See the module docs for variant
listings.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-cluster:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
