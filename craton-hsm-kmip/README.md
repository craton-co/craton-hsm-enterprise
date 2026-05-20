# craton-hsm-kmip

KMIP (Key Management Interoperability Protocol) server for Craton HSM.

## What it does

Implements an OASIS KMIP server that speaks the binary Tag-Type-Length-
Value (TTLV) protocol on the wire and dispatches requests to
Craton HSM's key store and crypto backend. Intended to provide a
drop-in KMIP endpoint for applications that already talk KMIP — the
wire protocol is stable, the schema is well specified, and the HSM
side stays abstract.

> Scope: this crate implements **KMIP 2.1 wire encoding** and a
> **subset of §6 operations** (those listed below). Full 2.1 feature
> coverage is not claimed.

## Modules

- `ttlv` — binary codec for KMIP messages. Enforces a **maximum nesting
  depth of 32 structure levels** and a **maximum per-value length of
  1 MiB**, so a malicious client cannot exhaust the parser.
- `types` — KMIP enumerations (tags, operations, result reasons, object
  types, attribute names).
- `operations` — per-operation request/response handlers.
- `server` — top-level message dispatcher, authentication integration,
  and an auth-rate-limiter that tracks per-token failure counts over a
  sliding window.

## Operations implemented

- `Create` — generate a symmetric or asymmetric key
- `Register` — import externally supplied key material
- `Get` — retrieve a key by unique identifier
- `GetAttributes` — read individual attributes
- `AddAttribute` — attach a new attribute to an object
- `ModifyAttribute` — replace the value of an existing attribute
- `DeleteAttribute` — remove an attribute from an object
- `Activate` — transition `Pre-Active` → `Active`
- `Revoke` — transition to `Deactivated`
- `Destroy` — zero and remove a key
- `Locate` — find keys by attribute predicate
- `Check` — verify an object's usage limits
- `DeriveKey` — derive a new key from existing material (HKDF-SHA256)
- `RNG_Retrieve` — return a random byte block from the OS RNG
- `Query` — advertise server capabilities

## Feature flags

| Flag | Default | Effect |
|------|---------|--------|
| `insecure-static-token` | off | Exposes `KmipServerConfig::auth_token` (a single shared bearer). Misconfiguring a dev-only auth mode into production is extra-hard: the build feature is only the first gate — runtime startup additionally requires `CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN=1` in the environment. Production deployments should integrate `craton-hsm-auth` (mTLS / IdP) instead. |

## MSRV

Rust **1.75+**.

## Safety (FFI / `unsafe`)

`#![deny(unsafe_code)]` at the crate root. No `unsafe` blocks.

## Security properties

- `#![deny(unsafe_code)]` at the crate root.
- TTLV parser bounds (depth 32, per-value length 1 MiB).
- Authentication rate limiting per client-token hash.
- mTLS authentication expected at the transport layer; identity is
  handed off to `craton-hsm-auth` for RBAC enforcement before any
  operation is dispatched.
- Key material is held in `Zeroizing` buffers where it crosses trust
  boundaries.

## Usage

```rust
use craton_hsm_kmip::server::KmipServer;
use craton_hsm_kmip::operations::InMemoryKeyStore;
use std::sync::Arc;

let store = Arc::new(InMemoryKeyStore::new());
let server = KmipServer::new(store);

// Decode, dispatch, and encode a KMIP TTLV message.
let request_bytes: Vec<u8> = vec![/* ... */];
let response_bytes = server.process_message(&request_bytes)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Wire the server into a real transport (typically TLS over TCP) in your
binary crate. The KMIP port by convention is 5696.

## Running the example

A minimal end-to-end demo lives in
[`examples/inmem_server.rs`](examples/inmem_server.rs). It spins up an
in-memory `KmipServer` on an ephemeral `127.0.0.1` port, opens a single
TCP client, and drives one `Create` + `Get` + `Destroy` lifecycle over
plain TTLV framing (no TLS, so the example is self-contained). Run it
with:

```sh
cargo run --example inmem_server -p craton-hsm-kmip
```

Output includes the OS-assigned listen address and the
`UniqueIdentifier` returned by `Create`, then a confirmation that the
key is gone after `Destroy`. Production deployments should swap the
plain TCP listener for the mTLS-aware `KmipServer::serve` entry point
and replace `AllowAll` with an ACL backed by `craton-hsm-auth`.

## Error types

TTLV parsing failures surface as `TtlvError` (including `DepthExceeded`
for nesting-depth violations and size-limit violations for oversize
values). Dispatched-operation errors surface through standard KMIP result
codes in the response message.

## Requirements

- Rust 1.75+.
- `craton-hsm-core` as a workspace dependency.
- For production deployments: a TLS terminator (rustls, nginx, etc.)
  doing client-cert validation, with the peer certificate subject or
  SPKI hash passed into `craton-hsm-auth` as the authenticated identity.

## Limitations and caveats

- **KMIP 2.1 subset**, not the full §6 operation set. Asymmetric,
  symmetric, secret-data, and opaque object types are supported;
  profiles beyond that (PGP, split keys, certificate chains) are not.
- **No built-in transport.** The crate provides the message
  dispatcher; applications embed it in their own TLS server.
- **No persistence contract** beyond what the supplied `KmipKeyStore`
  impl provides (`InMemoryKeyStore` is intended for tests; a
  production deployment provides its own store, usually backed by the
  replicated state machine in `craton-hsm-cluster`).
- **Credential-related KMIP attributes** (`Credential`, `Authentication`
  structures) are not fully modeled; authentication is handled outside
  the KMIP payload via mTLS + `craton-hsm-auth`.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-kmip:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
