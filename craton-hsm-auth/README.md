# craton-hsm-auth

Enterprise authentication, RBAC, and multi-tenancy for Craton HSM.

## What it does

Provides a pluggable authentication surface with enterprise identity
providers, role-based access control, multi-factor re-auth for destructive
operations, dual-control approvals, and per-tenant key quotas / isolation.
It sits in front of any `CryptoBackend` to enforce who can do what with
which key.

## Public modules

- `auth` — providers, credential types, `AuthManager`.
- `rbac` — roles, permissions, ACL evaluation, dual-control approval
  workflow.
- `tenant` — tenant manager, per-tenant quotas, `try_reserve_key` atomic
  quota enforcement.
- `error` — `AuthError` type.

## Features

- **Local PIN auth**: Wraps PKCS#11 PIN-based login in a pluggable provider
  (intended for development and testing; use LDAP or certificate auth in
  production).
- **LDAP** (`ldap-auth` feature): Bind-based authentication against
  LDAP/AD, TLS-required (LDAPS or StartTLS), injection-safe DN/filter
  escaping, connection pool, per-source rate limit with lockout.
- **OIDC** (`oidc-auth` feature): OpenID Connect token validation; JWKS
  cache with stale-serve fallback; rejects `alg: none`; RS256/RS384/RS512
  and ES256/ES384.
- **Certificate auth** (`cert-auth` feature): X.509 client certificate
  verification against configured trust anchors, full chain validation,
  static CRL revocation (see *Limitations* below).
- **MFA**: TOTP challenge/response before destructive operations, SHA-1
  (legacy) and SHA-256; constant-time comparison via `subtle`.
- **RBAC**: Per-operation ACLs, dual-control approval with self-approval
  rejection and TOCTOU-safe `consume_approved`.
- **Multi-tenancy**: Per-tenant key quotas, isolation, lifecycle
  management, atomic `try_reserve_key`.

## Feature flags

| Flag | Adds | Extra deps |
|------|------|------------|
| `ldap-auth` | LDAP/AD provider | `ldap3`, `tokio` |
| `oidc-auth` | OIDC provider | `jsonwebtoken`, `reqwest` |
| `cert-auth` | X.509 cert provider | `x509-parser` |
| `crl-http-fetch` | HTTPS CRL Distribution Point fetching (implies `cert-auth`) | `reqwest` |

All features are off by default. Enable them in your `Cargo.toml`:

```toml
craton-hsm-auth = { path = "../craton-hsm-auth", features = ["ldap-auth", "oidc-auth"] }
```

## MSRV

Rust **1.75+**.

## Safety (FFI / `unsafe`)

This crate contains no `unsafe` code. Crate-level lints additionally deny
`clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`,
`clippy::unreachable`, and `clippy::indexing_slicing` in non-test builds so
that malformed binds, JWTs, or claims cannot crash the process.

## Security properties

- LDAP DN/filter injection prevention via input escaping.
- Full X.509 chain validation against configured trust anchors.
- TOTP constant-time comparison (`subtle::ConstantTimeEq`).
- Dual-control approval: both requester and approver must have non-empty
  user IDs; empty strings and `None` both rejected.
- `OsRng` (not `thread_rng`) for MFA challenge IDs, PIN salts, approval IDs.
- Salted PIN hashing.
- CRL parse failure fails **closed** (returns error rather than warn-and-skip).

## Usage

```rust
use craton_hsm_auth::auth::{AuthConfig, manager::AuthManager, provider::AuthCredentials};
use zeroize::Zeroizing;

let config = AuthConfig::default();
let mgr = AuthManager::new(&config)?;

let creds = AuthCredentials::Pin {
    user_type: 1,
    pin: Zeroizing::new(b"my-pin".to_vec()),
};
let identity = mgr.authenticate(&creds)?;
```

See [`examples/basic_auth.rs`](examples/basic_auth.rs) for a runnable example.

## Error types

All provider and RBAC failures surface as `craton_hsm_auth::error::AuthError`.
See the module docs for the full variant list.

## Requirements

- Rust 1.75+
- `craton-hsm-core` as a workspace dependency.
- For `ldap-auth`: a reachable LDAP/AD directory with TLS enabled.
- For `oidc-auth`: a reachable OIDC issuer with a JWKS endpoint.
- For `cert-auth`: configured trust anchors and (recommended) static CRLs.

## Limitations and caveats

- **Local PIN store** is intended for testing and development only.
- **Certificate revocation**: static (pre-loaded) DER-encoded CRLs are
  supported by default. CRL Distribution Point HTTP fetching is implemented
  behind the `crl-http-fetch` feature (off by default; HTTPS-only, with body
  caps and no-redirect). OCSP is **not** implemented in `0.1.x`. See
  [SECURITY.md — Certificate revocation](../SECURITY.md#craton-hsm-auth)
  for the authoritative statement and
  [OPERATIONS.md §3](../OPERATIONS.md) for refresh procedures.
- **Rate limiter state is per-process**; in multi-node deployments the
  limiter does not coordinate between nodes.

## Threat model

- **Rate-limiter state is per-process.** Horizontally-scaled deployments
  (multiple HSM frontends sharing one identity store) need an external
  limiter — Redis, an API gateway, or similar — to enforce a global cap.
  The built-in limiter only defends a single process from local brute force.
- **Replay cache (JTI) retention is bounded.** The OIDC replay cache holds
  recently-seen JTIs up to a TTL; a token whose `exp` is further out than
  the cache TTL has its effective replay window collapse to the cache TTL.
  Operators who issue long-lived tokens should size the cache accordingly
  or shorten token lifetimes.
- **OS clock assumption.** Expiry decisions use a monotonic clock
  internally to defeat clock-skew attacks (NTP step, VM pause, manual
  `date -s`); a non-monotonic OS clock is out of scope.
- **Side channels.** Cert-chain parsing is delegated to `x509-parser`;
  vulnerabilities in that crate's parser are out-of-scope for this
  crate's mitigations and are tracked via its own advisories.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-auth:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
