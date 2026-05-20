# craton-hsm-pkcs11

PKCS#11 hardware HSM passthrough backend for Craton HSM.

## What it does

Implements the `CryptoBackend` trait by delegating all cryptographic operations
to a vendor PKCS#11 library (Thales Luna, Entrust nShield, AWS CloudHSM,
YubiHSM, SoftHSM2, etc.). This turns Craton HSM into a unified abstraction
layer with audit logging and session management on top of a hardware root of
trust.

## Architecture

```text
                   ┌──────────────────────────────────────┐
                   │        Pkcs11PassthroughBackend      │
                   │  ┌────────────────────────────────┐  │
                   │  │          SessionPool           │  │
                   │  │                                │  │
                   │  │  Mutex<PooledSession>  ─┐      │  │
                   │  │  Mutex<PooledSession>  ─┼─ N   │  │
                   │  │  Mutex<PooledSession>  ─┘      │  │
                   │  │     (each owns a KeyCache)     │  │
                   │  └────────────────────────────────┘  │
                   └──────────────────────────────────────┘
                                     │
                                     ▼
                         cryptoki::Pkcs11 (Arc, shared)
                                     │
                                     ▼
                            vendor .so / .dll
```

- **Session pool**: Multiple `PooledSession` instances share an `Arc<Pkcs11>`
  context. Each session owns a `KeyCache` for imported key handles.
  Default pool size is 8 (raised from 4 in the most recent hardening sweep).
- **Key cache**: LRU eviction policy. Per-key AES-GCM counter high-water
  marks are held in a separate non-evictable `counters` map, so a key
  evicted and re-imported resumes counting from its prior mark instead of
  silently resetting to zero.
- **No TOCTOU**: Lookup and crypto call run sequentially under one mutex.
- **No string-matching of error types**: verification uses the typed
  `error::VerifyOutcome` decoder (`error::classify_verify_result`).

## Feature flags

This crate currently exposes no Cargo features. The vendor PKCS#11 library is
loaded at runtime from the path in `Pkcs11PassthroughConfig::library_path`.

## MSRV

Rust **1.75+**.

## Safety (FFI / `unsafe`)

The vendor PKCS#11 library is loaded dynamically through `cryptoki` /
`libloading`. All `unsafe` FFI is contained in `cryptoki`; this crate does not
add unsafe blocks of its own. RAII session handles (`PooledSession`) guarantee
`C_CloseSession` on drop.

## Security properties

- **No TOCTOU on imported-key handles.** Each `PooledSession` owns its own
  `KeyCache`; lookup and the subsequent crypto call are sequential under one
  mutex.
- **AES-GCM nonce-reuse bound enforced per key.** Each cache entry tracks the
  encryption count and refuses further encryptions past the configured
  ceiling (default `2^32`, per NIST SP 800-38D §8.3). Eviction no longer
  resets this counter.
- **PIN material minimized.** `Pkcs11PassthroughConfig` holds the PIN in
  `Zeroizing<String>`; the `SessionPool` hands exactly one owned copy to
  `AuthPin` per login. PINs are also redacted from `Debug` output.
- **Fail-closed software fallbacks.** Key generation only falls back to
  software when the operator explicitly sets
  `allow_software_keygen_fallback = true`.
- **Domain-separated fingerprints.** All cache keys are derived with a
  per-key-type domain tag and length-prefixed parts to prevent cross-type
  or concatenation collisions.

## Usage

```rust
use craton_hsm_pkcs11::{Pkcs11PassthroughBackend, Pkcs11PassthroughConfig};
use craton_hsm::crypto::backend::CryptoBackend;

let config = Pkcs11PassthroughConfig {
    library_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
    slot_id: 0,
    // ...
};
let backend = Pkcs11PassthroughBackend::new(config)?;
# Ok::<(), craton_hsm::error::HsmError>(())
```

No runnable examples are shipped in `examples/`. Unit-style tests under
`tests/smoke.rs` (LRU cache, fingerprint domain separation, DigestInfo
helpers, error classification) run by default with `cargo test`. Opt-in
live-token tests against SoftHSM2 are gated behind `#[ignore]` and run via
`cargo test -- --ignored` once the operator has provisioned a slot and PIN.

## Error types

All errors surface through `craton_hsm::error::HsmError`, mapped from
`cryptoki::error::Error` and `cryptoki::error::RvError` via the module's
`error` submodule. Verification results go through the typed
`VerifyOutcome` / `classify_verify_result` path rather than string matching.

## Public surface

The crate exposes two types: `Pkcs11PassthroughBackend` and
`Pkcs11PassthroughConfig`. Everything else is implementation detail,
re-exported under submodules (`backend`, `cache`, `config`, `digest_info`,
`error`, `pool`) for white-box tests.

## Requirements

- Rust 1.75+
- A PKCS#11 shared library (`.so` / `.dll`) from your HSM vendor
- `craton-hsm-core` checked out as a sibling directory

## Limitations and caveats

- **No built-in PIN rotation.** Changing a PIN requires re-instantiating
  the backend with the new credential.
- **No offline PKCS#11 module validation.** The vendor `.so` / `.dll` is
  loaded and trusted at its library path; deployments should load it from a
  write-protected location.
- Software key-generation fallback is off by default and must be opted into
  explicitly.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-pkcs11:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
