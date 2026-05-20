# craton-hsm-awslc

FIPS 140-3 validated crypto backend for Craton HSM, powered by
[aws-lc-rs](https://github.com/aws/aws-lc-rs).

## What it does

Implements the `CryptoBackend` trait from `craton-hsm-core` using AWS-LC, a
FIPS 140-3 validated cryptographic library. Supports AES-GCM/CBC/CTR, RSA
(PKCS#1v1.5, PSS, OAEP), ECDSA (P-256, P-384), Ed25519, AES key wrap,
ECDH, SHA-2, and HKDF.

## FIPS notes

- All classical crypto operations run inside the FIPS validation boundary.
- **Exception**: Prehashed signing (`*_sign_prehashed`, `*_verify_prehashed`)
  uses RustCrypto crates for signature math and is **not** FIPS-validated.
  When `fips_mode = true`, prehashed operations are rejected.
- AES-GCM enforces a per-key 2^32 encryption limit (NIST SP 800-38D).
  The counter defaults to in-memory / per-process, but an optional
  file-backed journal is available — see "Persistent AES-GCM counter"
  below.

## Feature flags

| Flag | Default | Effect |
|------|---------|--------|
| `fips` | off | Enable the FIPS-validated build of AWS-LC. Requires Go 1.18+ on `PATH`. |

## MSRV

Rust **1.75+**.

## Safety (FFI / `unsafe`)

All `unsafe` FFI is contained in the `aws-lc-rs` upstream crate. This
crate contains no direct `unsafe` blocks; private-key material is wrapped
in `Zeroizing` buffers.

## Security considerations

- FIPS-validated primitives for all classical crypto operations.
- Per-key AES-GCM encryption counter enforced at `2^32` (NIST SP 800-38D).
- Optional file-backed HMAC-integrity-checked persistent counter for keys
  that outlive the process (see below).
- RSA minimum modulus 2048-bit enforced for both sign and verify.
- Prehashed signing uses non-FIPS RustCrypto and is **rejected** when
  `fips_mode = true`.

## Error types

Failures surface through `craton_hsm::error::HsmError`. `MechanismInvalid`
indicates an operation that is intentionally unavailable in the current
mode (e.g. prehashed signing in FIPS mode).

## Build requirements

- Rust 1.75+
- Go 1.18+ on `PATH` (required by aws-lc-rs for the FIPS build)
- A working C/C++ toolchain (clang or gcc on Unix; MSVC build tools on Windows)
  and `cmake` 3.x — aws-lc-rs invokes the AWS-LC C build at compile time
- `craton-hsm-core` checked out as a sibling directory

## Usage

```rust
use craton_hsm_awslc::AwsLcBackend;
use craton_hsm::crypto::backend::CryptoBackend;

// FIPS mode (fallible — surfaces probe failure)
let backend = AwsLcBackend::new_fips()?;

// Non-FIPS mode (infallible)
let backend = AwsLcBackend::new();

// Generate a key and encrypt
let key = backend.generate_aes_key(32, true)?;
let ct = backend.aes_256_gcm_encrypt(key.as_ref(), b"plaintext")?;
```

See [`examples/basic_crypto.rs`](examples/basic_crypto.rs) for a runnable example.

## Persistent AES-GCM counter

By default the per-key AES-GCM nonce counter lives only in-process memory.
A long-lived key reused across restarts would silently regain its 2^32
budget each time, breaking the NIST SP 800-38D safety guarantee.

For deployments where keys outlive the process, install the journal once
at startup and then construct backends normally:

```rust
use craton_hsm_awslc::AwsLcBackend;

// Install the process-global counter. Returns Err(HsmError::AlreadyInitialized)
// if called twice, so callers see install conflicts instead of silently
// inheriting a previously-installed counter.
AwsLcBackend::try_install_persistent_gcm_counter(
    "/var/lib/craton-hsm/gcm-counter.journal",
)?;

// Now construct one or more backends bound to that counter.
let backend = AwsLcBackend::new_fips()?;
// or, non-FIPS:
// let backend = AwsLcBackend::new();
# Ok::<(), craton_hsm::error::HsmError>(())
```

The older `new_fips_with_persistent_gcm_counter` and
`new_with_persistent_gcm_counter` constructors are `#[deprecated]` because
they silently swallowed install conflicts — prefer
`try_install_persistent_gcm_counter` so a misconfigured second install fails
loudly.

Behaviour:

- On startup the journal is loaded, its HMAC-SHA256 integrity footer is
  verified, and the in-memory counter is hydrated so it never goes
  backwards.
- Counter advances are written through to disk (with `fsync`) when the
  in-memory counter has advanced by 1024 since the last flush, or when a
  key is seen for the first time, or on poison.
- Worst-case lost count on a `SIGKILL` is bounded by the 1024-count
  batch threshold.
- An integrity-footer mismatch fails **closed**: every fingerprint
  previously recorded is treated as poisoned for this process, and further
  writes are refused.
- If a journal has no integrity footer (e.g. a cold start after a bad
  crash that left the file half-written), the previously recorded counter
  values are accepted with a warning and the next flush writes a fresh
  footer.

The journal's HMAC key is derived (v2) from
`SHA-256("craton-hsm-gcm-counter-v2" || "\0path:" || canonicalised_path_bytes
[ || "\0id:" || dev/inode bytes ])`. Canonicalising the path means two
symlinks to the same underlying file derive the same key, and the inode
binding (on Unix; path-only fallback on Windows where the stable file index
is unavailable on stable Rust) catches an attacker swapping a different
file in at the same path. Legacy v1 journals
(`SHA-256("craton-hsm-gcm-counter-v1" || path_bytes)`) are accepted on load
and silently upgraded to v2 on the next write. The MAC exists to detect
accidental truncation / corruption across restarts; it does **not** defend
against an attacker with filesystem write access, who would already have
access to the keys themselves.

The journal file is held under an exclusive OS file lock (`fs2`
`try_lock_exclusive`) for the lifetime of the `PersistentGcmCounter`, so
two processes cannot share a journal and race on the append-only writer.
A second install attempt against the same path returns
`HsmError::AlreadyInitialized`.

Only the **first** `try_install_persistent_gcm_counter` call in a process
installs the counter. Subsequent calls return
`HsmError::AlreadyInitialized` — to swap paths, restart the process.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-awslc:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
