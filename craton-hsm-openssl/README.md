# craton-hsm-openssl

OpenSSL crypto backend for Craton HSM. Builds against **OpenSSL 1.1.1 or
3.x**; the FIPS provider is supported on 3.x. On 1.1.1 the `openssl` 0.10
crate's `fips::enabled()` probe maps to the legacy `FIPS_mode()` symbol.

## What it does

Implements the `CryptoBackend` trait from `craton-hsm-core` by delegating
primitive operations to the [`openssl`](https://crates.io/crates/openssl)
crate (which binds to the system's OpenSSL 3 library). When the OS OpenSSL
build has the FIPS provider enabled and active, every operation dispatched
through this backend runs inside the FIPS validation boundary.

## Features

- AES-128/192/256 in GCM, CBC, CTR, and key-wrap modes
- RSA (PKCS#1 v1.5, PSS, OAEP) with 2048-bit minimum, 8192-bit ceiling
- ECDSA on P-256 / P-384
- Ed25519 sign and verify
- ECDH on P-256 / P-384 with HKDF-SHA256 derivation (fixed salt to match
  the core crate's ECDH-HKDF derivation)
- SHA-2 digests (SHA-256, SHA-384, SHA-512) via streaming
  `DigestAccumulator`
- Constant-time signature verification (`subtle::ConstantTimeEq`)
- `Zeroizing` buffers for private key material

## AES-GCM nonce safety

This backend generates random 96-bit nonces and enforces the NIST
SP 800-38D birthday bound (2^32 encryptions per key) via a per-process
counter keyed by `SHA-256(key)`:

- Counters live in a `DashMap<[u8; 32], AtomicU64>`.
- Once a key reaches the limit it is moved into a sticky **poison set**
  that cannot be cleared by `reset_gcm_counter` or `evict_gcm_counters`.
  The only way to use that key again is to destroy and re-key.
- The counter map has a soft cap of 1,000,000 entries. Poisoned entries
  are *never* evicted; if the map cannot be shrunk below the cap,
  encryption fails fast rather than silently re-arming a retired key.

**Caveat:** the counter defaults to in-memory / per-process. Long-lived
keys used across restarts must either be rotated on restart, have the
counter persisted at a higher layer, or use the optional persistent
counter described in "Persistent AES-GCM counter" below.

## Persistent AES-GCM counter

For deployments where keys outlive the process, use:

```rust
use craton_hsm_openssl::OpenSslBackend;

let backend = OpenSslBackend::new_with_persistent_gcm_counter(
    "/var/lib/craton-hsm/gcm-counter.journal",
)?;
# Ok::<(), craton_hsm::error::HsmError>(())
```

Behaviour:

- On startup the journal is loaded, its HMAC-SHA256 integrity footer is
  verified, and the in-memory counter + poison set are hydrated so they
  never go backwards.
- Counter advances are written through to disk (with `fsync`) when the
  in-memory counter has advanced by 1024 since the last flush, or when a
  key is seen for the first time, or on poison.
- Worst-case lost count on a `SIGKILL` is bounded by the 1024-count
  batch threshold.
- An integrity-footer mismatch fails **closed**: every fingerprint
  previously recorded is treated as poisoned for this process, and
  further writes are refused.
- If a journal has no integrity footer (e.g. a cold start after a bad
  crash that left the file half-written), the previously recorded counter
  values are accepted with a warning and the next flush writes a fresh
  footer.

The journal's HMAC key is derived as follows (v2 derivation, since the
M2 hardening pass):

1. If `CRATON_HSM_GCM_JOURNAL_KEY` is set to a 64-character hex string,
   that value (32 bytes) is used directly as the MAC key. This lets an
   operator stage a fixed key out-of-band (e.g. when the journal is
   stored on a network filesystem where path canonicalisation drifts).
   A malformed value is ignored with a warning and falls through to (2).
2. Otherwise the key is `SHA-256("craton-hsm-gcm-counter-v2" || "\0path:"
   || canonicalised_path || "\0id:" || device_id || inode)`. Canonicalising
   the path means a journal written through a symlink and re-opened through
   the resolved target still validates. On platforms where `canonicalize`
   fails (file does not yet exist) the un-canonicalised path is used and
   the file-identity component is omitted.
3. v1 journals (`SHA-256("craton-hsm-gcm-counter-v1" || path_bytes)`) are
   accepted transparently for backward compatibility and rewritten with a
   v2 footer on the next flush.

This lets the MAC detect accidental truncation / corruption across
restarts; it does **not** defend against an attacker with filesystem
write access, who would already have access to the keys themselves.

Only the **first** `new_with_persistent_gcm_counter` call in a process
installs the counter; subsequent calls return a backend bound to the
existing counter.

## FIPS POST gating coverage

Every approved mechanism that touches **private key material** invokes
`enforce_fips_post_gate()` before doing any crypto. That gate fails closed
(`HsmError::ConfigError`) when either `openssl::fips::enabled()` (legacy
1.1.x probe, behind the `legacy-ossl-fips` feature) or the
`CRATON_HSM_REQUIRE_FIPS=1` environment variable says the operator is in a
FIPS-strict posture but `OpenSslBackend::mark_fips_post_passed()` has not
yet been latched. The set of gated methods:

| Category | Methods | Why gated |
|---|---|---|
| RSA sign | `rsa_pkcs1v15_sign`, `rsa_pkcs1v15_sign_prehashed`, `rsa_pss_sign`, `rsa_pss_sign_prehashed` | Private-key operation; KAT must pass first. |
| ECDSA sign | `ecdsa_p256_sign`, `ecdsa_p256_sign_prehashed`, `ecdsa_p384_sign`, `ecdsa_p384_sign_prehashed` | Private-key operation. |
| Ed25519 sign | `ed25519_sign` | Private-key operation. (Ed25519 is itself non-approved as of FIPS 186-5 final, but the gate is still applied for defence-in-depth.) |
| AES-GCM | `aes_256_gcm_encrypt`, `aes_256_gcm_decrypt` | FIPS-approved AEAD (NIST SP 800-38D). |
| AES-CBC | `aes_cbc_encrypt`, `aes_cbc_decrypt` | FIPS-approved (NIST SP 800-38A). |
| AES-CTR | `aes_ctr_encrypt`, `aes_ctr_decrypt` | FIPS-approved (NIST SP 800-38A). |
| RSA-OAEP decrypt | `rsa_oaep_decrypt` | Private-key operation. |

The set of methods that **do not** gate, and why:

| Category | Methods | Rationale |
|---|---|---|
| Public-key verification | `rsa_pkcs1v15_verify[_prehashed]`, `rsa_pss_verify[_prehashed]`, `ecdsa_p256_verify[_prehashed]`, `ecdsa_p384_verify[_prehashed]`, `ed25519_verify` | NIST SP 800-140Brev1 §4.A: verification operates only on public material, never reveals secrets, and is needed during the boot path (e.g. to verify a CA cert chain) before any KAT can run. |
| Public-key encryption | `rsa_oaep_encrypt` | Public-key only; the mirror `rsa_oaep_decrypt` IS gated. |
| AES key wrap | `aes_key_wrap`, `aes_key_unwrap` | Delegated to `craton-hsm-core` which performs its own gating. |
| Key generation, ECDH, hashing | All `generate_*` / `ecdh_*` / `compute_digest` / `create_hasher` | Delegated to `craton-hsm-core` (or to OpenSSL key-gen, which itself runs inside the validated provider). The trait-level gate is applied by the core dispatcher where appropriate. |

The intent: a failed KAT or a missing `mark_fips_post_passed()` blocks
every operation that touches a private key, while still allowing the
operator to verify the very signatures (e.g. CA chain at startup) needed
to *unlock* a later POST pass.

## Feature flags

- **`vendored`** (off by default) — forwards to `openssl/vendored`, which
  builds OpenSSL from source via the `openssl-src` crate. Useful on
  systems missing the system OpenSSL development headers (minimal
  Windows CI runners, locked-down build environments). Do **not** enable
  in production unless your build pipeline runs its own OpenSSL
  provenance check; the vendored copy bypasses the OS's hardened, audited
  OpenSSL build.

There is no `hw` feature; hardware acceleration, if any, is whatever the
linked OpenSSL build provides (AES-NI, AVX, etc.).

## Usage

```rust
use craton_hsm_openssl::OpenSslBackend;
use craton_hsm::crypto::backend::CryptoBackend;

let backend = OpenSslBackend;

// Generate an AES-256 key and encrypt a message
let key = backend.generate_aes_key(32, true)?;
let ct = backend.aes_256_gcm_encrypt(key.as_ref(), b"plaintext")?;
# Ok::<(), craton_hsm::error::HsmError>(())
```

## Requirements

- Rust 1.75+
- OpenSSL 1.1.1 or 3.x development headers and libraries available at
  build time (`libssl-dev` / `openssl-devel` / vcpkg, etc.). The
  [`openssl`] crate's build script links against the system OpenSSL.
  The FIPS provider path is only available on 3.x.
- `craton-hsm-core` checked out as a sibling directory.
- For FIPS-mode operation, an OpenSSL 3 build with the FIPS provider
  installed and activated in `openssl.cnf`.

## Limitations and caveats

- **No AAD** for AES-GCM. The core `CryptoBackend` trait does not expose
  additional authenticated data, so AAD cannot be supplied through this
  backend today.
- **No configurable MGF1 hash / label** for RSA-OAEP; the MGF1 hash
  tracks the OAEP hash and no label is supplied.
- **Fixed RSA-PSS salt length** equal to the digest length (the RFC 8017
  SHOULD value). Configurable salt length is not exposed.
- **Not implemented**: ChaCha20-Poly1305, AES-GCM-SIV, AES-CCM,
  AES-CMAC, HMAC, X25519 / X448. These gaps live in the core trait.
- **Nonce counter is in-memory** (see above).
- FIPS compliance is a property of the linked OpenSSL build, not of this
  crate. This crate does not itself force FIPS mode; deployments must
  configure the OpenSSL library accordingly.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-openssl:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
