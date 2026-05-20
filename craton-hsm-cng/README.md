# craton-hsm-cng

Windows CNG / BCrypt crypto backend for Craton HSM.

## What it does

Implements the `CryptoBackend` trait from `craton-hsm-core` on top of the
native Windows Cryptography API: Next Generation (CNG, the BCrypt\*
family). When FIPS mode is requested, algorithm providers are opened
with `BCRYPT_PROV_DISPATCH`, restricting operations to Windows-validated
FIPS-approved algorithms.

## Platform

**Windows only.** The full implementation is gated behind `#[cfg(windows)]`.
On non-Windows targets the crate compiles to a minimal stub whose
`new_fips()` returns `HsmError::FunctionNotSupported`, so applications
can cfg-gate backend selection without sprinkling feature flags.

## Features

- AES-256-GCM only for the authenticated-encryption path (the
  `aes_256_gcm_encrypt`/`aes_256_gcm_decrypt` trait methods reject any
  key whose length is not 32 bytes). AES-CBC and AES-CTR accept 16-,
  24-, and 32-byte keys; AES-KW is exercised through the key-wrap path.
- RSA (PKCS#1 v1.5, PSS, OAEP) on 2048-/3072-/4096-bit moduli
- ECDSA and ECDH on P-256 and P-384
- Ed25519 (via RustCrypto `ed25519-dalek`; CNG does not expose Ed25519
  directly, so this operation is outside the CNG FIPS boundary — sign,
  verify, and key-generation entry points all refuse with
  `HsmError::FunctionNotSupported` when the backend is constructed via
  `new_fips()`)
- SHA-2 digests via `BCryptCreateHash`
- Hardware RNG via `BCryptGenRandom`
- RAII handle wrappers (`AlgHandle`, `KeyHandle`, `HashHandle`) for
  `BCryptCloseAlgorithmProvider` / `BCryptDestroyKey` /
  `BCryptDestroyHash`
- `Zeroizing` buffers for sensitive material
- `#![forbid(unsafe_op_in_unsafe_fn)]`; every FFI call site is in an
  explicit `unsafe` block with a `SAFETY:` comment.

## Feature flags

This crate currently exposes no Cargo features. Windows-specific
`windows-sys` dependencies are activated by the target triple
(`cfg(windows)`).

## MSRV

Rust **1.75+**.

## Safety (FFI / `unsafe`)

All CNG / BCrypt calls are `unsafe extern` FFI. The crate sets
`#![forbid(unsafe_op_in_unsafe_fn)]`; every FFI call site is wrapped in
an explicit `unsafe` block with a `SAFETY:` comment naming the invariant
being upheld. RAII wrappers (`AlgHandle`, `KeyHandle`, `HashHandle`)
guarantee `BCryptCloseAlgorithmProvider` / `BCryptDestroyKey` /
`BCryptDestroyHash` on drop, so handle leaks on error paths are not
possible.

## FIPS power-on self-test (POST) gating

When a `CngBackend` is constructed in FIPS mode (`new_fips()`), every
FIPS-relevant entry point refuses to run with
`HsmError::ConfigError("FIPS POST not yet executed")` until the POST
latch has been set. The latch is set by calling
`CngBackend::mark_fips_post_passed()`.

This call is made by `craton-hsm-certified` (the FIPS bring-up harness)
after it has driven the full known-answer-test (KAT) suite against the
backend and verified that every KAT passed. Application code does **not**
call `mark_fips_post_passed()` directly — the certified harness is the
sole authority for advancing the FIPS state machine from "POST pending"
to "operational".

### FIPS POST gating coverage

| `CryptoBackend` method                   | POST-gated? | Notes |
| ---------------------------------------- | :---------: | ----- |
| `rsa_pkcs1v15_sign`                      | yes         | private-key op |
| `rsa_pkcs1v15_verify`                    | no          | verify (public material) |
| `rsa_pss_sign`                           | yes         | |
| `rsa_pss_verify`                         | no          | |
| `rsa_pkcs1v15_sign_prehashed`            | yes         | |
| `rsa_pkcs1v15_verify_prehashed`          | no          | |
| `rsa_pss_sign_prehashed`                 | yes         | |
| `rsa_pss_verify_prehashed`               | no          | |
| `ecdsa_p256_sign`                        | yes         | |
| `ecdsa_p256_verify`                      | no          | |
| `ecdsa_p384_sign`                        | yes         | |
| `ecdsa_p384_verify`                      | no          | |
| `ecdsa_p256_sign_prehashed`              | yes         | |
| `ecdsa_p256_verify_prehashed`            | no          | |
| `ecdsa_p384_sign_prehashed`              | yes         | |
| `ecdsa_p384_verify_prehashed`            | no          | |
| `ed25519_sign`                           | n/a — refused in FIPS mode | RustCrypto, outside CNG boundary |
| `ed25519_verify`                         | n/a — refused in FIPS mode | RustCrypto, outside CNG boundary |
| `aes_256_gcm_encrypt`                    | yes         | |
| `aes_256_gcm_decrypt`                    | yes         | |
| `aes_cbc_encrypt` / `aes_cbc_decrypt`    | yes         | |
| `aes_ctr_encrypt` / `aes_ctr_decrypt`    | yes         | |
| `rsa_oaep_encrypt`                       | yes         | |
| `rsa_oaep_decrypt`                       | yes         | |
| `generate_aes_key`                       | yes         | |
| `generate_rsa_key_pair`                  | yes         | |
| `generate_ec_p256_key_pair`              | yes         | |
| `generate_ec_p384_key_pair`              | yes         | |
| `generate_ed25519_key_pair`              | yes; refused in FIPS mode | |
| `aes_key_wrap` / `aes_key_unwrap`        | yes         | RFC 3394 |
| `ecdh_p256` / `ecdh_p384`                | yes         | |
| `compute_digest`                         | yes         | |
| `create_hasher`                          | no          | hashing is a public operation |
| `digest_output_len`                      | no          | pure query |

Verify-only entry points (`*_verify` and `*_verify_prehashed`) are
intentionally not gated, so that the certified harness can validate
public-key material during bring-up before the POST latch has been set.

## Security considerations

- FIPS compliance is a Windows OS property, not a crate property —
  `new_fips()` opens providers in FIPS-dispatch mode but does not change
  the OS FIPS policy.
- Private-key material is wrapped in `Zeroizing` buffers; handles are
  destroyed on drop.
- NTSTATUS values returned by CNG are mapped to `HsmError` via a typed
  mapping covering 13+ documented codes (invalid handle, host memory, not
  found, access denied, invalid key, buffer overflow, device busy, and
  others) rather than string-matching error text.

## Error types

Failures surface through `craton_hsm::error::HsmError`. NTSTATUS →
`HsmError` mapping lives in the crate's error module.

## Usage

```rust
# #[cfg(windows)]
# {
use craton_hsm_cng::CngBackend;
use craton_hsm::crypto::backend::CryptoBackend;

// Non-FIPS: any Windows CNG-supported algorithm.
let backend = CngBackend::new(false);

// FIPS mode: opens providers with BCRYPT_PROV_DISPATCH so only
// FIPS-approved algorithms succeed. The constructor requires the OS
// FIPS policy to be enabled (see "Requirements" below) because
// `BCRYPT_PROV_DISPATCH` is rejected otherwise.
let backend = CngBackend::new_fips()?;

// FIPS-mode entry points refuse with `HsmError::ConfigError` until
// the POST latch has been flipped — typically driven by
// `craton-hsm-certified` after running every KAT against this backend
// instance. The marker below is shown only for documentation; real
// callers should never invoke it directly.
backend.mark_fips_post_passed();

let key = backend.generate_aes_key(32, true)?;
let ct = backend.aes_256_gcm_encrypt(key.as_ref(), b"plaintext")?;
# }
# Ok::<(), craton_hsm::error::HsmError>(())
```

## Requirements

- Rust 1.75+.
- Windows 10 / Windows Server 2016 or newer.
- `craton-hsm-core` as a workspace dependency.
- For FIPS-mode operation, the **Windows FIPS-mode Group Policy must be
  enabled**:
  - `Computer Configuration → Windows Settings → Security Settings →
    Local Policies → Security Options → "System cryptography: Use FIPS
    compliant algorithms for encryption, hashing, and signing"`, or
    equivalently `HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled = 1`.

  `CngBackend::new_fips()` does **not** change this policy — it only
  opens algorithm providers in FIPS-dispatch mode. Without the OS
  policy set, the CNG module is not running under its validated FIPS
  configuration and the deployment is not FIPS-compliant regardless of
  what this crate does.

## Limitations and caveats

- **Full FIPS 140-3 compliance is a Windows property, not a crate
  property.** See the Requirements note above: if the OS FIPS policy
  is not enabled, calling `new_fips()` restricts the algorithms you can
  use but does not place you inside the certified boundary.
- **Ed25519 is not FIPS.** Ed25519 runs in `ed25519-dalek` (RustCrypto)
  rather than CNG, and is rejected when FIPS mode is selected.
- **Prehashed signing** uses RustCrypto and, like in
  `craton-hsm-awslc`, falls outside the CNG FIPS boundary.
- **Non-Windows targets compile to a stub** — every constructor returns
  a backend that rejects operations, or returns
  `FunctionNotSupported` directly. Applications targeting portable
  builds should pick a different backend on non-Windows targets.
- **AES-GCM AAD** is not currently threaded through the
  `CryptoBackend` trait.

## Changelog

Per-crate `CHANGELOG.md` files are not used in this workspace. See the
workspace-level [CHANGELOG.md](../CHANGELOG.md) for release notes; the
entries that affect this crate are prefixed `craton-hsm-cng:`.

## License

BSL 1.1. See [LICENSE-BSL](../LICENSE-BSL).
