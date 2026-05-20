# Third-Party Licenses

Craton HSM Enterprise depends on several open-source libraries. This document
lists the key dependencies and their licenses.

## Cryptographic Libraries

| Dependency | License | Purpose |
|-----------|---------|---------|
| aws-lc-rs | Apache-2.0 / ISC | AWS-LC FIPS-validated cryptographic backend |
| openssl | Apache-2.0 | OpenSSL cryptographic backend |
| cryptoki | Apache-2.0 / MIT | PKCS#11 Rust bindings |
| rsa | Apache-2.0 / MIT | RSA encryption and signing |
| p256 | Apache-2.0 / MIT | NIST P-256 elliptic curve |
| p384 | Apache-2.0 / MIT | NIST P-384 elliptic curve |
| sha1 | Apache-2.0 / MIT | SHA-1 hash implementation |
| sha2 | MIT / Apache-2.0 | SHA-2 hash family implementation |
| hmac | MIT / Apache-2.0 | HMAC message authentication |
| hkdf | Apache-2.0 / MIT | HKDF key derivation function |
| pbkdf2 | Apache-2.0 / MIT | PBKDF2 key derivation function |
| base64 | Apache-2.0 / MIT | Base64 encoding/decoding |
| zeroize | MIT / Apache-2.0 | Secure memory zeroization |

## Infrastructure Libraries

| Dependency | License | Purpose |
|-----------|---------|---------|
| serde | MIT / Apache-2.0 | Serialization / deserialization |
| serde_json | MIT / Apache-2.0 | JSON encoding/decoding |
| thiserror | Apache-2.0 / MIT | Derive macro for Error trait |
| tokio | MIT | Asynchronous runtime |
| tracing | MIT | Structured logging and diagnostics |
| dashmap | MIT | Concurrent hash map |
| rand | MIT / Apache-2.0 | Random number generation |
| parking_lot | Apache-2.0 / MIT | Faster mutex and synchronization primitives |
| windows-sys | Apache-2.0 / MIT | Windows API bindings |

## Optional Dependencies

| Dependency | License | Purpose |
|-----------|---------|---------|
| ldap3 | Apache-2.0 / MIT | LDAP authentication provider (optional) |
| jsonwebtoken | MIT | JWT/OIDC token validation (optional) |
| reqwest | Apache-2.0 / MIT | HTTP client for OIDC discovery (optional) |
| x509-parser | Apache-2.0 / MIT | X.509 certificate parsing for cert-auth (optional) |

## Build and Test Dependencies

| Dependency | License | Purpose |
|-----------|---------|---------|
| tempfile | MIT / Apache-2.0 | Temporary file handling in tests |

## License Compliance

All dependencies are verified by `cargo-deny` against an allowlist of
permissive licenses (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC,
Unicode-DFS-2016, OpenSSL) plus this workspace's own `BUSL-1.1`
identifier for internal crate-to-crate dependencies. Copyleft licenses
(GPL family, LGPL, AGPL, MPL, SSPL, etc.) are denied. See
[`deny.toml`](deny.toml) for the full policy.

For the complete dependency tree and license information, run:

```bash
cargo deny list
```

Release artefacts also ship Syft-generated SBOMs (SPDX 2.3 +
CycloneDX 1.5) that enumerate every resolved transitive dependency
and its declared licence. See [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) for
how to fetch and verify these.
