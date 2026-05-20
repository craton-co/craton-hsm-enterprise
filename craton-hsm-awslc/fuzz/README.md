# craton-hsm-awslc fuzz targets

cargo-fuzz scaffolding for the aws-lc-rs backend's most externally-exposed
decryption and verification surfaces.

## Targets

- **`aes_gcm_decrypt`** — feeds arbitrary bytes to `aes_256_gcm_decrypt` as
  `(key, ciphertext+nonce+tag)`. Asserts the backend never panics.
- **`rsa_verify`** — feeds arbitrary bytes as an RSA public key + signature +
  message to `rsa_pkcs1v15_verify`. Asserts the backend never panics.

## Running

Install cargo-fuzz first:

```bash
cargo install cargo-fuzz
```

Then, from the crate root (`craton-hsm-awslc/`):

```bash
# Build all fuzz targets (no run):
cargo +nightly fuzz build

# Run the AES-GCM decrypt fuzzer for 60 seconds:
cargo +nightly fuzz run aes_gcm_decrypt -- -max_total_time=60

# Run the RSA-verify fuzzer with a fixed corpus dir and 4 workers:
cargo +nightly fuzz run rsa_verify -- -jobs=4 -workers=4 corpus/rsa_verify
```

Nightly Rust is required by libFuzzer.

## CI

These targets are **not** run in normal CI — they're wired into a separate
fuzzing job (nightly or OSS-Fuzz) because cargo-fuzz requires a nightly
toolchain and typical CI budgets can't absorb a meaningful fuzz run
(minutes to hours per target per run).

## Triage

A crash under `target/<name>/crashes/` indicates a panic in the backend.
Minimise with:

```bash
cargo +nightly fuzz tmin aes_gcm_decrypt target/crashes/crash-<hash>
```

and open an issue with the minimised reproducer.
