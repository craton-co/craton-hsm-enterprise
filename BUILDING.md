# Building craton-hsm-enterprise

## Two-Repository Layout (Required)

Craton HSM Enterprise depends on the open-core library `craton-hsm-core`,
which lives in a **separate** repository. Both repositories must be checked
out as siblings before any `cargo` command will succeed:

```bash
git clone https://github.com/craton-co/craton-hsm-core ../craton-hsm-core
git clone https://github.com/craton-co/craton-hsm-enterprise
cd craton-hsm-enterprise
```

Expected directory layout:

```
craton-hsm/
  craton-hsm-core/       <- core library (Apache-2.0)
  craton-hsm-enterprise/ <- this workspace (BSL 1.1)
```

If `cargo` reports `error: failed to read .../craton-hsm-core/Cargo.toml`,
the most likely cause is that the sibling core crate is missing — see the
troubleshooting section at the bottom of this file.

## Prerequisites

### All Platforms

- **Rust** 1.75 or later (install via [rustup](https://rustup.rs))
- **cargo** (included with Rust)

### Linux (Ubuntu 22.04+)

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libssl-dev clang
```

### macOS

```bash
xcode-select --install
brew install cmake openssl
export OPENSSL_DIR=$(brew --prefix openssl)
```

### Windows

- Install [Visual Studio 2022](https://visualstudio.microsoft.com/) with the "Desktop development with C++" workload
- Install [CMake](https://cmake.org/download/)
- Install [NASM](https://www.nasm.us/) (required by `aws-lc-rs`)
- Ensure `nasm.exe` is on `PATH`
- Go 1.21+ is also required for FIPS builds on Windows.
- **OpenSSL** is required to build `craton-hsm-openssl`. See
  [Building `craton-hsm-openssl` on Windows](#building-craton-hsm-openssl-on-windows)
  below for three supported install paths (pre-built MSVC binaries via scoop,
  vcpkg, or the `vendored` cargo feature).

#### Building `craton-hsm-openssl` on Windows

The `craton-hsm-openssl` crate links against an external OpenSSL ≥ 1.1.1
(OpenSSL 3.x is preferred and is what we test against). The `openssl-sys`
build script discovers OpenSSL via the following environment variables, in
order of preference:

1. `OPENSSL_DIR` — pointing at an install root that contains both `include/`
   and `lib/` sub-directories (the layout most package managers ship).
2. `OPENSSL_INCLUDE_DIR` + `OPENSSL_LIB_DIR` — used when the headers and
   import libraries live in separate trees (this is what the Shining Light /
   scoop `openssl` package does).
3. `VCPKG_ROOT` (with `openssl:x64-windows-static-md` installed).
4. As a last resort, the `vendored` cargo feature of this crate, which uses
   `openssl-src` to build OpenSSL from source — requires MSVC `cl.exe`, Perl,
   and NASM.

##### Recommended path: pre-built MSVC binaries via scoop

This is the lowest-friction path and is what our Windows dev machines and
agent worktrees use.

```powershell
# One-time setup
scoop install openssl              # installs OpenSSL 3.x at scoop\apps\openssl
scoop install perl nasm cmake make # general build deps used elsewhere

# Per-shell environment (or set permanently in the system env)
$installRoot = "$env:USERPROFILE\scoop\apps\openssl\current"
$env:OPENSSL_INCLUDE_DIR = "$installRoot\include"
$env:OPENSSL_LIB_DIR     = "$installRoot\lib\VC\x64\MD"
# (use \MT instead of \MD if you build with `+crt-static`)
```

Bash / Git Bash equivalent:

```bash
export OPENSSL_INCLUDE_DIR="$USERPROFILE/scoop/apps/openssl/current/include"
export OPENSSL_LIB_DIR="$USERPROFILE/scoop/apps/openssl/current/lib/VC/x64/MD"
```

Verify:

```bash
RUSTFLAGS="--cap-lints=warn" cargo check -p craton-hsm-openssl --offline
```

The expected output ends with `Checking craton-hsm-openssl …` followed by
`Finished … profile [unoptimized + debuginfo] target(s)`. If you instead see

```
note: vcpkg did not find openssl: No vcpkg installation found.
Could not find directory of OpenSSL installation
$HOST = x86_64-pc-windows-msvc
openssl-sys = 0.9.x
```

then `OPENSSL_INCLUDE_DIR` / `OPENSSL_LIB_DIR` did not propagate into the
cargo invocation. Re-export them in the *same* shell and try again.

##### Alternative path 1: vcpkg

```powershell
git clone https://github.com/microsoft/vcpkg .vcpkg
.\.vcpkg\bootstrap-vcpkg.bat
.\.vcpkg\vcpkg.exe install openssl:x64-windows-static-md
$env:VCPKG_ROOT = (Resolve-Path .\.vcpkg).Path
$env:RUSTFLAGS  = "-C target-feature=+crt-static --cap-lints=warn"
cargo check -p craton-hsm-openssl --offline
```

`vcpkg` builds OpenSSL from source the first time you run `install`, which
takes ~15 minutes and ~2 GB of disk. After that it is cached.

##### Alternative path 2: Shining Light pre-built installer

1. Download the latest 64-bit installer from
   <https://slproweb.com/products/Win32OpenSSL.html> (pick *Win64 OpenSSL
   v3.x* — *not* the "Light" variant; the headers are only in the full one).
2. Install to the default location `C:\Program Files\OpenSSL-Win64`.
3. Export:
   ```bash
   export OPENSSL_DIR="C:/Program Files/OpenSSL-Win64"
   ```
   (forward slashes; cargo accepts them on Windows.)
4. `cargo check -p craton-hsm-openssl --offline`

##### Alternative path 3: `vendored` cargo feature

If you cannot install OpenSSL on the host (locked-down CI image, no admin),
build it from source via the `vendored` feature:

```bash
cargo check -p craton-hsm-openssl --features vendored --offline
```

Prerequisites: `cl.exe` (MSVC), `perl` ≥ 5.10, `nasm`. The build adds ~3
minutes of cold compile and produces a statically-linked OpenSSL inside the
final binary.

**Security implications of `vendored`:** the binary embeds whatever OpenSSL
version `openssl-src` happens to pin (currently OpenSSL 3.x). Security fixes
for OpenSSL then require a full re-build of `craton-hsm-openssl` rather than
a system package update. Prefer the system-OpenSSL paths above for any
production deployment so OS-level CVE patching applies automatically.

## Standard Build

The MSRV is **1.75**; the workspace builds on stable Rust with no nightly
features required at compile time. The reproducible invocation used in CI
and on developer machines is:

```bash
rustup run stable cargo build --workspace
```

Verbose / strict variants:

```bash
# Check all crates (no hw features)
cargo check --workspace

# Build all crates
cargo build --workspace

# Run all tests
cargo test --workspace

# Check formatting
cargo fmt --all -- --check

# Lint
cargo clippy --workspace -- -D warnings
```

If your toolchain is a bit ahead of MSRV and surfaces new lints, the
recommended environment variable is:

```bash
RUSTFLAGS="--cap-lints=warn" cargo build --workspace
```

This caps newly-added clippy / rustc lints at warn so they do not fail
the build. CI uses the same flag when running on stable toolchains newer
than the MSRV pin. Per-crate builds (`-p <crate>`) are also supported and
recommended when iterating on a single backend.

## FIPS Build (`craton-hsm-awslc`)

The `craton-hsm-awslc` crate uses `aws-lc-rs` which includes a FIPS-validated build of AWS-LC.

```bash
# Build with FIPS mode (aws-lc-rs uses the FIPS module when fips feature is enabled)
cargo build -p craton-hsm-awslc --features fips
```

FIPS mode requires `go` 1.21+ on PATH for the AWS-LC FIPS build. Install Go from [go.dev](https://go.dev/dl/).

## Feature Flags

| Crate | Feature | Description |
|-------|---------|-------------|
| `craton-hsm-cloud` | `mock-insecure-do-not-ship` | Enable mock AWS/Azure/Vault/CSI implementations for testing (not default) |
| `craton-hsm-infineon` | `hw` | Link against libtss2-esys (requires Infineon TPM and TSS2 SDK) |
| `craton-hsm-nxp` | `hw` | Link against NXP HSE host library (requires S32G/S32K hardware) |
| `craton-hsm-awslc` | `fips` | Enable FIPS-validated build of AWS-LC (requires Go 1.21+ on PATH) |
| `craton-hsm-auth` | `ldap-auth` | Enable LDAP authentication provider |
| `craton-hsm-auth` | `cert-auth` | Enable certificate-based authentication |
| `craton-hsm-auth` | `oidc-auth` | OpenID Connect authentication provider |
| `craton-hsm-kmip` | `insecure-static-token` | Exposes `KmipServerConfig::auth_token` (a single shared bearer token). Off by default so misconfiguration cannot silently ship a dev-only auth mode into production. **Requires both** the build feature **and** `CRATON_HSM_ALLOW_INSECURE_STATIC_TOKEN=1` in the environment at process start. Production deployments should integrate `craton-hsm-auth` (mTLS / IdP) instead. |
| `craton-hsm-cluster` | `insecure-no-cluster-secret` | Allows `RaftNode::new` to construct a node without a cluster secret. Intended for tests, demos, and development tooling only — never for production. |

### Build with cloud mocks (opt-in)

```bash
cargo build -p craton-hsm-cloud --features mock-insecure-do-not-ship
```

## Hardware Backend Builds

### Infineon TPM 2.0 (`craton-hsm-infineon`)

Requires the [TPM2 Software Stack (TSS2)](https://github.com/tpm2-software/tpm2-tss) with ESAPI support.

```bash
# Ubuntu
sudo apt-get install -y libtss2-dev libtss2-esys-3.0.2-0

# Build with hw feature
cargo build -p craton-hsm-infineon --features hw
```

Supported hardware: Infineon SLB 9670, SLB 9672 (TPM 2.0).

### NXP HSE (`craton-hsm-nxp`)

Requires the NXP HSE Host Library from the [NXP MCUXpresso SDK](https://mcuxpresso.nxp.com/).

1. Obtain the NXP HSE SDK for your target (S32G274A or S32K344)
2. Build the host library: `libhse.a` or `libhse.so`
3. Set environment variables:
   ```bash
   export HSE_SDK_ROOT=/path/to/nxp-hse-sdk
   export HSE_LIB_DIR=$HSE_SDK_ROOT/lib
   ```
4. Build:
   ```bash
   cargo build -p craton-hsm-nxp --features hw
   ```

## Windows CNG Backend (`craton-hsm-cng`)

The `craton-hsm-cng` crate is Windows-only. It uses native Windows CNG (BCrypt) APIs with FIPS algorithm-provider dispatch when the OS is in FIPS mode. Ed25519 is intentionally delegated to RustCrypto because it sits outside the CNG FIPS boundary on supported Windows versions.

```bash
# Build on Windows
cargo build -p craton-hsm-cng

# Exclude on non-Windows cross-compilation targets
cargo build --workspace --exclude craton-hsm-cng --target aarch64-unknown-linux-gnu
```

## craton-hsm-certified

Build the FIPS certification tooling:

```bash
cargo build -p craton-hsm-certified
cargo test -p craton-hsm-certified
```

This crate provides ACVP test vector runners, integrity verification, FSM validation, and binary signing tools for CMVP certification workflows.

## Cross-Compilation

### Linux ARM64 (for embedded/edge deployments)

```bash
rustup target add aarch64-unknown-linux-gnu
sudo apt-get install -y gcc-aarch64-linux-gnu

cargo build --workspace --target aarch64-unknown-linux-gnu \
  --exclude craton-hsm-cng  # Windows-only
```

### NXP S32G (Linux target, ARM Cortex-A53)

```bash
rustup target add aarch64-unknown-linux-gnu
# Use the NXP-provided cross toolchain
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
cargo build -p craton-hsm-nxp --features hw --target aarch64-unknown-linux-gnu
```

## Documentation

```bash
# Build docs for all crates (no external links)
cargo doc --workspace --no-deps

# Open in browser
cargo doc --workspace --no-deps --open
```

## Security Audit

```bash
cargo install cargo-audit
cargo audit
```

## Running CI Locally

Reproduce the full CI pipeline on your local machine:

```bash
# Format check
cargo fmt --all -- --check

# Lint
cargo clippy --workspace -- -D warnings

# Test
cargo test --workspace

# Security audit
cargo audit

# Dependency policy check
cargo deny check
```

## Troubleshooting

### `error: failed to read .../craton-hsm-core/Cargo.toml`

The `craton-hsm` core library (`craton-hsm-core`) must be checked out as a sibling directory to this workspace. Clone it:

```bash
cd ..
git clone https://github.com/craton-co/craton-hsm-core
```

Expected directory layout:
```
craton-hsm/
  craton-hsm-core/       <- core library
  craton-hsm-enterprise/ <- this workspace
```

### NASM not found (Windows, aws-lc-rs)

Install NASM from https://www.nasm.us/ and add it to your `PATH`. Then restart your terminal.

### `libtss2-esys` not found (Infineon hw feature)

Install the TSS2 development package for your distribution or build from source. See the [tpm2-tss build instructions](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md).

### OpenSSL not found (macOS)

```bash
export OPENSSL_DIR=$(brew --prefix openssl)
export OPENSSL_INCLUDE_DIR=$OPENSSL_DIR/include
export OPENSSL_LIB_DIR=$OPENSSL_DIR/lib
```

### OpenSSL not found (Windows)

If `cargo check -p craton-hsm-openssl` fails with

```
note: vcpkg did not find openssl: No vcpkg installation found.
Could not find directory of OpenSSL installation
$HOST = x86_64-pc-windows-msvc
openssl-sys = 0.9.x
```

see [Building `craton-hsm-openssl` on Windows](#building-craton-hsm-openssl-on-windows)
above. The fastest fix is:

```powershell
scoop install openssl
$env:OPENSSL_INCLUDE_DIR = "$env:USERPROFILE\scoop\apps\openssl\current\include"
$env:OPENSSL_LIB_DIR     = "$env:USERPROFILE\scoop\apps\openssl\current\lib\VC\x64\MD"
cargo check -p craton-hsm-openssl --offline
```
