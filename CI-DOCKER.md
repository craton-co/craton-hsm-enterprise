# Running CI Pipeline Locally in Docker

This directory contains scripts to run the GitHub CI pipeline locally using Docker.

## Prerequisites

- Docker installed and running
- Git installed
- For Windows: PowerShell
- For Linux: Bash

## Usage

### Windows (PowerShell)

```powershell
# Run all CI jobs (2 long-lived containers in parallel: misc + tests)
.\local-ci-docker.ps1

# Run a specific job (one disposable container)
.\local-ci-docker.ps1 -JobName check

# List available jobs and which container they use
.\local-ci-docker.ps1 -List
```

### Linux / macOS / Windows Git Bash (Bash)

```bash
# Make script executable
chmod +x local-ci-docker.sh

# Run all CI jobs (2 long-lived containers in parallel: misc + tests)
./local-ci-docker.sh

# Run a specific job (one disposable container)
./local-ci-docker.sh check

# List available jobs
./local-ci-docker.sh --list
```

The bash script auto-detects MSYS2 / Git Bash / Cygwin and uses `cygpath` plus
`MSYS_NO_PATHCONV=1` so Docker volume mounts work on Windows too.

## Two-container batch mode

When you run the script with **no job name**, the full CI suite uses exactly **two** Docker containers that run **in parallel**:

| Container | Jobs |
|-----------|------|
| `craton-hsm-ci-misc` | `fmt`, `audit`, `deny`, `features`, `msrv`, `check`, `clippy`, `docs`, `cross-aarch64`, `reproducible-build` |
| `craton-hsm-ci-tests` | `test`, `test-features`, `fips`, `miri`, `coverage`, `fuzz-smoke` |

Each container:

1. Starts once with the workspace mounted at `/workspace/enterprise`
2. Runs `apt-get` and any category-specific `rustup` toolchains **once**
3. Runs its jobs sequentially via `docker exec`
4. Is removed when the category finishes

Cargo registry/git caches use **per-category** named volumes (`craton-hsm-cargo-registry-misc`, `craton-hsm-cargo-registry-tests`, etc.) so the two containers can compile in parallel without fighting over the same cache locks.

**Single-job mode** (`-JobName` / `./local-ci-docker.sh <job>`) still uses one short-lived `docker run --rm` container per invocation.

## Available Jobs

Use `-List` / `--list` to see the full list grouped by container.

## What the Scripts Do

1. **Check Docker is running** — Verifies the Docker daemon is accessible
2. **Batch mode (default)** — Two containers as described above
3. **Single-job mode** — One fresh `rust:latest` container with:
   - Build dependencies (cmake, golang, nasm, gcc-aarch64-linux-gnu, pkg-config, libssl-dev)
   - Environment variables (`CARGO_TERM_COLOR=always`, `RUSTFLAGS=--cap-lints=warn`, toolchain per job)
   - Enterprise workspace mounted at `/workspace/enterprise` (workdir)

## Notes

- Windows and macOS jobs (`check-windows`, `check-macos`) are not included as they require specific OS environments
- DCO sign-off check (`dco`) is not included as it requires git history
- Semver checks (`semver-checks`) are not included as they require PR context
- Some jobs (miri, fuzz-smoke) use nightly Rust toolchain
- Coverage job enforces 85% line coverage threshold
- Fuzz smoke tests run for 60 seconds per target
- Target directories are **not** cached in Docker volumes (disk usage); only cargo registry/git are

## Troubleshooting

**Docker not running**: Start Docker daemon before running the script

**Permission denied**: Run `chmod +x local-ci-docker.sh` first

**Build failures**: Ensure you have sufficient disk space and memory for Docker (two containers compiling at once needs more RAM than one)

**`No such container` on Windows PowerShell**: Update to the latest `local-ci-docker.ps1`; older versions treated `docker rm` stderr as a fatal error when cleaning up absent containers
