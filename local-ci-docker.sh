#!/usr/bin/env bash
# Run GitHub CI pipeline locally in Docker.
# Works on Linux, macOS, and Windows (Git Bash / MSYS2 / Cygwin).
#
# Usage:
#   ./local-ci-docker.sh                    # all jobs in 2 containers (misc + tests, parallel)
#   ./local-ci-docker.sh <job>              # one job in a disposable container
#   ./local-ci-docker.sh --category-only misc  # internal: one category (batch runner)
#   ./local-ci-docker.sh --list             # list available jobs

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

DOCKER_IMAGE="rust:latest"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# SCRIPT_DIR IS the enterprise workspace root (no parent navigation).
PROJECT_ROOT="$SCRIPT_DIR"

# Names of the long-running containers used by the batch ("run all jobs")
# path. Test jobs share one container so the slow apt-get + rustup install
# happens once for all of them; non-test jobs share the other for the same
# reason. Single-job mode (`./local-ci-docker.sh <job>`) still spins up a
# disposable container per invocation.
CONTAINER_TESTS="craton-hsm-ci-tests"
CONTAINER_MISC="craton-hsm-ci-misc"

print_status() {
    local color=$1
    local message=$2
    printf '%b%s%b\n' "$color" "$message" "$NC"
}

check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_status "$RED" "Error: Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Cheap probe so the runner can short-circuit a job when Docker has died
# mid-suite (we've seen this multiple times under heavy load).
docker_alive() {
    docker info > /dev/null 2>&1
}

# Detect Windows-ish shells (Git Bash, MSYS2, Cygwin) so we can translate paths
# for Docker Desktop. On Linux/macOS the host path is already absolute and
# Docker-compatible.
is_msys_like() {
    case "${OSTYPE:-}" in
        msys*|cygwin*|win32*) return 0 ;;
    esac
    [[ "$(uname -s 2>/dev/null || true)" == MINGW* ]] || \
    [[ "$(uname -s 2>/dev/null || true)" == MSYS* ]] || \
    [[ "$(uname -s 2>/dev/null || true)" == CYGWIN* ]]
}

# Convert a path to a form Docker Desktop on Windows accepts (e.g. C:/foo/bar).
# On Linux/macOS this returns the path unchanged.
to_docker_path() {
    local p="$1"
    if is_msys_like && command -v cygpath >/dev/null 2>&1; then
        cygpath -m "$p"
    else
        (cd "$p" && pwd)
    fi
}

# craton-hsm is resolved from crates.io (no `path = "..."` in workspace
# Cargo.toml), so we no longer mount a sibling checkout. Developers who
# want to override locally should add a `[patch.crates-io]` entry in their
# own gitignored `.cargo/config.toml`.

# ----------------------------------------------------------------------------
# Job bodies and metadata
# ----------------------------------------------------------------------------
#
# Each job is defined as a triple:
#   job_body(name)       — the bash command(s) that actually do the work
#   job_toolchain(name)  — which rustup toolchain to invoke under
#   job_category(name)   — "tests" or "misc"; selects which container
#
# Single-job mode (`run_job`) and batch mode (`run_in_container`) both
# consume the same `job_body` output, so the work each job does cannot
# drift between the two paths.

job_body() {
    case "$1" in
        check)
            echo "cargo check --workspace --exclude craton-hsm-infineon --exclude craton-hsm-nxp && cargo check -p craton-hsm-infineon --features stub && cargo check -p craton-hsm-nxp --features stub"
            ;;
        test)
            echo "cargo test --workspace --exclude craton-hsm-infineon --exclude craton-hsm-nxp && cargo test -p craton-hsm-infineon --features stub && cargo test -p craton-hsm-nxp --features stub"
            ;;
        clippy)
            echo "rustup component add clippy && cargo clippy --workspace --exclude craton-hsm-infineon --exclude craton-hsm-nxp -- -D warnings -D clippy::correctness -D clippy::suspicious && cargo clippy -p craton-hsm-infineon --features stub -- -D warnings && cargo clippy -p craton-hsm-nxp --features stub -- -D warnings"
            ;;
        fmt)
            echo "rustup component add rustfmt && cargo fmt --all -- --check"
            ;;
        audit)
            echo "cargo install cargo-audit --locked && cargo audit"
            ;;
        deny)
            echo "cargo install cargo-deny --locked && cargo deny check"
            ;;
        docs)
            echo "cargo doc --workspace --no-deps --exclude craton-hsm-infineon --exclude craton-hsm-nxp && cargo doc -p craton-hsm-infineon --no-deps --features stub && cargo doc -p craton-hsm-nxp --no-deps --features stub"
            ;;
        msrv)
            echo "cargo check --workspace --locked --exclude craton-hsm-infineon --exclude craton-hsm-nxp && cargo check -p craton-hsm-infineon --features stub --locked && cargo check -p craton-hsm-nxp --features stub --locked"
            ;;
        fips)
            echo "cargo test -p craton-hsm-awslc --features fips"
            ;;
        features)
            echo "cargo check -p craton-hsm-cloud --no-default-features && cargo check -p craton-hsm-cloud --features mock-insecure-do-not-ship && cargo check -p craton-hsm-awslc --features fips && cargo check -p craton-hsm-auth --features ldap-auth && cargo check -p craton-hsm-auth --features cert-auth && cargo check -p craton-hsm-auth --features oidc-auth && cargo check -p craton-hsm-kmip --features insecure-static-token"
            ;;
        test-features)
            echo "cargo test -p craton-hsm-auth --features cert-auth && cargo test -p craton-hsm-auth --features oidc-auth && cargo test -p craton-hsm-auth --features ldap-auth && cargo test -p craton-hsm-cluster && cargo test -p craton-hsm-kmip && cargo test -p craton-hsm-kmip --features insecure-static-token && cargo test -p craton-hsm-pkcs11 && cargo test -p craton-hsm-certified && cargo test -p craton-hsm-cloud && cargo test -p craton-hsm-nxp && cargo test -p craton-hsm-infineon"
            ;;
        cross-aarch64)
            echo "rustup target add aarch64-unknown-linux-gnu && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo check --target aarch64-unknown-linux-gnu -p craton-hsm-openssl -p craton-hsm-awslc --no-default-features"
            ;;
        coverage)
            echo "rustup component add llvm-tools-preview && cargo install cargo-llvm-cov --locked && cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info && cargo llvm-cov report --fail-under-lines 85"
            ;;
        miri)
            # MIRIFLAGS=-Zmiri-disable-isolation matches .github/workflows/ci.yml — a
            # subset of tests (MfaManager eviction, etc.) calls SystemTime::now() which
            # requires clock_gettime(REALTIME), unavailable under Miri's default
            # sandbox.
            echo "export MIRIFLAGS=-Zmiri-disable-isolation && rustup component add miri rust-src --toolchain nightly && cargo +nightly miri setup && cargo +nightly miri test -p craton-hsm-auth --lib && cargo +nightly miri test -p craton-hsm-cluster --lib && cargo +nightly miri test -p craton-hsm-kmip --lib"
            ;;
        fuzz-smoke)
            # Single-quoted body: shell escaping inside the for-loop must survive
            # round-tripping through `bash -c`.
            echo 'cargo +nightly install cargo-fuzz --locked && for fuzz_dir in */fuzz; do crate=$(dirname "$fuzz_dir"); echo "--- fuzz smoke for $crate ---"; ( cd "$crate"; for target in $(cargo +nightly fuzz list); do echo "running $crate::$target for 60s"; cargo +nightly fuzz run "$target" -- -max_total_time=60 || exit 1; done ) || exit 1; done'
            ;;
        reproducible-build)
            echo "cargo build --release -p craton-hsm-awslc && sha256sum target/release/libcraton_hsm_awslc.rlib > /tmp/build1.sha256 && cargo clean && cargo build --release -p craton-hsm-awslc && sha256sum target/release/libcraton_hsm_awslc.rlib > /tmp/build2.sha256 && echo 'Build 1:' && cat /tmp/build1.sha256 && echo 'Build 2:' && cat /tmp/build2.sha256 && if ! diff /tmp/build1.sha256 /tmp/build2.sha256; then echo 'ERROR: Builds are NOT reproducible'; exit 1; fi && echo 'Builds are reproducible'"
            ;;
        *)
            return 1
            ;;
    esac
}

job_toolchain() {
    case "$1" in
        msrv) echo "1.75.0" ;;
        miri|fuzz-smoke) echo "nightly" ;;
        *) echo "stable" ;;
    esac
}

job_category() {
    case "$1" in
        test|test-features|fips|miri|coverage|fuzz-smoke) echo "tests" ;;
        *) echo "misc" ;;
    esac
}

# Apt packages required by every job. Installed once per long-running
# container during `setup_container`; standalone (`run_job`) also installs
# them on container startup.
APT_PACKAGES="cmake golang nasm gcc-aarch64-linux-gnu pkg-config libssl-dev"

apt_install_script() {
    cat <<'EOF'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq cmake golang nasm gcc-aarch64-linux-gnu pkg-config libssl-dev >/dev/null
EOF
}

# Build the rustup-install fragment for one toolchain. Cheap if the
# toolchain is already present (rustup is idempotent), so it's fine to
# call once per category up-front even when not strictly needed.
toolchain_install_script() {
    case "$1" in
        1.75.0)
            # Cargo.lock is kept at v3 (see rust-toolchain.toml) so 1.75.0 can
            # parse it. We deliberately do NOT delete the lockfile — that would
            # let 1.75 re-resolve to the latest published version of every dep,
            # which now picks up edition2024 transitives (toml_datetime
            # 1.1.0+spec-1.1.0) that 1.75's cargo cannot parse.
            echo "rustup toolchain install 1.75.0 --profile minimal -c rustfmt -c clippy"
            ;;
        nightly)
            echo "rustup toolchain install nightly --profile minimal -c miri -c rust-src"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Per-category registry/git volumes so misc and tests containers can run in
# parallel without fighting over the same cargo cache locks.
cargo_volume_args() {
    local category=${1:-shared}
    echo "-v craton-hsm-cargo-registry-${category}:/usr/local/cargo/registry -v craton-hsm-cargo-git-${category}:/usr/local/cargo/git"
}

# ----------------------------------------------------------------------------
# Single-job mode: one disposable container per invocation
# ----------------------------------------------------------------------------

run_job() {
    local job_name=$1
    local toolchain
    toolchain=$(job_toolchain "$job_name")
    local body
    body=$(job_body "$job_name") || {
        print_status "$RED" "Unknown job: $job_name"
        return 1
    }

    print_status "$GREEN" "Running job: $job_name (toolchain=$toolchain)"

    local enterprise_path
    enterprise_path=$(to_docker_path "$PROJECT_ROOT")

    print_status "$YELLOW" "Enterprise mount: $enterprise_path -> /workspace/enterprise"

    local setup="set -eo pipefail
$(apt_install_script)"
    local tc_script
    tc_script=$(toolchain_install_script "$toolchain")
    if [ -n "$tc_script" ]; then
        setup="$setup
$tc_script"
    fi

    local full
    full="$setup
$body"

    # Persistent named volumes for cargo registry/git so successive jobs
    # don't re-download every crate. Target dirs are deliberately NOT cached:
    # each toolchain's target/ runs several GB and the 2026-05-16 run filled
    # the WSL VM's virtual disk (containerd I/O error). Re-enable per-toolchain
    # target volumes only after disk headroom is confirmed.
    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "${enterprise_path}:/workspace/enterprise" \
        $(cargo_volume_args shared) \
        -w "/workspace/enterprise" \
        -e CARGO_TERM_COLOR=always \
        -e RUSTFLAGS="--cap-lints=warn" \
        -e RUSTUP_TOOLCHAIN="$toolchain" \
        "$DOCKER_IMAGE" \
        bash -c "$full"
}

# ----------------------------------------------------------------------------
# Batch mode: one long-running container per category, exec each job
# ----------------------------------------------------------------------------

# Tear down a category container if one is still hanging around from a
# previous (interrupted) run, then start a fresh one and install all
# packages and toolchains it will need.
setup_container() {
    local category=$1
    local cname
    case "$category" in
        tests) cname="$CONTAINER_TESTS" ;;
        misc)  cname="$CONTAINER_MISC" ;;
        *) print_status "$RED" "setup_container: unknown category '$category'"; return 1 ;;
    esac

    local enterprise_path
    enterprise_path=$(to_docker_path "$PROJECT_ROOT")

    print_status "$YELLOW" "========================================"
    print_status "$YELLOW" "Starting container '$cname' for category '$category'"
    print_status "$YELLOW" "Enterprise mount: $enterprise_path -> /workspace/enterprise"
    print_status "$YELLOW" "========================================"

    # Clean up any leftover from an interrupted prior run.
    docker rm -f "$cname" >/dev/null 2>&1 || true

    # Same mount/env layout as `run_job` so a job built standalone or in
    # batch sees an identical workspace.
    MSYS_NO_PATHCONV=1 docker run -d \
        --name "$cname" \
        -v "${enterprise_path}:/workspace/enterprise" \
        $(cargo_volume_args "$category") \
        -w "/workspace/enterprise" \
        -e CARGO_TERM_COLOR=always \
        -e RUSTFLAGS="--cap-lints=warn" \
        "$DOCKER_IMAGE" \
        sleep infinity >/dev/null

    # Install apt deps; install every toolchain this category will need
    # so individual jobs don't pay the rustup cost. Each `rustup toolchain
    # install` is idempotent.
    local install="set -eo pipefail
$(apt_install_script)"
    case "$category" in
        tests)
            install="$install
$(toolchain_install_script nightly)"
            ;;
        misc)
            install="$install
$(toolchain_install_script 1.75.0)"
            ;;
    esac

    docker exec "$cname" bash -c "$install" || return 1
}

teardown_container() {
    local category=$1
    local cname
    case "$category" in
        tests) cname="$CONTAINER_TESTS" ;;
        misc)  cname="$CONTAINER_MISC" ;;
        *) return 0 ;;
    esac
    docker rm -f "$cname" >/dev/null 2>&1 || true
}

# Run a single job inside the already-running container for its category.
run_in_container() {
    local job=$1
    local category
    category=$(job_category "$job")
    local cname
    case "$category" in
        tests) cname="$CONTAINER_TESTS" ;;
        misc)  cname="$CONTAINER_MISC" ;;
    esac
    local toolchain
    toolchain=$(job_toolchain "$job")
    local body
    body=$(job_body "$job") || { print_status "$RED" "Unknown job: $job"; return 1; }

    print_status "$GREEN" "Running job: $job (toolchain=$toolchain, container=$cname)"

    MSYS_NO_PATHCONV=1 docker exec \
        -e RUSTUP_TOOLCHAIN="$toolchain" \
        "$cname" \
        bash -c "set -eo pipefail
$body"
}

# ----------------------------------------------------------------------------
# Job ordering
# ----------------------------------------------------------------------------

# Order misc jobs from cheapest (no compile) to most compile-heavy. If the
# Docker daemon dies mid-suite the user still has pass/fail data for the
# quick signals.
JOBS_MISC=(
    "fmt"                  # formatting only, no compile
    "audit"                # cargo-audit, metadata only
    "deny"                 # cargo-deny, metadata only
    "features"             # per-crate checks
    "msrv"                 # 1.75 workspace check
    "check"                # stable workspace check
    "clippy"               # stable workspace clippy
    "docs"                 # cargo doc --workspace
    "cross-aarch64"        # aarch64 check
    "reproducible-build"   # 2x release builds
)

# Test jobs ordered by escalating cost.
JOBS_TESTS=(
    "test"                 # full workspace test
    "test-features"        # feature-gated tests
    "fips"                 # awslc fips tests
    "miri"                 # nightly miri
    "coverage"             # llvm-cov full run
    "fuzz-smoke"           # nightly fuzz, 60s/target
)

# Composite list used by --list and for arg validation.
ALL_JOBS=("${JOBS_MISC[@]}" "${JOBS_TESTS[@]}")

list_jobs() {
    echo "Available jobs:"
    echo "  misc (run in container '$CONTAINER_MISC'):"
    printf "    - %s\n" "${JOBS_MISC[@]}"
    echo "  tests (run in container '$CONTAINER_TESTS'):"
    printf "    - %s\n" "${JOBS_TESTS[@]}"
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

record_category_result() {
    local job=$1 status=$2
    if [ -n "${RESULT_DIR:-}" ]; then
        echo "${job}=${status}" >> "${RESULT_DIR}/${CI_CATEGORY}.results"
    else
        CATEGORY_RESULT_NAMES+=("$job")
        CATEGORY_RESULT_STATUSES+=("$status")
    fi
}

run_jobs_in_category() {
    # $1 = category, rest = job names
    local category=$1; shift
    local jobs=("$@")
    local MAGENTA='\033[0;35m'
    CI_CATEGORY=$category

    if [ -n "${RESULT_DIR:-}" ]; then
        : > "${RESULT_DIR}/${category}.results"
    fi

    if ! docker_alive; then
        print_status "$MAGENTA" "Skipping category '$category' -- Docker daemon is not reachable."
        for job in "${jobs[@]}"; do
            record_category_result "$job" "SKIP"
            ANY_SKIP=1
        done
        return
    fi

    if ! setup_container "$category"; then
        print_status "$RED" "Failed to initialise container for '$category'"
        for job in "${jobs[@]}"; do
            record_category_result "$job" "SKIP"
            ANY_SKIP=1
        done
        return 2
    fi

    for job in "${jobs[@]}"; do
        print_status "$YELLOW" "----------------------------------------"
        print_status "$YELLOW" "[$category] Starting job: $job"
        print_status "$YELLOW" "----------------------------------------"
        if ! docker_alive; then
            print_status "$MAGENTA" "Skipping $job -- Docker daemon went away mid-run."
            record_category_result "$job" "SKIP"
            ANY_SKIP=1
            continue
        fi
        if run_in_container "$job"; then
            print_status "$GREEN" "Job $job completed successfully"
            record_category_result "$job" "PASS"
        else
            if ! docker_alive; then
                print_status "$MAGENTA" "Job $job aborted -- Docker daemon went away mid-run."
                record_category_result "$job" "SKIP"
                ANY_SKIP=1
            else
                print_status "$RED" "Job $job failed"
                record_category_result "$job" "FAIL"
                ANY_FAIL=1
            fi
        fi
    done

    teardown_container "$category"

    if [ "$ANY_FAIL" -ne 0 ]; then return 1; fi
    if [ "$ANY_SKIP" -ne 0 ]; then return 2; fi
    return 0
}

merge_category_results() {
    local job status
    CATEGORY_RESULT_NAMES=()
    CATEGORY_RESULT_STATUSES=()
    for job in "${ALL_JOBS[@]}"; do
        status=""
        for cat in misc tests; do
            if [ -f "${RESULT_DIR}/${cat}.results" ]; then
                status=$(grep -E "^${job}=" "${RESULT_DIR}/${cat}.results" 2>/dev/null | tail -1 | cut -d= -f2-)
                [ -n "$status" ] && break
            fi
        done
        if [ -z "$status" ]; then
            status="SKIP"
            ANY_SKIP=1
        fi
        CATEGORY_RESULT_NAMES+=("$job")
        CATEGORY_RESULT_STATUSES+=("$status")
        case "$status" in
            FAIL) ANY_FAIL=1 ;;
        esac
    done
}

run_category_only() {
    local category=$1
    ANY_FAIL=0
    ANY_SKIP=0
    case "$category" in
        misc)  run_jobs_in_category misc "${JOBS_MISC[@]}" ;;
        tests) run_jobs_in_category tests "${JOBS_TESTS[@]}" ;;
        *) print_status "$RED" "Unknown category '$category'"; exit 1 ;;
    esac
    if [ "$ANY_FAIL" -ne 0 ]; then exit 1; fi
    if [ "$ANY_SKIP" -ne 0 ]; then exit 2; fi
}

main() {
    local arg="${1:-}"

    if [ "$arg" = "--list" ] || [ "$arg" = "-l" ]; then
        list_jobs
        exit 0
    fi

    if [ "$arg" = "--category-only" ]; then
        local category=${2:-}
        if [ -z "$category" ] || [ -z "${RESULT_DIR:-}" ]; then
            print_status "$RED" "Usage: RESULT_DIR=<dir> $0 --category-only misc|tests"
            exit 1
        fi
        mkdir -p "$RESULT_DIR"
        check_docker
        trap 'teardown_container misc; teardown_container tests' EXIT
        run_category_only "$category"
        exit $?
    fi

    check_docker

    if [ -z "$arg" ]; then
        local MAGENTA='\033[0;35m'
        ANY_FAIL=0
        ANY_SKIP=0

        RESULT_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t craton-ci)
        export RESULT_DIR

        # If something crashes mid-suite, make sure the long-running
        # containers don't linger and hold the cargo-registry volume.
        trap 'teardown_container misc; teardown_container tests; rm -rf "$RESULT_DIR"' EXIT

        print_status "$GREEN" "Running all CI jobs in 2 containers (in parallel):
  '$CONTAINER_MISC'  — fmt, check, clippy, audit, deny, docs, msrv, features, cross-aarch64, reproducible-build
  '$CONTAINER_TESTS' — test, test-features, fips, miri, coverage, fuzz-smoke"

        run_jobs_in_category misc "${JOBS_MISC[@]}" &
        local pid_misc=$!
        run_jobs_in_category tests "${JOBS_TESTS[@]}" &
        local pid_tests=$!
        local ec_misc=0 ec_tests=0
        wait "$pid_misc" || ec_misc=$?
        wait "$pid_tests" || ec_tests=$?

        merge_category_results

        print_status "$YELLOW" "========================================"
        print_status "$YELLOW" "CI suite summary"
        print_status "$YELLOW" "========================================"
        local i
        for i in "${!CATEGORY_RESULT_NAMES[@]}"; do
            local color
            case "${CATEGORY_RESULT_STATUSES[$i]}" in
                PASS) color="$GREEN" ;;
                FAIL) color="$RED" ;;
                SKIP) color="$MAGENTA" ;;
                *)    color="$YELLOW" ;;
            esac
            print_status "$color" "$(printf '  %-22s %s' "${CATEGORY_RESULT_NAMES[$i]}" "${CATEGORY_RESULT_STATUSES[$i]}")"
        done
        if [ "$ANY_FAIL" -ne 0 ] || [ "$ec_misc" -eq 1 ] || [ "$ec_tests" -eq 1 ]; then
            print_status "$RED" "One or more jobs failed."
            exit 1
        fi
        if [ "$ANY_SKIP" -ne 0 ] || [ "$ec_misc" -eq 2 ] || [ "$ec_tests" -eq 2 ]; then
            print_status "$MAGENTA" "Some jobs were skipped (Docker daemon unreachable or category failed to start)."
            exit 2
        fi
        print_status "$GREEN" "All jobs completed successfully!"
    else
        local found=0
        local j
        for j in "${ALL_JOBS[@]}"; do
            if [ "$j" = "$arg" ]; then found=1; break; fi
        done
        if [ "$found" -eq 1 ]; then
            run_job "$arg"
            print_status "$GREEN" "Job $arg completed successfully!"
        else
            print_status "$RED" "Error: Unknown job '$arg'"
            echo ""
            list_jobs
            exit 1
        fi
    fi
}

main "$@"
