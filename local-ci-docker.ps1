# Run GitHub CI pipeline locally in Docker (Windows / PowerShell)
# Usage:
#   .\local-ci-docker.ps1                      # all jobs in 2 containers (misc + tests, parallel)
#   .\local-ci-docker.ps1 -JobName check       # one job in a disposable container
#   .\local-ci-docker.ps1 -CategoryOnly misc   # internal: one category (used by batch runner)
#   .\local-ci-docker.ps1 -List                # list available jobs

param(
    [string]$JobName = "",
    [ValidateSet("", "misc", "tests")]
    [string]$CategoryOnly = "",
    [string]$ResultsDir = "",
    [switch]$List
)

$ErrorActionPreference = "Stop"

$DOCKER_IMAGE = "rust:latest"
$PROJECT_ROOT = $PSScriptRoot

# Names of the long-running containers used by the batch ("run all jobs")
# path. Test jobs share one container so the slow apt-get + rustup install
# happens once for all of them; non-test jobs share the other for the same
# reason. Single-job mode (`-JobName <job>`) still spins up a disposable
# container per invocation.
$CONTAINER_TESTS = "craton-hsm-ci-tests"
$CONTAINER_MISC  = "craton-hsm-ci-misc"

function Write-Status {
    param([string]$Color, [string]$Message)
    Write-Host $Message -ForegroundColor $Color
}

function Test-DockerRunning {
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Red" "Error: Docker is not running. Please start Docker and try again."
        exit 1
    }
}

# Cheap probe so the runner can short-circuit a job when Docker has died
# mid-suite (we've seen this multiple times under heavy load). Returns
# $true if the daemon answers, $false otherwise.
function Test-DockerAlive {
    docker info *> $null
    return ($LASTEXITCODE -eq 0)
}

# Native docker writes progress to stderr; with $ErrorActionPreference = Stop
# that must not abort the script (see Remove-ContainerIfExists).
function Invoke-Docker {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [switch]$Quiet
    )
    $prevNative = $PSNativeCommandUseErrorActionPreference
    try {
        $PSNativeCommandUseErrorActionPreference = $false
        if ($Quiet) {
            & docker @Arguments 2>&1 | Out-Null
        } else {
            & docker @Arguments
        }
    } finally {
        $PSNativeCommandUseErrorActionPreference = $prevNative
    }
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') failed (exit $LASTEXITCODE)"
    }
}

# Per-category registry/git volumes so misc and tests containers can run in
# parallel without fighting over the same cargo cache locks.
function Get-DockerCargoVolumeArgs {
    param([string]$Category)
    $suffix = switch ($Category) {
        "misc"  { "misc" }
        "tests" { "tests" }
        default { "shared" }
    }
    return @(
        "-v", "craton-hsm-cargo-registry-${suffix}:/usr/local/cargo/registry",
        "-v", "craton-hsm-cargo-git-${suffix}:/usr/local/cargo/git"
    )
}

# Docker Desktop on Windows accepts forward-slash paths like C:/foo for -v.
function Convert-ToDockerPath {
    param([string]$Path)
    return (Get-Item -LiteralPath $Path).FullName.Replace('\', '/')
}

# craton-hsm is resolved from crates.io (no `path = "..."` in workspace
# Cargo.toml), so we no longer mount a sibling checkout. Developers who
# want to override locally should add a `[patch.crates-io]` entry in their
# own gitignored `.cargo/config.toml`.

# ----------------------------------------------------------------------------
# Job bodies and metadata
# ----------------------------------------------------------------------------
#
# Each job is defined by:
#   Get-JobBody name       — the bash command string that does the work
#   Get-JobToolchain name  — which rustup toolchain to invoke under
#   Get-JobCategory name   — "tests" or "misc"; selects which container
#
# Single-job mode (`Invoke-StandaloneJob`) and batch mode
# (`Invoke-JobInContainer`) both consume the same body, so the work each
# job does cannot drift between the two paths.

function Get-JobBody {
    param([string]$Name)
    switch ($Name) {
        "check"              { return "cargo check --workspace --exclude craton-hsm-infineon --exclude craton-hsm-nxp && cargo check -p craton-hsm-infineon --features stub && cargo check -p craton-hsm-nxp --features stub" }
        "test"               { return "cargo test --workspace --exclude craton-hsm-infineon --exclude craton-hsm-nxp && cargo test -p craton-hsm-infineon --features stub && cargo test -p craton-hsm-nxp --features stub" }
        "clippy"             { return "rustup component add clippy && cargo clippy --workspace --exclude craton-hsm-infineon --exclude craton-hsm-nxp -- -D warnings -D clippy::correctness -D clippy::suspicious && cargo clippy -p craton-hsm-infineon --features stub -- -D warnings && cargo clippy -p craton-hsm-nxp --features stub -- -D warnings" }
        "fmt"                { return "rustup component add rustfmt && cargo fmt --all -- --check" }
        "audit"              { return "cargo install cargo-audit --locked && cargo audit" }
        "deny"               { return "cargo install cargo-deny --locked && cargo deny check" }
        "docs"               { return "cargo doc --workspace --no-deps --exclude craton-hsm-infineon --exclude craton-hsm-nxp && cargo doc -p craton-hsm-infineon --no-deps --features stub && cargo doc -p craton-hsm-nxp --no-deps --features stub" }
        "msrv"               { return "cargo check --workspace --locked --exclude craton-hsm-infineon --exclude craton-hsm-nxp && cargo check -p craton-hsm-infineon --features stub --locked && cargo check -p craton-hsm-nxp --features stub --locked" }
        "fips"               { return "cargo test -p craton-hsm-awslc --features fips" }
        "features"           { return "cargo check -p craton-hsm-cloud --no-default-features && cargo check -p craton-hsm-cloud --features mock-insecure-do-not-ship && cargo check -p craton-hsm-awslc --features fips && cargo check -p craton-hsm-auth --features ldap-auth && cargo check -p craton-hsm-auth --features cert-auth && cargo check -p craton-hsm-auth --features oidc-auth && cargo check -p craton-hsm-kmip --features insecure-static-token" }
        "test-features"      { return "cargo test -p craton-hsm-auth --features cert-auth && cargo test -p craton-hsm-auth --features oidc-auth && cargo test -p craton-hsm-auth --features ldap-auth && cargo test -p craton-hsm-cluster && cargo test -p craton-hsm-kmip && cargo test -p craton-hsm-kmip --features insecure-static-token && cargo test -p craton-hsm-pkcs11 && cargo test -p craton-hsm-certified && cargo test -p craton-hsm-cloud && cargo test -p craton-hsm-nxp && cargo test -p craton-hsm-infineon" }
        "cross-aarch64"      { return "rustup target add aarch64-unknown-linux-gnu && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo check --target aarch64-unknown-linux-gnu -p craton-hsm-openssl --features vendored -p craton-hsm-awslc --no-default-features" }
        "coverage"           { return "rustup component add llvm-tools-preview && cargo install cargo-llvm-cov --locked && cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info && cargo llvm-cov report --fail-under-lines 85" }
        "miri"               {
            # MIRIFLAGS=-Zmiri-disable-isolation matches .github/workflows/ci.yml — a
            # subset of tests (MfaManager eviction, etc.) calls SystemTime::now()
            # which requires clock_gettime(REALTIME), unavailable under Miri's
            # default sandbox.
            return "export MIRIFLAGS=-Zmiri-disable-isolation && rustup component add miri rust-src --toolchain nightly && cargo +nightly miri setup && cargo +nightly miri test -p craton-hsm-auth --lib && cargo +nightly miri test -p craton-hsm-cluster --lib && cargo +nightly miri test -p craton-hsm-kmip --lib"
        }
        "fuzz-smoke"         {
            $loop = 'for fuzz_dir in */fuzz; do crate=$(dirname "$fuzz_dir"); echo "--- fuzz smoke for $crate ---"; (cd "$crate" && for target in $(cargo +nightly fuzz list); do echo "running $crate::$target for 60s"; cargo +nightly fuzz run "$target" -- -max_total_time=60 || exit 1; done) || exit 1; done'
            return "cargo +nightly install cargo-fuzz --locked && $loop"
        }
        "reproducible-build" { return "cargo build --release -p craton-hsm-awslc && sha256sum target/release/libcraton_hsm_awslc.rlib > /tmp/build1.sha256 && cargo clean && cargo build --release -p craton-hsm-awslc && sha256sum target/release/libcraton_hsm_awslc.rlib > /tmp/build2.sha256 && echo 'Build 1:' && cat /tmp/build1.sha256 && echo 'Build 2:' && cat /tmp/build2.sha256 && (diff /tmp/build1.sha256 /tmp/build2.sha256 || (echo 'ERROR: Builds are NOT reproducible' && exit 1)) && echo 'Builds are reproducible'" }
        default              { throw "Unknown job '$Name'" }
    }
}

function Get-JobToolchain {
    param([string]$Name)
    switch ($Name) {
        "msrv"        { return "1.75.0" }
        "miri"        { return "nightly" }
        "fuzz-smoke"  { return "nightly" }
        default       { return "stable" }
    }
}

function Get-JobCategory {
    param([string]$Name)
    switch ($Name) {
        "test"          { return "tests" }
        "test-features" { return "tests" }
        "fips"          { return "tests" }
        "miri"          { return "tests" }
        "coverage"      { return "tests" }
        "fuzz-smoke"    { return "tests" }
        default         { return "misc" }
    }
}

# apt + rustup install fragments. Each is a SINGLE bash command line
# (joined with `;`) so it survives `docker exec bash -c`. Each command is
# idempotent so `setup_container` can install everything a category will
# need up-front, and `Invoke-StandaloneJob` can install just what it
# needs at job start.
function Get-AptInstallScript {
    return "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq cmake golang nasm gcc-aarch64-linux-gnu pkg-config libssl-dev >/dev/null"
}

function Get-ToolchainInstallScript {
    param([string]$Toolchain)
    switch ($Toolchain) {
        "1.75.0"  {
            # Cargo.lock is kept at v3 (see rust-toolchain.toml) so 1.75.0 can
            # parse it. We deliberately do NOT delete the lockfile — that would
            # let 1.75 re-resolve to the latest published version of every dep,
            # which picks up edition2024 transitives (toml_datetime
            # 1.1.0+spec-1.1.0) whose manifests 1.75's cargo cannot parse.
            return "rustup toolchain install 1.75.0 --profile minimal -c rustfmt -c clippy"
        }
        "nightly" { return "rustup toolchain install nightly --profile minimal -c miri -c rust-src" }
        default   { return "" }
    }
}

# ----------------------------------------------------------------------------
# Single-job mode: one disposable container per invocation
# ----------------------------------------------------------------------------

function Invoke-StandaloneJob {
    param([string]$Name)

    $toolchain = Get-JobToolchain $Name
    $body      = Get-JobBody $Name

    Write-Status "Green"  "Running job: $Name (toolchain=$toolchain)"

    $enterprisePath = Convert-ToDockerPath $PROJECT_ROOT
    Write-Status "Yellow" "Enterprise mount: $enterprisePath -> /workspace/enterprise"

    $setup = @("set -eo pipefail", (Get-AptInstallScript))
    $tcScript = Get-ToolchainInstallScript $toolchain
    if ($tcScript) { $setup += $tcScript }

    $fullScript = ($setup -join "; ") + "; " + $body

    # Persistent named volumes for cargo registry/git so successive jobs
    # don't re-download every crate. Target dirs are deliberately NOT cached:
    # each toolchain's target/ runs several GB and the 2026-05-16 run filled
    # the WSL VM's virtual disk (containerd I/O error). Re-enable per-toolchain
    # target volumes only after disk headroom is confirmed.
    $dockerArgs = @(
        "run", "--rm",
        "-v", "${enterprisePath}:/workspace/enterprise"
    )
    $dockerArgs += Get-DockerCargoVolumeArgs "shared"
    $dockerArgs += @(
        "-w", "/workspace/enterprise",
        "-e", "CARGO_TERM_COLOR=always",
        "-e", "RUSTFLAGS=--cap-lints=warn",
        "-e", "RUSTUP_TOOLCHAIN=$toolchain",
        $DOCKER_IMAGE, "bash", "-c", $fullScript
    )

    Invoke-Docker $dockerArgs
}

# ----------------------------------------------------------------------------
# Batch mode: one long-running container per category, exec each job
# ----------------------------------------------------------------------------

function Get-ContainerName {
    param([string]$Category)
    switch ($Category) {
        "tests" { return $CONTAINER_TESTS }
        "misc"  { return $CONTAINER_MISC }
        default { throw "Unknown category '$Category'" }
    }
}

# docker rm writes to stderr when the container is absent; with
# $ErrorActionPreference = "Stop" that becomes a terminating error unless
# we suppress it (local-ci-docker.sh uses `|| true` for the same reason).
function Remove-ContainerIfExists {
    param([string]$Name)
    $prevNative = $PSNativeCommandUseErrorActionPreference
    $prevError = $ErrorActionPreference
    try {
        $PSNativeCommandUseErrorActionPreference = $false
        $ErrorActionPreference = "SilentlyContinue"
        docker rm -f $Name 2>&1 | Out-Null
    } finally {
        $PSNativeCommandUseErrorActionPreference = $prevNative
        $ErrorActionPreference = $prevError
    }
}

# Start a fresh long-running container for the category, mount the
# workspace, install apt deps and every toolchain the category will need.
function Initialize-CategoryContainer {
    param([string]$Category)

    $cname = Get-ContainerName $Category
    $enterprisePath = Convert-ToDockerPath $PROJECT_ROOT

    Write-Status "Yellow" "========================================"
    Write-Status "Yellow" "Starting container '$cname' for category '$Category'"
    Write-Status "Yellow" "Enterprise mount: $enterprisePath -> /workspace/enterprise"
    Write-Status "Yellow" "========================================"

    # Clean up any leftover from an interrupted prior run.
    Remove-ContainerIfExists $cname

    # Same mount/env layout as Invoke-StandaloneJob so a job built standalone
    # or in batch sees an identical workspace.
    $dockerArgs = @(
        "run", "-d",
        "--name", $cname,
        "-v", "${enterprisePath}:/workspace/enterprise"
    )
    $dockerArgs += Get-DockerCargoVolumeArgs $Category
    $dockerArgs += @(
        "-w", "/workspace/enterprise",
        "-e", "CARGO_TERM_COLOR=always",
        "-e", "RUSTFLAGS=--cap-lints=warn",
        $DOCKER_IMAGE,
        "sleep", "infinity"
    )
    Invoke-Docker ($dockerArgs) -Quiet

    # Install apt deps + every toolchain this category will need so individual
    # jobs don't pay the rustup cost. Each `rustup toolchain install` is
    # idempotent.
    $setup = @("set -eo pipefail", (Get-AptInstallScript))
    switch ($Category) {
        "tests" { $setup += (Get-ToolchainInstallScript "nightly") }
        "misc"  { $setup += (Get-ToolchainInstallScript "1.75.0") }
    }
    $setupScript = ($setup -join "; ")

    Invoke-Docker @("exec", $cname, "bash", "-c", $setupScript)
}

function Remove-CategoryContainer {
    param([string]$Category)
    $cname = Get-ContainerName $Category
    Remove-ContainerIfExists $cname
}

# Run a single job inside the already-running container for its category.
function Invoke-JobInContainer {
    param([string]$Name)

    $category  = Get-JobCategory $Name
    $cname     = Get-ContainerName $category
    $toolchain = Get-JobToolchain $Name
    $body      = Get-JobBody $Name

    Write-Status "Green" "Running job: $Name (toolchain=$toolchain, container=$cname)"

    $fullScript = "set -eo pipefail; $body"

    Invoke-Docker @("exec", "-e", "RUSTUP_TOOLCHAIN=$toolchain", $cname, "bash", "-c", $fullScript)
}

# ----------------------------------------------------------------------------
# Job ordering
# ----------------------------------------------------------------------------

# Order misc jobs from cheapest (no compile) to most compile-heavy. If the
# Docker daemon dies mid-suite the user still has pass/fail data for the
# quick signals.
$JOBS_MISC = @(
    "fmt",                  # formatting only, no compile
    "audit",                # cargo-audit, metadata only
    "deny",                 # cargo-deny, metadata only
    "features",             # per-crate checks
    "msrv",                 # 1.75 workspace check
    "check",                # stable workspace check
    "clippy",               # stable workspace clippy
    "docs",                 # cargo doc --workspace
    "cross-aarch64",        # aarch64 check
    "reproducible-build"    # 2x release builds
)

# Test jobs ordered by escalating cost.
$JOBS_TESTS = @(
    "test",                 # full workspace test
    "test-features",        # feature-gated tests
    "fips",                 # awslc fips tests
    "miri",                 # nightly miri
    "coverage",             # llvm-cov full run
    "fuzz-smoke"            # nightly fuzz, 60s/target
)

# Composite list used by -List and for arg validation.
$ALL_JOBS = $JOBS_MISC + $JOBS_TESTS

function Get-JobsForCategory {
    param([string]$Category)
    switch ($Category) {
        "misc"  { return $JOBS_MISC }
        "tests" { return $JOBS_TESTS }
        default { throw "Unknown category '$Category'" }
    }
}

function Write-CategoryResults {
    param(
        [string]$ResultsDir,
        [string]$Category,
        $Results
    )
    $path = Join-Path $ResultsDir "$Category.results"
    $lines = foreach ($k in $Results.Keys) { "$k=$($Results[$k])" }
    Set-Content -Path $path -Value $lines -Encoding utf8
}

function Read-CategoryResults {
    param([string]$ResultsDir)
    $merged = [ordered]@{}
    foreach ($cat in @("misc", "tests")) {
        $path = Join-Path $ResultsDir "$cat.results"
        if (-not (Test-Path $path)) { continue }
        foreach ($line in Get-Content $path) {
            $eq = $line.IndexOf("=")
            if ($eq -lt 1) { continue }
            $merged[$line.Substring(0, $eq)] = $line.Substring($eq + 1)
        }
    }
    return $merged
}

# Run every job in one category inside its long-lived container.
function Invoke-CategoryJobs {
    param(
        [string]$Category,
        [string[]]$Jobs,
        [string]$ResultsDir
    )

    $results = [ordered]@{}
    $anyFail = $false
    $anySkip = $false

    if (-not (Test-DockerAlive)) {
        Write-Status "Magenta" "Skipping category '$Category' -- Docker daemon is not reachable."
        foreach ($k in $Jobs) { $results[$k] = "SKIP" }
        $anySkip = $true
        Write-CategoryResults $ResultsDir $Category $results
        if ($anySkip) { exit 2 }
        return
    }

    try {
        Initialize-CategoryContainer $Category
    } catch {
        Write-Status "Red" "Failed to initialise container for '$Category': $_"
        foreach ($k in $Jobs) { $results[$k] = "SKIP" }
        Write-CategoryResults $ResultsDir $Category $results
        exit 2
    }

    foreach ($k in $Jobs) {
        Write-Status "Yellow" "----------------------------------------"
        Write-Status "Yellow" "[$Category] Starting job: $k"
        Write-Status "Yellow" "----------------------------------------"
        if (-not (Test-DockerAlive)) {
            Write-Status "Magenta" "Skipping $k -- Docker daemon went away mid-run."
            $results[$k] = "SKIP"
            $anySkip = $true
            continue
        }
        try {
            Invoke-JobInContainer $k
            Write-Status "Green" "Job $k completed successfully"
            $results[$k] = "PASS"
        } catch {
            if (-not (Test-DockerAlive)) {
                Write-Status "Magenta" "Job $k aborted -- Docker daemon went away mid-run."
                $results[$k] = "SKIP"
                $anySkip = $true
            } else {
                Write-Status "Red" "Job $k failed: $_"
                $results[$k] = "FAIL"
                $anyFail = $true
            }
        }
    }

    Remove-CategoryContainer $Category
    Write-CategoryResults $ResultsDir $Category $results

    if ($anyFail) { exit 1 }
    if ($anySkip) { exit 2 }
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

function Show-JobList {
    Write-Host "Available jobs:"
    Write-Host "  misc (run in container '$CONTAINER_MISC'):"
    foreach ($k in $JOBS_MISC) { Write-Host "    - $k" }
    Write-Host "  tests (run in container '$CONTAINER_TESTS'):"
    foreach ($k in $JOBS_TESTS) { Write-Host "    - $k" }
}

if ($List) {
    Show-JobList
    exit 0
}

Test-DockerRunning

if ($CategoryOnly) {
    if ([string]::IsNullOrWhiteSpace($ResultsDir)) {
        Write-Status "Red" "Error: -ResultsDir is required with -CategoryOnly"
        exit 1
    }
    New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
    Invoke-CategoryJobs $CategoryOnly (Get-JobsForCategory $CategoryOnly) $ResultsDir
    exit $LASTEXITCODE
}

if ([string]::IsNullOrWhiteSpace($JobName)) {
    Write-Status "Green" @"
Running all CI jobs in 2 containers (in parallel):
  '$CONTAINER_MISC'  — fmt, check, clippy, audit, deny, docs, msrv, features, cross-aarch64, reproducible-build
  '$CONTAINER_TESTS' — test, test-features, fips, miri, coverage, fuzz-smoke
"@

    $resultDir = Join-Path $env:TEMP ("craton-ci-{0}" -f [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $resultDir -Force | Out-Null

    $psExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) {
        (Get-Command pwsh).Source
    } else {
        (Get-Command powershell).Source
    }
    $self = $PSCommandPath
    $commonArgs = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", $self,
        "-ResultsDir", $resultDir
    )

    try {
        $pMisc = Start-Process -FilePath $psExe -ArgumentList ($commonArgs + @("-CategoryOnly", "misc")) -PassThru -NoNewWindow
        $pTests = Start-Process -FilePath $psExe -ArgumentList ($commonArgs + @("-CategoryOnly", "tests")) -PassThru -NoNewWindow
        Wait-Process -InputObject @($pMisc, $pTests)

        $results = Read-CategoryResults $resultDir
        $anyFail = ($results.Values -contains "FAIL")
        $anySkip = ($results.Values -contains "SKIP")

        Write-Status "Yellow" "========================================"
        Write-Status "Yellow" "CI suite summary"
        Write-Status "Yellow" "========================================"
        foreach ($k in $ALL_JOBS) {
            $status = if ($results.Contains($k)) { $results[$k] } else { "SKIP" }
            $color = switch ($status) {
                "PASS" { "Green" }
                "FAIL" { "Red" }
                "SKIP" { "Magenta" }
                default { "Yellow" }
            }
            Write-Status $color ("  {0,-22} {1}" -f $k, $status)
            if ($status -eq "SKIP" -and -not $results.Contains($k)) { $anySkip = $true }
        }

        if ($pMisc.ExitCode -eq 1 -or $pTests.ExitCode -eq 1) { $anyFail = $true }
        if ($pMisc.ExitCode -eq 2 -or $pTests.ExitCode -eq 2) { $anySkip = $true }

        if ($anyFail) {
            Write-Status "Red" "One or more jobs failed."
            exit 1
        } elseif ($anySkip) {
            $skipped = @($results.Values | Where-Object { $_ -eq "SKIP" }).Count
            Write-Status "Magenta" "$skipped job(s) skipped (Docker daemon unreachable or category failed to start)."
            exit 2
        } else {
            Write-Status "Green" "All jobs completed successfully!"
        }
    } finally {
        Remove-CategoryContainer "misc"
        Remove-CategoryContainer "tests"
        Remove-Item -LiteralPath $resultDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    if ($ALL_JOBS -contains $JobName) {
        Invoke-StandaloneJob $JobName
        Write-Status "Green" "Job $JobName completed successfully!"
    } else {
        Write-Status "Red" "Error: Unknown job '$JobName'"
        Write-Host ""
        Show-JobList
        exit 1
    }
}
