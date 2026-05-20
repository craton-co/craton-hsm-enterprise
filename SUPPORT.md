# Support

This document explains how to get help with `craton-hsm-enterprise`, what the community support policy covers, and where commercial support is available. For vulnerability reports, see [SECURITY.md](SECURITY.md) instead.

## Supported Versions

| Version | Community Support | Security Fixes | Notes |
|---------|-------------------|----------------|-------|
| `0.1.x` (latest patch) | Yes | Yes | Only the most recent `0.1.x` release is supported |
| `0.1.x` (superseded) | No | No | Upgrade to the latest `0.1.x` |
| `0.0.x` / pre-release | No | No | Not released; do not use |

We ship security fixes against the latest `0.1.x` line only. Backports to older minor versions are available only under a commercial support contract.

## Where to Ask

| Question Type | Where | Response Expectation |
|---------------|-------|----------------------|
| Usage / how-to | [GitHub Discussions](https://github.com/craton-co/craton-hsm-enterprise/discussions) | Best-effort, community |
| Suspected bug | GitHub Issues (use `bug_report.yml`) | Triaged within 5 business days |
| Feature request | GitHub Issues (use `feature_request.yml`) | Triaged within 5 business days |
| Security vulnerability | `security@craton.com.ar` (PGP at `.well-known/security-key.asc` in this repository — see [SECURITY.md](SECURITY.md)) | 2 business days initial, 7 days assessment |
| Commercial / SLA | `support@craton.io` | Per contract |
| BSL licensing | `license@craton.com.ar` | Best-effort |

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for coordinated disclosure.

## Community Support (No SLA)

Community support through GitHub Issues and Discussions is provided on a best-effort basis by maintainers and contributors. There is **no guaranteed response time** and **no SLA**. The targets in the [MAINTAINERS.md](MAINTAINERS.md) review SLA apply to pull requests, not support questions.

What you can reasonably expect from the community channel:

- Triage of bug reports within about a week.
- Guidance on build, configuration, and documented features.
- Duplicate detection and cross-linking of related issues.

What is **not** covered:

- Debugging your deployment configuration, network, or third-party systems (LDAP, OIDC, PKCS#11 vendors).
- Feature development on your timeline.
- Integration assistance with proprietary HSMs or cloud services.
- Customer-specific patches or backports.

## Commercial Support

Craton Software Company offers commercial support contracts with defined SLAs, guaranteed response times, and named engineering contacts. Commercial support is also the path to:

- Backported security fixes on older minor versions.
- BSL-1.1 commercial-use licenses (required for competing HSM/KMS/FIPS-validated services — see [README.md](README.md#license)).
- Custom hardware vendor integration work.
- FIPS 140-3 submission engineering assistance (see [FIPS_CERTIFICATION_PLAN.md](FIPS_CERTIFICATION_PLAN.md)).
- Production incident response.

Contact `support@craton.io` or visit `https://craton.io/support` for available tiers and pricing.

## End-of-Life (EOL) Policy

A minor version is supported until approximately **12 months** after the next minor version supersedes it. For example, if `0.2.0` ships, `0.1.x` receives security fixes for 12 months from that release date, after which it is EOL.

| Phase | Duration | What You Get |
|-------|----------|--------------|
| Active | Until next minor ships | Bug fixes, security fixes, features |
| Maintenance | 12 months after supersession | Security fixes only |
| EOL | After maintenance window | No fixes; upgrade required |

EOL dates are announced in [CHANGELOG.md](CHANGELOG.md) and GitHub Releases at least 90 days in advance. Commercial support contracts may extend the maintenance window.

Per the Business Source License 1.1, each version auto-converts to Apache 2.0 four years after its release, independent of support status. EOL has no effect on the license change date.

## Filing a Good Bug Report

A well-formed bug report is the fastest route to a fix. Please include:

- **Crate and version** (e.g., `craton-hsm-auth 0.1.1`).
- **Exact cargo command** used (`cargo build -p craton-hsm-awslc --features fips`).
- **Rust toolchain** (`rustc --version`, `cargo --version`).
- **Platform** (OS, kernel, architecture, containerized?).
- **Feature flags** actually enabled.
- **Minimal reproducer**: the smallest Rust snippet, config file, or command that triggers the issue.
- **Expected vs actual behavior**.
- **Logs**: `RUST_LOG=debug` output where applicable. Redact secrets, PINs, and identifiers before posting.
- **Stack trace** for panics (set `RUST_BACKTRACE=1`).

For FIPS-related questions, first check whether the behavior is a documented FIPS restriction (SHA-1, prehashed signing, and Ed25519 in FIPS mode all return `MechanismInvalid` intentionally — see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)). AES-128 key generation is permitted in FIPS mode; AES-256 is recommended for new keys.

Do **not** attach:

- Cryptographic keys (even test keys).
- Production configuration files containing bind DNs, endpoints, or secrets.
- Customer data.

If reproduction requires sensitive material, open the issue with a redacted reproducer and provide the sensitive parts to `security@craton.com.ar` on request.

## Documentation Index

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | Overview and quick start |
| [BUILDING.md](BUILDING.md) | Build, features, cross-compilation |
| [DEPLOYMENT.md](DEPLOYMENT.md) | systemd, Docker, Kubernetes patterns |
| [OPERATIONS.md](OPERATIONS.md) | Runbooks: key rotation, CRL, cluster, backup |
| [HARDENING.md](HARDENING.md) | Production hardening checklist |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Symptom-indexed debugging guide |
| [COMPATIBILITY_MATRIX.md](COMPATIBILITY_MATRIX.md) | Supported OS, SDK, library versions |
