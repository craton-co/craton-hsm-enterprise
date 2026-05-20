# Contributing to craton-hsm-enterprise

Thank you for your interest in contributing. Please read this document before submitting issues or pull requests.

## License

By contributing, you agree that your contributions will be licensed under the [Business Source License 1.1](LICENSE-BSL). The change date is 2030-05-19, after which contributions relicense to Apache 2.0.

## Developer Certificate of Origin (DCO)

All commits must include a DCO sign-off:

```
Signed-off-by: Your Name <your@email.com>
```

Add it automatically with `git commit -s`. Commits without a sign-off will not be merged.

## Workflow

1. **Fork** the repository and create a branch from `main`.
2. **Write code** following the style guide below.
3. **Add tests** — new functionality requires tests; bug fixes require a regression test.
4. **Open a PR** against `main`. Fill out the PR template completely.
5. **Address review feedback** within a reasonable time or the PR may be closed.

### Branch Naming

Use one of the following prefixes followed by a short description:

| Prefix | Use for |
|--------|---------|
| `feat/` | New features (`feat/oidc-refresh-tokens`) |
| `fix/` | Bug fixes (`fix/crl-fail-closed`) |
| `sec/` | Security fixes (`sec/ttlv-size-limit`) |
| `perf/` | Performance improvements (`perf/raft-log-append`) |
| `docs/` | Documentation only (`docs/building-feature-flags`) |
| `chore/` | Tooling, CI, refactoring (`chore/ci-feature-matrix`) |

## Code Style

- Format with `rustfmt`: `cargo fmt --all`
- No clippy warnings: `cargo clippy --workspace -- -D warnings`
- No `#[allow(dead_code)]` or `#[allow(unused)]` without a comment explaining why

### Running CI Locally

Before opening a pull request, run the full CI pipeline locally:

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
```

For feature-gated code in `craton-hsm-auth`, also run:

```bash
# Certificate authentication
cargo test -p craton-hsm-auth --features cert-auth

# OpenID Connect authentication
cargo test -p craton-hsm-auth --features oidc-auth

# LDAP authentication
cargo test -p craton-hsm-auth --features ldap-auth
```

This ensures your changes will pass all CI checks before code review.

## Testing Requirements

- All existing tests must pass: `cargo test --workspace`
- New public APIs must have at least one test covering the happy path and one covering error conditions
- Security-sensitive code (auth, crypto, RBAC) requires tests for adversarial inputs
- Tests must not depend on external services unless gated behind a `#[cfg(feature = "integration")]` or similar

## Feature Flags

When adding a feature flag:
- Document it in the crate's `Cargo.toml` with a comment
- Add a CI job or extend an existing one to test the flag
- Update `BUILDING.md` with build instructions

## Review Gates & Branch Protection

The `main` branch is protected. Merges require:

- All CI jobs green (fmt, clippy, test matrix, audit, deny, MSRV, coverage).
- Approval from at least one owner listed in [`.github/CODEOWNERS`](.github/CODEOWNERS).
  Security-sensitive paths (auth, crypto backends, cluster transport, KMIP,
  certified/FIPS) require review from the security team in addition to a
  crate-area reviewer.
- DCO sign-off on every commit in the PR (enforced by
  [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

These rules are enforced by GitHub branch-protection settings, not by files
in the repository — maintainers are responsible for keeping them in sync
with `CODEOWNERS`. See [MAINTAINERS.md](MAINTAINERS.md) for the authoritative
operational policy.

## Changelog policy

Changelogs are maintained at workspace level in [CHANGELOG.md](CHANGELOG.md).
Per-crate `CHANGELOG.md` files are **not** used in this workspace — every
release-relevant change lands in the single workspace changelog so that
downstream consumers tracking `craton-hsm-enterprise` as a unit get one
canonical place to read it.

When contributing a crate-scoped change, add an entry under the
appropriate version section of the workspace `CHANGELOG.md`, prefixed
with the affected crate name (for example `craton-hsm-cng:` or
`craton-hsm-cluster:`). Workspace-wide or doc-only changes can be
recorded without a crate prefix. The PR template prompts you for the
changelog entry; reviewers will block merges that should have updated
the changelog but did not.

## Security Issues

Do **not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).

## Commercial Licensing

For commercial licensing inquiries, contact **license@craton.com.ar**.
