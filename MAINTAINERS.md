# Maintainers

This document lists the individuals and teams responsible for reviewing and merging changes to `craton-hsm-enterprise`. The authoritative CODEOWNERS rules live in [.github/CODEOWNERS](.github/CODEOWNERS); this file explains intent, review SLAs, and how maintainership is granted.

Project-level governance — sponsorship, decision model, release authority, and how new maintainers are voted in — is documented separately in [GOVERNANCE.md](GOVERNANCE.md).

## Project Owner

| Team | GitHub Handle | Scope |
|------|---------------|-------|
| Core Team | `@craton-co/core-team` | All paths; default reviewer on every PR |

The core team holds write access, dispatches releases, and owns the architectural direction of the workspace.

## Security-Sensitive Paths

Changes under the following paths **must** be reviewed by `@craton-co/security` in addition to the core team. These are paths where a bug has a direct path to key compromise, auth bypass, or FIPS non-compliance.

| Path | Reason for Security Review |
|------|-----------------------------|
| `craton-hsm-auth/` | RBAC, LDAP, OIDC, certificate auth, dual-control, MFA, tenant isolation |
| `craton-hsm-certified/` | FIPS certification tooling, ACVP/CAVP vectors, binary integrity |
| `craton-hsm-awslc/` | FIPS-validated crypto backend; any change affects the FIPS boundary |
| `craton-hsm-openssl/` | Non-FIPS crypto backend with parallel algorithm coverage |
| `craton-hsm-pkcs11/` | PKCS#11 passthrough; session, token, and PIN handling |

`.github/` changes (workflows, templates, actions) require core-team review to preserve supply-chain controls.

A PR touching any of the above paths cannot be merged until **both** teams have approved. This matches the `CODEOWNERS` entries and is enforced by branch protection.

## Review SLA

| PR Class | Initial Response | Decision Target |
|----------|------------------|-----------------|
| Security fix (CVE, embargoed) | 1 business day | 3 business days |
| Bug fix (regression) | 2 business days | 5 business days |
| Feature / enhancement | 3 business days | 5 business days |
| Documentation only | 3 business days | 5 business days |
| Dependency bump (`cargo update`) | 3 business days | 5 business days |

"Business day" is Monday–Friday excluding US federal holidays. If no maintainer has responded within SLA, the PR author may escalate by `@`-mentioning `@craton-co/core-team` on the PR or emailing `engineering@craton.io`.

Security-embargoed changes are coordinated off-GitHub via `security@craton.com.ar`; see [SECURITY.md](SECURITY.md).

## Decision Authority

- **Merge**: requires at least one core-team approval plus any applicable CODEOWNERS approval. All required status checks must pass.
- **Revert**: any core-team member may revert a merged PR within 72 hours if regression is confirmed; the revert is then treated as a normal PR.
- **Architectural changes** (new crate, public trait signature change, MSRV bump, dependency with non-trivial transitive surface): require two core-team approvals and a linked ROADMAP/ADR entry.
- **FIPS boundary changes**: require security-team approval regardless of path touched.
- **Tie-breaking**: unresolved disagreement after 10 business days is escalated to the project lead, currently staffed by the core team rotation.

## Release Approval

Release cutting is restricted to the core team. A release requires:

1. CHANGELOG entry under a dated version heading.
2. All CI jobs green on the release commit.
3. `cargo audit` clean or documented advisory waivers.
4. Security-team sign-off if any crate listed under "Security-Sensitive Paths" was modified since the previous tag.
5. Tag signed with a core-team GPG key and pushed to `origin`.

The release workflow is defined in `.github/workflows/release.yml`.

## Becoming a Maintainer

Maintainership is granted based on sustained, high-quality contribution. Typical criteria:

- At least 10 merged non-trivial PRs across at least two crates, over a minimum of six months.
- Demonstrated review activity on others' PRs with constructive, technically sound feedback.
- Familiarity with the FIPS boundary, the Raft/KMIP/auth threat model, and the BSL-1.1 licensing constraints.
- Agreement to the Code of Conduct and the DCO sign-off requirement documented in [CONTRIBUTING.md](CONTRIBUTING.md).

Nomination process:

1. An existing core-team member opens a private discussion nominating the candidate.
2. The core team holds lazy consensus for 10 business days; any objection pauses the process pending resolution.
3. On approval, the candidate is added to `@craton-co/core-team` and granted the appropriate repository permissions.
4. Security-team membership is a separate, stricter process run by Craton Software Company internally; it is not available through community contribution alone.

Maintainers may voluntarily step down at any time by opening a PR removing themselves from this file and `CODEOWNERS`.

## Inactive Maintainer Policy

A maintainer inactive for 6 consecutive months (no merges, reviews, or issue triage) is moved to Emeritus. Reinstatement is handled the same way as a new nomination, without the 10-PR threshold.

## Emeritus Maintainers

_No emeritus maintainers yet._

## Release Process

Releases are cut from `main` by a core-team member. Patch releases (0.1.x
→ 0.1.x+1) may skip the release-branch step for low-risk fixes; minor and
major releases always use a release branch.

1. **Cut the release branch** from a green `main`:
   `git switch -c release/0.1.<N>`.
2. **Update `CHANGELOG.md`**: move entries from `## [Unreleased]` into a
   new dated version heading (`## [0.1.<N>] - YYYY-MM-DD`); leave
   `[Unreleased]` empty; update the compare-URL footer links.
3. **Verify CI** on the release branch: `cargo fmt --check`, `clippy -D
   warnings`, `test --workspace`, `audit`, `deny check`, feature matrix
   — all green. Re-run locally per [BUILDING.md](BUILDING.md#running-ci-locally).
4. **Bump workspace version** in the root `Cargo.toml` `[workspace.package]`
   block; regenerate `Cargo.lock`.
5. **Security sign-off** if any path under "Security-Sensitive Paths"
   changed since the previous tag.
6. **Open a release PR** against `main`, titled `release: 0.1.<N>`.
   Two core-team approvals required.
7. **Merge, then tag the merge commit** with an annotated,
   GPG-signed tag: `git tag -s v0.1.<N> -m "Craton HSM Enterprise 0.1.<N>"`.
   Push with `git push origin v0.1.<N>`.
8. **The release workflow** (`.github/workflows/release.yml`) runs on
   the tag: builds release artefacts, Syft SBOMs (SPDX + CycloneDX),
   cosign keyless signatures, and SLSA build provenance. Verify the
   workflow succeeded; inspect artefact signatures with
   `cosign verify-blob` per [SECURITY.md](SECURITY.md#release-artifact-integrity).
9. **Publish** the GitHub Release page with the CHANGELOG slice as
   release notes; attach the signed artefacts.
10. **Announce** via the usual channels; notify commercial-support
    customers per their contracts.

Hotfix releases (`0.1.<N>.<hotfix>`) follow the same flow from a
`hotfix/` branch cut off the previous tag rather than `main`.

## Backport Policy

We ship only from the latest `0.1.x` by default. Backports are handled
on these rules:

| Class | Eligible Branches | SLA Target |
|-------|-------------------|------------|
| Critical security fix (CVSS ≥ 9.0, active exploit or trivial-to-exploit) | All supported branches plus the most recent EOL'd minor in its 12-month maintenance window | Patch released within **7 days** of embargo lift |
| High security fix (CVSS 7.0–8.9) | Latest `0.1.x` plus the previous minor if still in maintenance | Patch released within **14 days** |
| Medium / low security fix | Latest `0.1.x` only | Bundled into the next scheduled patch release |
| Non-security bug fix | Latest `0.1.x` only (community); older minors under commercial contract | Bundled into the next scheduled patch release |
| Feature | Never backported; ships on `main` only | N/A |

Community bug fix backports to superseded minors are available only
under a commercial support contract (see [SUPPORT.md](SUPPORT.md)).
Security backports to EOL'd minors are not guaranteed outside the
12-month maintenance window, with the narrow critical-severity
exception above.

## Dependency Updates

Authority to merge a dependency update depends on the change class.

| Change Class | Example | Authority | Notes |
|--------------|---------|-----------|-------|
| Patch (`x.y.z` → `x.y.z+1`) | `serde 1.0.200 → 1.0.201` | One core-team approval; no SemVer review required | `cargo audit` must be green. |
| Minor (`x.y.z` → `x.y+1.0`) | `tokio 1.36 → 1.37` | One core-team approval plus CHANGELOG entry | Run the feature matrix in CI; verify no MSRV regression. |
| Major (`x.0.0` → `y.0.0`) | `rustls 0.22 → 0.23` | Two core-team approvals; security-team approval if the dep is in a security-sensitive crate (per CODEOWNERS) | Write a migration note if the change is user-visible; update lockfile and re-benchmark if it affects crypto paths. |
| MSRV bump | `1.75 → 1.80` | Two core-team approvals; announced in CHANGELOG as a **breaking change** | Requires a minor-version bump of this workspace. |

`cargo update` PRs (the "dependabot-style" weekly sweep) group patch
bumps and are reviewed as a single unit; any dep in that PR that is
actually a minor or major bump is split off into its own PR.

## Revert Policy

When a regression is confirmed on `main`, choose revert vs. fix-forward
deliberately:

- **Prefer revert** when:
  - The defect is user-visible (panic, data loss, auth bypass, FIPS
    violation).
  - The fix is not obvious within the revert SLA (see below).
  - The offending PR is still within 72 hours of merge.
  - The PR introduced a new public API whose design is questioned.
- **Prefer fix-forward** when:
  - The defect is internal (flaky test, CI-only, docs typo).
  - A small, well-understood patch is already in hand.
  - Reverting would cascade across multiple follow-on commits.
  - The offending PR shipped in a released tag (revert on `main` would
    diverge release history; cut a hotfix instead).

**Revert SLA**: any core-team member may revert within 72 hours of
merge without additional approval. After 72 hours a revert is a normal
PR requiring CODEOWNERS review. Reverts must preserve the original
commit's SHA in the revert message for traceability
(`This reverts commit <sha>.`).

Security-sensitive reverts (touching a crate under "Security-Sensitive
Paths") always require security-team approval regardless of the 72-hour
window.

## Contact

- General maintainer questions: `engineering@craton.io`
- Security (private): `security@craton.com.ar` (PGP key at `.well-known/security-key.asc` in this repository — the single authoritative source; see [SECURITY.md](SECURITY.md))
- Commercial licensing / BSL exceptions: `license@craton.com.ar`
