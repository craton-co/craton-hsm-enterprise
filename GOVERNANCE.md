# Governance

This document describes how decisions are made in the
`craton-hsm-enterprise` project. It complements [MAINTAINERS.md](MAINTAINERS.md),
which lists the individual maintainers and the per-PR review SLAs; this file
covers project-level governance.

## Project Sponsor

The project is sponsored and stewarded by **Craton Software Company** Craton Software Company owns
the trademark, the BSL 1.1 license grant, and the release signing keys. All
contributor License/DCO sign-off agreements flow through Craton Software Company

Sponsorship does not grant veto over technical decisions outside of the
scopes enumerated below (licensing, FIPS boundary, security-embargoed
disclosures).

## Decision Model

Day-to-day technical decisions are made by **lazy consensus** among the
maintainers listed in [MAINTAINERS.md](MAINTAINERS.md):

- A proposal is raised as a GitHub issue, PR, or RFC document.
- Maintainers have five business days to object.
- If there are no substantive objections, the proposal is considered
  accepted.
- If there are objections, the maintainers seek consensus through
  discussion. Where consensus cannot be reached within ten business days,
  the dispute is escalated (see "Tie-breaking" below).

## Tie-breaking

When maintainers cannot reach consensus:

- **General technical disputes** are decided by the core-team rotation lead
  (the "project lead"), as documented in MAINTAINERS.md.
- **Security-sensitive disputes** — anything touching the crypto boundary,
  FIPS scope, auth surface, or signed-release process — are decided by the
  Craton Software Company security team (`security@craton.com.ar`), which holds final
  authority on security matters regardless of maintainer consensus.
- **Licensing disputes** (BSL scope, commercial-use questions) are decided
  by Craton Software Company legal (`license@craton.com.ar`).

## Release Authority

Cutting and signing releases is reserved to the core team. The full release
procedure — including tag signing, SBOM generation, SLSA provenance, and
Security-team sign-off for changes to security-sensitive paths — is
specified in [MAINTAINERS.md § Release Process](MAINTAINERS.md#release-process).

## Adding New Maintainers

New maintainers are admitted by **nomination plus a 2/3 supermajority vote
of existing maintainers**, beyond the threshold criteria documented in
[MAINTAINERS.md § Becoming a Maintainer](MAINTAINERS.md#becoming-a-maintainer).

- Nomination: any existing core-team member may nominate a candidate by
  opening a private discussion.
- Voting: the nomination stays open for 10 business days. Each existing
  core-team member has one vote (yes / no / abstain). Abstentions do not
  count toward the 2/3 threshold.
- Security-team membership is a stricter, internal Craton Software Company process and
  is not granted through this vote.
- Removing a maintainer follows the same 2/3 vote, except that a
  maintainer may voluntarily step down at any time without a vote.

## Conflict Resolution

Conflicts between contributors (interpersonal, not technical) are handled
under the [Code of Conduct](CODE_OF_CONDUCT.md). Enforcement actions
(warnings, temporary bans, permanent bans) require two core-team
approvals; the affected party may appeal to `engineering@craton.io`.

Conflicts between contributors and Craton Software Company on licensing or commercial
terms are directed to `license@craton.com.ar` and are outside the scope of
community governance.

## Changes to this Document

Changes to `GOVERNANCE.md` require a 2/3 supermajority vote of existing
maintainers, opened as a PR with a 10-business-day discussion window. The
Craton Software Company security team holds veto authority over changes that would
weaken the security-review requirements, and Craton Software Company legal holds veto
authority over changes that alter licensing governance.
