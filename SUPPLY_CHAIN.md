# Supply-Chain Security & Release Integrity

This document describes how Craton HSM Enterprise is built, signed, and
verified end-to-end. It is the canonical reference for:

- Verifying a downloaded release artifact.
- Understanding the SLSA build provenance that we publish.
- Inspecting the SBOM (software bill of materials) for a release.
- Reviewing the PGP key-ceremony runbook for `security@craton.com.ar`.
- Knowing what to expect when reporting a suspected supply-chain compromise.

All concrete commands in this document are pinned to the release workflow
at [`.github/workflows/release.yml`](.github/workflows/release.yml) — if the
workflow changes, this file must be updated in the same commit.

---

## 1. Release artefact inventory

Every tagged release of `craton-hsm-enterprise` publishes the following
artefacts on the GitHub release page:

| Artefact                                | Purpose                                                 |
|-----------------------------------------|---------------------------------------------------------|
| `craton-hsm-<version>.tar.gz`           | Reproducible source tarball (what `cargo publish` sees) |
| `craton-hsm-<version>.tar.gz.sig`       | Cosign keyless signature over the tarball               |
| `craton-hsm-<version>.tar.gz.pem`       | Sigstore ephemeral certificate (binds signature→OIDC)   |
| `craton-hsm-<version>.sbom.spdx.json`   | Syft-generated SBOM (SPDX 2.3)                          |
| `craton-hsm-<version>.sbom.cdx.json`    | Syft-generated SBOM (CycloneDX 1.5)                     |
| `craton-hsm-<version>.sbom.spdx.json.sig` | Cosign signature over the SPDX SBOM                    |
| `craton-hsm-<version>.intoto.jsonl`     | SLSA v1.0 build provenance attestation                  |
| `SHA256SUMS`                            | Text file of SHA-256 digests over the above             |
| `SHA256SUMS.sig`                        | Cosign signature over `SHA256SUMS`                      |

Everything above is produced by a single GitHub Actions workflow run on a
tag push. That workflow:

- Runs with `permissions: contents: read, id-token: write, attestations: write`
  (least privilege; it cannot overwrite repository contents).
- Re-runs the entire CI matrix (`cargo test --workspace`, clippy, fmt,
  audit, deny) before any artefact is produced.
- Generates the tarball from a clean `git archive` so the artefact is
  byte-for-byte reproducible from any Git checkout at the release tag.
- Signs using [Sigstore cosign](https://github.com/sigstore/cosign) in
  keyless mode (OIDC identity from GitHub Actions), recording every
  signature in the public [Rekor](https://docs.sigstore.dev/logging/overview)
  transparency log.
- Generates SBOMs with [Syft](https://github.com/anchore/syft) in both
  SPDX 2.3 and CycloneDX 1.5 formats.
- Emits a SLSA v1.0 provenance attestation using GitHub's
  `actions/attest-build-provenance`, bound to the source tarball by digest.

---

## 2. Verifying a release — minimum steps

You will need [`cosign`](https://github.com/sigstore/cosign)
(≥ v2.2) and [`gh`](https://cli.github.com/) (≥ v2.40). All commands
run against the public Sigstore trust root by default; no key material
needs to be installed.

### 2.1 Verify the source tarball signature

```bash
# From the release page, download:
#   craton-hsm-<version>.tar.gz
#   craton-hsm-<version>.tar.gz.sig
#   craton-hsm-<version>.tar.gz.pem

cosign verify-blob \
  --certificate         craton-hsm-<version>.tar.gz.pem \
  --signature           craton-hsm-<version>.tar.gz.sig \
  --certificate-identity-regexp \
      '^https://github\.com/craton-co/craton-hsm-enterprise/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer \
      'https://token.actions.githubusercontent.com' \
  craton-hsm-<version>.tar.gz
```

A successful verification prints `Verified OK`. The identity regexp pins
the signature to the release workflow at a tag ref; a signature produced
by any other workflow, branch, or identity is rejected.

### 2.2 Verify the SLSA provenance

```bash
gh attestation verify craton-hsm-<version>.tar.gz \
  --owner craton-co
```

This cross-checks the attestation chain against GitHub's attestation
endpoint. A valid provenance binds the artefact digest to a specific
commit SHA, workflow file, and runner — all of which you can inspect.

### 2.3 Verify the SBOM

```bash
cosign verify-blob \
  --certificate         craton-hsm-<version>.tar.gz.pem \
  --signature           craton-hsm-<version>.sbom.spdx.json.sig \
  --certificate-identity-regexp \
      '^https://github\.com/craton-co/craton-hsm-enterprise/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer \
      'https://token.actions.githubusercontent.com' \
  craton-hsm-<version>.sbom.spdx.json
```

Then inspect the SBOM contents to confirm you see only the dependencies
you expect — no injected or substituted package versions.

### 2.4 Cross-check with `SHA256SUMS`

```bash
cosign verify-blob \
  --certificate      craton-hsm-<version>.tar.gz.pem \
  --signature        SHA256SUMS.sig \
  --certificate-identity-regexp \
      '^https://github\.com/craton-co/craton-hsm-enterprise/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer \
      'https://token.actions.githubusercontent.com' \
  SHA256SUMS

sha256sum -c SHA256SUMS
```

If cosign verifies `SHA256SUMS` and `sha256sum -c` reports all files OK,
you have validated the entire release in a single step against a single
signed manifest.

---

## 3. SBOM format and contents

The SBOMs are generated from a clean checkout at the release tag, so they
represent the **source-level** dependency graph — not any particular
compiled binary. Each dependency is listed with:

- Package URL (`pkg:cargo/<name>@<version>`)
- SPDX license identifier
- Download location (crates.io index URL, for reproducibility)
- Checksum (where available from the crate registry)

The SBOMs do not (yet) include transitive Go dependencies for the
`craton-hsm-certified` FIPS build-scripts; those are documented separately
in `craton-hsm-certified/README.md` and are pinned via the release
workflow's `go.sum` file. Closing this gap is tracked in
[ROADMAP.md](ROADMAP.md).

---

## 4. Dependency policy

Dependencies are gated on three levels:

1. **License** — only `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`,
   `ISC`, `Unicode-DFS-2016`, `OpenSSL`, and our own `BUSL-1.1` workspace
   licence are permitted. Enforced by `cargo-deny` (see [`deny.toml`](deny.toml))
   on every CI run.
2. **Advisories** — `cargo audit` runs on every CI run and on a daily
   schedule. Open advisories against any transitive dependency block CI.
3. **Source** — only crates from the official crates.io index
   (`https://github.com/rust-lang/crates.io-index`) are permitted; arbitrary
   Git dependencies are denied.

Automated dependency updates are proposed by Dependabot (configuration
in [`.github/dependabot.yml`](.github/dependabot.yml)) and must pass the
same CI pipeline as human-authored PRs.

---

## 5. Security PGP-key ceremony

The PGP key for `security@craton.com.ar` is generated through an offline
ceremony. The high-level runbook is:

1. Two maintainers meet at an offline workstation with no persistent
   network connection (wifi disabled, cable unplugged).
2. A fresh `gpg --full-generate-key` produces an **RSA 4096, 365-day
   expiry** primary key with three subkeys (signing, encryption,
   authentication).
3. The primary key fingerprint is read aloud, written down on paper by
   both maintainers, and later cross-checked over an independent channel
   (voice call, in-person).
4. The armored public key is exported, the secret key is split via
   Shamir's Secret Sharing (3-of-5) across hardware tokens held by
   distinct maintainers, and the workstation is wiped before being
   reconnected to any network.
5. The armored public key is committed to this repository at
   `.well-known/security-key.asc` as a single, reviewable diff. The
   fingerprint is added to `SECURITY.md` and to the craton.io homepage
   footer in the same release.
6. Annual rotation follows the same procedure; the old key is kept for
   90 days in a `revocation-certificates/` directory after the new key
   is published, then revoked via the transparent log.

Until step 5 is complete for the initial key, `.well-known/security-key.asc`
contains a clearly-labelled placeholder so the path does not 404 and so
any future substitution is visible in `git log`.

---

## 6. Reporting a suspected supply-chain compromise

If you believe a published artefact, SBOM, signature, or provenance does
**not** match what you observe:

1. **Do not** open a public issue. Email `security@craton.com.ar` using the
   channels in [SECURITY.md](SECURITY.md).
2. Attach: the exact artefact filename(s), the SHA-256 you computed, the
   `cosign verify-blob` output (success or failure), and the release tag
   you were verifying against.
3. We will triage within 2 business days and, if the report is valid,
   issue a coordinated disclosure following the timeline in
   [SECURITY.md](SECURITY.md#responsible-disclosure-timeline). A
   compromised artefact is a Critical severity finding.
