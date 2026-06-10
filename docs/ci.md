# CI/CD pipelines

Five GitHub Actions workflows plus Dependabot and GitHub **default-setup
CodeQL**. All of them follow the same hardening conventions (see
[below](#hardening-conventions)).

## Overview

| Workflow | Triggers | What it does | Red means |
|---|---|---|---|
| `build.yml` | push to `main`, every PR, manual | **lint** job (`cargo fmt --check`, `cargo clippy -D warnings`) + `cargo build --release --locked` + `cargo test --release --locked` on Linux **and** Windows; uploads the binaries as artifacts | the code doesn't compile, tests fail on at least one platform, or fmt/clippy is dirty |
| `security.yml` | push to `main`, every PR, weekly (Mon 06:37 UTC), manual | three independent jobs: `cargo-audit` (RUSTSEC advisories), `cargo-deny` (advisories + licenses + bans + sources policy from `deny.toml`), `opengrep` SAST | a dependency has a known vulnerability / policy violation, or SAST flagged the diff |
| CodeQL (default setup) | every PR, push to `main` | CodeQL analysis (rust + actions), managed by GitHub — no workflow file. The old advanced `codeql.yml` was removed: default setup **rejects** SARIF from advanced configs, so the two cannot coexist | a code-scanning finding |
| `scorecard.yml` | push to `main`, weekly (Mon 05:19 UTC), branch-protection changes, manual | OpenSSF Scorecard posture score | repo hygiene regressed. Requires `ossf/scorecard-action@*` in the repo's Actions allowlist |
| `trivy.yml` | push to `main`, every PR, weekly (Sat 18:33 UTC), manual | Trivy **filesystem** scan: dependency vulns, secrets, IaC/workflow misconfig → SARIF to code scanning (this repo ships binaries, not images — there is no Dockerfile to scan) | a CRITICAL/HIGH/MEDIUM finding in the tree |
| `release.yml` | tag `v*` | build → checksum → SLSA provenance attestation → Sigstore keyless signing → SPDX SBOM → GitHub release | the release did not publish; never ship artifacts from a red run |

Dependabot (`.github/dependabot.yml`): weekly grouped update PRs for **cargo**
(all crates in one PR) and **github-actions** (all action pins in one PR),
max 10 open PRs. These PRs land in the same CI gauntlet as any other change.

## What runs when

- **Every PR:** lint (fmt+clippy), build+test (both OSes), cargo-audit,
  cargo-deny, opengrep, CodeQL (default setup). This is the merge gate.
- **Push to `main`:** the same set re-runs against the merged tree.
- **Weekly:** security re-runs on a schedule so *new* advisories against
  *unchanged* code still surface; Scorecard re-scores the repo.
- **Tag `v*`:** the release pipeline (below).

## Release pipeline anatomy

`release.yml`, on pushing a tag matching `v*`:

1. **build** (matrix: `ubuntu-latest` → `sfos-rs-linux-x86_64`,
   `windows-latest` → `sfos-rs-windows-x86_64.exe`):
   - `cargo build --release --locked`
   - stage the binary under its release asset name and write a
     `<asset>.sha256` checksum
   - **attest build provenance** (`actions/attest-build-provenance`) — a
     SLSA attestation binding the artifact digest to this repo, workflow,
     and commit, signed via GitHub OIDC; the bundle is also staged as a
     release asset (`<asset>.intoto.jsonl`)
   - **sign** with `cosign sign-blob --yes --bundle <asset>.cosign.bundle`
     (Sigstore keyless: the signing identity is the workflow itself, recorded
     in the public Rekor transparency log)
2. **sbom:** generates an SPDX SBOM for the dependency tree
   (`cargo sbom`, version-pinned install) named
   `sfos-rs-<tag>.spdx.json`.
3. **publish:** downloads all staged artifacts and creates the GitHub
   release with `gh release create --generate-notes`.

Per-job permissions: the build job has `contents: read` plus
`id-token: write`/`attestations: write` (for OIDC signing); only the publish
job has `contents: write`. There are **no long-lived signing keys anywhere**
— compromise of a maintainer laptop cannot forge a release signature, only a
compromised *workflow run* could (see
[supply-chain.md](supply-chain.md#scenario-ci-compromise)).

Verification commands for consumers are in
[SECURITY.md](../SECURITY.md#verifying-a-downloaded-release-binary).

## Hardening conventions

These are deliberate and must survive refactors — review any workflow PR
against this list:

1. **Actions pinned to commit SHAs** (with a `# vX.Y.Z` comment), never to
   tags or branches. A hijacked upstream tag cannot change what we run.
   Dependabot bumps the SHAs.
2. **Least-privilege `permissions:`** — top-level `contents: read`
   everywhere; jobs that need more (SARIF upload, OIDC token, release
   creation) request it per-job.
3. **`persist-credentials: false`** on every checkout — workflow steps never
   inherit a writable repo token.
4. **`--locked` on every cargo invocation** — CI builds exactly what
   `Cargo.lock` pins.
5. **Third-party tools are pinned** — opengrep, trivy, and cosign are
   downloaded at pinned versions and verified against hardcoded SHA-256s
   before they run; `cargo install`s in workflows (cargo-deny, cargo-audit,
   cargo-sbom) pin an exact `--version` plus `--locked`. Apply the same
   pattern to any future tool.
6. **Actions allowlist** — the repository's Actions policy permits
   GitHub-owned actions only (plus explicit allowlist entries; currently
   `ossf/scorecard-action@*` is the only third-party action needed) and
   enforces SHA pinning at the platform level. Prefer the checksum-verified
   binary pattern over adding allowlist entries.
6. **Forked-PR safety** — no workflow uses `pull_request_target` or exposes
   secrets to PR builds.

## Responding to failures

| Failure | Response |
|---|---|
| `cargo-audit` / `cargo-deny` advisory | triage per [maintaining.md](maintaining.md#handling-a-rustsec-advisory) — usually a Dependabot bump fixes it; never blanket-ignore |
| `cargo-deny` license/source failure | a new dep introduced a non-allowlisted license or a non-crates.io source; reject or justify in `deny.toml` with a comment |
| opengrep / CodeQL finding | treat as a review comment: fix or document a false-positive determination in the PR |
| build red on one OS only | platform regression — reproduce with the same target before merging anything |
| release pipeline red | fix and re-tag; never hand-upload artifacts to a release (they would lack provenance + signature, and that asymmetry is what [incident-response.md](incident-response.md#scenario-2--compromised-or-suspect-release-artifact) treats as a compromise indicator) |
