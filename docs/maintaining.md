# Maintainer guide

Process documentation for whoever holds the keys. Contributor-facing
conventions live in [CONTRIBUTING.md](../CONTRIBUTING.md); incident handling
in [incident-response.md](incident-response.md).

## Responsibilities

- Review and merge PRs (CI green is a precondition, not a substitute for
  reading the diff — especially `Cargo.lock` and workflow changes).
- Keep dependencies current and triage advisories (below).
- Cut releases (below) and answer security reports within the
  [SECURITY.md](../SECURITY.md) SLA (acknowledge ≤ 3 business days).
- Keep the docs truthful — particularly the *Validation status* claims in
  [docs/README.md](README.md): nothing is described as live-validated unless
  it was, and the docs say against what.

## Dependency management

Dependabot opens grouped weekly PRs (one for crates, one for action pins).
Review discipline:

1. CI must be green (build+test both OSes, audit, deny, SAST).
2. Read the `Cargo.lock` diff — every changed crate, not just the headline
   ones. Unexpected new transitive deps are a stop-and-look.
3. For non-trivial version jumps of security-relevant crates (`reqwest`,
   `rustls`-family, `quick-xml`), skim the upstream changelog/release notes
   before merging.
4. Do not let dependency PRs rot: a stale tree makes emergency bumps (when a
   RUSTSEC advisory lands) larger and riskier.

Policy is enforced by `deny.toml`: crates.io is the **only** allowed source,
wildcard versions are denied, yanked crates are denied, licenses outside the
allowlist fail CI.

## Handling a RUSTSEC advisory

When `cargo-audit`/`cargo-deny` go red (PR, push, or the weekly schedule):

1. **Read the advisory.** Which crate/versions, what's the vulnerable code
   path, is there a fixed version?
2. **Determine reachability.** Is the vulnerable functionality used by
   sfos-rs at all? (e.g. an advisory in an HTTP/2 path is unreachable from a
   blocking client that never enables it.)
3. **Fix forward when a fixed version exists**: `cargo update -p <crate>`
   (or take the Dependabot PR), commit the lockfile, verify CI.
4. **If no fix exists**: decide patch/replace/wait. Only as a last resort
   add the advisory ID to `ignore` in `deny.toml` — **always with a comment**
   stating the reachability analysis and a revisit condition. An ignore
   without justification is a finding in itself.
5. If the vulnerability was reachable in a released binary, treat it as an
   incident: see [incident-response.md](incident-response.md#scenario-1--vulnerability-in-sfos-rs)
   for the advisory/release steps.

## Cutting a release

Preflight on `main`:

```bash
cargo test --locked && cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
git log <last-tag>..HEAD --oneline     # know what you're shipping
```

1. Bump `version` in `Cargo.toml` (`[workspace.package]`) — the two crates
   inherit it. Keep `sfos-cli`'s `sfos-sdk` path-dep version in sync.
   Commit (`chore: release v0.x.y`).
2. Tag and push:

   ```bash
   git tag -a v0.x.y -m "v0.x.y"
   git push origin main v0.x.y
   ```

3. `release.yml` does the rest (build → checksum → SLSA attestation →
   cosign signing → GitHub release). See
   [ci.md](ci.md#release-pipeline-anatomy).
4. **Post-release verification** — run the consumer steps yourself on a
   downloaded artifact:

   ```bash
   sha256sum -c sfos-rs-linux-x86_64.sha256
   gh attestation verify sfos-rs-linux-x86_64 --repo yokoszn/sfos-rs
   cosign verify-blob --bundle sfos-rs-linux-x86_64.cosign.bundle \
     --certificate-identity-regexp 'https://github.com/yokoszn/sfos-rs/.github/workflows/release.yml@.*' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     sfos-rs-linux-x86_64
   ```

   A release whose artifacts don't verify is pulled immediately
   ([incident-response.md](incident-response.md#scenario-2--compromised-or-suspect-release-artifact)).

Never hand-upload or replace release assets: pipeline-built artifacts are
the only ones that carry provenance, and consumers are told to treat
unattested assets as compromise indicators.

## Entity-registry stewardship

Registry tags (`crates/sfos-sdk/src/registry.rs`) are best-effort from the
SFOS 21.5 API reference. `export_all` reports per-entity success/failure
against a live box — that output is the validation feedback loop. When a tag
is confirmed wrong against real hardware, fix the tag (don't add a
duplicate) and note the firmware version it was validated on in the commit
message.

## Account & repo security

- 2FA with hardware keys on the GitHub account(s); no SMS fallback.
- No long-lived personal access tokens with `repo` scope lying around in CI
  or on disk; workflows use the ephemeral `GITHUB_TOKEN` and OIDC only.
- Workflow changes get the same scrutiny as code: check action SHA pins,
  `permissions:` blocks, and that `persist-credentials: false` survived
  ([ci.md](ci.md#hardening-conventions)).
- When the repo goes public: enable branch protection on `main` (PRs +
  required checks), which also un-skips CodeQL and Scorecard.

## Adding / removing maintainers

Onboarding: 2FA verified → read this file, [SECURITY.md](../SECURITY.md),
[incident-response.md](incident-response.md) → start with PR review only,
then merge, then release rights.

Offboarding (voluntary or not): remove repo access, rotate any shared
secrets (there should be none — verify), review their recent pushes/releases
as a precaution, and update SECURITY.md contacts. If offboarding is due to a
suspected compromise, run the full
[maintainer-compromise response](incident-response.md#scenario-3--maintainer-account-compromise)
instead.
