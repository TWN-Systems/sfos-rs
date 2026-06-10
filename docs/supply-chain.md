# Supply-chain security

What we defend against, the controls in place, and the response plan for
the two scenarios people actually worry about: a compromised upstream crate
and a compromised maintainer. Response procedures for live incidents are in
[incident-response.md](incident-response.md).

This matters more than usual here: sfos-rs is run with **firewall admin
credentials** against **security infrastructure**. A compromised build of
this tool is a compromised firewall estate.

## Threat model

| Threat | Vector |
|---|---|
| malicious dependency version | upstream crate account/repo compromise, malicious maintainer |
| typosquat / source substitution | a dep resolved from somewhere other than crates.io |
| known-vulnerable dependency | RUSTSEC advisory against a pinned version |
| malicious CI action | hijacked tag of a third-party GitHub Action |
| maintainer account takeover | phished/stolen credentials → malicious commits, tags, releases |
| forged release artifact | hand-uploaded or replaced release assets |
| consumer-side drift | users building different deps than we tested |

## Controls, mapped

| Control | Defends against |
|---|---|
| `Cargo.lock` committed + `--locked` on every build (CI and documented for users) | drift; silent version substitution — only lockfile-pinned versions are ever built |
| `deny.toml` `[sources]`: **crates.io only**, unknown registries/git denied | typosquat & source substitution |
| `deny.toml` `[bans]`: wildcard versions denied | accidental "latest" resolution |
| `cargo-audit` + `cargo-deny` advisories on every PR/push **and weekly** | known-vulnerable deps, including new advisories against unchanged code |
| Dependabot weekly **grouped** PRs | stale deps; one reviewable diff instead of ten auto-merges |
| 7-crate direct dependency tree, additions require justification ([CONTRIBUTING.md](../CONTRIBUTING.md)) | total exposure surface |
| Actions pinned to commit SHAs | hijacked upstream action tags |
| Least-privilege workflow `permissions:` + `persist-credentials: false` | blast radius of any compromised CI step |
| Third-party CI binaries checksum-verified (opengrep) | poisoned tool downloads |
| Keyless (OIDC) Sigstore signing + SLSA provenance + Rekor transparency log | forged releases; stolen-key signing (there are no keys to steal) |
| `.sha256` checksums per artifact | corrupted/tampered downloads |
| CodeQL + opengrep SAST, OpenSSF Scorecard (active when repo is public) | vulnerable first-party code; repo hygiene regressions |

## Scenario: compromised upstream crate

A version of a direct or transitive dependency is discovered to be malicious
or critically vulnerable.

**Why exposure is bounded:** builds are `--locked`, so the only versions
that ever entered any build or release are the ones recorded in
`Cargo.lock` history. Dependabot bumps are human-reviewed PRs, which gives a
natural delay-and-review window between an upstream release and it entering
the lockfile — the window in which most crate compromises are caught.

**Response:**

1. **Establish exposure precisely:**

   ```bash
   git log -p -- Cargo.lock | grep -B2 -A2 '<crate>'   # every version we ever pinned, with dates
   ```

   Cross-reference with release tags to know which **released binaries** (if
   any) contain the bad version.

2. **No exposure** (version never pinned): record the determination in an
   issue and move on.

3. **Exposed but unreleased:** pin away immediately —
   `cargo update -p <crate> --precise <good-version>` (or remove/replace the
   dependency), commit, let the full CI gauntlet re-run.

4. **Exposed in a release:** additionally treat as an artifact incident —
   advisory naming affected release versions and digests, fixed release
   under a new version
   ([incident-response.md](incident-response.md#scenario-5--upstream-crate-compromise)).

5. **If the fix must wait** (no good version exists): document the
   reachability analysis in `deny.toml`'s `ignore` with a comment and a
   revisit condition — never a bare ignore
   ([maintaining.md](maintaining.md#handling-a-rustsec-advisory)).

## Scenario: maintainer compromise

An attacker controls a maintainer account. What can they actually achieve,
given the controls?

| Attacker action | What limits it |
|---|---|
| push malicious commits | visible history; consumers pinning `rev` unaffected; PR-required branch protection (once public) forces a second surface |
| cut a malicious release | the pipeline will *sign* it — but provenance + Rekor bind the artifact to the exact workflow, repo, and **commit**, so the malicious source is permanently, publicly attributable and discoverable |
| hand-upload a doctored binary to a release | it has no attestation/cosign bundle; verification per [SECURITY.md](../SECURITY.md) fails loudly — this is why the docs tell consumers to always verify |
| edit workflows (exfiltrate, weaken) | workflow changes are diffable code; least-privilege tokens limit what a poisoned run can reach; no long-lived secrets exist to steal |
| force-push / rewrite history | audit log records it; Rekor entries for already-signed releases cannot be rewritten |

**Response:** the full checklist is
[incident-response.md Scenario 3](incident-response.md#scenario-3--maintainer-account-compromise)
— contain the account, bound the takeover window from the audit log, audit
every push/tag/release/workflow-change/setting in it, advisory even on a
clean audit.

**Prevention** (from [maintaining.md](maintaining.md#account--repo-security)):
hardware-key 2FA, no long-lived PATs, workflow edits reviewed like code,
branch protection once public.

## Scenario: CI compromise

Covered in [incident-response.md Scenario 4](incident-response.md#scenario-4--ci--workflow-compromise).
The design keeps this small: SHA-pinned actions, least-privilege ephemeral
tokens, no stored secrets, checksum-verified tool downloads. The release job
is the only high-value target, and everything it signs lands in a public
transparency log.

## If/when sfos-rs publishes to crates.io

Not yet done. When it happens:

- use crates.io **Trusted Publishing** (OIDC from the release workflow) —
  no API token to leak;
- publish from the same tagged, attested commit the binaries build from;
- enable 2FA-required publishing on the crate;
- document the crate-name → repo mapping in both directions (README badge,
  `repository` field) so typosquats are distinguishable.

## For consumers

- **Binaries:** always verify — checksum, `gh attestation verify`, `cosign
  verify-blob` ([SECURITY.md](../SECURITY.md#verifying-a-downloaded-release-binary)).
  Treat any release asset that fails verification, or lacks its
  `.cosign.bundle`/attestation, as hostile and tell us.
- **Source builds:** build at a tag with `--locked`; you get exactly the
  dependency set we tested and scanned.
- **SDK dependents:** pin `rev = "<commit>"` in your `Cargo.toml`, not a
  branch — immune to history rewrites and account takeovers alike.
- **Defense in depth:** run the tool from a host you'd trust with firewall
  admin credentials anyway, keep `SFOS_PASSWORD` out of CI logs, and review
  [safety.md](safety.md#credentials--transport).

## Residual risks (honest list)

- The transitive tree behind `reqwest`/`rustls` is far larger than our 7
  direct crates; we inherit its advisories via the same audit tooling but
  can't review every line.
- GitHub itself (Actions runners, OIDC issuer, release storage) is a trusted
  third party; Rekor's public log is the independent check on it.
- While the repo is private, CodeQL and Scorecard are skipped (platform
  limitation) — they activate when it goes public.
- The live HTTP path is not yet validated against real hardware
  ([README](README.md#validation-status)) — a correctness risk, not a
  supply-chain one, but listed because it bounds what "tested" means here.
