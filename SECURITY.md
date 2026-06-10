# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — use GitHub's *Security → Advisories →
Report a vulnerability* on this repository, or email <dev@clayatownsend.com>. Do not
open public issues for vulnerabilities. We aim to acknowledge within 3 business days
(committed maximum for an initial response: 14 days).

## Supported versions

Only the **latest release** receives security fixes; older releases reach
end-of-support the moment a newer release is published. Fixes ship as a new
release — assets on existing releases are never modified (a modified asset is
treated as a compromise indicator, see
[docs/incident-response.md](docs/incident-response.md)).

## Remediation targets

| Severity (CVSS-informed, judged per [docs/incident-response.md](docs/incident-response.md#severity-guide)) | Target |
|---|---|
| Critical | fix and release as fast as humanly possible; advisory immediately |
| High | fixed release within 14 days |
| Medium and below | fixed release within 60 days |

Dependency (SCA) findings: `cargo-audit`/`cargo-deny` **block CI**, so a
release cannot ship with a known un-triaged advisory; any waiver must carry a
written reachability justification in `deny.toml`
([docs/maintaining.md](docs/maintaining.md#handling-a-rustsec-advisory)).

## Supply-chain assurances

- **Build provenance** — release binaries carry SLSA build-provenance attestations.
- **Signatures** — release binaries are signed with Sigstore `cosign` (keyless OIDC);
  each artifact ships a `*.cosign.bundle` recorded in the Rekor transparency log.
- **Checksums** — each artifact ships a `.sha256`.
- **Dependencies** — `cargo-audit` (RUSTSEC) and `cargo-deny` (advisories, licenses,
  bans, sources) run in CI; Dependabot keeps crates and pinned actions current; GitHub
  vulnerability alerts and automated security fixes are enabled.
- **SAST** — `opengrep` scans on every push (results surfaced in code scanning).
- **CI hardening** — all GitHub Actions are pinned to commit SHAs and run with
  least-privilege `permissions:`; checkout uses `persist-credentials: false`.

## Verifying a downloaded release binary

```bash
# 1. checksum
sha256sum -c sfos-rs-linux-x86_64.sha256

# 2. build provenance (SLSA)
gh attestation verify sfos-rs-linux-x86_64 --repo yokoszn/sfos-rs

# 3. Sigstore signature
cosign verify-blob \
  --bundle sfos-rs-linux-x86_64.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/yokoszn/sfos-rs/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sfos-rs-linux-x86_64
```
