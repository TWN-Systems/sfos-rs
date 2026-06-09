# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — use GitHub's *Security → Advisories →
Report a vulnerability* on this repository, or email <dev@clayatownsend.com>. Do not
open public issues for vulnerabilities. We aim to acknowledge within 3 business days.

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
