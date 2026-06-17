# Changelog

All notable changes to sfos-rs are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Security fixes are explicitly marked
**Security** and reference the corresponding GitHub Security Advisory.

## [Unreleased]

### Added
- Full SFOS XML API SDK: live client (get/set/remove/export, server-side
  filters), 66-entity registry, typed create/update/delete layer
- Offline `Entities.xml` parsing and analysis: `parse`, `dump`, `search`,
  `check`, `trace`, `verify`, `graph`
- Differential reachability (`explain`), single-box packet trace (`path`),
  cross-firewall trace over IPsec (`site-path`)
- Multi-site VPN audit (`s2s`): tunnel pairing, subnet/auth/IKE symmetry
- Per-subsystem reporting (`report`), IaC emission (`iac`, `--ansible`)
- Terraform-style plan/commit (`apply`, dry-run by default, `--prune`)
- Documentation set under `docs/`; CI (build/test/lint, cargo-audit,
  cargo-deny, opengrep, CodeQL, Scorecard); signed + attested releases

### Fixed
- Parsing a real backup `Entities.xml` no longer aborts on a single
  unexpected element. The loader now salvages every modellable entity and
  reports the ones it had to skip (`note: skipped N unmodelled entities …`)
  instead of failing the whole run — so `report`/`check`/`iac`/`verify` work
  against full exports, not just the curated test corpus.
- A `<VPNIPSecConnection>` carrying more than one `<Configuration>` block now
  parses (previously `XML parse error: duplicate field Configuration`, which
  took down every offline command); both tunnel bodies are surfaced.
- A leading UTF-8 BOM (PowerShell `Set-Content -Encoding utf8` on PS 5.1) is
  tolerated on input files.
