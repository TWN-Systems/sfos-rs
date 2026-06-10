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
