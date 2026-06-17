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
- CI now publishes ready-to-download, signed artifacts on every release:
  the Linux/Windows binaries, a no-dependency Debian `.deb`, and a `scratch`
  container image on GHCR (`ghcr.io/twn-systems/sfos-rs`). A `v*` tag cuts a
  versioned release (`:<version>`/`:latest`); pushes to `main` refresh a
  rolling `edge` pre-release and `:edge` image. Every artifact (binaries,
  `.deb`, image) is cosign-signed and carries SLSA build provenance.

### Changed
- `graph` rendered views (DOT, Mermaid) are tuned for legibility: intra-zone
  self-loops and the uninformative `any` edge label are dropped, zones with no
  accept rules are parked in a side bucket, and WAN-sourced edges (inbound
  exposure) are coloured red. `--format json` is unchanged in shape (now also
  carries `from_wan`/`self_loop`) and remains the faithful, complete export.

### Fixed
- `graph --mermaid` now quotes edge labels, so service names containing `(`,
  `)`, or `,` (e.g. `SMTP(S)`) render instead of failing Mermaid's parser
  (`Parse error … got 'PS'`); node IDs are sanitised with the real zone name
  kept as a display label, so a zone like `Guest WiFi` can't emit a broken ID.
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
