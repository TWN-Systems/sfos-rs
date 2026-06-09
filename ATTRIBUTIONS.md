# Attributions & Disclaimer

## Disclaimer

**sfos-rs is an independent, community project. It is not affiliated with,
endorsed by, sponsored by, or supported by Sophos Ltd.**

"Sophos", "SFOS", "XG", "XGS", and related names are trademarks of Sophos Ltd.
They are used here only for identification and interoperability. sfos-rs is a
clean-room Rust implementation written against Sophos's **publicly documented**
XML API. It does **not** include or derive from the source code of the projects
listed below — those are credited as inspiration and as references for the API
surface only.

## References & inspiration

- **Sophos Firewall XML API documentation (SFOS 21.5)** — the authoritative API
  surface this SDK targets.
- **[sophos/sophos-firewall-sdk](https://github.com/sophos/sophos-firewall-sdk)**
  (Python) — the official XML API SDK; `sfos-sdk` reimagines its
  get/set/remove client model in Rust.
- **[sophos/sophos-firewall-audit](https://github.com/sophos/sophos-firewall-audit)**
  (Python) — baseline-audit concept.
- **[sophos/sophosfirewall-ansible](https://github.com/sophos/sophosfirewall-ansible)**
  (GPL-3.0) — consulted only for entity coverage; **no code reused** (sfos-rs is MIT).
- **[jkopacko/sfos_analyzer_tool](https://github.com/jkopacko/sfos_analyzer_tool)**
  (PowerShell) — offline `Entities.xml` analysis concept (`parse`/`check`/`verify`).
- **[sophos/PS.Unprotected_Machines](https://github.com/sophos/PS.Unprotected_Machines)**
  (Python) — referenced for estate-coverage ideas; not ported.

## Third-party Rust dependencies

All runtime dependencies use permissive licenses (MIT / Apache-2.0 / BSD / ISC /
Unicode-3.0 / CDLA-Permissive-2.0), enforced in CI by `cargo-deny` (see
[`deny.toml`](deny.toml)). List them with `cargo tree` or `cargo deny list`.
