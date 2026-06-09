# sfos-rs

A standalone **Rust SDK + CLI for Sophos SFOS firewalls** — "Batfish for Sophos".
Parse an `Entities.xml` backup offline, or authenticate to a live firewall over the
XML API, pull the entire configuration, and produce reports.

> **Disclaimer:** sfos-rs is an independent community project and is **not affiliated
> with, endorsed by, or supported by Sophos Ltd.** "Sophos" and "SFOS" are trademarks
> of Sophos Ltd., used here only for identification. It is a clean-room Rust
> implementation written against Sophos's public XML API. See
> [ATTRIBUTIONS.md](ATTRIBUTIONS.md).

Workspace:

- **`crates/sfos-sdk`** — the library (Rust port of the official `sophos-firewall-sdk` XML API):
  - `client` — live XML API: auth, `get`/`set`/`remove`, full `export`, self-signed-cert support
  - `sophos` — typed config model + `Entities.xml` / API-response parser + object search
  - `registry` — catalogue of SFOS XML API entities across every menu category
  - `xmljson` — generic XML→JSON, so *any* entity is pullable without a typed struct
  - `ir` + `extract` — vendor-neutral firewall IR and the Sophos→IR bridge
  - `acl` — packet-forwarding (reachability) evaluation; `shadow` — dead-rule detection
- **`crates/sfos-cli`** — the `sfos-rs` binary

## Build

```bash
cargo build --release          # -> target/release/sfos-rs[.exe]
```

Cross-platform (Linux/macOS/Windows). TLS is `rustls` (no OpenSSL needed). On Windows,
the standard MSVC Rust toolchain builds it with no extra native dependencies.

## Commands

Offline (against a backup `Entities.xml`):

```bash
sfos-rs parse  Entities.xml
sfos-rs dump   Entities.xml [--rules|--zones|--hosts|--services]
sfos-rs search Entities.xml --referencing WebServer
sfos-rs search Entities.xml --from LAN --to WAN
sfos-rs check  Entities.xml
sfos-rs trace  Entities.xml --from WAN --to DMZ --proto tcp --dport 443 --dst 10.0.10.5
sfos-rs verify Entities.xml
sfos-rs graph  Entities.xml [--mermaid]
```

Live (against a firewall's XML API — set `SFOS_PASSWORD` or pass `--password`):

```bash
sfos-rs entities                                            # list the entity catalogue
sfos-rs fetch  --host fw --user admin --insecure            # typed summary
sfos-rs get    --host fw --user admin --insecure FirewallRule   # one entity (JSON or --raw)
sfos-rs export --host fw --user admin --insecure --out-dir ./dump   # pull the whole config
```

Add `--format json` for machine-readable output. `--insecure` skips TLS verification
(SFOS ships a self-signed certificate by default).

## Getting an Entities.xml

Export a backup from the firewall (System → Backup & Firmware), extract the `.tar`,
and use the `Entities.xml` inside — or just use `fetch`/`export` against the live box.

## Status

The XML API surface is driven by a uniform engine over an entity registry, so coverage
grows by extending the catalogue. The live HTTP path is exercised against real firewalls;
the request/response logic is unit-tested offline. Ansible/PowerShell ports are out of scope.

## License

MIT — see [LICENSE](LICENSE).

## Attributions

sfos-rs is not affiliated with Sophos. It is informed by Sophos's public XML API
documentation and by the official Sophos firewall tooling. See
[ATTRIBUTIONS.md](ATTRIBUTIONS.md) for full credits and references.

## Security

Supply-chain assurances (signed/attested releases) and vulnerability reporting are
described in [SECURITY.md](SECURITY.md). CI runs opengrep (SAST), `cargo-audit`,
`cargo-deny`, CodeQL (Rust), and OpenSSF Scorecard.
