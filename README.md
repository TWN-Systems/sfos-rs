# sfos-rs

A standalone **Rust SDK + CLI for Sophos SFOS firewalls**

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

## Documentation

Full documentation lives in [`docs/`](docs/README.md):
[CLI reference](docs/cli-reference.md) (every command, flag, and exit code) ·
[SDK guide](docs/sdk-guide.md) ·
[error reference](docs/errors.md) ·
[safety / destructive operations](docs/safety.md) ·
[playbooks](docs/playbooks.md) (multi-site VPN audit, BCDR export, safe change application, …).

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

Analysis & reporting:

```bash
sfos-rs explain   Entities.xml --to WebServer --dport 443        # differential reachability: which zones can, which can't, and why
sfos-rs path      Entities.xml --src 192.0.2.50 --to 10.0.10.5   # ingress -> DNAT -> route -> firewall -> SNAT
sfos-rs site-path siteA.xml siteB.xml --src 10.1.0.20 --to 10.2.0.10   # cross-firewall, over the IPsec tunnel
sfos-rs s2s       siteA.xml siteB.xml [siteC.xml ...]            # site-to-site IPsec symmetry audit
sfos-rs report    Entities.xml                                   # per-subsystem state report
sfos-rs iac       Entities.xml [--ansible]                       # normalized declarative JSON / Ansible playbook
```

Live (against a firewall's XML API — set `SFOS_PASSWORD` or pass `--password`):

```bash
sfos-rs entities                                            # list the entity catalogue
sfos-rs fetch  --host fw --user admin --insecure            # typed summary
sfos-rs get    --host fw --user admin --insecure FirewallRule   # one entity (JSON or --raw)
sfos-rs export --host fw --user admin --insecure --out-dir ./dump   # pull the whole config
sfos-rs apply  desired.xml --host fw --user admin --insecure        # dry-run plan; add --commit to write
```

Add `--format json` for machine-readable output. `--insecure` skips TLS verification
(SFOS ships a self-signed certificate by default). `apply --commit` is the only
operation that writes to a firewall — see [docs/safety.md](docs/safety.md).

## Getting an Entities.xml

Export a backup from the firewall (System → Backup & Firmware), extract the `.tar`,
and use the `Entities.xml` inside — or just use `fetch`/`export` against the live box.

## Status

The XML API surface is driven by a uniform engine over an entity registry, so coverage
grows by extending the catalogue. The request/response logic is unit-tested offline
against fixtures derived from Sophos's own configuration-template tooling; **the live
HTTP path has not yet been validated against a real firewall** (see
[docs/README.md](docs/README.md#validation-status)). Ansible/PowerShell ports are out
of scope.

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
