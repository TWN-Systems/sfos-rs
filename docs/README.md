# sfos-rs documentation

A Rust SDK + CLI for Sophos SFOS firewalls (XML API). Parse offline config
exports, audit live firewalls, compare site-to-site VPN meshes, trace packets
through the rule base, and apply declarative configuration changes.

## Documentation index

Using the tool:

| Document | What it covers |
|---|---|
| [cli-reference.md](cli-reference.md) | Every command, flag, default, and exit code |
| [sdk-guide.md](sdk-guide.md) | Library usage: client, typed entities, registry, filters |
| [errors.md](errors.md) | Every error message, what it means, and how to fix it |
| [safety.md](safety.md) | Read-only vs write operations; potentially destructive activities |
| [playbooks.md](playbooks.md) | SOPs for common tasks (multi-site VPN audit, BCDR export, change application, …) |

Developing and operating the project:

| Document | What it covers |
|---|---|
| [architecture.md](architecture.md) | Design doc: actors, data flows, trust boundaries, threat model |
| [building.md](building.md) | Building from source, `--locked`, tests, dependency footprint |
| [ci.md](ci.md) | Every CI/CD workflow, the release pipeline, hardening conventions |
| [openssf-readiness.md](openssf-readiness.md) | Best Practices badge / OSPS Baseline / Scorecard evidence maps + owner checklist |
| [maintaining.md](maintaining.md) | Maintainer guide: dependencies, advisories, releases, account security |
| [supply-chain.md](supply-chain.md) | Threat model, controls, crate/maintainer-compromise scenarios |
| [incident-response.md](incident-response.md) | What to do when something happens (six scenarios) |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Contribution scope, conventions, PR checklist |

## Quick orientation

```
                       ┌─────────────────────────────────────────────┐
                       │              OFFLINE  (read-only)            │
  Entities.xml ──────► │ parse · dump · search · check · trace ·      │
  (or export output)   │ verify · graph · explain · path · site-path  │
                       │ · s2s · report · iac · entities              │
                       └─────────────────────────────────────────────┘

                       ┌─────────────────────────────────────────────┐
  https://fw:4444 ───► │              LIVE  (network)                 │
  XML API              │ fetch · get · export          (read-only)    │
                       │ apply --commit       (the ONLY write path)   │
                       └─────────────────────────────────────────────┘
```

- **Offline commands** operate on a saved configuration file (an `Entities.xml`
  backup or the output of `sfos-rs export`). They never touch the network and
  are read-only by construction.
- **Live commands** talk to the firewall's XML API
  (`https://<host>:4444/webconsole/APIController`). `fetch`, `get`, and
  `export` only read. **`apply --commit` is the single code path that writes
  to a firewall** — everything else, including `apply` without `--commit`, is
  a dry run.

## Conventions

- **Output format**: every command accepts `--format text` (default) or
  `--format json`. JSON output is intended for scripting/CI.
- **Severity ordering**: findings are reported as `CRIT > HIGH > MEDIUM > LOW > INFO`.
  `check` and `s2s` exit non-zero when HIGH or CRIT findings exist, so they can
  gate CI pipelines.
- **Exit codes**: `0` success / no blocking findings; `1` error, HIGH/CRIT
  finding, BLOCKED verdict (`trace`/`path`/`site-path`), or a failed change
  (`apply --commit`). See [cli-reference.md](cli-reference.md#exit-codes).
- **Credentials**: pass `--password`, or set `SFOS_PASSWORD` in the
  environment to keep secrets out of shell history and process listings.
- **TLS**: SFOS ships with a self-signed certificate on the admin port. Use
  `--insecure` to accept it, or install a CA-signed cert on the firewall.

## Validation status

The offline parsing/analysis layer is unit-tested against fixtures derived
from Sophos's own configuration-template tooling. **The live HTTP path
(`fetch` / `get` / `export` / `apply --commit`) has not yet been validated
against a real firewall** — request/response handling is unit-tested, but
treat the first run against production hardware as an experiment: start with
read-only commands (`fetch`, `export`) and dry-run `apply` before ever using
`--commit`.

## Affiliation

This project is not affiliated with, endorsed by, or supported by Sophos Ltd.
"Sophos" and "SFOS" are trademarks of Sophos Ltd. Use it only against
firewalls you are authorized to administer.
