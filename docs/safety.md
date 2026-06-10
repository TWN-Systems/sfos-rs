# Safety: what reads, what writes, what can hurt you

sfos-rs is built so that the destructive surface is as small and explicit as
possible. This page is the complete inventory.

## Read-only by construction

These can never modify a firewall, no matter what flags you pass:

| Surface | Why it's safe |
|---|---|
| `parse`, `dump`, `search`, `check`, `trace`, `verify`, `graph`, `explain`, `path`, `site-path`, `s2s`, `report`, `iac`, `entities` | operate on local files only; no network code path |
| `fetch`, `get`, `export` | send only `<Get>` requests; the firewall treats these as reads |
| `apply` **without** `--commit` | computes and prints the plan, then stops — the commit branch is the only code that transmits `<Set>`/`<Remove>` |
| `apply --live <file>` | offline diff between two files; `--commit` is rejected outright in this mode |

Local-filesystem caveat: `export --out-dir DIR` creates `DIR` and
**overwrites** existing `<Tag>.json`/`<Tag>.xml` files in it. Point it at a
fresh or dedicated directory.

## The single write path: `apply --commit`

`apply <desired> --host <fw> --user <u> --commit` is the **only** way the CLI
modifies a firewall. What it can do:

| Plan action | API operation | Effect on the firewall |
|---|---|---|
| `+ ADD` | `<Set operation="add">` | creates the object |
| `~ UPDATE` | `<Set operation="update">` | **replaces** the object's fields with the desired serialization — fields present on the box but absent from your desired config are subject to being reset |
| `- REMOVE` (only with `--prune`) | `<Remove>` by name | **deletes** the object |

Scope: the five writable entity types — `Zone`, `IPHost`, `IPHostGroup`,
`Services`, `FirewallRule`. Nothing else is ever written.

### `--prune` is the dangerous flag

Without `--prune`, `apply` only adds and updates. With `--prune`, **every
live object (of the five types) that is missing from your desired config is
deleted**. A desired file that was exported from a different box, an older
firmware, or that simply omits objects you still need, will generate mass
removals — including firewall rules. The dry-run plan shows every `- REMOVE`
line before you commit: read them all.

### Partial application

Changes are sent one at a time, in plan order (zones → hosts → groups →
services → rules). A failure does not stop the run and there is **no
rollback** — the firewall can be left part-way between old and desired state.
Recovery: fix the cause (see [errors.md](errors.md)), re-run `apply`; the
plan recomputes against the new live state so completed items drop out.

### Standard precautions before any `--commit`

1. **Back up first**: `sfos-rs export --host fw … --raw --out-dir backup-$(date +%F)/`
   (and/or take a firewall backup from System → Backup & firmware).
2. **Dry-run and read the whole plan** — every line, especially `- REMOVE`s.
   The printed `<Set>` bodies are byte-for-byte what will be sent.
3. **Plan offline against the backup** (`apply desired.xml --live backup.xml`)
   if you want to iterate without touching the box at all.
4. Prefer a **maintenance window** for rule changes; a wrong rule update can
   cut off management access — know your out-of-band/console path.
5. Remember the live write path is **not yet validated against real
   hardware** (see [docs/README.md](README.md#validation-status)): treat the
   first commits as experiments on a non-production box.

## SDK users

Library calls `set`, `remove`, `create`, `update`, `delete` write
immediately with no plan/confirm step — that discipline is the caller's job.
Everything else on `Client` is read-only.

## Credentials & transport

- Prefer `SFOS_PASSWORD` over `--password`: CLI flags leak into shell
  history and `ps` output.
- `--insecure` disables TLS verification. Acceptable for the default
  self-signed cert on a trusted management network; on anything else it
  invites man-in-the-middle interception of admin credentials. The better
  fix is installing a CA-signed certificate on the firewall.
- Use a dedicated API admin account with the least privilege your firmware
  supports, and allowlist only the automation host's IP in the firewall's
  API settings.
- Exports contain your **entire firewall config** (objects, rules, tunnel
  definitions). Treat export files and `--out-dir` directories as
  sensitive material; don't commit them to public repos.
