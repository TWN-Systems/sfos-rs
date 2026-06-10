# CLI reference

```
sfos-rs [--format text|json] <COMMAND> [ARGS]
```

Binary: `sfos-rs` (build with `cargo build --release` → `target/release/sfos-rs`).

## Global flags

| Flag | Values | Default | Effect |
|---|---|---|---|
| `--format` | `text`, `json` | `text` | Output format for **every** command. JSON is pretty-printed and stable for scripting. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. For `check`/`s2s`: no HIGH/CRIT findings. For `trace`/`path`/`site-path`: verdict DELIVERED. For `apply --commit`: every change applied. |
| `1` | Any error (printed as `sfos-rs: <message>` on stderr), **or** a HIGH/CRIT finding (`check`, `s2s`), **or** a BLOCKED verdict (`trace`, `path`, `site-path`), **or** at least one failed change (`apply --commit`). |

`verify`, `parse`, `dump`, `search`, `graph`, `report`, `iac`, `entities`,
`fetch`, `get`, `export` always exit `0` unless an error occurs — they inform,
they don't gate.

## Input files

Offline commands take a `FILE` argument: a backup `Entities.xml` (System →
Backup & firmware on the firewall; extract the `.tar`) **or** any XML API
`<Response>` body (e.g. saved `get --raw` / `export --raw` output). Parse
errors are reported as `sfos-rs: <path>: <reason>` with exit 1.

---

## Offline commands

### `parse <FILE>`

Parse and print object counts (zones, firewall rules, IP hosts, IP host
groups, services). Quick sanity check that a file is readable.

### `dump <FILE> [--zones] [--rules] [--hosts] [--services]`

Dump parsed objects. With no selection flags, **all four sections** are
printed. Flags are additive (`--zones --rules` prints just those two).

Text format per line:
- zone: `name (type)`
- rule: `[on|off] name action srcZones→dstZones svc:[services]` (`any` when a zone list is empty)
- host: `name [IP|Network|IPRange] address` (`ip/mask`, `start-end`, or `-` when empty)
- service: `name (type)`

### `search <FILE> (--referencing <OBJECT> | --from <ZONE> --to <ZONE>)`

Find firewall rules either:
- `--referencing <OBJECT>` — rules referencing a host / network / service /
  zone by name (membership in any rule field), or
- `--from <ZONE> --to <ZONE>` — rules for a zone pair (both flags required).

Passing neither (or only one of `--from`/`--to`) errors:
`specify --referencing <object>, or both --from <zone> and --to <zone>`.
No matches is not an error (prints `no matching rules`, exits 0).

### `check <FILE>`

Baseline hygiene checks. Exits `1` if any HIGH/CRIT finding exists.

| Check ID | Severity | Trigger |
|---|---|---|
| `SFOS-UNDEFINED-ZONE` | HIGH | a rule references a zone that is not defined |
| `SFOS-DISABLED-RULE` | INFO | rule disabled — dead configuration |
| `SFOS-WAN-INBOUND-NO-IPS` | MEDIUM | WAN-sourced accept rule with no intrusion-prevention policy |
| `SFOS-RULE-NO-LOG` | LOW | accept rule does not log traffic |

Output line: `[SEVERITY] CHECK-ID object — message`, then a summary count.

### `trace <FILE> --from <ZONE> --to <ZONE> [--proto tcp|udp|icmp] [--dport N] [--src IP] [--dst IP]`

Simulate one packet against the synthesized rule set for a **zone pair**.

| Flag | Default | Notes |
|---|---|---|
| `--from` / `--to` | (required) | source / destination **zone names** |
| `--proto` | `tcp` | `tcp`, `udp`, or `icmp` |
| `--dport` | `0` | give a real port to match port-scoped services |
| `--src` / `--dst` | `0.0.0.0` | give real IPs to match address-scoped rules |

If no rule covers the zone pair, the SFOS implicit **default-drop** applies
(`rule set <none>`, `matched: no rule — default action`). Verdict line:
`verdict: Accept|Drop → DELIVERED|BLOCKED`. Exits `1` when BLOCKED.

### `verify <FILE>`

Detect shadowed rules per zone-pair rule set. Two kinds:
- `unreachable` — an earlier rule with the **same action** fully covers it
  (dead weight),
- `overridden` — an earlier rule with a **different action** fully covers it
  (the later rule's intent never takes effect — investigate).

Output: `[SHADOW] rule set <pair>: rule <seq> unreachable|overridden by rule <seq>`.
Detection is sound but incomplete: it reports single-rule total shadowing; it
cannot see a rule shadowed only by a *combination* of earlier rules. Always
exits `0` (informational).

### `graph <FILE> [--mermaid]`

Zone-reachability graph from enabled accept rules. Edge label = the union of
services allowed between the two zones (`any` if a rule has no service list).
Empty zone lists render as the pseudo-node `Any`.

- default: Graphviz DOT (`dot -Tsvg`)
- `--mermaid`: Mermaid `graph LR` (paste into a Markdown doc)
- `--format json`: `[{from, to, services[]}, …]` edge list (`--mermaid` ignored)

### `explain <FILE> --to <IP|HOST> [--proto tcp|udp|icmp] [--dport N] [--from <ZONE>]... [--src <IP>]`

**Differential reachability** — answers "why can zone A reach this server but
zone B can't?". Evaluates the rule base from multiple source-zone vantages and
names the deciding rule for each.

| Flag | Default | Notes |
|---|---|---|
| `--to` | (required) | destination IP, **or an IPHost object name** to resolve |
| `--proto` | `tcp` | `tcp`, `udp`, `icmp` |
| `--dport` | `443` | ignored for icmp |
| `--from` | every zone in the config | repeatable; evaluate only these zones |
| `--src` | — | infer the source zone from interface addressing (used when `--from` is omitted) |

DNAT-aware: if the destination is DNAT'd, the firewall verdict is evaluated
against the internal (translated) host and the NAT rule is reported.
When vantages disagree it prints the divergence and a concrete fix
(`X is allowed by rule 'R' (source zones: …); Y is not. Add the zone(s) to
that rule's source zones, or add an equivalent rule.`), plus all related
rules that touch the destination/service. Always exits `0`.

### `path <FILE> --src <IP> --to <IP|HOST> [--proto tcp|udp|icmp] [--dport N]`

Single-firewall end-to-end packet trace:
**ingress → DNAT → route → firewall → SNAT**. Defaults: `--proto tcp`,
`--dport 443`. `--to` accepts an IPHost object name.

Stages printed in order, e.g.:

```
ingress: 10.1.0.20 -> zone LAN
dnat: 203.0.113.10 -> 10.0.10.5 (rule DNAT-web)
route: ... / route: no route to <dst> / route: not modelled (no interfaces/routes in config)
result: DELIVERED | BLOCKED
```

Exits `1` when BLOCKED. JSON includes `ingress_zone`, `egress_zone`,
`egress_interface`, `nat`, `snat`, the firewall verdict, and all stages.

### `site-path <SITE_A> <SITE_B> --src <IP> --to <IP> [--proto tcp|udp|icmp] [--dport N]`

Cross-firewall trace over a site-to-site IPsec tunnel: the flow is evaluated
through site A's firewall, matched against A's tunnels, then checked for a
mirrored tunnel and evaluated through site B's firewall. Defaults:
`--proto tcp`, `--dport 443`. **`--src`/`--to` must be IPs** (no object
resolution here — names differ across boxes).

Convention: traffic arriving over IPsec is evaluated as entering zone `VPN`
(the SFOS default for IPsec). Distinctive stage messages:

```
<site-a>: no site-to-site tunnel covers <dst> — not routed off-site
tunnel: <site-b> has no matching tunnel for <src> -> <dst> (asymmetric or missing)
```

Exits `1` when BLOCKED. JSON includes `tunnel_a`, `tunnel_b`, `paired`,
`delivered`, `stages`.

### `s2s <FILE>... `

Site-to-site IPsec audit across **one or more** configs. For each config it
reports single-firewall VPN posture; for every unique *pair* of configs it
pairs tunnels by IP-space overlap (local subnets of one end overlap the remote
subnets of the other) and checks symmetry. Subnets are resolved to CIDRs via
each firewall's own host objects, so naming differences between boxes don't
cause false mismatches.

| Check ID | Severity | Trigger |
|---|---|---|
| `S2S-UNPAIRED` | HIGH | a site-to-site tunnel has no overlapping counterpart on the peer |
| `S2S-SUBNET-ASYMMETRY` | HIGH | paired tunnels' local/remote subnet sets are not exact mirrors |
| `S2S-AUTH-MISMATCH` | MEDIUM | authentication type differs between the two ends |
| `S2S-IKE-MISMATCH` | MEDIUM | IKE version differs between the two ends |
| `VPN-IKEV1` | MEDIUM | (per-site posture) connection negotiates IKEv1 — migrate to IKEv2 |

Output: `[SEVERITY] CHECK-ID object — message` where `object` is
`site/tunnel` for posture findings and `tunnelA↔tunnelB` for pair findings.
Exits `1` if any HIGH/CRIT finding.

### `report <FILE>`

Granular per-subsystem state report: object summary, IPsec tunnel inventory
(name, ends, subnets, IKE version, auth), and findings. The site name is
taken from the file stem (`site-a.xml` → `site-a`). `--format json` emits the
full structured report.

### `iac <FILE> [--ansible]`

Emit version-controllable IaC from a parsed config:
- default: **normalized declarative JSON** (stable field order — diff-friendly;
  commit it to git and diff between exports),
- `--ansible`: a `sophos.sophos_firewall` Ansible playbook skeleton.

### `entities`

List the built-in XML API entity catalogue (66 entities across 15 SFOS menu
categories — see [sdk-guide.md](sdk-guide.md#entity-registry)). Text output
groups by category; JSON emits `{category, display, tag}` objects. Offline —
does not contact any firewall.

---

## Live commands

All live commands share the connection flags:

| Flag | Default | Notes |
|---|---|---|
| `--host` | (required) | firewall hostname or IP |
| `--port` | `4444` | XML API / webadmin port |
| `--user` | (required) | admin username |
| `--password` | env `SFOS_PASSWORD` | error if neither is provided |
| `--insecure` | off | skip TLS certificate verification (SFOS ships a self-signed cert) |

Endpoint: `https://<host>:<port>/webconsole/APIController`, 30-second request
timeout. The API must be **enabled** on the firewall and your source IP
**allowlisted** (Backup & firmware → API) — see
[playbooks.md](playbooks.md#playbook-1--enable-the-xml-api-on-a-firewall).

### `fetch --host <H> --user <U> [...]`

Pull the typed entity set (Zone, IPHost, IPHostGroup, Services, FirewallRule)
from a live firewall and print the same summary as `parse`. Connectivity +
credential smoke test.

### `get --host <H> --user <U> [...] <ENTITY> [--raw]`

Fetch **one entity type** — any XML API tag, including tags not in the
catalogue (`get SSLTLSInspectionRule`, `get DNS`, …). Default output is a
generic XML→JSON conversion; `--raw` prints the firewall's raw XML response.

### `export --host <H> --user <U> [...] [--out-dir <DIR>] [--raw]`

Pull **every catalogued entity** (66 `Get` requests). Resilient: each
entity's result is captured independently, so one failure (or an entity that
doesn't exist on that model/firmware) never aborts the export.

- default: one combined JSON document on stdout (failed entities appear as
  `{"error": …}` values)
- `--raw`: concatenated raw XML on stdout with `<!-- Tag -->` separators
- `--out-dir <DIR>`: one `<Tag>.json` (or `.xml` with `--raw`) file per
  entity; creates the directory; **overwrites** same-named files

Summary on stderr: `exported N entities (M unavailable)`.

---

## `apply` — plan & commit

```
sfos-rs apply <DESIRED> (--live <FILE> | --host <H> --user <U> [...]) [--prune] [--commit]
```

Terraform-style workflow over the writable entity types (Zone, IPHost,
IPHostGroup, Services, FirewallRule). `<DESIRED>` is the desired-state config
(an `Entities.xml`). The "live" side is either:

- `--live <FILE>` — a saved config: **offline plan only** (`--commit` is
  rejected: `--commit requires --host (cannot write changes to a --live file)`), or
- `--host …` — a live firewall (requires `--user`, and `--password` or
  `SFOS_PASSWORD`; same `--port`/`--insecure` flags as above). The live state
  is fetched first, then diffed.

| Flag | Default | Effect |
|---|---|---|
| `--prune` | off | also **REMOVE** live objects absent from the desired config — destructive, see [safety.md](safety.md) |
| `--commit` | off | actually transmit the changes; without it the plan is a pure dry run |

Plan output (text): one line per change `+ ADD / ~ UPDATE / - REMOVE`,
followed by the exact `<Set operation="…">…</Set>` body that would be sent,
and a summary `N change(s): A add, U update, R remove`. Matching is by object
name (case-insensitive); an object whose serialized XML differs becomes an
UPDATE. JSON format emits `{action, tag, name, operation, xml}` objects.

Without `--commit` it ends with `(dry run — re-run with --host … --commit to
apply)` and exits `0`. With `--commit`, changes are sent **one at a time** in
plan order; failures don't stop the run — each is reported as
`! ACTION name failed: <error>`, the summary `applied N change(s), M failed`
goes to stderr, and the exit code is `1` if anything failed. There is **no
rollback**; see [safety.md](safety.md#partial-application) before using it.
