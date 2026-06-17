# Error reference

Every CLI error prints `sfos-rs: <message>` to **stderr** and exits `1`.
This page lists each message, what actually went wrong, and the fix.

## Argument & input errors (offline and live)

| Message | Cause | Fix |
|---|---|---|
| `<path>: <reason>` | the config file could not be read or parsed (`load` failure: missing file, not XML, truncated export) | check the path; the file must be an `Entities.xml` backup or an XML API `<Response>` body. Try `parse <file>` to isolate. A *single* unmodelled entity no longer fails the load — see [partial parse](#partial-parse-skipped-entities) below; a hard error here means the file itself is unreadable or not XML. |
| `specify --referencing <object>, or both --from <zone> and --to <zone>` | `search` called with no selector, or only one of `--from`/`--to` | pick one mode: `--referencing NAME`, or both `--from Z --to Z` |
| `unknown --proto '<x>' (use tcp\|udp\|icmp)` | `--proto` was something else | only `tcp`, `udp`, `icmp` are modelled |
| `invalid --src IP '<x>'` / `invalid --dst IP` / `invalid --to IP '<x>'` | the value didn't parse as an IPv4/IPv6 address | `site-path` takes **IPs only**; `path`/`explain --to` also accept an IPHost object name |
| `--to '<x>' is not an IP and not a resolvable host object` | `explain`/`path` tried to resolve `--to` as an IPHost name and failed | use the exact object `Name` from `dump --hosts`, or pass the IP directly |
| `could not infer a zone for --src <ip> (no interface covers it)` | `explain --src` could not map the IP to a zone — no interface subnet contains it | pass `--from <zone>` explicitly, or check the config actually contains interface addressing |
| `no zones to evaluate — config has no zones; pass --from or --src` | `explain` over a config with zero zones and no `--from`/`--src` given | verify the export contains `Zone` entities, or name zones explicitly |

## Connection & credential errors (live commands)

| Message | Cause | Fix |
|---|---|---|
| `provide --password or set SFOS_PASSWORD` | neither the flag nor the env var is set | `export SFOS_PASSWORD=…` (preferred) or `--password` |
| `--user is required with --host` | `apply --host` without `--user` | add `--user admin` |
| `specify --live <file> for an offline plan, or --host <fw> to plan against a live firewall` | `apply` with neither a live file nor a host | choose one source of truth for the "live" side |
| `--commit requires --host (cannot write changes to a --live file)` | `apply --live <file> --commit` | `--live` plans are offline-only by design; to write, point at the firewall with `--host` |

## SDK errors (`SdkError`)

These surface through any live command (`fetch`, `get`, `export`, `apply`)
and through library calls.

### `HTTP transport error: <detail>` (`SdkError::Transport`)

The request never produced an HTTP response. The `<detail>` is the underlying
reqwest error; common cases:

- **certificate errors** (`invalid peer certificate`, `self-signed`, …) — the
  firewall is using its default self-signed cert and you didn't pass
  `--insecure` (SDK: `verify_certs=false`)
- **connection refused / timed out** (30 s limit) — wrong `--port` (API is on
  the webadmin port, default 4444), the admin service isn't listening on that
  interface, or a firewall rule blocks you. If your IP isn't in the API
  allowlist some configurations drop the connection outright — see
  [playbooks.md](playbooks.md#playbook-1--enable-the-xml-api-on-a-firewall)
- **DNS errors** — bad `--host`

### `HTTP status <NNN>` (`SdkError::Http`)

The server answered, but not 2xx. A 404 usually means the endpoint path
doesn't exist on the target (is this actually an SFOS webadmin port?);
5xx means the admin service errored.

### `authentication failed: Authentication Failure` (`SdkError::Auth`)

The firewall's `<Login>` status contained the literal text
`Authentication Failure`. Causes, most common first:

1. wrong username/password
2. the XML API is **not enabled**, or your **source IP is not in the API
   allowlist** (Backup & firmware → API) — SFOS rejects the login rather
   than admitting the API is off
3. the account's admin profile doesn't permit API access

### `API error: status <code>` (`SdkError::Api`)

A `Set`/`Remove` was accepted at the HTTP layer but the firewall rejected the
operation: its `<Status code="NNN">` was outside 200–299. The code and the
human-readable text in the response come from the firewall itself — the SDK
deliberately does not maintain its own table of Sophos status codes. To see
the firewall's full explanation, replay the read side with
`get <Tag> --raw`, or run `apply` without `--commit` and inspect the exact
`<Set>` body being sent. Typical causes: referencing an object that doesn't
exist yet (create dependencies first — zones/hosts/services before rules),
name collisions, or a field invalid for your firmware version.

A response with **no** `<Status>` element at all is treated as success
(benign), matching observed SFOS behaviour for some read paths.

### `XML parse error: <detail>` (`SdkError::Xml`)

The response body wasn't valid XML at the document level (truncated, wrong
content type, an HTML error page, …). A *single* unmodelled entity inside an
otherwise-valid response no longer trips this — it's skipped (see
[partial parse](#partial-parse-skipped-entities)). If `get <Tag> --raw` shows
valid XML but a tag you need is missing from the parsed output, its shape isn't
modelled yet — use `--raw`/JSON output, and open an issue with the (redacted) XML.

## `apply --commit` partial failures

Per-item failures do not abort the run:

```
  ! ADD web-host failed: API error: status 502
applied 3 change(s), 1 failed
```

Exit code is `1` if anything failed. The applied changes **stay applied** —
there is no rollback. Re-running `apply` is the recovery path: the plan is
recomputed against the new live state, so already-applied items drop out.

## Partial parse (skipped entities)

When an offline command loads a config, a clean document is parsed whole. If
the file contains a top-level entity whose shape the typed model can't take
(an element repeated where a scalar was expected, a field missing, a
firmware-specific shape we don't model yet), the loader **skips that one
element and keeps going** rather than aborting. You'll see a note on stderr:

```
sfos-rs: note: skipped 1 unmodelled entity (VPNIPSecConnection ×1); analysis continues on the rest
sfos-rs:   first: <VPNIPSecConnection> — <detail>
```

The analysis then runs on everything that *did* parse, and exit codes reflect
the findings, not the skip. This is by design — a real export exercises far
more of the schema than the curated fixtures, and one odd entity shouldn't
sink the whole report. If a tag you care about is being skipped, capture it
live with `get <Tag> --raw` and open an issue with the (redacted) XML so the
model can be extended.

> Note: `XML parse error` only surfaces now when the file as a whole isn't
> valid XML (truncated, wrong encoding, not a `<Configuration>`/`<Response>`
> document). Per-entity modelling gaps become skips, not hard failures.

## `export` partial results

`exported 58 entities (8 unavailable)` on stderr is **normal**: entities that
don't exist on a given model/firmware (e.g. wireless on a virtual appliance)
fail individually. With `--out-dir` failed entities are skipped; in combined
JSON output they appear as `{"error": "<message>"}` values, so you can grep
for what your box doesn't serve.

## Exit-code cheat sheet

| Command | exits `1` when |
|---|---|
| any | an error above occurred |
| `check`, `s2s` | a HIGH or CRIT finding exists |
| `trace`, `path`, `site-path` | the verdict is BLOCKED |
| `apply --commit` | at least one change failed |

## Mapping from the Python SDK

If you're migrating from `sophosfirewall-python`:

| Python exception | sfos-rs equivalent |
|---|---|
| `SophosFirewallAuthFailure` | `SdkError::Auth` |
| `SophosFirewallAPIError` | `SdkError::Api { code }` |
| `SophosFirewallZeroRecords` | **no error** — an empty `SophosConfig` / empty JSON. Zero records is data, not an exception; test for emptiness explicitly. |
