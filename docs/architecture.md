# Architecture & security model

Design documentation: actors, data flows, trust boundaries, and the threat
model for the **software itself** (the project's *supply-chain* threat model
is separate: [supply-chain.md](supply-chain.md)).

## Actors and components

```
 ┌──────────────────────── operator host ────────────────────────┐
 │                                                               │
 │  operator ──► sfos-rs (CLI) ──► sfos-sdk (library)            │
 │                  │                  │                         │
 │                  │ reads/writes     │ HTTPS (TLS via rustls)  │
 │                  ▼                  ▼                         │
 │   local files: Entities.xml,   ┌─────────────────────────┐    │
 │   exports, desired configs,   ─┼─►  trust boundary  ─────┼──┐ │
 │   reports                      └─────────────────────────┘  │ │
 └──────────────────────────────────────────────────────────────┼─┘
                                                                │
                              ┌─────────────────────────────────▼──┐
                              │ SFOS firewall(s)                   │
                              │ XML API on :4444                   │
                              │ /webconsole/APIController          │
                              └────────────────────────────────────┘
```

| Actor / component | Role |
|---|---|
| Operator | runs the CLI; holds firewall admin credentials |
| `sfos-cli` | argument parsing, output rendering, exit codes; no network logic of its own |
| `sfos-sdk` | parsing, analysis, and the only HTTP client code |
| Local files | configs in, reports/exports out — all plaintext on the operator host |
| SFOS firewall | the managed system; authenticates every request via the embedded `<Login>` block |

## System actions (complete)

1. **Parse local file** → in-memory `SophosConfig` (offline commands). No
   side effects.
2. **Read from firewall** (`fetch`/`get`/`export`, `apply` planning):
   HTTPS POST of `<Request><Login/><Get…>` — read-only on the firewall.
3. **Write to firewall** (`apply --commit` only, and SDK
   `set`/`remove`/`create`/`update`/`delete`): `<Set>`/`<Remove>` requests.
   Full inventory: [safety.md](safety.md).
4. **Write local files** (`export --out-dir`, shell redirection of stdout).

## External interfaces

| Interface | Direction | Format |
|---|---|---|
| CLI arguments / exit codes | in / out | [cli-reference.md](cli-reference.md) |
| `Entities.xml` / API `<Response>` files | in | SFOS XML ([sdk-guide.md](sdk-guide.md)) |
| XML API over HTTPS | out (in: responses) | `reqxml` form POST |
| stdout reports | out | text or JSON (`--format json`) |
| `SFOS_PASSWORD` | in | environment variable |
| Rust SDK API | in | [sdk-guide.md](sdk-guide.md) |

## Trust boundaries & threat model

**Assets:** firewall admin credentials; full firewall configurations
(rules, objects, tunnel definitions — sensitive); integrity of the firewall
itself (via the write path).

**TB1 — operator host ↔ firewall (network).**
- *Threats:* credential interception, response tampering (MITM), connecting
  to an impostor firewall.
- *Controls:* TLS everywhere (rustls; no cleartext mode exists). Credentials
  are XML-escaped and sent only in the request body, never in URLs.
- *Residual:* `--insecure` disables certificate validation and is the
  default operational reality on self-signed SFOS boxes — documented as a
  risk with the CA-cert alternative in
  [safety.md](safety.md#credentials--transport).

**TB2 — untrusted input files → parser.**
- *Threats:* malicious/crafted XML (entity expansion, deep nesting, huge
  files) aimed at the analyst's machine.
- *Controls:* memory-safe Rust throughout (`#![forbid(unsafe)]` not yet
  asserted, but no `unsafe` in this codebase); `quick-xml` does not resolve
  external entities (no XXE); parse errors are contained (`SdkError::Xml` /
  CLI error, exit 1).
- *Residual:* no explicit resource limits on input size; fuzzing of the
  parser is on the roadmap ([openssf-readiness.md](openssf-readiness.md)).

**TB3 — firewall responses → tool.**
- Same parser path and properties as TB2: a compromised firewall can lie
  about its config but cannot escape data-plane handling in the tool.

**TB4 — credentials at rest / in invocation.**
- *Threats:* `--password` leaking via shell history and process listings;
  exports leaking configs.
- *Controls:* `SFOS_PASSWORD` env path; documentation treats exports as
  sensitive ([safety.md](safety.md)); incident guidance exists for user-side
  leaks ([incident-response.md](incident-response.md#scenario-6--user-side-credential-exposure)).

**TB5 — the write path.**
- *Threats:* unintended firewall modification (operator error, hostile
  desired-state file).
- *Controls:* single explicit write path (`apply --commit`), dry-run by
  default, plan shows exact bytes to be sent, `--prune` required for any
  deletion, per-item results, documented no-rollback semantics
  ([safety.md](safety.md#the-single-write-path-apply---commit)).

## Design properties relied on for security

- **Read-only by construction:** offline commands share no code with the
  write path; the only `<Set>`/`<Remove>` emission sits behind the
  `--commit` branch in one function and behind explicit SDK methods.
- **No dynamic code, no exec:** the tool never shells out, evaluates, or
  downloads code at runtime.
- **No telemetry:** nothing leaves the operator host except the XML API
  requests to the firewall the operator named.
- **Deterministic dependencies:** `--locked` builds; supply-chain controls
  in [supply-chain.md](supply-chain.md).
