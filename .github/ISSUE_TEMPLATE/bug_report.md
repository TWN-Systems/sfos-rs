---
name: Bug report
about: Something behaves wrongly (parsing, analysis, CLI, live API)
labels: bug
---

**What happened**

**What you expected**

**Reproduction**

```bash
# exact command line (redact hosts/credentials)
sfos-rs ...
```

- sfos-rs version (`sfos-rs --version`):
- OS:
- SFOS firmware version (if live API related):

**Input** — if the bug involves parsing or analysis, attach a **redacted**
minimal `Entities.xml` snippet that reproduces it (strip hostnames, public
IPs, PSKs, certificates, usernames).

**Output** — full stderr/stdout, or `--format json` output.

> Security vulnerabilities: do **not** file an issue — see
> [SECURITY.md](../../SECURITY.md) for private reporting.
