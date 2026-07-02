# Playbooks (SOPs)

Step-by-step procedures for the common operational tasks. All commands accept
`--format json` for machine-readable output; pipe to `jq` in scripts.

- [1. Enable the XML API on a firewall](#playbook-1--enable-the-xml-api-on-a-firewall)
- [2. Multi-site VPN audit](#playbook-2--multi-site-vpn-audit)
- [3. Differential reachability ("LAN can, VPN can't")](#playbook-3--differential-reachability)
- [4. Trace one flow end-to-end](#playbook-4--trace-one-flow-end-to-end)
- [5. BCDR: config export, backup, and drift detection](#playbook-5--bcdr-config-export-backup-and-drift-detection)
- [6. Rule-base hygiene review](#playbook-6--rule-base-hygiene-review)
- [7. Safe change application (plan → commit)](#playbook-7--safe-change-application-plan--commit)
- [8. CI gating](#playbook-8--ci-gating)

---

## Playbook 1 — Enable the XML API on a firewall

Once per firewall, in the web admin UI:

1. Log in to the webadmin (`https://<fw>:4444`).
2. Go to **Backup & firmware → API**.
3. Enable **API configuration**.
4. Add the IP address of the machine that will run sfos-rs to the
   **allowed IP addresses** list. Keep this list tight — it is the API's
   primary access control.
5. (Recommended) Create a dedicated administrator for automation with the
   least-privileged profile your firmware supports.

Verify from the sfos-rs host:

```bash
export SFOS_PASSWORD='…'
sfos-rs fetch --host fw1.example.com --user apiadmin --insecure
```

Expected: a parse summary (zones/rules/hosts/services counts).
- `authentication failed` → credentials, API not enabled, or your IP isn't
  allowlisted ([errors.md](errors.md#authentication-failed-authentication-failure))
- `HTTP transport error` → TLS (add `--insecure` for the self-signed cert),
  port, or network path

## Playbook 2 — Multi-site VPN audit

Goal: verify that site-to-site IPsec across N firewalls is symmetric, fully
paired, and free of deprecated settings. This is the `s2s` command's job.

**1. Collect one config per site** — either live:

```bash
for site in fw-hobart fw-launceston fw-devonport; do
  sfos-rs export --host $site --user apiadmin --insecure --raw > $site.xml
done
```

or offline: take a backup per box (System → Backup & firmware), extract each
`.tar`, and use the `Entities.xml` inside (rename per site:
`fw-hobart.xml`, …). File stems become the site names in every report.

**2. Run the audit across all sites at once:**

```bash
sfos-rs s2s fw-hobart.xml fw-launceston.xml fw-devonport.xml
```

Every unique pair of configs is compared; tunnels are paired by IP-space
overlap and then checked for exact symmetry. Findings and what to do:

| Finding | Meaning | Action |
|---|---|---|
| `S2S-UNPAIRED` (HIGH) | a tunnel has no counterpart on the peer — the other end is missing, deleted, or its subnets don't overlap at all | create/fix the peer connection; check both ends' local/remote subnet objects |
| `S2S-SUBNET-ASYMMETRY` (HIGH) | the ends pair up but local/remote subnet sets aren't exact mirrors (e.g. one end says `10.2.0.0/16`, the other `10.2.1.0/24`) | make each end's *remote* exactly equal the peer's *local*; the message prints both ends' resolved CIDR sets |
| `S2S-AUTH-MISMATCH` (MEDIUM) | authentication types differ between ends | align (e.g. both PSK or both certificate) |
| `S2S-IKE-MISMATCH` (MEDIUM) | IKE versions differ | align; prefer IKEv2 |
| `VPN-IKEV1` (MEDIUM) | a connection still negotiates IKEv1 | migrate to IKEv2 |

Notes:
- Subnets are resolved to CIDRs through **each firewall's own host objects**,
  so different object names on each box don't cause false mismatches.
- Exit code is `1` if any HIGH finding exists — wire it into CI/cron
  ([playbook 8](#playbook-8--ci-gating)).

**3. Per-site detail** for anything flagged:

```bash
sfos-rs report fw-hobart.xml        # tunnel inventory: ends, subnets, IKE, auth
```

**4. Prove an actual flow works across the mesh** (control-plane symmetry
doesn't guarantee the firewall rules allow the traffic):

```bash
sfos-rs site-path fw-hobart.xml fw-launceston.xml \
    --src 10.1.0.20 --to 10.2.0.10 --proto tcp --dport 443
```

Use real IPs **inside each site's subnets**. The stage list shows exactly
where a BLOCKED flow dies: site A's rule base, no covering tunnel, no
mirrored tunnel on B, or site B's rule base (traffic from the tunnel is
evaluated as entering zone `VPN`, the SFOS convention).

**5. Re-run after remediation** until `s2s` exits 0.

## Playbook 3 — Differential reachability

Symptom: "the office can reach the app but remote-VPN users can't" (or any
two vantages disagreeing).

```bash
sfos-rs explain Entities.xml --to 10.0.10.5 --proto tcp --dport 443
```

- `--to` accepts an IPHost object name (`--to WebServer`) or an IP.
- Default is every zone; narrow with repeatable `--from LAN --from VPN`.
- With `--src 10.0.30.7` (and no `--from`) the source zone is inferred from
  interface addressing.

The output gives an ALLOW/BLOCK verdict per zone **with the deciding rule**,
detects DNAT (verdict evaluated against the translated host), and when zones
disagree it prints the minimal fix: which rule to widen or clone. The
`Related rules` list shows everything touching that destination/service —
your candidates for tightening instead of widening.

## Playbook 4 — Trace one flow end-to-end

```bash
# zone-pair quick check (no addressing needed)
sfos-rs trace Entities.xml --from WAN --to DMZ --proto tcp --dport 443 --dst 10.0.10.5

# full single-box path: ingress → DNAT → route → firewall → SNAT
sfos-rs path Entities.xml --src 192.0.2.50 --to 10.0.10.5 --proto tcp --dport 443
```

`trace` answers "does any rule for this zone pair pass this packet?" —
remember `--dport` defaults to `0` and `--src`/`--dst` to `0.0.0.0`; give
real values to exercise port- and address-scoped rules. `path` additionally
resolves the ingress zone from the source IP, applies DNAT, and consults the
route table. Both exit `1` on BLOCKED, so they work in scripts.

## Playbook 5 — BCDR: config export, backup, and drift detection

**Full-fidelity backup** (all 70 catalogued entities, raw XML):

```bash
sfos-rs export --host fw --user apiadmin --insecure --raw --out-dir backups/fw1/$(date +%F)/
```

`exported N entities (M unavailable)` is normal — M are entities your
model/firmware doesn't serve. Treat the output directory as sensitive (it is
your whole firewall config).

**Version-controlled normalized state** (diff-friendly):

```bash
sfos-rs export --host fw --user apiadmin --insecure --raw > fw1.xml
sfos-rs iac fw1.xml > state/fw1.json
git -C state diff                  # drift since last export
git -C state commit -am "fw1 $(date +%F)"
```

**Offline drift check against a known-good baseline** (no writes possible):

```bash
sfos-rs apply baseline.xml --live fw1.xml          # plan only; --commit is rejected with --live
```

Any `+`/`~`/`-` lines are drift from baseline, expressed as the actions that
would reconcile it.

## Playbook 6 — Rule-base hygiene review

```bash
sfos-rs check  Entities.xml          # undefined zones, WAN-in without IPS, no-log accepts, disabled rules
sfos-rs verify Entities.xml          # shadowed rules: unreachable (dead) / overridden (intent defeated)
sfos-rs graph  Entities.xml --mermaid    # zone-reachability picture for the report
sfos-rs search Entities.xml --referencing OldServer   # is this object still used? (before deleting it)
sfos-rs dump   Entities.xml --rules                   # full annotated rule listing
```

Review order that works: fix `check` HIGHs (undefined zones are real
misconfig), delete `verify` *unreachable* rules (pure dead weight),
investigate *overridden* rules (something's intent is silently defeated),
then use the graph to spot zone pairs that shouldn't be connected at all.

## Playbook 7 — Safe change application (plan → commit)

The full discipline is in [safety.md](safety.md); the procedure:

```bash
# 0. backup (see playbook 5)
# 1. craft desired.xml — start from an export and edit, or generate it
# 2. iterate OFFLINE until the plan is exactly what you intend
sfos-rs apply desired.xml --live backup.xml

# 3. dry-run against the live box (state may have moved since the backup)
sfos-rs apply desired.xml --host fw --user apiadmin --insecure

# 4. read EVERY line — especially "- REMOVE" lines if you used --prune
# 5. commit
sfos-rs apply desired.xml --host fw --user apiadmin --insecure --commit

# 6. verify
sfos-rs fetch --host fw --user apiadmin --insecure
sfos-rs s2s ... / check ...           # whatever proves your intent
```

If the commit reports failures (`applied N change(s), M failed`): the
applied items stay applied; fix the cause ([errors.md](errors.md)) and
re-run — the plan recomputes, completed items drop out. Ordering note: the
planner emits zones → hosts → groups → services → rules, so dependencies
created in the same run are satisfied.

## Playbook 8 — CI gating

`check` and `s2s` exit `1` on HIGH/CRIT findings; `trace`/`path`/`site-path`
exit `1` on BLOCKED. Examples:

```bash
# fail the pipeline on hygiene regressions
sfos-rs check Entities.xml --format json > findings.json

# fail when the VPN mesh degrades
sfos-rs s2s site-*.xml --format json \
  | jq -e '[.[] | select(.severity=="HIGH" or .severity=="CRIT")] | length == 0'

# invariant tests: these flows MUST work / MUST be blocked
sfos-rs site-path a.xml b.xml --src 10.1.0.20 --to 10.2.0.10 --dport 443      # exit 1 = broken
! sfos-rs trace Entities.xml --from WAN --to LAN --proto tcp --dport 3389     # exit 0 = hole!
```

The last pattern (asserting a flow is blocked by negating the exit code) is
the cheapest regression net for "someone opened RDP from WAN".
