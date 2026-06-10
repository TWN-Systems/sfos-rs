# Incident response

How security events in or around sfos-rs are handled. The supply-chain
threat model and prevention controls live in
[supply-chain.md](supply-chain.md); this page is what to **do** when
something happens.

Report channel (for anyone): private advisory via GitHub *Security →
Advisories → Report a vulnerability*, or <dev@clayatownsend.com>
([SECURITY.md](../SECURITY.md)). Acknowledgement SLA: 3 business days.

## Severity guide

| Level | Examples |
|---|---|
| **Critical** | compromised release artifact; maintainer account takeover; vulnerability allowing credential theft or `apply`-style writes the operator didn't intend |
| **High** | reachable RUSTSEC advisory in a released binary; vulnerability exposing firewall config contents |
| **Medium** | vulnerability requiring unusual configuration; unreachable-but-present vulnerable dependency |
| **Low** | hardening gaps, non-exploitable bugs with security flavour |

## Process (all incidents)

1. **Triage** — confirm the report, classify severity, establish the
   affected versions/commits and the exposure window.
2. **Contain** — stop the bleeding before root-causing (pull artifacts,
   revoke credentials, disable workflows — per scenario below).
3. **Eradicate & recover** — fix, rebuild from a clean tree, re-release.
4. **Disclose** — GitHub Security Advisory with affected versions, impact,
   and upgrade/verification instructions. Credit the reporter.
5. **Post-mortem** — write down cause, detection gap, and the control that
   would have prevented it; turn that into an issue/PR, not a memory.

**Preserve evidence as you go** (before deleting anything): `git reflog`,
the GitHub audit log, workflow run logs, artifact checksums, and — for
releases — the Rekor transparency log entries, which are public and
append-only and therefore survive any cleanup on our side.

---

## Scenario 1 — vulnerability in sfos-rs

1. Acknowledge privately; reproduce; assess severity (what does it leak or
   let an attacker do — remember this tool holds **firewall admin
   credentials** and **full firewall configs**).
2. Develop the fix in a private fork/advisory workspace for
   Critical/High — not in a public PR that describes the hole before a fix
   ships.
3. Release the fixed version (normal pipeline,
   [maintaining.md](maintaining.md#cutting-a-release)).
4. Publish the advisory; if the flaw could have exposed firewall credentials
   or configs, the advisory must say so explicitly so operators can rotate
   firewall admin passwords — their blast radius, not just ours.

## Scenario 2 — compromised or suspect release artifact

Triggers: an artifact fails `sha256sum`/`gh attestation verify`/`cosign
verify-blob`; an asset exists that the pipeline didn't build; a release
exists that no maintainer cut.

1. **Contain:** delete the affected release assets (or the whole release)
   immediately. Deleting does **not** un-distribute — assume copies exist.
2. Publish an advisory naming the exact bad artifact digests and the good
   ones, and telling users to verify per
   [SECURITY.md](../SECURITY.md#verifying-a-downloaded-release-binary)
   before trusting any copy they downloaded.
3. **Investigate how it got there:** GitHub audit log (who created the
   release), workflow run logs (was it pipeline-built?), Rekor log (was it
   signed by our workflow identity — and if yes, treat as Scenario 4).
   Hand-uploaded assets implicate an account (→ Scenario 3).
4. Re-release clean artifacts under a **new** version; never reuse the
   tainted tag.

## Scenario 3 — maintainer account compromise

Assume the attacker had everything the account had: push, tag, release,
workflow edit, settings.

1. **Contain:** regain account control (password + 2FA reset), revoke all
   sessions, all PATs, all OAuth app grants; remove the account's repo
   access until cleanup is done if another maintainer exists.
2. **Audit the damage window** (GitHub audit log timestamps bound it):
   - all pushes: `git log --all` + reflog vs known-good; force-pushes show
     in the audit log
   - all tags/releases created or modified (→ Scenario 2 for each)
   - all workflow-file changes (→ Scenario 4 if any ran)
   - settings: new deploy keys, webhooks, collaborators, Actions secrets
3. **Eradicate:** revert/remove malicious commits with history rewriting
   only if necessary (and say so loudly in the advisory — consumers pinning
   `rev` are immune, branch-followers are not); delete rogue keys/webhooks.
4. **Disclose** even if nothing malicious is found: the audit log proves a
   takeover window existed; say what was checked and how.

## Scenario 4 — CI / workflow compromise

Triggers: a malicious workflow edit ran; a SHA-pinned upstream action was
found to be malicious at the pinned commit; signing happened from an
unexpected workflow identity in Rekor.

1. **Contain:** disable Actions on the repo (Settings → Actions) while
   investigating.
2. Identify every run of the tainted workflow/action and what each run's
   `GITHUB_TOKEN`/OIDC permissions allowed (our jobs are least-privilege:
   most runs can read contents and nothing else — the release job is the
   dangerous one).
3. Any release built during the window → Scenario 2 treatment.
4. Replace the tainted action pin / revert the workflow change; re-enable
   Actions; re-verify the next release end-to-end.

Note: there are no long-lived secrets in CI to rotate — signing is keyless
OIDC. That is deliberate ([ci.md](ci.md#hardening-conventions)).

## Scenario 5 — upstream crate compromise

A dependency (direct or transitive) ships a malicious or vulnerable
version. Full prevention/response detail:
[supply-chain.md](supply-chain.md#scenario-compromised-upstream-crate).
Short form:

1. Check exposure: `git log -p Cargo.lock` answers *exactly* which versions
   we ever pinned and when. `--locked` builds mean nothing outside the
   lockfile was ever built or shipped.
2. If a pinned version is affected: bump/pin away
   (`cargo update -p <crate> --precise <ver>`), rebuild, re-release; treat
   shipped binaries per Scenario 2's disclosure pattern (digests of bad vs
   good).
3. If the bad version was never in `Cargo.lock`: no exposure — say so in an
   issue for the record.

## Scenario 6 — user-side credential exposure

Not our infrastructure, but our users: someone reports that firewall admin
credentials or an exported config leaked through tool usage (shell history,
CI logs with `--password`, committed `export` output).

Response: help the operator scope it (what the credential could do, whether
`apply --commit` writes were possible), point at the prevention guidance in
[safety.md](safety.md#credentials--transport), and — if the leak mode was
something the tool made easy — file the UX fix (e.g. warn when `--password`
is used interactively) as a tracked issue.
