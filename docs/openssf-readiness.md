# OpenSSF readiness — Best Practices badge, OSPS Baseline, Scorecard

Status mapping of sfos-rs against three OpenSSF frameworks, with the exact
remaining actions. Legend: ✅ met · 🔓 met automatically once the repo is
public · 👤 owner action required · 🛣 roadmap.

> The repository is **public** (github.com/TWN-Systems/sfos-rs) — the
> hard prerequisite for all three frameworks (`repo_public` MUST /
> OSPS-QA-01.01) is met, and the CodeQL/Scorecard workflows are active.
> What remains is the settings checklist below.

## Owner checklist (in order)

1. ✅ **Repo is public** under the TWN-Systems org.
2. 👤 **Branch protection / ruleset on `main`** (Settings → Branches), per
   Scorecard Branch-Protection tiers: require a PR before merging (≥1
   approval — with CODEOWNERS in place review routes to @yokoszn), require
   status checks (`build`, `fmt + clippy`, `cargo-audit`, `cargo-deny`,
   `opengrep`), block force pushes and deletion, "Do not allow bypassing the
   above settings" for admins last (Scorecard scores admin-enforcement).
3. 👤 **Security & analysis settings** (Settings → Code security):
   - enable **Private vulnerability reporting** (the SECURITY.md and issue
     templates already point reporters there)
   - enable **Secret scanning** + **push protection** (free on public repos)
   - confirm Dependabot alerts + security updates are on
4. 🔓 **CodeQL and Scorecard activate on their own** — both workflows
   already exist and are merely `if:`-gated on the repo being public
   (`codeql.yml`, `scorecard.yml` with `publish_results: true`).
5. 👤 **Register on bestpractices.dev**: sign in with GitHub, add
   `https://github.com/TWN-Systems/sfos-rs`, fill the form using the
   [evidence map below](#best-practices-badge-passing--evidence-map). Add
   the issued badge ID to README.md.
6. 👤 **Add badges to README.md** once live:

   ```markdown
   [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>)
   [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/TWN-Systems/sfos-rs/badge)](https://scorecard.dev/viewer/?uri=github.com/TWN-Systems/sfos-rs)
   ```

## Best Practices badge (passing) — evidence map

MUST criteria only (SHOULD/SUGGESTED noted where we exceed). N/A answers are
legitimate on the form and noted explicitly.

| Criterion | Status | Evidence |
|---|---|---|
| description_good, interact | ✅ | README.md (what it does, how to get/build/contribute) |
| contribution, contribution_requirements | ✅ | CONTRIBUTING.md |
| floss_license, license_location, floss_license_osi | ✅ | MIT in `LICENSE` at root |
| documentation_basics | ✅ | `docs/` set (cli-reference, sdk-guide, playbooks) |
| documentation_interface | ✅ | docs/cli-reference.md + docs/architecture.md#external-interfaces |
| sites_https | ✅ | GitHub-hosted everything |
| discussion | ✅ | GitHub Issues (searchable, URL-addressable) |
| english | ✅ | all docs English |
| maintained | ✅ | active commits; MAINTAINERS.md |
| repo_public, repo_track, repo_interim, repo_distributed | ✅ | public git repo on GitHub |
| version_unique, version_semver, version_tags | ✅ | SemVer workspace version, `v*` tags |
| release_notes | ✅ | GitHub releases (`--generate-notes`) + CHANGELOG.md |
| release_notes_vulns | ✅ | CHANGELOG policy: Security entries reference advisories |
| report_process, report_tracker | ✅ | `.github/ISSUE_TEMPLATE/` bug template |
| report_responses, report_archive | ✅ | public Issues archive |
| vulnerability_report_process, _private | ✅ | SECURITY.md (private advisory + email) |
| vulnerability_report_response | ✅ | SECURITY.md: acknowledge ≤ 3 business days (≪ 14-day max) |
| build, build_common_tools, build_floss_tools | ✅ | cargo; docs/building.md |
| test, test_invocation | ✅ | `cargo test --locked`, 30 offline tests, CI on Linux+Windows |
| test_policy, tests_are_added, tests_documented_added | ✅ | CONTRIBUTING.md PR checklist requires tests for new behaviour |
| test_continuous_integration (suggested) | ✅ | build.yml on every PR/push |
| warnings, warnings_fixed, warnings_strict | ✅ | CI `fmt + clippy` job with `-D warnings` |
| know_secure_design, know_common_errors | 👤 | self-attestation on the form (docs/architecture.md is the supporting evidence) |
| crypto_published, crypto_call, crypto_floss | ✅ | TLS only, via rustls — no crypto implemented in-project |
| crypto_password_storage | N/A | the tool stores no passwords (credentials pass through to the firewall; `SFOS_PASSWORD` env) |
| crypto_keylength, crypto_working, crypto_weaknesses, crypto_pfs | ✅/N/A | delegated to rustls defaults (modern TLS only) |
| crypto_random | N/A | no key generation in-project |
| delivery_mitm, delivery_unsigned | ✅ | HTTPS-only distribution; sha256 + cosign + SLSA provenance per release |
| vulnerabilities_fixed_60_days, vulnerabilities_critical_fixed | ✅ | SECURITY.md remediation SLA |
| no_leaked_credentials | ✅/👤 | synthetic fixtures only; enable secret scanning on flip to public |
| static_analysis, static_analysis_fixed, _often (suggested) | ✅ | opengrep every PR/push + weekly; CodeQL once public; clippy `-D warnings` |
| dynamic_analysis (suggested) | 🛣 | parser fuzzing roadmap below |

## OSPS Baseline — control map

Level 1 + 2 controls (level 3 noted where already satisfied).

| Control | Status | Evidence |
|---|---|---|
| OSPS-AC-01 (MFA) | 👤 | required by docs/maintaining.md#account--repo-security; owner attests |
| OSPS-AC-02 (least privilege collaborators) | ✅ | single maintainer; policy in maintaining.md |
| OSPS-AC-03 (protect primary branch) | 👤 | branch-protection step in the owner checklist |
| OSPS-AC-04 (least-privilege CI) | ✅ | top-level `contents: read`, per-job escalation only (docs/ci.md) |
| OSPS-BR-01 (sanitize pipeline inputs) | ✅ | no untrusted workflow inputs; no `pull_request_target`; env-quoted vars |
| OSPS-BR-02 (unique version IDs, assets ↔ version) | ✅ | SemVer tags; release assets named per version |
| OSPS-BR-03 (encrypted channels) | ✅ | GitHub HTTPS everywhere |
| OSPS-BR-04 (changelog) | ✅ | CHANGELOG.md + generated release notes |
| OSPS-BR-05 (standardized dependency ingestion) | ✅ | cargo + committed `Cargo.lock`, `--locked` builds |
| OSPS-BR-06 (signed releases) | ✅ | cosign bundles + SLSA provenance attached per asset (docs/ci.md) |
| OSPS-DO-01 (user guides) | ✅ | docs/ set |
| OSPS-DO-02 (defect reporting guide) | ✅ | issue templates + CONTRIBUTING.md |
| OSPS-DO-03 (verify asset integrity) — L3 | ✅ | SECURITY.md verification section |
| OSPS-DO-04/05 (support scope / EOL) — L3 | ✅ | SECURITY.md "Supported versions" |
| OSPS-DO-06 (dependency selection/tracking) | ✅ | docs/building.md#dependency-footprint + docs/supply-chain.md |
| OSPS-GV-01 (members + roles) | ✅ | MAINTAINERS.md + docs/maintaining.md |
| OSPS-GV-02 (public discussion mechanism) | ✅ | GitHub Issues |
| OSPS-GV-03 (contribution process + guide) | ✅ | CONTRIBUTING.md |
| OSPS-GV-04 (review before escalated perms) — L3 | ✅ | maintainer onboarding ladder in maintaining.md |
| OSPS-LE-01 (contributor authorization assertion) | ✅ | DCO sign-off required (CONTRIBUTING.md) |
| OSPS-LE-02/03 (approved license, in repo, per release) | ✅ | MIT `LICENSE` at root, included in source archives |
| OSPS-QA-01 (public repo, change history) | ✅ | public repo; full git history |
| OSPS-QA-02 (dependency list; SBOM for releases — L3) | ✅ | `Cargo.lock` in repo; SPDX SBOM attached to releases |
| OSPS-QA-03 (status checks before merge) | 👤 | required-checks step in the owner checklist |
| OSPS-QA-04 (subprojects documented) | ✅ | single repo, two crates — README workspace section |
| OSPS-QA-05 (no committed binaries) | ✅ | none; CI builds from source |
| OSPS-QA-06 (tests pre-merge; documented; required for changes) | ✅ | build.yml on PRs; CONTRIBUTING checklist; docs/building.md#test--lint |
| OSPS-QA-07 (non-author approval) — L3 | 👤 | branch protection; inherently limited while single-maintainer |
| OSPS-SA-01/02 (design docs, interfaces) | ✅ | docs/architecture.md |
| OSPS-SA-03 (security assessment / threat model) | ✅ | docs/architecture.md#trust-boundaries--threat-model + docs/supply-chain.md#threat-model |
| OSPS-VM-01/02/03 (reporting policy, contacts, private channel) | ✅ | SECURITY.md (+ enable GitHub private reporting on flip) |
| OSPS-VM-04 (publish vulnerability data) | ✅ | GitHub advisories per docs/incident-response.md |
| OSPS-VM-05 (SCA policy + enforcement) — L3 | ✅ | cargo-audit/cargo-deny block PRs; policy in SECURITY.md + maintaining.md |
| OSPS-VM-06 (SAST policy + enforcement) — L3 | ✅ | opengrep + clippy `-D warnings` gate PRs; policy in maintaining.md |

## Scorecard — check-by-check

| Check | Expected | Notes |
|---|---|---|
| Binary-Artifacts | 10 | no binaries in repo |
| Branch-Protection | 👤 | scored once protection is configured (owner checklist #2); single-maintainer caps the reviewer tier |
| CI-Tests | ✅ | build+test on every PR |
| CII-Best-Practices | 👤 | register for the badge (checklist #5) |
| Code-Review | partial | inherent for a single-maintainer project; improves with a second reviewer |
| Contributors | partial | single-org today; informational |
| Dangerous-Workflow | 10 | no untrusted checkout / script-injection patterns; keep it that way (docs/ci.md conventions) |
| Dependency-Update-Tool | 10 | Dependabot, cargo + actions |
| Fuzzing | 🛣 | see roadmap |
| License | 10 | LICENSE (MIT) at root |
| Maintained | ✅ | commit cadence |
| Packaging | partial | binaries-only today; crates.io publication is future work (docs/supply-chain.md) |
| Pinned-Dependencies | ✅ | SHA-pinned actions, `Cargo.lock` + `--locked`, version-pinned `cargo install`s, checksum-verified opengrep |
| SAST | ✅ | CodeQL (once public) + opengrep |
| SBOM | ✅ | SPDX SBOM released as an asset (release.yml `sbom` job) |
| Security-Policy | 10 | SECURITY.md |
| Signed-Releases | ✅ | cosign bundle + `*.intoto.jsonl` provenance per asset |
| Token-Permissions | 10 | read-only top level everywhere |
| Vulnerabilities | ✅ | OSV/RUSTSEC clean; gated in CI |
| Webhooks | N/A | none configured |

## Roadmap (the honest gaps)

- **Fuzzing** (Scorecard check; badge dynamic_analysis): add `cargo-fuzz`
  targets for `parse_entities` and `xmljson::to_json` (the two
  untrusted-input parsers), run via ClusterFuzzLite on PRs. Requires nightly
  toolchain in a dedicated workflow.
- **Second maintainer / reviewer** lifts Code-Review and OSPS-QA-07 beyond
  their single-maintainer ceilings.
- **crates.io publication** with Trusted Publishing lifts Scorecard
  Packaging (plan in docs/supply-chain.md#ifwhen-sfos-rs-publishes-to-cratesio).
- **VEX statements** (OSPS-VM-04.02, L3) if/when a non-exploitable advisory
  is waived in `deny.toml` — template the justification as OpenVEX in the
  advisory issue.
