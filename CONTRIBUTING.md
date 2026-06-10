# Contributing to sfos-rs

Thanks for considering a contribution. This page covers scope, setup,
conventions, and the PR checklist. Maintainer-side process (releases,
dependency stewardship, incidents) lives in
[docs/maintaining.md](docs/maintaining.md).

## Scope

In scope:

- XML API coverage: new registry entities, typed (`SophosEntity`) writable
  types, parser fields
- Analysis: reachability, NAT, shadowing, VPN symmetry, new checks
- Reporting / IaC output formats
- Documentation and test fixtures

Out of scope (deliberate):

- Ansible and PowerShell ports
- Features requiring services beyond the firewall's own XML API

If you're unsure, open an issue before writing code.

## Security issues

**Never** open a public issue or PR for a vulnerability. Use the private
channel in [SECURITY.md](SECURITY.md).

## Development setup

Stable Rust (2021 edition) is the only requirement — TLS is `rustls`, so
there are no system library dependencies on any platform.

```bash
cargo build --locked
cargo test  --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check          # cargo install cargo-deny --locked
```

`--locked` matters: `Cargo.lock` is part of the supply-chain contract
([docs/supply-chain.md](docs/supply-chain.md)); builds that mutate it will be
rejected in CI.

## Conventions

- **Dependencies are attack surface.** New direct dependencies need a stated
  justification in the PR description: what it does, why std/existing deps
  can't, its maintenance health. Expect pushback — the whole tree is
  currently 7 direct crates and we want to keep it that order of magnitude.
  Wildcard versions are rejected by `cargo-deny`; sources other than
  crates.io are rejected outright.
- **Tests are offline.** No test may open a network connection. Live XML API
  behaviour is modelled with request/response fixtures. If you add fixtures
  from a real firewall, **redact**: hostnames, public IPs, PSKs,
  certificates, usernames.
- **Honesty about validation.** Anything not exercised against real hardware
  is documented as such (see *Validation status* in
  [docs/README.md](docs/README.md)). Don't claim live validation in code
  comments or docs unless you actually did it and say on what.
- **Commit style:** short imperative subject with a conventional prefix
  (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`). One logical change
  per commit.
- **Error messages** follow the existing pattern: lowercase, actionable,
  name the flag that fixes the problem. Every new user-facing error gets a
  row in [docs/errors.md](docs/errors.md).

### Adding a registry entity

Add one `e("Category", "Display Name", "Tag")` line to
`crates/sfos-sdk/src/registry.rs`, keeping the firewall's menu grouping.
Tags are best-effort from the SFOS API reference and self-validate via
`export_all` against a live box — note in the PR whether the tag is
doc-derived or live-verified.

### Adding a writable (typed) entity

Implement `SophosEntity` (`TAG`, `name()`, `to_xml()`) in
`crates/sfos-sdk/src/entity.rs` with a constructor mirroring the Python
SDK's `create_*` helper, plus a serialization unit test asserting the exact
XML. If it should be `apply`-managed, wire it into `apply::plan` and
`client::EXPORTABLE_ENTITIES` (dependency order matters: referenced objects
before referencing ones) and document it in
[docs/cli-reference.md](docs/cli-reference.md) and
[docs/safety.md](docs/safety.md).

## PR checklist

- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo test --locked` green
- [ ] `cargo deny check` clean (if you touched dependencies)
- [ ] new behaviour has tests; new errors/flags/entities are documented in `docs/`
- [ ] no real-world identifiers in fixtures
- [ ] PR description states what was validated and how (unit tests only vs live firewall)

CI runs build+test on Linux and Windows, `cargo-audit`, `cargo-deny`, and
opengrep SAST on every PR ([docs/ci.md](docs/ci.md)). A red check is a
blocker — don't ask for review with failing CI.

## License & sign-off (DCO)

MIT. By submitting a contribution you agree to license it under the
project's [LICENSE](LICENSE).

Commits must carry a [Developer Certificate of Origin](https://developercertificate.org/)
sign-off asserting you have the right to contribute the code:

```bash
git commit -s        # adds: Signed-off-by: Your Name <you@example.com>
```
