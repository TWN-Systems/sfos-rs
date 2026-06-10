# Building sfos-rs

## Prerequisites

- Stable Rust toolchain (2021 edition). No MSRV is pinned yet; CI tracks
  current stable on `ubuntu-latest` and `windows-latest`.
- Nothing else. TLS is `rustls`, so there is no OpenSSL or other system
  library dependency on any platform. On Windows the standard MSVC toolchain
  builds it as-is.

## Build

```bash
cargo build --release --locked     # -> target/release/sfos-rs (.exe on Windows)
```

**Always pass `--locked`.** `Cargo.lock` is committed and is part of the
supply-chain contract: it pins the exact dependency versions that CI built,
tested, scanned (`cargo-audit`), and policy-checked (`cargo-deny`). A build
that silently resolves different versions has none of those assurances. CI
itself builds with `--locked` everywhere, so a PR that requires lockfile
changes must commit the new `Cargo.lock` explicitly — that diff is exactly
where dependency review happens.

The workspace has two crates:

| Crate | Output |
|---|---|
| `crates/sfos-sdk` | library (also usable as a dependency — see [sdk-guide.md](sdk-guide.md)) |
| `crates/sfos-cli` | the `sfos-rs` binary |

## Test & lint

```bash
cargo test --locked                              # full workspace suite (all offline; no network)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check                                 # advisories, licenses, bans, sources
```

Tests run entirely against fixtures in `crates/sfos-sdk/tests/fixtures/` —
no test touches the network, so the suite runs anywhere (including air-gapped
build environments).

## Using the SDK as a dependency

```toml
[dependencies]
sfos-sdk = { git = "https://github.com/TWN-Systems/sfos-rs", package = "sfos-sdk", rev = "<commit>" }
```

Pin a `rev` (not a branch) so your build is reproducible and immune to
history rewrites — see [supply-chain.md](supply-chain.md#for-consumers).

## Release binaries vs building from source

Tagged releases ship Linux and Windows x86_64 binaries with three
verification artifacts each (`.sha256` checksum, SLSA build-provenance
attestation, Sigstore `cosign` bundle). Verify before running — the exact
commands are in [SECURITY.md](../SECURITY.md#verifying-a-downloaded-release-binary).

Building from source with `--locked` at the release tag is the strongest
verification of all: you reproduce the artifact from the same inputs the
pipeline used. Note that byte-identical output is **not** guaranteed across
different toolchain versions/platforms (Rust builds embed paths and toolchain
metadata), so compare behaviour and provenance, not just hashes.

## Dependency footprint

Direct dependencies, by design kept minimal:

| Crate | Used for |
|---|---|
| `serde` (+derive) | model serialization |
| `quick-xml` | `Entities.xml` / API response parsing |
| `ipnetwork` | CIDR math (reachability, VPN pairing) |
| `thiserror` | `SdkError` |
| `reqwest` (blocking, `rustls-tls`, default-features off) | the live XML API client |
| `clap` (derive) | CLI |
| `serde_json` | JSON output |

If you're adding one, read the dependency policy in
[CONTRIBUTING.md](../CONTRIBUTING.md#conventions) first.
