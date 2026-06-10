# Packaging

Two distribution forms, both built from a single **statically-linked (musl)**
binary with no runtime dependencies. The CLI links no system libraries — TLS is
`rustls` with the webpki root store compiled into the binary — so there is
nothing to dynamically link and no CA-certificate bundle to ship.

## Container image (`Dockerfile`)

A two-stage build: Alpine + Rust compiles the static binary, and the runtime
image is `scratch` — literally just the binary. No shell, no package manager, no
libc, nothing else to attack or patch.

```bash
make docker                       # or: docker build -t sfos-rs .
docker run --rm sfos-rs --help
docker run --rm -v "$PWD:/data:ro" sfos-rs parse /data/Entities.xml
```

- **Size:** ~5 MB total (the stripped binary; the base is `scratch`).
- **User:** runs as uid `65534` (nobody). Mount inputs read-only; mount a
  writable directory if a command writes output files.
- **Base pin:** the builder image is digest-pinned, consistent with the
  SHA-pinned GitHub Actions (`docs/supply-chain.md`). Bump the digest when you
  intentionally move the Rust toolchain.

## Debian package (`packaging/deb/build-deb.sh`)

A `.deb` containing the static binary at `/usr/bin/sfos-rs`. Because the binary
is static, the package declares **no `Depends`** — it installs and runs on any
amd64 Debian/Ubuntu with nothing else pulled in.

```bash
make deb                          # builds the static binary via Docker, then packages → dist/
SFOS_BIN=/path/to/sfos-rs packaging/deb/build-deb.sh   # package a prebuilt static binary

sudo dpkg -i dist/sfos-rs_*_amd64.deb
sfos-rs --version
```

The script refuses to package a dynamically-linked binary (which would need
`Depends`), so the no-dependency guarantee can't silently regress.

## Why static / scratch

The threat model (`docs/supply-chain.md`) values a small, auditable surface. A
`scratch` image and a `Depends`-free package mean the only thing shipped is the
reviewed binary — no distro base image with its own CVE stream, no transitive
system packages, no certificate store to keep current.
