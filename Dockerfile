# syntax=docker/dockerfile:1
#
# sfos-rs — ultra-minimal container.
#
# The CLI is a single Rust binary with no system-library dependencies: TLS is
# `rustls` (webpki roots compiled in), so there is nothing to dynamically link
# and no CA-certificate bundle to ship. Built static against musl in an Alpine
# Rust image, the runtime image is therefore `scratch` — literally just the
# binary, nothing else to attack or update.
#
#   docker build -t sfos-rs .
#   docker run --rm sfos-rs --help

# ---- builder: Alpine + Rust → one fully static musl binary ----
# Digest-pinned (rust 1.96, Alpine) to match this repo's pin-everything posture.
FROM rust:1-alpine@sha256:66f48b19d6e88519e2e58bebe0d945779a6a4ca41c2db17db78c9569655b50ac AS builder

# build-base pulls gcc + musl-dev + binutils — ring (the rustls crypto backend)
# compiles C, and we strip the result. Builder layer is discarded.
RUN apk add --no-cache build-base

WORKDIR /src
COPY . .

# rust:alpine's host target is x86_64-unknown-linux-musl, which links static by
# default (crt-static). --locked pins to the committed Cargo.lock.
RUN cargo build --release --locked -p sfos-cli \
 && strip target/release/sfos-rs

# ---- runtime: nothing but the binary ----
FROM scratch
COPY --from=builder /src/target/release/sfos-rs /sfos-rs

# Run as an unprivileged uid (numeric: scratch has no /etc/passwd).
USER 65534:65534

ENTRYPOINT ["/sfos-rs"]
