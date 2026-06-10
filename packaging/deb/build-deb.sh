#!/usr/bin/env bash
# Build a Debian package for sfos-rs from the static (musl) binary.
#
# The binary is statically linked, so the package has NO Depends — it installs
# and runs on any amd64 Debian/Ubuntu with nothing else pulled in.
#
#   packaging/deb/build-deb.sh                 # builds the static binary via Docker, then packages
#   SFOS_BIN=/path/to/sfos-rs build-deb.sh     # package an already-built static binary
#   OUT_DIR=/tmp build-deb.sh                   # choose the output directory (default: dist/)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
ver="$(grep -m1 '^version' "$root/Cargo.toml" | sed -E 's/.*"(.*)".*/\1/')"
arch="amd64"
out_dir="${OUT_DIR:-$root/dist}"
bin="${SFOS_BIN:-}"

# Obtain a static binary. Default: the Dockerfile's builder stage (Alpine/musl),
# which produces the same artifact the container ships — reproducible and static.
cleanup_bin=""
if [ -z "$bin" ]; then
  echo ">> building static binary via the Dockerfile builder stage"
  docker build -t sfos-rs:build --target builder "$root"
  cid="$(docker create sfos-rs:build)"
  bin="$(mktemp)"; cleanup_bin="$bin"
  docker cp "$cid:/src/target/release/sfos-rs" "$bin"
  docker rm "$cid" >/dev/null
fi

# Refuse to ship a dynamically-linked binary as a no-Depends package.
if file "$bin" | grep -q 'dynamically linked'; then
  echo "error: $bin is dynamically linked; this package declares no Depends." >&2
  exit 1
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"; [ -n "$cleanup_bin" ] && rm -f "$cleanup_bin"' EXIT
pkg="$stage/sfos-rs_${ver}_${arch}"

install -Dm0755 "$bin" "$pkg/usr/bin/sfos-rs"
install -Dm0644 "$root/LICENSE" "$pkg/usr/share/doc/sfos-rs/copyright"
install -d "$pkg/DEBIAN"
cat > "$pkg/DEBIAN/control" <<EOF
Package: sfos-rs
Version: ${ver}
Section: utils
Priority: optional
Architecture: ${arch}
Maintainer: TWN Systems <dev@clayatownsend.com>
Installed-Size: $(( ($(stat -c%s "$bin") + 1023) / 1024 ))
Homepage: https://github.com/TWN-Systems/sfos-rs
Description: Sophos SFOS firewall configuration analysis, search & live XML API CLI
 sfos-rs parses an Entities.xml backup offline, or authenticates to a live
 Sophos firewall over the XML API, pulls the full configuration, and produces
 reports. Statically linked (musl) with no runtime dependencies.
EOF

mkdir -p "$out_dir"
deb="$out_dir/sfos-rs_${ver}_${arch}.deb"
dpkg-deb --build --root-owner-group "$pkg" "$deb"
echo ">> built $deb"
