#!/bin/sh
# Cross-build a Weston 1.10 backend plugin for the Gen5W guest (x86_64-linux-gnu).
# Verified to build the unmodified vendored compositor-headless.c into a loadable .so.
set -e
cd "$(dirname "$0")/../../.."
ZIG=${ZIG:-work/toolchains/zig-macos-aarch64-0.13.0/zig}
W=work/weston-source-1.10/full
WAY=work/vm/wayland-1.10.0-src          # wayland 1.10.0 src + generated wayland-server-protocol.h
OUT=tools/uk_fw/ias_backend_soft
SRC=${1:-$W/src/compositor-headless.c}
DST=${2:-$OUT/headless-probe.so}

"$ZIG" cc -target x86_64-linux-gnu -shared -fPIC -O1 \
  -I "$OUT" -I "$W/src" -I "$W/shared" -I "$W" \
  -I "$WAY" -I /opt/homebrew/include/pixman-1 -I /opt/homebrew/include \
  -o "$DST" "$SRC"

file "$DST" | cut -c1-80
nm -D --defined-only "$DST" | grep -E 'backend_init' || true
