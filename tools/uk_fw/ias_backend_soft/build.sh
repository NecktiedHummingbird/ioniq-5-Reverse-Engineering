#!/bin/sh
# Cross-build a Weston 1.10 backend plugin for the Gen5W guest (x86_64-linux-gnu).
# Verified to build the unmodified vendored compositor-headless.c into a loadable .so.
#
# The real ias backend (output + ias_crtc/ias_mode) is built with the same flags
# plus two more sources, since `parse_options` is not exported by the guest's weston:
#   $0 ias-backend-soft.c ias-backend-soft.so \
#       ias_protocol.c ../weston-source-1.10/full/shared/option-parser.c
set -e
cd "$(dirname "$0")/../../.."
ZIG=${ZIG:-work/toolchains/zig-macos-aarch64-0.13.0/zig}
W=work/weston-source-1.10/full
WAY=work/vm/wayland-1.10.0-src          # wayland 1.10.0 src + generated wayland-server-protocol.h
OUT=tools/uk_fw/ias_backend_soft
SRC=${1:-$W/src/compositor-headless.c}
DST=${2:-$OUT/headless-probe.so}
shift 2 2>/dev/null || true

# Host header locations for the cross build. Override PIXMAN_INC / XKB_INC if your
# prefix is not the local Homebrew one; nothing here assumes a specific machine layout.
BREW_PREFIX=${BREW_PREFIX:-$(brew --prefix 2>/dev/null || echo /usr/local)}
PIXMAN_INC=${PIXMAN_INC:-$BREW_PREFIX/include/pixman-1}
XKB_INC=${XKB_INC:-$BREW_PREFIX/include}

# The guest's weston is LG-patched: its struct weston_output/weston_seat/
# weston_compositor carry extra members, so a header taken from upstream 1.10
# produces a plugin that writes 0x18 bytes too low and segfaults weston in
# bind_output. vendor-abi.patch restores the vendor layout; applied idempotently.
if ! grep -q 'Vendor additions, present in the shipped weston binary' "$W/src/compositor.h"; then
  ( cd "$W" && patch -p1 --forward < "../../../$OUT/vendor-abi.patch" )
  grep -q 'Vendor additions, present in the shipped weston binary' "$W/src/compositor.h"
fi

"$ZIG" cc -target x86_64-linux-gnu -shared -fPIC -O1 \
  -I "$OUT" -I "$W/src" -I "$W/shared" -I "$W" \
  -I "$WAY" -I "$PIXMAN_INC" -I "$XKB_INC" \
  -o "$DST" "$SRC" "$@"

file "$DST" | cut -c1-80
nm -D --defined-only "$DST" | grep -E 'backend_init' || true
