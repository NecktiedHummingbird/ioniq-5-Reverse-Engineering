# `ias-backend-soft` — scope for the first slice

Goal: one 1920x720 output named `HDMI1` that the vendor IAS control path can drive, without any DRM
device. This is the smallest slice of the decided display architecture that produces something
reviewable. Evidence below is from the shipped binaries and the Weston 1.10 tree.

## Backend ABI (verified)

- Weston loads backends with `dlsym(module, entrypoint)` as seen in `compositor.c:4995`.
- The entrypoint in this build is **`backend_init`**, not `weston_backend_init`: both
  `ias-backend.so` and `headless-backend.so` export `T backend_init`.
- Signature, from `work/weston-source-1.10/full/src/compositor-headless.c:260`:
  `WL_EXPORT int backend_init(struct weston_compositor *compositor, int *argc, char *argv[])`.
- `ias-backend.so` additionally exports the two protocol interfaces a soft backend must replace:
  `ias_crtc_interface` (`0x220f40`) and `ias_mode_interface` (`0x221060`).

## IAS protocol surface (extracted from `ias-backend.so` `.data`)

`struct wl_interface` parsed at the symbol addresses, with vaddr→file-offset mapping via PT_LOAD:

**`ias_crtc` — version 1, 5 methods, 4 events**

| kind | name | signature |
|---|---|---|
| method | `set_mode` | `u` |
| method | `set_gamma` | `uuu` |
| method | `set_contrast` | `uuu` |
| method | `set_brightness` | `uuu` |
| method | `set_fb_transparency` | `u` |
| event | `mode` | `uuuu` |
| event | `gamma` | `uuu` |
| event | `contrast` | `uuu` |
| event | `brightness` | `uuu` |

**`ias_mode` — version 1, 1 method, 0 events**

| kind | name | signature |
|---|---|---|
| method | `add` | *(empty)* |

This matches what `wrandr` drives exactly: its usage string offers `--crtc=<#>`, `--mode=<#>`,
`--gamma=red:green:blue`, `--brightness`, `--contrast` and `--enable`, which map one-to-one onto the
methods above. Any soft backend must publish these two interfaces or `wrandr` and `ias-shell` cannot
address an output.

## Implementation plan

1. Copy `compositor-headless.c` as the base; it already provides a pixman software renderer and an
   output with configurable mode, which is the part that usually needs a GPU.
2. Rename the created output to `HDMI1`, fix the mode at 1920x720, and keep `ias.conf`'s
   `<crtc name='HDMI1'>` unmodified — the config stays vendor-authentic rather than being edited to
   match our backend.
3. Add the two `wl_interface` tables above and the resource creation for them, so `wrandr` enumerates a
   CRTC and can enable it.
4. Build for `x86_64-linux-gnu` with the bundled zig 0.13.0 (`zig cc -target x86_64-linux-gnu`), since
   the host is arm64 and there is no system cross-gcc.

## Immediate blocker

**No pixman headers.** The image ships `usr/lib/libpixman-1.so.0.42.2` (runtime) but `pixman.h` exists
nowhere in the tree, and `compositor-headless.c` includes it. Compiling needs either the pixman 0.42.2
headers or a minimal hand-written declaration of the handful of `pixman_image_*` and `pixman_region_*`
symbols that the headless renderer actually calls. That choice is the first decision the build forces.

## Falsification for the slice

Run `weston --backend=ias-backend-soft.so --shell=ias-shell.so`, then:
- `wrandr` must list a CRTC rather than only unhandled globals;
- `wrandr --crtc=0 --enable=true` must succeed;
- `weston-info` must report a `wl_output` at 1920x720 named `HDMI1`.

If `wrandr` lists no CRTC, the interface tables or their resource creation are wrong.
