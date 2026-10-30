# Display architecture decision — 2026-02-xx

## Decision

**Choose (c): replace/patch only `ias-backend.so`'s DRM output implementation with a
software-output IAS backend, while retaining the stock `/usr/bin/weston`, `ivi-shell.so`,
IAS shell/protocol surface, and application Wayland clients.**  It must provide a fixed
1920x720 output called `HDMI1` and the `ias_crtc` Wayland global, but render into a
host-capturable software surface rather than open `/dev/dri/card0`.

This is not a permanent substituted compositor: weston proper, IVI surface policy,
`ivi-window-manager.so`, `ivi-controller.so`, client ABI, and the IAS private controls remain
in the running vendor path.  Only the impossible physical scanout adaptation is replaced.
It is therefore the smallest non-hardware adaptation that can credibly support a complete HMI,
rather than proving that Qt clients can draw under a different compositor.

## Why not virtual KMS as the primary route

Option (a) is a useful diagnostic/fallback, but not the delivery architecture.  This 4.1.27
vendor kernel has `CONFIG_DRM=y`, `CONFIG_DRM_KMS_HELPER=y`, modules enabled, and
`CONFIG_DRM_VGEM` unset; it has no in-tree vkms (a modern vkms backport cannot be assumed).
The existing module work is real: `work/kbuild/drmkms/drmkms10.c` has registered `card0`, a
VGA connector, and an advertised 1280x720 mode.  It is nevertheless not a usable KMS device:
it has no 1920x720 HDMI connector, scanout plane, dumb-buffer mapping, page-flip/vblank, or
GBM import contract.  More importantly, it was compiled with vanilla structures while this
LG kernel changes DRM layouts; `RESULTS-graphics-B-vs-C.md` records repeated layout failures.

The analysis's claim that IAS is “pure libdrm+GBM” is unverified and materially optimistic.
`ias-backend.so` has i915 headers/debug references and calls `drmCommandWriteRead`, atomic and
legacy KMS, plane APIs, and i915/intel helper paths.  `kms_swrast` can only help after a
functional generic KMS/GBM allocation-and-scanout path exists; a card node and sysfs mode do
not establish that.  Recreating that contract in the vendor 4.1 DRM ABI is a kernel-driver
project with no host-GPU payoff.

Option (b) has the wrong seam: interposing libdrm/GBM/EGL would have to emulate every KMS,
GBM and likely Intel-private ioctl used by the backend, affects client EGL as well, and makes
faults opaque.  Option (d) permanently excludes the vendor compositor and its IAS controls,
so is only a demo baseline.  A hybrid is acceptable operationally only after this decision:
keep the existing virtual-KMS work as a later compatibility experiment, not the critical path.

## First implementation step

Create `work/vm/vendor-userspace-260128/ias-backend-soft/` and make a loadable
Weston-1.10 backend named `ias-backend.so`.  Start from
`work/weston-source-1.10/full/src/compositor-headless.c` for the pixman/software output and
from the recovered IAS ABI/protocol evidence in the stock
`.../mango-rootfs/usr/lib/weston/ias-backend.so`.  Implement `backend_init`, one 1920x720
`HDMI1` output, repaint/frame callbacks, libinput seat setup, and the exact `ias_crtc`
Wayland interface consumed by `usr/bin/wrandr` (`set_mode`, `set_gamma`, `set_contrast`,
`set_brightness`, `set_fb_transparency`).  Load it through the stock
`etc/xdg/weston/weston_1920.ini`; do not replace `/usr/bin/weston` or its IVI modules.

Before coding beyond module load, compare the vendor Weston's backend ABI (`backend_init` and
`struct weston_backend` symbols/relocations) to this source; the source may not exactly match
the vendor's patched Weston 1.10 ABI.  That is the first static check because an ABI mismatch
invalidates the proposed replacement, not just a rendering feature.

## Riskiest assumption and one-run falsification

The riskiest assumption is that the stock IAS backend's externally visible value is limited to
standard Weston backend callbacks plus the small `ias_crtc` protocol, rather than hidden
IAS-to-i915 semantics required by IVI modules or apps.  In one isolated VM run (when the image
owner permits), install only the soft `ias-backend.so`, retain stock weston/INI/IVI modules,
and start `/usr/bin/weston --tty=1` with a 1920x720 software surface.  Pass only if it creates
the Wayland socket, loads `ivi-shell.so` and both configured IVI modules, `wrandr --crtc=1
--brightness=128:128:128` succeeds, and a stock Qt Wayland client gets frame callbacks.  Any
missing protocol/global or unresolved backend ABI is immediately visible in the weston log and
bounds the remaining interface work.

## Cost and scope

Estimate **2–3 engineer-weeks** to reach the above bring-up/capture milestone and **4–6 weeks**
to preserve enough IAS plane, color, input and lifecycle behavior for sustained HMI operation.
That is materially lower risk than a 6–12+ week bespoke 4.1 DRM/GBM/i915-compat driver, and it
keeps all further work on MICOM, assets, CAN, GPS and input directed at the real HMI stack.

The gap analysis is correct that no i915/card0 exists and that `ias.conf` requests HDMI1, but
wrong/unverified in equating this with a generic, software-KMS-ready backend.  First verify the
vendor backend ABI and enumerate the `ias_crtc` wire protocol before treating its suggested
`drmkms + kms_swrast` path as viable.
