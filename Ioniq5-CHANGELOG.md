# IONIQ 5 changelog

All entries describe the IONIQ 5 research programme. The root `CHANGELOG.md`
belongs to the parallel Kona programme and is not modified by IONIQ work.

## 1.15.0 - IAS protocol extracted; soft-backend slice scoped

- The IAS control protocol is now known exactly, extracted from `ias-backend.so`'s `.data` by parsing
  `struct wl_interface` at the exported symbol addresses (`0x220f40`, `0x221060`) with a proper
  vaddr-to-file-offset mapping through PT_LOAD.
- **`ias_crtc` v1**: methods `set_mode(u)`, `set_gamma(uuu)`, `set_contrast(uuu)`, `set_brightness(uuu)`,
  `set_fb_transparency(u)`; events `mode(uuuu)`, `gamma(uuu)`, `contrast(uuu)`, `brightness(uuu)`.
  **`ias_mode` v1**: one method, `add()`. This maps one-to-one onto `wrandr`'s documented options, which
  confirms the tool drives exactly this interface and is not an unrelated shim.
- Backend ABI confirmed for this build: the entrypoint is **`backend_init`**, not
  `weston_backend_init`, with signature
  `WL_EXPORT int backend_init(struct weston_compositor *, int *argc, char *argv[])`
  (`compositor-headless.c:260`), loaded via `dlsym` at `compositor.c:4995`.
- First slice scoped (`evidence/vm-bringup/ias-backend-soft-scope.md`): derive from
  `compositor-headless.c`, rename the output `HDMI1` at 1920x720 so the vendor `ias.conf` stays
  unmodified, and publish the two interface tables so `wrandr` can enumerate and enable a CRTC.
- **Immediate blocker, stated plainly: there are no pixman headers.** The image ships
  `libpixman-1.so.0.42.2` as a runtime only, and `compositor-headless.c` includes `pixman.h`. The build
  therefore needs either the pixman 0.42.2 headers or a hand-written declaration of the small
  `pixman_image_*` / `pixman_region_*` surface the renderer uses. The bundled zig 0.13.0 handles the
  `x86_64-linux-gnu` cross build.
- Falsification defined before any code is written: `wrandr` must list a CRTC, `wrandr --crtc=0
  --enable=true` must succeed, and `weston-info` must report a 1920x720 `HDMI1` output.

## 1.14.0 - ias_shell is live on the compositor; scanout is closed off by the kernel config

- The vendor compositor now exposes its own IAS interface and an output. `wrandr` enumerates the
  registry and reports **`ias_shell`** among the globals, and `weston-info` reports `wl_output` version 2
  alongside `wl_compositor`, `wl_scaler`, `presentation` and `wl_seat`. With `ias-shell.so` loaded and
  its config accepted, the stack is coherent rather than merely running.
- **Scanout is definitively unavailable**, and the kernel configuration settles it rather than an
  experiment: `CONFIG_DRM_I915=y` is the only DRM driver present. `CONFIG_DRM_FBDEV_EMULATION` is not
  set, and `CONFIG_DRM_BOCHS`, `CONFIG_DRM_VIRTIO_GPU`, `CONFIG_DRM_UDL`, `CONFIG_FB_VESA`,
  `CONFIG_FB_SIMPLE` and `CONFIG_FB_EFI` are all absent. So no `/dev/fb*` can exist for
  `fbdev-backend.so` to bind, and no `/dev/dri/card0` can appear unless i915 binds — which QEMU cannot
  cause, since it emulates no Intel IGD.
- This closes the "just use the fbdev backend" option permanently and confirms the display decision was
  correct: a virtual KMS driver or a patched software IAS backend are the only routes to a visible
  surface, and the image's own headless backend is the only one that works today.
- `opt/ias/` is an empty OEM mount point in the rootfs — `bin` and `lib` exist and are empty — so the
  `grid_layout.so` that `ias.conf` references as `defer="1"` is genuinely absent, not misplaced. That
  matches the absence of any complaint about it: the shell treats the layout plugin as deferred.
- Net position: the HMI stack runs, its control interface is live, an output exists on the protocol
  level, and nothing is rendered to a framebuffer. That is the exact boundary the display decision
  addresses.

## 1.13.0 - IAS shell initialised with the vendor config; `/media` resolves to world-writable

- The compositor now loads `ias-shell.so` **with its configuration**, and the IAS error is gone. The
  path is `$XDG_CONFIG_HOME/ias.conf` exactly — not `$XDG_CONFIG_HOME/.config/ias.conf` — which is why
  the vendor ships it at `etc/xdg/weston/.config/ias.conf`. With `XDG_CONFIG_HOME=/tmp/ias` holding a
  copy and the CRTC renamed from `HDMI1` to the headless backend's `headless-0`, the shell initialises
  without complaint, `wayland-0` exists, and `NaviUpdateApp` stays attached with only the benign
  `QDBusConnection` warning.
- `esinit` sets `XDG_RUNTIME_DIR="/run/user/root"` (line 148), so the earlier `/tmp/xdg` was a
  research-side invention; the vendor path is now used.
- **V-011's weakest link is resolved, in the more serious direction.** `etc/fstab_emmc:8` mounts
  `tmpfs /media tmpfs defaults`, nothing in the tree sets a mode or owner (no `tmpfiles.d` entry, no
  `/media` reference in `esinit`), and the kernel's tmpfs root default is `01777`. So `/media` is very
  likely world-writable and sticky while the per-device subdirectories are `0755 root:root`: an
  unprivileged process can create entries in `/media` but cannot rename root's.
- That sharpens V-011 rather than changing its precondition. Because the kernel interprets a device
  node's own recorded uid/gid/mode, an attacker crafting an image sets the node `0666` and defeats
  `0660 root:disk` entirely — unprivileged read and write of **internal** storage, not merely removable
  media. Physical USB access is still required; what changes is scope.
- The `..` serial vector remains an amplifier, now with a plausibly writable mount root. Recorded as
  unverified, with the specific test that would settle it.

## 1.12.0 - the vendor compositor runs and the UI connects to it

- No build was needed to get a compositor: the image already ships **`headless-backend.so`** and
  **`fbdev-backend.so`** alongside `ias-backend.so`, so the vendor's own weston can run without a DRM
  device.
- Running `/usr/bin/weston --backend=headless-backend.so --shell=/usr/lib/weston/ias-shell.so` with
  `XDG_RUNTIME_DIR` set produces a live socket: `wayland-0` and `wayland-0.lock` appear, weston stays
  alive, and `ias-shell.so` loads.
- **`NaviUpdateApp` no longer fails on display.** It stays alive and its only remaining output is the
  benign `QDBusConnection: session D-Bus connection created before QCoreApplication` warning. The
  earlier `Failed to create display (No such file or directory)` is gone, which means the UI process
  connects to the vendor compositor.
- Two ordinary obstacles were cleared on the way. Weston initially quit because it could not launch
  `/usr/libexec/weston-desktop-shell`; that is the wrong shell for this product, and `ias-shell.so` is
  the right one. And `ias-shell` then reported
  `Failed to open IAS config file (//.config/ias.conf)` because `HOME` is unset, so the config path
  collapses to `//.config/ias.conf` instead of the vendor's `etc/xdg/weston/ias.conf`.
- Next: supply the IAS config so the shell initialises its outputs, confirm a surface is created, and
  then replace the headless backend with real scanout — which is where the display architecture
  decision applies.

## 1.11.0 - the MICOM daemon's exit was the missing device, and the gate is now the compositor

- **`micommanager` starts successfully** on the authentic multi-user boot once `/dev/ttyS1` exists:
  `Starting System service for micommanager`, the daemon logging its own banner
  (`micommanager_userspace release data : 2015.10.19`), then `Started System service for micommanager`.
- That corrects the previous reading. The `status=1/FAILURE` that appeared to block
  `ApplicationLauncher`'s hard `Requires=` was simply the absent serial device: the earlier multi-user
  run was booted without `--micom-serial`. No protocol work was needed to satisfy the dependency, and
  the reply/frame simulator is therefore not on the critical path for the HMI.
- With the daemon up, `Reached target Multi-User System` stands and the next failure is upwards of it:
  `nua.service` restarts three times from 64.4 s and then hits `start-limit`. The daemon exits 1 each
  time, and the earlier standalone repro gives the reason: `XDG_RUNTIME_DIR not set in the environment`
  and `Failed to create display (No such file or directory)`.
- So the operative blocker is now the one the display decision predicted: **nothing creates a Wayland
  compositor, a runtime directory, or a socket**. There is no `weston.service` in the image at all,
  only `weston-crash.path`, and esinit's own weston launch is still gated off by `/tmp/spi_validation_NOK`.
- Both workers dispatched for this round returned no result and wrote nothing to disk; the finding above
  came from re-reading an existing run rather than from new work. Recorded plainly rather than presented
  as progress by delegation.

## 1.21.0 - Constrain ConnMan CVE-2023-28488 to the exact fortified outcome

- Confirmed CVE-2023-28488's pre-fix IPv4 total-length ordering in exact
  `connmand` instructions rather than inferring from the recovered package
  version.
- Mapped ordinary IPv4 startup through `INIT_SELECTING`, listening mode 1, an
  `AF_PACKET` datagram socket, and the affected GLib receive callback.
- Established that this exact build calls `__memcpy_chk` with a 628-byte object
  size. Every recovered libc checked-copy implementation reviewed reaches
  `__chk_fail`/`__fortify_fail` before copying an underflowed length.
- Added a packet-free exhaustive arithmetic model and tests. All 43,057,152
  combinations of possible 0..656-byte reads and 16-bit IP total lengths divide
  into short/partial rejects, 17,612 fortified abort cases, and 198,135 bounded
  copies; the model opens no socket and creates no packet bytes.
- Recorded V-016 as a conditional adjacent-network ConnMan availability issue,
  not a stack overwrite, RCE, or root path for recovered `260128`. No packet was
  generated, the NIC-free VM was unchanged, and the owner's installed build
  remains unknown.
- Preserved official responses, decoded upstream fix, full source/disassembly,
  Ghidra records, and generated JSON under ignored `work/`; tracked only the
  model, tests, report, planning checkpoint, and sanitized evidence excerpt.

## 1.20.0 - Recover exact package inventory and confirm the ConnMan DHCPv6 candidate

- Recovered 1,679 exact installed-package records from the RPM Berkeley DB
  `Nvra` index using a read-only project-local Berkeley DB 18.1.40 `db_dump`.
  Added `tools/uk_fw/rpm_nvra_inventory.py` and focused tests for strict,
  deterministic parsing of printable dump records, exact package selection,
  symlink rejection, malformed-input failure, and atomic output replacement.
- Identified `connman-1.29+5w.master.38-r1.corei7_64`, then confirmed
  CVE-2026-115863 from exact shipped instructions rather than the version label.
  `connmand+0x1f150` makes the fixed 1,025-byte DOMAIN_LIST copy and performs the
  unbounded label-pointer `'.'` stores; option-24 dispatch calls it directly.
- Mapped the exact conditional route: the connected-network RA callback handles
  Managed/Other flags, the Other path starts a DHCPv6 information request, and
  that routine explicitly requests option 24. The installed uid-0 service does
  not exclude intended `wlan0` and uses `Restart=on-failure`.
- Recorded trigger gates and mitigations: a reply still must match live DHCPv6
  transaction/client/server/state checks, while the ELF has PIE, NX stack,
  stack canaries, and full RELRO. No packet was sent and no crash, RCE, root
  access, or physical-device applicability is claimed.
- Kept the full database dump, source, disassembly, decompiler output, and online
  responses under ignored `work/`; tracked only the parser, tests, conservative
  report, and sanitized evidence excerpt.
- Fable remained unavailable for native delegation, and the previously checked
  DeepSeek Flash route remained rejected by the native dispatcher; no silent
  substitute or failed worker output was used.

## 1.19.0 - Confirm synthetic udev activation and map the thumbnail ASF route

- Added `tools/uk_fw/udev_systemd_probe.py` and focused tests for matched
  negative/positive controls using exact recovered `systemd`, `systemd-udevd`,
  and `udevadm` binaries.
- Both offline runs used `-nic none`, snapshot-backed storage, a read-only root,
  transient `/run` files, and a minimal custom target layered on installed
  sysinit. The vulnerable persistent-storage and V4L helper rules were masked
  before coldplug; no shipped vulnerable helper or pre-existing property-selected
  unit was selected.
- The negative synthetic-add run persisted only fixed `ID_SCSI_SERIAL` and kept
  the marker unit inactive. The positive run added fixed `SYSTEMD_WANTS`, exact
  PID 1 logged the otherwise-unreferenced transient marker unit starting, and
  fixed marker-file/active-state checks passed.
- Extended `vm_boot.py` with an optional exact terminated serial-completion line
  for safe PID-1 handoff diagnostics, preserving all default behavior.
- Preserved the boundary: this confirms synthetic udev database/device-unit and
  manager semantics, not hardware bytes reaching shipped helpers, a physical
  device, the installed shell unit, root access, interactivity, or persistence.
- Fable remained unavailable for native subagents. DeepSeek Flash passed static
  route checks but native dispatch was rejected as an unknown model; no failed
  worker output or silent substitute was used.
- Corrected V-012's thumbnail model using exact binaries. MediaBrowser's
  `requestThumbnails(as)` forwards to the extractor's session-bus `Start(as)`;
  that method always selects `VideoContext`, whose exact pipeline is
  `uridecodebin ... appsink` and whose autoplug callback does not reject
  `asfdemux`. The separate audio/TagLib context is for cover art.
- Preserved the reachability boundary: reviewed scan callbacks do not request
  thumbnails, and bounded VM attempts observed no delivered `Start`, ASF-plugin
  map, cache output, or natural crash. The new evidence is a static explicit
  client-request route, not automatic USB/UI invocation or dynamic thumbnail
  corruption.

## 1.18.0 - Confirm benign second-property retention in the exact udev parser

- Added `tools/uk_fw/udev_import_probe.py` and focused tests for a fixed,
  parser-only offline diagnostic. The tool verifies exact recovered `udevadm`
  and `systemd-udevd` hashes, uses only `udevadm test`, sends no uevent, starts
  no daemon or service, and names only an intentionally nonexistent benign unit.
- Matched the advisory's security-relevant two-line shape: fixed synthetic output
  contained `ID_SCSI_SERIAL=V014_BENIGN_CONTROL` followed by a leading-space
  ` SYSTEMD_WANTS=v014-benign-nonexistent.service` line.
- The exact recovered rule engine executed the synthetic import helper, recorded
  the raw leading-space line, and emitted the normalized separate property
  `SYSTEMD_WANTS=v014-benign-nonexistent.service`. The helper, rule, and log were removed,
  the command exited zero, and classification was
  `benign-second-property-retained`.
- Preserved the boundary: shipped vulnerable helpers were not executed; udevd,
  a kernel uevent, systemd manager, existing unit, root shell, and privilege
  transition were not involved. This closes the downstream import-parser step,
  not physical hardware delivery or root activation.
- DeepSeek Flash passed static route checks but native dispatch still rejected
  its model as unknown; Fable remains unavailable for native subagents. No
  failed worker output or silent substitute was used.

## 1.17.0 - Exact udev helper injection reaches a shipped root-shell unit

- Added `tools/uk_fw/privilege_surface.py`, a deterministic standard-library
  scanner for extracted Linux root filesystems, with focused tests and explicit
  limits for host-visible modes, xattrs, systemd parsing, loader paths, and udev
  rules. The bounded ignored report walked 236,552 entries and 102 services.
- Confirmed no setuid/setgid entries in the extracted metadata or reviewed
  source archives. The 129 writable-executable-mode results are mostly `/navi`
  files whose original archive modes are `0777`, while normal fstab policy
  mounts `/navi` read-only; this is not promoted to a write or root path.
- Added V-014 for CVE-2026-40225. Exact shipped `v4l_id` and `scsi_id`
  instructions directly print kernel-provided fields without the upstream
  control-character checks. Installed rules invoke both helpers, execute
  injected `REMOVE_CMD`, and expose block-device `SYSTEMD_WANTS` to systemd.
- Identified the decisive installed target: `debug-shell.service` is configured
  to start `/bin/sh` as root on `/dev/tty9` when its path condition passes. This
  yields a high-confidence static malicious-SCSI-device-to-root-console path
  without requiring an attacker-
  written unit file.
- Closed one narrow runtime condition safely: an offline VM control confirmed
  `/dev/tty9` exists as `root:root` mode `0600`, character device `4:9`, under
  the recovered vendor kernel/userspace and research init. It did not start the
  service or inject a property.
- Preserved the remaining runtime boundary: no malicious hardware, authentic
  injected udev event, systemd service activation, VT9 interaction, root
  command, or installed-head-unit applicability was demonstrated.
- Recorded mixed component provenance rather than trusting one banner: PID 1
  and pkg-config report `225`, while embedded build paths say
  `systemd/1_249.3-r0`. Exact binary instructions and installed rules—not either
  version string—establish the finding.
- Kept V-006 rejected as USB-to-root. Its sanitized `usb_id`
  `ID_SERIAL_SHORT` path is distinct from V-014's unsanitized `v4l_id` and
  `scsi_id` helper output.

## 1.16.0 - LightMediaScanner indexing is not the V-012 GStreamer route

- Confirmed authentic `startup-scan=true` handling of a 33-stream ASF/WMA under
  `/media/usb/probe`. LightMediaScanner discovered the USB path, processed one
  file, committed it with zero reported errors, and remained alive.
- Identified the exact scanner parser:
  `/app/lib/lightmediascanner/plugins/asf.so`, SHA-256
  `f4b42a8eacb73990d35439e27513c28f1d31257488d0c130e6e1a936cb9bb219`.
  It imports direct `open`/`read`/`lseek` and LightMediaScanner database APIs;
  it has no GStreamer dependency or `gst_*` import.
- Captured an unfiltered bounded session-bus interaction. It contains scanner
  registration, properties, `Scanner1.Scan`, and progress signals, but no
  PlayerEngine or thumbnail-service call.
- Classified this as a route-specific negative result for V-012: automatic
  LightMediaScanner indexing is real, but it does not invoke vulnerable
  `asfdemux` in this path. Post-index media-manager/browser selection, thumbnail,
  and playback handoff remain open.
- Added a minimally sufficient tracked excerpt under
  `evidence/artifacts/media-candidates/lightmediascanner-asf-evidence.txt` and
  updated the primary V-012 report, register, inventory, handover, and priorities.

## 1.15.0 - PlayerEngine reaches the ASF corruption and vendor offsets are exact

- Corrected the PlayerEngine contract: accepted audio options are nested JSON,
  `{"option":{"mediatype":"audio"}}`; old flat calls were negative contract
  controls. Stock audio is `alsasink` on `media_mixer`.
- Isolated the remaining VM prerequisite. QEMU reports no soundcards, so stock
  `media_mixer` fails. A disposable VM-only ALSA `type null` mapping for that
  exact PCM lets a valid one-stream WMA return true and reach `asfdemux` without
  changing the vendor sink factory or device name.
- Confirmed the boundary under one environment: one-stream and 32-stream file
  URIs return true and PlayerEngine survives; 33- and 34-stream inputs return
  true, enter the vulnerable range, and terminate PlayerEngine with signal 11.
  A plain path returns false while `file:///tmp/input.wma` succeeds.
- Extracted the exact fatal stack:
  `g_queue_push_head+0x1d <- libgstasf.so+0xb6cc <- libgstasf.so+0x1305d`.
  The shell marker `PLAYERENGINE_ALIVE=1` means `kill -0` failed and the process
  had died; 0 means alive.
- Corrected the source-derived layout against the shipped plugin. The vendor
  `AsfStream` stride is 208 bytes, not 200. The 33rd stream zeros the low 32
  bits of `flowcombiner`; its pad pointer lands in `old_stream[0]`. Exact code at
  `0xb6c0..0xb6c7` loads the corrupted combiner and calls
  `gst_flow_combiner_add_pad`, leading to the observed GLib failure.
- Preserved the boundary: this proves manual uid-0 PlayerEngine service
  reachability, memory corruption, and process death—not attacker-selected
  pointer control, RCE, persistence, automatic removable-media/indexer
  invocation, or physical-head-unit applicability.
- Added minimally sufficient tracked excerpts under
  `evidence/artifacts/media-candidates/` and updated V-012, the exploit
  inventory, corrections log, handover, and prioritization.

## 1.14.0 - adjacent ALSA CVEs split by exact lock and permission evidence

- Rejected ALSA PCM CVE-2017-0861 for recovered EU `260128`: exact shipped
  `snd-pcm.ko` takes the per-PCM open mutex around `snd_pcm_info_user`, matching
  the complete two-line upstream fix.
- Confirmed that ALSA sequencer CVE-2018-1000004's native ioctl path lacks the
  per-client serialization in the mainline and Linux 4.1 stable fixes.
- Kept the reachability boundary explicit: the published sequencer-pool race
  requires concurrent `write()` activity, while recovered `/dev/snd/seq` policy
  is `root:root 0644`. The VM confirmed V-013 ioctls through an `O_RDONLY`
  descriptor under that manually modeled mode, but an ordinary user cannot
  obtain the write-capable descriptor required by this sibling sequence.
- Added tracked upstream patches, exact relocation-aware function
  disassemblies, provenance commands, and
  `evidence/vendor-kernel-alsa-follow-up-cves.md`. No new root path is claimed.

## 1.13.0 - exact ALSA/UFO kernel candidates and a bounded sequencer diagnostic

- Added V-013 for CVE-2017-15265 after exact `snd-seq.ko` review showed the
  pre-fix port lifetime flow. The finding is grounded in module instructions,
  not the `4.1.27-abl` banner.
- Added `tools/uk_fw/alsa_seq_probe.py`, a no-network, snapshot-backed harness
  for a freestanding single-create/delete diagnostic. It hash-verifies the
  transferred probe and runs it as numeric uid/gid 65534 under the recovered
  `root:root 0644` DAC mode. The run confirmed read-only open, client-ID,
  create-port and delete-port reachability.
- Preserved the impact boundary: a separate bounded race issued 200,000 create
  and 400,000 delete attempts without a kernel fault. No dynamic UAF,
  controlled reuse, privilege transition, or arbitrary execution is claimed.
- Confirmed exact pre-fix IPv4 and IPv6 logic for CVE-2017-1000112. This remains
  conditional because `CONFIG_USER_NS=n` blocks the published unprivileged root
  setup, production `NETIF_F_UFO` features are unknown, and the VM remains
  intentionally NIC-free.
- Rejected CVE-2016-0728 through exact `join_session_keyring` evidence: the
  shipped function contains the missing-reference `key_put()` operation. Added
  correction C22.
- Added dedicated evidence reports, updated the kernel triage and exploit
  inventory, and retained all version-derived claims as candidates until exact
  shipped code and reachability are established. Canonical validation reports
  `196 passed, 25 subtests passed`; the canonical rootfs hash and clean
  `e2fsck -fn` counts remain unchanged.

## 1.12.0 - the MICOM daemon does transmit first, and the command table exists

- Measured on the authentic multi-user boot with `--micom-serial`: **1056 bytes, 103 frames** on
  `/dev/ttyS1`, against `micom_serial_bytes: 0` on every earlier attempt. The contract's weakest link
  is now closed by measurement rather than argument.
- **The daemon transmits before it receives.** It does not wait for a MICOM-init frame, so a passive
  peer suffices to reach the ask stage. The earlier zero-byte observation was an artefact of a
  transcript filter that watched a single fd, not a protocol precondition.
- The frame format is confirmed on real traffic and not merely in the validator: all 103 frames parse
  as `AA id_hi id_lo L payload CS` with whole-frame XOR zero, and none are malformed.
- The command-id table that no static table in the binary encodes now exists empirically: `0x0400`
  ×32, `0x01a4` ×20, `0x029d` ×13, `0x0266` and `0x0210` ×10 each, `0x0212` ×5, `0x0201` ×4,
  `0x02a3` ×3, `0x0289` ×2, then `0x01aa` (payload `01`), `0x02c3`, `0x0217` and `0x0110` singly. The
  run opens with `0x0212` ×3, then `0x01aa(01)`, then `0x0212` ×2, `0x02c3`, `0x0266`, `0x0201`.
- Still open: which id is `AskSysBootinfo`, and so which frame must carry the 35-byte `ay`. The
  launcher's static sequence places it second, making `0x01aa (01)` then the first `0x02c3` the leading
  candidates, answerable in one run by replying to all ids and observing which reply the launcher's
  field decoder actually consumes.
- A delegated worker on this task was cut off before producing anything; the measurement above was
  taken directly instead. `micom-contract.md` was unchanged by that worker, so nothing is being
  credited to it that it did not do.

## 1.11.0 - bounded Tuxera harness and exact kernel-backport checks

- Added `tools/uk_fw/tuxera_fs_probe.py` and its tests: a no-network,
  snapshot-backed harness that attaches only a project-local regular raw image
  with QEMU `readonly=on`, loads one exact vendor filesystem module, mounts with
  `ro,nodev,nosuid,noexec`, and performs bounded metadata enumeration.
- Switched the harness from QEMU xHCI to EHCI after authentic `xhci-pci` faulted
  in vendor `xhci_toggle_dis_perr_det()`. EHCI with the authentic `ehci-pci`
  module is stable; the xHCI result is recorded as a VM compatibility issue, not
  a production vulnerability.
- Authentic Tuxera exFAT `3016.6.23.3` cleanly mounted a 64 MiB control. Sixteen
  malformed upstream exfatprogs fixtures yielded three clean rejections and
  thirteen clean bounded mounts/unmounts, with no detected kernel parser fault.
  This is a bounded negative result rather than evidence of parser safety.
- Generated a clean 64 MiB NTFS 3.1 control with project-local Alpine `mkntfs`;
  exact Tuxera NTFS `3016.7.1.2.3` mounted and unmounted it cleanly. The V-011
  harmless semantics test then retained character node `1:3` across remount.
  Numeric uid/gid 65534 under SMACK `_` opened QEMU `/dev/null` read-only when
  `nodev` was omitted; the `nodev` control denied the same open. This confirms a
  device-policy bypass primitive, not a demonstrated USB-to-root path.
- Exact recovered-binary analysis rejects four version-derived local-root
  candidates for EU `260128`: Dirty COW/CVE-2016-5195, AF_PACKET
  CVE-2016-8655, AF_PACKET CVE-2017-1000111, and the generic Stack Clash
  missing-guard-gap premise. The vendor kernel contains the relevant
  `FOLL_COW`, socket-locking, and 1 MiB inter-VMA guard-gap backports despite its
  `4.1.27-abl` banner.
- Added dedicated evidence reports and corrections C18-C21. V-011 remains a
  hardening gap/post-execution primitive: production mount-path access, useful
  major/minor selection, application SMACK labels, and any root consequence are
  still unverified.

## 1.09.0 - normal multi-user reached; the blockers are now the two known ones

- **`Reached target Multi-User System`**, startup 10.6 s kernel plus 46.9 s userspace, no emergency
  mode, `dlt-daemon` writing to `/log_data/kernel/*.dlt`. The authentic vendor boot now completes.
- Two ordinary defects were in the way rather than anything architectural. `/bin/check-mount.sh` ships
  **`0644`** — no execute bit — in both the image and the vendor tarball, so a required mount check
  simply could not run (`direct_exec_rc=126`, `via_sh_rc=0`). And `systemd-remount-fs`'s
  `ExecStartPre=/bin/mount -a` exited 64, which is util-linux's "some mounts succeeded", because
  eleven fstab lines wanted `/dev/mmcblk0pN` partitions the projection does not have.
- Fix applied on a CoW clone: `chmod 0755` on the check script, and the eleven partition lines replaced
  with self-binds of the same filesystem (`/navi /navi none bind,ro,noatime` and so on), which invents
  no block devices. Canonical image still hashes `4953a005…66d036f`.
- `Dbuslaunch` now succeeds: `Started HKMC Preminum AVN 2.1 -Launcher`.
- What remains is exactly the pair already identified, now with hard evidence:
  - `micommanager_userspace` exits 1, logging only to kmsg/DLT, and `ApplicationLauncher` carries a
    hard `Requires=` on it, so the launcher dies by dependency.
  - Nothing starts a Wayland compositor. **There is no `weston.service` at all** — only
    `weston-crash.path` — so weston is launched solely by esinit's own branch, which the `SPI NOK`
    marker still skips. Consequently `nua` fails with `XDG_RUNTIME_DIR not set` and
    `Failed to create display`.
- `micom` is not a unit either; `Dbuslaunch`'s `After=micom.service` dangles harmlessly.

## 1.08.0 - systemd runs for the first time; USB nodev defect found

- **PID 1 is now systemd.** `systemd 225 running in system mode`, hostname `prm-gen-5`, with
  `systemd-modules-load`, udev, sysusers, tmpfiles, journald, `auditd` and the fstab mount units all
  attempted. This is the first time the authentic vendor boot has got past esinit's own script.
- The unblock was one line: `install lge_usb_adapter /bin/true` in `etc/modprobe.d`, applied to an
  APFS copy-on-write clone (`cp -c`, instant) rather than the canonical image, which still hashes
  `4953a005…66d036f`. `fan` then loaded normally, confirming the earlier deadlock was the orphaned
  platform lock and nothing else.
- The chain now stops at `local-fs.target`. `systemd-remount-fs` exits 64, `check-mount.sh` fails with
  permission denied, and every fstab entry wants a `/dev/mmcblk0pN` that this projection does not have,
  so `dev-mmcblk0p8.device` times out and the system reaches **Emergency Mode** at 103 s. The missing
  piece is the partition table, not a service.
- `/tmp` artefacts from esinit are all present and correct: `/tmp/passwd` 996 bytes, `/tmp/fstab`,
  `/tmp/weston.ini`, and the SPI marker. The SPI gate still blocks esinit's own weston launch.
- USB root-surface map completed. **Most promising vector: the automounted USB filesystem is mounted
  without `MS_NODEV`.** The flag word at `0x4c00` is `0xC0ED000A`, which is `nosuid,noexec,dev` — so an
  attacker-controlled filesystem image can carry a device node and reach block devices that
  `0660 root:disk` would otherwise guard. Statically provable and needs no bug. Recorded as V-011.
- The udev sanitiser mechanism is now precisely characterised: the `#+-.:=@_` allow-list is
  `util_replace_chars(0x22a00)` called from `builtin_usb_id` with `allow=NULL`, not
  `udev_util_encode_string`; `ID_SERIAL` is safe only because its components were sanitised first;
  `ENV{…}=` rules apply no sanitiser at all, but the single USB-relevant rule is unreachable behind a
  firewire and skip_pci gate.
- **V-010 is downgraded.** Its faulting pointer is the global `0xffffffff81bd5460`, set only from
  `dev.platform_data` at `0x810594c2`, with no attacker-reachable path identified. It stands as a
  bring-up defect and a reminder that the driver asserts hardware presence, not as a security finding.
- Second and third ranked vectors recorded for further work: the unseparated media-parser chain
  (V-007), and a `..` serial combined with an unchecked `umount2`/`mkdir`/`mount` sequence that lands a
  mount on `/media` when `/media` is writable — an amplifier whose severity depends on a `/media` mode
  that is still unverified.

## 1.09.0 - authentic ASF parser overflow reproduced; V-006 guidance corrected

- Dynamically reproduced CVE-2026-2920 in the shipped GStreamer ASF plugin
  `/usr/lib/gstreamer-1.0/libgstasf.so` (SHA-256
  `05e887731708f0b0a52ff9fc75767a00fda9984e422983e5ff1d672f4b1af45d`). A valid
  WMA/ASF probe with 33 unique Stream Properties Objects causes authentic
  `gst-discoverer-1.0` to create stream 33 beyond the element's fixed 32-entry array and then
  terminate with `SIGSEGV`/exit 139.
- Added `tools/uk_fw/asf_stream_probe.py`, a bounded generator/auditor that duplicates exactly one
  valid ASF stream object, repairs header/file sizes, assigns unique 7-bit stream IDs, refuses
  malformed templates and in-place output, and audits the upstream rejection marker. Added five unit
  tests.
- Recorded the parser finding as V-012. The VM proves memory corruption and denial of service, not
  arbitrary code execution, persistence or physical-head-unit applicability. Upstream/NVD describe
  RCE potential, but instruction-pointer control was not attempted or claimed.
- Traced likely production context: `libthumbnailextractor.so` links GStreamer and contains a
  `uridecodebin ... ! appsink` pipeline, while D-Bus activation does not drop uid. Two bounded
  `Start(as)` attempts did not reproduce the ASF crash, so automatic thumbnail/scanner reachability
  remains unproven and those runs are retained as negative controls.
- Rewrote the stale `usb-root-test-plan.md` and exploit inventory. The old `${IFS}` MTP serial
  payload is explicitly withdrawn: `usb_id`'s second sanitizer limits `ID_SERIAL_SHORT` to
  `[A-Za-z0-9#+-.:=@_]`, as already confirmed dynamically in 1.05.0. The root shell sink remains
  unsafe design and a possible denial-of-service surface, not demonstrated descriptor-to-root code
  execution.
- Added `evidence/gstreamer-cve-2026-2920.md` with artifact hashes, exact dynamic sequence, production
  reachability boundary, related-CVE triage, remediation and regression criteria.
- Resolved the concurrent vulnerability-ID collision: the earlier missing-`nodev` hardening gap remains
  V-011 and the ASF memory-corruption finding is V-012.
- Tightened V-011's impact claim. The automounter accepts vendor `tntfs`/`texfat`, not arbitrary ext
  images; FAT/exFAT cannot natively store POSIX device inodes, and Tuxera NTFS special-node semantics
  remain untested. Missing `MS_NODEV` is confirmed, but a useful device node and privilege bypass are
  not. It is not a first-step root path.

## 1.07.0 - authentic init chain runs to a kernel oops, and the MICOM contract is written

- The boot harness gained a validated `--init` choice (`/init` or `/lib/systemd/esinit`), defaulting to
  the research init. The canonical image is provably untouched by this: the drive is already
  `snapshot=on` so QEMU writes a throw-away overlay, and `rootfs.img` hashes identically before and
  after four runs.
- `esinit` now runs authentically through step 22 and stalls one line before systemd. The artefacts
  that its absence kept costing us now exist: `/tmp/passwd` at 996 bytes, `/tmp/fstab`,
  `/tmp/weston.ini`, and the `*_code_*` files. PID 1 never becomes systemd and no `Reached target`
  line appears, held for 300 extra seconds across two long runs.
- The blocker is a kernel fault, not a service failure. `/etc/esinit-modprobe.sh` killed
  `/sbin/modprobe lge_usb_adapter`, which oopsed with a NULL dereference at `000000000000000c` in
  `sbi_apl_commit+0x60/0x2bc`. That orphans the platform `device` lock, so the next platform driver
  registration blocks: `/sbin/modprobe fan` never returns and sits in state `D` inside
  `lge_fan_init`. The hung-task detector is compiled out, which is why the stall is silent.
- Controls isolate it: `modprobe fan` on a clean guest returns 0, and `modprobe hid-generic` still
  succeeds after the oops, so only the platform bus is wedged. Recorded as V-010.
- `esinit`'s own weston launch is skipped for a second, independent reason: the SPI validation marker
  `/tmp/spi_validation_NOK` persists because `/sys/module/micom/parameters/spi_validation` does not
  exist. That branch is also console-silent, because the vendor wrote `echo "SPI NOK" > kmsg` with a
  relative path, creating `/kmsg` instead of logging.
- MICOM contract written from static evidence with each claim tagged verified, inferred or
  unestablished: bus `com.lge.car.micom`, object `/Ihu`, interface `com.lge.car.micom.ihu`, method
  `AskSysBootinfo` taking no arguments and returning `ay`. The 35 bytes are the reply payload, not the
  request: frames are `AA id_hi id_lo L payload CS` with an XOR checksum over the whole frame, and a
  reply carries the request id with bit 15 set, at 115200 baud on `/dev/ttyS1`. Five methods in
  dependency order would satisfy the launcher.
- Weakest link stated plainly: it is unresolved whether the daemon transmits before it receives, since
  the retained trace filtered a single fd, so a MICOM-init precondition and a wrong-fd write are not
  separable from static evidence. One `xxd` of `micom-serial.bin` settles it.
- **Correction:** `/work/` is gitignored, so earlier commits that appeared to include the analysis
  documents did not. Sanitised analysis now lives under `evidence/vm-bringup/`, which is the tracked
  location the repository policy intends.

## 1.06.0 - display architecture decided: software IAS backend, stock weston

- Decision recorded after reviewing the gap analysis against the actual kernel tree: patch only
  `ias-backend.so`'s DRM output path into a software IAS backend at 1920x720 named `HDMI1`, and keep
  stock `/usr/bin/weston`, the IVI modules and the IAS protocol. Reason: it preserves the vendor
  compositor architecture instead of permanently substituting it.
- Rejected, with reasons: a vkms-style kernel module is not the critical path, because 4.1.27 has the
  DRM/KMS helpers but no in-tree vkms, and `work/kbuild/drmkms/drmkms10.c` demonstrates only
  card/connector/mode registration — not GBM allocation, scanout, planes, flips, vblank or an
  1920x720 HDMI CRTC. An LD_PRELOAD/libdrm emulation is the wrong seam, needing broad DRM/GBM/EGL and
  likely Intel private ioctl behaviour. A permanent weston-headless baseline excludes the IAS
  compositor and control path, so it is a demo rather than the goal.
- This **corrects the gap analysis**, which was optimistic that a generic libdrm/GBM node plus
  `kms_swrast` would satisfy the compositor. `ias-backend.so` carries i915/intel-specific paths and
  both atomic and legacy KMS and plane APIs, so a plain card node is not a compatible device.
- Riskiest assumption, stated for falsification in one run: that the stock IVI modules need only the
  Weston backend ABI plus the `ias_crtc` interface, and no hidden i915 semantics. Estimate 2-3 weeks to
  bring up, 4-6 weeks to sustained HMI fidelity.

## 1.05.0 - MTP branch proven reachable, and its injection is blocked by udev

- The V-006 sink is now confirmed reachable at runtime: an emulated `usb-mtp` device yields
  `ID_USB_INTERFACES=:060101:`, the automounter takes the MTP branch, and the guest reports
  `sh: /usr/bin/go-mtpfs: No such file or directory` — a message only the `system()` call can emit.
- Injection does **not** fire. udev delivers a sanitised property: the submitted
  `a;id>/tmp/v006.id;echo${IFS}V006KMSG>/dev/kmsg;#` arrives as
  `a_id__tmp_v006.id_echo__IFS_V006KMSG__dev_kmsg_#`. A second sanitiser beyond
  `util_replace_whitespace` enforces alphanumerics plus `#+-.:=@_` and rewrites every other printable
  byte to `_`. The allow-list string is present in `systemd-udevd` and `libudev`.
- A positive control settles the cause: the same string handed directly to the guest's `/bin/sh`
  produces `uid=0(root)`, so the payload, the guest and the harness are all fine and the sanitiser is
  the obstacle.
- V-006 is therefore downgraded to a latent defect rather than an exploitable-by-construction one, and
  the register's own "metacharacters pass through" claim is withdrawn. The `sprintf`-into-`system()`
  pattern is still a real defect worth removing.
- Static HMI gap analysis completed (569 lines, `hmi-gap-analysis.md`). The harness `/init` is an
  artefact, so the authentic chain `init=/lib/systemd/esinit` and systemd itself have never run in the
  VM, which is why the `/tmp` state that services authenticate against keeps being missing.
- Ranked blockers recorded: authentic init chain, a live `com.lge.car.micom` with the 35-byte
  `AskSysBootinfo`, a DRM node for the vendor compositor, weston's start condition and session-bus
  ordering, the `mnt-wt` resource table and theme assets, `can0`, `/dev/ttyGPS`, then touch and audio.
- Largest single blocker identified: the vendor compositor needs `HDMI1` at 1920x720 through
  `ias-backend.so` over i915/GBM, and neither emulated QEMU VGA nor the vendor kernel provides an i915
  device, so `/dev/dri/card0` cannot exist as configured. Every HMI result so far used a substituted
  compositor.

## 1.04.0 - the mount service runs in the VM, and a passwd symlink surfaces

- `usb-automount` now stays alive in the emulated userspace and owns `com.lge.car.automount` on the
  system bus. Twelve polls over sixty seconds all saw a live process in state `S`, and `ListNames`
  confirms the name is owned. The mount request surface is therefore live in the VM for the first
  time, which is the precondition for any V-006 work.
- The blocker was not a D-Bus policy problem but a missing password database: `/etc/passwd` in this
  image is a symlink to `/tmp/passwd`, and that target does not exist in a fresh boot, so the daemon
  cannot resolve `root` or its own `messagebus` user and refuses to start. Writing the two entries to
  `/tmp/passwd` is enough, which also shows how the vendor intends this to work: init populates it.
- Control run to establish causality rather than assume it: with the daemon up but the password file
  absent, `usb-automount` still dies in about three seconds with the original assertion. So the
  password database, not the bus policy, was the missing piece.
- Harness notes carried forward: backgrounding a guest daemon without `</dev/null` wedges the serial
  shell silently until timeout, and the host's default `python3` is broken for spawning, so runs must
  use `python3.13`.
- New register entry V-009 for the `/etc/passwd` to `/tmp/passwd` symlink. Recorded as a candidate:
  the runtime permission and ownership of `/tmp` on a real unit are unverified here, and without them
  the impact cannot be stated.

## 1.03.0 - USB injection harness enumerates; V-006 reproduction path corrected

- The three earlier USB attempts failed for one reason each, now identified. `-chardev null` prevents
  QEMU's `usb-serial` from presenting on the bus at all: no connect, no `new full-speed USB device`
  line, nothing in the device list. A file or socket chardev fixes it, and the device then enumerates
  as `0403:6001` with the crafted serial string read back verbatim
  (`SerialNumber: ;id>/dev/kmsg;#`).
- Controller choice is constrained by this kernel. `qemu-xhci` registers a bus but oopses in the
  vendor's `xhci_toggle_dis_perr_det` during root-hub device creation, so no device can attach.
  `ich9-usb-ehci1` is rejected by QEMU itself, because `usb-serial` is full-speed and QEMU treats the
  high-speed bus mismatch as fatal, exiting before boot. `ich9-usb-uhci1` works: a keyboard
  enumerated as `1-2` and the serial adapter as `1-1` in the same run.
- The image carries no `ftdi_sio`, `pl2303` or `cp210x`, so the emulated FTDI adapter produces no
  `/dev/ttyUSB` node. That is expected and is unrelated to V-006.
- `usb-automount` is a Qt5 and dbus-glib service exposing `com.lge.car.automount.request`, not a
  shell script. Started without a system bus it dies at once on a `QDBusConnection` assertion and
  never reaches any mount logic. `/usr/bin/dbus-daemon` is present in the image, so the next run
  starts it first.
- **Correction to this session's earlier reasoning.** Passing a shell payload in the serial string was
  framed as exercising a generic injection path in `usb-automount`. That framing is wrong: the
  documented V-006 mechanism is the MTP branch, and `usb-automount` has no shell interpolation to
  reach. Reproduction therefore needs an emulated MTP device, not a serial adapter.
- No injection fired in any run. `uid=` never appears in the guest log except in the echoed command
  text, which is why the harness must match on structured output rather than a grep of the transcript.

## 1.02.0 - disk investigation: the backups were clones and cost nothing

- Pruned 15 of the 70 `rootfs-pre-*.img` backups, the earliest superseded control chains whose
  results are already retained in `runs/` and `evidence/`. Seven milestone-bearing images were
  kept: the working deadline-pie runner, the llvmpipe Home/Navi/Home run, both valet runners, the
  hmc widget bind, the v2 widget link, and the home-navi deadline predecessor.
- **The prune freed nothing.** 480 GiB was removed from the apparent size and available space did
  not increase; these files are APFS clones sharing blocks with the canonical image, so unlinking
  them releases no space. The 1.6 TB figure was never real usage.
- `tmutil listlocalsnapshots` is empty, so pinned snapshots are not the cause either. The container
  is genuinely full across the whole machine: `~/Library/Application Support` 402 GB, `~/.codex`
  248 GB, `~/Documents/Codex` 201 GB, `~/Downloads` 111 GB, alongside the research tree.
- Consequence recorded plainly: **deleting more project backups will not help**, and further VM
  work is blocked until roughly 50 GB is freed elsewhere or the workspace is moved to another
  volume.
- Correction to the previous entry, which listed the backups as the cause: that inference came from
  apparent size rather than allocation and was wrong.

## 1.01.0 - USB test plumbing added; disk-full blocker recorded

- Added an opt-in `extra_devices` argument to `tools/uk_fw/vm_boot.py` so a research run can
  attach extra QEMU devices, with `-flag value` pairs kept together and multi-line arguments
  rejected. Two tests cover it and pass.
- Purpose: QEMU's `usb-serial` accepts a `serial=` property, which sets `iSerialNumber` on a
  vendor-class device. That means the V-006 serial-injection path can be exercised **without any
  hardware**, which was the open question.
- First attempt reached QEMU and failed correctly but for an environmental reason: `q35` in this
  configuration exposes **no USB bus**, so the device cannot attach. Booting with a USB controller
  plus loading the kernel's USB modules (`usb`, `xhci_pci`, `usbserial`) is the next step, and the
  image carries `usbserial.ko` and `cdc-acm.ko`.
- **Disk blocker recorded:** the volume is at 100% with ~500 MB free. `work/vm/vendor-userspace-260128`
  holds **70 `rootfs-pre-*.img` per-experiment backups, 2.4 TB apparent**, which is what consumed the
  disk. Removing my own derived workspaces freed only 33 MB because they were APFS clones sharing
  blocks.
- The full suite currently fails one test (`test_fat_harness`) with `No space left on device`; that is
  the disk, not the change. `test_vm_boot` passes 24/24 in isolation.
- **Not deleted:** those 70 backups are pre-existing work from earlier sessions and pruning them is
  the owner's decision. Recommended: keep the canonical `rootfs.img` (SHA-256 `4953a005…6d036f`) and
  a small number of retained checkpoints, archive the rest externally, since each is a full copy of
  the same base image taken before one experiment.

## 1.00.0 - live ESP design: interactive root over USB, not a blind one-shot

- Reworked the USB plan now that the owner can reprogram the ESP while it is plugged in. That
  turns a one-shot into an interactive channel, for two concrete reasons.
- **The payload can be a shell.** The template appends `&`, but the payload ends with `;#`, so the
  `#` comments out the backgrounding and the injected command becomes `system()`'s foreground
  child. `;/bin/sh</dev/ttyACM0>/dev/ttyACM0${IFS}2>&1;#` (46 chars, charset-clean) is parsed as
  an interactive root shell whose stdio is the USB serial channel.
- **There is a real feedback channel.** `CONFIG_USB_ACM=m` is present, so a CDC-ACM interface
  yields `/dev/ttyACM0` without needing any mount. That is better than a mass-storage mailbox,
  because the automounter's filesystem strings are only `ntfs`, `exfat` and `ext4` — a FAT volume
  from a microcontroller is not obviously accepted.
- Composite descriptor recorded: `ff/ff/00` vendor interface to satisfy the MTP branch test,
  CDC-ACM for the data channel, and the payload carried as `iSerialNumber`. Since descriptors are
  fixed at enumeration, changing the payload means re-enumerating, which TinyUSB can do in
  software — that is the whole iteration loop, over WiFi, with no unplugging.
- Step order recorded: `;id>/dev/ttyACM0;#` to prove both the injection and the channel, then
  locate the node if `ttyACM0` is absent, then the shell payload, with the credential overwrite
  as an alternative.
- Corrected a stray space in my own `tty*` probe payload, which the whitespace rewrite would have
  mangled into `_`.
- Caveats kept: ACM is a module and may not autoload; the branch fires on the device add event so
  the automount service must already be up; and an open shell blocks the automounter.

## 0.99.0 - USB root test plan written (private)

- Wrote `evidence/usb-root-test-plan.md`, a lab procedure for the owner's own unit, kept
  **private**: it contains an exploit payload and the public mirror carries only the
  status-only V-006 entry.
- Vector A (V-006 serial injection) is validated at the shell level against the exact
  command the firmware builds. Two payloads checked against both real filters (126-character
  limit, `0x20`–`0x7f` minus comma, no whitespace): a 15-character proof of execution writing
  to `/dev/kmsg`, and a 49-character credential overwrite.
- The useful payload targets `/etc/shadow`, which is a symlink to `/tmp/shadow`, using the
  shipped field layout with an empty hash. Combined with `/etc/securetty` already permitting
  root on `ttyS2`, that yields an interactive root login on the serial console. Because `/tmp`
  is tmpfs the change is cleared by a reboot.
- Corrected my own first draft, which wrote `passwd` field order into a `shadow` file; the real
  `shadow.Global` line is `root:…:20481:0:99999:7:::` and the payload now matches it.
- Hardware recommendation recorded: **ESP32-S3 with TinyUSB**, because the trigger needs an
  arbitrary interface class (`06/01/01` or `ff/ff/00`). A Pi Zero in gadget mode cannot present
  either class from stock configfs functions, all of which are `02/06/00`, `02/02/01` or
  `08/06/50`.
- Vector C (USB Ethernet) recorded as supported but useless alone: the kernel has CDC-ECM, but
  the image ships no DHCP client and no remote-login daemon.
- Pre-flight recommendation: pass the ESP32 through to QEMU and exercise the real
  `usb-automount` before involving the car.

## 0.98.0 - physical HID is dropped by the shell, not by a driver

- Explained the reported mouse and keyboard behaviour from the firmware rather than by guessing.
  `weston_1920.ini` has **no `[input]` section**, and `ias-backend.so` fully supports pointer,
  keyboard and touch (`weston_seat_init_pointer`/`_keyboard`/`_touch`, `notify_motion`,
  `notify_key`, libinput + libevdev). Udev is stock apart from a touchscreen symlink rule.
- The gap is `ivi-shell.so`: it contains **no pointer or keyboard focus implementation at all**.
  The only keyboard logic in the window manager concerns the on-screen keyboard surface.
- So the cursor appears because the backend creates a pointer seat and weston draws the cursor,
  but moving it and granting pointer focus is shell work that ivi-shell does not do. Keys are
  consumed by the compositor with no focus surface and dropped. The caps-lock flicker on plug-in
  is LED state on device open, not key handling.
- Consequence recorded: input must be simulated at the **touch** layer, which the GUI accepts,
  rather than by presenting a mouse or keyboard. That is already where the project's
  `weston_vm_input` and `qt_input_observe` helpers point.

## 0.97.0 - correction: visibility is granted, and the harness has no ApplicationManager

- **Withdrew** the "zero visibility events" claim. It came from counting the string
  `ivi_surface_visibility`, but the compositor logs `ivi_surface@7.visibility(1)` — twice. The
  surface **is** made visible. That is the second time a wrong marker string inverted a
  conclusion in this investigation, and both are now recorded as such.
- Also recorded: this harness deliberately runs **no ApplicationManager**, so its empty manager
  query proves nothing about the manager's view. The "drawing application 0" observation came
  from a different configuration.
- With the retained milestone screenshot showing genuine map pixels, the standalone harness
  already reaches visible authentic AppNavi rendering.
- **Therefore the remaining gap is integration, not rendering.** The full launcher chain starts
  AppNavi through AppLauncher with different environment and ordering and does not reproduce
  this harness's ingredients.
- Next: carry the three essentials into the full chain — gpio440 adaptor, valet-status D-Bus
  boolean stub, and the widget/visibility helper — and see whether the manager latches the
  navigation window.

## 0.96.0 - retargeting the helper to 30000 does not produce visibility either

- Rebuilt the widget-linking helper with parent id 30000 instead of 3000 and ran it through the
  same harness. `set_surface_visible`=16 and `request_fg`=8 as before, and
  **`ivi_surface.visibility` events still 0**.
- So addressing the id that exists is **necessary but not sufficient**. The mismatch was real,
  but it does not on its own produce visibility, so at least one further condition governs
  whether the window manager emits a visibility event.
- Candidates recorded in cost order: the helper's requests not reaching the same window-manager
  instance that owns the surface (its log has been empty, which is suspicious); visibility
  requiring a further state change such as a later commit or a layout change; or 30000 not
  being the parent surface the helper should address at all.
- Next discriminator: confirm the helper actually connects and its first request is accepted,
  by capturing its output and the compositor's response.

## 0.95.0 - the surface id is fixed at 30000; the helper addresses 3000

- Settled the id question with one run: `QT_WAYLAND_SET_SURFACE_ID=0` still produces surface
  id **30000**, the same as with `3000`. The environment variable does not control the id in
  this path.
- So the mismatch is not a configuration slip on our side. AppNavi creates 30000 regardless,
  the helper programmes visibility for 3000, and sixteen visibility requests therefore
  produce zero `ivi_surface.visibility` events.
- **The fix follows directly:** address the id that exists. Rebuilding the widget-linking
  helper with parent 30000 is cheaper than establishing where 30000 originates and making it
  configurable.
- This closes the diagnosis of the visibility blocker: surfaces are created, buffers are
  attached, requests are issued, and the only thing wrong is the identifier.

## 0.94.0 - visibility requests are plentiful; the surface id does not match

- Counted visibility markers in the compositor log for the valet-stub run:
  `set_surface_visible`=16, `set_visible_for_qtwayland`=16, `request_fg`=8,
  `set_surface_layout`=16 — and **`ivi_surface_visibility` events = 0**.
- The only surface id the compositor logs as created is **30000**, while the helper
  programmes visibility for **3000**. So the requests are issued correctly but never bind to
  a surface that exists, which is consistent with the manager still reporting drawing
  application `0`.
- This turns the 3000-versus-30000 puzzle from a suspicion into the leading explanation,
  supported now by an event count rather than inference.
- Next: establish the mapping between the environment value and the created id (one run with
  a different value makes it plain), then either point the helper at the id that exists or
  make AppNavi create the id the helper expects.

## 0.93.0 - correction: AppNavi does create surfaces; the earlier stop point was wrong

- **Withdrew** the previous claim that AppNavi never calls
  `ivi_application.surface_create`. It was based on marker counts from the client's
  `WAYLAND_DEBUG` log, and the client does not emit those requests in this build, so their
  absence there proved nothing.
- Counting the **compositor** log for the same run shows `surface_create`=2,
  `ivi_surface`=7, `attach`=2, `commit`=2. AppNavi creates ivi surfaces and attaches buffers.
- The reproduced recipe is the one the retained milestone used: the gpio440 adaptor, the
  valet-status D-Bus boolean stub, and the widget-linking helper in place of the plain
  foreground helper.
- What remains is **visibility**, not surface creation: whether a foreground/visible request
  reaches the surface ids that actually exist, and on which plane.

## 0.92.0 - wl_drm ruled out; a working harness is known; a working harness is known

- Ruled out the missing `wl_drm` as the gate. A prior successful run used the same
  `weston-headless` pixman stack with **no ApplicationManager** and reached `surface_create`
  for ids **3000, 30000 and 4903** with 26 attach calls, so clients can create ivi surfaces
  and attach without any DRM interface. The current stop is configuration-specific.
- That also settles the 3000-versus-30000 puzzle: AppNavi creates **both** ids plus
  4903/4900 for the map widget, so there was never one expected id.
- A working harness is known and can be diffed: that run executed
  `/appnavi-valet-stub-probe.sh` with `/appnavi-valet-stub-run.sh`, both still present in the
  image. The next step is to diff that harness against the current probe rather than debug
  further.

## 0.62.0 - public VM source and evidence publication

- Published the authored VM reproduction sources and bounded evidence to the
  public research repository, with source and evidence manifests binding every
  published file to a SHA-256.
- Added the authentic launcher profile/confirm screen and a navigation-window
  frame that still shows Home to the inspected screenshots there.

## 0.91.0 - AppNavi stops between create_surface and ivi surface_create

- With the gpio440 adaptor in place, counted protocol markers in AppNavi's own
  `WAYLAND_DEBUG` log instead of transporting text over the console. That is both cheaper
  and decisive.
- **Measured stop point:** AppNavi binds `wl_display`, enumerates 71 registry lines, binds
  `wl_compositor`, `wl_shm` and `ivi_application`, creates a `wl_surface` — and then
  **never calls `ivi_application.surface_create`** and never attaches or commits.
- **`wl_drm` is absent entirely** (0 references). The compositor runs headless with pixman,
  so no GPU buffer interface is offered. Whether that causes the stop or merely accompanies
  it is not established.
- Tried `QT_WAYLAND_SET_SURFACE_ID_FORCED=1` in addition to the id already being set: a
  second `wl_surface` appears but `surface_create` is still 0, so the forced path alone does
  not get past the stop.
- Ruled out by construction: gpio440 polling (now stubbed, errors zero), the preload adapter
  (baseline without it is identical), ApplicationManager presence, and the current
  command-line flags.
- Next hypotheses recorded: libivi's id acquisition still declining, QtWayland refusing to
  complete ivi surface creation without a buffer integration under pixman headless, or a
  later startup requirement that surface creation sits downstream of.

## 0.90.0 - privacy checker no longer mistakes Wayland notation for email addresses

- The harness failed on the retained AppNavi analysis with five "private email address"
  findings. They were false positives: the checker's email pattern matched Wayland debug
  syntax, where a protocol object is written `object@<id>.method(...)`, so `wl_surface@3.attach`
  and `ivi_controller@13.surface(30000)` looked like addresses.
- Tightened `EMAIL_PATTERN` so the domain must begin with a letter. Real addresses still
  match (`someone@example.com`, `a.b@corp.example.org`); Wayland forms no longer do.
- Added a regression test, `test_wayland_object_notation_is_not_an_email`, so future
  protocol captures can be retained as evidence without tripping the privacy gate.
- Deliberately fixed the checker rather than rewriting the quoted log lines: every Wayland
  capture from here on would hit the same false positive, and mangling evidence to satisfy
  a scanner is the wrong trade.

## 0.89.0 - first hardware-dependency adaptor: AppNavi polls a GPIO the board lacks

- Traced why AppNavi is alive but paints nothing: with `WAYLAND_DEBUG` on, its own log
  shows it connects, enumerates the registry (including `ivi_application` as global 111),
  and then **never calls `surface_create`**. The tail of that log is a repeated loop on
  `/sys/class/gpio/gpio440/value: No such file or directory`.
- Checked the node in the VM: `/sys/class/gpio` contains only `export` and `unexport`, and
  writing `440` to `export` returns **EINVAL** — the pin is not registered by any gpiochip,
  consistent with the kernel log where `lge_gps_driver` defers with `-517` and never gets
  its GPIO. So this is not a configuration mistake; the emulated board genuinely lacks a
  GPIO the firmware expects.
- Built the adaptor: a tmpfs mounted over `/sys/class/gpio` with a `gpio440` node and an
  inert `value`. With it, the `gpio440` errors disappear from AppNavi's log entirely, which
  is the first time a simulated hardware dependency has been shown to unblock a firmware
  startup path in this project.
- Honest limitation: surface creation is **not yet consistent**. One run showed
  `surface_create` in the log, the next showed none, so something beyond the GPIO is also
  gating the render path or the timing is racy. The GPIO stub is necessary and
  reproducible; it is not yet sufficient on its own.
- Retained as `tools/uk_fw/guest/appnavi_gpio_probe.sh` so the stub and the probe can be
  reproduced.

## 0.88.0 - why AppNavi idles: the ivi surface id and visibility are injected from outside

- Ran a targeted analysis of the "alive but paints nothing" blocker and added it as
  `evidence/appnavi-startup-analysis.md` (full report retained under
  `work/vm/vendor-userspace-260128/appnavi-startup-analysis/`).
- **Root cause candidate, verified at string and dependency level:** AppNavi directly
  links `libivi-platform-interface.so.1`, which resolves its ivi surface id *only* from
  the environment (`QT_WAYLAND_SET_SURFACE_ID`, with `_FORCED` and
  `USE_PID_FOR_SURFACE_ID` variants). On the vehicle that value is injected by
  `AppLauncher`, which also sets `APPID`. Verified here: the library is a direct `NEEDED`
  of AppNavi and contains all three variable names.
- **Unset behaviour:** an uncapped `blockingReadEvents` loop waiting for an id reply. That
  is precisely the observed symptom — alive, silent, no surface — rather than a crash.
- **Ruled out:** ApplicationManager's absence (the project's no-AppManager run still
  committed a 1920x720 buffer), every command-line flag in the current invocation, and
  `APPID` (read by AppLauncher, not by AppNavi or libivi). AppNavi reads exactly one
  environment variable itself: `MD_CONA40_ON`.
- **Open point flagged, and it is a big one:** the VM logs show the ivi surface created
  under id **30000** while the project's `/ivi-fg-navi` helper programmes **3000**. If
  real, visibility is being requested for an id that does not exist, which would explain
  the byte-identical screenshots even in the configuration believed to work. The origin of
  the added offset lives in `.bss` and was not established statically.
- **Cheapest next test, one boot:** run with `QT_WAYLAND_SET_SURFACE_ID=3000` and no
  ApplicationManager, then check which id the surface actually receives and re-drive
  `/ivi-fg-navi` with *that* id.
- Supporting runtime observation from this session: a run of the baseline probe produced
  **no surface_create at all**, and AppNavi had exited by the end, so the id hypothesis and
  the lifetime question both need the instrumented run above.

## 0.87.0 - A/B shows AppNavi paints nothing at all

- Ran the A/B the previous entry left open. Three runs of the same probe with the captured
  frame compared: with the adapter (AppNavi alive, 1 log line), baseline without it
  (AppNavi alive, 0 lines), and a control with **AppNavi not launched at all**.
- The screenshot is byte-identical (`b316a82a…0b9a83`) between baseline and the no-AppNavi
  control. AppNavi renders nothing: alive, silent, contributing no pixels.
- Consequence: the adapter is not implicated, and the compositor contract, the `0x0` hold
  and the BG notification cannot be exercised until AppNavi paints. The blocker moves one
  level earlier.
- Next step recorded: find why AppNavi is alive but idle — compare the environment and
  arguments the launcher normally supplies against this probe's direct launch.
- Documentation inconsistency fixed: an earlier `git reset --hard` in the public clone
  discarded an uncommitted doc edit, so the public copy still presented the question as
  open while this copy carried the baseline result. Both copies now agree, and the public
  repo is at `462c9fa`.

## 0.86.0 - baseline clears the interposer; AppNavi is silent on its own

- Ran the decisive control: the identical render probe **without** the preload.
  AppNavi's log came back **0 lines** and the manager reported drawing application `0`
  — the same result as with the adapter loaded, whose log holds only the adapter's own
  one-line load record. So the interposer is **not** what stops AppNavi; its startup is
  failing for reasons of its own in this probe.
- Stated with it, because it matters: **an empty log is not proof that nothing rendered.**
  AppNavi may log to DLT or a file, or not at all, and the probe's screenshot has not
  been inspected yet. "Renders but silently" and "never renders" both remain open.
- Next step recorded: inspect the captured frame, and check whether AppNavi logs to DLT,
  before concluding anything about its startup.
- `docs/navigation-status.md` updated in both repositories: the open question section is
  replaced by this baseline result.

## 0.85.0 - working tree committed; probes published

- Committed the working tree that had been preserved uncommitted throughout the VM work:
  the harness additions in `tools/uk_fw/vm_boot.py`, the native TE2 decryptor work in
  `tools/uk_fw/gen5w_decrypt.py`, their tests, the eleven VM research helpers under
  `tools/uk_fw/guest/`, and `PROJECT-OPERATIONS.md`.
- Sanitisation: one personal path in `PROJECT-OPERATIONS.md` was replaced with a
  placeholder. The rest of the set contains no personal paths, VIN-shaped tokens or
  credentials. Harness and the full 171-test suite pass.
- Published three further research instruments to the public repository
  (`dr_breakpoint_probe.c`, `ec03_observer.c`, `ec03_target.c`), closing the gap between
  the private and public tool sets. Public repo at `3089bf4`.
- Deliberately still private: the vulnerability register, the raw evidence tree, the
  task ledger and all firmware. Public tree carries no firmware and no credentials.

## 0.84.0 - navigation status published to both repositories

- Published `docs/navigation-status.md` to the public repository together with the
  research helpers behind it (`navi_bg_0x0.c`,
  `launcher_appnavi_navibg_preload.c`, `appnavi_bg_probe.sh`), and kept the same
  document here as `evidence/navigation-status.md`. Public repo at `2b179d5`.
- The document consolidates the three things measured this session — the EGL dimension
  ordering on the authentic client, that a Qt hide cannot produce a background
  notification, and that guest hardware breakpoints work under TCG with per-thread
  scoping and the disarm-before-detach requirement — and states the remaining blocker
  plainly: AppNavi never attaches a surface, so nothing reaches the compositor.
- Sanitisation before publishing: the new files contain no personal paths, no VIN-shaped
  tokens and no credentials; the public harness passed on the clone before the push.
- The public repository does not carry the vulnerability register, the raw evidence tree,
  the ledger or any firmware; those remain private.

## 0.83.0 - adapter moved to the render probe; AppNavi still never attaches

- Built `appnavi-bg-probe.sh` from the standalone render probe, which runs a real
  session bus, `weston-headless` with the IVI shell, a real ApplicationManager, and then
  **execs AppNavi directly** — so the adapter needs no launcher hook at all.
- First attempt launched AppNavi through the busybox `timeout` applet and the preload was
  lost across that extra exec hop. Launching AppNavi directly fixed it: AppNavi's own log
  now contains `navi-bg: loaded pid=772 hold_after=200 hold_count=900`.
- **Still no surface attach.** That single line is the entire AppNavi log, and the manager
  reported drawing application `0` before and after, which is not what a rendering Qt
  client looks like.
- Important open question recorded: whether the **interposer itself** is now what stops
  AppNavi rendering. The cheapest discriminator is a baseline run of the same probe
  without the preload, to compare AppNavi's log and behaviour. That is the next step.
- Method note: in this probe stderr is the reliable channel (it reaches `appnavi.log`),
  while `/dev/kmsg` produced nothing — so an absent `dmesg` line here is a channel
  artifact, not evidence of absence.

## 0.82.0 - BG experiment repositioned; AppNavi does not render in the full chain

- Moved the navi-bg experiment to after the chain's own navigation transition request,
  since the previous placement ran before AppNavi was ever asked to come forward. The
  hold also switched from a wall-clock window (measured from process start, long past by
  then) to an attach-count window anchored at that point.
- Result: the wait ran its full 180 seconds **without ever seeing a surface attach**
  (`NAVI_BG_PAINT_SEEN_AFTER_S=180`), no interposer timeline was produced, and the
  navi-live screenshots hash identically to the earlier Home frames.
- Conclusion recorded: in this full-chain configuration **AppNavi never becomes a
  rendering Wayland client**, so there is no surface for the adapter to hold. That is
  the Home↔Navigation blocker itself, not a fault in the adapter.
- Strategic correction recorded: the full chain is the wrong vehicle for the BG
  experiment. The standalone AppNavi render probe already in the image
  (`appnavi-render-probe.sh`, `launcher-appnavi-probe.sh`) is documented to produce
  genuine map pixels and should host the adapter, reusing the now-proven execve-hook
  injection.
- Method caveat recorded: `dmesg` is a weak late-run probe because the ring buffer can
  wrap during a ~570 s run. An absent line late in a run is not proof of absence;
  process state or a log file is better near real time.

## 0.81.0 - navi 0x0 injection unblocked: interposer now loads into AppNavi

- Found the root cause of every earlier "adapter never ran" result:
  `launcher_appnavi_liveness_preload.c` deliberately calls
  `unsetenv("LD_PRELOAD")` when running as AppLauncher, so vendor children inherit a
  clean environment. **No `LD_PRELOAD` set on the launcher command line can reach
  AppNavi**, which is why four attempts produced nothing.
- Fix: piggyback on that interposer's own `execve` hook, which rewrites `envp` for
  AppNavi alone. `tools/uk_fw/guest/launcher_appnavi_navibg_preload.c` is a variant that
  injects `LD_PRELOAD=/navi-bg-0x0.so:/appnavi-egl-no-msaa-preload.so` for AppNavi only.
- **Verified:** the kernel log now shows `navi-bg: loaded pid=857
  hold_at_ms=20000 hold_for_ms=6000`. The adapter demonstrably executes inside AppNavi.
- Also made the probe filesystem-free: the hold window comes from a monotonic clock
  plus launch-time environment variables, and the timeline goes to `/dev/kmsg`, so
  SMACK and exec-environment handling can no longer block it silently.
- Remaining gap: no `first-attach` line followed, so AppNavi never attached a buffer on
  the elected surface inside that window, and the manager still reported `11/11`. Next
  step recorded: log every attach plus a destructor summary so a zero-attach run is
  unambiguous, then align the hold window with real rendering.
- Method note: an earlier "decisive" conclusion that the library never loaded was
  **wrong** — it rested on AppNavi's stderr being captured in `launcher.log`, which it
  is not. `/dev/kmsg` is the reliable channel and corrected the diagnosis.

## 0.80.0 - navi 0x0 adapter not reaching BG; diagnosis narrowed to "never fired"

- Replaced the attach-count trigger with a **sustained hold**: while the trigger file
  exists, every attach on AppNavi's target surface is replaced by a null-buffer attach,
  so the surface is held at `0x0` instead of flipping for a single frame. Held for 6 s,
  then released and observed again.
- Manager reported **11/11 during the hold and 11/11 after release**. No change, so BG
  was still not reached.
- Added an audit write from the interposer on first hold, because "no manager change"
  and "adapter never ran" were indistinguishable. The run produced **no
  `/tmp/navi-bg.log` at all**, which means the interposer never executed a hold. The
  manager numbers from both attempts therefore say nothing about whether BG is
  reachable this way.
- Two candidate causes, currently indistinguishable: the preload may not reach AppNavi
  (AppLauncher may exec child apps with a sanitised environment), or SMACK denies the
  `/tmp` trigger read and the audit write for AppNavi's label, which would fail silently
  and produce exactly the observed evidence.
- Next step recorded: remove the filesystem from the probe entirely — log to stderr
  (captured in `launcher.log`) and derive the trigger from a monotonic clock or a
  launch-time environment variable, so neither SMACK nor exec-environment handling can
  block it silently.
- Everything still builds and injects cleanly, the chain completes with exit 0 in
  ~418 s, and screenshots were captured during the hold and after release.

## 0.79.0 - engineering mode research published; navi 0x0 still not reaching BG

- Wrote `evidence/engineering-mode-research.md` and published the same document to the
  public repository (owner approved releasing the PINs and entry methods).
- Entry recorded: Settings -> General settings -> System info -> Manual, tap the **left**
  panel (QR code and text, not the vehicle image) as `3 2 8 9 6 5`, then an eight-digit
  keypad. Engineering-mode PIN `19480717`, reported accepted on a UK-origin 2021 IONIQ 5
  whose build was later identified as `250604`, so acceptance does not prove it on
  `260128`.
- Dealer mode and full engineering mode are distinct with different codes. The
  previously single-source SOP-gate claim is now **corroborated in code**: the binary
  contains `bool AppEngineerModeEngine::checkSOPVersion()`.
- PIN check located: `AppEngineerMode_PinCodeKeypad.qml` (1,087 lines) calls
  `AppEngineerModeEngine.checkPassWord(...)` at line 391 and branches on the return
  value, where `21`/`11` are menu selectors. Lockout machinery exists
  (`startBadPassword`, `setBadPasswordInfo`, `getBadPasswordDiff`, `getEnterPasswordCnt`).
  The binary is stripped but keeps 111 C++ signature strings, which is how these were
  identified.
- **The PIN is not a literal.** 408,412 files across all five extracted components plus
  444 expanded archives gave zero hits in ASCII, UTF-16LE, uint32 LE, uint64 LE and hex.
  Most probable explanation recorded: the reported PIN belongs to the owner's `250604`
  build rather than this `260128` package.
- Entry gesture is not in QML (`Screen_Manual.qml` has no `MouseArea`/`onClicked`), and
  no binary contains the literal `AppEngineerMode`, so the gesture is native and the app
  launches through the launcher registry.
- AppNavi update: the older capability is recorded as Engineering Mode -> Config ->
  "Update AppNavi from USB"; state on `260128` remains **not established**, with four
  decision gates listed and the launcher's executable inspection flagged as the
  cheapest decisive check.
- Also recorded, from the paint-first navi run: the gated interposer
  (`MIN_ATTACHES_BEFORE_FORCE = 40`) completed with exit 0 but the manager **still
  reported 11/11**. BG was not reached, and the Home-to-Navigation transition is
  unchanged. Triggering on a count rather than on an observed event is the likely
  remaining flaw.

## 0.78.0 - navigation 0x0 adapter built; timing still wrong

- Started the integration piece the BG analysis called for: a scoped adapter that
  drives AppNavi's parent surface to a genuine `0x0` configure so the compositor
  classifies it BG and the manager latches its window byte.
- Mechanism, from the earlier ordering finding: a single null attach is not enough,
  because the size block at `0x40f470` stores the previous `width_from_buffer` before
  `0x40f813` zeroes it. **Two** consecutive null attaches reach `0x0`. Implemented as
  an `LD_PRELOAD` interposer on `wl_surface_attach` that forces a NULL buffer on two
  consecutive attaches. It only drives the vendor compositor; it never calls the
  manager, writes the window byte, or synthesises a notification.
- Two runs, both completed (exit 0, ~412 s) and both still reported manager `11/11`.
  Two real defects were found and fixed along the way: the preload also applies to
  every launcher child, so the first attempt collapsed the wrong app (now gated to
  AppNavi via `/proc/self/cmdline`); and the trigger fired before the client had
  painted, so AppNavi never foregrounded (now gated behind
  `MIN_ATTACHES_BEFORE_FORCE = 40`).
- Honest status: the plumbing is proven end-to-end — the interposer loads under the
  vendor glibc 2.25, is correctly scoped, the chain still completes, and manager state
  is queryable at the chosen point — but **BG was not reached** and the
  Home↔Navigation transition is unchanged. The paint-first variant is built and
  untested.
- Built against `x86_64-linux-gnu.2.25` rather than musl: a musl-linked `.so` will not
  load into the vendor's glibc process.

## 0.77.0 - I-001 scoped to the swrast path; Intel hardware not needed to proceed

- Answered the question of whether an Intel machine is required. It is not, and the
  check that settles it also narrows I-001. Vendor `libEGL` contains four distinct
  surface constructors — `dri2_create_window_surface`, `dri2_drm_create_window_surface`,
  `dri2_wl_create_window_surface` and `dri2_wl_swrast_create_window_surface` — and the
  `-1` sentinel is written by the **swrast-specific** one, while `put_image2`,
  `get_image` and `swap_buffers` all belong to the `dri2_wl_swrast_*` family.
- Consequence recorded honestly: the hardware paths use different constructors and do
  not share that vtable, so the evidence **does not implicate the i965/i915 path**.
  I-001 is therefore a defect of the vendor's Wayland **software-rendering** path,
  which is exactly the path this VM must use. That lowers rather than raises its
  real-world severity, and the register now says so.
- Also noted: the vendor image ships its own DRI drivers (`usr/lib/dri/i965_dri.so`,
  `usr/lib/dri/iu3d9_dri.so`, `usr/lib/mesadri/i915_dri.so`), so the "mixed stack"
  caveat is about which module loads, not about missing vendor code.
- No Intel hardware is needed for the remaining authorised work: the navigation
  `0x0` adapter, services, audio, CAN/MICOM and persistence all run in the VM.

## 0.76.0 - null-buffer question resolved: hide does not produce BG

- Settled the outstanding navigation question with DWARF rather than inference.
  `usr/bin/weston` retains debug info for `weston_surface` (weston 1.10.0-r21), which
  fixes the layout: `width` at `0x68`, `height` at `0x6c`, `width_from_buffer` at
  `0x104`, `height_from_buffer` at `0x108`. That confirms the FG/BG predicate tests
  the surface's own size, fed from the `_from_buffer` pair at commit.
- A null attach **does** zero both `_from_buffer` fields (`0x40f813`, reached when the
  buffer pointer is null). My previous entry stopped there and concluded BG was
  reachable. That was wrong: the size block at `0x40f470` runs **before** that
  zeroing, so it stores the *previous* positive size and the surface stays positive.
- Therefore **a bare `hide()` does not produce BG**; a genuine `0x0` size transition is
  required, matching the earlier Camera/Standby control. The integration route needs a
  scoped resize adapter rather than the authentic hide path.
- Recorded transparently: this reverses the correction I made two turns ago, and the
  withdrawn reasoning is preserved in the analysis report rather than deleted.
- Two method notes: the DWARF dump needed `/opt/homebrew/opt/llvm/bin/llvm-dwarfdump`
  with a byte-window scan, and several of my earlier greps silently matched nothing
  because `objdump` separates columns with tabs, not spaces.

## 0.75.0 - authentic measurement: dimensions are -1 then 1920x720

- Ran the observer against the **authentic AppCamera** inside the real launcher chain
  and captured both EC-01 stages on the same surface pointer:
  `libEGL+0x16f16` (before the width cache) read width **-1**, height **-1**;
  `libEGL+0x16f1e` (immediately after `swrast_update_buffers` returned) read width
  **1920**, height **720**. Teardown reported `verified detach=ok`.
- This **measures** the ordering defect behind I-001 instead of inferring it: the
  stride used by the copy path was derived from `Width = -1` (giving `-4` bytes)
  while the update populated the real geometry during the same invocation. It
  supersedes earlier statements that a width change had not been observed, including
  my own correction of two turns ago.
- `Ioniq5-VULNERABILITIES.md` I-001 rewritten accordingly: mechanism measured, still
  not a demonstrated exploitable vulnerability, stock-driver reachability and
  attacker influence explicitly unestablished.
- Setup notes worth keeping: the canonical vendor image must not be modified, and a
  plain copy costs 23 GB, so the run used an **APFS copy-on-write clone** (0.031 s)
  with two files injected by `debugfs`. A first attempt to stream the binary over the
  serial console failed because the whole command became one 80 KB line and the line
  discipline truncated it.
- Two real defects surfaced and were fixed: the driver inherited an argument-guard
  block that still tested the old crash observer, and the observer resolved `libEGL`
  before the client had mapped it. The latter is a genuine race — `AppCamera` is
  visible before its graphics libraries load — and is now handled by a bounded
  `--wait-module-ms` poll.

## 0.74.0 - observer gains field capture; three validation cases pass

- Added the increment the ledger recorded next for EC-03: **int32 field capture at
  an observation hit**. The observer now reads two fields from a struct pointer
  supplied either absolutely (`--struct-addr`) or from a register (`--struct-reg`),
  defaulting to the EC-01 contract offsets `+0x2c` (width) and `+0x30` (height),
  with `--off-a`/`--off-b` overrides. That is the shape needed to capture the vendor
  `dri2_surf` dimensions before and after the buffer update.
- Validated in the VM in three cases, all exit 0, 12.87 s total: without `--once` the
  tracee outlives the observer and teardown reports `unverifiable reason=tracee-gone`;
  with `--once` it reports `teardown=verified detach=ok`; and an unknown register
  name is reported as `FIELDS status=unknown-register` rather than guessed.
- Measured `FIELDS status=ok a=1926 b=753` at `+0x2c`/`+0x30`, i.e. the instrument
  reads the intended fields from a struct pointer.
- Honest bound: the register-held pointer mode is only validated on its error path,
  because a synthetic target cannot reliably place a chosen value in a callee-saved
  register at a breakpoint. That mode gets its real exercise at the authentic
  AppCamera stage with `--struct-reg r15`.
- Defect found and fixed during the increment: an unused `field_regs` global that
  `-Werror` rejected, removed rather than silenced.

## 0.73.0 - second skill bundle pulled, policy re-applied mechanically

- Pulled `AiSkills-Council-Astra-Medium-or-Sol-XHigh.zip` and installed it over both
  skills. The substantive change is Council defaulting to **three Sol 6.1 reviewers
  at `xhigh`**, with Astra-medium supported and `sol` aliasing Sol 6.1.
- The bundle again shipped without the direct-DeepSeek-provider rule and still named
  the superseded `deepseek/deepseek-v4.1-flash` route. Rather than editing by hand a
  second time, added `work/skills-update-261029/apply_direct_deepseek_policy.py`: an
  idempotent patcher that enforces the policy across `SKILL.md`, both protocol
  references, README, installation guide and invocation metadata, tries several
  anchors because the Council protocol wording has changed between bundles, and
  fails loudly if it cannot find a place to apply the rule.
- Re-validated after patching: 148 + 93 unit tests pass and both skills report
  "Skill is valid!".
- Left deliberately unchanged: nine occurrences of the stale route id in
  `tests/support.py`, `tests/test_workflow.py` and `templates/ledger.example.json`.
  Those are test fixtures and an example, not policy statements, and editing them
  risks breaking assertions that bind to the literal.

## 0.72.0 - skills updated, disclosure reduced, EC-03 minimal core working

- Installed the Sol 6.1 skill bundle into the Parallelism and Council skills. The
  bundle switches default reviewers to `gpt-6.1-sol` and replaces Astra in examples
  and fixtures. It did **not** carry the operator's direct-DeepSeek-provider rule and
  still named the superseded `deepseek/deepseek-v4.1-flash` route, so that policy was
  re-applied across `SKILL.md`, `references/protocol.md`, `README.md`,
  `docs/INSTALLATION.md`, `agents/openai.yaml` and The Council, using the verified
  direct route `deepseek/deepseek-flash`.
- Both skills re-validated: 148 + 93 unit tests pass and the packaging validator
  reports "Skill is valid!" for each. The earlier validator failure was a
  missing-PyYAML interpreter, not a skill defect; using a yaml-enabled interpreter
  resolves it.
- **Public disclosure reduced.** The mirror's V-006/V-007/V-008 entries are now
  status-only, with no component names, property names, code locations or payload
  detail. Verified the public tree contains no occurrence of the affected service
  name or property name. Full dossiers remain in the private register.
- Noted rather than altered: the engineering-mode entry sequence and PIN were
  already published in the public tree by earlier work, so removing them now would
  not undo that exposure. Flagged for the owner.
- **EC-02 rescoped and EC-03 minimal core implemented.** Rather than a fifth
  specification round, built `tools/uk_fw/guest/ec03_observer.c`: SEIZE on one
  thread, up to four execute breakpoints addressed as module-substring + offset,
  bounded register capture, disarm-after-hit, mandated disarm/verify/detach
  teardown, a 60 s deadline and a bounded stop count.
- Validated end-to-end in the VM against a synthetic target in two cases: without
  `--once` the tracee runs to completion and teardown is honestly reported
  `unverifiable reason=tracee-gone`; with `--once` the observer detaches while the
  tracee is stopped and reports `teardown=verified detach=ok`. Both exit 0.
- Three defects found and fixed during validation: a missing `stddef.h` for
  `offsetof`, module-base resolution that wrongly required an offset-zero mapping
  (static non-PIE text has none), and teardown being attempted on an already-exited
  tracee. The guest image also has no busybox applet symlinks, so the driver invokes
  applets through `/bin/busybox` explicitly.
- EC-02 is recorded as **blocked/superseded, not accepted**. Remaining bounds: the
  vendor libEGL observation points, surface field capture and the resolved-copy-entry
  stage were not exercised.

## 0.71.0 - null-buffer BG question narrowed, with a reversed inference

- Returned to the main navigation workstream (independent of the EC-02 gate) to
  answer whether a Qt hide can ever produce the BG notification the manager needs.
- Proven by disassembly: the FG/BG predicate is in `ivi-window-manager.so` at
  `0xf981` and tests the surface size fields `0x68`/`0x6c`, reproducing the known
  rule (any positive dimension selects FG). Those fields are written only by
  `surface_set_size` (`usr/bin/weston` `0x40d4a0`), whose three call sites are all
  inside `weston_surface_commit_state`.
- First inference — that a null buffer leaves the size positive and therefore
  cannot produce BG — was **contradicted by two further checks** and is recorded as
  reversed rather than quietly dropped. `surface_attach` gives a NULL buffer the
  same `pending+0x00` "buffer attached" flag as a real one, and the commit path
  enters the size block whenever that flag is set. So a null-buffer commit *does*
  reach `surface_set_size`.
- Whether that call writes `0x0` depends on `[rbx+0x104]`/`[rbx+0x108]`, whose
  meaning for a null attach is not yet established. A hidden surface producing
  `0x0` and hence BG is therefore **plausible, not excluded**, which raises rather
  than lowers the value of pursuing AppNavi's authentic hide path.
- One delegated worker was interrupted mid-analysis by the pi-gui restart; its six
  listings were retained and the analysis completed by the coordinator. No rootfs
  file was modified and no VM was booted.

## 0.70.0 - capability matrix complete: per-thread scoping verified

- Closed the last open capability item. Debug registers are **per thread**: after
  the traced main thread trapped and was stepped past, the slot was deliberately
  re-armed, and an untraced sibling thread then executed the same function with no
  effect — the process exited 0. Eleven checks pass in 3.94 s, exit 0.
- The test is sequenced rather than raced (the sibling waits on a flag), so it
  distinguishes the two outcomes deterministically: an unaffected sibling gives a
  clean exit, while a process-wide slot would make the untraced sibling die on
  `SIGTRAP`, the same failure signature measured in T8.
- Consequence for EC-02: single-thread observation is sound and does not require
  thread-group control or `PTRACE_O_TRACECLONE`, which removes an open design
  question rather than adding one.
- Authoring correction recorded: an edit that added the threading headers replaced
  `stdarg.h` instead of adding to the include list, caught by `-Werror` at build
  time before any VM run.
- Newly stated bounds: only execute breakpoints were tested; data read/write
  watchpoints were not, and behaviour with many threads or `PTRACE_O_TRACECLONE`
  was not examined.

## 0.69.0 - DR6 attribution verified; transcript IV claim corroborated

- Completed the capability matrix: `DR6` carries per-slot trap bits and is
  clearable through ptrace. With slots 0 and 1 armed, the first trap reported
  `DR6`=0x1 (B0), `POKEUSER DR6 = 0` read back 0x0, and the second trap reported
  `DR6`=0x2 (B1). Ten checks now pass in 3.83 s, exit 0.
- This removes another assumption the EC-02 specification had argued about: the
  observer can attribute a trap to a specific slot and drop stale status between
  stages, rather than inferring the slot from RIP alone.
- Remaining unexercised: per-TID scoping, i.e. one traced thread while a sibling
  executes the same code.
- Checked the community transcript's most testable claim against our own tooling.
  The chat states the encryption IV is "derived from the SHA256 of the encrypted
  file name and size"; `tools/uk_fw/gen5w_decrypt.py` independently implements
  exactly that, as the first 16 bytes of
  `SHA256((basename + signed_int32(body_size)))` with body size `file_size - 0x4024`,
  and produces working decryptions. The claim is therefore corroborated, and the
  transcript now records the precise semantics rather than leaving it as a lead.
- No VM image was modified and no vendor binary was executed beyond the earlier
  observation runs; the probe continues to use a synthetic tracee.

## 0.68.0 - community chat transcribed into evidence

- Transcribed eight owner-supplied Discord screenshots into
  `evidence/community-chat-transcript-261029.md` as a single de-duplicated,
  timestamp-preserving log with attribution. Recorded as unverified participant
  reports, not findings, consistent with the existing community-leads policy.
- The transcript confirms the provenance of the three exploit bullets that became
  V-006/V-007/V-008, and cross-references each against our own offline results:
  V-006 confirmed but with a different mechanism than the claim, V-007 configuration
  only, V-008 normal password-gated behaviour.
- Extracted the actionable leads and ran cheap offline checks. `AppEngineerMode`
  is present with QML at `/app/share/AppEngineerMode/qml/main.qml`, but neither the
  reported PIN `19480717` nor the tap sequence `3 2 8 9 6 5` appears as text there,
  so the entry handler is almost certainly the Settings app behind
  *System info -> Manual* rather than the engineering binary.
- `/tool/velix_aes.key` and `/tool/public.crt` do not exist in the rootfs; those
  paths belong to the AppUpgrade payload and must be looked for in its decrypted
  tree. The claimed IV derivation from the SHA-256 of encrypted name and size
  remains the most testable claim and is flagged for checking against
  `tools/uk_fw/gen5w_decrypt.py`.
- Publication caution recorded: the transcript contains an engineering-mode PIN, a
  claimed VM digest and a partial key-like string, so `PUBLIC-RELEASE.md` applies
  before any mirroring to the public repository.

## 0.67.0 - detach discipline measured; four-slot behaviour verified

- Extended the capability probe to the four behaviours round 1 left unexercised.
  Nine checks now pass in **3.85 s**, exit 0.
- **Four slots armed simultaneously** (`DR7` image `0x455`) fire in program order
  at the correct RIPs, provided the fired slot is disarmed before resuming —
  an execute breakpoint retriggers if left enabled, so this discipline is
  mandatory rather than stylistic.
- **Slot replacement** works: slot 0 fired at one function, then at a different
  address after reprogramming.
- **`DR4`/`DR5` are rejected** by the kernel with `EIO`, confirming the valid
  index set is `0-3,6,7`. EC-02's fixture V-03 had assumed a fifth slot could be
  tested through `DR4`; that assumption is wrong and is now measured.
- **Detach alone is unsafe.** With a slot still armed, `PTRACE_DETACH` leaves the
  breakpoint live and the untraced process is **killed by `SIGTRAP`**. This
  confirms EC-02's C-09 concern was real rather than defensive.
- **The safe exit is proven**: clear the `DR7` enables, clear the address
  register, verify the readback is zero, then detach. The tracee then completes
  with exit 0.
- Bounds held: synthetic tracee at user addresses, no vendor observation point;
  per-TID scoping and `DR6` semantics beyond `B0` remain unexercised.

## 0.66.0 - guest hardware breakpoints proven under TCG

- Resolved the single load-bearing unknown behind EC-02 by measurement rather than
  further specification: the guest **does** honour `DR0`/`DR7` execute breakpoints
  set through ptrace under QEMU TCG with the measured `4.1.27-abl` kernel.
- Wrote `tools/uk_fw/guest/dr_breakpoint_probe.c` (VM-only capability probe, no
  vendor code) and ran it in 3.64 s through the project's own harness with the
  documented `--sdhci-compat` adaptation. Four checks all pass: no-trap control;
  armed execute breakpoint firing at exactly the armed address with `DR6.B0` set;
  clean disarm and completion with no re-trap; and single step advancing RIP.
- One self-correction during authoring: the first draft needed a missing
  `stdarg.h` and left its tracee parked after the trap; it was rewritten as a
  single arm/trap/restore/clean-exit sequence before any run.
- Consequence: EC-02 was never blocked on capability, only on specification. The
  fixture it deferred this question to turns out to be cheap and runnable without
  vendor userspace. Remaining EC-02 blockers are spec defects alone.
- Bounded honestly: proven on a synthetic tracee at user addresses, not on vendor
  libEGL observation points; four-slot capacity, slot replacement, `DR6` semantics
  beyond `B0`, and detach-time teardown remain unexercised. No vendor binary was
  executed and no navigation state was claimed.

## 0.65.0 - EC-02 blocked by over-specification; rescope recommended

- Ran four lead reviews of the EC-02 hardware-breakpoint mechanism. Round 3
  changed approach as instructed: policy moved into a new normative
  `ec02-state-machine.json` (17 states, 48 transitions, 21-row classify-only
  decision table, mechanically derived budget) with the report and facts reduced
  to citations of it.
- The fourth review still returned REQUEST_CHANGES, with real structural defects:
  missing pre-arm and subsequent revalidation failure edges, a missing
  `ST_SEIZE -> ST_STOP0` transition and initial interrupt, already-forwarded
  signals staying pending for redelivery, budget sums that disagree with their
  declarations, unreachable maxima, a detach-error terminal falsely reporting
  "detached", classifier row shadowing, and single-step routing inconsistencies.
- Diagnosis recorded rather than looping again: the defect is over-specification.
  The mechanism report grew from 771 to 1,931 lines plus a 1,187-line state machine
  for a bounded diagnostic tool, and each correction exposes a new edge because
  edge policy is being authored without implementation feedback.
- Recommendation: rescope EC-03 to a minimal verifiable core (SEIZE, four
  hardware observation points, bounded capture, restoration, host-owned timeout)
  and let the EC-04 fixtures settle the remaining edge policy empirically. No
  fifth textual correction round was run.
- EC-03 remains gated. No VM boot, no target execution, no fixture run and no
  measured EGL claim. Ledger validates; artifacts re-hashed.

## 0.64.0 - advisor claims validated: one confirmed root command injection

- Validated the three 2026-10-28 advisor claims offline against the recovered
  `260128` rootfs. **V-006 upgraded to a confirmed static command injection**
  (CWE-78) in `/app/bin/usb-automount`: `system()` at `0x535f` and `popen()` at
  `0x53b9` build shell commands from `ID_SERIAL_SHORT`, reachable on the PTP
  (`060101`) or vendor-specific (`ffff00`) branch and running as uid 0. The
  advisor's "mount script" mechanism and literal payload were both wrong: udev's
  `util_replace_whitespace` neutralises spaces, so only parameter expansion works.
- **V-007** confirmed as configuration only (media parsers configured uid 0, no
  seccomp or capability limits, zero setuid binaries image-wide) and reclassified
  as informational hardening rather than a vulnerability.
- **V-008** confirmed as shipped configuration (root console on ttyS2, autologin
  commented out, `$6$` SHA-512 verifier with unique salt, other accounts locked)
  but **not** as a vulnerability: no bypass, no weak hash. Fail-open ordering in
  `esinit` and dormant Dropbear key material noted.
- Astra triaged and corrected several overstatements, including that a
  system-service default is not an observed uid and that a password verifier is
  not evidence of weakness. Astra advised holding the technical dossiers
  privately pending vendor contact; the public mirror remains at its conservative
  "unverified" text.
- Fable returned no output on two attempts, so Astra performed the triage and is
  attributed. All evidence is static; no VM boot and no hardware contact.

## 0.63.0 - unverified physical-access vectors logged

- Added V-006/V-007/V-008 to the defensive register from a third-party advisor
  summary: USB descriptor strings into a privileged mount script, media parsing as
  root, and a hashed-password root serial console. All three are labelled
  **unverified actor reports** with no code path, process identity, console device
  or reproduction supplied; none was validated in this session.
- Recorded the engineering caveats that bound them: USB string descriptors are
  UTF-16LE (metacharacters arrive NUL-interleaved) and `udev` sanitises
  `ID_SERIAL`/`ID_MODEL`, so a vulnerable consumer would have to be custom; the
  126-code-unit descriptor limit still admits a ~40-character payload, making
  encoding and shell quoting rather than length the binding constraint; a hashed
  root console password is ordinary practice and only becomes a finding if weak,
  reused, bypassable or extractable.
- All three require physical access; none is remote. Validation is scoped to the
  isolated VM snapshot or offline analysis of the recovered rootfs. No hardware
  was touched and no attack tooling was built.

## 0.61.0 - Parallelism/Council measurement-plan checkpoint

- Activated the requested Parallelism + three-seat Council workflow using inline
  workers only. Astra-high led planning; Astra-high and two independent Sol-medium
  seats reviewed and reconciled the same frozen package. The Council checker
  returned `COMPLETE` for the **plan only**, with package fingerprint
  `c59ac8a0d4ece96fd8fab5fe8a6795789697c95394d6e548a02dc8484052bbb5`
  and packet SHA-256
  `528649b5b337fb0b76bafd6cb9b020e572851ec33136c6d0927a5c38a12ef790`.
- Corrected the experimental claim boundary: captured `-4` supports an invalid
  width-derived copy count, but does not yet prove width changed during that
  update or that the original width was `-1`. The accepted plan distinguishes
  EGL call-site arguments from the actual resolved libc entry and requires
  PLT/IFUNC-aware evidence before a fix.
- DeepSeek EC-01/EC-02 did not run. The live tool rejects the required direct
  provider route `deepseek/deepseek-v4.1-flash` as unknown; its suggestion of an
  OpenCode route is not authorized. Parallelism and Council policy now requires
  direct `deepseek/...` provider routes and forbids intermediary fallback. No
  substitute model, implementation, VM run, new thread or bypass routing was
  used. Both tasks remain blocked in the validated ledger.
- Council suggestions require downstream contracts to record both mapped vendor
  EGL and project Mesa identities, numerical capture caps, debugger restoration,
  and host-owned disposable-VM termination. The scheduler still lists the prior
  heartbeat paused; update remains impossible because the exposed API requires
  fields it simultaneously rejects for interval schedules.

## 0.60.0 - bounded fault-time stack and EGL caller

- Added VM-only `ptrace_crash_observe.c`: explicit target allowlist, SEIZE rather
  than group SIGSTOP, bounded 64-word stack/64 KiB maps and original fatal-signal
  redelivery. Compiles statically with warnings-as-errors. Timeout/cancellation/
  group-stop paths remain dynamically untested and are not broadly accepted.
- Completed a short snapshot experiment with guest invalid-PID/disallowed-target
  tests and actual Camera fault capture; 64 stack words read, SIGSEGV re-delivered.
- Identified immediate memcpy call site in vendor EGL software put-image code.
  Cached width-derived stride precedes an update that can change the width;
  captured stride/count registers are -4. Original entry arguments/order remain
  to be measured before a fix. Added qualified investigation I-001 to the
  defensive register, not a confirmed exploitable vendor vulnerability.
- Complete archive SHA-256:
  `e0884a3c11582ed2b986db28f2673b7fde9297a1871f2633ad13672b2dfdeaae`.
  Safe extraction/digest checks pass; 168 repository tests pass; base rootfs
  independently rehashed unchanged. No new threads, commits or fabricated state;
  no independent-model review obtained due the recorded host worker error.

## 0.59.0 - focused early-client core capture

- Completed a short no-NIC/snapshot early-startup experiment in 44.83 seconds,
  capturing one 80 KiB AppCamera core with eight thread-register notes. No full
  agreement/Navigation sequence was attempted. Verified early-client decoration
  value is `1`; this does not validate AppNavi startup.
- Core notes/program headers confirm SIGSEGV/SEGV_MAPERR at libc offset
  `0x128dde`: vector-store destination lies 64 bytes below a writable mapping.
  Fault-thread stack bytes are absent; caller/original copy length remains unknown.
  Modified loop counter is not asserted to be an original argument.
- Requested coredump filter `0x10` read back zero; actual stored memory coverage
  is reported instead of assuming filter behavior. Retained validated core-note
  report, complete archive and exact scripts. Base rootfs rehashed unchanged.
- Archive SHA-256:
  `10fbb21b674ab1795c5e2b52d4e04ad47611f8674c4ac5ed43d283322c24987c`.
  Shell syntax/diff whitespace checks pass. No new thread, image mutation,
  vulnerability classification or Navigation-success claim.

## 0.58.0 - community-source reconciliation

- Recorded the owner's supplied channel-summary leads in
  `evidence/community-chat-leads.md`, explicitly not independently accessed or
  validated. Separated known tools from new compatibility/acquisition leads.
- Retained the tentative CV_E 220721 recollection as different-model comparison
  evidence, not an IONIQ install/downgrade recommendation. Bounded historical
  downloader availability by model, region, endpoint and time.
- Added current-reading warnings to three older evidence notes whose plaintext-
  recovery/API conclusions are superseded or too broad for current VM work.
- Added the reported signature-blocked updater attempt as unvalidated provenance
  for V-005, not a confirmed vulnerability. No fetching, new hardware testing,
  firmware installation or VM run occurred from these chat leads.

## 0.57.0 - 2026-10-27

- Corrected the delegation explanation: inline `spawn_worker` is exposed and
  supports model selection without new chat threads. Earlier statements that
  only child-thread delegation existed were wrong. A useful read-only dispatch
  requesting the configured DeepSeek route failed with host error
  `store.runWorkerToolResult is not a function`; no worker result or runtime
  routing was verified. Operations/handover now identify the actual blocker.
- Executed a snapshot-only decoration-unset control, preserving all other
  baseline flow and existing compatibility behavior. Complete archive recovered
  and digest-verified; harness exit 0 is not feature acceptance.
- Negative semantic result: repeated Camera/Standby crashes, agreement false,
  AppNavi not launched, manager queries 0/0 and all screenshots remain splash.
  The intended child value/geometry was not verified. Do not adopt this change
  or infer a Navigation fix; early-client environment/crash observation is missing.
- Mapped the repeated crash site to libc non-temporal vector store
  `vmovntdq %ymm0,(%r9)` at offset `0x128dde`. Caller/length/register context is
  unknown; this is a write fault, not proof of unsupported AVX or a vendor bug.
  Verified canonical and both new run manifests use the same CPU/memory profile.
- Identified a lower-overhead next capture: vendor kernel supports ELF cores,
  while guest has no inventoried gdb/gdbserver. Proposed bounded snapshot-only
  early-client core-note capture before writing a new sampler; not yet executed.
  Header-only filtering will not provide a complete stack backtrace.
- Complete archive SHA-256:
  `648b5d30c169b2e4adaa2e8cf069742fd5b3d779b0ef1d6d7e63fead7f6910e9`.
  Retained exact source delta, summary, logs and evidence. Base image rehashed
  unchanged; baseline preserved, no new threads or vulnerability claim.

## 0.56.0 - 2026-10-27

- Ran an observation-only wrapper around the unchanged baseline launcher flow in
  isolated QEMU snapshot mode. Completed command exit 0 without timeout; captured
  26 AppNavi maps snapshots and allowlisted environment/mapped-file hashes.
- Runtime maps confirm the analyzed QtWayland client and EGL plugin load. Actual
  AppNavi environment has decoration-disable `1:1`; decoration plugin also loads.
  Parser effect and causal impact are unverified, not a completed fix.
- Authentic Home visibly renders before Navigation. Manager again follows
  `11/11 → 35/11 → 11/11` with FG delivery and status 5/window 0. Final return
  screenshot is black: manager-state return is not visible-Home acceptance.
- Follow-up static review confirms decoration-disable is parsed as a decimal
  scalar via QByteArray::toInt and cached, not as a colon-separated list. The
  inherited `1:1` is malformed for this consumer; exact-library execution of the
  parser remains untested. No environment correction has yet been applied.
- Raw Wayland requests were not captured despite WAYLAND_DEBUG; next observe
  actual hide/attach execution without changing behavior. Retained late cleanup-
  vicinity Camera/Radio crash messages without calling them vulnerabilities.
- Complete archive SHA-256:
  `6019ec6e42cacce8a41fdc79c7dd9705487efdc0a53b741313e6b5b7aad01d84`.
  Decode digest verified; extracted safely. Base rootfs independently rehashed
  unchanged. All 168 tests, shell syntax check and diff whitespace check pass.
  No new threads, image mutation, synthetic callbacks or commits.

## 0.55.0 - 2026-10-27

- Confirmed constructor connection of the same Qt object's visibleChanged(bool)
  to AppNavi onVisibleChanged(bool), refining the prior signal-source uncertainty.
- Traced recovered QtWayland false-visibility handling: explicit null-buffer
  attach/commit occurs only when a virtual discriminator returns zero. Recovered
  EGL plugin inherits that handler and its discriminator returns one, skipping
  that branch. Retained disassembly, relocation evidence and exact signal strings.
- Read-only extraction confirms current-image QtWayland library and EGL plugin
  bytes match the analyzed originals. Runtime selection remains unverified:
  launcher logs inspected lack backend-load identity and alternate library
  search paths precede `/usr/lib`. Next run must first capture mapped identities
  and hide requests without changing behavior.
- This is not yet a guest-backend/root-cause proof. Next verify runtime library
  selection and actual commits; explain older positive controls before
  proposing a narrowly scoped VM adapter. No vendor state or callback fabricated,
  no images changed, no new threads or vulnerability claims.

## 0.54.0 - 2026-10-27

- Host execution recovered; no QEMU/LLVM worker was found in the process check.
  Fresh bounded shell disassembly and read-only current-image extraction passed.
- Current-image IVI shell matches the recovered original. Surface creation
  initializes cached size to 0/0; configure suppresses unchanged dimensions and
  calls layout configure only after a size change. This narrows the prior
  initial-zero hypothesis: no automatic BG event is expected solely from a
  newly created zero-size surface through this path.
- Positive retained controls now show Camera and Standby each configure
  1926×753 → 0×0, then emit BG successfully and reach the manager. Retained
  hashed event excerpts. This demonstrates an earlier working VM transport and
  narrows the next task to AppNavi's hide/unmap/buffer-commit sequence.
- AppNavi visibility follow-up: `onVisibleChanged(false)` sets first-hide state,
  may send the one-shot boot notification, and calls renderer clear/swap. This
  does not prove parent Qt-window unmapping or a null Wayland buffer commit.
  Retained bounded disassembly; next separate the native map-screen callback
  from the parent-window hide path.
- Located authentic `QWindow::hide()` at `0x3362275` in AppNavi foreground
  handling, behind base-result and screen gates. Latest PID-specific logs show
  widget foreground activity but no matching primary-screen hide diagnostic;
  this remains a bounded log observation, not proof of absent invocation.
- Updated evidence and handover. No VM/image edits, new threads or vulnerability
  claims; `git diff --check` passes.

## 0.53.0 - 2026-10-26

- Follow-up provenance: read-only extraction of both compositor paths from the
  current image matches the original module digest; retained Weston log records
  loading the `/usr/lib/weston` path. This is not a historical memory digest.
- Shell-module follow-up commands timed out; completion is unverified. Resume
  only after checking host/process health; do not start duplicate analysis/VM
  runs. Existing scheduled task remains observed active, but prompt update is
  still rejected by scheduler validation.
- Recovered the original compositor callback's final FG/BG branch: any positive
  width or height emits FG; BG requires both non-positive. Exact full-screen
  dimensions are not tested, so changing 1926×753 to 1920×720 would not repair
  that branch. No geometry fix was applied based on the prior hypothesis.
- Hash-identified byte-identical recovered compositor copies and retained LLVM
  disassembly. Next inspect initial configure ordering and verify guest loaded
  module identity. Distinguish the local callback from the nearby exported
  function despite LLVM nearest-symbol labels. No runtime experiment, image
  mutation, synthetic BG event, new thread or vulnerability claim occurred.

## 0.52.0 - 2026-10-26

- Recovered exact QString-list membership after display matching; the subsequent
  AppNavi substring check is a separate predicate. Pending global initializes
  nonzero (`0xffffffff`), so initial zero state is not established as the cause.
- Correlated the full retained latest DLT log: authentic AppNavi surface 3000
  produces an FG callback received by ApplicationManager before status 5/window
  0. The log has no BG-info or naviWindoeCreate diagnostic matches. This narrows
  the next investigation to compositor FG/BG classification/routing.
- Recorded 1926×753 parent geometry as an observation, not a causal conclusion;
  decoration-disable environment is already set. Retained hashed event summary
  and matcher disassembly; updated evidence and handover. No VM changes or new
  runtime run; no new vulnerability claim. `git diff --check` passes.

## 0.51.0 - 2026-10-26

- Traced the window-setter caller into `slotNotifyBGInfo`, whose diagnostic
  identifies surface-ID, display and app-ID inputs. The AppNavi notification
  path additionally requires a display/string helper match, a nonzero global
  gate, and case-sensitive `AppNavi` containment; it clears that gate afterward.
- Recorded exact control-flow addresses and unknown matcher/global semantics
  in the Navigation evidence note. Next trace the upstream event caller and
  gate initialization rather than force a notification. No VM mutation or new
  runtime acceptance is claimed; diff whitespace validation passes.

## 0.50.0 - 2026-10-26

- Recovered ApplicationManager's exact Qt subscription to
  `notifyNaviLaunched(int)` and the routine producing the recorded diagnostic.
- Identified `window[%2]` as a separately latched receiver byte (+0x20), not a
  second boot-signal argument or a surface ID. Zero gates downstream dispatch.
  Adjacent vendor `naviWindoeCreate` code updates the byte and replays cached
  status (+0x1c); next trace direct caller `0x19108d` to recover its producer.
- Retained full LLVM disassembly and bounded extracts; updated Navigation
  evidence and handover. Status-5 enum semantics and runtime acceptance remain
  unresolved. No flags were forced and no VM/image/thread changes occurred.

## 0.49.0 - 2026-10-26

- Identified original ApplicationManager by SHA-256 and mapped six matching
  notification/interface string locations for receiver triage. No handler address
  or enum semantics is claimed from literal strings alone.
- Ordinary/dynamic symbol searches did not expose named handlers. REA deep
  providers are unavailable in the current environment configuration; no tooling
  configuration was changed. Retained raw locations and evidence limits in the
  Navigation contract note and project-local JSON. No target execution or image
  mutation occurred; `git diff --check` passes.

## 0.48.0 - 2026-10-26

- Resolved notification string references against SHA-256-identified original
  recovered AppNavi using read-only ELF section mapping. The function first
  calls `com.lge.avn.applauncher` `/Inform` interface
  `com.lge.avn.applauncher.inform` method `launched(30)`, then emits
  `/navigation_map` interface `com.lge.hkmc.avn.appnavi.naviboot` signal
  `SendNaviBootFail(5)`. These are distinct registration/status messages.
- Retained raw mappings in `work/vm/vendor-userspace-260128/appnavi-notification-strings.json`
  and conclusions in `evidence/navigation-launch-status-contract.md`.
  Located original ApplicationManager for the next receiver analysis. Enum
  semantics, caller selection and window-state producer remain unresolved.
- No target execution, image modification, new threads or security findings.

## 0.47.0 - 2026-10-26

- Reviewed existing saved AppNavi notification disassembly. This function sends
  literal status `5` after an initial one-shot gate; it does not derive that
  integer from engine state within the reviewed function. Exact enum semantics,
  message identity and manager window-state producer remain unresolved.
- Added `evidence/navigation-launch-status-contract.md` with instruction
  addresses, bounded conclusions and next exact receiver/string-mapping work.
  No image mutation, fresh VM run, new thread or vulnerability claim occurred.
- Existing active scheduled-task prompt update was rejected by tool validation;
  no successful update or replacement schedule is claimed. See operations/history.

## 0.46.0 - 2026-10-26

- Reconciled current progress against the existing handover, detailed changelog,
  append-only history, corrections, Git history and security notes. Retained
  existing milestones; no fresh firmware or VM success is claimed.
- Backfilled the history after its 2026-10-19 cutoff with source-labelled
  retrospective milestones, including the corrected VM boot, module-loading
  observation, native userspace recovery, authentic Home and incomplete
  Home↔Navigation integration.
- Added `Ioniq5-VULNERABILITIES.md`, a separate defensive register with evidence,
  preconditions, remediation and acceptance tests. It distinguishes previously
  VM-verified unsigned-module loading from unvalidated keystore/trust/update
  candidates, rejected hypotheses and third-party modification hazards.
- Added `PROJECT-OPERATIONS.md` with the full-VM objective, current blocker,
  append-only rules and an explicit existing-chat-only scheduled prompt draft.
  Scheduling awaits owner confirmation of interval and active-work behavior.
- Read-only routing inspection found the installed DeepSeek Flash builder
  statically ready, but inference routing remains unverified. This session lacks
  native role-selectable subagent tools; no child threads or workers were
  created, and no model/router configuration was changed.
- Preserved the pre-existing dirty source tree, untracked research artifacts,
  firmware and VM images. No commits, pushes, flashes or new VM runs occurred.
- Validation: 168 repository unit tests pass; `git diff --check` passes. Verified
  that the history's original 6,819-byte prefix remains byte-identical.

## 0.45.0 - 2026-10-26

- Added a launcher-local `execve` interposer that supplies the EGL compatibility
  preload only to AppLauncher's original signature-checked AppNavi child. It
  does not directly launch a duplicate AppNavi and does not preload unrelated
  vendor applications.
- The original AppLauncher-owned AppNavi reached map-engine success, selected
  logical `Samples: 2`, created parent surface `3000` with `AID(AppNavi)`, and
  created child surface `4903` while AppLauncher and ApplicationManager remained
  responsive.
- Recovered AppNavi's exact startup decision in
  `NimoExSLApplicationLinux::onInitializeDone()`: offset `0x33b48be` compares
  elapsed startup with `0x59d7` (22,999 ms), and the slow path invokes
  `SendToAppLauncherNaviLaunchedToExcute()`.
- Added a fail-closed, sentinel-gated, executable-scoped VM timing control. It
  validates the expected four immediate bytes and changes only the in-memory
  startup deadline from 22,999 to 180,000 ms using the PIE load base; the signed
  AppNavi file is unchanged. The first non-PIE-aware attempt is retained as a
  negative control because it caused AppNavi `SIGSEGV`/restart churn.
- With the corrected control, AppNavi completed initialization at 106,464 ms,
  created its parent window, and entered the launch-status path only after the
  authentic window event. This ruled out the 22,999 ms timeout ordering as the
  sole cause of the incomplete manager transition.
- The launch path still emitted `SendNaviBootFail(5)` and ApplicationManager
  logged `notifyNaviLaunched[5] window[0]`. Manager state remained `35/11`, no
  Navigation frame was foregrounded, and the authentic return request restored
  state `11/11` plus visible Home. Full Home↔Navigation acceptance remains
  unproven.
- Latest runner SHA-256 is
  `906e734012a9a9cac35aed2e9258674215b407a93cdce9e58024a2f78bf8dd9f`;
  host-log SHA-256 is
  `de9977d671cb203f918d878f939777c1eea330bad90dd2ca0643b6ba57c60021`;
  complete evidence archive SHA-256 is
  `a0e2100ca5a0eb72426db6179c88a27e34abe5928d8a364ce9f14d0e9bfd52b8`.
- Current rootfs SHA-256 is
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`;
  `prepare.json` matches and `e2fsck -fn` passes.

## 0.44.0 - 2026-10-26

- Established the first semantically corroborated authentic profile-confirm
  path under global two-thread llvmpipe. AppStandbyClock logs
  `confirmSkPressed()`, `onPressedButton`, `onReleased`, and
  `HANDLER_CONFIRMSCREEN_BUTTON_CONFIRM_CLICKED` after bounded pointer input to
  the observed enabled Confirm control.
- Standby progresses from `14` to `12`; ApplicationManager explicitly logs
  `is_standby_agree_pressed standbyStatus[12] result[1]`. Exception-filter
  masks `66` and `161` both return zero, superseding the prior mask-`161`
  result `32` seen before agreement.
- The immediate Home-transition D-Bus out value remains `255`, but downstream
  evidence proves it is not sufficient to classify the asynchronous request
  as rejected: manager current AppID becomes Home `11`, Home returns `ret[1]`,
  drawing AppID becomes `11`, and IVI foregrounds run-specific surface `1001`.
- Added the separately named VM-only Home-settle control. It pauses only
  ApplicationManager for 55 seconds after authentic `requestShow(APP_HOME)` so
  the unmodified Home binary can finish its first frame without a false
  production-liveness kill under x86 TCG software rendering, then resumes the
  manager and repeats the authentic Home request. It does not fabricate an
  alive reply, acceptance state, manager result, application ID, or pixels.
- Captured visibly composed authentic Home at 1920×720. The final vehicle,
  battery/range, and Media Off frame has SHA-256
  `23ccd6e6002d8bceddac3a64b2c94538cb844cc9aa274b44d18ada876d2cc968`.
- Positive evidence archive SHA-256 is
  `87d81b278f8b1bb20236faedd17dda0493b49b6cfc1e0fd2f1acfe8b8d2c6f5e`;
  host-log SHA-256 is
  `2c6c7ed142cb84b7dcc5daf5a9adb01a2e86934c731ae5653efa5d0d80d93b95`.
- Full Home↔Navigation operation remains unproven. AppNavi, data-bearing
  micom/CAN methods, authentic persistence, and production-speed liveness
  behavior remain separate unresolved boundaries.
- Current rootfs SHA-256 is
  `8a686d4bf0b278d7e99dd5d94181a58e5b5ef147bff9f99444a25d0134e16756`;
  `prepare.json` matches and `e2fsck -fn` passes.

## 0.43.0 - 2026-10-26

- Reached and repeatedly foregrounded the authentic AppStandbyClock
  profile-confirm screen with restored production ASTC assets. Runtime QML
  observation places the enabled Confirm control at `x=471..1179`,
  `y=621..699`; the transformed pointer point is inside it.
- Added exact-build observational pointer-focus logging to
  `tools/uk_fw/guest/weston_vm_input.c`. Every phase of the bounded pointer
  gesture remains focused on the authentic AppStandbyClock PID, excluding a
  late AppEURadio/Home client as the current routing owner.
- Identified the authentic screen/Loader sizing defect in this VM: the loaded
  `QRootScreen` and parent Loader resolve to `0×0` while explicit-size children
  render outside them. A separately named VM compatibility control adds
  `anchors.fill: parent` to both alternating Loaders and yields a complete
  `1920×720` screen → Loader → main-root ancestry without changing the legal
  handler or model state.
- The Loader repair does not by itself deliver Qt Quick input. A direct
  full-screen observational MouseArea still receives no press even though
  Weston sends motion/down/up to the correct client.
- Added bounded syscall and RIP observers. The QtWayland thread receives the
  three expected Wayland input batches (`recvmsg` 20/72/24 bytes), while the
  main GUI thread remains runnable in userland. All 32 sampled instruction
  pointers map inside Mesa 18 `swrast_dri.so`; Qt cannot dispatch the queued
  input while synchronous software rasterization monopolizes the GUI thread.
- Negative VM controls—threaded render loop, `vblank_mode=0`, two softpipe
  threads, hidden live status bar/noninteractive layers, scheduler priority,
  temporary AppNavi quiescence, `SIGCONT`, and a 60-second post-input wait—do
  not produce the authentic Confirm handler. None is treated as acceptance.
- Standby remains `11`, the Home transition result remains `255`, and no legal
  confirmation, filter-bit clearance, or normal Home↔Navigation transition is
  claimed.
- Current rootfs SHA-256 is
  `32f4e81f3e637c7fc3c2b3457852b7b8473dda4f2cc0288bff11618cdda5abee`;
  `prepare.json` matches and `e2fsck -fn` passes.

## 0.42.0 - 2026-10-26

- Corrected the full-chain Qt/Wayland environment: the probe no longer
  pre-sets `QT_WAYLAND_SHELL_INTEGRATION=ivi` before authentic AppLauncher
  appends `:ivi`. The invalid `ivi:ivi` value is gone; Qt clients load
  `libivi.so` and log `Using the 'ivi' shell integration`.
- Added `--micom-serial` to the offline VM harness, providing guest
  `/dev/ttyS1` through a project-local Unix socket while retaining the no-NIC
  boundary. The authentic micom daemon now configures 115200-baud serial and
  registers `com.lge.car.micom`, although hardware-dependent boot-info calls
  still do not complete.
- Captured authentic `/Ihu` and `/Can` introspection and established the exact
  `AskSysBootinfo() -> ay` contract. Consumer disassembly and controlled runs
  confirm a 35-byte reply.
- Added fail-closed VM research helper
  `tools/uk_fw/guest/micom_dbus_sim.c`. It supplies only the exact boot-info
  data reply, exposes evidence-derived introspection, acknowledges only exact
  transport signatures, logs all byte-array/int32 arguments, and rejects
  unimplemented data-bearing methods. It is not recovered firmware or a full
  micom/CAN emulator.
- The corrected candidate profile makes AppLauncher select HMC, vehicle code
  `0x26`/38, Europe, 12.3-inch display, RHD, Navigation, Modem, and English
  instead of the prior LX2/Korea fallback. Remaining zero option fields are
  explicitly incomplete rather than claimed as an authentic Ultimate profile.
- Full-chain run `1792936845027660000` reached concurrent authentic activity:
  AppNavi reported engine success and created surfaces `3000` and `4903`;
  AppHomeScreen finished QML drawing and created surface `1004`;
  AppLauncher, ApplicationManager, and Home remained alive at the evidence
  checkpoint.
- Reclassified AppNavi's later `SIGTRAP`: ApplicationManager's liveness
  watchdog explicitly executes `killall -5 AppNavi` after missed responses.
  No spontaneous SIGSEGV/ABRT/BUS/ILL was found in that trace set.
- Direct-launch no-`strace` control run `1792937492664474000` reproduces the
  watchdog kill, excluding syscall tracing as the sole cause. Session-bus
  evidence identifies the exact liveness path: AppNavi answers the first
  `org.freedesktop.DBus.Peer.Ping` at `/navigation_map`, then fails to answer
  eight later Pings while software-rendered startup continues.
- Captured 301 micom calls over 34 method signatures, including exact CAN IDs,
  masks, registration records, CPU-alive transitions, boot-complete states,
  and DID/version writes. No CAN signals are fabricated yet; payload semantics
  must be mapped consumer-by-consumer first.
- The final frame remains splash. Home is still marked non-visible, AppNavi is
  watchdog-terminated, persistence resource tables are absent, and
  data-bearing micom/CAN transitions remain to be implemented and tested.
- Updated the current image identity to
  `817ca674b0e181209ca154236c9fc7d284b085caa0b045c5e4e66cd2fd081f5d`;
  copy-on-write checkpoints and `e2fsck -fn` controls passed.
- All 21 focused VM harness tests and all 167 repository tests pass; JSON
  manifests parse, Python compilation succeeds, and `git diff --check` passes.

## 0.41.0 - 2026-10-25

- Validated native TE2/xcrypt decryption for current EU/AU packages and
  recovered the authentic rootfs, GUI, AppNavi, updater and RW-data userspaces.
- Booted recovered Weston/IVI with project-local Mesa 18 `softpipe`; authentic
  `AppHomeScreen` now renders a complete 1920×720 frame, and pointer/touch
  events reach authentic Qt/QML.
- Recovered launcher identity for AppNavi: AppID `30`, parent IVI surface
  `3000`, launcher path `/navi/navi/Bin/AppNavi`.
- Added a bounded authentic EU map/core/skin subset. AppNavi reaches
  `### Navi Engine Init Success ###`, loads the authentic theme image and
  night skin, and renders an independently committed 836×720 map-widget
  surface `4903`.
- Captured the first visible authentic navigation-map pixels in run
  `1792908755653936000`: roads, buildings, water and the vehicle marker are
  visible at native 836×720 inside a 1920×720 compositor frame. PNG SHA-256:
  `88e8403d808b6936181465ee512aa9e124b75ccc7dbd625a221e41e75ab8b4cb`.
- Added exact-configuration VM helper
  `tools/uk_fw/guest/ivi_link_navi_widget.S`, which reconstructs the missing
  IVI relationship `3000 -> 4903`, restores the child's native destination,
  and foregrounds the parent. This helper is not recovered firmware.
- Preserved controls showing that skin data alone still produced the prior
  nearly black frame, a parent/child relationship without child layout reduced
  it to 1×1, and hiding/promoting the child full-screen produced a stretched
  but visible map. This isolates the composition issue from map rendering.
- The milestone remains VM-adapted: it uses an exact-build zero-MSAA AppNavi
  compatibility copy and a one-method `NotifyValetStatus` D-Bus responder.
  Unmodified AppNavi and the full `ApplicationManager` chain are not claimed.
- The full chain remains blocked on missing `MICOMSTATUSMESSAGE`
  shared-memory/semaphore state. Missing landmark/DEM/sqlite resources remain
  logged, although they do not prevent the first map frame. Binding the
  recovered new2.0 HMC asset tree removed all 15 named PNG-load failures but
  left the compositor screenshot byte-identical, ruling those files out as the
  current cause of the black parent region.
- Reviewed the native TE2 decryptor implementation: 28 focused tests and all
  165 repository tests pass. A real official EU `.lge.upgrade.xml` decryption
  is byte-identical to the independently preserved recovered output.

## 0.40.0 - 2026-10-21

- Reached interactive BusyBox userspace on the **VM-adapted vendor kernel**:
  one verified guest-RAM SDHCI table change, a compatible ext4 SD root and
  explicit `/init`. Original firmware/boot-image files remain unchanged.
- Added an 800×480 direct-QEMU-VGA diagnostic with R/G/B/Q keyboard input.
  QMP captures match every expected pixel. This is explicitly **not the
  infotainment UI**, which remains unrecovered.
- Replaced the old launcher with a local-input-only, hash-checked preparation
  and run harness; retained unpatched and failing-command controls. Fixed
  foreground programs consuming the launcher's separate status-command input.
- Tested two additional recovery hypotheses using existing resources: the
  boot RSA public key against 38 opaque payload edges (zero matching type-1
  blocks), and two installed Mac updater AES constant pairs against bounded
  payload-start hypotheses (zero validated plaintext candidates). Retained
  scan scopes, synthetic controls and the rejected gzip-marker matches.
- Full suite: **137 tests pass**. Fresh serial and graphics VM checks pass;
  prepared artifacts and earlier evidence hashes remain unchanged.
- Replaced the stale handover and corrected categorical VM impossibility,
  sparse-log PCI-enumeration, anti-tamper-panic and footer-stripping claims.
  Entries 0.36–0.39 below preserve historical conclusions, not current findings.
- No head-unit access, new downloads, genuine firmware decryption, flashing,
  signature bypass, Fable review or new Council acceptance is claimed. Legacy
  accepted-input hashes were not refreshed.

## 0.39.0 - 2026-10-19

- Commissioned an independent reviewer/planner pass (child note 12) on the VM
  goal. Its verdict matches the measurements: **running the vendor UI under
  emulation is not achievable**, for three reasons — the userland is encrypted,
  the kernel has no display path at all, and no block device binds.
- Stated the ceiling explicitly in `vendor-kernel-vm.md`: this kernel's only
  console is 8250 serial; `CONFIG_FB` is not set, there is no VGA or framebuffer
  console, and the sole display driver is i915, which QEMU cannot emulate. The
  achievable outcome is an interactive **serial shell on the stock kernel**, not
  a picture — and calling it "the UI" would misrepresent it.
- Recovered significant keystore configuration from the same config:
  `CONFIG_KEYSTORE_TESTMODE=y`, `CONFIG_KEYSTORE_TEST_MIGRATION=y`,
  `CONFIG_KEYSTORE_DEBUG=y`, `CONFIG_KEYSTORE_SECURE_BOOT_IGNORE=y` alongside
  `CONFIG_SECURE_BOOT=y`, `CONFIG_KEYSTORE_SEED_SIZE_64=y`,
  `CONFIG_KEYSTORE_DEVICE_AND_USER_SEED=y`, and
  `CONFIG_KEYSTORE_OEM_KEY_USAGE_BIT=47` with the exact
  `CONFIG_KEYSTORE_OEM_KEY_IDENTIFIER` string seen in `verify_oem_signature`.
  Production firmware shipping with keystore test mode, debug and secure-boot
  ignore enabled is a notable configuration finding.
- Corrected the stale introduction in `vendor-kernel-vm.md`, which still claimed
  an ext4 mount and a deliberate panic.
- Also established that PCI devices are barely enumerated under this kernel in
  QEMU (one quirk line on q35, nine on `-machine pc`, no device registrations),
  which is a prerequisite problem for the SD controller binding.
- No exploit, key, decryption or device action is included.

## 0.38.0 - 2026-10-19

- **Solved the boot-parameter mechanism.** `setup_abl_params` is registered with
  the `__setup` string **`ABL.`** (trailing dot), confirmed by reading the string
  at `__setup_str_setup_abl_params`. The handler splits the remainder on `=` and
  stores name/value pairs in a 16-entry list. The correct command line is
  `ABL.oemkm=<hex size>@<hex phys>` and `ABL.seed=<hex phys>,<hex phys>`.
- **The anti-tamper is now satisfied under emulation**: with those parameters and
  the blobs loaded at physical addresses, the kernel reports
  `keystore_init completed successfully` and `manifest: init Completed
  Successfully`, and no longer panics on them. This corrects the documentation
  that recorded the parameters as bare `oemkm=` / `seed=`.
- Found the introspection interface: `abl_cmdline_init` exposes every collected
  parameter under **`/sys/kernel/abl/`**.
- Located the mechanism by a proper xref pass: a new `FindXrefs.java` Ghidra
  script showed a WRITE to `params_list` inside `setup_abl_params`, which is how
  the vendor hook was identified after the earlier dead end.
- Remaining VM gap is a root device, not the anti-tamper: sdhci core and the
  22 `sdhci_pci_*` symbols are present but QEMU's `sdhci-pci` device ID is not in
  the 4.1 driver's table, so no `mmc0` binds and root mounting fails. Recorded the
  next step: present a controller ID the driver recognises.
- No exploit, key, decryption or device action is included.

## 0.37.0 - 2026-10-19

- Extracted the exact boot-parameter contract by decompiling
  `get_apl_seed_offsets` and reading `keystore_fill_seeds`. The two parameters use
  **different separators**: `oemkm=<hex size>@<hex phys>` and
  `seed=<hex phys>,<hex phys>`. `keystore_fill_seeds` copies two **64-byte** seeds
  out of physical memory (device → `sec_seed`, user → keystore state) and then
  **zeroes both source regions**; an absent device seed is fatal, an absent user
  seed is tolerated.
- Derived a minimal manifest blob that satisfies `manifest_init`'s validation:
  0x40 bytes, word 0 = `0xE`, byte `0x13` = 0, words 5 and 6 = 0, word 1 =
  end-of-entries offset.
- **Tested it and it did not work.** With both parameters supplied and the blobs
  loaded via QEMU `-device loader`, the kernel still reports both missing, even
  though it prints the command line verbatim. `params_list` is an empty
  `LIST_HEAD` at `0xffffffff81a1e330` and stock `unknown_bootoption` never
  populates it, so the vendor's collection hook is elsewhere and has not been
  located. Recorded so the next attempt starts from that point.
- Recorded an environment fault: Homebrew Python 3.14 became unusable mid-session
  (`posix_spawn` error) and `python3` now resolves to it; all tools still run
  under `/opt/homebrew/bin/python3.13`.
- No exploit, key, decryption or device action is included.

## 0.36.0 - 2026-10-19

- Added `tools/uk_fw/fat_harness.py`: a from-scratch FAT16/FAT32 image builder,
  independent inspector, and 17-case semantic corruption corpus targeting the
  checks a filesystem driver must perform. Images were validated by mounting them
  on macOS, which reads and executes their contents correctly. Seven unit tests.
- Added `tools/uk_fw/vm_boot.py` and **got the vendor kernel booting under
  QEMU 11.1.2**: `4.1.27-abl #1`, built 2026-01-28, initialising SMP, ACPI, PCI,
  serial console and an ext4 root on an emulated SD card.
- Two obstacles solved and documented: the `ipk.` payload is a bzImage at offset
  **1008** (protocol 2.13, `setup_sects` 30), and this kernel **cannot use an
  initramfs** because `CONFIG_BLK_DEV_INITRD` is not set — no VIRTIO, no built-in
  ATA/SCSI, no NFS root. The only bootable root is ext4 on an SD card, which also
  mirrors the real unit's `mmcblk0`.
- **Discovered a boot-time anti-tamper**: without its parameters the kernel prints
  `keystore: d/u-seed info missing in cmdline`, `manifest: Key manifest info
  missing in cmdline` and panics with a vendor-modified message, "Invalid
  configuration from end user prevents continuing". It refuses to run rather than
  degrading. This confirms `oemkm` is mandatory at runtime and names the second
  required input (device/user seed material).
- Recovered the internal build provenance from a surviving path string:
  `26RU1_001`, built 2026-01-21, branch tag `s5w.26ru1.251203`, kernel source at
  `security/keystore/seed.c`.
- No exploit, key, decryption or device action is included.

## 0.35.0 - 2026-10-19

- Added `evidence/exploit-inventory.md`: a single table of every known technique
  for this platform with what it yields, its precondition, and whether it can be
  used as a **first** step. Consolidates Chimaera CVE-2023-26243/44/45/46,
  `navi_extended`, `disableEncryptionUpdate`, `wideopen.service`, the QML patch,
  boot-image substitution, CVE-2020-8539, `hmg_nemesis`, the kernel CVEs and the
  unverified Wi-Fi daemon classes.
- States the circularity plainly: every named CVE is a binary patch and therefore
  requires prior execution. The only non-circular entry is the Engineering Mode
  AppNavi installation, which is a feature rather than a vulnerability.
- Maps the two capabilities raised by the owner — a USB payload and a modified
  firmware image — and shows both are gated: the USB payload needs a replacement
  `AppNavi` installed, and custom firmware is a persistence capability (key or
  `disableEncryptionUpdate`), not an entry capability.
- Identifies the genuine pre-authentication surface: the USB update path, with the
  filesystem parser as the only stage that touches attacker bytes before any
  cryptographic gate.
- No exploit, key, decryption or device action is included.

## 0.34.0 - 2026-10-19

- Added `evidence/network-root-feasibility.md` in answer to a direct question:
  whether the Linux version yields a network path to root. Answer: vulnerabilities
  certainly exist, a network root does not follow.
- Recorded the config filter that removes most of the remote-RCE catalogue:
  `USER_NS`, `NF_TABLES`, `BLUETOOTH`, `SCTP`, `DCCP`, `RDS`, `TIPC`, `NFC`,
  `AX25`, `X25`, `INET_ESP`, `XFRM_USER`, `TCP_MD5SIG` and `INET_DIAG` are all
  absent; `AF_PACKET` is a module and needs `CAP_NET_RAW`. What remains
  pre-authenticated is IPv4/IPv6 parsing, TCP, UDP, ICMP, fragment reassembly and
  netfilter hooks — a surface that yields DoS, not code execution.
- **Discovered that the kernel is not a pristine 4.1.27:** the symbol
  `sysctl_tcp_challenge_ack_limit` is present, introduced by the CVE-2016-5696 fix
  in **4.1.32**. The vendor cherry-picks network fixes, so version-string
  reasoning is unreliable in both directions and per-fix verification is required.
- Recorded two false-inference traps for future work: the upstream GRO recursion
  helpers are `static inline` so their absence is suggestive, not conclusive; and
  `tcp_gso_segs` is a struct field, not a symbol, so its absence proves nothing.
- No exploit, key, decryption or device action is included.

## 0.33.0 - 2026-10-19

- Added `evidence/corrections-log.md`: an explicit, claim-oriented record of the
  eleven things this programme got wrong or superseded, each with what replaced
  it and why. Eleven entries cover the kallsyms 204-entry mispairing, the
  `0x18` pseudo-checksum, the A/B partition misreading, the downgrade conclusion,
  the weakened CRC hypothesis, the header entropy misreading, the guessed
  decryptor invocation, the `iasImage` decomposition, the absent kernel IAS
  driver, and two attempted vulnerabilities that were tested and **rejected**
  (`TEST_VERIFY_ECC_SIGNATURE` uninitialised fields and `keystore_get_ksm_key`
  buffer aliasing).
- The log states which evidence documents are affected by each correction, so a
  reader landing on an older document knows whether to trust it.
- It closes with the five practices that produced the corrections — cross-check
  against an independent table, disassemble before calling something a bug, check
  the entropy maximum, treat field reports as evidence against a hypothesis, and
  record rejections as well as findings.
- No exploit, key, decryption or device action is included.

## 0.32.0 - 2026-10-19

- Delivered the `workflow-normalized.csv` export that was requested earlier and
  never produced. Added `tools/uk_fw/ledger_export.py`, which flattens the nested
  ledger into two deterministic tables: `workflow-normalized.csv` (one row per
  task-artifact pair, 19 rows, tasks without artifacts retained) and
  `requirements-normalized.csv` (16 rows with the tasks citing each
  requirement).
- The export is byte-idempotent — re-running on an unchanged ledger produces
  identical files — and supports ``--check`` so drift between ledger and exports
  is detectable. Line terminator is LF so the files diff cleanly.
- Fixed a bug found during development: `--check` disagreed with the writer
  because CSV defaults to CRLF while `read_text` normalises newlines.
- Added five unit tests; the suite now runs 74 tests.
- No exploit, key, decryption or device action is included.

## 0.31.0 - 2026-10-19

- Added `evidence/pre-disclosure-security-assessment.md` in place of a further
  exploitation pass. It is an **internal assessment, not a disclosure**: no vendor
  was contacted and nothing was published.
- It records four candidate issues with explicit confidence levels — CRC-32 as the
  declared manifest integrity value (confirmed mechanism, unproven impact), the
  `oemkm=` command-line trust root (confirmed), the absent capability check in
  `keystore_open` (confirmed), and the boot container's embedded modulus
  (confirmed structure, unproven pinning) — and states for each what evidence
  would make it disclosable.
- It explicitly separates the **modification-created** root runner from vendor
  defects, so a report is not padded with an artefact of the mod itself.
- It records what was established as *not* vulnerable, so the assessment is not
  one-sided.
- No exploit, key, decryption or device action is included.

## 0.30.0 - 2026-10-19

- Read the final two public toolchain scripts, completing the read-through.
  `update_navi_manually.sh` answered the last open structural question: **the
  navigation application lives in the map partitions, not the rootfs** — at
  `/navi/Bin/AppNavi` and `/navi2/Bin/AppNavi`.
- Consequence recorded: the A/B pairing extends to the navigation app, so a
  custom `AppNavi` must be installed into **both** partitions or it disappears
  when the unit switches map partitions. The script also replaces `AppNavi`
  directly on the partition, bypassing the Engineering Mode dialog — but it needs
  an execution context, so it is a re-install path, not an entry bypass.
- `HANDOVER.md` now carries the navigation paths in the target table and the
  alternative in the chain diagram.
- Every script in the public toolchain has now been read. No new avenues remain
  in that corpus.
- No exploit, key, decryption or device action is included.

## 0.29.0 - 2026-10-19

- Consolidated six passes of findings into the two deliverables a returning
  operator actually reads. This is documentation work, not new discovery.
- Rewrote `HANDOVER.md`: seven findings instead of five, a line-level chain with
  the real paths and commands (entry at `/media/usb`, persistence unit, QML patch,
  decryptor path, `/tmp/<32 hex>` key capture, repack command), the corrected
  tool table, and four more rows in the established-negatives table.
- Added an explicit **safety warning** to the handover: `wideopen.service` is a
  root service that executes any `wideopen_service.sh` from any mounted USB with
  no authentication, and it survives official updates. Safe on a bench, an
  unauthenticated root backdoor if the image returns to a vehicle.
- Made `evidence/bench-runbook.md` Phase 4 concrete: the four-step key-capture
  procedure, the double-backup requirement for `DecryptToPIPE_OG`, the exact
  offline decrypt command, and the glibc/`gcompat` constraint.
- No new exploit research; no device action.

## 0.28.0 - 2026-10-19

- Recovered the **exact key-extraction mechanism** from `extract_keys.sh` and
  `spoof_decrypttopipe.sh`, including the real invocation the unit uses:
  `/app/share/AppUpgrade/DecryptToPIPE -d /tmp/<32 hex> /media/usb/1/<model>/AppUpgrade 0 | dd of=/update/usb/bin/AppUpgrade bs=512`.
  The decryptor path, the per-update random `/tmp` key path, and the output target
  are now all recorded.
- Documented the two-stage procedure: back up the genuine decryptor, install a
  patched `DecryptToPIPE_FK`, reboot, let the unit's own update call it with the
  temporary key, collect `*_key_*.der` from the USB, restore the original.
- Established that the public `update_decryptor` repository ships **placeholders,
  not the artifacts**: `DecryptToPIPE` is a 129-byte shell stub and
  `decryption_key.der` is a 193-byte `EMPTY_DECRYPTION_KEY` text file. This closes
  the last possibility of an offline decryption path — neither the binary nor the
  key is public.
- Recorded the defensive design of the extraction scripts (flag files, mandatory
  backup checks) and the warning that losing `DecryptToPIPE_OG` permanently breaks
  the unit's update path.
- No key, binary, decryption or device action is included.

## 0.27.0 - 2026-10-19

- Recovered the **real decryptor invocation** from `update_decryptor`'s
  `entrypoint.sh`: `DecryptToPIPE -d <keyfile> <input> 0 > <output>`. Output is on
  stdout, every file in the package is handed over whole (the footer is *not*
  stripped), and the binary is glibc x86-64 run under Alpine + `gcompat`.
  `tools/uk_fw/gen5w_decrypt.py` was corrected accordingly — it had guessed a
  different syntax and wrongly assumed the footer must be removed first.
- Recovered the complete payload and persistence chain from `navi_extended`'s
  `USB_FILES` and `update-patcher`'s scripts: `main_loop.sh` runs
  `main_loop_code.sh` every 10 s; `install_wideopen_service.sh` remounts `/` rw,
  installs and enables `wideopen.service`, remounts ro; the unit is a
  **root** service with `Restart=always`/`RestartSec=5` whose `ExecStart` runs
  `find /media/usb -iname 'wideopen_service.sh' -exec bash {} \;`.
- **Stated plainly in the evidence:** once installed, any USB stick carrying
  `wideopen_service.sh` yields root execution with no authentication. Safe on a
  bench, an unauthenticated root backdoor if the image ever returns to a vehicle.
- Recovered the exact Engineering Mode patch set: PIN comparisons `enterMenu ==
  21`/`== 11` removed, `checkSOPVersion() ===` inverted to `!==`, the
  engine call replaced with `false`, plus a `dropbear` → `dropbearmulti` symlink.
  This is what removes the gate permanently after one patched install.
- Confirmed the repack command and added its `*.DS_Store` exclusion to
  `rootfs_patch.py`; 69 tests still pass.
- No exploit, key, decryption or device action is included.

## 0.26.0 - 2026-10-19

- Disassembled the `navi_extended` application assembly in full using
  `dnfile` + `dncil` installed into a local venv under `work/` (nothing global),
  with **every metadata token resolved**. The behaviour is now exact rather than
  inferred from strings.
- Exact logic: an infinite loop that every **5 seconds** runs
  `Directory.GetFiles("/media/usb", …, SearchOption.AllDirectories)` +
  `FirstOrDefault` for **`install_wideopen_service.sh`**, then for
  **`main_loop.sh`**, and — if the first is non-null — executes them with
  `ExecuteBash`, which escapes only `"`, builds
  `/bin/bash -c "<path>"` with `RedirectStandardOutput`, `UseShellExecute=false`
  and `CreateNoWindow=true`, then `ReadToEnd` and `WaitForExit`.
- Operational consequences recorded: the script is **re-executed every five
  seconds**; `install_wideopen_service.sh` takes precedence and is the documented
  persistence step; only the first match of each name is used; the argument is
  the file **path**, not its contents; a blocking script holds the helper inside
  `ReadToEnd`.
- Recorded a command-injection seam in the tool (only `"` is escaped, not
  backticks or `$(...)`) and why it is moot: the operator already supplies the
  script.
- Corrected the previous note, which had described the matching predicate and
  poll interval as unconfirmed.
- No binary committed; hashes and behavioural description only. No device action
  and no execution of the artifact.

## 0.25.0 - 2026-10-19

- The GitLab rate limit cleared, so the **actual entry binary was obtained and
  analysed statically** (never executed). `AppNavi` release 0.2.0 is
  35,201,155 bytes, SHA-256 `9198abf2…85c7`, an ELF x86-64 .NET **6**
  self-contained single-file bundle; the application assembly `navi_extended.dll`
  is only **5,632 bytes** (SHA-256 `dc2ef0dc…4bc7`), recovered by parsing the
  trailing bundle table and inflating the entry.
- Established what the binary actually is: a file scan under **`/media/usb`** for
  **`main_loop.sh`** (and `install_wideopen_service.sh`), executed via
  `/bin/bash -c` with output redirected, in a sleep loop. There is **no
  vulnerability and no memory-corruption exploit in it** — it is a deliberate
  drop-in trampoline that runs a USB script.
- Consequence recorded: the entry primitive is a **legitimate app substitution**,
  so the entire chain rests on the unit's own AppNavi update path. The software
  barrier is trivial; the installation gate is everything.
- Recorded the unit's USB mount point and payload script name, which are required
  for any custom application and otherwise cost bench time to discover.
- No binary is committed; only hashes and behavioural description. No device
  action and no execution of the artifact.

## 0.24.0 - 2026-10-19

- Reviewed the second open-access primary source for this platform,
  Costantino & Matteucci, *"Reversing Kia Motors Head Unit to discover and
  exploit software vulnerabilities"* (JCVHT 19:33–49, 2023, DOI
  `10.1007/s11416-022-00430-5`, 17 pages, full text extracted). It documents
  four vulnerabilities in the **Android/Telechips** Kia IVI lineage
  (`micom`-centric, 116 references; no `AppNavi`, no AES, no `update` mechanism).
  It is the earlier KOFFEE work already covered by child note 04 and does **not**
  transfer to the Linux `S5W_L` path this programme targets. Recorded so it is
  not re-examined.
- `navi_extended` source and release binaries remain unobtainable: GitLab returns
  HTTP 429 on the API, the web tree endpoint and the archive endpoint alike.
  Recorded as an external rate limit rather than a dead end.
- No exploit, OEM key, decryption or device action is included.

## 0.23.0 - 2026-10-19

- Closed two remaining completeness questions as clean negatives and recorded
  them permanently in `HANDOVER.md` so they are not retried.
- **Package completeness:** both the EU `260128` and AU `260319` packages list
  exactly 35 files with **zero unlisted and zero missing**; only the map archive
  and its MD5 sidecar differ by region. There is no hidden or unmanifested
  payload.
- **No key material in the package:** 223 plaintext artifacts scanned for PEM
  headers, base64 X.509 prefixes, PKCS#7 and X.509 signature OIDs and SSH keys —
  no hits (three generic `30 82` byte pairs in binary data are coincidental).
  Key material is device-resident only, which confirms the published technique.
- Retried the `navi_extended` source archive from a different endpoint; still
  HTTP 429. Recorded as an external limit, not a dead end.
- Added an "Established negatives" table to `HANDOVER.md` covering ten ruled-out
  avenues, so future work starts from the right place.
- No exploit, OEM key, decryption or device action is included.

## 0.22.0 - 2026-10-19

- Added `HANDOVER.md` at the project root: a single read-first document covering
  the target identity, the five findings that matter, the end-to-end chain, the
  tool inventory, the three questions that unblock progress, the bench order, and
  an explicit statement of what is deliberately absent and where the honest limits
  are. Written because 25 evidence documents and 11 subagent notes are too much to
  wade through on return.
- No exploit, OEM key, decryption or device action is included.

## 0.21.0 - 2026-10-19

- Closed the boot-image format question with an exact decomposition:
  `iasImage` = **3,385-byte header + 6,210,308-byte payload + 13,035-byte
  trailer** = 6,226,728 bytes, where the payload length is exactly the plaintext
  `_sub` size. The header is variant-specific with no plaintext fields (a search
  for 6,210,308, 3,385, 13,035, 52, 953 and `0x42f08d94` as little-endian words
  finds nothing); the trailer is identical across five variants and package-scoped.
- Corrected an intermediate reading in this session: the header's per-64-byte-block
  entropy of ~5.7 looks structured only because 6.0 is the maximum for a 64-byte
  block; the region is in fact random, i.e. encrypted.
- Established a clean negative: the Linux kernel contains **no** IAS-related
  symbol, string or config option, so `ipk.`/`iasImage` verification is a **boot
  loader** function performed before Linux runs. The format therefore cannot be
  reverse engineered without the SPI flash contents; the boot path is closed
  offline and the OTA path remains the open one.
- No exploit, OEM key, decryption or device action is included.

## 0.20.0 - 2026-10-19

- Added `tools/uk_fw/rootfs_patch.py`, closing the *build* half of custom
  firmware: `list` inspects a rootfs package, `inject` installs a systemd unit,
  appends SSH keys (mode 0600) to `/etc/dropbear/authorized_keys`, or copies
  arbitrary payloads, and `meta` computes the rebuilt file's size and signed
  CRC-32 and rewrites the matching `.ver` record.
- Enforced the vendor archive constraints recovered from the public patcher:
  `--format=ustar` and `--numeric-owner`, since the reader rejects pax/GNU
  extensions and name-resolved ownership. Inputs are never modified.
- Added `evidence/custom-firmware-build-path.md`, separating the two independent
  problems: the cipher (bypassed entirely by the `disableEncryptionUpdate` path)
  and acceptance (the version gate plus the package descriptor binding).
- Added four unit tests for the repacker; the suite now runs 69 tests.
- Recorded that the `navi_extended` release binaries would reveal the exact
  `AppNavi` interface but GitLab returned HTTP 429 during this session, so the
  fetch was backed off rather than retried aggressively.
- No exploit, OEM key, decryption or device action is included.

## 0.19.0 - 2026-10-19

- **Corrected the previous conclusion that downgrade is blocked.** The
  anti-rollback analysis (child note 10) separates the two siblings: on the
  **Linux `S5W_L`** path the version gate is a single userland string comparison
  in `AppSetup`, evaluated after `DecryptToPipe` handles `.lge.upgrade.xml`, and
  the public `navi_extended` FAQ documents a substitution method — older official
  payloads paired with the **latest** `.lge.upgrade.xml` for the same vehicle, so
  a genuine signed newer manifest satisfies the `>=` check while older content is
  written. On the **Android Gen5W** sibling the `update_info` inside
  `system_package` is signed and binds the package, which is why the EV6 report
  was rejected even with corrected `.ver` CRCs.
- Recorded the three remaining obstacles on the Linux path, none of which are
  cryptographic: (a) the feed — the update API currently returns 503, so older
  packages cannot be enumerated; (b) distance — the entry precondition is a
  pre-November-2021 build, five years of package-format change away from
  `260128`; (c) the method is documented against 2021–2022 packages and is
  unconfirmed on 2026 packages.
- Recorded that no monotonic anti-rollback counter (fuse/OTP) is publicly
  demonstrated for this variant, so rollback protection is software-only, matching
  CVE-2023-26245.
- No exploit, OEM key, decryption or device action is included.

## 0.18.0 - 2026-10-19

- Characterised the encrypted boot wrapper (`iasImage` without `_sub`): all six
  variants are 6,226,728 bytes (16,420 more than the plaintext payload); five
  share an identical **13,035-byte trailer** (SHA-256 `41885928…`, entropy 7.976)
  while `iasImage_p5_1920_12` has a different tail; the trailer is package-scoped
  (EU and AU share no suffix) and contains no plaintext exponent marker, unlike
  `_sub`.
- Recorded that this mirrors the OTA footer pattern and supports a single packing
  model: encrypted content plus a package-level descriptor appended verbatim.
- No exploit, OEM key, decryption or device action is included.

## 0.17.0 - 2026-10-19

- Reviewed the public issue trackers of the Gen5 Wide-Open projects. Recorded
  that **downgrade remains unsolved in public**: `navi_extended` issue #2
  ("How do I downgrade?", open since 2022-10-30) reports that editing
  `update.info` did not work, and no answer was published.
- Recorded field evidence that **weakens this programme's own CRC hypothesis**:
  issue #3 (2023-09-23) describes repairing the `.ver` CRC and file size and the
  unit still refusing to install. The arithmetic result (CRC-32 is forgeable)
  stands; the exploitable reading is now treated as unlikely on its own. The
  hypothesis document was amended accordingly rather than left standing.
- Confirmed newer packages ship `appnavi.tar` (not `appnavi.tar.gz`), matching our
  `260128` package; scripts globbing the old name silently do nothing.
- Probed the official update API with the public tool's local-token scheme:
  `apieu.map-care.com` and `api.map-care.com` both return **HTTP 503**;
  `oem-euupload.map-care.com` returns 404/connection failure; two 2023 issues
  report "no cars available on any region". Older-build acquisition is therefore
  at risk, which removes the feedstock for a downgrade even if one became legal.
- Net effect on the plan: the entry gate is unchanged, the integrity gate is
  demonstrably stronger than the `.ver` CRC, and the pre-authentication parser
  surface remains the most promising target.
- No exploit, OEM key, decryption or device action is included.

## 0.16.0 - 2026-10-19

- Analysed the **open-access primary source** for this platform: *"A vehicle
  firmware security vulnerability: an IVI exploitation"* (DOI
  `10.1007/s11416-024-00522-4`, JCVHT 20(4):681–696). Recorded the published
  technique: `DecryptToPIPE` statically links mbedtls and retains an unused
  `mbedtls_printf`, whose register leak exposes the **AES-CBC-128** key; the
  `Key_file` holds the RSA public key plus the wrapped AES key; each file is
  described as content + terminator + SHA + signature; and `AppDMClient`,
  `AppUpgrade` and `DecryptToPIPE` are patched to skip signature checks.
- Established that the OTA key is recoverable with **public** RSA material plus
  one device file, so offline decryption needs only the `DecryptToPIPE` and key
  pair — no further reverse engineering.
- Closed the cross-build ciphertext avenue with measurements: no ECB anywhere
  (zero duplicate 16-byte blocks in 16 MiB samples), no same-offset block
  agreement between EU and AU, and the package footer identical within a package
  but completely different across packages — consistent with a derived IV over a
  package-constant plaintext.
- Recorded a tension: the paper implies a per-file SHA in the trailing block,
  yet the measured tail is identical across three files; the per-file SHA is
  therefore most likely inside the encrypted content. Left explicitly open.
- Extracted the AU boot containers for the first time: same command lines and
  build id as EU, but the kernels differ (126,510 differing bytes, 2,122 ranges).
- Confirmed two dead ends so they are not retried: `navi-updates-lfs` contains
  only a README, and stock Ghidra 12.1.4 has no RL78 processor module (M16C only),
  so the frontkey MCU is not decompilable without a third-party module.
- No exploit code, patch offsets, key-unwrap implementation or device action is
  reproduced.

## 0.15.0 - 2026-10-19

- **Proved that CRC-32 is not an integrity control** for this package format.
  `tools/uk_fw/crc32_forge.py` computes the 4-byte correction that forces any
  chosen CRC-32, and the demonstration preserved the manifest value across a real
  content change: original `0xa09a265d`, modified content gave `0x0338bbdf`,
  correction at offset 8 restored `0xa09a265d` with differing bytes
  `[8,9,10,11,20]`.
- Refined the earlier hypothesis: because `.ver` CRC-32 values are computed over
  **ciphertext**, a CRC-preserving modification still requires the decryption key,
  so this is a **post-execution** persistence mechanism, not a route to first
  execution. That distinction is recorded explicitly.
- Added `tools/uk_fw/gen5w_decrypt.py`, an orchestration harness around the
  unit-derived decryptor with `plan` / `run` / `verify` subcommands. It makes no
  assumption about the vendor binary's interface (the command is a caller-supplied
  template), strips the detected package footer from the model, and classifies
  outputs by entropy and printability.
- Added four unit tests for CRC forging (property, no-op, out-of-range offset,
  arbitrary targets). The full suite now runs 65 tests.
- No exploit, OEM key, decryption or device action is included.

## 0.14.0 - 2026-10-19

- Discovered the OTA container structure from ciphertext alone: each package
  appends a package-scoped **footer** of 14,059 bytes (EU `260128`) or 14,315
  bytes (AU `260319`) to exactly `AppUpgrade`, `.lge.upgrade.xml` and
  `update.tar.gz`. Footer digests:
  `fc1c07cc…` (EU) and `81c18efd…` (AU). The four large payloads carry no shared
  suffix and there is no shared prefix anywhere.
- Established that `.lge.upgrade.xml` is almost entirely footer: only 3,611 bytes
  (EU) / 3,497 bytes (AU) are its own encrypted content, consistent with
  `AppSetup` decrypting it first to read the version.
- Profiled the footer: entropy 7.98 overall and 7.1–7.3 per 256-byte block, no
  gzip/zlib/DER/PEM/X.509 markers and no printable runs, i.e. a structured but
  encrypted descriptor.
- Recorded a **hypothesis** (explicitly not a finding): because the `.ver`
  manifest carries only size and signed CRC-32, and the large payloads are not
  separately signed, per-file integrity may reduce to CRC-32, which is trivially
  forgeable. Falsified if the descriptor holds a cryptographic digest per file or
  the upgrader re-hashes decrypted content.
- Added `tools/uk_fw/ota_structure.py`, which reports shared regions, the
  detected footer, its digest and entropy, and per-file unique sizes, reading only
  64 KiB windows per file.
- No exploit, OEM key, decryption or device action is included.

## 0.13.0 - 2026-10-19

- Recovered the documented Gen5W operating model from the public
  `g4933/wideopen` wiki and `g4933/gen5w` projects, which fills the gap that the
  encrypted userland was hiding.
- Recorded the update flow: `AppSetup` reads `.lge.upgrade.xml`, decrypts it with
  `DecryptToPipe`, and proceeds only when the version is **greater than or equal
  to** the installed version; `AppUpgrade` then performs filesystem, map and
  firmware stages and finally rewrites `/etc/fstab`.
- Corrected an earlier interpretation: the two roots in the recovered command
  line (`mmcblk0p3`, `mmcblk0p5`) are the **A/B system partitions**, not merely
  display variants. A rootfs write goes to the inactive partition, so a failed
  rootfs experiment is recoverable by restoring `fstab`, while a bad boot image
  is rejected by the signed container rather than rolled back.
- Recorded `disableEncryptionUpdate` semantics: it disables decryption only; the
  `.lge.upgrade.xml` version check still runs.
- Recorded the public entry preconditions (`navi_extended` as a replacement
  `AppNavi` installed through Engineering Mode, requiring an unpatched build and
  therefore a downgrade on newer units) and the documented SSH persistence path
  (`/etc/dropbear/authorized_keys`, publickey installer, relaxed
  `dropbear@.service` condition).
- Identified the first gate for the public path: whether `260128` still offers
  "Update AppNavi from USB", and whether any rollback counter exists outside
  `AppUpgrade` (none found in the recovered kernel configuration or symbols).
- Updated `evidence/bench-runbook.md` with the A/B recovery path, the downgrade
  gate and the persistence procedure.
- No exploit, OEM key, decryption or device action is included.


- Added `tools/uk_fw/bench_assess.py`, a read-only orchestrator that runs the
  serial capture, network surface, rootfs survey and boot-container inspection in
  a fixed safe order and writes a single `report.json` plus per-step artifacts.
  Steps are independent and skipped steps are recorded explicitly.
- Verified the orchestrator offline: the image step reports `signature_ok=True`
  and the OEM modulus digest for the packaged container.
- Added `evidence/bench-runbook.md`, the phased operating procedure from physical
  preparation through disclosure, with read-first gates and the exact commands for
  each tool.
- No exploit, OEM key, decryption or device action is included.


- Recovered the keystore root of trust. `manifest_init` (boot initcall)
  `strcmp`s the kernel parameter **`oemkm`**, parses `oemkm=<size>@<phys>` with
  `sscanf("%x@%x")`, copies a 64 MiB-bounded blob out of physical memory via
  `memcpy_from_ph`, validates only a four-field header (type word `0xe`), then
  creates `.manifest_keyring` with `prepare_kernel_cred(0)` **root credentials**.
- Established that `oemkm=` is **absent from all six packaged command lines**, so
  the boot loader places the manifest and injects the parameter. The OEM key is
  therefore not in the root filesystem and not in the kernel image.
- Consequence recorded: root on the rootfs does **not** grant signing capability.
  The OEM public key is firmware-pinned; a signature bypass must be a userland
  decision, matching CVE-2023-26244/26245/26246 and the `update-patcher` approach.
- Recorded a design observation: the manifest blob is trusted implicitly and its
  location is a plain command-line value not covered by the `ipk.` container
  signature. Whoever controls `oemkm=` controls the trusted key set. With
  `CONFIG_KEXEC=y` this is a research direction post-root, not a persistence path.
- Verified **`check_usage_bits`** is a clean four-word subset test
  (`requested == allowed & requested`); a key with an all-ones mask authorises
  every usage.
- Studied **`keystore_backup`**: it gates key export on an OEM signature over a
  user-supplied 136-byte blob, then encrypts the 64-byte client key material to
  the host key and signs the result; the key material is hexdumped under dynamic
  debug before being zeroed.
- Tested a suspected uninitialised-copy defect in **`keystore_get_ksm_key`** at
  instruction level and **rejected it**: the buffer is `[68-byte private][136-byte
  public]`, the code zeroes the private half and returns the public half.
- Subagent research completed: daemon version-fingerprinting triage (dnsmasq,
  hostapd/wpa_supplicant, miniupnpd, dropbear, BusyBox) and SMACK device-access
  analysis. The SMACK note establishes that `/dev` is devtmpfs, so an unlabelled
  node defaults to the `*` label, which combined with the absence of a capability
  check in `keystore_open` makes `/dev/keystore` reachability purely a
  mode-plus-label question once the rootfs is decrypted.
- No exploit, OEM key, decryption or device action is included.


- Added `tools/uk_fw/ver_manifest.py` and verified both official packages end to
  end against their own manifests: EU `NE_E.EUR.S5W_L.001.001.260128` and AU
  `NE_E.AUS.S5W_L.001.001.260319` each report 33/35 files matching size and
  signed CRC-32, **0 mismatches, 0 missing**, with the two files larger than
  2 GB skipped (EU map archive and EU `mango-vr_fixed.tar.gz`).
- Documented the manifest path convention: the record carries the directory in
  the Windows-style field and the filename separately, and the package name
  prefix must be stripped before resolving against a package root.
- Added unit tests: `tests/test_ipk_tool.py` (8 tests covering parsing, signature
  verification, payload tampering, tag tampering, non-`ipk.` rejection,
  re-signing and oversized command-line rejection) and
  `tests/test_ver_manifest.py` (5 tests covering prefix stripping, clean
  verification, mismatches, missing files and large-file skipping). 13 tests
  pass.
- No exploit, OEM key, decryption or device action is included.


- Fully characterised the plaintext `ipk.` boot container. Field `0x018` is a
  constant format/build id, **not** a checksum: it is identical across all six
  `iasImage*_sub` variants whose command lines differ. Earlier zlib and
  CRC-32/MPEG-2 checksum hypotheses were wrong for that reason.
- Established that the six variants differ by only 261–274 bytes (command line,
  one byte at `0x46`, and the trailer), i.e. one kernel serves 1280, 1920/12 and
  p5 layouts.
- Recovered and verified the container signature: **RSA-2048, PKCS#1 v1.5,
  SHA-256**, signed over `[0, hdr+total+4)` = header + payload + 4-byte variant
  tag. `pow(sig, 65537, n)` yields the expected DigestInfo block and the trailing
  digest matches. OEM modulus SHA-256
  `227d89f5a3cabed4efb8e67d5a0f9fa29d03a6759b8a150503fb383698fedea6`.
- Established that this modulus appears **only** in the six containers and is
  **absent from the kernel image**, so any pinning lives in the boot loader or
  the encrypted main `iasImage`. Whether trust is pinned or self-referential
  cannot be decided offline and is the highest-value bench question.
- Added `tools/uk_fw/ipk_tool.py` with `info`, `verify`, `extract` and
  `resign`. Verified end-to-end: the OEM image verifies, and a modified
  `init=/bin/sh` image re-signed with a generated test key verifies under the new
  modulus. `resign` produces a correctly formed container for an acceptance
  experiment; it does not defeat OEM verification.
- Added `tools/uk_fw/bench_serial.py` driving the recovered `ttyS2` 115200 8N1
  console (capture, send, port enumeration) so the boot log can be recorded the
  moment the unit is available.
- Dispatched four research subagents: kernel 4.1.27 backport gap, daemon
  version-fingerprint triage, USB gadget/iAP2 protocol surface, and SMACK device
  access.
- No exploit, OEM key, decryption, simulated boot on a vehicle, or device action
  is included.


- Repaired kallsyms recovery for the exact EU kernel. `tools/uk_fw/kallsyms_extract.py`
  fails on this image; three defects were identified: false-positive
  `kallsyms_num_syms`, an odd-aligned marker array, and — most seriously — an
  address-array start taken at the first kernel-range pointer, which mispaired
  **every** symbol by 204 entries while still producing plausible prologues.
- Added `tools/uk_fw/kallsyms_structural.py`, which derives the layout
  structurally and recovers 64,923 symbols in 0.3 s.
- Cross-validated the recovered table against the independent `__ksymtab`
  export table: 4,369 of 4,375 exports match exactly with zero residual
  mismatches. Corrected layout: addresses `0x89f158`, num_syms `0x91de30`,
  names `0x91de38`, markers `0x9dedc8`, token table `0x9df5b8`, index `0x9df940`.
- Because the mispairing was silent, prior Ghidra naming derived from a
  run-start extraction is recorded as unverified and was re-derived. The
  corrected import renamed 25,033 functions and decompiled 41 priority
  functions.
- Established the trust-chain anatomy: `verify_oem_signature` SHA-256s the
  input, then `manifest_key_verify_digest` performs a `manifest_keyring` lookup,
  parses 16 usage-bit bytes from the key description, and calls the asymmetric
  verify op. It is reachable only from `keystore_backup` and
  `keystore_generate_mkey` and is not exported, so **firmware trust is decided
  in userland**, consistent with CVE-2023-26244/26245/26246.
- Reviewed the 26-ioctl `/dev/keystore` boundary. It is defensively written:
  a `size < 0x319` gate against a 0x318-byte staging area ending at the canary,
  overflow-checked user pointers, matching allocation and copy lengths, and
  post-dispatch zeroing. No memory-safety defect was found in the reviewed set
  — a bounded negative result, not proof of absence. A hypothesis about
  uninitialised tail fields in `TEST_VERIFY_ECC_SIGNATURE` was tested and
  rejected (decoded size 0x120 covers the offsets read).
- Recorded that `keystore_open` performs no capability check, so access depends
  on the device-node mode and SMACK label, which remain inside the encrypted
  rootfs. `keystore_verify` and `keystore_register` are exported.
- Confirmed the EU map ZIP is plaintext (1,335 entries) but data-only, that the
  VR package is plaintext TTS/ASR data with no executables, and that the map
  package ships a Gladman Rijndael licence — a hint at the AES implementation
  family, not a key.
- Re-stamped `ART-T6-CHANGELOG` after this documentation update. The frozen T6
  acceptance is therefore stale and requires re-review; this entry records the
  change rather than concealing it.
- No exploit, key, decryption, modified image, flash procedure, or device
  action is included.


- Established that the official `260128` userland is soundly encrypted: entropy
  ~8.00 per envelope, no keystream reuse between files, and no plaintext magic
  in any encrypted payload. Confirmed the manifest checksum is `zlib.crc32`
  against the plaintext `Checksum.txt`.
- Recovered the complete kernel command line from the plaintext
  `iasImage*_sub` containers: serial console `ttyS2` at 115200 8N1, early console
  at MMIO `0xfc000000`, `init=/lib/systemd/esinit`, dual root (`p3`/`p5`),
  Intel DRCFG USB0 mux, `ramoops` at `0x50000000`, and Intel Broxton platform.
- Integrated the public Gen5W prior art (`laralbir` EU standard Gen5W and the
  `gitlab.com/g4933/gen5w` tool group): the `navi_extended` → `DecryptToPIPE` +
  `decryption_key.der` → `update_decryptor` → `update-patcher` chain.
- Recorded the two MASS_PRODUCT Engineering Mode gates (SOP check plus QML PIN
  `21`/`11`) and the published alternative routes (UART, GDS, older build).
- Recorded the published ciphertext-level structure: re-sealed 16,417-byte
  modem trailers, stable container prefixes (14,048 / 14,122 / 640 / 112 bytes),
  and which payloads changed functionally between `251204` and `260128`.
- Confirmed `mango-vr_fixed.tar.gz` is real gzip but TTS/ASR data only (49
  entries in the AU package, no executables); frontkey MCUs are Renesas RL78.
- Added `evidence/known-exploits-and-cve-survey.md`,
  `evidence/gen5w-public-exploit-ecosystem.md`, `evidence/bench-hardware-root-path.md`,
  and `evidence/network-surface-and-wifi-root.md`, plus four child-thread notes.
- Reinforced the scope boundary: no exploit, decryptor key, modified image,
  flash procedure, or live-vehicle action is included.


- Recorded the active target as an AVN bench unit removed from the vehicle, and
  scoped research to that unit with no vehicle connected.
- Added `tools/uk_fw/dump_survey.py`, a read-only survey of a rootfs dump or
  ext4 image covering accounts, setuid/setgid, file capabilities, SMACK
  policy, systemd units, boot command line, debug surfaces, persistence paths
  and world-writable files.
- Added `tools/uk_fw/net_surface.py`, a TCP surface mapper with banner, HTTP,
  TLS-certificate, SSDP and mDNS discovery for an owned bench unit.
- Added `evidence/bench-hardware-root-path.md` with the UART / bootloader /
  storage / software ladder, the interface survey checklist, and the Gate 4
  recovery preconditions applied at bench scale.
- Added `evidence/network-surface-and-wifi-root.md` mapping Wi-Fi exposure
  modes, service-to-vulnerability classes, and the evidence each class needs.
- No exploit, payload, credential attack, flash procedure, or live-vehicle
  action is included.

## 0.5.1 - 2026-10-19

- Consolidated every IONIQ-owned research artifact, evidence file, Council
  package, test, analysis tool, ledger, plan, history, changelog and repository
  policy under the top-level `ioniq research/` directory.
- Preserved all relative paths inside the IONIQ project so evidence references,
  artifact hashes and test commands continue to resolve from that directory.
- Left the Kona root documents and every `kona_research/**` file in place and
  did not incorporate concurrent Kona changes into the IONIQ reorganization.

## 0.5.0 - 2026-10-19

- Verified completion of the exact European `260128` package: 35/35 payload
  sizes, 35/35 signed CRC-32 values, and all three supplied MD5 sidecars.
- Added the complete 36-file SHA-256 inventory identity.
- Replaced the interim EU/AUS comparison with the complete matrix and exact
  corresponding-kernel comparison.
- Added `evidence/eu-custom-firmware-feasibility.md`, separating initial
  execution, privilege transition, persistence, trust, recovery and regional
  compatibility prerequisites.
- Documented candidate defensive vulnerability-audit surfaces and exact
  evidence requirements without an exploit chain, crafted update, modified
  firmware image, flashing procedure or vehicle interaction.

## 0.4.0 - 2026-10-19

- Corrected the active vehicle to a UK-origin 2021 IONIQ 5 and added the exact
  European `260128` package acquisition and resume evidence.
- Added complete 64,923-symbol kernel recovery and symbol-aware Ghidra
  decompilation, including the LG keystore/OEM-signature trust anchor.
- Added the exact-build published-root-method and native Linux application-
  loading applicability assessment.
- Added an interim byte-level EU/AUS package comparison and explicit region-
  transition feasibility gates.
- Preserved the accepted Australian work as historical comparison evidence and
  made no Kona-owned changes, vehicle writes, media writes or firmware flashes.

## 0.3.0 - 2026-10-19

- Changed the private-repository retention policy so raw firmware, extracted
  analysis trees, captures, device-specific dumps, vehicle identifiers, and
  analysis workspaces may be deliberately staged and committed.
- Narrowed `.gitignore` to retain the downloaded 9.5 GB official package tree,
  live credentials/private keys, and regenerable cache noise outside Git.
- Kept exact-stage review, private-remote verification, provenance manifests,
  Kona path separation, and third-party-data controls in force.

## 0.2.0 - 2026-10-19

- Added `Ioniq5-research-plan.md`, the integrated car-specific research plan.
- Bound every accepted evidence artifact to its SHA-256 and traced R1-R11 to
  the accepted T1-T5, T7, and T2 work.
- Recorded the exact official Australian package identity, including the
  36-file inventory, the sorted-tree digest, all 35 manifest records, the map
  and voice MD5 values, the front-key CRC-32/MPEG-2 check, and the nineteen
  opaque envelopes.
- Added a subsystem register covering the AVN, cluster, smart key, keyless
  entry, immobilizer, body controller, gateway, CAN domains, diagnostics,
  telematics, ADAS, chassis safety controllers, VCU, BMS/HV/charging, HVAC,
  camera/audio, USB and projection, and the update supply chain.
- Added Phases 0-8 with passive-first exit criteria and stop conditions.
- Closed the T6 portion of ASTRA-G7-S01 by defining Gate 4 as a four-part
  conjunction, separating physical restoration from persistent software-state
  coverage, rejecting claims of an exclusive recovery route, and making Gate 4
  a hard stop before any state-changing stage.
- Added privacy and confidentiality handling for raw captures, identifiers,
  personal data, storage images, and credentials.
- Added a root `.gitignore` excluding firmware and archive formats, package and
  extraction trees, dumps and captures, credentials, identifiers, and
  personal-data workspaces.
- Recorded Council generation 10 acceptance of frozen batch 8 with three
  COMPLETE seats and truthful DeepSeek replacement labels.
- No USB medium was written, no firmware was flashed, no vehicle was connected,
  and no actuation was performed.

## 0.1.0 - 2026-10-19

- Initialized the dedicated IONIQ 5 research history and changelog.
- Recorded accepted T1 identity, T3 method catalogue, T4 passive and hardware
  route map, T5 trust-boundary and subsystem map, and T7 NEMESIS compatibility
  assessment.
- Established the rule that the car's installed build is read before method
  selection and that published-family evidence is not installed-car evidence.
