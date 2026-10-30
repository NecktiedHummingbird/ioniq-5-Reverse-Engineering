# Attack-surface prioritisation for the `260128` bench unit

Status: historical prioritisation, corrected 2026-11-01 with current recovery
and kernel evidence. No physical-device interaction. For the current finding
inventory use `evidence/exploit-inventory.md`.

## Former blocking dependency — resolved offline

The original encrypted-payload blocker no longer applies. The EU `260128`
payloads were recovered and the authentic userspace now boots in the isolated
VM. This enables exact userland and module review, but does not provide an OEM
signature bypass, installed-device execution, or evidence about the owner's
unknown installed firmware.

## Ranked routes

### 1. CVE-2026-40225 udev hardware-property injection — strongest static physical root path

- Exact shipped `v4l_id` and `scsi_id` binaries contain the
  direct, pre-fix prints of kernel-provided product/serial fields without the
  control-character checks added upstream in 2026.
- Installed rules import both helpers. Block devices are tagged for systemd and
  the image contains `debug-shell.service`, configured to start `/bin/sh` as
  root on `/dev/tty9` if `ConditionPathExists=/dev/tty9` passes. The upstream
  SCSI route can inject `SYSTEMD_WANTS`, so no new unit file is required.
- This is independent of V-006's blocked shell interpolation: it uses different
  helpers and property boundaries, not sanitized `usb_id` `ID_SERIAL_SHORT`.
- A fixed benign parser control retained the leading-space second property. A
  matched synthetic-event VM control then used exact `systemd-udevd` and PID 1
  systemd: only the positive `SYSTEMD_WANTS` property started the transient
  marker unit; the negative run did not. Shipped vulnerable helper rules were
  masked and no pre-existing property-selected unit was requested. Another control confirmed
  `/dev/tty9` exists as character device `4:9`; it did not start the shell unit.
  Remaining gates are malicious supported hardware, hardware bytes reaching the
  shipped helper, and a practical production VT9/display/input route.
  No head-unit event, root transition, or physical console access was observed.
- Evidence: `evidence/systemd-udev-cve-2026-40225.md`.

### 2. ConnMan DHCPv6 DOMAIN_LIST overwrite — strongest static adjacent-network candidate

- Exact RPM metadata identifies `connman-1.29+5w.master.38-r1`, but the finding
  does not rely on that version. Exact shipped instructions at `connmand+0x1f150`
  implement CVE-2026-115863's fixed 1,025-byte copy and unbounded DNS-label
  cursor/store; option-24 dispatch is exact at `+0x1f211`.
- Exact control flow also closes the main static activation question: on a
  connected managed network, RA Managed/Other flags reach stateful DHCPv6 or
  information-request startup, and the information path explicitly requests
  DOMAIN_LIST option 24.
- The installed service defaults to uid 0 and does not exclude intended `wlan0`.
  A reply must still match live transaction, client/server identity, message
  type, and state. Production IPv6/interface state and physical on-link delivery
  are unknown.
- PIE, NX stack, stack canary, full RELRO, and `Restart=on-failure` constrain the
  practical result. No packet, crash, controlled execution, or root transition
  has been demonstrated. Treat this as a disconnected-bench validation target,
  not network-to-root.
- Evidence: `evidence/connman-cve-2026-115863.md`.

### 3. USB storage via AppNavi replacement — published but installation-gated

- Mechanism: `navi_extended` replaces `AppNavi`; on launch it runs
  `main_loop.sh` from the root of an exFAT USB.
- Why first: it is the only published mechanism that yields arbitrary code
  execution on Gen5W_L, and it is a *storage* vector, matching the requested
  scope.
- Gate: Engineering Mode. Two layers on `MASS_PRODUCT` — an SOP check that
  fires before the PIN, then QML PINs `21`/`11`. Documented alternates: UART,
  GDS, older build.
- Unknown: whether `260128` still accepts the replacement, and whether the SOP
  gate can be cleared without already having execution.

### 4. Other Wi-Fi/network daemon candidates — exact identity now available, reachability still gated

The recovered RPM Btree contains 1,679 records and identifies, among others,
`wpa-supplicant-2.5+56-r1`, `busybox-1.23.2-r0mango12`,
`dropbear-2020.81-r8mango2`, and `openssl-1.0.2k-r0`. These are inventory leads,
not vulnerability findings. Exact file hashes, vendor backports, service
arguments, listeners, and packet routes must still be checked. For example,
ConnMan runs with `--nodnsproxy`, which removes older DNS-proxy CVE routes even
though the affected code may exist in the package.

`tools/uk_fw/rpm_nvra_inventory.py` deterministically parses preserved
`db_dump -p` output. `tools/uk_fw/net_surface.py` remains the physical-bench
listener and banner capture tool. No public end-to-end Wi-Fi-to-root for this
Gen5W_L build has been established.

### 5. USB gadget / iAP2 / CarPlay — recovered, parser review still needed

Kernel config enables `USB_F_IAP2`, `USB_U_IAP2`, `USB_G_SERIAL`,
`GADGETFS`, `USB_F_MASS_STORAGE`, `USB_DWC3` dual-role. These are modules and the
userspace has now been recovered. iAP2 is a bounded, length-prefixed protocol
parser and remains an exact-code review target; no
finding has yet been established.
Note: `CONFIG_LGE_CARPLAY=y` in the kernel, yet no `carplay` symbols exist in
`vmlinux`, so the parsing is userland.

### 6. Kernel — analysed; conditional post-execution candidates remain

- 64,923 symbols recovered and cross-validated (4,369/4,375 exports exact).
- 41 priority functions decompiled with corrected names.
- Trust chain: `verify_oem_signature` → SHA-256 → `manifest_key_verify_digest`
  → keyring lookup + usage bits → asymmetric verify. Reachable only from
  `keystore_backup` and `keystore_generate_mkey`, not exported.
- **Firmware acceptance is a userland decision.** A kernel signature bypass is
  not required to install a modified package.
- `/dev/keystore` (26 ioctls) is defensively coded: size gate, overflow-checked
  user pointers, matching alloc/copy lengths, post-dispatch zeroing. No
  memory-safety defect found in the reviewed set.
- Open question that matters: `keystore_open` has **no capability check**. If
  the device node is world-accessible and SMACK-permitted, any process can issue
  keystore ioctls, including `BACKUP` (which requires an OEM signature) and the
  `RUN_TESTS` path. Device-node mode and label are inside the encrypted rootfs.
- Built-in reachable code: netfilter/xtables (1,610 symbols), TCP (588),
  IPv6 (525), CAN (306, including `micom_*`), UDP (161).
- Exact checks reject CVE-2016-0728, Dirty COW, both ranked AF_PACKET races,
  ALSA PCM CVE-2017-0861, and the generic missing Stack Clash guard-gap premise
  despite the old banner.
- V-013/CVE-2017-15265 remains pre-fix in exact `snd-seq.ko`; a benign VM
  diagnostic confirmed uid/gid-65534 create/delete ioctl reachability, but a
  bounded race did not fault and no root primitive is established.
- ALSA sequencer CVE-2018-1000004 lacks the official ioctl serialization, but
  the published pool sequence requires a write-capable sequencer fd and
  recovered intended policy grants ordinary users no write permission.
- CVE-2017-1000112's IPv4/IPv6 UFO guards are absent, but
  `CONFIG_USER_NS=n` blocks the published unprivileged root setup and production
  interface UFO features are unknown.

### 7. MICOM / CAN — post-exploitation

`micom_*` (24 symbols) includes a user-writable sysfs handler
(`micom_sys_spidump_store`). CVE-2020-8539 (`micomd`) is a **local** issue:
the public KOFFEE report confirms it needs code execution first, then reaches
`/dev/socket/micomd` to emit M-CAN frames. Not an entry vector.

## What is not available

- No public Wi-Fi-to-root for Gen5W_L.
- No public copy of the Chimaera report or tooling (the IIT host is unreachable;
  only the 2024 journal version, DOI `10.1007/s11416-024-00522-4`, and the CVE
  records are readable). The KOFFEE report *was* recovered via the Wayback
  Machine.
- No evidence that `260128` retains the `211214` bypasses.
- No public end-to-end validation of the `navi_extended` chain on physical
  hardware.

## Decisive next evidence, in order

1. Preserve V-014's remaining helper-input, physical-port, production-tty, and
   display/input gates for a disconnected bench with a benign marker—not the
   installed shell unit. Parser and synthetic udevd-to-systemd semantics are
   complete; do not describe them as physical-device reproduction.
2. For V-015, preserve the current NIC-free VM. On a disconnected bench, first
   record installed `connmand`, interface ownership, IPv6 state, and benign
   RA/DHCPv6 behavior. Do not move to a malformed control unless restart and
   recovery are proven, and do not develop a privilege payload.
3. Identify an authentic post-index caller of V-012 playback or MediaBrowser's
   explicit `requestThumbnails(as)`, and repair the bounded VM thumbnail
   service-name/delivery boundary. Exact static code maps that request to
   `VideoContext → uridecodebin → eligible asfdemux`, while LightMediaScanner
   startup indexing uses a separate non-GStreamer ASF plugin. Manual authentic
   PlayerEngine D-Bus reachability is proven, but no automatic media-to-root path
   or RCE is established.
4. Determine production DAC/SMACK access to `/dev/snd/seq` and analyze V-013's
   first post-free use without attempting or claiming a root exploit.
5. Measure production interface features before treating CVE-2017-1000112 as a
   reachable path; keep the current VM NIC-free.
6. If physical bench access later becomes available, capture UART and installed
   version state before any write or engineering-mode experiment.

## Sources

- `evidence/eu-kernel-symbol-recovery-and-trust-chain.md`
- `evidence/gen5w-public-exploit-ecosystem.md`
- `evidence/known-exploits-and-cve-survey.md`
- `evidence/bench-hardware-root-path.md`
- `evidence/network-surface-and-wifi-root.md`
- `evidence/child-notes/01…04`
