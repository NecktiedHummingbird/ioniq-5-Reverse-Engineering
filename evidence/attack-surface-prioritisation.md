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

### 1. USB storage via AppNavi replacement — highest yield

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

### 2. Wi-Fi remote — component CVEs, version-gated

No public Wi-Fi-to-root exists for Gen5W_L. The realistic classes are old
daemons whose exact versions are encrypted. Survey totals (2015–2020):
dnsmasq 15, hostapd 26, wpa_supplicant 30, dropbear 12, BusyBox 24, miniupnpd 9,
OpenSSL 95.

| Candidate | Component | Type | Reachable when |
|---|---|---|---|
| CVE-2017-14491 | dnsmasq | heap overflow, DNS response | unit runs DHCP/DNS in AP mode |
| CVE-2017-14493 | dnsmasq | stack overflow, DHCPv6 | same |
| CVE-2016-2148 | BusyBox `udhcpc` | heap overflow, OPTION_6RD | unit joins a hostile AP as client |
| CVE-2015-1863 | wpa_supplicant | heap overflow, SSID in P2P frames | radio range |
| CVE-2016-6309 | OpenSSL 1.1.0 | TLS state-machine UAF | any TLS listener |

Triage requires version strings; `tools/uk_fw/net_surface.py` captures them.

### 3. USB gadget / iAP2 / CarPlay — needs plaintext

Kernel config enables `USB_F_IAP2`, `USB_U_IAP2`, `USB_G_SERIAL`,
`GADGETFS`, `USB_F_MASS_STORAGE`, `USB_DWC3` dual-role. These are modules, so the
code is in the encrypted rootfs. iAP2 is a bounded, length-prefixed protocol
parser — a classic memory-safety target, but auditable only after decryption.
Note: `CONFIG_LGE_CARPLAY=y` in the kernel, yet no `carplay` symbols exist in
`vmlinux`, so the parsing is userland.

### 4. Kernel — analysed; conditional post-execution candidates remain

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

### 5. MICOM / CAN — post-exploitation

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

1. Trace post-index V-012 reachability through media-manager/browser selection,
   thumbnail extraction, and playback handoff. LightMediaScanner startup indexing
   is now confirmed to use a separate non-GStreamer ASF plugin; manual authentic
   PlayerEngine D-Bus reachability is proven, but no automatic media-to-root path
   or RCE is established.
2. Determine production DAC/SMACK access to `/dev/snd/seq` and analyze V-013's
   first post-free use without attempting or claiming a root exploit.
3. Measure production interface features before treating CVE-2017-1000112 as a
   reachable path; keep the current VM NIC-free.
4. If physical bench access later becomes available, capture UART and installed
   version state before any write or engineering-mode experiment.

## Sources

- `evidence/eu-kernel-symbol-recovery-and-trust-chain.md`
- `evidence/gen5w-public-exploit-ecosystem.md`
- `evidence/known-exploits-and-cve-survey.md`
- `evidence/bench-hardware-root-path.md`
- `evidence/network-surface-and-wifi-root.md`
- `evidence/child-notes/01…04`
