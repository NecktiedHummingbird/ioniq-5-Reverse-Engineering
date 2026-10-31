# IONIQ 5 infotainment vulnerability and remediation register

Updated: 2026-11-01. Internal defensive research; no disclosure or vendor contact is implied.

## Scope and evidence rules

Target: official European Gen5W **Linux** `NE_E.EUR.S5W_L.001.001.260128`, vendor kernel `4.1.27-abl`. The owner's installed head-unit build is unknown. No physical or network head-unit access is available. VM observations do not establish hardware exploitability.

This register began as a backfill and now also records continuing exact-build review. Entries distinguish verified behavior, static observations, unvalidated candidates, rejected hypotheses, and modification-created hazards. No numeric severity is assigned without reachability and impact evidence. Never infer missing security fixes from a package or kernel version alone. See `evidence/corrections-log.md` before relying on historical reports.

**Validation status of the 2026-10-28 advisor report.** The three claims supplied as a third-party summary were tested offline against the recovered rootfs on 2026-10-28. None was accepted as stated:

- **V-006 is not a USB-to-root command-injection path in this build.** The MTP branch constructs unquoted `system()`/`popen()` commands, but `usb_id` calls both `util_replace_whitespace()` and `util_replace_chars(..., NULL)`. The second call restricts `ID_SERIAL_SHORT` to alphanumerics plus `#+-.:=@_`. A full VM run delivered the MTP event to the authentic root automounter and rewrote command separators/substitution characters to `_`; no command executed. The unsafe shell construction remains a latent defect and denial-of-service surface.
- **V-007 was confirmed as a configuration fact** (media parsers default to uid 0 with no isolation) and reclassified as informational hardening, not a vulnerability.
- **V-008 was confirmed as shipped configuration** (a password-gated root console) but **not** as a vulnerability; the SHA-512 hash is sound and no bypass was found.

Nothing here was demonstrated on a running unit or on hardware. Evidence lives under `work/vm/vendor-userspace-260128/validation-261028/`.

## V-001 — Unsigned kernel modules execute after privileged loading

- **Status:** existing VM-verified behavior; hardware applicability untested.
- **Evidence:** `work/ui-recovery/SECURITY-FINDING-module-load.md`; `work/eu-260128/kernel.config`; `work/ui-recovery/SUMMARY-and-runbook.md`.
- **Observation:** kernel configuration enables modules but not module signatures. Prior QEMU experiments record module initialization executing against the vendor kernel. The VM boot uses the separately documented SDHCI guest-RAM adaptation; this is not a complete stock-device boot.
- **Preconditions:** module-loading privilege, or a separately established privileged loader accepting attacker-controlled modules. No unprivileged entry is established.
- **Potential impact:** a prior privileged foothold can extend into kernel execution; sensitive kernel state and enforcement may then be exposed. Persistent installation, actual key extraction, and physical-unit compromise are not demonstrated by this result.
- **Remediation:** enforce signatures against a protected module trust store; remove unused module loading; restrict loading privileges and writable module paths; consider disabling further loading after required boot modules initialize. Preserve required vendor drivers and recovery behavior.
- **Acceptance:** required signed modules load; unsigned and modified modules fail before initialization; unprivileged loading fails; legitimate update/recovery still works. Test only on disposable VM snapshots until device recovery is established.

## V-002 — Keystore test/debug/secure-boot-ignore build options

- **Status:** configuration observation; security impact unvalidated.
- **Evidence:** `work/eu-260128/kernel.config`; `Ioniq5-CHANGELOG.md` 0.39.0; `evidence/eu-keystore-manifest-root-of-trust.md`.
- **Observation:** historical analysis records `KEYSTORE_TESTMODE`, `KEYSTORE_TEST_MIGRATION`, `KEYSTORE_DEBUG`, and `KEYSTORE_SECURE_BOOT_IGNORE` enabled. Names alone do not establish a usable bypass or disclosure.
- **Preconditions / gaps:** trace compiled call sites, runtime gates, device-node permissions, SMACK policy, and actual debug activation. No unauthenticated reachability is established.
- **Potential impact:** test-only operations or sensitive logging could weaken production isolation if reachable.
- **Remediation:** disable production test/migration/debug paths unless essential; remove secret-bearing logging; verify secure-boot enforcement through the entire boot chain rather than a configuration label.
- **Acceptance:** negative tests for test-only ioctls and secret logs; signed boot/update positive controls; demonstrate that production enforcement remains active under the intended threat model.

## V-003 — Keystore device authorization depends on external policy

- **Status:** static observation; not a confirmed vulnerability.
- **Evidence:** `evidence/pre-disclosure-security-assessment.md` §3; `evidence/eu-keystore-manifest-root-of-trust.md`; corrections C8/C9.
- **Observation:** reviewed `keystore_open` lacks a capability check. Device mode, SMACK label/policy, and individual operation checks determine access; absence of an open-time capability check alone is not a defect.
- **Gap:** re-audit permissions and policy using the now-recovered rootfs and guest runtime. Older reports calling userspace inaccessible are stale.
- **Potential impact:** unauthorized key operations only if an inappropriate caller can reach a sensitive operation lacking further authorization.
- **Remediation:** least-privilege device permissions and SMACK rules; operation-specific authorization; regression tests from actual service identities.
- **Acceptance:** unauthorized identities cannot perform sensitive operations; required authorized services continue functioning; public-key-only operations are not misclassified as secret disclosure.

## V-004 — Boot trust inputs and embedded public-key binding

- **Status:** confirmed format/mechanism observations; trust bypass unproven.
- **Evidence:** `evidence/eu-boot-container-signature.md`; `evidence/eu-keystore-manifest-root-of-trust.md`; `evidence/vendor-kernel-vm.md`; corrections C12.
- **Observation:** boot containers carry a modulus; vendor manifest initialization consumes `ABL.oemkm` physical-memory input. Synthetic VM inputs initialize subsystems, but do not demonstrate acceptance by the real bootloader.
- **Gap:** establish authenticated binding of the manifest, command line, and verification key to a hardware-protected root. No bootloader dump or acceptance test establishes a missing binding.
- **Potential impact:** attacker-selected trust roots only if the preceding trusted stage permits substitution.
- **Remediation:** authenticate the full handoff and pin verification keys to a protected trust anchor; prevent untrusted command-line overrides.
- **Acceptance:** reject substituted manifests/keys/command lines before use, retain known-good signed boot and recovery controls.

## V-005 — Update integrity / rollback binding candidates

- **Status:** unvalidated current-build candidates, not demonstrated bypasses.
- **Evidence:** `evidence/pre-disclosure-security-assessment.md` §1; `evidence/community-field-evidence.md`; `evidence/eu-ota-container-structure.md`; corrections C4/C5/C13/C14.
- **Observation:** manifest CRC-32/size is not cryptographic authentication. A repaired CRC alone does not establish package acceptance; field evidence reports rejection despite repair. Older public rollback reports do not validate this build.
- **Gap:** trace recovered updater signature/digest/version binding and anti-rollback state. Native decryption recovery is not equivalent to a signature bypass.
- **Additional unvalidated source:** the owner's channel summary reports a 25–26 October updater-execution attempt stopped by signature checks followed by reboot. No message links, exact artifact identity, execution trace or demonstrated bypass were supplied. This does not promote V-005 to a confirmed vulnerability; provenance and platform caveats are retained in `evidence/community-chat-leads.md`.
- **Potential impact:** unauthorized or obsolete payload acceptance only if authenticated metadata does not bind payload identity and policy.
- **Remediation:** cryptographically bind all payload hashes, target identity, dependencies and version; enforce authenticated rollback policy with a supported recovery design.
- **Acceptance:** reject modified payloads, mixed-release metadata, wrong-target packages, and disallowed rollback; accept genuine supported upgrades and recovery.

## H-001 — Third-party USB root runner (not a vendor defect)

- **Status:** confirmed public modification behavior, **not established as present in stock firmware or installed in the current VM**.
- **Evidence:** `evidence/wideopen-payload-and-persistence.md`; `evidence/navi-extended-binary-analysis.md`; `Ioniq5-CHANGELOG.md` 0.25–0.29.
- **Risk:** the modification's privileged service executes scripts from removable media without authenticating them. This introduces a root execution hazard after installation; it must not be attributed to the vendor image.
- **Remediation:** do not include it in a deployable image; isolate bench-only tools; remove the service and verify both boot slots before returning any modified unit to use.
- **Acceptance:** no privileged removable-media autorun; check unit files, installed binaries and both slots; verify that removing the modification does not break authentic services.

## I-001 — EGL copy-path ordering defect (measured on the authentic binary)

- **Status:** **mechanism measured**, still not a demonstrated exploitable vulnerability. No severity or CVE claim. Updated 2026-10-29.
- **Affected stack:** vendor `/usr/lib/libEGL.so.1.0.0` (SHA-256 `0c373e50…0e3d53`) on its **Wayland software (swrast) display path**, running with the project's Mesa 18 software DRI module.
- **Scope refinement (2026-10-29):** the binary contains four distinct surface constructors — `dri2_create_window_surface`, `dri2_drm_create_window_surface`, `dri2_wl_create_window_surface` and `dri2_wl_swrast_create_window_surface`. The `-1` sentinel is written by the **swrast-specific** constructor, and the affected `put_image2`/`get_image`/`swap_buffers` functions all belong to the `dri2_wl_swrast_*` family. The hardware paths use different constructors and do not share this vtable, so **this evidence does not implicate the i965/i915 hardware path**. The defect should therefore be read as specific to the software-rendering path that this VM necessarily uses, not as a defect shown to affect cars with working Intel graphics.
- **Measurement:** an in-VM hardware-breakpoint observer captured two stages on the authentic `AppCamera` inside the real launcher chain — `libEGL+0x16f16` (before the width cache) and `libEGL+0x16f1e` (immediately after `swrast_update_buffers` returns) — reading the surface fields at `+0x2c`/`+0x30`:
  - **P1:** same surface pointer `0x3ac74f68e0`, width **-1**, height **-1**
  - **P2:** same surface pointer, width **1920**, height **720**
- **Conclusion:** the dimensions are the creation sentinel at P1 and the real geometry at P2, so `swrast_update_buffers` populated them *during this invocation*, while the copy path had already derived its stride from `Width = -1` (yielding `-4`). The stale-stride ordering defect is therefore **measured**, not inferred. This supersedes earlier statements that width change had not been observed.
- **Threat/impact boundary:** local VM application termination is established. Attacker influence over the dimension values, stock-driver reachability, arbitrary writes, code execution and persistence remain unestablished. Do not describe this as a remotely reachable defect.
- **Remediation direction:** validate the surface dimensions before deriving a copy stride, or re-derive the stride after `swrast_update_buffers` returns; treat a non-positive width or height as "no copy" rather than converting it into a byte count. Reject negative and overflowing sizes in the copy loop.
- **Validation still needed:** reproduce with stock Intel graphics; test zero-size and first-swap buffers specifically; confirm that rejecting non-positive dimensions does not regress legitimate rendering.

## V-006 — Unsafe MTP shell construction, descriptor injection blocked (LATENT DEFECT)

- **Status:** the shell sink and physical MTP branch are VM-confirmed, but **USB descriptor-to-command execution is rejected for this exact build**. This supersedes the 2026-10-28 static classification.
- **Severity framing:** defects are not scored numerically here. Physical USB can reach and disrupt this root helper, but root command execution through `ID_SERIAL_SHORT` is not established.
- **Affected component:** `/app/bin/usb-automount` (43,136-byte stripped x86-64 ELF), started by `lib/systemd/system/usb-automount.service`, which contains **no `User=` directive** and therefore uses the system-service default of uid 0.
- **Evidence:** `work/vm/vendor-userspace-260128/validation-261028/v006/` (report, udev inventory, sanitiser excerpt, disassembly). Independently re-verified with `llvm-objdump`:
  - `0x5326` `__sprintf_chk` builds `"%s %s %s %s &"` (`.rodata 0x7928`) from `"/usr/bin/go-mtpfs"`, `"--dev"`, **`ID_SERIAL_SHORT`**, and `"/media/mtp/<ID_SERIAL_SHORT>"`; `system()` is called at `0x535f`. No quoting or escaping.
  - `0x53b9` `popen()` runs `"cat /proc/mounts | grep %s"` (`.rodata 0x7936`) using the same serial-derived string.
  - `ID_SERIAL_SHORT` is read at `0x4146` via `udev_device_get_property_value` (`.rodata 0x760c`).
  - Branch selection at `0x44c3`–`0x44cf` requires `ID_USB_INTERFACES` to contain `060101` (PTP/Still-Image) or `ffff00` (vendor-specific). Plain mass-storage-only devices take a different branch that uses `mount(2)`/`umount2(2)`/`mkdir(2)` and no shell. The unsafe MTP sink is real; descriptor-based command injection is blocked downstream by udev sanitization.
- **Corrected sanitizer analysis:** after `util_replace_whitespace` at `0x1c334`, `builtin_usb_id` calls `0x22a00` at `0x1c33e` with `rsi = NULL`. That second function calls the predicate at `0x29d80`, whose built-in allowlist at `0x537c9` is exactly `#+-.:=@_`, in addition to ASCII letters and digits. Other printable bytes become `_`. A literal `\\x` pair can survive, but the shell treats it as an escaped `x`, not a hexadecimal byte escape. The earlier analysis mislabelled `0x22a00` as trimming and therefore reached the wrong security conclusion.
- **Dynamic result:** QEMU `usb-mtp` presented raw serial `a;id>/tmp/v006.id;echo${IFS}V006KMSG>/dev/kmsg;#`; sysfs retained it, while udev emitted `a_id__tmp_v006.id_echo__IFS_V006KMSG__dev_kmsg_#`. The authentic uid-0 automounter stayed alive and reached the MTP `system()` branch, but created no marker and executed no injected command. A broader matrix preserved only `[A-Za-z0-9#+\-.:=@_]` and rewrote separators, substitutions, redirections, quotes, globs and slashes. Logs: `v006-exploit-host.log` SHA-256 `568f3197ff178cbf8356674c74a149b66ec1bfd96eedd5f2098a830c84adb27a`; matrix SHA-256 `de0757442ca4a74d3a3f87db79e8c3eb2b16b101dc47131d266af71ac734b0a1`.
- **Residual impact and preconditions:** physical PTP/MTP access can reach the root shell sink. A leading `#` can truncate the helper command as a comment, so denial of service is plausible. No surviving descriptor sequence found can introduce a new shell word, substitution, redirection or command.
- **Remediation:** remove both `system()` and `popen()`. Launch an absolute path with `execve()`/`posix_spawn()` and a fixed argument vector plus controlled environment. Read `/proc/mounts` directly and compare decoded fields instead of shelling out to `grep`. Derive mount-directory names independently of the raw serial; constrain paths beneath an owned directory and prevent traversal and symlink races. Treat serial validation as defence in depth, never as a substitute for removing the shell. Disable the MTP branch cleanly when the helper is absent. Move descriptor handling and helper execution out of root, retaining only narrowly scoped privileged mount operations.
- **Acceptance / regression:** shell metacharacters, separators, `${IFS}`-style expansion, over-long serials, comma and non-ASCII serials, and a missing helper must all produce no shell interpretation; legitimate PTP and mass-storage mount and unmount must still work; no privileged child of the automounter should exist.
- **Validation boundary:** do not describe V-006 as "USB-to-root" or as an exploitable CWE-78 on `260128`. Re-test other firmware builds because the sanitizer is defence in depth rather than a substitute for removing the shell.

**Runtime amendment (2026-10-29) — the metacharacter pass-through claim above is falsified.**

Dynamic confirmation was attempted in the isolated VM and reached the vulnerable sink without
executing injected code. Three things were established, in order:

1. **Reachability is real.** A QEMU `usb-mtp` device presents `bInterfaceClass=06 SubClass=01
   Protocol=01`, udev records `E:ID_USB_INTERFACES=:060101:`, and the automounter takes the MTP branch,
   emitting `sh: /usr/bin/go-mtpfs: No such file or directory`. That message can only be produced by
   the `system()` call at `0x535f`, so the unquoted `sprintf` path is confirmed reachable at runtime,
   not merely in disassembly.
2. **The delivered property is heavily sanitised.** udev hands over
   `ID_SERIAL_SHORT=a_id__tmp_v006.id_echo__IFS_V006KMSG__dev_kmsg_#` for a submitted
   `a;id>/tmp/v006.id;echo${IFS}V006KMSG>/dev/kmsg;#`. A second sanitiser exists beyond
   `util_replace_whitespace`: an allow-list of alphanumerics plus `#+-.:=@_` is present in
   `lib/systemd/systemd-udevd` and `lib/libudev.so.1.6.4`, and every other printable byte is rewritten
   to `_`. Semicolons, redirects, `$`, backticks, braces and `${IFS}` therefore cannot survive.
3. **The payload itself is sound.** Feeding the identical string directly to the guest's `/bin/sh`
   yields `uid=0(root) gid=0(root)`, so the failure is the property sanitiser, not the payload, the
   guest, or the harness.

**Revised status.** The source defect stands: `sprintf` into `system()` with no quoting, plus `popen`
with a serial-derived string, are genuine CWE-78 patterns and must be removed. But this entry is
**downgraded from "confirmed exploitable-by-construction" to a latent defect that is not exploitable on
260128 through the udev property path**, because the value reaching the sink is reduced to
`[A-Za-z0-9#+-.:=@_]`. It becomes exploitable again under any of: a udev version or rule set without
that allow-list, a path that reads the raw descriptor instead of the property, or a caller that passes
an unsanitised string. Treat the allow-list as accidental defence in depth, not as the fix. The earlier
statement in this register that shell metacharacters "pass through unchanged" is withdrawn.

**Reproduction status (updated 2026-10-30).** QEMU `usb-mtp`, the authentic udev database, system D-Bus and `usb-automount` now run together. `ID_USB_INTERFACES=:060101:` and the missing-`go-mtpfs` shell error prove MTP-branch reachability. The sanitizer—not missing hardware, D-Bus or payload syntax—is the reason command injection does not occur.

## V-007 — Media parsing runs as an unprivileged-separation gap (CONFIRMED configuration, not a demonstrated exploit)

- **Status:** **confirmed configuration, informational.** Root execution of a parser is a risk amplifier rather than a vulnerability by itself. A separate, dynamically reproduced ASF parser defect is now recorded as V-010; this entry remains the privilege-separation finding. Triaged 2026-10-28.
- **Evidence:** `work/vm/vendor-userspace-260128/validation-261028/v007/` (report, component table, evidence excerpts).
- **Observation:** none of the media service units specify `User=` (the only templated unit in the image is `user@.service`). `lightmediascannerd`, `thumbnail_extractor`, `mediamanager`, `playerengine` (GStreamer 1.8.3 with 160 plugins plus libav) and `MediaBrowser` (libmediainfo) are therefore configured for uid 0. No `CapabilityBoundingSet=`, `NoNewPrivileges=` or `SystemCallFilter=` is present, no `libseccomp` exists in the image, and the image contains **zero setuid binaries**. The only confinement is SMACK labelling (`App::mediaplayer`, `App::usbautomount`), which does not change uid.
- **What is not established:** production-hardware runtime uid; that missing unit directives prove the absence of inherited or directly-installed seccomp filtering; automatic V-010 reachability through the production scanner/thumbnail D-Bus workflow; or media-triggered code execution rather than the VM-confirmed crash.
- **Remediation:** run scanners, thumbnail workers, players and their D-Bus activation paths under dedicated non-root accounts; put privileged device and mount management behind a narrow broker; restrict filesystem writes and network access; tighten SMACK rules; apply the hardening this systemd-225 build actually supports; backport parser fixes and fuzz hostile media.
- **Acceptance:** media components run under distinct non-root identities; a parser crash cannot reach privileged state; legitimate playback, indexing and thumbnail generation still work.

## V-008 — Conditional root serial console, password-gated (shipped configuration, not an auth bypass)

- **Status:** **shipped configuration confirmed; status as a vulnerability unresolved.** A password-authenticated root console is normal engineering practice. It is **not** an authentication bypass, and no defective hashing was found. Triaged 2026-10-28.
- **Evidence:** `work/vm/vendor-userspace-260128/validation-261028/v008/` (report plus machine-readable summary with per-file digests).
- **Observation:** `etc/esinit_agetty.sh:6` starts `agetty -8 -L ttyS2 115200 xterm`; the autologin alternative on line 5 is commented out. `etc/securetty` permits `ttyS2`, and `etc/passwd.legacy` gives root `/bin/sh`. `etc/shadow.Global` holds a `$6$` SHA-512-crypt verifier with a unique 10-character salt, no explicit rounds parameter, and no locked marker; the other 18 accounts are locked with `*` or `!`. `lib/systemd/esinit` creates `/tmp/secure_console_disable` and then launches the getty when that file exists, which is fail-open ordering; the MICOM parameter `secure_console=1` would suppress it by removing `/dev/ttyS2`.
- **Latent trust material:** `etc/dropbear/authorized_keys` ships one static `ssh-rsa` key, and the RPM database retains a Dropbear package record, but the recovered product filesystem has no `dropbear`/`dropbearmulti` executable, socket unit, host-key unit/key, or enable link. The socket-fed template is inert. This is dormant configuration, not a backdoor: a public key is not a private key and no reachable SSH service exists. See `evidence/dropbear-activation-and-authentication.md`.
- **What is not established:** that `esinit` executes on a production unit (no unit, generator or init script in the rootfs references it; `sbin/init` is systemd, so an external trigger such as a bootloader `init=` would be required); that `passwd.legacy`/`shadow.Global` are the active databases; that production units ship the console enabled; that the UART is physically exposed; and anything about password strength or per-unit uniqueness.
- **Remediation:** identify the real production boot caller and the active account database first. Disable the serial getty by default in production. Replace the inverted temporary-file gate with an explicit authenticated service-mode decision that defaults to disabled on error or missing state, and do not rely solely on deleting a device node. Remove `ttyS2` root-login permission and lock direct root login where unnecessary, using controlled and auditable maintenance access instead. Remove unused authorized-key material and ensure future SSH enablement cannot silently trust it.
- **Acceptance:** no root login on a production serial line; maintenance access remains auditable; enabling the console requires an explicit authenticated decision that cannot be reached by creating a file; no dormant key material ships.

## V-009 — Password database lives at a volatile, world-facing path (CANDIDATE, unverified)

`/etc/passwd` in `NE_E.EUR.S5W_L.001.001.260128` is a **symlink to `/tmp/passwd`**, confirmed by
inspecting the recovered rootfs; `/etc/group` is a normal file. A fresh boot therefore has no user
database at all until init populates it, which is observable: `dbus-daemon --system` refuses to start
with `Could not get password database information for UID of current process: User "???" unknown`,
and `usb-automount` dies three seconds later as a consequence.

Two distinct concerns, neither demonstrated:

1. **Availability / fail-open reasoning.** Every NSS consumer in the system depends on a file in
   volatile storage being created correctly before it is needed. Anything that reads the user database
   earlier than init's population step sees no users, and services fail in ways their authors did not
   intend.
2. **Potential integrity of authorization inputs.** If `/tmp` is world-writable at runtime on a real
   unit, as is conventional, then an unprivileged process that wins the race to create `/tmp/passwd`
   supplies the user and group database that NSS subsequently answers from. That would let a local
   attacker define or alter identity records consulted by authorization checks, including the
   `messagebus` account this very service relies on.

**Status: candidate.** Not verified: the runtime mode and ownership of `/tmp` on hardware, whether
init recreates the file with restrictive ownership, whether any consumer caches the database before
init runs, and whether a local unprivileged context is reachable at all. Stated as a design hazard
worth checking on real hardware, not as an exploit. Evidence: `work/vm/vendor-userspace-260128/
dbus-automount-findings.md` and the `dbus-automount-probe.py` driver.

## V-010 — Null-pointer dereference in `sbi_apl_commit` wedges the platform bus (DOWNGRADED: bring-up defect, not security)

Loading the vendor module `lge_usb_adapter` on emulated hardware faults immediately:

```
BUG: unable to handle kernel NULL pointer dereference at 000000000000000c
IP: [<ffffffff8105913b>] sbi_apl_commit+0x60/0x2bc
```

`/etc/esinit-modprobe.sh` runs that load during init, and the process is killed. The fault occurs while
holding the platform `device` lock, which is then orphaned: the next platform driver to register
(`lge_fan_init`, reached via `/sbin/modprobe fan`) blocks indefinitely in state `D` inside
`__driver_attach`, and the system stops one line short of starting systemd. The hung-task detector is
compiled out, so the stall produces no diagnostic.

**Impact as observed:** a denial of service against boot, triggered by an in-tree module load rather
than by attacker input, so it is a robustness defect first. Severity is not scored: reaching it
requires the ability to load a module, which already implies privileged context.

**Why it is in the register anyway:** `sbi_apl_commit` reaches a null pointer at offset `0x0c` through
sideband access paths, and the argument that matters is whether any of the reachable paths can be
influenced by unprivileged input or by device-supplied data. If they can, this is an arbitrary
null-dereference or worse in a driver that runs before the HMI; if they cannot, it is a
bring-up defect. That question is open.

**Status: downgraded 2026-10-29.** Follow-up analysis resolved the open question in the negative: the faulting pointer is the global `0xffffffff81bd5460`, assigned only from `dev.platform_data` at `0x810594c2`, and no attacker-reachable path to it was found. The driver asserts hardware presence that emulation does not provide, so this is a bring-up defect and an illustration that the driver trusts platform data. Kept in the register for that lesson, not as a finding. Evidence: `evidence/vm-bringup/esinit-bringup-findings.md`.

## V-011 — Automounted Tuxera NTFS omits `nodev` (HARDENING GAP; DEVICE INTERPRETATION CONFIRMED)

- **Status:** the flag omission and exact Tuxera NTFS special-file behavior are now confirmed. A disposable NTFS image retained an inert character node across unmount/remount; without `nodev`, uid/gid 65534 opened it read-only, while the same open was denied with `nodev`. This remains a post-execution/DAC-bypass primitive, not a demonstrated first-step root path.
- **Where:** `/app/bin/usb-automount`, mass-storage mounts at `0x4d70`/`0x4df1`. Flag words `0xC0ED000A` and `0xC0ED000B` contain `MS_NOSUID | MS_NOEXEC` (plus read-only on retry) but omit `MS_NODEV` (`0x4`). There is no positive `MS_DEV` flag; device interpretation is enabled by omission of `nodev`.
- **Filesystem constraint:** the function constructs only vendor driver names `tntfs` and `texfat` for NTFS/exFAT. FAT/exFAT do not natively carry POSIX device inodes. Exact Tuxera NTFS `3016.7.1.2.3`, however, accepted an NTFS 3.1 control, created `inert-null` as character device `1:3`, and reproduced it as `root:root` mode `0755` after remount. The representation was generated by this same Tuxera driver; portability to arbitrary third-party NTFS authoring tools is not yet claimed.
- **Harmless dynamic control:** the no-`nodev` mount showed the character type and `1:3`, and a process reduced to numeric uid/gid 65534 with SMACK label `_` opened it read-only (`dd` rc 0). The `ro,nodev,nosuid,noexec` control retained the inode metadata but denied the open (`Permission denied`, rc 1). The target was QEMU `/dev/null`; no eMMC or sensitive emulated device was accessed.
- **Impact boundary:** a crafted NTFS volume can therefore activate VFS device semantics on this driver when `nodev` is omitted. A device node does not execute itself. Production impact still requires a local process that can reach the mount and a useful major/minor plus access mode; application-specific SMACK domains, mounted-path permissions, useful write access, and any root consequence remain unverified.
- **Evidence:** clean NTFS image SHA-256 `220ad1d065856ae49d971c5d014ab527aca36aa1367f9e8709ceb9d446295cde`; clean read-only mount log SHA-256 `e9d19e192700398c00b2fd083cc39fea726b8170ca0d5eb5e81f2a85ee17d036`; special-file log SHA-256 `4d68550b5cb8420622e25cdfd35ccb9fee194b48fb16f946090607c3f784a494`; numeric-uid control log SHA-256 `8c41d9025183781ade987cd688d4724d48d6964cb876492004649803eb2403f3`.
- **Remediation:** add `MS_NODEV` while retaining `nosuid,noexec`; isolate removable mounts in a namespace and expose only ordinary files to unprivileged media workers.

## V-012 — GStreamer ASF >32-stream object overwrite (VM-CONFIRMED SERVICE CRASH; RCE UNPROVEN)

- **Status:** CVE-2026-2920's affected path is dynamically reached in the recovered `260128` userspace through both authentic `gst-discoverer-1.0` and the authentic uid-0 PlayerEngine D-Bus service. A 32-stream boundary control survives; 33- and 34-stream files terminate PlayerEngine with signal 11. Exact static analysis also establishes an explicit `MediaBrowser requestThumbnails(as) → thumbnail_extractor Start(as) → VideoContext → uridecodebin` route eligible to select the shipped ASF plugin. Arbitrary code execution is **not** demonstrated. Automatic scan/UI invocation, dynamic thumbnail-parser reachability, and installed-device applicability remain unverified.
- **Component:** `/usr/lib/gstreamer-1.0/libgstasf.so`, SHA-256 `05e887731708f0b0a52ff9fc75767a00fda9984e422983e5ff1d672f4b1af45d`, GStreamer ABI `1.8.3`. PlayerEngine library SHA-256: `28987e1accfa7a7d04557b3d81dab7f8cd2aabb84a9c5aab7e1c8c4bc85510a0`. The firmware predates upstream's 11 February 2026 fix.
- **Mechanism:** `GstASFDemux` has `stream[32]`. The affected parser accepts stream 33 and creates `audio_32`. Exact vendor instructions show a 208-byte stream stride, array base `GstASFDemux+0x1a8`, `flowcombiner` at `+0x1bb0`, and `old_stream[0]` at `+0x1bb8`. The 33rd stream's vendor-only field store at plugin `0x990d` zeros the low 32 bits of `flowcombiner`; this corrects the earlier public-source-only 200-byte/pad-pointer-transplant interpretation.
- **Direct dynamic proof:** a bounded probe duplicated one valid WMA Stream Properties object to IDs 1–33. Authentic `gst-discoverer-1.0` logged `Found stream 33`, created its pad, continued into the data object, and exited `139`; the kernel recorded `asfdemux0:sink[...] segfault at e00000000 ... in libglib-2.0.so.0.4400.1`. Probe SHA-256: `9c5aaa1f7ad2a4e8526066f6f22e2b3737b912de93f94ab1aa858e3a9ec32518`; direct host-log SHA-256: `b98b05560207193831fe1d47ed8cc093d5ffcc46b48e2b1c0e23c4ee22da6225`.
- **PlayerEngine proof:** the accepted option is `{"option":{"mediatype":"audio"}}`, not the earlier flat JSON. Stock `alsasink`/`media_mixer` fails only because QEMU has no soundcard. A VM-only `/etc/asound.conf` mapping `pcm.media_mixer` to ALSA `type null` preserves the stock factory/device contract. With `file:///tmp/input.wma`, valid one-stream and 32-stream controls return `true` and survive; 33- and 34-stream inputs return `true`, reach the vulnerable range, then die. The 33-stream signal backtrace is `g_queue_push_head+0x1d <- libgstasf.so+0xb6cc <- libgstasf.so+0x1305d`. Exact code at `0xb6c0..0xb6c7` loads the corrupted `flowcombiner` and calls `gst_flow_combiner_add_pad`.
- **URI control:** under the corrected nested option and working ALSA-null environment, `file:///tmp/input.wma` succeeds while plain `/tmp/input.wma` returns `false`. This supersedes the old comparison confounded by a flat option and unavailable sink.
- **Impact boundary:** NVD/ZDI classify the generic defect as potential remote code execution in the current process. Here, root-context parser memory corruption and process death are proven. No attacker-selected pointer, instruction-pointer control, shell, persistence, SMACK bypass, CAN access, or safety-system impact was obtained. The ALSA-null mapping is a VM compatibility shim, not evidence about production hardware.
- **Automatic reachability boundary:** LightMediaScanner startup scanning of `/media/usb` is confirmed, but it uses its own direct-I/O `asf.so` metadata plugin (SHA-256 `f4b42a8eacb73990d35439e27513c28f1d31257488d0c130e6e1a936cb9bb219`) with no GStreamer dependency. It processed the 33-stream file with zero reported errors and remained alive; a full session-bus capture showed no PlayerEngine or thumbnail call. The thumbnail route is statically explicit but client-request driven: reviewed scan callbacks do not call it, and bounded VM attempts did not deliver `Start` or map `libgstasf`. Manual PlayerEngine D-Bus invocation remains the only dynamically proven production-service route.
- **Tooling:** `tools/uk_fw/asf_stream_probe.py` safely duplicates one valid ASF stream object, updates header/file sizes, and audits the upstream rejection marker. It refuses malformed templates, in-place overwrite and stream counts outside `1..127`. Generated files carry no command payload or shellcode.
- **Remediation:** backport upstream `37d7991168a223d0810fd1f4493ec6a8b6a510d3` for both audio and video stream objects; reject `num_streams >= G_N_ELEMENTS(demux->stream)` before any pad or stream state is created. Run media parsing under a dedicated unprivileged, sandboxed worker. Disable ASF parsing if the format is not required.
- **Acceptance:** 32-stream positive control parses as before; 33+ streams fail cleanly before pad creation; malformed/repeated headers do not crash; production thumbnail, scanner and playback paths are tested under non-root identities.
- **Evidence:** `evidence/gstreamer-cve-2026-2920.md`; reviewed excerpts `evidence/artifacts/media-candidates/playerengine-asf-service-evidence.txt` and `evidence/artifacts/media-candidates/thumbnail-extractor-asf-route-evidence.txt`. PlayerEngine 32-/33-/34-stream log SHA-256 values: `949d069052de525f24b4a2995b06d62ee4592cbcce3dcdd4a2a8cc9329799b36`, `16ff6f1241899846ccbfb3d9bae54a5f50994543c07a044625b846f19e598993`, `eee3b52e2ef458d67638b2bbf6f7e99d8ac2824bc3347411957e5001f0895908`.

## V-013 — ALSA sequencer port-creation race (EXACT PRE-FIX CODE; ENTRY POINT REACHABLE)

- **Status:** CVE-2017-15265's pre-fix lifetime logic is present in the exact shipped module. A benign offline VM diagnostic confirmed that numeric uid/gid 65534 can open `/dev/snd/seq` and complete one client-ID, create-port, and delete-port sequence under the recovered `root:root 0644` DAC mode. No use-after-free, root transition, or code execution was observed.
- **Component:** `/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko`, SHA-256 `ccc802452bb4ac4527d2def96ddef463211c03ae2c07d9003fdc7ebed9eb091d`; `CONFIG_SND_SEQUENCER=m`; aliases `devname:snd/seq` and `char-major-116-1`.
- **Mechanism:** shipped `snd_seq_create_port` publishes the new port without the use-lock reference added by upstream fix `71105998845fb012937332fe2e806d443c09e026`. Shipped `snd_seq_ioctl_create_port` consequently lacks both matching unlock paths. Another caller sharing the client can delete the port before later create-ioctl dereferences.
- **Dynamic reachability:** the tracked diagnostic contains no race, fork/clone, heap grooming, payload, or privilege operation. It produced `ALSA_SEQ_OPEN_OK`, `ALSA_SEQ_CLIENT_ID_OK`, `ALSA_SEQ_CREATE_PORT_OK`, `ALSA_SEQ_DELETE_PORT_OK`, and `ALSA_SEQ_UNPRIV_RC=0`. Probe SHA-256: `f12c99be0fd854d5ef7d1402c9ffd2292afe74a1a7b138d4c71d84735c42e5b1`; tool host-log SHA-256: `1f8d3dc1d29534945f9de21f02cbc8dbfb0f7a83307829a6c4ec11568ce4b23f`.
- **Negative control:** a bounded disposable race made 200,000 create and 400,000 delete attempts and completed without a kernel fault. This does not negate the missing lifetime guard, but it means no dynamic UAF is claimed. Race host-log SHA-256: `605a284973e62dfe0acb9ce8e5ff58af371313bec942ed98f1eee52d2474feb4`.
- **Impact boundary:** this is a local kernel memory-safety and denial-of-service surface and a conditional post-execution escalation candidate. The VM modeled the recovered DAC rule but does not prove access from every production SMACK domain. No controlled object reuse, arbitrary read/write, instruction-pointer control, or root path is demonstrated; installed-device firmware remains unknown.
- **Tooling:** `tools/uk_fw/alsa_seq_probe.py` builds, hash-verifies, transfers, and runs the single-create/delete diagnostic in the offline snapshot-backed VM. Source: `tools/uk_fw/guest/alsa_seq_reachability.S`; tests: `tests/test_alsa_seq_probe.py`.
- **Remediation:** backport upstream `71105998845fb012937332fe2e806d443c09e026`; remove or restrict the static sequencer node if untrusted applications do not require it; apply least-privilege DAC and SMACK policy.
- **Evidence:** `evidence/alsa-sequencer-cve-2017-15265.md`.

## V-014 — systemd/udev hardware-property injection reaches an installed root-shell unit (EXACT PRE-FIX CODE; SYNTHETIC BENIGN ACTIVATION CONFIRMED; PHYSICAL PATH UNTESTED)

- **Status:** exact CVE-2026-40225 pre-fix instructions and the installed rule/service chain are present in recovered EU `260128`. Fixed benign offline diagnostics confirmed both leading-space second-property retention and a matched synthetic `systemd-udevd` → PID 1 systemd activation: the positive run started only an otherwise-unreferenced transient marker unit, while the negative run did not. This remains the strongest static malicious-device-to-conditional-root-console path; physical hardware, shipped vulnerable helper execution, the installed shell unit, and the owner's unknown build remain untested.
- **Components:** `systemd-udevd` SHA-256 `f32f6296ea20d959ac046ae80724f39e317aaaf492a5c7eedd9270b5b2abab0d`; `v4l_id` `afb756b457284578c29960d4abd57f9612020fb45a14fbc285f5061da90a7125`; `scsi_id` `85aa83a73d44f19f6b60162a53ee896854b71e7882848819aad20c1ccf079b32`. Version evidence is mixed: the compiled PID 1 banner/pkg-config report `225`, while embedded OpenEmbedded source/recipe paths say `systemd/1_249.3-r0`. Neither banner is the vulnerability premise; exact instructions are.
- **Exact pre-fix code:** after `VIDIOC_QUERYCAP`, shipped `v4l_id` passes `v2cap.card` directly to `ID_V4L_PRODUCT=%s` at `0x14e5..0x14f8`. Shipped `scsi_id` passes `unit_serial_number` directly to `ID_SCSI_SERIAL=%s` at `0x273c..0x275b`. Neither path calls the UTF-8/control-character checks introduced by fixes `16325b35fa6ecb25f66534a562583ce3b96d52f3` and `54f880b02ecf7362e630ffc885d1466df6ee6820`.
- **Installed chain:** `60-persistent-v4l.rules` imports `v4l_id`; `50-udev-default.rules` executes nonempty `REMOVE_CMD` on removal. `60-persistent-storage.rules` imports `scsi_id` for `sd*`/`sr*`; `99-systemd.rules` tags block devices for systemd. The image ships `debug-shell.service`, with no `User=`, configured to run `/bin/sh` on `/dev/tty9` only when `ConditionPathExists=/dev/tty9` passes. Its preset disables default enablement but not an explicit unit request. The recovered kernel has `CONFIG_VT=y`, `CONFIG_VT_CONSOLE=y`, `CONFIG_USB_HID=m`, and `CONFIG_HID_GENERIC=m`.
- **Strongest path:** the upstream advisory states that a malicious SCSI serial can introduce `SYSTEMD_WANTS`. In this image that property can name the already-installed `debug-shell.service`; no attacker-written service file is required. The parser control retained the fixed benign second property. A second matched control used exact udevd and PID 1 systemd: only the positive synthetic property started the transient BusyBox marker unit, and the negative run kept it inactive. A separate control confirmed `/dev/tty9` exists as `root:root` mode `0600`, character device `4:9`. Hardware bytes reaching shipped `scsi_id`, a request for the installed shell unit, production-node existence, virtual-terminal selection, visible output, and keyboard interaction remain untested.
- **Relation to V-006:** V-006 remains blocked. Its `usb_id` `ID_SERIAL_SHORT` allowlist is not used here. V-014 crosses separate `v4l_id`/`scsi_id` line-oriented property boundaries that exact shipped instructions leave unsanitized.
- **Impact boundary:** a VM-only synthetic add event and benign transient unit request were demonstrated. No malicious USB device, hardware-controlled helper output, physical port, installed shell-unit request, observed root transition, interactive command, persistence, network path, CAN access, or safety impact was demonstrated. The V4L route also depends on choosing a useful existing executable and was not validated dynamically.
- **Remediation:** backport both upstream control-character validation fixes; remove `debug-shell.service` from production rather than merely leaving it disabled; allowlist hardware-originated `SYSTEMD_WANTS`; remove generic `REMOVE_CMD` execution; disable unnecessary V4L/SCSI/USB classes.
- **Evidence:** `evidence/systemd-udev-cve-2026-40225.md`; reviewed excerpts under `evidence/artifacts/udev-candidates/`.

## V-015 — ConnMan DHCPv6 DOMAIN_LIST stack overwrite (EXACT PRE-FIX CODE; CONDITIONAL ON-LINK ROUTE STATICALLY CONFIRMED)

- **Status:** the exact shipped `connmand` contains CVE-2026-115863's affected `get_domains` implementation, exact DHCPv6 option-24 dispatch, and the conditional Router Advertisement Managed/Other path that starts DHCPv6 on a connected managed network. No packet was sent, no dynamic crash occurred, and code execution/root access are not claimed.
- **Component:** `/usr/sbin/connmand`, SHA-256 `d82d4018bfa9d8f8d67407453bd783a3c896f6764f147dcf23cf06b978024c28`; recovered package-index record `connman-1.29+5w.master.38-r1.corei7_64`. The installed unit has no `User=` directive, so it uses the uid-0 system-service default, and has `Restart=on-failure`.
- **Mechanism:** `connmand+0x1f150` calls `strncpy` with fixed length `0x401`, then replaces each DNS-label byte with `'.'` and advances by that byte plus one without comparing the cursor to the option or local-buffer end. The caller beginning at `+0x1f211` tests bit 24 (`0x1000000`) and dispatches DOMAIN_LIST data to this function.
- **Static route:** the exact callback at `+0x574e0` requires a connected network, then routes RA Managed and Other flags to stateful DHCPv6 (`+0x856f0`) or information-request (`+0x855a0`). The latter's routine at `+0x84770` explicitly registers option 24. The service excludes many interfaces but not intended `wlan0`. A reply must still match the live transaction ID, CLIENTID/DUID, SERVERID, message type, and state.
- **Mitigations/impact boundary:** the exact ELF is PIE with a non-executable stack, stack canaries, and full RELRO. Those protections constrain straightforward execution but do not prevent the parser's out-of-bounds accesses. At present, a conditional root-daemon crash is the defensible impact; no stable disclosure/write primitive, instruction-pointer control, shell, persistence, or safety impact was demonstrated. Production Wi-Fi/IPv6 state and the owner's installed build remain unknown.
- **Remediation:** replace the parser with a strictly length-aware DNS-label decoder; reject cursor/label/expanded-name overflow and missing termination; update ConnMan when the upstream fix is available; disable unneeded DHCPv6; reduce daemon privilege; retain restart-rate and crash diagnostics.
- **Evidence:** `evidence/connman-cve-2026-115863.md`; reviewed excerpt `evidence/artifacts/network-candidates/connman-cve-2026-115863-static-evidence.txt`; deterministic RPM dump parser `tools/uk_fw/rpm_nvra_inventory.py`.

## V-016 — ConnMan DHCPv4 total-length underflow (EXACT PRE-FIX ORDER; FORTIFY BLOCKS THE STACK COPY)

- **Status:** the exact shipped `connmand` retains CVE-2023-28488's pre-fix ordering and reaches the affected L2 callback through ordinary IPv4 `INIT_SELECTING`. Exact `_FORTIFY_SOURCE` output changes the reviewed outcome: no oversized stack copy occurs because `__memcpy_chk` reaches `__chk_fail` first. No packet was generated and no dynamic abort occurred.
- **Component:** `/usr/sbin/connmand`, SHA-256 `d82d4018bfa9d8f8d67407453bd783a3c896f6764f147dcf23cf06b978024c28`, with `/lib/libc-2.25.so`, SHA-256 `04946077dfd7554a20438ee581367e3995931b26c9ee516ffeeecdc0ee9f331f`.
- **Mechanism:** the receiver requires the original read to contain 28 IPv4+UDP header bytes, replaces that count with untrusted 16-bit `ip.tot_len`, rejects only totals greater than the read, then computes `size_t(ip.tot_len - 28)`. The exact call supplies a 628-byte destination size to `__memcpy_chk`.
- **Static route:** normal IPv4 startup sets state `INIT_SELECTING`, selects listening mode 1, creates an `AF_PACKET` datagram socket, binds it to the interface/IPv4 protocol, and registers the affected callback. Runtime exposure still requires a ConnMan-managed interface to be acquiring an IPv4 lease and a frame to pass protocol, header, port/length, and checksum checks.
- **Mitigations/impact boundary:** all totals below 28 produce a 64-bit underflow larger than 628. Every exact libc checked-copy implementation reviewed branches to non-returning `__chk_fail`/`__fortify_fail` before copying. Totals 28..656 copy at most 628 bytes, while larger totals are rejected. Conditional unauthenticated daemon termination is statically plausible; a stack overwrite, RCE, root access, persistence, and applicability to the owner's installed build are not established. `Restart=on-failure` limits but does not eliminate availability impact.
- **Remediation:** backport upstream `99e2c16ea1cced34a5dc450d76287a1c3e762138`; retain fortification but do not use a fatal bound check as the parser fix; reduce daemon privilege and rate-limit/review restart failures.
- **Evidence:** `evidence/connman-cve-2023-28488.md`; reviewed excerpt `evidence/artifacts/network-candidates/connman-cve-2023-28488-fortify-evidence.txt`; packet-free arithmetic model `tools/uk_fw/connman_length_model.py`.

## V-017 — oFono SMS TPDU decoder overflows (EXACT PRE-FIX CODE; DIRECTIONAL ROUTES STATICALLY CONFIRMED)

- **Status:** the exact shipped `ofonod` retains missing destination checks for CVE-2023-4232 through CVE-2023-4235, CVE-2023-2794, and CVE-2024-7547. No modem input, target execution, dynamic crash, controlled execution, or root transition occurred.
- **Component:** `/usr/sbin/ofonod`, SHA-256 `3f6daee7c2ccd4b4e222c73d3d22478a997ec336e8a9d65042805625d987ac32`, Build ID `f596c565c77e4abb24d6b5b516ffb2bd6110b1ee`, package `ofono-0.6.8+5w.master.199-r1.corei7_64`. The embedded vendor path identifies `drivers/lgeqmimodem/sms.c`.
- **Exact incoming route and directionality:** QMI calls at `0x4a8d6` and `0x4a9e7` reach `ofono_sms_deliver_notify`; `0xa55ee` calls `sms_decode(..., FALSE, ...)` at `0xae8a0`. Incoming TP-MTI selects deliver, submit-report, or status-report decoding before `0xa55fb..0xa5601` rejects any returned type other than DELIVER. This route therefore reaches CVE-2023-4233/CVE-2023-2794, CVE-2023-4234, and CVE-2023-4232 before the late check.
- **Exact incoming writes:** the address decoder at `0xada70` can write 257 bytes to a 23-byte array; deliver `memcpy` at `0xaddb0` can copy 255 bytes to 140 bytes; status-report `memcpy` at `0xaeb1d` can copy 255 bytes to 143 bytes; submit-report `memcpy` at `0xaec48` can copy 255 bytes to 152-/151-byte ACK/ERROR arrays. Their maxima end 21, 64, 83, and 22 bytes beyond the `0x128`-byte `sms` object, respectively.
- **Outgoing-only writes and callers:** CVE-2023-4235 remains pre-fix at decoder `0xaeea8`, with maxima ending three/four bytes beyond `sms`; CVE-2024-7547 remains pre-fix at `0xaeda0`, with a maximum command copy ending 48 bytes beyond `sms`. They cannot be selected by the incoming QMI call. Exact `outgoing=TRUE` callers exist at `0xb1953` for local transmit-queue deserialization and `0xd8cbb` for SIM-Toolkit Send SMS parsing; the latter checks SUBMIT/COMMAND only after decoding.
- **Mitigations/impact boundary:** the ELF is PIE with NX stack, full RELRO/BIND_NOW, and stack canaries. In the incoming delivery caller, `sms` begins at `rsp+0x30`, later scratch at `rsp+0x160`, and the canary at `rsp+0x1f8`; none of the incoming decoder maxima directly reaches that canary. Outgoing-only caller frames have not yet been reconstructed, so their object-relative overruns must not be projected onto this layout. Exact corruption does not establish instruction-pointer control or RCE.
- **Activation/privilege boundary:** `ofono.service` has no `User=` and would run as uid 0, gated by `/tmp/telematics_code_TELEMATICS`; `ofono.path` additionally watches `/tmp/no_isa`. No recovered enable link for `ofono.path` was identified. `smack-relabel-ro.sh` assigns `App::tms`. Owner-vehicle activation, installed hashes, modem/QMI state, byte preservation, malicious SIM/STK or local queue input, direct radio reachability of outgoing decoders, and unrestricted root remain unknown.
- **Remediation:** backport `1a5fbefa59465bec80425add562bdb1d36ec8e23`, `a90421d8e45d63b304dc010baba24633e7869682`, `5209fd65ff41653d7725e407ccc359c54bb3121f`, `2ff2da7ac374a790f8b2a0216bcb4e3126498225`, `8d74bc66146ea78620d140640a0a57af86fc8936`, `02aa0f9bad3d9e47a152fc045d0f51874d901d7e`, and `305df050d02aea8532f7625d6642685aa530f9b0`; isolate modem-controlled parsing from uid 0; narrow `App::tms`; add sanitizer-backed boundary tests.
- **Evidence:** `evidence/ofono-sms-decoder-cves.md`; reviewed excerpt `evidence/artifacts/network-candidates/ofono-sms-decoder-evidence.txt`; message-free model `tools/uk_fw/ofono_sms_bounds_model.py`.

## V-018 — oFono QMI WMS message-list bounds (EXACT PRE-FIX CODE; MODEM TRUST BOUNDARY)

- **Status:** the exact vendor QMI callback retains CVE-2024-7537's missing equality check between returned TLV length and `4 + count*5`. It supplies a 16-bit length-output pointer to the accessor but never reads that output afterward. No QMI message, modem input, target execution, dynamic crash, or root transition occurred.
- **Exact mechanism:** around `0x48d61..0x48d6c`, the callback computes `count*5` modulo `2^32`. A small product allocates `4 + product` at `0x48d78..0x48d7c`; the overflow diagnostic at `0x48e40` falls through to the same call with a four-byte allocation rather than rejecting. The original 32-bit count controls the loop at `0x48da0..0x48db6`. Every count above 13,107—4,294,954,188 values—under-allocates; short lengths overread the selected TLV and can proceed beyond the backing QMI result.
- **Boundary:** this is a modem-supplied QMI WMS result, not ordinary incoming TPDU decoding. A defective or compromised modem is the established precondition; direct SMS/base-station control is unproven. The conditional process is uid 0 under `App::tms`, not demonstrated unrestricted root.
- **Remediation:** backport `e6d8d526d5077c0b6ab459efeb6b882c28e0fdeb`; use checked `size_t` multiplication/addition; reject short or mismatched TLVs before allocation or iteration; cap count; test with mocked QMI results under sanitizers.
- **Evidence:** `evidence/ofono-qmi-message-list-cve-2024-7537.md`; reviewed excerpt `evidence/artifacts/network-candidates/ofono-qmi-list-evidence.txt`; message-free model `tools/uk_fw/ofono_qmi_list_bounds_model.py`.

## V-019 — Broadcom BSA BNEP control-packet bounds (EXACT PRE-FIX CODE IN BOTH PCB VARIANTS; RADIO ROUTE CONDITIONAL)

- **Status:** both PCB-selectable `vbtd` binaries retain CVE-2017-0782's pre-fix `bnep_process_control_packet()` field reads. The Bluetooth service is enabled and BNEP/PAN code is linked, but no adapter, radio, packet, pairing, connection, crash, disclosure, or controlled execution was used.
- **Components:** `vbtd-51`, SHA-256 `55e21d077082e97f56fb113a1d3b216c0f2e63aa02fc4cd754a6593bc6cec9e0`, Build ID `12175aa88ccff70cc56498e0208c9a51aac0c9e9`, `BSA0107_00.51.00`; `vbtd-63`, SHA-256 `c56b68fdd35b16b95688ab54a48ffb9f18034d925c057e86f8b9fe304f8b26b9`, Build ID `04141ed222ee8f150c0eb0e46fdb73624d168920`, `BSA0107_00.63.00`. PCB 11/12 selects `vbtd-63`; other values select `vbtd-51`.
- **Exact mechanism:** in `vbtd-51`, the exported parser at `0x8c5020` reads the extended packet's first and second bytes at `0x8c5056` and `0x8c5062` after subtracting lengths but before its first wrap comparison at `0x8c507c`; the non-extended path also reaches `0x8c5062` without a one-byte bound. Later field reads at `0x8c5130`/`0x8c5139` retain the same pre-fix structure. `vbtd-63` matches at parser `0x8c7480`, reads `0x8c74b6`/`0x8c74c2`, first compares only at `0x8c74dc`, and retains later reads at `0x8c7590`/`0x8c7599`. These are the missing pre-read checks added by upstream `1b08775917413f1674882130a948add1ae44cc91`, with related bulletin fixes `4e47f3db62bab524946c46efe04ed6a2b896b150` and `c568fa9088ded964e0ac99db236e612de5d82177`.
- **Activation/privilege boundary:** `vbtd.service` is enabled by `multi-user.target`, has no `User=`/`Group=`, and restarts always; it has a configured uid-0 default, while recovered relabel policy intends `App::bluetooth` if it starts. Mandatory `/tmp/session_appmgr.env` is a runtime gate. Setup chooses a PCB-specific controller patchram and binary, then the service uses `/dev/ttyS0`.
- **Reachability boundary:** both engineering profile files say `PAN : N/A`; startup calls `BNEP_Init`, but bounded reference review found no direct call to exported `BNEP_Register`. This does not exclude indirect/runtime registration, but V-019 is dormant pending BNEP PSM/profile evidence. A live route would additionally require an ACL link and accepted L2CAP BNEP/PAN channel. Adapter state, pairing/bonding, authorization, controller preservation, selected PCB, installed owner hash, and restart behavior are unknown.
- **Impact boundary:** reads beyond the parser's declared packet/remaining-length boundary and 16-bit underflow are established. They may remain within backing GKI allocation slack. The Android bulletin's generic critical-RCE classification is not reproduced here. No allocation-bound OOB read, process crash, disclosure contents, overwrite, instruction-pointer control, shell, SMACK escape, unrestricted root, persistence, CAN access, or safety impact is demonstrated.
- **Remediation:** apply all three bulletin-linked CVE-2017-0782 fixes to both BSA variants; exact evidence directly proves the missing field-by-field parser checks, not independent absence of every mechanism in the other two commits. Disable unused PAN/BNEP, require authenticated/authorized channels, reduce privilege/narrow `App::bluetooth`, and regression-test both branches with sanitizer-backed boundary fixtures.
- **Evidence:** `evidence/broadcom-bsa-bluetooth-cves.md`; reviewed excerpt `evidence/artifacts/network-candidates/vbtd-cve-2017-0782-bnep-evidence.txt`.

## V-020 — BusyBox CVE-2015-9261 before USB-update member authentication (EXACT PRE-FIX CODE; STATIC USB PATH CONFIRMED; PHYSICAL ROUTE CONDITIONAL)

- **Status:** exact affected method-8 code and AppScomoDM's pre-authentication USB extraction order are present in recovered EU `260128`. No ZIP/DEFLATE stream, update package, target execution, crash, memory write, code execution, root transition, or signature bypass was produced.
- **Components/provenance:** stock `/bin/busybox`, SHA-256 `95bab633630fb158344497af52dc112e9e777458b810860068d4daa257bd9ebc`, two GNU Build ID notes `42e0a4c7631667cf9106ca36a4f2e7886f6f72b0` and `dc25533aa5ad984ec9a7ed388925f24d328c1836`, banner `BusyBox v1.23.2`; `/app/bin/AppScomoDM`, SHA-256 `c44da21eb39987e88d71c648f625338722b8458f0ff8ecfe29e3321cf6d62046`, Build ID `496a47fae4cca227723b1f4037be918cae18473c`. The current `extracted-safe/.../bin/busybox` is a VM-injected 1.35.0 helper, not stock; canonical stock bytes come from the independent original extraction. Original `/usr/bin/unzip` points to `/bin/busybox`.
- **Pre-authentication route:** `AppScomoDM::launchAppUpgrade` examines one first iterator result matching `S5W_SYSTEM_*_*_*.zip` and executes `unzip -o <archive> -d /update/usb/temp AppUpgrade .lge.upgrade.xml` at `0xbfaf2`. Only afterward does it call public-key-backed verifier wrapper `0x28580` for both extracted files at `0xbfe82` and `0xbfebc`; both results must be zero. Thus DEFLATE parsing precedes member authentication. A separate FOTA route uses `/usr/bin/unzip64` and is not assigned this finding.
- **Exact method route:** stock `unzip` at `0x45da8..0x45dbe` accepts only methods 0 and 8 and explicitly rejects method 12. Method 8 reaches `inflate_block` and dynamic `huft_build` calls at `0x47f01`, `0x48052`, and `0x48097`.
- **Exact CVE mechanism:** `huft_build` initializes only the nonzero-code-length prefix of stack-local `v[]`, but exact code computes/stores `v+n` at `0x475d1..0x475e0`, compares the cursor against that bound at `0x4788a`, and can read an uninitialized slot at `0x47938`. An indeterminate value at least `s` reaches indexed extra/base table reads at `0x47970`/`0x47974`. Initial fix `1de25a6e87e0e627aa34298105a3d17c60a1f44e` introduced a `v_end` bound; corrective follow-up `6bd3fff51aa74e2ee2d87887b12182a3b09792ef` replaced it with initialized `UINT_MAX` sentinels after breakage. Neither correction is present.
- **Impact boundary:** the strongest supported outcome is a likely `unzip` child segmentation fault and update denial of service. The uninitialized stack value is not claimed attacker-selected. No target crash, memory write, instruction-pointer control, AppScomoDM compromise, RCE, SMACK escape, unrestricted root, persistence, package acceptance, partition write, slot switch, boot-trust effect, or owner applicability is established.
- **Privilege/runtime boundary:** `ApplicationLauncher.service` has no `User=` and starts AppLauncher in the uid-0 system-service context; relabel policy intends AppScomoDM `App::upgrade`. Runtime uid/label, selected `-un` route, effective `PATH`, and physical discovery remain unobserved.
- **Hardening:** stock BusyBox is PIE/`ET_DYN`, has NX stack, full RELRO/BIND_NOW, fortified imports, and a canary in `huft_build`. The initial flaw is an uninitialized read within the frame and later direct indexed reads, so these mitigations do not prevent a child crash.
- **Tooling:** `tools/uk_fw/busybox_huft_bounds_model.py` compares recovered `p<n` with a conceptual populated prefix and the stable follow-up's initialized-sentinel behavior using numeric states only; it does not model the short-lived `v_end` implementation and emits no archive, compressed stream, packet, command, or payload. Tests: `tests/test_busybox_huft_bounds_model.py`.
- **Remediation:** backport both `1de25a6e87e0e627aa34298105a3d17c60a1f44e` and corrective follow-up `6bd3fff51aa74e2ee2d87887b12182a3b09792ef`, or use a maintained inflater; authenticate member digests before decompression; isolate extraction as non-root; invoke an absolute maintained extractor and check its complete exit status; use fresh transactional outputs; retain malformed regression fixtures only in a controlled sanitizer/vendor environment.
- **Evidence:** `evidence/busybox-unzip-cve-2015-9261.md`; reviewed excerpt `evidence/artifacts/update-candidates/busybox-unzip-cve-2015-9261-evidence.txt`.

## V-012 — Production compositor shipped unstripped with full DWARF (HARDENING, informational)

- **Status:** confirmed by inspection; informational hardening, not a vulnerability in itself.
- **Where:** `usr/bin/weston` in `NE_E.EUR.S5W_L.001.001.260128`, 1,052,408 bytes.
- **Scope:** confirmed on `usr/bin/weston` and also present in `usr/lib/weston/ias-shell.so` and
  `usr/lib/weston/ias_plugin_framework.so` (7 debug sections each), i.e. the components that decide what the
  vehicle display shows.
- **What:** the binary retains `.debug_info` (360,666 bytes), `.debug_loc` (286,264), `.debug_abbrev`,
  `.debug_str`, `.debug_aranges`, `.debug_ranges`, plus `.symtab` and `.strtab`. Full type definitions,
  struct member names and source line information are present in a production infotainment image.
- **Why it matters to a defender:** this is not exploitable on its own, but it removes most of the cost of
  reconstructing internal interfaces. In this project it enabled an exact, member-by-member ABI
  reconstruction that identified a 24-byte layout difference from upstream Weston, which was the cause of
  a compositor crash. An adversary attacking the compositor, its IPC, or any module loaded into it gets
  the same advantage for free, including struct layouts, function names and line tables for the
  highest-privileged graphical component in the vehicle.
- **Impact boundary:** information disclosure to anyone holding the firmware. No remote reachability is
  implied, and the firmware is already distributed to every vehicle.
- **Remediation:** strip debug information from shipped binaries, or ship it separately under a symbol
  server with access control. Verify the release build does not carry `-g` into the image, and audit other
  binaries in the image for the same condition.

## Rejected / out-of-scope items

- **Keystore ioctl tail disclosure:** rejected; decoded ioctl size is `0x120`, covering fields read (correction C8).
- **`keystore_get_ksm_key` stack disclosure:** rejected by instruction-level review; private/public sub-buffers were misread (C9).
- Android/Telechips `hmg_nemesis` and `micomd` findings are not findings against this Linux/x86-64 target.
- Historical published CVEs require exact-component/version and code-path validation; do not relabel them as newly found or confirmed on `260128`.
- wpa_supplicant CVE-2015-1863 and CVE-2021-27803 are rejected for the exact recovered `260128` binary. `p2p_add_device()` gates every SSID copy on length at most 32, and `p2p_process_prov_disc_req()` unconditionally re-fetches the peer after `p2p_add_device()`. P2P capability and conditional launch machinery remain present, but do not reverse these exact fixed-code conclusions. See `evidence/wpa-supplicant-p2p-cves.md`.
- Bluetooth CVE-2017-13262's named missing extension-length decrement is present in neither selectable BSA binary; both exact receive loops decrement before extension parsing. CVE-2018-9355's AOSP 512-byte local UUID-list shape is not present in the reviewed target function. CVE-2019-2025 is a local Binder-kernel flaw, not Bluetooth. CVE-2020-0022 names Android's absent `packet_fragmenter.cc` architecture. CVE-2017-0781/0783/0785 and CVE-2018-9588 remain unaccepted pending exact BSA fix comparison. These constraints do not alter V-019's separately proven CVE-2017-0782 BNEP parser defect. See `evidence/broadcom-bsa-bluetooth-cves.md`.
- ALSA PCM CVE-2017-0861 is rejected by the exact shipped open-mutex backport. ALSA sequencer CVE-2018-1000004 lacks the official per-client ioctl serialization, but its published sequence requires `write()` and recovered intended `/dev/snd/seq` mode `root:root 0644` grants ordinary users no write permission. See `evidence/vendor-kernel-alsa-follow-up-cves.md`.
- CVE-2017-11176 is rejected by exact shipped `sys_mq_notify` control flow despite `CONFIG_POSIX_MQUEUE=y`. `netlink_attachskb` drops the old socket reference before returning one, but both failed retry lookup paths bypass `netlink_detachskb` and enter skb-only cleanup. The compiler emits no explicit socket-register clear on the loop edge; branch routing provides the source fix's semantic effect. See `evidence/vendor-kernel-mq-notify-backport.md`.
- VM rendering slowness, watchdog timeouts and missing simulated CAN data are currently compatibility/integration issues, not established exploitable security defects.

## Maintenance

For each new issue record: stable ID, affected artifact/build and digest, source location, evidence type, caller/reachability, preconditions, bounded impact, remediation owner/status, regression test and remaining unknowns. Keep secrets and private keys out of reports. Append discovery/validation/correction events to `Ioniq5-HISTORY.md`; edit this register to reflect current conclusions. Preserve rejected findings to avoid rediscovery.
