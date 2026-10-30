# IONIQ 5 infotainment vulnerability and remediation register

Updated: 2026-10-28. Internal defensive research; no disclosure or vendor contact is implied.

## Scope and evidence rules

Target: official European Gen5W **Linux** `NE_E.EUR.S5W_L.001.001.260128`, vendor kernel `4.1.27-abl`. The owner's installed head-unit build is unknown. No physical or network head-unit access is available. VM observations do not establish hardware exploitability.

This is a backfill from existing research, **not a new vulnerability discovery pass**. Entries distinguish verified behavior, static observations, unvalidated candidates, rejected hypotheses, and modification-created hazards. No numeric severity is assigned without reachability and impact evidence. Never infer missing security fixes from the kernel version alone. See `evidence/corrections-log.md` before relying on historical reports.

**Validation status of the 2026-10-28 advisor report.** The three claims supplied as a third-party summary were tested offline against the recovered rootfs on 2026-10-28. None was accepted as stated:

- **V-006 was upgraded to a confirmed command-injection vulnerability** (static proof, CWE-78) — but through `/app/bin/usb-automount`'s MTP branch, not a "mount script". The reported literal payload would in fact **fail**, because spaces are neutralised to `_` by `util_replace_whitespace`; parameter expansion is needed instead.
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

## V-006 — Root command injection via USB device serial string (CONFIRMED, static)

- **Status:** **confirmed vulnerability, static proof only** — CWE-78 OS command injection. Runtime exploitation on a running unit has **not** been demonstrated. Triaged 2026-10-28.
- **Severity framing:** defects are not scored numerically here. Reachability requires physical USB access; the payoff is root code execution inside the head unit.
- **Affected component:** `/app/bin/usb-automount` (43,136-byte stripped x86-64 ELF), started by `lib/systemd/system/usb-automount.service`, which contains **no `User=` directive** and therefore uses the system-service default of uid 0.
- **Evidence:** `work/vm/vendor-userspace-260128/validation-261028/v006/` (report, udev inventory, sanitiser excerpt, disassembly). Independently re-verified with `llvm-objdump`:
  - `0x5326` `__sprintf_chk` builds `"%s %s %s %s &"` (`.rodata 0x7928`) from `"/usr/bin/go-mtpfs"`, `"--dev"`, **`ID_SERIAL_SHORT`**, and `"/media/mtp/<ID_SERIAL_SHORT>"`; `system()` is called at `0x535f`. No quoting or escaping.
  - `0x53b9` `popen()` runs `"cat /proc/mounts | grep %s"` (`.rodata 0x7936`) using the same serial-derived string.
  - `ID_SERIAL_SHORT` is read at `0x4146` via `udev_device_get_property_value` (`.rodata 0x760c`).
  - Branch selection at `0x44c3`–`0x44cf` requires `ID_USB_INTERFACES` to contain `060101` (PTP/Still-Image) or `ffff00` (vendor-specific). Plain mass-storage-only devices take a different branch that uses `mount(2)`/`umount2(2)`/`mkdir(2)` and no shell — so **the claim's "mount script" mechanism is wrong, but the injection is real on the MTP path.**
- **Why the usual udev mitigation does not help:** `systemd-udevd`'s `usb_id` builtin sanitises with `util_replace_whitespace` (`0x22b20`); at `0x22b72` it tests only the `_ISspace` ctype bit (mask `0x2000`). Only whitespace is rewritten to `_`. Shell metacharacters (`; $ ( ) \` | & ' " < > * ? # ! { } /`) pass through unchanged.
- **Encoding constraints on the attacker string:** the serial filter at `0x1c2df` accepts bytes `0x20`–`0x7f` and rejects `0x2c` (comma). Literal spaces are therefore neutralised to `_`, and comma-list brace expansion is unavailable; parameter expansion such as `${IFS}` needs neither, so the filter is not a mitigation.
- **Aggravating detail:** `/tmp` is mounted as tmpfs read-write by `lib/systemd/esinit:10` with default options, so it is executable and suid-capable. `/usr/bin/go-mtpfs` is **absent** from the image, but the shell parses and expands the entire command line before attempting execution, so a missing helper does not prevent an injected command from running.
- **Preconditions:** physical access to a USB port; a device that advertises a PTP (`06/01/01`) or vendor-specific (`ff/ff/00`) interface; a chosen `iSerialNumber`; and the `usb-automount` service starting with effective uid 0 (configured, but not observed at runtime).
- **Impact boundary:** if execution retains uid 0, an attacker can manipulate infotainment processes and accessible data, and disrupt media/navigation/UI. This does **not** establish vehicle-bus access or transmit permission, control of braking/steering or other safety systems, access to hardware-protected keys or ECU key material, or persistence across reboot or firmware update. UID 0 is not automatically unrestricted under SMACK.
- **Remediation:** remove both `system()` and `popen()`. Launch an absolute path with `execve()`/`posix_spawn()` and a fixed argument vector plus controlled environment. Read `/proc/mounts` directly and compare decoded fields instead of shelling out to `grep`. Derive mount-directory names independently of the raw serial; constrain paths beneath an owned directory and prevent traversal and symlink races. Treat serial validation as defence in depth, never as a substitute for removing the shell. Disable the MTP branch cleanly when the helper is absent. Move descriptor handling and helper execution out of root, retaining only narrowly scoped privileged mount operations.
- **Acceptance / regression:** shell metacharacters, separators, `${IFS}`-style expansion, over-long serials, comma and non-ASCII serials, and a missing helper must all produce no shell interpretation; legitimate PTP and mass-storage mount and unmount must still work; no privileged child of the automounter should exist.
- **Not yet done:** isolated-VM dynamic confirmation (see below). Do not describe this as "USB-to-root demonstrated".

**Reproduction harness status (2026-10-29).** The emulated-device half of the harness now works: a
QEMU USB device presenting `0403:6001` with an arbitrary serial string enumerates on UHCI with that
string read back verbatim, so the attacker-controlled input to this vulnerability is reproducible in
the VM. Two blockers remain before an end-to-end demonstration: the image carries no `ftdi_sio`-family
driver, and `usb-automount` refuses to run without a system D-Bus, exiting on a `QDBusConnection`
assertion. Neither affects the static confirmation above. A plain serial adapter is the wrong device
class for this entry in any case; the MTP branch requires an MTP device. Evidence: runs
`1793332245651259000` and `1793332361615248000`.

## V-007 — Media parsing runs as an unprivileged-separation gap (CONFIRMED configuration, not a demonstrated exploit)

- **Status:** **confirmed configuration, informational.** Not a vulnerability on its own: no parser defect has been identified, and root execution of a parser is a risk amplifier rather than an exploitable condition. Triaged 2026-10-28; reclassified from "unverified actor report" and from the earlier "SUPPORTED vulnerability" framing.
- **Evidence:** `work/vm/vendor-userspace-260128/validation-261028/v007/` (report, component table, evidence excerpts).
- **Observation:** none of the media service units specify `User=` (the only templated unit in the image is `user@.service`). `lightmediascannerd`, `thumbnail_extractor`, `mediamanager`, `playerengine` (GStreamer 1.8.3 with 160 plugins plus libav) and `MediaBrowser` (libmediainfo) are therefore configured for uid 0. No `CapabilityBoundingSet=`, `NoNewPrivileges=` or `SystemCallFilter=` is present, no `libseccomp` exists in the image, and the image contains **zero setuid binaries**. The only confinement is SMACK labelling (`App::mediaplayer`, `App::usbautomount`), which does not change uid.
- **What is not established:** observed runtime uid; any reachable memory-safety defect in any parser; that missing unit directives prove the absence of inherited or directly-installed seccomp filtering; and consequently any media-triggered code execution.
- **Remediation:** run scanners, thumbnail workers, players and their D-Bus activation paths under dedicated non-root accounts; put privileged device and mount management behind a narrow broker; restrict filesystem writes and network access; tighten SMACK rules; apply the hardening this systemd-225 build actually supports; backport parser fixes and fuzz hostile media.
- **Acceptance:** media components run under distinct non-root identities; a parser crash cannot reach privileged state; legitimate playback, indexing and thumbnail generation still work.

## V-008 — Conditional root serial console, password-gated (shipped configuration, not an auth bypass)

- **Status:** **shipped configuration confirmed; status as a vulnerability unresolved.** A password-authenticated root console is normal engineering practice. It is **not** an authentication bypass, and no defective hashing was found. Triaged 2026-10-28.
- **Evidence:** `work/vm/vendor-userspace-260128/validation-261028/v008/` (report plus machine-readable summary with per-file digests).
- **Observation:** `etc/esinit_agetty.sh:6` starts `agetty -8 -L ttyS2 115200 xterm`; the autologin alternative on line 5 is commented out. `etc/securetty` permits `ttyS2`, and `etc/passwd.legacy` gives root `/bin/sh`. `etc/shadow.Global` holds a `$6$` SHA-512-crypt verifier with a unique 10-character salt, no explicit rounds parameter, and no locked marker; the other 18 accounts are locked with `*` or `!`. `lib/systemd/esinit` creates `/tmp/secure_console_disable` and then launches the getty when that file exists, which is fail-open ordering; the MICOM parameter `secure_console=1` would suppress it by removing `/dev/ttyS2`.
- **Latent trust material:** `etc/dropbear/authorized_keys` ships one static `ssh-rsa` key, but Dropbear is not installed and its unit is inert with no socket and no binary. This is dormant configuration, not a backdoor: a public key is not a private key and no reachable SSH service exists.
- **What is not established:** that `esinit` executes on a production unit (no unit, generator or init script in the rootfs references it; `sbin/init` is systemd, so an external trigger such as a bootloader `init=` would be required); that `passwd.legacy`/`shadow.Global` are the active databases; that production units ship the console enabled; that the UART is physically exposed; and anything about password strength or per-unit uniqueness.
- **Remediation:** identify the real production boot caller and the active account database first. Disable the serial getty by default in production. Replace the inverted temporary-file gate with an explicit authenticated service-mode decision that defaults to disabled on error or missing state, and do not rely solely on deleting a device node. Remove `ttyS2` root-login permission and lock direct root login where unnecessary, using controlled and auditable maintenance access instead. Remove unused authorized-key material and ensure future SSH enablement cannot silently trust it.
- **Acceptance:** no root login on a production serial line; maintenance access remains auditable; enabling the console requires an explicit authenticated decision that cannot be reached by creating a file; no dormant key material ships.

## Rejected / out-of-scope items

- **Keystore ioctl tail disclosure:** rejected; decoded ioctl size is `0x120`, covering fields read (correction C8).
- **`keystore_get_ksm_key` stack disclosure:** rejected by instruction-level review; private/public sub-buffers were misread (C9).
- Android/Telechips `hmg_nemesis` and `micomd` findings are not findings against this Linux/x86-64 target.
- Historical published CVEs require exact-component/version and code-path validation; do not relabel them as newly found or confirmed on `260128`.
- VM rendering slowness, watchdog timeouts and missing simulated CAN data are currently compatibility/integration issues, not established exploitable security defects.

## Maintenance

For each new issue record: stable ID, affected artifact/build and digest, source location, evidence type, caller/reachability, preconditions, bounded impact, remediation owner/status, regression test and remaining unknowns. Keep secrets and private keys out of reports. Append discovery/validation/correction events to `Ioniq5-HISTORY.md`; edit this register to reflect current conclusions. Preserve rejected findings to avoid rediscovery.
