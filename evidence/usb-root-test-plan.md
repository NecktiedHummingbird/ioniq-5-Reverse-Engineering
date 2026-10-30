# Bench root-path test plan — corrected after V-006 dynamic validation

Date: 2026-11-01
Target family: Gen5W Linux/x86-64
Safety: owner-authorized, disconnected bench unit only; preserve recovery access

## Executive result

The former primary vector—command injection through an MTP device's USB serial—is
**not viable in recovered EU build `260128` through `ID_SERIAL_SHORT`**. This file
supersedes the older `${IFS}` payload guidance.

The authentic root automounter does construct shell commands unsafely, but udev's
`usb_id` builtin reduces the property to:

```text
[A-Za-z0-9#+\-.:=@_]
```

All tested command separators, substitutions, whitespace, quotes, redirects,
globs, braces, parentheses and slashes become `_`. No tested surviving sequence
can create a shell word, substitution, redirection or second command.

Do **not** attempt the old payload on a vehicle. It is disproved for this userspace,
adds no useful evidence, and risks media-service disruption.

## V-006 evidence

### Static sink

`/app/bin/usb-automount` runs without a `User=` override and contains:

```text
0x535f  system("/usr/bin/go-mtpfs --dev %s /media/mtp/%s &")
0x53b9  popen("cat /proc/mounts | grep %s", "r")
```

Both `%s` values derive from `ID_SERIAL_SHORT`. The branch requires PTP/MTP
`ID_USB_INTERFACES=:060101:` or vendor-specific `ffff00`; mass storage follows
direct `mount(2)` logic instead.

### Corrected udev path

The original analysis stopped after `util_replace_whitespace()` and incorrectly
assumed shell punctuation survived. `builtin_usb_id` actually calls:

1. `0x22b20` at `0x1c334` — whitespace normalization;
2. `0x22a00` at `0x1c33e`, `rsi = NULL` — character replacement using the
   predicate at `0x29d80`.

That predicate accepts letters, digits, and the built-in set at `0x537c9`:

```text
#+-.:=@_
```

There is also a narrow literal `\\x` exception. It cannot synthesize a byte in the
shell: unquoted `\\x` is parsed as escaped `x`.

### Dynamic result

QEMU `usb-mtp` delivered this raw serial to sysfs:

```text
a;id>/tmp/v006.id;echo${IFS}V006KMSG>/dev/kmsg;#
```

The udev property consumed by the authentic automounter was:

```text
a_id__tmp_v006.id_echo__IFS_V006KMSG__dev_kmsg_#
```

The root service reached the MTP `system()` call (proven by the missing
`/usr/bin/go-mtpfs` shell error), stayed alive, and created no marker. A printable
matrix confirmed:

- replaced: `; | & $ ( ) { } < > * ? [ ] ! ~ ^ % ' " / \\` and whitespace;
- retained: `# = @ : + - . _` plus alphanumerics.

Primary logs:

| Evidence | SHA-256 |
|---|---|
| `v006-exploit-host.log` | `568f3197ff178cbf8356674c74a149b66ec1bfd96eedd5f2098a830c84adb27a` |
| `v006-sanitizer-matrix-host.log` | `de0757442ca4a74d3a3f87db79e8c3eb2b16b101dc47131d266af71ac734b0a1` |
| `v006-discover-host.log` | `121f966b7c228425e5cfaec1f6e82a6ceef8a9bcebe28bf8f17f5e4cf6e2aef9` |

### Residual test, not an exploitation plan

A leading `#` can comment out the helper command, so descriptor-triggered command
disruption remains plausible. Option-like values may also perturb `go-mtpfs` on a
build where it exists. These are denial-of-service/robustness checks, not root
access.

On a disposable bench image only:

1. confirm the installed udev/automounter hashes before inferring parity;
2. observe the `ID_SERIAL_SHORT` property rather than the raw sysfs serial;
3. use inert values and monitor whether the helper is skipped or restarted;
4. verify legitimate MTP/mass-storage operation afterward; and
5. stop if the media stack restart-loops.

No alternate USB-descriptor property was found flowing into the two shell sinks.
A local privileged udev rule could overwrite the property, but that assumes the
privilege V-006 was meant to obtain.

## Separate udev helper path: V-014 / CVE-2026-40225

V-006's rejection is narrow. Exact shipped `v4l_id` and `scsi_id` instructions
contain CVE-2026-40225's separate pre-fix line-oriented property prints. Installed
rules import their output, block devices are tagged for systemd, and the image
ships `debug-shell.service`, configured to run `/bin/sh` as root on `/dev/tty9`
if that device exists. The upstream SCSI route can inject `SYSTEMD_WANTS` and
therefore request this existing unit.

This remains the strongest static physical-device root path, with downstream
parser and synthetic benign activation substeps dynamically confirmed, but it is
not a bench reproduction.
A fixed benign parser control retained the leading-space second
`SYSTEMD_WANTS` line. A matched synthetic-add control then used exact udevd and
PID 1 systemd: only the positive property started an otherwise-unreferenced
transient marker unit; the negative run did not. Vulnerable helper rules were
masked and no pre-existing property-selected unit was requested. Another control found `/dev/tty9` as
character device `4:9`; it did not start the shell service or test interactivity.
Do not test the path by starting the root-shell unit. If a future
disconnected bench validation is authorized and recovery is proven, use a
benign marker unit and inert property observation to test only whether the
production helper output is split into an additional property. Stop before
shell activation or commands. See
`evidence/systemd-udev-cve-2026-40225.md`.

## Higher-value removable-media validation

For file-only media, the current evidence-based path remains parser reachability,
not V-006 descriptor shell injection.

### ASF stream-count crash (V-012)

The shipped GStreamer ASF plugin is dynamically vulnerable to CVE-2026-2920 in
the isolated VM. A valid WMA/ASF file with 33 Stream Properties Objects reaches a
fixed 32-entry array and crashes authentic `gst-discoverer-1.0` after creating
stream 33.

This establishes memory corruption and denial of service only. Exact static code
also maps an explicit MediaBrowser thumbnail request through
`thumbnail_extractor Start(as) → VideoContext → uridecodebin`, but reviewed scan
callbacks do not issue that request and bounded VM attempts did not deliver it.
This does not establish code execution or automatic physical-unit reachability.

Before any bench test:

1. validate a known-good recovery/update path and preserve the installed build;
2. disconnect the head unit from the vehicle and all networks;
3. use a disposable USB device containing one benign control and one bounded
   crash-only probe generated by `tools/uk_fw/asf_stream_probe.py`;
4. capture service uid, process tree, DLT/journal and restart behavior;
5. test explicit playback separately from automatic indexing/thumbnailing;
6. remove the media immediately if a restart loop or UI wedge occurs; and
7. make no code-execution claim unless instruction-pointer control is separately
   and safely demonstrated.

See `evidence/gstreamer-cve-2026-2920.md`.

## Other bench paths

These remain evidence-gathering paths, not established root exploits:

- V-011 missing `MS_NODEV`: exact Tuxera `tntfs` now materializes a retained
  harmless NTFS character-node representation, and a numeric uid/gid 65534
  process can open it read-only when `nodev` is absent. The `nodev` control
  denies the same open. This validates the hardening effect, not a root path:
  useful major/minor access and production SMACK/path reachability remain open;
- filesystem-parser review must use the exact commercial modules recovered here:
  Tuxera NTFS `3016.7.1.2.3` (`tntfs.ko`, SHA-256
  `da2ae1545125a1679bd37d987f2fcb81fdbca89b69042eb3a97d54a5ef9454be`) and
  Tuxera exFAT `3016.6.23.3` (`texfat.ko`, SHA-256
  `b0f5ea01ead8a6588a0427334ad4de9e1caba4ca55d6a259cccb124d8f49289f`).
  NVD keyword queries for `Tuxera` and `TexFAT` returned no records when checked
  on 1 November 2026. CVEs for
  Linux's separate in-tree exFAT implementation are not evidence that these
  proprietary modules are affected. This is an unknown parser surface to test
  in disposable VM snapshots, not a known-CVE claim;
- password-gated serial console: identify the actual boot caller, active account
  database and physical UART before testing authentication;
- removable-media updater: validate signatures, manifest checks, downgrade rules
  and recovery behavior with inert malformed packages, never a production key or
  unreviewed image;
- media parser hardening: confirm services run under dedicated non-root identities
  after remediation and that malformed files fail without restart loops;
- SMACK boundaries: record labels and policy decisions before treating uid 0 as
  unrestricted.

## Offline Tuxera parser harness

`tools/uk_fw/tuxera_fs_probe.py` now attaches one project-local raw image to the
recovered-kernel VM through QEMU EHCI/USB storage. QEMU opens the image with
`readonly=on`; the fixed guest script accepts only `tntfs` or `texfat`, identifies
exactly one `/dev/sd?` candidate, and mounts it with
`ro,nodev,nosuid,noexec`. The canonical VM root remains snapshot-backed. The
harness refuses external paths, symlinks, rootfs aliases (including hard links),
unsafe QEMU path separators, and images outside its size bounds.

A clean 64 MiB NTFS 3.1 image generated with `mkntfs` also mounted and unmounted
successfully through authentic Tuxera NTFS `3016.7.1.2.3`:

- image SHA-256:
  `220ad1d065856ae49d971c5d014ab527aca36aa1367f9e8709ceb9d446295cde`;
- host log `tuxera-ntfs-clean-probe-host.log`, SHA-256
  `e9d19e192700398c00b2fd083cc39fea726b8170ca0d5eb5e81f2a85ee17d036`;
- result: `clean-mount`, bounded enumeration, clean unmount, and no parser fault.

The separate V-011 semantics run used a copy-on-write disposable copy. The same
Tuxera driver created character node `inert-null` (`1:3`) on that NTFS volume.
After unmount and remount without `nodev`, the inode remained a `root:root`
character device with mode `0755`; root and numeric uid/gid 65534, SMACK label
`_`, could open it read-only. Remounting with `nodev` preserved its metadata but
denied the open with `EACCES`. Only QEMU `/dev/null` was addressed. No eMMC,
block storage, or host device was touched. Evidence:

- initial special-file control host log SHA-256
  `4d68550b5cb8420622e25cdfd35ccb9fee194b48fb16f946090607c3f784a494`;
- numeric-uid/no-`nodev` versus `nodev` host log SHA-256
  `8c41d9025183781ade987cd688d4724d48d6964cb876492004649803eb2403f3`.

This confirms that omission of `MS_NODEV` has a real VFS effect for this Tuxera
NTFS build. It does not identify a useful privileged device, prove a production
application's SMACK access, or establish privilege escalation.

A clean 64 MiB exFAT image generated with exfatprogs 1.4.3 mounted and unmounted
successfully through authentic Tuxera exFAT `3016.6.23.3`:

- image SHA-256:
  `63dc4f133e2fc41183aafbb8ff2163cc9461571f48cbe738b407d202934da934`;
- host log `tuxera-exfat-clean-probe-v2-host.log`, SHA-256
  `f4965c43c5f9446a5586e51c37745d6692144e2650ea2b8ea8460476d0199573`;
- result: `clean-mount`, including `TUXERA_PROBE_MOUNT_OK`, bounded root
  enumeration, `TUXERA_PROBE_UNMOUNT_OK`, and no parser fault marker.

Sixteen bounded malformed exFAT images from the upstream exfatprogs fsck tests
were also exercised read-only. `bad_bitmap_size`, `bad_root`, and `bs_bad_csum`
were cleanly rejected. The other thirteen mounted, completed bounded root
enumeration, and unmounted without a detected kernel fault. These are
compatibility/negative controls for a different exFAT implementation, not proof
that the proprietary module is generally safe and not a claim that Linux
in-tree exFAT CVEs affect it. Retained host-log SHA-256 values:

- `bad_bitmap_size`: `3d78a9783d80f677bb868d886fea58cd45cc09da1b739b88b8197d9d6a84a914`;
- `bad_root`: `32faad69c2288d573b55e404b13025ce41361bcaee0bda732e757a97ddb86cbe`;
- `bad_dentries`: `57f40f47c892fac6e8ee2008a821848a02e96d9156892381bf3ac1d008b84404`;
- `file_invalid_clus`: `e7c40ee0b019c1e9f27118930775e02dd72416e849894e8f3497dc0dd5eebc5d`;
- `invalid_name`: `f3ba47661a7be9b3eced9fed0352ec52c9ef34c8eb746b5f8681050c2c6b73c2`;
- `loop_chain`: `b5b861ea1fa5ac73ba7ced974aaca520095a94947e868c1d6e4285e5791973f1`;
- `bad_bitmap`: `e4fb81250f52aa7d3d83fa25ed7fb06b615d07f967de5cbe95b20752b5b02866`;
- `bad_dentries2`: `d8c99341f7d7ac4612a4ec6f66c59a2cdeeffe003839c2bb1bf5a57690144636`;
- `bad_file_size`: `40b9da2ac856ebc72858e4ab193c522f05f3a4c2400ea173e5064a0d038448db`;
- `bad_first_clu`: `d5affdcf9b9ea13814d9ed830c4b0ebe2c81c3e64b5b8261f0d9e6e5d726dfb7`;
- `bad_num_chain`: `b3c0fb03d1f00df1b5dae91ff114e51d3ded897a52e3a1d4704a377ec96dfc9f`;
- `bs_bad_csum`: `f469fff79f50cd58dae9156c51aeed5426f34d62ae7052a5bc4071168caff3cf`;
- `de_bad_csum`: `e4140d240f8f9637e2e9ba49f60dec87037e71e0df409df608c95b98842a3fbe`;
- `duplicate_clu`: `29a43f703d46f6d7729f741225acc6e379d11365d693873891db14e4f0a4faf9`;
- `duplicated_name`: `7d22efa2c268ae90c7e240ceb822c81a6c6def86a589002dfb8a0db6c00f9e8d`;
- `unused-dentries`: `594401a8a92e8b2898c2b90963b343ebebbe813dfd693def21072cecdca7db7b`.

This establishes a safe baseline for deterministic mutation campaigns. It does
not yet establish a Tuxera parser vulnerability, a physical-unit trigger, or root
execution.

## Stop conditions

Stop immediately on repeated reboot, storage errors, unexpected writes outside
the disposable media, loss of serial recovery, thermal warnings, or any evidence
the disconnected bench setup can interact with vehicle networks.

## Claims that are not permitted from current evidence

- V-006 provides USB-to-root on `260128`.
- V-014 has been dynamically reproduced on a head unit, that hardware bytes
  reached a shipped vulnerable helper, that the installed shell unit started, or
  that VT9 is physically accessible. Current dynamic evidence covers parser
  retention, synthetic benign udevd/systemd activation, and the VM tty condition.
- `${IFS}` or shell separators survive `ID_SERIAL_SHORT`.
- The V-012 ASF crash is arbitrary code execution.
- VM behavior proves the owner's installed build or physical hardware behavior.
- Root in one SMACK domain implies unrestricted CAN, ECU-key or safety-system
  access.
- V-011 is a first-step USB-to-root path merely because Tuxera NTFS preserves
  special nodes; a local opener and useful permitted device operation are still
  required.
