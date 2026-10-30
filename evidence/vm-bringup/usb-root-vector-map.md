# USB attack surface → root: consumer map and ranked vectors (EU 260128, static only)

Date: 2026-11-01. Target: `work/decrypted-eu-260128/extracted-safe/mango-rootfs` (build `NE_E.EUR.S5W_L.001.001.260128`).
Mode: **static analysis only.** No VM boot, no QEMU, no execution of target binaries. Rootfs read read-only.

> **2026-11-01 dynamic supersession of the ranking below:** absence of
> `MS_NODEV` is verified and exact Tuxera NTFS `3016.7.1.2.3` now preserves a
> character-node representation across remount. A numeric uid/gid 65534 process
> opened harmless QEMU `/dev/null` read-only when `nodev` was absent; the
> `nodev` control denied it. This confirms a post-execution device-policy bypass
> primitive, but not the original first-step USB-root claim: a production local
> opener, useful device, access mode and SMACK/path permission remain required.
> See `evidence/corrections-log.md` C17/C21 and the current vulnerability
> register. The body below remains the original static analysis.
>
> **2026-11-01 V-014 correction:** the broader statements below that nothing
> sets `REMOVE_CMD` and that `scsi_id` has no security-sensitive consumer are
> superseded. Exact shipped `v4l_id` and `scsi_id` contain CVE-2026-40225's
> pre-fix direct property prints. The former can introduce `REMOVE_CMD`; the
> latter can introduce `SYSTEMD_WANTS`, and block devices are tagged for
> systemd. The image ships `debug-shell.service`, conditional on `/dev/tty9`,
> configured to run `/bin/sh` as root. This is separate from V-006's blocked
> `usb_id` path. See `evidence/systemd-udev-cve-2026-40225.md` and C25.

Tagging: **[V]** = verified by disassembly/byte inspection of the named file at the named offset.
**[I]** = inferred from code structure, standard library/kernel semantics, or one verified fact extended by
reasoning. **[U]** = unresolved / not established. Every claim carries one of these.

Companion evidence already in the tree (not repeated here): `work/vm/vendor-userspace-260128/validation-261028/v006/`
(report, full `usb-automount` disassembly, udev inventory), `evidence/vm-bringup/v006-dynamic-injection-findings.md`,
`evidence/vm-bringup/esinit-bringup-findings.md`. Line references into
`usb-automount.disasm.asm` use its own addresses.

---

## 0. The one thing that is now dead

**The MTP `system()` injection (V-006) is not exploitable on 260128 through the udev property path. Do not
re-litigate it; do not cite it as "USB-to-root".** The static pattern is still a real defect
(`sprintf`→`system()` at `0x5326`/`0x535f`, `popen()` at `0x53b9`, no quoting — [V]), and the branch is
reachable at runtime ([V], `sh: /usr/bin/go-mtpfs: No such file or directory`), but the value that arrives is
reduced to `[A-Za-z0-9#+-.:=@_]`.

Why (new detail beyond the earlier note): the allow-list is **not** a separate mystery sanitiser and it is
**not** `udev_util_encode_string`. `systemd-udevd` contains `util_replace_chars(str, allow)` at `0x22a00`
and its character predicate at `0x29d80`, whose allow string is `"#+-.:=@_"` at `.rodata 0x537c9`; the
replacement byte is `'_'` (`movb $0x5f` at `0x22af0`). `builtin_usb_id` calls it with `allow = NULL`
(`xorl %esi,%esi` at `0x1c243`, `0x1c2ab`, `0x1c339`, `0x1c388`, …), immediately after
`util_replace_whitespace` (`0x22b20`) — [V]. The allow-list table is *shared* with the encoder that appears in
`libudev.so.1.6.4` and `udevadm` (same bytes, escaping semantics `\x%02x` at `.rodata` neighbour), which is why
the earlier grep for that string found it in several binaries and read like a global filter. It is not.

Consequences that must stay in the register:
- the alphabet reaching `udev_device_get_property_value(dev,"ID_SERIAL_SHORT")` cannot express `; | $ ( ) ` `
  `< > & { } / ' " * ? ! ~ \` or a comma [V];
- `ID_SERIAL` is *also* safe, but not because it is re-sanitised: it is composed at `0x1bf32` via `strscpyl`
  (`0x46100`) from the already-sanitised `ID_VENDOR`/`ID_MODEL`/`ID_SERIAL_SHORT` buffers and stored from
  `r15 = [rsp+0x1a0]` at `0x1bfef` — [V];
- the earlier register statement that metacharacters "survive" is withdrawn (already corrected at
  `Ioniq5-VULNERABILITIES.md` §V-006 runtime amendment). Keep the source-level defect, drop the exploit claim.

---

## 1. Every consumer of attacker-controlled USB data

There is exactly **one** removable-media automounter: `/app/bin/usb-automount` (43 136 B, stripped, x86-64),
started by `lib/systemd/system/usb-automount.service`. No `udisks`, `usbmount`, `mdev`, or `.automount` units
exist — [V] (re-confirmed by directory sweep).

### 1.1 `/app/bin/usb-automount` — property reads (the whole list)

Frame is set up at `0x3ef0`; every property comes from `udev_device_get_property_value` unless noted.
Slot = stack offset in the `0x3ef0` frame.

| slot | property | read at | string | sanitised? | what it is used for |
|---|---|---|---|---|---|
| +0x08 | `ACTION` | `0x409b` (`udev_device_get_action`) | – | n/a (kernel) | selects add vs remove (`0x3d00`, `0x3b60`) |
| +0x18 | `DEVTYPE` | `0x40a8` (`udev_device_get_devtype`) | – | n/a (kernel) | `0x39e0`: `"partition"`/`"disk"` → mount branch, else device branch |
| +0x20 | `ID_VENDOR_ID` | `0x40ad` | 0x75c2 | hex | classification only (`"05ac"` = Apple/CarPlay, 0x766f) |
| +0x10 | `ID_USB_INTERFACES` | `0x40c1` | 0x75cf | built from bInterfaceClass/SubClass/Protocol as `:xxyyzz` | `0x3c20`: `strstr("ffff00", 0x756e)` or `strstr("060101", 0x7575)` → MTP branch |
| +0x04 | (port int) | `0x3850` on `udev_device_get_devpath` | – | kernel topology | index into `[port]` of `/etc/usb-automount.conf` (`strstr` classify, `strcmp` at `0x3950`) |
| +0x30 | `DEVNAME` | `0x40f1` (`udev_device_get_devnode`) | – | kernel | `mount(2)` **source** argument |
| +0x38 | `ID_FS_TYPE` | `0x40f6` | 0x75e1 | fixed table in libblkid | `fstype`: `sprintf("t%s")` (0x788c) for ntfs/exfat, literal `"mtp"` otherwise (0x794e/0x7951) |
| +0x58 | `ID_FS_LABEL` | `0x410a` | 0x75ec | **raw filesystem text** (blkid LABEL) | D-Bus `UsbMount` payload + DLT log only — never a path, never a shell (**verified**: not an argument to `mkdir`/`mount`/`sprintf` path builders) |
| +0x48 | `ID_FS_UUID` | `0x411e` | 0x75f8 | libblkid canonical form (hex/dash) — [I] | **path component**: `sprintf("%s/%d/%s", "/media/usb", port, uuid)` at `0x4d11` (fmt 0x78a6) |
| +0x50 | `ID_MODEL` | `0x4132` | 0x7603 | usb_id allow-list | `0x3d00`/`0x5280` arg, D-Bus payload, log |
| +0x60 | `ID_SERIAL_SHORT` | `0x4146` | 0x760c | usb_id allow-list | **MTP branch**: `system()` and `popen()`; also the MTP path component `"%s/%s"` (0x791c) |
| +0x40 | `ID_ATA_SATA` | `0x415a` | 0x761c | hex | MTP/branch logging only |
| +0x68 | `ID_PART_ENTRY_NUMBER` | `0x416e` | 0x7628 | decimal from partition scan | **alt-UUID**: `sprintf("%s_%s", ID_SERIAL_SHORT, partno)` (fmt 0x7595) |

### 1.2 Sinks in the same binary (complete)

| addr | sink | argument provenance |
|---|---|---|
| `0x2d0d` | `system("%s %s %04x %04x &")` 0x71d9 | config strings + hex |
| `0x2ed3` | `system("udevadm trigger --property=ID_BUS=usb …")` 0x73c0 | constant |
| `0x2f67` | `system("udevadm trigger --property=DEVPATH=%s* …")` 0x7388 | **config** port devpath (`0x20a0a8` family), unquoted |
| `0x535f` | `system("%s %s %s %s &", mtp_bin, "--dev", ID_SERIAL_SHORT, "/media/mtp/<serial>")` 0x7928 | **device serial** — dead, §0 |
| `0x53b9` | `popen("cat /proc/mounts \| grep %s")` 0x7936 | serial-derived dir — dead, §0 |

The MTP branch cannot mount even benignly: `/usr/bin/go-mtpfs` is absent, and there is no `fusermount`,
no `/dev/fuse`, and no `fuse` module in the image — [V]. The shell still parses (proven at runtime), so the
missing helper is not a mitigation for the *pattern*, only for the mount.

### 1.3 udev rules (`lib/udev/rules.d`, `etc/udev/rules.d`, `usr/lib/udev/rules.d`)

All vendor/custom rules, with the attacker-controlled-value question answered — [V] (file text read directly):

| rule | line | command | sub-world substitution | verdict |
|---|---|---|---|---|
| `etc/udev/rules.d/98-QHSUSB__BULK.rules` | 1 | `RUN+="/usr/bin/naddump.sh"` on `ATTR{product}=="QHSUSB__BULK"`, `idProduct!=9008` | none (literal match); `/usr/bin/naddump.sh` **absent** | dangling |
| `lib/udev/rules.d/10-mirrorlink_rename.rules` | 6,10 | `RUN+="/etc/mirrorlink_setup.sh %k ncmF %p"` | `%k`, `%p` = kernel ifname/devpath | script exists, unquoted, but args are kernel-generated |
| `lib/udev/rules.d/99-static-ip.rules` | 6 | `RUN+="/home/root/ip_setup.sh %k"` | IDs are match predicates only; target **absent** | dangling |
| `lib/udev/rules.d/50-udev-default.rules` | 4 | `RUN+="$env{REMOVE_CMD}"` | **superseded by V-014:** pre-fix `v4l_id` can inject this property from a control-character-bearing product field | security-sensitive static path; physical event untested |
| `lib/udev/rules.d/78-sound-card.rules` | 45–47 | `ENV{ID_SERIAL}="$attr{guid}"`, **`ENV{ID_SERIAL_SHORT}="$attr{guid}"`**, `ENV{ID_MODEL}="$attr{model_name}"` | raw sysfs attrs, **no sanitiser** | gated `SUBSYSTEMS=="firewire"` and preceded by `SUBSYSTEMS=="usb", GOTO="skip_pci"` (40–41) → **unreachable for a USB device** |
| `lib/udev/rules.d/60-persistent-storage.rules` | 18,19,45,50 | `ENV{ID_SERIAL}="$attr{serial}"` / `"$attr{name}"` | raw, unsanitised | only virtio / mmcblk / memstick; and the automounter never reads `ID_SERIAL` → inert here |
| `lib/udev/rules.d/60-persistent-storage.rules` | 22,25,28,31,34,35,66 | `IMPORT{program}="ata_id …"`, `scsi_id …`, `IMPORT{builtin}="usb_id"`, `blkid` | execve, no shell; **but pre-fix `scsi_id` line output can inject `SYSTEMD_WANTS`** | V-014 systemd unit-request path; physical event untested |

`usb_id` is the producer for the automounter properties analyzed in V-006, and
its allowlist protects that specific path. It is not a global sanitizer for
properties printed by separate helpers such as `v4l_id` and `scsi_id` — [V],
corrected by V-014/C25.

### 1.4 D-Bus: the cross-process consumer chain

- Producer: `usb-automount` binds `com.lge.car.automount`, object `/com/lge/car/automount`, and emits signal
  `UsbMount`/`UsbUnMount` (`.rodata 0x784f`/`0x7858`) built at `0x5f00` with
  `dbus_message_append_args(…, 'i' Port, 's' Mnt_Dir, 's' Label, 's' Model, 's' FS_Type, 'i' Mount_Flag,
  'i' Count, …)` (`0x5fda`) — [V]. `Label` and `Model` are attacker text; `Mnt_Dir` is the computed path.
- Consumers found by string presence on the system bus name (not audited to sink): `AppEngineerMode`,
  `AppDMClient`, `ApplicationManager`, `AppVH`, `MediaBrowser`, `AppUpgrade`, `AppMPAutoTest`, `AppScomoDM`,
  `AppProjection`, `TmsFgApp`, `AppCamera`, `usr/bin/watchdogd` — [V] presence only; **[U]** whether any of
  them feeds these strings to a shell or a path. This is the largest unaudited boundary in this map.
- Inbound: the automounter installs a filter for interface `com.lge.car.automount.request`, member
  `ReqMountedList` (`0x2b3c`–`0x2b54`); the handler `0x5f00` only re-serialises its internal list and calls
  `dbus_connection_send` (`0x610a`). No shell, no path use → any local process may trigger a re-broadcast
  (spam/DoS at most) — [V].

### 1.5 Raw-descriptor / non-udev readers

Binaries importing `libusb_get_string_descriptor*`: `/usr/bin/lsusb` and `/app/bin/modem_fw_updater` only — [V].
Neither is in the media path; `lsusb` prints, the updater targets the internal LTE modem.
`ID_SERIAL` (bare) appears as a NUL-terminated string only in `usr/bin/adb`, `usr/bin/fastboot`, `usr/bin/udevadm`,
`lib/udev/scsi_id`, `lib/udev/ata_id` — [V]. Of those, only `usb-automount` contains `ID_SERIAL_SHORT`, i.e. the
automounter **never reads `ID_SERIAL`** — [V]. `adb`/`fastboot` are host-side tools with no unit or
hotplug trigger in the image — [V] (no unit references them); they are not an automatic path.

### 1.6 File-content consumers of the mounted media (not strings)

`app/bin/lightmediascanner.conf`: `directory=audio:/media/usb/;audio:/media/mtp/` — the scanner recurses into
attacker files; per V-007 the media-parsing chain runs without privilege separation (informational there, but it
is what turns vector #2 below into code execution) — [V] config text.
`AppLogExtractor` (logexport to USB), `AppUpgrade` + `etc/update_start_5w.sh.ori` (update-from-USB, `TARGET_DIR=$1`)
consume the mounted tree — [V] presence; not audited here.

---

## 2. Can the sanitiser be bypassed? (four specific questions)

**2.1 Does anything read `ID_SERIAL` rather than `ID_SERIAL_SHORT`?** No. `usb-automount`'s rodata contains only
`ID_SERIAL_SHORT` (0x760c) — [V]. Where `ID_SERIAL` is read elsewhere it is by tools (`udevadm`, `scsi_id`,
`ata_id`, `adb`, `fastboot`), none of which feed a privileged sink. It would not help anyway: `ID_SERIAL` is
composed only from already-sanitised components (§0) — [V].

**2.2 Does any path read the serial via libusb or an ioctl instead of the udev property?** Not in the
automount path. No `USBDEVFS_*`/`ioctl` serial fetch and no libusb string fetch exists in `usb-automount`
(no `libusb` import at all) — [V]. The only libusb string consumers are `lsusb` and `modem_fw_updater`, neither
privileged-by-device-input — [V]. The kernel sysfs attribute `/sys/.../serial` *is* raw, but nothing privileged
reads it — [I, from the binary sweep above].

**2.3 Do any vendor udev rules copy unsanitised attributes into a property that is then read?** Exactly one
family does (`78-sound-card.rules:45-47`, `ENV{ID_SERIAL_SHORT}="$attr{guid}"` and `ENV{ID_MODEL}="$attr{model_name}"`
— no `util_replace_chars` anywhere on the rule path), and it is unreachable from USB because line 41 sends any
`SUBSYSTEMS=="usb"` device to `skip_pci` — [V]. `60-persistent-storage.rules` sets `ENV{ID_SERIAL}` from raw
`$attr{serial}` for virtio/mmc/memstick only, and that property is not read by the automounter — [V].

**2.4 Is the allow-list applied to all properties or only to `usb_id`'s output?** Only per-call-site, and
`usb_id` passes `allow=NULL`. `util_replace_chars` (`0x22a00`) has 12 call sites in `systemd-udevd`: eight
inside `builtin_usb_id` (`0x1c248/0x1c2b0/0x1c33e/0x1c38d` and `0x1c7a2/0x1c7fc/0x1c8a2`, all `allow=NULL`);
four in adjacent helpers (`0x18e13`, `0x1909a`, `0x19379`, `0x194b4`) that pass *different* allow-lists
(`"/"` at `0x51938`, `"/ $%?,"` at `0x525b9`, `"/ "` at `0x52685`) and run on **device-node names**, not
properties; plus `0x495e5` — [V]. **No call site exists in the rule `ENV{…}=` assignment path**, so a rule-set
property is *not* sanitised — [I, high confidence: the rule engine would have to be one of those 12 addresses,
and each is inside a builtin]. Today no shipped rule exploits that gap for the properties read in §1.1.

That last point is the honest residual: the defence is **accidental and local**, not architectural. Any future
rule of the form `ENV{ID_SERIAL_SHORT}="$attr{serial}"` on a USB path would re-arm V-006 verbatim.

---

## 3. The non-MTP (mass-storage) branch

Route: `0x43e0` dispatch → `DEVTYPE` ∈ {`disk`,`partition`} → `0x3a50` → `0x4c00` (mount) / `0x5090` (unmount);
cleanup loop at `0x6360` (`access`, `umount2(…,MNT_DETACH)`, `rmdir`). Calls present in `0x4c00`–`0x5068`:
`strncasecmp`, `__sprintf_chk`, `umount2`, `usleep`, `mkdir`, `mount`, `rmdir`, DLT logging. **No `system`,
no `popen`, no `exec*`** — [V].

**Target path.** `sprintf_chk(dir, 0x200, "%s/%d/%s", cfg_usb, port, uuid)` at `0x4d11`/`0x4d24` with
`cfg_usb = [0x20a0b8]` = `[mount] usb=` = `/media/usb` — [V]. There is **no** canonicalisation and no check for
`/`, `..`, or a trailing component: the only string comparisons in the function are the ntfs/exfat tests
(`0x4c62`, `0x4c7a`) and the rw-mode test (`0x4cbe`) — [V].

**Traversal reachability.** `uuid` is `ID_FS_UUID` when present. When `ID_FS_TYPE` is set but `ID_FS_UUID` is
absent (`0x4419`–`0x4427` → `0x45a0`), and `[quirk] support_no_uuid=enable` (shipped; flag at `0x20a0f8`
compared against `"enable"` 0x72ae at `0x4605` [V]), the "alternative UUID" is built at `0x4676` by
`0x3e50`: `sprintf(dst,"%s_%s", ID_SERIAL_SHORT, ID_PART_ENTRY_NUMBER)` (`0x3ec0`, fmt 0x7595), or a bare
`strcpy(dst, ID_SERIAL_SHORT)` when the part number is NULL (`0x3e7f`).
So an attacker who sets `iSerialNumber=".."` and supplies a filesystem that blkid recognises without a UUID, on a
device with **no partition table** (so `ID_PART_ENTRY_NUMBER` is absent), gets
`dir = "/media/usb/<port>/.."` → the kernel resolves it to **`/media/usb`** itself: `mkdir` fails (return value
**ignored** at `0x4d4a`) and `mount(2)` succeeds, mounting the attacker filesystem over the `/media` tmpfs — [V for
the code path; I for "blkid yields no UUID for a plausible fs"]. This is one component of traversal only —
`/` cannot be expressed (`util_replace_chars` maps it to `_`), so `/media/usb/<port>/../..` is not reachable
through the serial.

**uid.** 0. `usb-automount.service` has `[Service] Restart=always / ExecStart=/app/bin/usb-automount` and no
`User=`, `Group=`, or capability restriction → system-service default root — [V]. SMACK label
`App::usb-automount` grants `_ rwxa--` and `* ----t-` (`etc/smack/accesses.d/usb-automount`), which does not
mediate `mount(2)` — [V file, I for the effect].

**Symlink race.** `umount2(dir, MNT_DETACH)` at `0x4d31` precedes `mkdir(dir, 0777)` at `0x4d4a` precedes
`mount` at `0x4d70`; a pre-existing path at `dir` is therefore detached and reused, not validated. *But*
`/media` comes from `etc/fstab_emmc`: `tmpfs /media tmpfs defaults 0 0`, mounted by root at boot with the
default tmpfs root mode (`mode=0777` default, umask applied ⇒ 0755 expected) — [V fstab, **I mode**]. The
automounter then creates `/media/usb`, `/media/usb/1`, `/media/usb/3`, `/media/mtp`, and the sdcard mount with
`mkdir(path, 0777)` at `0x2d74`–`0x2e06` (formats `"%s/1"` 0x71fe, `"%s/3"` 0x7203) — [V]. Port values other
than 1 and 3 have no pre-created parent, so their `mkdir` fails with `ENOENT` and the mount never happens — [V].
If `/media` (or `/media/usb`) is writable by a non-root process on the real unit, the `mkdir`-after-`umount2`
ordering becomes a symlink-mount race. That is the one load-bearing assumption in this section (§6).

**Mount flags — the substantive finding.** `0xC0ED000A` = `MS_MGC_VAL | MS_NOSUID | MS_NOEXEC` when
`[fs] rw_mode`/`fat_rw_mode` are `enable` (both are, shipped: `0x4f20`, reached from `0x4cbe`/`0x4cd1`) — [V].
Default and the retry mount (`0x4dec`) are `0xC0ED000B`, i.e. `+MS_RDONLY` — [V]. **`MS_NODEV` (0x4) is never
set on any USB mount.** Attacker filesystems are therefore mounted read-write with device nodes live:
a stick carrying `mknod`-created block/character nodes at mode 0666 yields `/media/usb/<port>/<uuid>/…` nodes
that any local process can open regardless of the normal `0660 root:disk` mode on `/dev/*` — [V for flags;
I for the DAC consequence]. `MS_NOEXEC`/`MS_NOSUID` block the obvious "drop a binary + run it" step, so this is
a *raw-device exposure*, not directly code execution.

Adjacent (different device class, same binary): the SD-card route at `0x586d` mounts with `0xC0ED0002` =
`MS_MGC_VAL | MS_NOSUID` only — rw, **exec allowed, `MS_NODEV` absent** — at the fixed config path
`[mount] sdcard=` (`/navi`) — [V]. Not USB-reachable; worth a separate look because it drops both `noexec` and
`nodev` on a physically-replaceable medium.

---

## 4. `sbi_apl_commit` at offset `0xc` (V-010)

Symbol resolution: `sbi_apl_commit` is exported by the kernel (undefined in `lge_usb_adapter.ko`). Its entry in
`__ksymtab` (name string at `__ksymtab_strings` VMA `0xffffffff818c5a66`) gives `value = 0xffffffff810590db`
in `work/kbuild/vmlinux-vendor`; `+0x60 = 0xffffffff8105913b`, which is **exactly** the oops IP — [V].

Disassembly of the fault site:

```
81059101  cmpb $1, 0x9(%rdi)          ; arg->9  <= 1
8105910b  cmpb $3, 0xa(%rdi)          ; arg->a  <= 3
81059118  cmpb $0xf, 0xb(%rdi)        ; arg->b  <= 0xf
81059122  cmpb $7, 0xc(%rdi)          ; arg->c  <= 7
8105912c  mov 0xb7c32d(%rip),%rax     ; rax = *(0xffffffff81bd5460)   <-- NULL
8105913b  mov 0xc(%rax),%esi          ; <-- fault: NULL + 0xc
```

**The pointer at offset `0xc` is a global context pointer (`0xffffffff81bd5460`) plus `0xc`, and the global was
NULL.** It is written in exactly one place: `810594c2  mov %rbx,0xffffffff81bd5460` inside the probe at
`0x810593a9`, where `rbx = *(platform_device + 0xa8)` — i.e. `dev.platform_data`, the sideband bus/adapter
descriptor supplied by whoever registered the "sbi" platform device — [V]. Nothing else writes it; the module
`lge_usb_adapter` only ever calls into `sbi_apl_commit` (`lge_usb_write_sbi_reg` at `.text.unlikely+0x0`,
`lge_usb_read_sbi_reg.part.0` at `.text.unlikely+0x3f`) with a 16-byte *stack* struct whose first byte is
`0xA7` and whose fields 6/…/0xf are constants — [V].

**Can a USB device or unprivileged process influence it?** No — [V for the call graph, I for absence of any
other writer]:
- the argument's bytes are only used as *values* (register address/data) after being bounds-checked, so they
  cannot become the pointer;
- the pointer is set solely by an in-kernel platform-device probe; the crash is the module probing *before*
  that probe has run (the vendor ordering defect: `esinit-modprobe.sh:5` modprobes `lge_usb_adapter` on a
  machine where the sbi platform device never probes);
- the sysfs attributes that can reach the same relay (`sbi_onoff`, `sbi_level` via `lge_usb_write_sbi_reg`) are
  created by the same module that crashes at init, so they never exist; and sysfs attributes default to 0644
  root — [I].

Residual, [I]: the failure paths at `0x810594d6`–`0x8105953e` set the global and then can return an error
without clearing it, and the pointee is owned by a separately-registered platform device. A device-unregister /
late-call race would be a dangling read in the same driver. That needs an in-kernel event, not USB input, and is
not a USB attack surface.

**Verdict: V-010 is an init-ordering bring-up defect, not a security vulnerability reachable from USB,
unprivileged userspace, or device-supplied data. Recommend downgrading it to "bring-up defect" with this
rationale recorded, and keeping the stale-global observation as a separate low-severity driver-hygiene item.**

---

## 5. Ranked candidates

Ranked by plausible path to *code execution or privilege gain* for someone with a USB port. "Cheapest test"
assumes the image is free of the other worker's QEMU run; nothing here was executed.

**#1 — Missing `MS_NODEV` on attacker-controlled filesystems → raw block-device access.**
Confidence in the defect: high ([V] flags). Confidence in the escalation: medium ([I] DAC, [U] SMACK).
- Precondition: any USB mass-storage device whose filesystem mounts (nothing crafted beyond a normal image
  containing `mknod`-created nodes at mode 0666, e.g. `brw-rw-rw- 179,0 mmcblk0`); a local context able to
  `open()` under `/media/usb/…` (any HMI app, shell, or a later-staged payload). `[fs] rw_mode=enable` shipped.
- Gain: read/write the eMMC block device outside the 0660 `root:disk` policy of `/dev/*`, i.e. direct rootfs
  tampering.
- Falsifier: `/media/usb/1/<uuid>` appears in `/proc/mounts` with `nodev`, **or** opening a crafted block node
  from that mount fails `EACCES`/`EPERM`.
- Cheapest test: `grep '/media/usb' /proc/mounts` after hot-plugging a stick with a node in it; one command,
  seconds. Static cross-check: confirm `MS_NODEV` (`0x4`) is absent from `0xC0ED000A` (it is — §3).

**#2 — Media-parser chain over attacker files (V-007) as the direct root-execution route.**
Confidence: [V] that `lightmediascanner` scans `/media/usb/` and that media parsing has no privilege
separation; [U] whether any reachable parser has a memory-safety defect.
- Precondition: successful automount (#1/#3 machinery) plus one parser bug in the audio/tag chain.
- Falsifier: lightmediascanner (or the parser it dlopens) runs non-root, or runs under a seccomp/SMACK
  confinement that prevents useful exec.
- Cheapest test: `ps -o user,label,cmd` for the media scanner on the unit/VM; then a static pass over the
  scanner's parser plugins for the usual length bugs. No device needed for the first half.

**#3 — Alt-UUID `".."` mount-over-`/media` (path hijack, prerequisite amplifier).**
Confidence: [V] code path; [I] that a UUID-less-but-recognised filesystem is easy to produce.
- Precondition: `iSerialNumber=".."`; a filesystem type blkid recognises with no UUID; no partition table;
  `support_no_uuid=enable` (shipped).
- Gain alone: attacker filesystem mounted at `/media` (hides real media mount points, controls everything under
  `/media/usb/…`), and it makes #1 and #2 reachable without depending on the UUID format. Not root by itself.
- Falsifier: `blkid -o value -s UUID` always non-empty for every fs type the image's libblkid probes, or the
  `ID_PART_ENTRY_NUMBER` slot is always populated.
- Cheapest test: host-side, no VM — build a vfat image with a zero volume ID (`mkfs.vfat -i 0`) and run the
  image's `libblkid`/`blkid` against it; if `ID_FS_UUID` is empty, construct the serial `..` case.

**#4 — MTP `system()` injection (V-006).** **Dead on 260128** (§0). Kept in the ranking only so nobody
re-discovers it.
- Precondition to revive: any path where a property the automounter reads carries bytes outside
  `[A-Za-z0-9#+-.:=@_]` — a new rule of the `ENV{ID_SERIAL_SHORT}="$attr{serial}"` shape on a USB path, a udev
  build without `usb_id`'s `util_replace_chars`, or an added libusb/ioctl reader.
- Falsifier of "dead": find such a rule or reader in a later build. In 260128 there is none (§2, all four
  questions answered negatively).
- Cheapest test: grep-only, already done — `grep -rn 'ID_SERIAL' <rules>` plus a binary sweep for
  `ID_SERIAL_SHORT`. Re-run per build.

**#5 — D-Bus `UsbMount` consumer chain.** [U], unbounded; included because it is the only route by which
*non-sanitised* attacker text (`ID_FS_LABEL`, `ID_MODEL` for non-`usb_id` producers) reaches other privileged
processes.
- Precondition: some subscriber (12 binaries, §1.4) uses `Label`/`Model`/`Mnt_Dir` in a shell command or as a
  path prefix.
- Falsifier: every subscriber treats them as display/log strings.
- Cheapest test: for each subscriber, locate the `com.lge.car.automount` handler and check for
  `system`/`popen`/`execl` or path concatenation reachable from the message body. Hours, not days, and no device
  required.

**#6 — `sbi_apl_commit` (V-010).** Drop as a USB vector (§4). No attacker-controlled pointer exists.

**Single most promising: #1.** It needs no memory-corruption bug, no crafted superblock, and no unusual device
class: a plain stick plus one `mknod` node, combined with a mount option set that is statically provable
(`MS_NODEV` never set, rw enabled in the shipped config). It is also cheap to falsify — one `grep` of
`/proc/mounts` — which makes it a good next experiment. #2 is where the root payoff is, but it is contingent on
a parser bug we have not found.

---

## 6. Weakest link in this analysis

The chain in §3 and vector #1/#3 depends on **`/media` being root-owned and non-writable by unprivileged
processes**, and I established that only indirectly: `etc/fstab_emmc` mounts `tmpfs /media tmpfs defaults`,
which implies the tmpfs default root mode (0777 in the kernel, reduced by the mounting process's umask ⇒ 0755),
and the automounter creates its sub-directories with `mkdir(…, 0777)` under systemd's default umask. I did not
verify the mode on a running unit, and I did not verify whether any HMI process re-labels or chmods `/media`.
If `/media` or `/media/usb` is group- or world-writable, then the `umount2`-then-`mkdir`-then-`mount` ordering
without `O_NOFOLLOW`/`openat` becomes a symlink mount race that an unprivileged local process can aim at any
directory — including, with serial `".."`, `/` — which would be a straightforward local-to-root escalation and
would move #3 to the top of the list. Second-weakest: whether `blkid` in this image can emit a UUID containing
`/` or `..` for any filesystem type (I reasoned from libblkid's canonical UUID formatter but did not disassemble
it); if it can, #3 needs no `".."` serial and detaches from the alt-UUID branch entirely.

## 7. Recommended register deltas

- V-006: unchanged conclusion (latent defect, not exploitable on 260128); add the *mechanism* — the allow-list
  lives in `util_replace_chars` called from `builtin_usb_id` with `allow=NULL`, table `#+-.:=@_` at
  `.rodata 0x537c9` in `lib/systemd/systemd-udevd` — and the point that `ID_SERIAL` is safe only because its
  components were sanitised first.
- V-010: downgrade to bring-up defect; record that the faulting pointer is the global `0xffffffff81bd5460`
  set only at `0x810594c2` from `dev.platform_data`, unreachable from device or unprivileged input.
- New (proposed) — "USB media mounted without `MS_NODEV` while writable": `0x4c00` mount flags `0xC0ED000A`;
  impact = raw block-device access for local processes; needs the `/media` mode test to be finalised.
- New (proposed, low) — stale `0x81bd5460` on the sbi probe error path (driver hygiene, not USB-reachable).
- Out of bandwidth, flagged not claimed: SD-card route `0x586d` mounts `0xC0ED0002` (rw, exec, dev) at `/navi`.
