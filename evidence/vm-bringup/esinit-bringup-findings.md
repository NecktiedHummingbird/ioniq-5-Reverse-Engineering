# Authentic vendor init chain (`init=/lib/systemd/esinit`) — VM bring-up findings

Date: 2026-10-30. Image: `work/vm/vendor-userspace-260128/rootfs.img` (unchanged:
`sha256 4953a005…66d036f` before and after; see §1). Kernel: the measured EU 260128 `bzImage`.

## 1. Safety: the canonical image was never written

`tools/uk_fw/vm_boot.py` boots the rootfs through
`-drive if=none,id=sd0,format=raw,file=…/rootfs.img,snapshot=on`, i.e. QEMU writes into a
throw-away overlay created inside `TMPDIR` (= the per-run directory) and deletes it on exit.
Proof: `shasum -a 256 rootfs.img` is byte-identical before and after all four runs
(`4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`). No clone was needed,
no large copy was made, nothing was deleted; the four new run dirs total ~180 KB.

## 2. How to boot the authentic chain

The harness previously hard-coded `init=/init` inside `qemu_command()`, so there was **no way to
override the kernel command line**. Smallest change (implemented, default behaviour preserved):

* `tools/uk_fw/vm_boot.py`: new `INIT_CHOICES = ("/init", "/lib/systemd/esinit")` (validated
  whitelist), `init: str = "/init"` threaded through `qemu_command()` and `run()`, and a new
  `run --init {/init,/lib/systemd/esinit}` flag; the value is echoed into `result.json`.
* `run --interactive` stdin forwarding was gated on the research marker
  `IONIQ_VM_USERSPACE_READY`, which a non-research PID 1 never prints; the gate is now only the
  marker-gated *command* injection (that still requires the marker), while keystrokes are
  forwarded whenever `--interactive` is set.

Invocation used:

```
python3.13 tools/uk_fw/vm_boot.py run --workspace work/vm/vendor-userspace-260128 \
  --sdhci-compat --init /lib/systemd/esinit --timeout 240
```

## 3. Does esinit run? Yes — PID 1 is `/bin/bash /lib/systemd/esinit`

Authentic run `runs/1793335992750096000/serial.log` (kernel echo, verbatim):

```
[    0.000000] Command line: root=/dev/mmcblk0 rootwait rootdelay=2 rootfstype=ext4 rw init=/lib/systemd/esinit console=ttyS0,115200 panic=-1 loglevel=7 ABL.oemkm=40@20000000 ABL.seed=21000000,21000040
...
[    2.624668] VFS: Mounted root (ext4 filesystem) on device 179:0.
[    2.657523] devtmpfs: mounted
```

then esinit's own stdout from step 2 onwards:

```
mount tmp filesystems
OEM Type: 1, KMC
Car Type: 5, SK3
LCD TYPE: 3
...
NAVI SUPPORT: yes
SECURE CONSOLE Mode: NO !!!
[FDE] ***** use fstab for non FDE        <-- last line of the whole run
```

No `systemd[1]`, no `Reached target`, no `esinit`-to-systemd handover line exists anywhere in the
log (the only two matches for `systemd` are the kernel's echo of `init=/lib/systemd/esinit`).
After `[FDE] ***** use fstab for non FDE` the guest produced **no further output**: the last line
of that log is identical in the two long diagnostic runs after 300 s and 420 s of additional wall
time; QEMU was still alive each time and was terminated by the harness timeout. **PID 1 never
became systemd**; `exec /lib/systemd/systemd` (esinit line 617) was never reached.

## 4. How far through esinit it gets

Steps 1–22 of the hmi-gap-analysis table ran and produced their artefacts (verified in a
diagnostic run where the same `esinit` was started from the research shell, so `/tmp` could be
listed): `/tmp/passwd` (996 bytes = `passwd.legacy`), `/tmp/shadow -> /etc/shadow.Global`,
`/tmp/fstab -> /etc/fstab_emmc`, `/tmp/weston.ini -> /etc/xdg/weston/weston_1920.ini`,
`/tmp/front_lcd.png -> /app/share/SplashScreen/LOGO_KMC_NA_NA_1920.png`,
`/tmp/{oem_type,car_type,lcd_type,hw_type,hw_version,pcb_version,eco_type,telematics,optMIC,
country,navi_support,boot_reason}_code_*`, `/tmp/secure_console_disable`, `/tmp/shells`.

Two esinit steps are inert in the VM, both observed, not inferred:

* **SPI gate (step 3) never passes**: `/sys/module/micom/parameters/spi_validation` does not
  exist (`micom` is not loaded), so esinit leaves `/tmp/spi_validation_NOK` in place (seen in
  `ls /tmp`). Consequence: step 11 takes the `SPI NOK` branch and **`/usr/bin/weston --tty=1` is
  never started**. That branch is also silent on the console because the vendor wrote
  `echo "SPI NOK" > kmsg &` — a *relative* path, so it writes a file `/kmsg` instead of
  `/dev/kmsg` (vendor bug; no fix applied).
* eMMC/PLK2 recovery (steps 15–16, 22) only emits benign "partition does not exist" messages,
  because this image is a single-partition `root=/dev/mmcblk0` projection with no `mmcblk0pN`.

## 5. First real blocker (exact text) — `modprobe fan` deadlocks the platform bus

esinit line 588 (`/sbin/modprobe fan`) never returns. Its cause is the preceding oops in
`/etc/esinit-modprobe.sh` line 5 (`/sbin/modprobe lge_usb_adapter`), which the authentic run
prints as:

```
lge-usb-adapter lge-usb-adapter: lge-usb-adapter probe
lge_usb_init: Failed to get SoC info
BUG: unable to handle kernel NULL pointer dereference at 000000000000000c
IP: [<ffffffff8105913b>] sbi_apl_commit+0x60/0x2bc
...
---[ end trace bc37b8a2c82c845d ]---
/etc/esinit-modprobe.sh: line 5:   830 Killed                  /sbin/modprobe lge_usb_adapter
```

The oops kills the probe while the platform `device` lock is held. The next platform driver
registration (`fan`) then blocks on that lock forever. Measured in
`runs/1793336899275858000` (esinit started from the research shell so `/proc` could be read;
`/proc/sys/kernel/hung_task_timeout_secs` does not exist in this kernel —
`sh: can't create /proc/sys/kernel/hung_task_timeout_secs: nonexistent directory`, so the hung
task detector is off and the kernel prints nothing):

```
/proc/965/status:State:	D (disk sleep)
  710 root      0:00 /bin/bash /lib/systemd/esinit
  965 root      0:00 /sbin/modprobe fan
== /proc/965 modprobe
__driver_attach
[<ffffffff8139c65e>] __driver_attach+0x2e/0x7c
[<ffffffff8139a59a>] bus_for_each_dev+0x74/0xa2
[<ffffffff8139bc2d>] driver_attach+0x19/0x1b
[<ffffffff8139b8f3>] bus_add_driver+0x133/0x22b
[<ffffffff8139ce3a>] driver_register+0x8a/0xc7
[<ffffffff8139dce9>] __platform_driver_register+0x45/0x47
[<ffffffffa017b055>] lge_fan_init+0x55/0x94 [fan]
[<ffffffff810004a3>] do_one_initcall+0x190/0x1a5
[<ffffffff8155c343>] do_init_module+0x56/0x1a8
[<ffffffff810a910d>] load_module+0x1817/0x1c7c
[<ffffffff810a9760>] SYSC_finit_module+0x95/0xb6
```

Controls (`runs/1793336659679272000`) confirm the mechanism and localise it to the platform bus:

* `modprobe fan` on a clean guest **before** any lge load: `fan1_rc=0`, `/sys/module/fan` exists.
* `modprobe hid-generic` **after** the lge oops: `hg_rc=0` — the module loader itself is fine;
  only `register_platform_driver` (device_lock during `__driver_attach`) is wedged.
* So the blocker is not "fan", it is the orphaned platform-device lock left by the
  `lge_usb_adapter` oops, which `sbi_apl_commit` triggers on non-vendor hardware.

## 6. Were the HMI units attempted? No — not one of them

`weston`, `ApplicationLauncher`, `micom`, `Dbuslaunch` are systemd units; **systemd never ran**,
so none of them was attempted. Separately, esinit's own compositor launch (the only non-systemd
way weston starts) was skipped by the SPI gate as described in §4. So the serial logs contain no
line that names any of these four units being started, and no `systemd` line at all.

## 7. Untested next steps (deliberately not guessed at)

1. Pre-load `fan` (`/sbin/modprobe fan` succeeds on a clean guest) before esinit reaches line 588,
   or suppress the `lge_usb_adapter` modprobe (`/etc/esinit-modprobe.sh:5`) — either would remove
   the platform-bus deadlock and let esinit reach `exec /lib/systemd/systemd`. Both need a write to
   the image (a `modules-load.d` entry / an edited script), which was out of scope here because
   the canonical `rootfs.img` must stay unmodified.
2. Once systemd runs, expect the SPI gate to still suppress weston: `/tmp/spi_validation_NOK`
   survives and `micom` is unloaded, so `/tmp/weston.ini`, `/tmp/front_lcd.png` and `/tmp/passwd`
   will exist but the compositor will not be started by esinit.

## 8. Evidence index

| Path | Content |
|---|---|
| `runs/1793335992750096000/` | authentic `init=/lib/systemd/esinit` boot; stops after `[FDE] ***** use fstab for non FDE` |
| `runs/1793336299417507000/` | esinit from research shell; `ps`, `/tmp` listing, `readlink` of `/tmp/fstab`, `/etc/passwd` |
| `runs/1793336659679272000/` | clean-guest `modprobe fan` (`fan1_rc=0`) then lge oops then `hid-generic` (`hg_rc=0`) |
| `runs/1793336899275858000/` | D-state `modprobe fan` with `__driver_attach` / `lge_fan_init` kernel stack |
