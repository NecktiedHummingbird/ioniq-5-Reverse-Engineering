# HMI gap analysis — vendor userspace 260128, from "init reaches a shell" to "infotainment UI is running"

**Method: static, read-only.** No VM was booted for this document. Every runtime statement
below is quoted from a serial/DLT/strace log that already existed in the workspace, with the
file and line given. Nothing was written outside this file; the VM image was not touched.

**Target tree:** `work/decrypted-eu-260128/extracted-safe/mango-rootfs`
(authentic `mango-rootfs.tar.gz` from `work/decrypted-eu-260128/HU/images/`, merged with
`new_gui`, `appnavi`, `mango-rwdata` per `work/vm/vendor-userspace-260128/prepare.json`
`integrated` list). Self-identifies as `5W.XXX.S5W_L.001.001.260128`
(`etc/version.txt:1`), `ID="mango"` OpenEmbedded (`etc/os-release:1-5`), systemd 225
(`strings lib/systemd/systemd` → `systemd 225 running in %ssystem mode
(-PAM -AUDIT -SELINUX +IMA -APPARMOR +SMACK +SYSVINIT +UTMP ...)`), dbus 1.8.20
(`strings usr/bin/dbus-daemon` → source path `dbus/1.8.20-r0/...`).

**Citation convention.** Paths are relative to the rootfs tree unless they start with `work/`,
`evidence/`, `tools/` or `docs`. `vmlinux-off` means a byte offset in the authentic decompressed
vendor kernel `work/kbuild/vmlinux-vendor` (SHA-256
`f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`, the recovered ELF of the
shipped `bzImage`, `evidence/vendor-kernel-vm.md:170-180`). Claims that are reasoning rather than
direct observation are marked **(inferred)**; everything else is **(verified)**.

---

## 1. The boot path, and where the harness stops

### 1.1 Authentic path (verified)

The shipped kernel command line, recovered from the plaintext IPK header, is:

```
root=/dev/mmcblk0p3 rootfstype=ext4 rootwait init=/lib/systemd/esinit
console=ttyS2,115200n8
i915.nuclear_pageflip=1 i915.enable_1920_720_mode=1
i915.splash=HDMI-A-1:splash_1920x720.data:1920,720,1920,0,0,1920,720
lge.lcd_res=1920,720 lge.lcd_type=3
```

(`evidence/official-package-static.md:239-244`; the same `init=/lib/systemd/esinit` appears at
`evidence/gen5w-public-exploit-ecosystem.md:91`.) The kernel parameter name `lge.lcd_res=` is
present in the vendor kernel (`vmlinux-off 16339554`), and `i915.enable_1920_720_mode` /
`i915.nuclear_pageflip` at `vmlinux-off 50548` / `50555`.

So PID 1 on the device is **`/lib/systemd/esinit`, a bash script**, not systemd. `/sbin/init` is
only a symlink to `/lib/systemd/systemd` (`sbin/init -> /lib/systemd/systemd`, verified with
`ls -l`), and it is reached only because esinit `exec`s it at the very end
(`lib/systemd/esinit:617`).

Order of operations in `lib/systemd/esinit` (all line numbers verified):

| # | What esinit does | Line(s) |
|---|---|---|
| 1 | Banner to `/dev/kmsg` | 3 |
| 2 | Mount proc, sysfs, tmpfs on `/run` and `/tmp` | 6-10 |
| 3 | **SPI gate:** `touch /tmp/spi_validation_NOK`; poll `/sys/module/micom/parameters/spi_validation` 10 × 0.3 s; only if it reads `1` → `touch /tmp/spi_validation_OK` and remove NOK | 25-45 |
| 4 | Read `oem_type` → `/tmp/oem_type_code_*` | 57-71 |
| 5 | Read `car_type` (92-entry table) → `/tmp/car_type_code_*` | 74-87 |
| 6 | `ln -s /etc/shadow.Global /tmp/shadow` (the account DB) | 90 |
| 7 | Read `lcd_type` → `LCD_TYPE` 1280/1920 → `/tmp/lcd_type_code_*` | 92-107 |
| 8 | Emblem/OEM resolution (KMC/NEWKMC/HMC/NEWHMC/2022NEWHMC) | 109-138 |
| 9 | `install_westonPngLogo.sh` → symlinks `/tmp/front_lcd.png` and **`/tmp/weston.ini` → `/etc/xdg/weston/weston_${LCD_TYPE}.ini`** | 143 (script line 73) |
| 10 | Create `/run/wayland`, `/run/user/root`; `HOME=/etc/xdg/weston`, `XDG_RUNTIME_DIR=/run/user/root` | 145-148 |
| 11 | **Compositor gate:** if `/tmp/spi_validation_NOK` exists → print `SPI NOK`; **else** start `/usr/bin/weston --tty=1` in background and `touch /tmp/weston.crash` on exit | 150-154 |
| 12 | Early camera `/etc/cam_launch.sh` | 157 |
| 13 | Read `car_type`, `optNSport`, `product_id` (unquoted, so unset values are shell errors) | 159-161 |
| 14 | eco/telematics/MIC/HWType/country → `/tmp/*_code_*` markers | 163-251 |
| 15 | iasPreload compare/repair on `/dev/mmcblk0p1/p2` | 254-314 |
| 16 | PLK2→PLK1 crash recovery | 291-314 |
| 17 | ECNR / BT patchram DB setup, ISYS freq, `modprobe xhci_pci`, `modprobe lgivi_qmi` | 362-384 |
| 18 | `navi_support` → `/tmp/navi_support_code_{yes,no,none}`, plus hw/pcb/boot_reason codes | 386-422 |
| 19 | `esinit-modprobe.sh`, 1228 MB zram + swapon | 457-463 |
| 20 | Secure-console decision → `/tmp/secure_console_disable`, `/tmp/shells`, `/tmp/passwd` from `passwd.legacy`/`passwd.secure` | 466-503 |
| 21 | FDE probe; **writes `endFde` into `/sys/module/micom/parameters/optUNECE`** | 525-543 |
| 22 | eMMC fsck/recovery; **`ln -s /etc/fstab_emmc /tmp/fstab`** (or FDE variant) | 565-583 |
| 23 | `modprobe fan`, start `kp.sh` (kdump) | 587-592 |
| 24 | **Create device aliases:** `ln -s spidev3.0 /dev/spidevDMB`, `ln -s ttyS3 /dev/ttyGPS` (or `ttyACM1` when `pcb_version=1`) | 594-602 |
| 25 | Remove unused nodes (`spidev2.0`, `i2c-2/8/9/10/11`) | 604-610 |
| 26 | `/etc/set_gps_ttyhook.sh` | 613 |
| 27 | `exec /lib/systemd/systemd` | 617 |

Two consequences matter for the whole analysis: **the compositor is not a systemd unit at all**
(only esinit starts it, step 11), and **esinit is the producer of the `/tmp` state that later units
require** (accounts, fstab, weston.ini, and every `*_code_*` marker).

### 1.2 The harness path (verified) — and where it stops

The research image does **not** use the vendor init chain:

* `work/vm/vendor-userspace-260128/prepare.json` `source_rootfs` is the authentic tarball; the
  tarball contains **no top-level `./init`** (`tar -tzf ... | grep -cx "./init"` → `0`; only
  `./sbin/init` exists). The tree's `/init` is a harness artifact.
* `init:1-16` is a 16-line busybox script: mkdir `/rw_data/var/...`, mount proc/sys/devtmpfs/run/tmp
  and smackfs, print `IONIQ_VM_USERSPACE_READY` / `IONIQ_VENDOR_USERSPACE_READY`, then
  `exec $BB sh` (line 16).
* `tools/uk_fw/vm_boot.py:338` forces `... rootfstype=ext4 rw init=/init console=ttyS0,115200`,
  i.e. it overrides the authentic `init=/lib/systemd/esinit`.
* Observed result: `work/vm/vendor-userspace-260128/appnavi-wayland-host-run.log:279-282` —
  `IONIQ_VM_USERSPACE_READY` / `IONIQ_VENDOR_USERSPACE_READY` /
  `Authentic EU 260128 userspace under research init; HMI not yet launched.` /
  `sh: can't access tty; job control turned off`. Same lines exist in every run
  (`work/vm/bootable/runs/*/serial.log`, `work/vm/vendor-userspace-260128/micom-contract/*.log`).
* No serial log in the workspace contains `systemd[1]` or `Reached target`
  (`grep -rln "systemd 225\|Reached target\|systemd\[1\]" work/vm/**/serial.log` → empty), so
  **systemd has never run in this harness**, and esinit has never executed either.

**The current stopping point is therefore step 0 of the authentic path.** PID 1 is a shell; esinit
never runs, so: no `/tmp/passwd`/`/tmp/shadow`, no `/tmp/fstab`, no `/tmp/weston.ini`, no
`/tmp/*_code_*` markers, no `/dev/ttyGPS` alias, no weston, no systemd units.

Two harness-level side effects are visible in the same log:

* `mkdir: can't create directory '/rw_data/var/log': No such file or directory` and the same for
  `/rw_data/var/tmp` (`appnavi-wayland-host-run.log:277-278`) — `init:4` assumes `rw_data/var`
  exists; in this image `rw_data/var` exists but `log`/`tmp` are symlinks to `volatile/...`
  (`ls -l rw_data/var`), so the harness `mkdir` fails. Cosmetic, but it shows the harness init was
  written against a different `/rw_data` layout.

---

## 2. What would start the HMI, and would it start now

### 2.1 The owner chain (verified)

```
esinit:153  /usr/bin/weston --tty=1              ← compositor (not a unit)
   ↓ wayland socket (weston.ini [core] shell=ivi-shell.so backend=ias-backend.so)
systemd multi-user.target
  ├─ Dbuslaunch.service            → /app/bin/Dbuslaunch.sh  (private session bus)
  │      creates /tmp/session_appmgr + /tmp/session_appmgr.env
  └─ dbus-com.lge.car.micom.service (Type=dbus, BusName=com.lge.car.micom)
         → /app/bin/micommanager_userspace   (/dev/ttyS1)
              ↓ Required by
  ApplicationLauncher.service (Type=oneshot, ExecStart=/app/bin/AppLauncher.sh)
         → /app/bin/AppLauncher 3&
              → /app/bin/ApplicationManager, AppHomeScreen, AppStandbyClock, AppNavi…
```

Evidence for each hop:

* `lib/systemd/system/ApplicationLauncher.service:4-5` — `After=Dbuslaunch.service
  dbus-com.lge.car.micom.service pas-daemon.service`, `Requires = dbus-com.lge.car.micom.service`;
  `:12-15` — `LD_LIBRARY_PATH=/app/lib`, `QT_QPA_PLATFORM=wayland`,
  `XDG_RUNTIME_DIR=/var/run/user/root`, `EnvironmentFile=/tmp/session_appmgr.env`;
  `:19` — `ExecStart=/app/bin/AppLauncher.sh`; `:23` — `WantedBy=multi-user.target`; the unit is
  symlinked into `lib/systemd/system/multi-user.target.wants/` (verified with `ls`).
* `lib/systemd/system/dbus-com.lge.car.micom.service:3-9` — `Requires=dbus.service dlt.service`,
  `Type=dbus`, `BusName=com.lge.car.micom`, `ExecStart=/app/bin/micommanager_userspace`.
* `lib/systemd/system/Dbuslaunch.service:4` — `After=micom.service`, **a unit that does not exist**
  in this image (`ls lib/systemd/system | grep -c '^micom.service$'` → 0). So Dbuslaunch has no
  ordering constraint against the real micom unit, and nothing forces the session bus to exist
  before micom comes up.
* `app/bin/Dbuslaunch.sh:1-13` — deletes `/tmp/session_appmgr{,.env}`, runs
  `dbus-daemon --session --print-address --fork`, writes `DBUS_SESSION_BUS_ADDRESS=...` into the
  env file. This is the private bus that ApplicationManager/AppHomeScreen/AppNavi use — the
  previous chain runs bind `com.lge.hkmc.avn.appnavi` and answer `org.freedesktop.DBus.Peer.Ping`
  on it (`micom-contract/BOOTINFO-AND-SIM-V2.md`, "No-strace liveness control").
* `app/bin/AppLauncher.sh:1-12` — exports `QV4_MM_MAX_CHUNK_SIZE=16384`,
  `LD_LIBRARY_PATH=/app/lib:/navi/navi/Lib`, **`LD_PRELOAD=/usr/lib/libEGL.so.1`**,
  `XDG_RUNTIME_DIR`, `QT_QPA_PLATFORM=wayland`, `QV4_NO_SSA=1`, `QV4_FORCE_INTERPRETER=1`, `cd
  /app/bin`, `exec /app/bin/AppLauncher 3&`.
* `app/bin/AppLauncher` strings contain the whole child inventory it spawns:
  `/app/bin/AppHomeScreen`, `/app/bin/ApplicationManager`, `/app/bin/AppStandbyClock`,
  `/app/bin/AppNavi`-family, `AppSetup`, `MediaBrowser`, `BluetoothHMI`, `NotificationManager`,
  `UserProfileManager`, `TmsFgApp`, … plus `/com/lge/car/micom`, `/Ihu`, `/Eng`, `/Request`,
  `/app/bin/CarOption.csv`, `/etc/version.txt`, `/app/share/images/new_gui`.
  **There is no separate Home/Navi systemd unit** — `/app/bin/AppHomeScreen` is spawned by
  AppLauncher (verified: no unit in `lib/systemd/system` mentions `AppHomeScreen`, and
  `grep -rl AppHomeScreen lib/systemd/system etc/systemd/system` is empty).

### 2.2 Unit-by-unit: present, requirements, would it start now

| Component | Present? | Requires to start | Would start now? |
|---|---|---|---|
| `/usr/bin/weston` (vendor compositor) | yes (`usr/bin/weston`, 1 052 408 B) | DRM `/dev/dri/card0` + CRTC `HDMI1` at `1920x720` (ias-backend), GBM driver from `/usr/lib/mesadri`, `HOME=/etc/xdg/weston`, `/tmp/weston.ini`, `XDG_RUNTIME_DIR`, `/run/wayland`; **and** `/tmp/spi_validation_NOK` absent | **No.** Three independent stops: esinit never runs (`init:16`), the gate at `esinit:150-154` would still block it because `spi_validation` never becomes 1, and there is no DRM node (§3.7) |
| `ApplicationLauncher.service` | yes, enabled in `multi-user.target.wants` | `dbus-com.lge.car.micom.service` (`:5`), `/tmp/session_appmgr.env` (`:15`), `QT_QPA_PLATFORM=wayland` + a live compositor, `/app/share/images/new_gui` (§3.8) | **No** — `Requires=` on a unit that cannot acquire its bus name |
| `dbus-com.lge.car.micom.service` | yes, enabled | `dbus.service` + `dlt.service`; `/dev/ttyS1`; a responding MICOM peer | **No.** `dbus.service` itself needs a working NSS database: `/etc/passwd` is a **dangling symlink to `/tmp/passwd`** (`ls -l etc/passwd`), created only by `esinit:492-496`; the measured consequence is `Could not get password database information for UID of current process` and dbus refusing auth (`work/vm/vendor-userspace-260128/dbus-automount-findings.md`, "Why the original attempt died"). `/dev/ttyS1` exists only with `vm_boot.py:342-346 --micom-serial` |
| `Dbuslaunch.service` | yes, enabled | nothing beyond `/bin/bash` and a writable `/tmp` | **Yes**, if systemd ran at all. It is the cheapest unit in the chain |
| `AudioManager.service` | yes, enabled | `Requires=dbus-com.lge.car.micom.service` (`AudioManager.service:6`); `/usr/lib/audioManager/...` plugins | **No** — same micom gate; and there is no sound card (§3.4) |
| `mediamanager.service` | yes, enabled | `Requires=ApplicationLauncher.service` (`mediamanager.service:3-4`) | No (cascade) |
| `MediaBrowser.service`, `vbtd.service` | yes, enabled | `Dbuslaunch.service` / `ApplicationLauncher.service` + `/tmp/session_appmgr.env` | No (cascade) |
| `mof.service` (MOFManager) | yes, enabled | `Requires=dbus-com.lge.car.micom.service Dbuslaunch.service`; `ConditionPathExists=/tmp/country_code_{KOREA,USA,CHINA,CANADA}` or `/tmp/telematics_code_TELEMATICS` (`mof.service:11-16`) | **No and by design for EU** — the EU condition is commented out (`:15`), and the markers come only from `esinit:236-251` |
| `nua.service` (NaviUpdateApp) | yes, enabled | `ConditionPathExists=/tmp/navi_support_code_yes` (`nua.service:6`) — produced by `esinit:386-405` | No |
| `alsa-dev.path` → `alsa-dev.service` | yes | `PathExists=/dev/snd/controlC0` (`alsa-dev.path:3`) | **No** — boot log line `No soundcards found` (`appnavi-wayland-host-run.log:262`) |
| `spi-validation.path`/`.service` | yes, enabled (`multi-user.target.wants/spi-validation.path`) | `PathExists=/tmp/spi_validation_NOK`; `After=dbus-com.lge.car.micom.service` | Only after a NOK boot; the service just sends `SetETCCPUWDTReset` over D-Bus and logs (`etc/spi-validation.sh:1-10`) |
| `weston-crash.path`/`.service` | yes, enabled | `PathExists=/tmp/weston.crash` — touched by esinit **after weston exits** (`esinit:153`) | No (weston never starts) |
| `pas-daemon.service` (persistence admin) | yes (enabled via `etc/systemd/system/multi-user.target.wants/`) | `Requires=dbus.service`; `Type=notify` | Blocked by NSS/passwd; and it has no resource table to serve (§3.8) |
| `systemd-backlight@.service` | template only | a `/sys/class/backlight/*` device | No — brightness on this unit is not a backlight class device (§3.6) |

**Other HMI-relevant pieces that exist but are not units:** `usr/lib/qt5/plugins/wayland-shell-integration/libivi.so`
(the Qt IVI shell integration that assigns surface ids 1004/3000/4903), `usr/lib/weston/{ivi-shell.so,
ivi-controller.so,ivi-window-manager.so,hmi-controller.so,ias-shell.so,ias-backend.so,
gl-renderer.so}`, `usr/libexec/weston-ivi-shell-user-interface`, `usr/bin/wrandr`.

**One inert defect worth recording:** `etc/xdg/weston/weston_1920.ini:7` and `weston_1280.ini`
set `ivi-shell-user-interface=/usr/lib/weston/weston-ivi-shell-user-interface`, but that file does
not exist in the authentic tarball (`tar -tvzf mango-rootfs.tar.gz | grep usr/lib/weston` lists 16
`.so` files only); the binary is `/usr/libexec/weston-ivi-shell-user-interface`. Upstream
`hmi-controller.c` passes that string straight to `weston_client_start()`
(`work/weston-source-1.10/full/ivi-shell/hmi-controller.c:747-749,1977-1979`), so it would be an
ENOENT. It is inert here only because the configured `ivi-module` list
(`weston_1920.ini:6`) does not include `hmi-controller.so`, so the key is never read. **(verified
config vs binary; the "never read" part is inferred from the module list.)**

---

## 3. Hardware adaptors the UI expects, and what the VM would have to simulate

### 3.1 MICOM (serial + kernel SPI bridge) — the central adaptor

**What the UI needs to see.**
* A system-bus service `com.lge.car.micom` with object `/Ihu`, interface
  `com.lge.car.micom.ihu`, method `AskSysBootinfo() → ay` returning **exactly 35 bytes**; the
  consumer is AppLauncher's boot-info decoder (`work/vm/vendor-userspace-260128/micom-contract/
  BOOTINFO-AND-SIM-V2.md`, §"Exact boot-info contract"; daemon interface/path strings are in
  `app/bin/micommanager_userspace`: `/Ihu /Can /Eng /Hdr /Radio /Tmc /Tmu`, `<interface
  name="com.lge.car.micom.ihu">`, `AskSysBootinfo`, `AskSysVersion`, `AskSysUpmID`,
  `AskSysAutomaticBrightness`, `SetETCAppBootComplete`, `SetETCCPUAliveMsg`,
  `SetControlKeyLock`, `SetDIDInfo`, `AskCANMMCANMicomReq`, `SetCANMicomRecv`,
  `SetCANTPMicomRecv`, `SetCANFixedMicomRecv(ayiii)`, …).
* Its transport: `/dev/ttyS1` at 115200 8N1 raw (`strings app/bin/micommanager_userspace` contains
  `/dev/ttyS1`), plus `/sys/module/micom/parameters/hw_version`.
* The kernel half: a **built-in** driver (`lib/modules/4.1.27-abl/modules.builtin` lists
  `kernel/drivers/lge/micom/micom.ko`; boot log `MICOM I> [micom_init] Registering LGE MICOM
  interface driver`, `appnavi-wayland-host-run.log:224`) that publishes the module parameters
  esinit and the apps read: `micom.spi_validation` (`vmlinux-off 8922016`), `micom.car_type`
  (`8922536`), `micom.oem_type`, `micom.lcd_type`, `micom.country`, `micom.navi_support`,
  `micom.pcb_version`, `micom.eco_type`, `micom.optModem`, `micom.optMIC`, `micom.optHWType`,
  `micom.optNSport`, `micom.secure_console`, `micom.boot_reason`, `micom.product_id`,
  `micom.optUNECE` (full contiguous list `vmlinux-off 8922016`…`8922700`-ish).

**State in the VM (verified).**
* The parameters exist and are readable: AppHomeScreen opens
  `/sys/module/micom/parameters/pcb_version` successfully
  (`hmi-wayland-mesa18-host-run.log:3476`, `AppHomeModel::readPcbVersionFromFile() → Open file
  success`).
* They stay at their zero defaults, because the MCU side never speaks: `lge_lcd_driver
  lge_lcd_driver.0: [lge_lcd_init_func] Micom didn't sent SPI data`
  (`vmlinux-off 10967876`; first occurrence `evidence/vm-graphics/serial.log:296`, and in every
  later run, e.g. `appnavi-wayland-host-run.log:288`), preceded at boot by `No Front adapter fail`
  (`vmlinux-off 10970591`, log line 223) — no front display adapter was registered.
* With `--micom-serial` the guest does get a second 16550 (`ttyS1 at I/O 0x2f8`,
  `micom-contract/micommanager-serial-strace-host.log:206`), and `micommanager_userspace` opens it
  and sets `B115200 -opost -isig -icanon -echo` (that log's lines 306 and 308: `ioctl(8, TCGETS,
  {B9600 ...})` then `ioctl(8, TCSETS, {B115200 -opost -isig -icanon -echo ...})`).
  But **zero bytes are exchanged**
  (`"micom_serial_bytes": 0` in that run's `result.json`) and `AskSysBootinfo` never returns:
  `ASK_RC=143` (killed at the 10 s timeout) in the same log, and in a second probe
  `ASK_RC=1` with `Error org.freedesktop.DBus.Error.UnknownObject: No such object path
  '/com/lge/car/micom/Ihu'` (`micommanager-serial-ask-host.log:307-308`). **(inferred:** the
  daemon publishes `/Ihu` only once MICOM init frames have been consumed, so the object tree
  appears late or not at all.)
* Consequence chain in the real boot: `spi_validation` never leaves 0 → `/tmp/spi_validation_NOK`
  survives `esinit:25-45` → `esinit:150-154` takes the `SPI NOK` branch → **no weston**; and
  `ApplicationLauncher`'s `Requires=dbus-com.lge.car.micom.service` + a never-answering
  `AskSysBootinfo` produce the historical 8 s boot-info timeout.

**Minimal simulation that would satisfy it.**
1. Boot with `--micom-serial` (already wired: `tools/uk_fw/vm_boot.py:342-346`,
   `-device isa-serial,chardev=micom,index=1`).
2. Peers: either push MICOM framing on that chardev so the *authentic* daemon parses it (preferred;
   the daemon is the only thing that knows all 30+ method semantics), or keep the existing
   fail-closed D-Bus substitute `tools/uk_fw/guest/micom_dbus_sim.c` (owns the name, answers only
   `AskSysBootinfo` with the 35-byte payload, rejects everything else) and **do not** register
   `dbus-com.lge.car.micom.service` in the same run.
3. Separately, satisfy the esinit gates: at least `/sys/module/micom/parameters/optUNECE` is
   demonstrably writable from userspace — esinit itself writes it (`esinit:542`) — so
   `echo 1 > .../spi_validation` is a *plausible* userspace lever for the remaining parameters
   **(inferred: same module, but per-parameter permissions were not verified statically)**.

### 3.2 CAN

**What the UI needs.** A `can0` interface that a PF_CAN socket can bind, then periodic state
frames. Evidence: `/navi/Bin/CANService` contains `can0` at file offsets 59309, 59722, 1202197;
AppNavi's OSAL does `ioctl(fd, SIOCGIFINDEX, {ifr_name="can0"})` and gets `-1 ENODEV`
(`appnavi-dlt-base-map-host-run.log:1276`; same line in every strace run, e.g.
`appnavi-dlt-core-map-eglpatch-v2-host-run.log:1267`).
**State now.** No CAN netdev exists and none can be created: the kernel has `CONFIG_CAN=y`,
`CAN_RAW/BCM/GW`, but **`CONFIG_CAN_VCAN`, `CONFIG_CAN_SLCAN`, `CONFIG_CAN_MCP251X`,
`CONFIG_CAN_SJA1000`, `CONFIG_CAN_C_CAN`, `CONFIG_CAN_M_CAN`, `CONFIG_CAN_SOFTING` are all
"not set"** (`work/kbuild/vendor.config`, CAN drivers block). The M-CAN/I-CAN paths are the
vendor's own `micom_can_open`/`micom_ext_can_handle_event` (`vmlinux-off` symbol names ~`51673`),
which only come up after the MICOM link is alive. **(inferred:** `can0`/`can1` on the device are
created by the micom driver, not by a generic controller.)
**Minimal simulation.** Rebuild or extend the kernel with `CONFIG_CAN_VCAN=m` (module load works:
`CONFIG_MODULES=y`, `CONFIG_MODULE_UNLOAD=y`), create `can0`, and emit only the signals the
evidence already pins down — ignition/ACC, P/R/N/D, illumination day/night, speed — which the
existing call log already enumerates (`micom-contract/BOOTINFO-AND-SIM-V2.md`, "Observed micom
consumers and payloads": `AskCANMMCANMicomReq` 97 calls, `SetCANMicomRecv` 16 × 11-byte,
`SetCANTPMicomRecv` 85-byte, `SetCANFixedMicomRecv` IDs `0173`/`0197`).

### 3.3 GPS

**What the UI needs.** `/dev/ttyGPS` carrying NMEA; on the device this is a symlink created by
esinit (`esinit:594-602`: `ln -s ttyS3 /dev/ttyGPS` for `pcb_version != 1`), with the vendor
`lge_gps_driver` + `LGE ttyhook` netlink fan-out (`vmlinux-off` symbols `lge_gps_init_func`,
`ttyhook_netlink_broadcast`), and `com.lge.hkmc.avn.locationmanager` on D-Bus
(`strings app/bin/LocationManager`).
**State now.** No `/dev/ttyGPS` and no resolver: AppNavi logs
`open("/dev/ttyGPS", O_RDWR|O_NOCTTY|O_NONBLOCK) = -1 ENOENT` and
`[CDriverSerial::OpenSerialPort] mSerial: /dev/ttyGPS open failed, Error(2)`
(`appnavi-dlt-base-map-host-run.log:1777,3580`). The driver itself cannot probe:
`lge_gps_driver lge_gps_driver.0: err: gpio_request_array() return: (-517)`
(`appnavi-wayland-host-run.log:227`, repeated at `:248`). Navigation **continues** without GPS
(engine success is reached), so this is a function gap, not a launch gate.
**Minimal simulation.** One more `isa-serial` at index 1/3 plus the esinit-equivalent symlink
`/dev/ttyGPS`; feed GGA/RMC at 9600 or 115200 (rate is a daemon setting, unverified statically).

### 3.4 Audio

**What the UI needs.** `/dev/snd/controlC0` to make `alsa-dev.path` fire (`alsa-dev.path:3`), a
GENIVI AudioManager that starts (`AudioManager.service:10` →
`/usr/bin/AudioManager -c.../libPluginControlInterface.so -r.../routing`), and micom volume
methods (`AskSysAutomaticBrightness`, volume key lock — `micommanager_userspace` strings).
**State now.** `No soundcards found` (`appnavi-wayland-host-run.log:262`); `CONFIG_SND_HDA_INTEL`
is absent from `work/kbuild/vendor.config` (only the SND core/OSS emulation is present), and QEMU's
`-vga none -device VGA ... -nic none` config exposes no HD-Audio controller
(`tools/uk_fw/vm_boot.py:315-341`).
**Minimal simulation.** Add `CONFIG_SND_HDA_INTEL` (or the vendor's `snd_soc_skl` path referenced
in the commented `alsa-dev.path:2`) and QEMU `-device ich9-intel-hda -device hda-duplex`, or accept
that AudioManager is degraded: it is *not* a `Requires=` of the launcher, so audio loss does not
stop the HMI from being drawn (**(inferred** from the unit graph: only micom is a hard requirement).

### 3.5 Touch / input

**What the UI needs.** A seat with pointer/touch. The compositor side is `libinput` + udev
(`usr/lib/weston/ias-backend.so` links `libinput.so.10`, `libevdev.so.2`, `libmtdev.so.1`,
`libudev.so.1`), so any `/dev/input/event*` that libinput classifies is enough to obtain
`wl_seat`/`wl_pointer`/`wl_touch` — as observed (`hmi-wayland-host-run.log:4817-4847`,
`wl_seat@7.capabilities(3)`, `get_keyboard`, `get_pointer`).
On the device the panel touch is **not** an ordinary USB device: it arrives over the GMSL2 link and
is registered by the LCD driver (`vmlinux-off` strings `[%s] Register Touch device. Name:[%s],
Type:[0x%02x]`, `[%s] Fail to register touch device`, `lge_lcd_touch_work`), with `siw_touch`
(SW17700) also initialised at boot (`appnavi-wayland-host-run.log:219`).
**State now.** QEMU provides PS/2 + optional USB HID; `vm_boot.py` adds no input device by default
(`-vga none -device VGA`, `-nic none`, `-serial stdio`; `extra_devices` is opt-in, `:310-315`).
So touch is missing **and the panel-touch registration path can never run** because `lge_lcd` does
not initialise.
**Minimal simulation.** `-device usb-tablet` (or a `uinput` device with `ABS_MT_*` + `BTN_TOUCH`) so
libinput produces `wl_touch`; keep the QMP/PS-2 path for keyboard. Note that earlier work bypassed
this by patching the QML input (`work/vm/vendor-userspace-260128/qml-input-override/`), i.e. the
authentic input path has not yet been exercised.

### 3.6 Backlight

Not a `/sys/class/backlight` device on this unit. Brightness/contrast/gamma are set through a
**private Wayland protocol**: `usr/bin/wrandr` implements the ias-backend client
(`strings usr/bin/wrandr` → `ias-backend-client-protocol.h`, `ias_crtc_set_brightness`,
`ias_crtc_set_contrast`, `ias_crtc_set_gamma`, `ias_crtc_set_fb_transparency`,
`ias_crtc_set_mode`), and ApplicationManager shells out to it:
`PlatformUtils::writeBLValue []->[wrandr --crtc=1 --gamma=128:128:128 --brightness=128:128:128]`
(`micom-contract/full-chain-...-deadline-1536-evidence/launcher-chain/dlt.log:6487`).
The panel's own backlight (`lcd blu on/off`, `turn on backlight`, `Cannot find blu_on for lcd
type(%d)`) is driven by `lge_lcd` over i2c/GMSL2, i.e. after `Micom didn't sent SPI data` that
path is dead too.
**Minimal simulation.** None needed to *launch*: `wrandr` only requires that
`ias_crtc` global to exist. On a substituted compositor the call fails harmlessly. Full fidelity
requires the vendor backend (§3.7).

### 3.7 The display node — the hard one

**What the vendor compositor needs (verified):**
* `etc/xdg/weston/weston_1920.ini:1-3` → `shell=ivi-shell.so`, **`backend=ias-backend.so`**;
  `:6` → modules `ivi-window-manager.so,ivi-controller.so`; `:36-38` → output **`HDMI1`
  `mode=1920x720`**, and `:40-42` → `HDMI2` with the literal typo `mode=mode=1280x720`.
* `etc/xdg/weston/.config/ias.conf:7-15` → the backend's own XML: `raw_keyboards='0'`,
  `use_nuclear_flip='1'`, **`GBM_DRIVERS_PATH=/usr/lib/mesadri`**, and a mandatory startup CRTC
  named **`HDMI1`, model `classic`, `mode='preferred'`**, output `HDMI1-0`.
* `usr/lib/weston/ias-backend.so` is a DRM/KMS backend: undefined symbols include
  `drmModeSetCrtc`, `drmModeCreatePropertyBlob`, `drmModeObjectSetProperty`, `drmModeSetPlane`,
  `drmHandleEvent`, plus `libgbm.so.1` — so it needs a KMS device with a usable connector and a
  GBM-capable Mesa driver.
* Vendor Mesa is **11.2.1** (`strings usr/lib/libEGL.so.1.0.0` →
  `.../mesa/2_11.2.1-r3/git/src/egl/drivers/dri2/platform_drm.c`), hard-wired to
  `/dev/dri/card0` and `/usr/lib/dri` (`strings`), and the GBM driver tree is
  `usr/lib/mesadri/{i915_dri.so,i965_dri.so}` (49 MB each). `usr/lib/dri/` contains only
  `i965_dri.so`, `i965_drv_video.so` and a vendor `iu3d9_dri.so` — **no software fallback**.
* Authentic cmdline names the connector: `i915.splash=HDMI-A-1:...:1920,720,...` and
  `lge.lcd_res=1920,720 lge.lcd_type=3` (`evidence/official-package-static.md:239-244`).

**State now (verified).** No DRM device at all: the log shows only `[drm] Initialized drm 1.1.0
20060810` and then `lge_lcd`, with **zero `i915` lines** and no `card0`
(`work/vm/ec03-build/workspace/runs/1793245273391011000/serial.log:213` and neighbours; same in
`appnavi-wayland-host-run.log:214-224`). QEMU is started as `-vga none -device VGA,id=display0,
addr=01.0` (`tools/uk_fw/vm_boot.py:316`) — a Bochs-style VGA that this kernel has no KMS driver
for (`CONFIG_DRM_I915=y`, no `CONFIG_DRM_BOCHS`, no `CONFIG_DRM_VIRTIO_GPU`, no `CONFIG_FB_VESA`,
no `CONFIG_DRM_KMS` alternative in `work/kbuild/vendor.config`). `i915` never probes because no
Intel PCI display device exists in QEMU.

**How the gap has been worked around so far (and why that is not the vendor path).** Prior runs
substitute the compositor: a patched copy `work/vm/vendor-userspace-260128/weston-headless-patched`
(one-byte conditional flip at file offset `0x21c58`, `weston-headless-patch.json`) started as
`/usr/bin/weston-headless --use-pixman --width=1920 --height=720 --socket=wayland-0`
(`appnavi-wayland-host-run.log:292`, probe script `appnavi-wayland-probe.sh`). That renders into
main memory and is captured via QMP; it never exercises `ias-backend.so`, the `ias_crtc` protocol,
or scanout. A software EGL stack was assembled for the clients separately
(`work/software-egl/manifest-mesa18.json`: Mesa 18.2.8 `swrast_dri.so`, `libLLVM-6.0`, `libglapi`,
`libdrm`), because the vendor `libEGL` preloaded at `AppLauncher.sh:4` cannot find a driver.

**Minimal simulation that keeps the vendor compositor.** The missing piece is a KMS device, not a
GPU: `ias-backend.so` targets GL/GBM generically and Mesa's `kms_swrast_dri.so` (already available
in `work/software-egl/extracted/mesa18/usr/lib/x86_64-linux-gnu/dri/`, alongside
`virtio_gpu_dri.so`) can drive any DRM node without hardware. Concretely: load an out-of-tree
`drmkms` module that registers one CRTC with a connector whose name yields weston output `HDMI1`
(e.g. `HDMI-A-1`) at 1920x720 preferred; the scaffolding for exactly this already exists in the
workspace (`work/kbuild/drmkms/Makefile` → `obj-m := drmkms.o`, `-I$(srctree)/drivers/gpu/drm`;
`CONFIG_MODULES=y`, `CONFIG_DRM_KMS_HELPER=y`; `work/kbuild/bzImage-4.1.27-abl-vdisp`). Then
`Gbm`/EGL resolve through `GBM_DRIVERS_PATH` (`ias.conf:9`) to the Mesa 18 `kms_swrast` driver.
**(inferred:** that `ias-backend` accepts a non-Intel KMS node; what is verified is that it is
pure libdrm+GBM and that `ias.conf` only constrains the CRTC/output *names*, not the driver.)

### 3.8 Persistence, resources and assets (UI-visible, easy to miss)

* `/Data/mnt-wt` is a real ext4 partition on the device (`etc/fstab_emmc:17`,
  `/dev/mmcblk0p12 → /Data/mnt-wt`); the harness image has `Data/mnt-wt/mnt-wt` (empty dirs) and no
  partition. The UI's persistence client needs the resource table there, and its absence is logged
  per app:
  `[checkGroupPermissionForApp : Opening database file: < /Data/mnt-wt/shared/public/GroupContent.json > failed: No such file or directory`
  (`micom-contract/full-chain-...-deadline-1536-evidence/launcher-chain/dlt.log:583`, repeated for
  every app; same run also opens `/Data/mnt-wt/Settings/shared_public/resource-table-cfg.itz`,
  `:579`). This is a concrete reason AppHomeScreen can complete `DRAW FINISHED` and still not be
  promoted to visible (`BOOTINFO-AND-SIM-V2.md`, "Negative/remaining results").
* The shipped content for it is on disk: `app/share/hkmc.tar.gz` contains
  `resource/groups/10/GroupContent.json`, `resource/apps/Settings/resourceconfiguration.json`,
  `.../key/factoryDefaultData.json`, `.../installExceptions.json` (verified with `tar -tzf`).
  Nothing in `etc/`, `lib/systemd/` or `app/bin/*.sh` references `hkmc.tar.gz`
  (`grep -rl hkmc.tar.gz etc app/bin/*.sh lib/systemd` → empty), so the installer step that maps
  `resource/apps/*` to `/Data/mnt-wt/...` is still unidentified. **(inferred:** it is part of
  PAS/AppUpgrade rather than a boot script.)
* Theme assets are a dangling projection: `app/share/images/new_gui -> /tmp/new_gui`
  (`ls -l`, verified) and nothing in the tree creates `/tmp/new_gui`; the same asset tree exists at
  `system/new_gui/{eco3.0,new2.0}/{hmc,kmc}/{day,night}/...` (2.5 GB, merged per
  `integration-report.json`). Prior runs had to bind it manually:
  `mount -o bind /system/new_gui /tmp/new_gui` and
  `mount -o bind /system/new_gui/new2.0/hmc/night /app/share/images/hmc`
  (`micom-contract/full-chain-timeout120-legal-assets-confirm.sh:38-40`). The consumer is
  `app/lib/libImageProvider.so.1.0.0` (`/app/share/images/` + `new_gui/eco3.0/`,
  `new_gui/new2.0/`).

---

## 4. Ranked next steps, in dependency order

Each item is "make X true, prove it with Y". The order is the order in which each becomes
*testable*; items 3-4 can proceed in parallel with 2.

1. **Run the authentic init chain instead of the harness shell.**
   Boot with `init=/lib/systemd/esinit` (or a shim that reproduces exactly its outputs) so that
   `/tmp/passwd`, `/tmp/shadow`, `/tmp/fstab`, `/tmp/weston.ini` and the `*_code_*` markers exist
   and systemd becomes PID 1.
   *Proof of need:* `init:1-16` vs `tools/uk_fw/vm_boot.py:338`; `esinit:90,143,492-496,578-583`;
   `dbus.service` cannot authenticate without the account DB (`dbus-automount-findings.md`);
   `mof.service:11-16`, `nua.service:6` are gated on esinit markers.
   *Acceptance:* serial log shows `systemd 225 running in system mode`, then
   `systemctl list-units` shows `dbus.service` active and `journalctl` free of
   `User "???" unknown`.

2. **Make `com.lge.car.micom` a working bus name with a 35-byte `AskSysBootinfo`.**
   Either drive the authentic `micommanager_userspace` over `/dev/ttyS1` (needs the MICOM framing
   the daemon expects — it currently sends nothing and waits), or hold the name with the bounded
   substitute `tools/uk_fw/guest/micom_dbus_sim.c` and leave the real unit masked.
   *Proof of need:* `dbus-com.lge.car.micom.service:7-9` (`Type=dbus`, `BusName=`),
   `ApplicationLauncher.service:5` (`Requires=`), `AudioManager.service:6`,
   `micommanager_userspace` `/dev/ttyS1` + `AskSysBootinfo`, measured timeout
   (`micommanager-serial-strace-host.log`, `ASK_RC=143`, `"micom_serial_bytes": 0`), 35-byte
   contract in `micom-contract/BOOTINFO-AND-SIM-V2.md`.
   *Acceptance:* `systemctl status ApplicationLauncher` is active and AppLauncher logs the
   decoded HMC/`0x26`/Europe/12.3-inch profile instead of the 8 s timeout.

3. **Give the vendor compositor a DRM node it can bind: `card0` + `HDMI1` CRTC + GBM driver.**
   Load an out-of-tree KMS module (`work/kbuild/drmkms`) exposing a connector that renders as
   weston output `HDMI1` at 1920x720 preferred, and point `GBM_DRIVERS_PATH` at a Mesa that has
   a software GBM driver for it (Mesa 18 `kms_swrast_dri.so`, already staged in
   `work/software-egl/`).
   *Proof of need:* `weston_1920.ini:2-3,36-38`; `ias.conf:7-15`; `ias-backend.so` libdrm/GBM
   imports; `libEGL.so.1.0.0` string `/dev/dri/card0` + Mesa 11.2.1 with only `i965`/`iu3d9`
   drivers; zero `i915` lines and no `card0` in every serial log; `vm_boot.py:316` (`-vga none
   -device VGA`).
   *Acceptance:* `/dev/dri/card0` exists, then `/usr/bin/weston --tty=1` with the stock
   `weston.ini` reaches `[core] shell=ivi-shell.so` + `ias-backend` without ENOENT/EINVAL, and
   `wrandr --crtc=1 --brightness=...` succeeds (it currently cannot: `wrandr` strings
   `ias_crtc_set_brightness`, `Failed to open wayland display`).

4. **Unblock the compositor start condition and session-bus ordering.**
   Provide `/tmp/spi_validation_OK` / remove `/tmp/spi_validation_NOK` without faking the whole
   micom state (e.g. write `spi_validation=1`, or patch the gate), and fix/ignore
   `Dbuslaunch.service:4 After=micom.service` so the private bus provably exists before
   AppLauncher reads `/tmp/session_appmgr.env`.
   *Proof of need:* `esinit:25-45,150-154`; `Dbuslaunch.sh:1-13`;
   `ApplicationLauncher.service:15`; dangling `micom.service` reference.
   *Acceptance:* weston is running and `/tmp/session_appmgr.env` contains a live
   `DBUS_SESSION_BUS_ADDRESS` when AppLauncher starts.

5. **Project the persistence table and theme assets.**
   Populate `/Data/mnt-wt/{shared/public/GroupContent.json, Settings/shared_public/resource-table-cfg.itz}`
   from `app/share/hkmc.tar.gz`, and make `/tmp/new_gui` (target of
   `app/share/images/new_gui`) resolve to `system/new_gui` with the correct
   `hmc|kmc × day|night` variant.
   *Proof of need:* `fstab_emmc:17`; DLT `checkGroupPermissionForApp ... No such file or directory`
   (`.../dlt.log:583`); `app/share/images/new_gui -> /tmp/new_gui` with no creator;
   `libImageProvider.so.1.0.0` path composition; prior manual binds in
   `full-chain-timeout120-legal-assets-confirm.sh:38-40`.
   *Acceptance:* the "No such file or directory" line disappears and AppHomeScreen's surface is
   promoted to visible instead of staying on the splash frame.

6. **CAN state (`can0`).**
   Add `CONFIG_CAN_VCAN` (or reconstruct the micom CAN netdev) and emit only evidence-pinned
   signals: ignition/ACC, P/R/N/D, illumination day/night, speed.
   *Proof of need:* `navi/Bin/CANService` `can0` strings; AppNavi `SIOCGIFINDEX can0 → ENODEV`
   (`appnavi-dlt-base-map-host-run.log:1276`); `work/kbuild/vendor.config` (all CAN interfaces
   "not set"); request inventory in `micom-contract/BOOTINFO-AND-SIM-V2.md`.
   *Acceptance:* `ip link` shows `can0`; the `ENODEV` line disappears; `NotifyMCANEachMsg` traffic
   comes from real frames rather than the simulator.

7. **GPS transport.**
   Third serial port + the esinit-equivalent `/dev/ttyGPS` symlink + NMEA source.
   *Proof of need:* `esinit:594-602`; `open("/dev/ttyGPS") = -1 ENOENT`
   (`appnavi-dlt-base-map-host-run.log:1777`); `lge_gps_driver ... gpio_request_array() return:
   `(-517)` (`appnavi-wayland-host-run.log:227`).
   *Acceptance:* `mSerial: /dev/ttyGPS open failed` is gone and LocationManager publishes a fix.

8. **Input and audio adaptors (lowest risk to launch, needed for a usable HMI).**
   Add a libinput-visible touch/tablet device (`-device usb-tablet` or a `uinput` ABS_MT node) and,
   for audio, an HDA codec the vendor kernel can bind so `/dev/snd/controlC0` appears.
   *Proof of need:* `ias-backend.so` libinput/libevdev/mtdev dependency;
   `wl_seat.capabilities(3)` observed only with a patched compositor input build
   (`hmi-wayland-host-run.log:4817-4847`); panel touch registered by `lge_lcd`
   (`Register Touch device` strings) which never initialises; `alsa-dev.path:3` +
   `No soundcards found` (`appnavi-wayland-host-run.log:262`) + `CONFIG_SND_HDA_INTEL` absent.
   *Acceptance:* `wl_touch` is advertised on the stock backend and `alsa-dev.path` triggers.

---

## 5. Verified vs inferred, in one place

**Verified in the tree or in existing logs:** the authentic cmdline and `init=/lib/systemd/esinit`
(IPK header, cited above); every esinit step and marker listed in §1.1; the absence of a top-level
`/init` in the shipped tarball; the harness `/init` and its `init=/init` override; the unit graph,
`Requires=`, `Environment*`, `WantedBy=` and `ConditionPathExists=` quoted in §2; the absence of a
`weston.service`; the `weston.ini`/`ias.conf` contents; the missing
`/usr/lib/weston/weston-ivi-shell-user-interface`; Mesa/EGL/GBM driver inventory; the
`micom.*` parameter names in the kernel and their readability from the guest; `No Front adapter
fail` + `Micom didn't sent SPI data`; zero `i915`/`card0`; `SIOCGIFINDEX can0 → ENODEV`;
`/dev/ttyGPS` ENOENT; `No soundcards found`; the persistence `No such file or directory` lines;
`app/share/images/new_gui -> /tmp/new_gui`; `/etc/passwd`,`/etc/shadow`,`/etc/fstab` as dangling
`/tmp` symlinks; `dbus` NSS failure; no `systemd[1]` line in any retained serial log.

**Inferred (stated as such above):** that `micommanager_userspace` publishes `/Ihu` only after MICOM
init; that `can0`/`can1` on device come from the micom driver rather than a generic controller; that
`spi_validation` (like `optUNECE`) is writable from userspace; that `ias-backend` would accept a
non-Intel KMS node with a software GBM driver; that `hmi-controller.so` never reads the
`ivi-shell-user-interface` key in this configuration; that audio loss does not gate the launcher;
that the `/Data/mnt-wt` installer is part of PAS/AppUpgrade; and the exact serial framing/baud of
the MICOM link and the GPS feed.

---

## 6. The single biggest blocker

**There is no display device for the vendor compositor.** `weston` is launched only by
`esinit:153`, and the shipped configuration makes it `backend=ias-backend.so` with a mandatory
`HDMI1`/1920x720 CRTC (`weston_1920.ini:2-3,36-38`; `ias.conf:7-15`), i.e. a libdrm/GBM KMS client
over an Intel i915 connector, driven by Mesa 11.2.1 whose only GBM drivers are `i965`/`iu3d9`
(`usr/lib/mesadri/`). QEMU is started with `-vga none -device VGA` (`tools/uk_fw/vm_boot.py:316`)
and the vendor kernel never binds `i915` — every serial log has zero `i915` lines and no
`/dev/dri/card0` — so the authentic compositor cannot start, and with it the authentic
`ias_crtc`/`wrandr` brightness path, the panel/backlight/touch init in `lge_lcd`, and real scanout.
Everything demonstrated so far either bypassed the compositor (patched `weston-headless
--use-pixman`) or bypassed the boot chain (harness `/init` + manual D-Bus/micom substitutes), which
is why the recovered UI has been reached but not through the vendor path.
