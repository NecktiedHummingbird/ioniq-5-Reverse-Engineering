# V-006 dynamic attempt — MTP branch reached, injection neutralised by udev

Date: 2026-10-30. Guest: `work/vm/vendor-userspace-260128` (EU 260128), `tools/uk_fw/vm_boot.py`
(`compat=True`, 1536 MiB). Driver: `v006-injection-probe.py` (stages `discover`, `exploit`, `port`,
`port` + positive control). QEMU 11.1.2, `ich9-usb-uhci1` + `usb-mtp`.

## Device model used
`-device ich9-usb-uhci1,id=uhci0 -device usb-mtp,bus=uhci0.0,rootdir=<project>/v006-mtp-store,serial=<payload>`

The device enumerates on UHCI as `46f4:0004` with the serial read back verbatim, and it presents a
still-image interface:

```
/sys/bus/usb/devices/1-1:1.0/bInterfaceClass    = 06
                                  bInterfaceSubClass = 01
                                  bInterfaceProtocol = 01
modalias = usb:v46F4p0004d0000dc00dsc00dp00ic06isc01ip01in00
/devices/pci0000:00/0000:00:02.0/usb1/1-1
```

`usb-mtp` needs `rootdir`; without it QEMU refuses the device. Enumeration needs ~5-15 s after
`uhci-hcd` loads (a first attempt that read sysfs immediately saw only `usb1`).

## Chain executed (stage `port`, run 1793334923737493000)
1. `modules-load` usbcore/uhci-hcd/usbserial; device appears as `1-1`.
2. `/etc/passwd` (symlink to `/tmp/passwd`) populated with root + messagebus.
3. `/etc/usb-automount.conf` replaced by a **bind mount of a `/tmp` copy** whose `[port]` entries all
   name the emulated device's real devpath (`/devices/pci0000:00/0000:00:02.0/usb1/1-1`). The shipped
   file names `0000:00:15.0` connectors, and `usb-automount` matches the connector by exact devpath
   (0x3850 strstr classify, 0x3950 strcmp), so without this the MTP branch is skipped. Only `/tmp`
   and `/run` were written; the ext4 image is a snapshot.
4. `systemd-udevd` started, then `dbus-daemon --system`, then `/app/bin/usb-automount` (setsid, `</dev/null`).
5. Three synthetic `echo add > /sys/bus/usb/devices/1-1/uevent` events (udevd runs `usb_id`, then
   broadcasts to the automounter's libudev monitor; there is no coldplug enumeration in the binary).

## Results
1. **ID_USB_INTERFACES = `:060101:` — yes.** Verified two ways: sysfs interface class above, and the
   udev database `/run/udev/data/c189:1` after the trigger.
2. **MTP branch taken — yes.** `/tmp/probe/ua.err` contains one line per triggered add event:
   `sh: /usr/bin/go-mtpfs: No such file or directory` (x3). That string can only come from the
   `system()` at 0x535f reached through 0x44c3 (interface check) -> 0x4710 -> 0x3d00 action=="add" -> 0x5280.
3. **Injected command executed — no.** No `/tmp/v006.id`; no `V006KMSG` in dmesg. The automounter's
   own shell error is present, so the shell ran but with an inert command line.

## Blocking cause (single)
udev delivered a **sanitised** `ID_SERIAL_SHORT`:

```
payload (serial):  a;id>/tmp/v006.id;echo${IFS}V006KMSG>/dev/kmsg;#
udev property:     a_id__tmp_v006.id_echo__IFS_V006KMSG__dev_kmsg_#
```

`udevadm info` + `/run/udev/data/c189:1` show the same value in `ID_SERIAL_SHORT` and `ID_SERIAL`.
A character-set probe (run 1793334502494966000, serial `Aa0 !"#$%&'()*+-./:;<=>?@[\]^_`{|}~`) gives
the exact surviving set: **alphanumerics plus `# + - . : = @ _`**; every other printable byte becomes
`_` (`;` `>` `/` `$` `{` `}` `(` `` ` `` `|` `&` `~` `<` `?` `[` `]` `^` `\` `'` `"` `*` `%` `!` `,`).
The literal allow-list string `#+-.:=@_` is present in both `/lib/libudev.so.1.6.4` and
`/lib/systemd/systemd-udevd`.

So this image applies a **second, allow-list sanitiser** to builtin udev properties, on top of the
`util_replace_whitespace` call that the V-006 static analysis accounted for. Nothing in the surviving
set can create a second command, a redirect or an expansion; `${IFS}` cannot even be expressed (`$`
and braces are replaced).

## Positive control (payload validity, not exploitation)
The identical string executed directly by the guest's `/bin/sh` (i.e. exactly the command that
`system()` would have received had the serial reached it unsanitised):

```
/usr/bin/go-mtpfs --dev a;id>/tmp/v006control.id;echo${IFS}CONTROLKMSG>/dev/kmsg;# ...
-> /tmp/v006control.id : uid=0(root) gid=0(root)     (dmesg CONTROLKMSG count = 1)
```

This proves the payload syntax, `/dev/kmsg` writes and the uid-0 shell all work in this guest; the
only difference between it and the automounter's line is udev's sanitiser.

## Corrections this implies for the register
- V-006's "encoding constraints" section is incomplete: `util_replace_whitespace` is not the last
  transformation. The value handed to `udev_device_get_property_value(dev, "ID_SERIAL_SHORT")` is
  reduced to `[A-Za-z0-9#+-.:=@_]`, so the injection string cannot be formed at all on this image.
- The register's claim that `; $ ( ) ` | & ' " < > * ? # ! { } /` "survive into ID_SERIAL_SHORT"
  is contradicted by runtime evidence; the "shell parses the whole line before exec" argument and the
  "`${IFS}` defeats the filter" argument therefore do not establish exploitability on 260128.
- Suggested restatement: static defect (unquoted `system()`/`popen()` with device-derived data) still
  real; runtime exploitation **not demonstrated and currently blocked** by the udev property
  allow-list. Confidence that the source-level bug is genuine is unchanged; only reachability via this
  input path is refuted.

## Reproduce
```
/opt/homebrew/bin/python3.13 work/vm/vendor-userspace-260128/v006-injection-probe.py port
```
(default serial = the payload above; an optional second argument overrides it). Runs: 1793334207675115000
(failed QEMU, no rootdir), 1793334237293217000 / 1793334276767100000 (enumeration timing, EHCI),
1793334399858263000 (first exploit attempt), 1793334502494966000 (charset probe), 1793334664199165000 /
1793334739067491000 (config port mapping), 1793334849056622000, 1793334923737493000 (final + control).
