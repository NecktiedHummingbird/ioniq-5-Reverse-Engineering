# USB root-access test plan (owner-authorised, physical unit)

Scope: the owner's own head unit. Everything here is a lab procedure for their
hardware. It is **not** published to the public repository; that mirror carries the
status-only V-006 entry.

Build: EU Gen5W Linux `NE_E.EUR.S5W_L.001.001.260128`, kernel `4.1.27-abl`, x86-64.

## Vector A — serial-string command injection (V-006). Primary.

### Why it is the best candidate

`/app/bin/usb-automount` runs as **uid 0** (its unit has no `User=`) and builds a shell
command from the USB `iSerialNumber`:

```
0x5326  __sprintf_chk(cmd, …, "%s %s %s %s &", "/usr/bin/go-mtpfs", "--dev",
                      ID_SERIAL_SHORT, "/media/mtp/<ID_SERIAL_SHORT>")
0x535f  system(cmd)
0x53b9  popen("cat /proc/mounts | grep %s", …)          // same string
```

The branch is taken when `ID_USB_INTERFACES` contains `060101` (PTP) or `ffff00`
(vendor-specific), tested at `0x44c3`–`0x44cf`.

### Filters, and why they do not stop it

| Filter | Effect |
| --- | --- |
| `usb_id` sanitiser (`util_replace_whitespace`, `0x22b72`) | only the `_ISspace` ctype bit is tested — **whitespace alone** becomes `_` |
| serial charset (`0x1c2df`) | bytes `0x20`–`0x7f` accepted, **comma `0x2c` rejected** |
| descriptor length | 126 UTF-16 code units ≈ 126 ASCII characters |

So: no spaces, no commas — use `${IFS}`. `${`, `}`, `$`, `/`, `;`, `#`, `'`, `>` all
survive.

### Validated payloads

Checked against both filters (length and charset):

```
;id>/dev/kmsg;#                                   15 chars   proof of execution
;echo${IFS}root::20481:0:99999:7:::>/etc/shadow;#  49 chars   credential overwrite
```

The second is the useful one. `/etc/shadow` is a **symlink to `/tmp/shadow`**, and
`esinit` populates that from `/etc/shadow.Global` at boot, so writing the file takes
effect immediately. The field layout above matches the shipped
`root:…:20481:0:99999:7:::` exactly, with an empty hash field — `login` is built
without PAM, and an empty field means no password required.

`/etc/passwd` is likewise `/tmp/passwd`, populated from `passwd.legacy`, which already
gives `root … /bin/sh`.

### Two-stage result

1. USB device delivers the payload → root command runs → `/etc/shadow` replaced.
2. Log in on the **serial console** (`ttyS2`, 115200 8N1, root login already permitted
   by `/etc/securetty`) with no password → interactive root.

### Reversibility

`/tmp` is tmpfs. The credential change disappears on reboot; nothing persistent is
written by the USB path itself. That makes this safe to try and easy to undo.

### Hardware

**ESP32-S3 with native USB (TinyUSB)** is the right tool, because the trigger needs an
**arbitrary interface class**, not a standard gadget:

- required: one interface with class/subclass/protocol `06/01/01` (PTP) **or**
  `ff/ff/00` (vendor-specific)
- required: a custom `iSerialNumber` string containing the payload

A Raspberry Pi Zero in USB-gadget mode **cannot do this** with configfs: its stock
functions present `02/06/00` (ECM), `02/02/01` (ACM) or `08/06/50` (mass storage), none
of which match either branch condition. Faking a vendor-specific class needs a custom
kernel function. TinyUSB supplies descriptors verbatim, so the ESP32-S3 does it with a
descriptor table and no kernel work.

The device does **not** need to implement MTP. The branch only inspects the interface
string, then builds and runs a shell command; `go-mtpfs` is absent from the image and
the shell parses the line anyway.

### Pre-flight in the VM (recommended first)

Pass the ESP32 through to QEMU with `-device usb-host,vendorid=…,productid=…` and run
the authentic image. That exercises the real `usb-automount`, real udev, real kernel and
the real payload path before the car is involved. The only thing untested is the
physical port and its power.

## Vector B — media parsing as root (V-007). No known bug.

Media scanning, indexing, playback and metadata extraction all run as uid 0 with no
sandbox, so any parser memory-safety defect would be root. No such defect has been
identified, so this is a fuzzing target rather than a usable entry today. Worth keeping
in the list, not worth trying first.

## Vector C — USB Ethernet. Supported, but not useful alone.

The kernel has `CONFIG_USB_NET_CDCETHER=m`, so a CDC-ECM gadget gives the unit a network
interface. But the image ships **no DHCP client** (`udhcpc`, `dhclient`, `dhcpcd`,
`connman`, `systemd-networkd`, `NetworkManager` all absent) and **no remote-login
daemon** (`dropbear` not installed, no `sshd`, no `telnetd`). A network interface with
nothing listening and no address is not a foothold. Skip unless combined with something
else.

## What is still unproven

- The injection is **statically confirmed only**. It has not been executed on the unit,
  nor yet in the VM with a real device.
- Whether the head unit's USB port supplies enough current for the chosen board.
- Whether the MTP branch fires on device insertion in every boot state, or only once the
  automount service is up.
- Empty-password root login is expected to be accepted by the non-PAM `login`, but that
  is reasoning from the binary, not an observed login.

## Suggested order of work

1. Flash an ESP32-S3 with the vendor-specific interface and the `;id>/dev/kmsg;#`
   proof-of-execution serial. Observe via UART if available.
2. If proof appears, switch the serial to the shadow-overwrite payload and log in on
   `ttyS2`.
3. Only if (1) fails, investigate boot-state timing, port power, or the interface
   descriptor shape.
