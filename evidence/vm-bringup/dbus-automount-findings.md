# dbus-daemon + /app/bin/usb-automount in the emulated vendor userspace

Guest: `work/vm/vendor-userspace-260128` (EU 260128), booted via `tools/uk_fw/vm_boot.py`
(`compat=True`, 1536 MiB, no extra devices). Driver: `dbus-automount-probe.py` (stages 1, 1b, 1c, 2a, 3, 4).

## Why the original attempt died
Two independent gaps, both in the image, neither of them a config-file problem:

1. `/etc/passwd` is a **dangling symlink** to `/tmp/passwd` (and `/tmp` is a fresh tmpfs per boot).
   Consequence: every NSS lookup fails — `Could not get password database information for UID of
   current process: User "???" unknown` and `Unknown username "root" in message bus configuration file`.
2. `/etc/machine-id` exists but is **0 bytes**. Not fatal for dbus 1.8.20: the daemon still derived a
   bus GUID (`unix:path=/run/dbus/system_bus_socket,guid=d6763f9c5f08ff5916c936a500000004`).

`/etc/dbus-1/system.conf` is present and usable as-is (no `/usr/share/dbus-1/system.conf` in the image —
that is the normal vendor layout, not a defect).

## Observed results
| Run | Setup | dbus-daemon | usb-automount |
|---|---|---|---|
| 1b | stock `--system`, no /tmp/passwd | dies, exit 1, no socket | n/a |
| 4 | minimal root-owned /tmp config, no /tmp/passwd | **starts, listens**, but auth fails | dies in ~3 s, `dbus_connection_send()` assertion (same crash as stock boot) |
| 1c/2a/3 | stock `--system`, /tmp/passwd present | **starts**, drops to `messagebus`, socket 0777 | **alive 60 s**, owns `com.lge.car.automount` |

Stage 3 (60 s, stock bus): 12/12 liveness polls `alive=yes`, `/proc/<pid>/stat` state `S`,
`ListNames` → `com.lge.car.automount`, stderr only
`QDBusConnection: system D-Bus connection created before QCoreApplication. Application may misbehave.`
No other error text. Bus stderr only warns about vendor accounts `byungsu`/`xuser` (non-fatal).

Control (stage 4) proves the passwd database, not machine-id or policy, is the decisive piece:
authentication needs a UID→name map, so with no `/tmp/passwd` the client handshake fails while the
daemon itself is healthy.

## Harness note
Launching `usb-automount` in the background *without* `</dev/null` hangs the guest shell (no output for
the full timeout, `VM_COMMAND_END` never printed). `/usr/bin/setsid ... </dev/null` avoids it.

## Reproduce
```
/opt/homebrew/bin/python3.13 work/vm/vendor-userspace-260128/dbus-automount-probe.py 3
```
(homebrew python3.14 is broken on this host: `posix_spawn: ... Undefined error: 0`; use python3.13.)

Guest-side changes were confined to `/tmp` and `/run`; the ext4 image is untouched.
