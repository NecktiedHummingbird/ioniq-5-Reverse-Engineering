# Offline udevd-to-systemd benign-marker validation plan

## Objective

Validate one remaining V-014 downstream boundary in the exact recovered EU
`260128` userspace: whether a synthetic kernel `add` uevent handled by the
shipped `systemd-udevd` can retain a fixed second `SYSTEMD_WANTS`
property and cause PID 1 systemd to start an intentionally benign marker unit.

The result must distinguish parser retention (already established) from authentic
daemon/database/device-unit/manager activation. It is still not a physical-device
or root-access reproduction.

## Safety contract

The diagnostic is offline and disposable:

- QEMU uses `-nic none`, the canonical snapshot-backed rootfs, and no host mounts;
- all probe-created helper, rule, target, trigger, and marker units live under
  guest `/run` or `/tmp`; no firmware input is modified;
- the root filesystem is remounted read-only before handing PID 1 to systemd;
- the exact recovered `udevadm trigger` requests only one fixed `add` event for
  `/sys/class/block/mmcblk0`; a transient readiness gate makes this existing VM
  device model a new-device transition for the matched control;
- the synthetic helper emits only fixed benign values:
  `ID_SCSI_SERIAL=V014_SYSTEMD_CONTROL` and, in the positive run,
  ` SYSTEMD_WANTS=v014-benign-marker.service`;
- the marker unit may only invoke BusyBox `touch` and `echo` with fixed paths/text;
- `debug-shell.service`, existing unit names, `REMOVE_CMD`, interactive shells,
  payloads, persistence, network access, host-root operations, and privilege
  transitions are forbidden;
- shipped vulnerable `scsi_id`/`v4l_id` rules are shadowed by transient
  `/run/udev/rules.d/* -> /dev/null` masks before coldplug, and the helpers are
  not executed;
- success must never be described as physical exploitability or owner-vehicle
  applicability.

## Design

Add a bounded tool, `tools/uk_fw/udev_systemd_probe.py`, with focused tests.
It will:

1. host-verify the five canonical VM artifacts against fixed hashes and verify
   exact guest hashes for `/lib/systemd/systemd`,
   `/lib/systemd/systemd-udevd`, and `/bin/udevadm`;
2. run a matched negative control without a second property and a positive run
   with the fixed benign second `SYSTEMD_WANTS` property;
3. use the research PID-1 shell only to mount `/run` and `/tmp` as tmpfs, create
   fixed transient runtime files, remount `/` read-only, and `exec` the shipped
   systemd as PID 1;
4. boot a minimal transient target with default dependencies disabled on top of
   the installed `sysinit.target` (ordinary sysinit/coldplug activity remains),
   shadow the two vulnerable installed helper rules, start the shipped udev daemon,
   wait for coldplug completion, arm a transient readiness gate, and request
   one fixed `add` uevent for the existing emulated block device;
5. leave the marker unit disabled/unwanted except through the device property;
6. stop each VM on exact, fail-closed serial completion markers rather than a
   shell return marker;
7. emit canonical sorted-key JSON with per-run provenance and conservative
   classifications.

A minimal extension to `tools/uk_fw/vm_boot.py` is allowed only if needed to
support an exact caller-selected serial completion marker after PID-1 handoff.
It must preserve all existing default behavior and record whether that marker was
observed. Do not add arbitrary init choices or network/device access.

## Required controls

- Positive run: exact daemon and manager hashes, exact begin/end framing, uevent
  trigger evidence, imported benign property evidence, marker unit start evidence,
  fixed marker output, and no forbidden marker.
- Negative run: same boot/daemon/uevent route but no second property; marker unit
  must not start and the observation service must report marker absence.
- Any duplicate/malformed/out-of-order markers, unexpected unit, hash mismatch,
  timeout before an exact completion frame, or contradictory result fails closed.
- Tests must prove the generated guest scripts contain no shipped shell-unit name,
  no network command, no `REMOVE_CMD`, and no writable persistent output path.

## Evidence boundary

A positive/negative matched result may establish:

- exact shipped udevd processes the synthetic kernel event;
- the second property survives into the udev/device-unit path;
- exact PID 1 systemd requests and executes the benign marker unit.

It does not establish:

- hardware-controlled bytes reaching shipped helpers;
- behavior of a physical USB/SCSI device or production port;
- activation of `debug-shell.service`, a root command, interactivity, persistence,
  or applicability to unknown installed firmware.

## Acceptance

- focused tests pass;
- canonical full test suite passes;
- both matched VM runs complete without network or host mounts;
- positive classification is activation confirmed and negative classification is
  marker absent;
- canonical rootfs SHA-256 remains
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`;
- `e2fsck -fn` passes unchanged;
- reviewed evidence and documentation preserve the static-versus-dynamic and
  VM-versus-physical boundaries;
- only reviewed summaries are tracked; complete logs stay under ignored `work/`.
