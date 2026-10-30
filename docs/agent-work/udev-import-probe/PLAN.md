# Bounded udev import probe plan

## Objective

Add a deterministic offline VM diagnostic that verifies how the exact recovered
udev rule engine handles multi-line `IMPORT{program}` output. The diagnostic must
use only fixed benign properties and an intentionally nonexistent marker unit.
It closes one parser/transport step without starting systemd units, changing
privilege, or claiming physical-device behavior.

## Security contract

- Offline QEMU only; no NIC or host mounts.
- Canonical rootfs remains snapshot-backed and hash-verified.
- Do not invoke `debug-shell.service`, `/bin/sh` as a service, `REMOVE_CMD`, or
  any existing unit.
- Do not emulate malicious hardware or execute recovered vulnerable helpers.
- The synthetic helper may emit only:
  - `ID_SCSI_SERIAL=V014_BENIGN_CONTROL`;
  - raw second line ` SYSTEMD_WANTS=v014-benign-nonexistent.service` (one
    leading ASCII space, matching the advisory's relevant output shape), with
    expected parsed property `SYSTEMD_WANTS=v014-benign-nonexistent.service`.
- Use `udevadm test --action=change` against an existing disposable guest block
  sysfs path. Do not send a kernel uevent and do not run a udev daemon.
- Treat success only as evidence that the exact udev parser splits and retains
  the second property. It is not evidence of systemd activation, root access,
  physical hotplug behavior, or installed-device applicability.
- Keep complete logs/generated files under ignored `work/`; track only code,
  tests, plan/checkpoint, and a reviewed minimal excerpt after acceptance.

## Implementation bundle

Add:

- `tools/uk_fw/udev_import_probe.py`;
- `tests/test_udev_import_probe.py`.

The tool should follow existing `vm_boot` probe conventions:

1. accept a project-local workspace and output directory;
2. reject output aliasing, pre-existing output directories, and unsupported
   workspace artifacts through existing `vm_boot` validation;
3. build a fixed guest script—no caller-controlled property names, values,
   commands, service names, or sysfs paths;
4. verify exact shipped `udevadm` and `systemd-udevd` hashes before testing;
5. select the expected guest block path only from a fixed allowlist such as
   `/sys/class/block/mmcblk0` and fail closed otherwise;
6. install the synthetic helper and one uniquely named temporary rule beneath
   `/run/udev/rules.d`;
7. run bounded `udevadm test --action=change`, capture output, and remove the
   temporary rule/helper inside the disposable guest;
8. emit canonical sorted-key JSON with artifact hashes, salient lines, VM
   result, classification, and explicit per-run provenance (run directory and
   elapsed time are expected to vary between equivalent runs);
9. classify only when both benign properties and explicit begin/end markers are
   present and the VM command exits zero.

## Tests

Cover at minimum:

- guest script contains the two exact benign outputs;
- guest script does not contain `debug-shell`, `REMOVE_CMD`, a service-start
  command, or a daemon invocation;
- workspace/output path safety and fixed exact hashes;
- successful fixture classification;
- missing second property, timeout, hash mismatch, and missing completion marker
  classifications;
- deterministic salient-line extraction, stable JSON schema, and canonical
  serialization of each per-run report.

## Acceptance

- Focused tests and `py_compile` pass.
- `git diff --check` passes.
- One bounded VM run completes without a kernel fault or persistent rootfs
  change.
- Canonical rootfs SHA-256 remains unchanged and `e2fsck -fn` passes.
- Documentation states the parser-only boundary without upgrading V-014 to a
  dynamic root finding.
