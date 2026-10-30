#!/usr/bin/env python3
"""Verify benign multi-line udev IMPORT output in the offline recovered VM.

The probe runs only ``udevadm test`` with a fixed temporary rule and synthetic
helper. It never starts udevd or systemd, sends no kernel uevent, names no
existing service, and performs no privilege-changing action. A successful run
proves only that the exact recovered udev parser retains a second benign
property from line-oriented IMPORT{program} output.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

import vm_boot

EXPECTED_UDEVADM_SHA256 = (
    "b3d0274757f9ded9260f22a629da22e1e06ef0f6c750293b317e09810c93692b"
)
EXPECTED_UDEVD_SHA256 = (
    "f32f6296ea20d959ac046ae80724f39e317aaaf492a5c7eedd9270b5b2abab0d"
)
BENIGN_SERIAL = "V014_BENIGN_CONTROL"
BENIGN_UNIT = "v014-benign-nonexistent.service"
GUEST_TARGET = "/sys/class/block/mmcblk0"
MARKER_RE = re.compile(r"^UDEV_IMPORT_[A-Z0-9_]+(?:=.*)?$")
EXPECTED_WORKSPACE_SHA256 = {
    "bzImage": "85e0086202758117015437a5ce7b580d7d32484807d1953c3a16e571f65f3f59",
    "rootfs.img": "4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f",
    "manifest.bin": "d282155bfed37b20a7222bb3e9d21a7c8618eaab88f7644f5770f35bdd90ef2d",
    "seed_dev.bin": "a5112d84e63962066e1d2ad290e0a9f1f2e806c56df15b6a10681aa532ecd7ca",
    "seed_user.bin": "9706e118d96d4ac08ee34ff276330d01db646aeb5356cd88ea8ef05099f9c50c",
}
BEGIN_MARKER = "UDEV_IMPORT_PROBE_BEGIN"
COMPLETE_MARKER = "UDEV_IMPORT_PROBE_COMPLETE"
PASS_MARKERS = (
    f"UDEV_IMPORT_UDEVADM_SHA256={EXPECTED_UDEVADM_SHA256}",
    f"UDEV_IMPORT_UDEVD_SHA256={EXPECTED_UDEVD_SHA256}",
    f"UDEV_IMPORT_TARGET={GUEST_TARGET}",
    "UDEV_IMPORT_TEST_RC=0",
    f"UDEV_IMPORT_ID_SCSI_SERIAL={BENIGN_SERIAL}",
    f"UDEV_IMPORT_SYSTEMD_WANTS={BENIGN_UNIT}",
    "UDEV_IMPORT_HELPER_REMOVED=1",
    "UDEV_IMPORT_RULE_REMOVED=1",
    "UDEV_IMPORT_LOG_REMOVED=1",
    COMPLETE_MARKER,
)
EXPECTED_SEQUENCE = (BEGIN_MARKER,) + PASS_MARKERS


def validate_output(output: Path, workspace: Path) -> Path:
    """Require a new project-local directory disjoint from the VM workspace."""
    resolved = vm_boot.project_output(output)
    workspace = vm_boot.project_output(workspace)
    if resolved.is_relative_to(workspace) or workspace.is_relative_to(resolved):
        raise ValueError("output directory must not alias or contain the VM workspace")
    if resolved.exists():
        raise ValueError("output directory already exists")
    return resolved


def verify_exact_workspace(workspace: Path) -> dict[str, str]:
    """Host-verify every guest-affecting prepared artifact against fixed hashes."""
    vm_boot.verify_workspace(workspace)
    metadata = json.loads((workspace / "prepare.json").read_text())
    actual_manifest = metadata.get("sha256")
    if actual_manifest != EXPECTED_WORKSPACE_SHA256:
        raise ValueError("workspace artifacts do not match the approved recovered VM")
    return dict(actual_manifest)


def guest_script() -> str:
    """Return the fixed parser-only guest diagnostic."""
    return f"""export PATH=/bin:/sbin:/usr/bin:/usr/sbin
BB=/bin/busybox
probe_main() {{
echo UDEV_IMPORT_PROBE_BEGIN
UDEVADM_SHA=$($BB sha256sum /bin/udevadm | $BB cut -d' ' -f1)
UDEVD_SHA=$($BB sha256sum /lib/systemd/systemd-udevd | $BB cut -d' ' -f1)
echo UDEV_IMPORT_UDEVADM_SHA256=$UDEVADM_SHA
echo UDEV_IMPORT_UDEVD_SHA256=$UDEVD_SHA
[ "$UDEVADM_SHA" = "{EXPECTED_UDEVADM_SHA256}" ] || {{ echo UDEV_IMPORT_UDEVADM_HASH_MISMATCH; return 20; }}
[ "$UDEVD_SHA" = "{EXPECTED_UDEVD_SHA256}" ] || {{ echo UDEV_IMPORT_UDEVD_HASH_MISMATCH; return 21; }}
TARGET={GUEST_TARGET}
echo UDEV_IMPORT_TARGET=$TARGET
[ -d "$TARGET" ] || {{ echo UDEV_IMPORT_TARGET_MISSING; return 22; }}
for unitdir in /etc/systemd/system /run/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
    [ ! -e "$unitdir/{BENIGN_UNIT}" ] && [ ! -L "$unitdir/{BENIGN_UNIT}" ] || {{ echo UDEV_IMPORT_UNIT_UNEXPECTEDLY_EXISTS; return 23; }}
done
HELPER=/tmp/v014-benign-helper
RULE=/run/udev/rules.d/00-v014-benign-import.rules
LOG=/tmp/v014-udevadm-test.log
for temp_path in "$HELPER" "$RULE" "$LOG"; do
    [ ! -e "$temp_path" ] && [ ! -L "$temp_path" ] || {{ echo UDEV_IMPORT_TEMP_PATH_EXISTS; return 24; }}
done
$BB mkdir -p /run/udev/rules.d
cat > "$HELPER" <<'EOF_HELPER'
#!/bin/busybox sh
printf '%s\\n' 'ID_SCSI_SERIAL={BENIGN_SERIAL}' ' SYSTEMD_WANTS={BENIGN_UNIT}'
EOF_HELPER
$BB chmod 0700 "$HELPER"
cat > "$RULE" <<'EOF_RULE'
ACTION=="change", SUBSYSTEM=="block", KERNEL=="mmcblk0", IMPORT{{program}}="/tmp/v014-benign-helper"
EOF_RULE
/bin/udevadm test --action=change "$TARGET" > "$LOG" 2>&1
RC=$?
echo UDEV_IMPORT_TEST_RC=$RC
if $BB grep -Fx 'ID_SCSI_SERIAL={BENIGN_SERIAL}' "$LOG" >/dev/null; then
    echo UDEV_IMPORT_ID_SCSI_SERIAL={BENIGN_SERIAL}
else
    echo UDEV_IMPORT_ID_SCSI_SERIAL_MISSING
fi
if $BB grep -Fx 'SYSTEMD_WANTS={BENIGN_UNIT}' "$LOG" >/dev/null; then
    echo UDEV_IMPORT_SYSTEMD_WANTS={BENIGN_UNIT}
else
    echo UDEV_IMPORT_SYSTEMD_WANTS_MISSING
fi
echo UDEV_IMPORT_RAW_BEGIN
$BB grep -E 'ID_SCSI_SERIAL|SYSTEMD_WANTS|v014-benign-helper|00-v014-benign' "$LOG" | $BB head -n 40
echo UDEV_IMPORT_RAW_END
$BB rm -f "$HELPER" "$RULE" "$LOG"
[ ! -e "$HELPER" ] && [ ! -L "$HELPER" ] && echo UDEV_IMPORT_HELPER_REMOVED=1
[ ! -e "$RULE" ] && [ ! -L "$RULE" ] && echo UDEV_IMPORT_RULE_REMOVED=1
[ ! -e "$LOG" ] && [ ! -L "$LOG" ] && echo UDEV_IMPORT_LOG_REMOVED=1
[ "$RC" -eq 0 ] || return 25
echo UDEV_IMPORT_PROBE_COMPLETE
}}
probe_main
"""


def probe_frame(serial: str) -> tuple[list[str], bool]:
    """Return one exact runtime frame and whether it has one ordered end marker."""
    lines = serial.splitlines()
    starts = [index for index, line in enumerate(lines) if line == BEGIN_MARKER]
    ends = [index for index, line in enumerate(lines) if line == COMPLETE_MARKER]
    if len(starts) != 1 or len(ends) != 1:
        return [], False
    start, end = starts[0], ends[0]
    if end <= start:
        return [], False
    return lines[start:end + 1], True


def salient_lines(serial: str, limit: int = 100) -> list[str]:
    frame, _ = probe_frame(serial)
    return [line[:1000] for line in frame if MARKER_RE.fullmatch(line)][:limit]


def classify(serial: str, result: dict[str, Any]) -> str:
    if result.get("timeout"):
        return "timeout"
    if result.get("error") or not result.get("userspace") or not result.get("root_mounted"):
        return "harness-error"
    raw_lines = serial.splitlines()
    global_markers = [line for line in raw_lines if MARKER_RE.fullmatch(line)]
    if any(line.endswith("_HASH_MISMATCH") for line in global_markers):
        return "artifact-mismatch"
    frame, complete = probe_frame(serial)
    marker_lines = [line for line in frame if MARKER_RE.fullmatch(line)]
    if global_markers != marker_lines:
        return "harness-error"
    if any(
        line.startswith("UDEV_IMPORT_") and not MARKER_RE.fullmatch(line)
        for line in frame
    ):
        return "harness-error"
    if not complete:
        return "harness-error"
    if (
        "UDEV_IMPORT_ID_SCSI_SERIAL_MISSING" in marker_lines
        or "UDEV_IMPORT_SYSTEMD_WANTS_MISSING" in marker_lines
    ):
        return "parser-rejected"
    failure_tokens = (
        "_MISSING",
        "_MISMATCH",
        "_UNEXPECTEDLY_EXISTS",
        "_TEMP_PATH_EXISTS",
        "_FAIL",
    )
    if any(any(token in line for token in failure_tokens) for line in marker_lines):
        return "harness-error"
    positions: list[int] = []
    for marker in EXPECTED_SEQUENCE:
        if marker_lines.count(marker) != 1:
            return "harness-error"
        positions.append(marker_lines.index(marker))
    if (
        result.get("command_exit_code") == 0
        and positions == sorted(positions)
    ):
        return "benign-second-property-retained"
    return "harness-error"


def newest_run(workspace: Path, before: set[Path]) -> Path:
    runs = workspace / "runs"
    candidates = [path for path in runs.iterdir() if path.is_dir() and path not in before]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one new VM run directory, got {len(candidates)}")
    return candidates[0]


def run_probe(
    workspace: Path, output: Path, timeout: float, memory_mib: int
) -> tuple[dict[str, Any], int]:
    workspace = vm_boot.project_output(workspace)
    workspace_hashes = verify_exact_workspace(workspace)
    output = validate_output(output, workspace)
    output.mkdir(parents=True)
    runs = workspace / "runs"
    before = set(runs.iterdir()) if runs.exists() else set()
    rc = vm_boot.run(
        workspace,
        True,
        guest_script(),
        timeout=timeout,
        memory_mib=memory_mib,
    )
    run_dir = newest_run(workspace, before)
    result_path = run_dir / "result.json"
    result = json.loads(result_path.read_text()) if result_path.exists() else {}
    serial_path = run_dir / "serial.log"
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    report = {
        "schema": 1,
        "scope": "benign udev IMPORT parser diagnostic; no daemon, unit activation, or uevent",
        "network": "disabled by vm_boot (-nic none)",
        "workspace": str(workspace.relative_to(vm_boot.PROJECT)),
        "run_directory": str(run_dir.relative_to(vm_boot.PROJECT)),
        "workspace_artifacts": workspace_hashes,
        "expected_artifacts": {
            "/bin/udevadm": EXPECTED_UDEVADM_SHA256,
            "/lib/systemd/systemd-udevd": EXPECTED_UDEVD_SHA256,
        },
        "synthetic_properties": {
            "ID_SCSI_SERIAL": BENIGN_SERIAL,
            "SYSTEMD_WANTS": BENIGN_UNIT,
        },
        "guest_target": GUEST_TARGET,
        "classification": classify(serial, result),
        "vm_return_code": rc,
        "vm_result": result,
        "salient_lines": salient_lines(serial),
        "limitations": [
            "The vulnerable recovered helpers were not executed.",
            "No udev daemon, kernel uevent, or systemd manager handled the properties.",
            "Success proves parser retention only, not unit activation or root access.",
            "VM behavior does not prove physical hardware or installed-device behavior.",
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    (output / "udev-import-probe.json").write_text(rendered)
    return report, rc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--memory-mib", type=int, default=1024)
    args = parser.parse_args(argv)
    if not 30 <= args.timeout <= 300:
        parser.error("--timeout must be between 30 and 300 seconds")
    if not 256 <= args.memory_mib <= 8192:
        parser.error("--memory-mib must be between 256 and 8192")
    try:
        report, _ = run_probe(args.workspace, args.output, args.timeout, args.memory_mib)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["classification"] == "benign-second-property-retained" else 1


if __name__ == "__main__":
    raise SystemExit(main())
