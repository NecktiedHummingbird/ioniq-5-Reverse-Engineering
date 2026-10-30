#!/usr/bin/env python3
"""Validate benign udevd-to-systemd activation in the offline recovered VM.

The probe uses fixed synthetic properties, an intentionally transient marker
unit, the shipped udev daemon and PID 1 manager, and one emulated block-device
``add`` event behind a transient readiness gate. It does not execute recovered hardware helpers, name an
installed unit, provide a shell, or establish physical-device behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

import vm_boot

EXPECTED_WORKSPACE_SHA256 = {
    "bzImage": "85e0086202758117015437a5ce7b580d7d32484807d1953c3a16e571f65f3f59",
    "rootfs.img": "4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f",
    "manifest.bin": "d282155bfed37b20a7222bb3e9d21a7c8618eaab88f7644f5770f35bdd90ef2d",
    "seed_dev.bin": "a5112d84e63962066e1d2ad290e0a9f1f2e806c56df15b6a10681aa532ecd7ca",
    "seed_user.bin": "9706e118d96d4ac08ee34ff276330d01db646aeb5356cd88ea8ef05099f9c50c",
}
EXPECTED_SYSTEMD_SHA256 = (
    "a7f5290180223def9e09570edac76f50a1bfe40b63480153daad1f22d54032b5"
)
EXPECTED_UDEVD_SHA256 = (
    "f32f6296ea20d959ac046ae80724f39e317aaaf492a5c7eedd9270b5b2abab0d"
)
EXPECTED_UDEVADM_SHA256 = (
    "b3d0274757f9ded9260f22a629da22e1e06ef0f6c750293b317e09810c93692b"
)
BENIGN_SERIAL = "V014_SYSTEMD_CONTROL"
BENIGN_UNIT = "v014-benign-marker.service"
GUEST_TARGET = "/sys/class/block/mmcblk0"
VARIANTS = ("negative", "positive")
MARKER_RE = re.compile(r"^V014_SYSTEMD_[A-Z0-9_]+(?:=[A-Za-z0-9_.:-]+)?$")
FAILURE_TOKENS = ("_FAIL=", "_MISSING=", "_UNEXPECTED=", "_MISMATCH=")
MASKED_RULES = ("60-persistent-storage.rules", "60-persistent-v4l.rules")


def begin_marker(variant: str) -> str:
    return f"V014_SYSTEMD_PROBE_BEGIN={variant}"


def completion_marker(variant: str) -> str:
    return f"V014_SYSTEMD_PROBE_COMPLETE={variant}"


def validate_variant(variant: str) -> None:
    if variant not in VARIANTS:
        raise ValueError(f"unsupported probe variant: {variant}")


def validate_output(output: Path, workspace: Path) -> Path:
    resolved = vm_boot.project_output(output)
    workspace = vm_boot.project_output(workspace)
    if resolved.is_relative_to(workspace) or workspace.is_relative_to(resolved):
        raise ValueError("output directory must not alias or contain the VM workspace")
    if resolved.exists():
        raise ValueError("output directory already exists")
    return resolved


def verify_exact_workspace(workspace: Path) -> dict[str, str]:
    vm_boot.verify_workspace(workspace)
    metadata = json.loads((workspace / "prepare.json").read_text())
    actual = metadata.get("sha256")
    if actual != EXPECTED_WORKSPACE_SHA256:
        raise ValueError("workspace artifacts do not match the approved recovered VM")
    return dict(actual)


def _helper_body(variant: str) -> str:
    wants = (
        f"printf '%s\\n' ' SYSTEMD_WANTS={BENIGN_UNIT}'\n"
        if variant == "positive"
        else ""
    )
    return f"""#!/bin/busybox sh
/bin/busybox echo V014_SYSTEMD_HELPER={variant} > /dev/console
printf '%s\\n' 'ID_SCSI_SERIAL={BENIGN_SERIAL}'
{wants}"""


def _observer_body(variant: str) -> str:
    return f"""#!/bin/busybox sh
BB=/bin/busybox
emit() {{ $BB echo "$1" > /dev/console; }}
$BB sleep 5
/bin/udevadm info --query=property --path={GUEST_TARGET} > /run/v014-properties 2>/run/v014-udevadm-info.err
if $BB grep -Fx 'ID_SCSI_SERIAL={BENIGN_SERIAL}' /run/v014-properties >/dev/null; then
    emit V014_SYSTEMD_ID_SERIAL=present
else
    emit V014_SYSTEMD_ID_SERIAL=missing
fi
if $BB grep -Fx 'SYSTEMD_WANTS={BENIGN_UNIT}' /run/v014-properties >/dev/null; then
    emit V014_SYSTEMD_WANTS=present
else
    emit V014_SYSTEMD_WANTS=absent
fi
if [ -e /run/v014-benign-marker-fired ]; then
    emit V014_SYSTEMD_MARKER_FILE=present
else
    emit V014_SYSTEMD_MARKER_FILE=absent
fi
if /bin/systemctl --quiet is-active {BENIGN_UNIT}; then
    emit V014_SYSTEMD_MARKER_ACTIVE=active
else
    emit V014_SYSTEMD_MARKER_ACTIVE=inactive
fi
ROOT_FLAGS=$($BB awk '$2 == "/" {{ print $4; exit }}' /proc/mounts)
if echo "$ROOT_FLAGS" | $BB tr ',' '\\n' | $BB grep -Fx ro >/dev/null; then
    emit V014_SYSTEMD_ROOT_FINAL_READONLY=1
else
    emit V014_SYSTEMD_ROOT_FINAL_READONLY=0
fi
emit {completion_marker(variant)}
"""


def guest_script(variant: str) -> str:
    """Build one fixed transient PID-1 handoff diagnostic."""
    validate_variant(variant)
    complete = completion_marker(variant)
    helper = _helper_body(variant)
    observer = _observer_body(variant)
    return f"""export PATH=/bin:/sbin:/usr/bin:/usr/sbin
BB=/bin/busybox
probe_fail() {{
    echo "V014_SYSTEMD_FAIL=$1"
    echo {complete}
    return 1
}}
probe_main() {{
    echo {begin_marker(variant)}
    SYSTEMD_SHA=$($BB sha256sum /lib/systemd/systemd | $BB cut -d' ' -f1)
    UDEVD_SHA=$($BB sha256sum /lib/systemd/systemd-udevd | $BB cut -d' ' -f1)
    UDEVADM_SHA=$($BB sha256sum /bin/udevadm | $BB cut -d' ' -f1)
    echo V014_SYSTEMD_SYSTEMD_SHA256=$SYSTEMD_SHA
    echo V014_SYSTEMD_UDEVD_SHA256=$UDEVD_SHA
    echo V014_SYSTEMD_UDEVADM_SHA256=$UDEVADM_SHA
    [ "$SYSTEMD_SHA" = "{EXPECTED_SYSTEMD_SHA256}" ] || {{ probe_fail systemd_hash; return 1; }}
    [ "$UDEVD_SHA" = "{EXPECTED_UDEVD_SHA256}" ] || {{ probe_fail udevd_hash; return 1; }}
    [ "$UDEVADM_SHA" = "{EXPECTED_UDEVADM_SHA256}" ] || {{ probe_fail udevadm_hash; return 1; }}
    [ -d {GUEST_TARGET} ] || {{ probe_fail target_missing; return 1; }}
    $BB mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run || {{ probe_fail run_mount; return 1; }}
    $BB mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp || {{ probe_fail tmp_mount; return 1; }}
    $BB mkdir -p /run/systemd/system /run/udev/rules.d
    for unitdir in /etc/systemd/system /run/systemd/system /lib/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system; do
        [ ! -e "$unitdir/{BENIGN_UNIT}" ] && [ ! -L "$unitdir/{BENIGN_UNIT}" ] || {{ probe_fail installed_unit; return 1; }}
        [ ! -e "$unitdir/{BENIGN_UNIT}.d" ] && [ ! -L "$unitdir/{BENIGN_UNIT}.d" ] || {{ probe_fail installed_unit_dropin; return 1; }}
    done
    for rule in {' '.join(MASKED_RULES)}; do
        [ ! -e "/etc/udev/rules.d/$rule" ] && [ ! -L "/etc/udev/rules.d/$rule" ] || {{ probe_fail etc_rule_override; return 1; }}
    done
    for path in /run/v014-benign-helper /run/v014-trigger /run/v014-observe \
        /run/udev/rules.d/00-v014-benign-systemd.rules \
        /run/udev/rules.d/60-persistent-storage.rules \
        /run/udev/rules.d/60-persistent-v4l.rules \
        /run/systemd/system/{BENIGN_UNIT} \
        /run/systemd/system/v014-probe.target \
        /run/systemd/system/v014-trigger.service \
        /run/systemd/system/v014-observe.service \
        /run/systemd/system/default.target; do
        [ ! -e "$path" ] && [ ! -L "$path" ] || {{ probe_fail transient_path; return 1; }}
    done
    cat > /run/v014-benign-helper <<'EOF_HELPER'
{helper}EOF_HELPER
    cat > /run/v014-trigger <<'EOF_TRIGGER'
#!/bin/busybox sh
set -e
/bin/udevadm settle --timeout=30
/bin/busybox echo V014_SYSTEMD_SETTLED={variant} > /dev/console
/bin/busybox touch /run/v014-trigger-armed
/bin/busybox echo V014_SYSTEMD_TRIGGER={variant} > /dev/console
/bin/udevadm trigger --action=add {GUEST_TARGET}
EOF_TRIGGER
    cat > /run/v014-observe <<'EOF_OBSERVER'
{observer}EOF_OBSERVER
    $BB chmod 0700 /run/v014-benign-helper /run/v014-trigger /run/v014-observe
    for rule in {' '.join(MASKED_RULES)}; do
        $BB ln -s /dev/null "/run/udev/rules.d/$rule" || {{ probe_fail rule_mask_create; return 1; }}
        [ "$($BB readlink "/run/udev/rules.d/$rule")" = /dev/null ] || {{ probe_fail rule_mask_verify; return 1; }}
    done
    echo V014_SYSTEMD_RULE_MASKS=1
    cat > /run/udev/rules.d/00-v014-benign-systemd.rules <<'EOF_RULE'
ACTION=="add", SUBSYSTEM=="block", KERNEL=="mmcblk0", TEST!="/run/v014-trigger-armed", TAG+="systemd", ENV{{SYSTEMD_READY}}="0"
ACTION=="add", SUBSYSTEM=="block", KERNEL=="mmcblk0", TEST=="/run/v014-trigger-armed", IMPORT{{program}}="/run/v014-benign-helper", TAG+="systemd", ENV{{SYSTEMD_READY}}="1"
EOF_RULE
    cat > /run/systemd/system/{BENIGN_UNIT} <<'EOF_MARKER_UNIT'
[Unit]
Description=V014 transient benign marker
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/busybox touch /run/v014-benign-marker-fired
ExecStart=/bin/busybox echo V014_SYSTEMD_MARKER_FIRED=positive
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
EOF_MARKER_UNIT
    cat > /run/systemd/system/v014-trigger.service <<'EOF_TRIGGER_UNIT'
[Unit]
Description=V014 transient fixed block add event
DefaultDependencies=no
After=systemd-udev-trigger.service systemd-udevd.service
Requires=systemd-udevd.service

[Service]
Type=oneshot
ExecStart=/run/v014-trigger
StandardOutput=journal+console
StandardError=journal+console
EOF_TRIGGER_UNIT
    cat > /run/systemd/system/v014-observe.service <<'EOF_OBSERVER_UNIT'
[Unit]
Description=V014 transient inert observer
DefaultDependencies=no
After=v014-trigger.service
Requires=v014-trigger.service

[Service]
Type=oneshot
ExecStart=/run/v014-observe
StandardOutput=journal+console
StandardError=journal+console
EOF_OBSERVER_UNIT
    cat > /run/systemd/system/v014-probe.target <<'EOF_TARGET'
[Unit]
Description=V014 transient minimal probe target
DefaultDependencies=no
Requires=sysinit.target
After=sysinit.target
Wants=v014-trigger.service v014-observe.service
EOF_TARGET
    $BB ln -s v014-probe.target /run/systemd/system/default.target
    : > /tmp/fstab
    $BB mount -o remount,ro / || {{ probe_fail root_remount; return 1; }}
    ROOT_FLAGS=$($BB awk '$2 == "/" {{ print $4; exit }}' /proc/mounts)
    echo "$ROOT_FLAGS" | $BB tr ',' '\\n' | $BB grep -Fx ro >/dev/null || {{ probe_fail root_not_readonly; return 1; }}
    echo V014_SYSTEMD_ROOT_READONLY=1
    echo V014_SYSTEMD_HANDOFF=1
    export SYSTEMD_LOG_TARGET=console
    export SYSTEMD_LOG_LEVEL=info
    exec /lib/systemd/systemd --unit=v014-probe.target
}}
probe_main
"""


def expected_markers(variant: str) -> tuple[str, ...]:
    validate_variant(variant)
    common = (
        begin_marker(variant),
        f"V014_SYSTEMD_SYSTEMD_SHA256={EXPECTED_SYSTEMD_SHA256}",
        f"V014_SYSTEMD_UDEVD_SHA256={EXPECTED_UDEVD_SHA256}",
        f"V014_SYSTEMD_UDEVADM_SHA256={EXPECTED_UDEVADM_SHA256}",
        "V014_SYSTEMD_RULE_MASKS=1",
        "V014_SYSTEMD_ROOT_READONLY=1",
        "V014_SYSTEMD_HANDOFF=1",
        f"V014_SYSTEMD_SETTLED={variant}",
        f"V014_SYSTEMD_TRIGGER={variant}",
        f"V014_SYSTEMD_HELPER={variant}",
    )
    if variant == "positive":
        result = (
            "V014_SYSTEMD_MARKER_FIRED=positive",
            "V014_SYSTEMD_ID_SERIAL=present",
            "V014_SYSTEMD_WANTS=present",
            "V014_SYSTEMD_MARKER_FILE=present",
            "V014_SYSTEMD_MARKER_ACTIVE=active",
        )
    else:
        result = (
            "V014_SYSTEMD_ID_SERIAL=present",
            "V014_SYSTEMD_WANTS=absent",
            "V014_SYSTEMD_MARKER_FILE=absent",
            "V014_SYSTEMD_MARKER_ACTIVE=inactive",
        )
    return common + result + (
        "V014_SYSTEMD_ROOT_FINAL_READONLY=1",
        completion_marker(variant),
    )


def probe_frame(serial: str, variant: str) -> tuple[list[str], bool]:
    validate_variant(variant)
    lines = serial.splitlines()
    begin = begin_marker(variant)
    complete = completion_marker(variant)
    starts = [index for index, line in enumerate(lines) if line == begin]
    ends = [index for index, line in enumerate(lines) if line == complete]
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
        return [], False
    return lines[starts[0]:ends[0] + 1], True


def salient_lines(serial: str, variant: str, limit: int = 120) -> list[str]:
    frame, _ = probe_frame(serial, variant)
    return [line for line in frame if MARKER_RE.fullmatch(line)][:limit]


def classify(serial: str, result: dict[str, Any], variant: str) -> str:
    validate_variant(variant)
    raw_lines = serial.splitlines()
    raw_markers = [line for line in raw_lines if MARKER_RE.fullmatch(line)]
    if any(
        line.startswith("V014_SYSTEMD") and not MARKER_RE.fullmatch(line)
        for line in raw_lines
    ):
        return "harness-error"
    frame, complete = probe_frame(serial, variant)
    markers = [line for line in frame if MARKER_RE.fullmatch(line)]
    if not complete or raw_markers != markers:
        return "harness-error"
    if any(any(token in line for token in FAILURE_TOKENS) for line in markers):
        return "harness-error"
    if result.get("error") or result.get("timeout"):
        return "harness-error"
    if not result.get("userspace") or not result.get("root_mounted"):
        return "harness-error"
    expected_complete = completion_marker(variant)
    if (
        not result.get("serial_completion_seen")
        or result.get("serial_completion_marker") != expected_complete
        or not vm_boot.exact_serial_line_seen(serial, expected_complete)
    ):
        return "harness-error"
    fired = "V014_SYSTEMD_MARKER_FIRED=positive"
    if variant == "negative" and fired in markers:
        return "negative-control-failed"
    if markers != list(expected_markers(variant)):
        return "harness-error"
    return (
        "negative-marker-absent"
        if variant == "negative"
        else "benign-unit-activation-confirmed"
    )


def newest_run(workspace: Path, before: set[Path]) -> Path:
    runs = workspace / "runs"
    candidates = [path for path in runs.iterdir() if path.is_dir() and path not in before]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one new VM run directory, got {len(candidates)}")
    return candidates[0]


def run_variant(
    workspace: Path, variant: str, timeout: float, memory_mib: int
) -> tuple[dict[str, Any], int]:
    runs = workspace / "runs"
    before = set(runs.iterdir()) if runs.exists() else set()
    complete = completion_marker(variant)
    script = guest_script(variant)
    rc = vm_boot.run(
        workspace,
        True,
        script,
        timeout=timeout,
        memory_mib=memory_mib,
        serial_completion_marker=complete,
    )
    run_dir = newest_run(workspace, before)
    result_path = run_dir / "result.json"
    result = json.loads(result_path.read_text()) if result_path.exists() else {}
    serial_path = run_dir / "serial.log"
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    artifact_names = ("serial.log", "result.json", "command.json", "patch.json")
    artifact_hashes = {
        name: vm_boot.sha256(run_dir / name)
        for name in artifact_names
        if (run_dir / name).is_file()
    }
    command = json.loads((run_dir / "command.json").read_text())
    qemu_path = Path(command[0]).resolve()
    qemu_version_run = subprocess.run(
        [str(qemu_path), "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    qemu_version = (qemu_version_run.stdout or qemu_version_run.stderr).splitlines()
    return {
        "variant": variant,
        "classification": classify(serial, result, variant),
        "run_directory": str(run_dir.relative_to(vm_boot.PROJECT)),
        "vm_return_code": rc,
        "vm_result": result,
        "guest_script_sha256": hashlib.sha256(script.encode()).hexdigest(),
        "run_artifacts_sha256": artifact_hashes,
        "qemu": {
            "path": str(qemu_path),
            "sha256": vm_boot.sha256(qemu_path),
            "version": qemu_version[0] if qemu_version else "unknown",
        },
        "salient_lines": salient_lines(serial, variant),
    }, rc


def run_probe(
    workspace: Path, output: Path, timeout: float, memory_mib: int
) -> tuple[dict[str, Any], int]:
    workspace = vm_boot.project_output(workspace)
    workspace_hashes = verify_exact_workspace(workspace)
    output = validate_output(output, workspace)
    output.mkdir(parents=True)
    runs: list[dict[str, Any]] = []
    return_codes: list[int] = []
    for variant in VARIANTS:
        run_report, rc = run_variant(workspace, variant, timeout, memory_mib)
        runs.append(run_report)
        return_codes.append(rc)
    matched = (
        runs[0]["classification"] == "negative-marker-absent"
        and runs[1]["classification"] == "benign-unit-activation-confirmed"
        and return_codes == [0, 0]
    )
    report = {
        "schema": 1,
        "scope": "offline benign udevd-to-systemd marker validation",
        "network": "disabled by vm_boot (-nic none)",
        "workspace": str(workspace.relative_to(vm_boot.PROJECT)),
        "workspace_artifacts": workspace_hashes,
        "tool_artifacts_sha256": {
            "tools/uk_fw/udev_systemd_probe.py": vm_boot.sha256(Path(__file__)),
            "tools/uk_fw/vm_boot.py": vm_boot.sha256(Path(vm_boot.__file__)),
        },
        "expected_guest_artifacts": {
            "/lib/systemd/systemd": EXPECTED_SYSTEMD_SHA256,
            "/lib/systemd/systemd-udevd": EXPECTED_UDEVD_SHA256,
            "/bin/udevadm": EXPECTED_UDEVADM_SHA256,
        },
        "synthetic_properties": {
            "ID_SCSI_SERIAL": BENIGN_SERIAL,
            "SYSTEMD_WANTS": BENIGN_UNIT,
        },
        "guest_target": GUEST_TARGET,
        "matched_controls_passed": matched,
        "runs": runs,
        "limitations": [
            "Recovered vulnerable helper rules were transiently masked and not selected.",
            "The readiness transition and block event are VM-only controls.",
            "Only a transient BusyBox marker unit was requested.",
            "No pre-existing property-selected unit, interactive shell, persistence, or root access was tested.",
            "VM behavior does not establish physical hardware or installed-device behavior.",
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    (output / "udev-systemd-probe.json").write_text(rendered)
    return report, 0 if matched else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--memory-mib", type=int, default=1024)
    args = parser.parse_args(argv)
    if not 45 <= args.timeout <= 300:
        parser.error("--timeout must be between 45 and 300 seconds")
    if not 256 <= args.memory_mib <= 8192:
        parser.error("--memory-mib must be between 256 and 8192")
    try:
        report, rc = run_probe(
            args.workspace, args.output, args.timeout, args.memory_mib
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
