#!/usr/bin/env python3
"""Read-only Tuxera NTFS/exFAT parser probe for the offline recovered-kernel VM.

The input raw image is never mounted on the host. QEMU opens it read-only and the
fixed guest script mounts only the newly attached USB-storage disk with
ro,nodev,nosuid,noexec. Results are retained with the normal vm_boot run evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

import vm_boot

MIN_IMAGE_BYTES = 64 * 1024
MAX_IMAGE_BYTES = 4 * 1024 * 1024 * 1024
FILESYSTEMS = ("tntfs", "texfat")
FAULT_RE = re.compile(
    r"(?:kernel panic|general protection fault|\bBUG:|\bOops:|"
    r"unable to handle kernel|KASAN:)", re.I
)
PROBE_RE = re.compile(r"^TUXERA_PROBE_[A-Z_]+(?:=.*)?$")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_image(image: Path, workspace: Path) -> Path:
    """Return a safe canonical image path or fail before QEMU is launched."""
    if image.is_symlink():
        raise ValueError("probe image must not be a symlink")
    try:
        resolved = image.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError("probe image does not exist") from exc
    if not resolved.is_file():
        raise ValueError("probe image must be a regular file")
    if not resolved.is_relative_to(vm_boot.PROJECT):
        raise ValueError("probe image must be inside the project")
    if any(char in str(resolved) for char in (",", "\n", "\r")):
        raise ValueError("probe image path cannot contain commas or newlines")
    rootfs = (workspace / "rootfs.img").resolve()
    if resolved == rootfs or (rootfs.exists() and os.path.samefile(resolved, rootfs)):
        raise ValueError("probe image must not alias the VM rootfs")
    size = resolved.stat().st_size
    if not MIN_IMAGE_BYTES <= size <= MAX_IMAGE_BYTES:
        raise ValueError(
            f"probe image size must be {MIN_IMAGE_BYTES}..{MAX_IMAGE_BYTES} bytes"
        )
    return resolved


def extra_devices(image: Path) -> list[str]:
    """QEMU argv fragments for one explicitly read-only USB-storage image."""
    return [
        "-drive",
        f"if=none,id=tuxprobe,format=raw,readonly=on,file={image}",
        "usb-ehci,id=tuxprobe_ehci",
        "usb-storage,bus=tuxprobe_ehci.0,drive=tuxprobe,removable=on,serial=TUXPROBE",
    ]


def guest_script(fstype: str) -> str:
    if fstype not in FILESYSTEMS:
        raise ValueError("filesystem must be tntfs or texfat")
    # Keep all behavior fixed. The only interpolated token is the allowlisted
    # module/filesystem name above.
    return f"""export PATH=/bin:/sbin:/usr/bin:/usr/sbin
BB=/bin/busybox
FS={fstype}
probe_main() {{
echo TUXERA_PROBE_BEGIN
echo TUXERA_PROBE_FILESYSTEM=$FS
for module in ehci-pci usb-storage sd_mod; do
    $BB modprobe "$module" 2>&1 || {{ echo TUXERA_PROBE_TRANSPORT_MODULE_FAIL=$module; return 0; }}
done
$BB modprobe "$FS" 2>&1 || {{ echo TUXERA_PROBE_MODULE_FAIL; return 0; }}
i=0
DEV=
while [ $i -lt 20 ]; do
    for sysdev in /sys/block/sd*; do
        [ -e "$sysdev" ] || continue
        name=${{sysdev##*/}}
        if [ -n "$DEV" ] && [ "$DEV" != "/dev/$name" ]; then
            echo TUXERA_PROBE_DEVICE_AMBIGUOUS
            return 0
        fi
        DEV=/dev/$name
    done
    [ -n "$DEV" ] && break
    i=$((i+1))
    sleep 1
done
if [ -z "$DEV" ]; then
    echo TUXERA_PROBE_DEVICE_MISSING
    return 0
fi
# Prefer the sole first partition when the image contains a partition table.
sleep 1
[ -b "${{DEV}}1" ] && DEV="${{DEV}}1"
echo TUXERA_PROBE_DEVICE=$DEV
case "$DEV" in /dev/sd[a-z]|/dev/sd[a-z]1) ;; *) echo TUXERA_PROBE_DEVICE_REFUSED; return 0;; esac
$BB mkdir -p /tmp/tuxera-probe
if $BB mount -t "$FS" -o ro,nodev,nosuid,noexec "$DEV" /tmp/tuxera-probe; then
    echo TUXERA_PROBE_MOUNT_OK
    $BB grep ' /tmp/tuxera-probe ' /proc/mounts | $BB head -n 1
    $BB ls -lan /tmp/tuxera-probe 2>&1 | $BB head -n 100
    if $BB umount /tmp/tuxera-probe; then
        echo TUXERA_PROBE_UNMOUNT_OK
    else
        echo TUXERA_PROBE_UNMOUNT_FAIL
    fi
else
    rc=$?
    echo TUXERA_PROBE_MOUNT_REJECTED=$rc
fi
$BB dmesg | $BB tail -n 200
echo TUXERA_PROBE_COMPLETE
}}
probe_main
"""


def salient_lines(serial: str, limit: int = 100) -> list[str]:
    lines = []
    for raw in serial.replace("\r", "").splitlines():
        line = raw.strip()
        if PROBE_RE.match(line) or FAULT_RE.search(line):
            lines.append(line[:1000])
            if len(lines) >= limit:
                break
    return lines


def classify(serial: str, result: dict[str, Any]) -> str:
    if FAULT_RE.search(serial):
        return "kernel-fault"
    if result.get("timeout"):
        return "timeout"
    if result.get("error") or not result.get("userspace") or not result.get("root_mounted"):
        return "harness-error"
    markers = salient_lines(serial)
    complete = "TUXERA_PROBE_COMPLETE" in markers
    if "TUXERA_PROBE_MOUNT_OK" in markers and complete:
        return "clean-mount"
    if any(line.startswith("TUXERA_PROBE_MOUNT_REJECTED=") for line in markers) and complete:
        return "clean-rejection"
    return "harness-error"


def newest_run(workspace: Path, before: set[Path]) -> Path:
    runs = workspace / "runs"
    candidates = [p for p in runs.iterdir() if p.is_dir() and p not in before]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one new VM run directory, got {len(candidates)}")
    return candidates[0]


def run_probe(workspace: Path, image: Path, fstype: str,
              timeout: float, memory_mib: int) -> tuple[dict[str, Any], int]:
    workspace = vm_boot.project_output(workspace)
    vm_boot.verify_workspace(workspace)
    image = validate_image(image, workspace)
    original_hash = file_sha256(image)
    original_size = image.stat().st_size
    runs = workspace / "runs"
    before = set(runs.iterdir()) if runs.exists() else set()
    rc = vm_boot.run(
        workspace,
        True,
        guest_script(fstype),
        timeout=timeout,
        memory_mib=memory_mib,
        extra_devices=extra_devices(image),
    )
    run_dir = newest_run(workspace, before)
    after_hash = file_sha256(image)
    if after_hash != original_hash or image.stat().st_size != original_size:
        raise RuntimeError("read-only probe image changed unexpectedly")
    result_path = run_dir / "result.json"
    result = json.loads(result_path.read_text()) if result_path.exists() else {}
    serial_path = run_dir / "serial.log"
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    report = {
        "schema": 1,
        "image": str(image.relative_to(vm_boot.PROJECT)),
        "image_sha256": original_hash,
        "image_size": original_size,
        "filesystem": fstype,
        "read_only": True,
        "guest_mount_options": ["ro", "nodev", "nosuid", "noexec"],
        "network": "disabled by vm_boot (-nic none)",
        "run_directory": str(run_dir.relative_to(vm_boot.PROJECT)),
        "classification": classify(serial, result),
        "vm_return_code": rc,
        "vm_result": result,
        "salient_lines": salient_lines(serial),
    }
    (run_dir / "tuxera-fs-probe.json").write_text(json.dumps(report, indent=2) + "\n")
    return report, rc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--filesystem", choices=FILESYSTEMS, required=True)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--memory-mib", type=int, default=1024)
    args = parser.parse_args(argv)
    if not 30 <= args.timeout <= 900:
        parser.error("--timeout must be between 30 and 900 seconds")
    if not 256 <= args.memory_mib <= 8192:
        parser.error("--memory-mib must be between 256 and 8192")
    try:
        report, _ = run_probe(
            args.workspace, args.image, args.filesystem, args.timeout, args.memory_mib
        )
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0 if report["classification"] in ("clean-mount", "clean-rejection") else 1


if __name__ == "__main__":
    raise SystemExit(main())
