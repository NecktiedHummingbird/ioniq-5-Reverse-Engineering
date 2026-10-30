#!/usr/bin/env python3
"""Build and run a benign ALSA sequencer reachability probe in the offline VM.

The diagnostic performs one read-only open, one CLIENT_ID ioctl, one CREATE_PORT
and one DELETE_PORT as numeric uid/gid 65534. It verifies the exact shipped
module before loading it and captures only the post-probe dmesg delta. It
contains no race, heap grooming, payload, or privilege action. The VM remains
offline and its rootfs remains snapshot-backed through vm_boot.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

import vm_boot
from vm_display import executable, text_from_object

SOURCE = Path(__file__).with_name("guest") / "alsa_seq_reachability.S"
PROBE_NAME = "alsa-seq-reachability"
EXPECTED_MODULE_SHA256 = (
    "ccc802452bb4ac4527d2def96ddef463211c03ae2c07d9003fdc7ebed9eb091d"
)
FAULT_RE = re.compile(
    r"(?:kernel panic|general protection fault|kernel BUG at|\bBUG:|\bOops:|"
    r"unable to handle kernel|invalid opcode|KASAN:|use-after-free|"
    r"double free|slab corruption|list_(?:add|del) corruption|corrupted list|"
    r"\bWARNING:)", re.I
)
MARKERS = (
    f"ALSA_SEQ_MODULE_SHA256={EXPECTED_MODULE_SHA256}",
    "ALSA_SEQ_OPEN_OK",
    "ALSA_SEQ_CLIENT_ID_OK",
    "ALSA_SEQ_CREATE_PORT_OK",
    "ALSA_SEQ_DELETE_PORT_OK",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_llvm_mc() -> str:
    found = shutil.which("llvm-mc")
    if found:
        return found
    installed = Path("/opt/homebrew/opt/llvm/bin/llvm-mc")
    if installed.is_file():
        return str(installed)
    raise ValueError("llvm-mc is unavailable; no downloads are performed")


def build_probe(output: Path) -> dict[str, Any]:
    output = vm_boot.project_output(output)
    if output.exists():
        raise ValueError("output directory already exists")
    output.mkdir(parents=True)
    assembler = find_llvm_mc()
    obj = output / f"{PROBE_NAME}.o"
    binary = output / PROBE_NAME
    command = [
        assembler,
        "-triple=x86_64-pc-linux-gnu",
        "-filetype=obj",
        str(SOURCE),
        "-o",
        str(obj),
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (output / "assembler.log").write_bytes(result.stdout)
    if result.returncode:
        raise ValueError("probe assembly failed; see assembler.log")
    raw = executable(text_from_object(obj.read_bytes()))
    binary.write_bytes(raw)
    binary.chmod(0o755)
    manifest = {
        "schema": 1,
        "scope": "benign ALSA sequencer reachability; no race or privilege action",
        "command": command,
        "source": str(SOURCE.relative_to(vm_boot.PROJECT)),
        "source_sha256": vm_boot.sha256(SOURCE),
        "object_sha256": vm_boot.sha256(obj),
        "binary_sha256": sha256_bytes(raw),
        "binary_size": len(raw),
    }
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def guest_script(probe: bytes, expected_sha256: str) -> str:
    encoded = base64.b64encode(probe).decode("ascii")
    chunks = "\n".join(
        f"echo '{encoded[index:index + 512]}' >> /tmp/alsa-seq-probe.b64"
        for index in range(0, len(encoded), 512)
    )
    return f"""export PATH=/bin:/sbin:/usr/bin:/usr/sbin
BB=/bin/busybox
alsa_probe_main() {{
echo ALSA_SEQ_PROBE_BEGIN
MODULE=/lib/modules/$($BB uname -r)/kernel/sound/core/seq/snd-seq.ko
[ -f "$MODULE" ] || {{ echo ALSA_SEQ_MODULE_MISSING; return 19; }}
MODULE_SHA=$($BB sha256sum "$MODULE" | $BB cut -d' ' -f1)
echo ALSA_SEQ_MODULE_SHA256=$MODULE_SHA
[ "$MODULE_SHA" = "{EXPECTED_MODULE_SHA256}" ] || {{ echo ALSA_SEQ_MODULE_HASH_MISMATCH; return 20; }}
$BB modprobe snd-seq 2>&1 || {{ echo ALSA_SEQ_MODULE_FAIL; return 21; }}
[ -c /dev/snd/seq ] || {{ echo ALSA_SEQ_DEVICE_MISSING; return 22; }}
# Model the recovered later udev rule: root:root mode 0644.
$BB chown 0:0 /dev/snd/seq || return 23
$BB chmod 0644 /dev/snd/seq || return 24
$BB stat -c 'ALSA_SEQ_DEVICE=%F mode=%a uid=%u gid=%g dev=%t:%T' /dev/snd/seq
: > /tmp/alsa-seq-probe.b64
{chunks}
$BB base64 -d /tmp/alsa-seq-probe.b64 > /tmp/{PROBE_NAME} || return 25
$BB chmod 0755 /tmp/{PROBE_NAME}
ACTUAL=$($BB sha256sum /tmp/{PROBE_NAME} | $BB cut -d' ' -f1)
echo ALSA_SEQ_PROBE_SHA256=$ACTUAL
[ "$ACTUAL" = "{expected_sha256}" ] || {{ echo ALSA_SEQ_HASH_MISMATCH; return 26; }}
# Clear only the disposable guest's ring buffer so post-probe output is a delta.
$BB dmesg -c > /tmp/alsa-seq-dmesg-before
$BB setuidgid 65534 /tmp/{PROBE_NAME}
RC=$?
echo ALSA_SEQ_UNPRIV_RC=$RC
echo ALSA_SEQ_DMESG_DELTA_BEGIN
$BB dmesg
echo ALSA_SEQ_DMESG_DELTA_END
echo ALSA_SEQ_PROBE_COMPLETE
return $RC
}}
alsa_probe_main
"""


def probe_window(serial: str) -> str:
    clean = serial.replace("\r", "")
    marker = "ALSA_SEQ_PROBE_BEGIN\n"
    return clean.split(marker, 1)[1] if marker in clean else clean


def salient_lines(serial: str, limit: int = 100) -> list[str]:
    lines = []
    for raw in probe_window(serial).splitlines():
        line = raw.strip()
        if line.startswith("ALSA_SEQ_") or FAULT_RE.search(line):
            lines.append(line[:1000])
            if len(lines) >= limit:
                break
    return lines


def classify(serial: str, result: dict[str, Any]) -> str:
    if FAULT_RE.search(probe_window(serial)):
        return "kernel-fault"
    if result.get("timeout"):
        return "timeout"
    if result.get("error") or not result.get("userspace") or not result.get("root_mounted"):
        return "harness-error"
    lines = set(salient_lines(serial))
    if (result.get("command_exit_code") == 0
            and all(marker in lines for marker in MARKERS)
            and "ALSA_SEQ_UNPRIV_RC=0" in lines
            and "ALSA_SEQ_PROBE_COMPLETE" in lines):
        return "unprivileged-reachable"
    if "ALSA_SEQ_PROBE_COMPLETE" in lines:
        return "clean-probe-rejection"
    return "harness-error"


def newest_run(workspace: Path, before: set[Path]) -> Path:
    runs = workspace / "runs"
    candidates = [path for path in runs.iterdir() if path.is_dir() and path not in before]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one new VM run directory, got {len(candidates)}")
    return candidates[0]


def run_probe(workspace: Path, build_dir: Path, timeout: float,
              memory_mib: int) -> dict[str, Any]:
    workspace = vm_boot.project_output(workspace)
    vm_boot.verify_workspace(workspace)
    build_dir = vm_boot.project_output(build_dir)
    binary = build_dir / PROBE_NAME
    manifest_path = build_dir / "build.json"
    if not binary.is_file() or not manifest_path.is_file():
        raise ValueError("build directory lacks the probe or build.json")
    manifest = json.loads(manifest_path.read_text())
    workspace_manifest_path = workspace / "prepare.json"
    workspace_manifest = json.loads(workspace_manifest_path.read_text())
    probe = binary.read_bytes()
    digest = sha256_bytes(probe)
    if digest != manifest.get("binary_sha256"):
        raise ValueError("probe hash differs from build.json")
    runs = workspace / "runs"
    before = set(runs.iterdir()) if runs.exists() else set()
    rc = vm_boot.run(
        workspace,
        True,
        guest_script(probe, digest),
        timeout=timeout,
        memory_mib=memory_mib,
    )
    run_dir = newest_run(workspace, before)
    result_path = run_dir / "result.json"
    serial_path = run_dir / "serial.log"
    result = json.loads(result_path.read_text()) if result_path.exists() else {}
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    report = {
        "schema": 1,
        "probe_sha256": digest,
        "probe_build": str(build_dir.relative_to(vm_boot.PROJECT)),
        "run_directory": str(run_dir.relative_to(vm_boot.PROJECT)),
        "expected_snd_seq_module_sha256": EXPECTED_MODULE_SHA256,
        "workspace_prepare_sha256": vm_boot.sha256(workspace_manifest_path),
        "workspace_rootfs_sha256": workspace_manifest["sha256"]["rootfs.img"],
        "workspace_kernel_sha256": workspace_manifest["sha256"]["bzImage"],
        "network": "disabled by vm_boot (-nic none)",
        "rootfs": "snapshot-backed",
        "simulated_udev_mode": "root:root 0644",
        "probe_identity": "numeric uid/gid 65534",
        "classification": classify(serial, result),
        "vm_return_code": rc,
        "vm_result": result,
        "salient_lines": salient_lines(serial),
    }
    (run_dir / "alsa-seq-probe.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--memory-mib", type=int, default=1024)
    args = parser.parse_args(argv)
    if not 30 <= args.timeout <= 900:
        parser.error("--timeout must be between 30 and 900 seconds")
    if not 256 <= args.memory_mib <= 8192:
        parser.error("--memory-mib must be between 256 and 8192")
    if not args.build_only and args.workspace is None:
        parser.error("--workspace is required unless --build-only is used")
    try:
        manifest = build_probe(args.output)
        if args.build_only:
            print(json.dumps(manifest, indent=2))
            return 0
        report = run_probe(args.workspace, args.output, args.timeout, args.memory_mib)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0 if report["classification"] == "unprivileged-reachable" else 1


if __name__ == "__main__":
    raise SystemExit(main())
