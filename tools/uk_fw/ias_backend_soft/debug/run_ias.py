#!/usr/bin/env python3.13
"""Run one command in the softbackend guest via tools/uk_fw/vm_boot.py.

Usage: run_ias.py <command-file> [timeout-seconds]

Paths are resolved from the repository root, derived from this file's location, so the
script works from any checkout and carries no absolute paths.
"""
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "tools" / "uk_fw"))
import vm_boot as vb

ws = REPO_ROOT / "work" / "vm" / "softbackend"
cmd = pathlib.Path(sys.argv[1]).read_text().strip()
timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 200.0
rc = vb.run(ws, True, cmd, timeout=timeout, memory_mib=1536)
print("run rc", rc)
