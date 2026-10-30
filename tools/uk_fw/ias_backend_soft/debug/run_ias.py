#!/usr/bin/env python3.13
"""Run one command in the softbackend guest via tools/uk_fw/vm_boot.py."""
import pathlib
import sys

sys.path.insert(0, "/Users/leo/Documents/ChatGPT/reverse engineering/ioniq research/tools/uk_fw")
import vm_boot as vb

ws = pathlib.Path("/Users/leo/Documents/ChatGPT/reverse engineering/ioniq research/work/vm/softbackend")
cmd = pathlib.Path(sys.argv[1]).read_text().strip()
timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 200.0
rc = vb.run(ws, True, cmd, timeout=timeout, memory_mib=1536)
print("run rc", rc)
