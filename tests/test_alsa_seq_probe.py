"""Contract tests for the bounded ALSA sequencer VM diagnostic."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

TOOL = Path(__file__).parents[1] / "tools/uk_fw/alsa_seq_probe.py"
SPEC = importlib.util.spec_from_file_location("alsa_seq_probe", TOOL)
PROBE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(TOOL.parent))
try:
    SPEC.loader.exec_module(PROBE)
finally:
    sys.path.pop(0)


class ProbeContractTests(unittest.TestCase):
    def test_source_is_single_create_delete_diagnostic_without_race(self):
        source = PROBE.SOURCE.read_text()
        self.assertEqual(source.count("SNDRV_SEQ_IOCTL_CREATE_PORT"), 1)
        self.assertEqual(source.count("SNDRV_SEQ_IOCTL_DELETE_PORT"), 1)
        self.assertNotIn("fork", source.lower())
        self.assertNotIn("clone", source.lower())
        self.assertNotIn("setuid", source.lower())
        self.assertIn("No race, heap grooming, payload", source)
        self.assertIn("$0xc0a85320", source)
        self.assertIn("$0x40a85321", source)
        self.assertEqual(
            hashlib.sha256(source.encode()).hexdigest(),
            "dbe95a4aaa8ab0256148ec1ef1153058280902bca7cb9107b3957a213ab7b89e",
        )

    def test_guest_contract_is_numeric_unprivileged_and_hash_checked(self):
        raw = b"bounded-probe"
        digest = PROBE.sha256_bytes(raw)
        script = PROBE.guest_script(raw, digest)
        self.assertIn("modprobe snd-seq", script)
        self.assertIn(PROBE.EXPECTED_MODULE_SHA256, script)
        self.assertIn("ALSA_SEQ_MODULE_HASH_MISMATCH", script)
        self.assertIn("chmod 0644 /dev/snd/seq", script)
        self.assertIn("setuidgid 65534", script)
        self.assertIn(digest, script)
        self.assertIn("dmesg -c", script)
        self.assertIn("ALSA_SEQ_DMESG_DELTA_BEGIN", script)
        self.assertNotIn("exit ", script)
        encoded_lines = [line for line in script.splitlines()
                         if ">> /tmp/alsa-seq-probe.b64" in line]
        self.assertTrue(encoded_lines)
        self.assertTrue(all(len(line) < 600 for line in encoded_lines))

    def test_vm_command_is_offline_and_rootfs_snapshot_backed(self):
        workspace = PROBE.vm_boot.PROJECT / "work/vm/example"
        command = PROBE.vm_boot.qemu_command(workspace, "qemu", False)
        self.assertEqual(command[command.index("-nic") + 1], "none")
        root_drive = [value for value in command if "rootfs.img" in value]
        self.assertEqual(len(root_drive), 1)
        self.assertIn("snapshot=on", root_drive[0])

    def test_existing_build_directory_is_refused_before_assembly(self):
        work = PROBE.vm_boot.PROJECT / "work"
        work.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as directory:
            with self.assertRaisesRegex(ValueError, "already exists"):
                PROBE.build_probe(Path(directory))


class ClassificationTests(unittest.TestCase):
    RESULT = {
        "userspace": True,
        "root_mounted": True,
        "timeout": False,
        "error": None,
        "command_exit_code": 0,
    }

    def test_unprivileged_reachability_requires_complete_marker_set(self):
        serial = "\n".join((*PROBE.MARKERS, "ALSA_SEQ_UNPRIV_RC=0",
                            "ALSA_SEQ_PROBE_COMPLETE"))
        self.assertEqual(
            PROBE.classify(serial, self.RESULT), "unprivileged-reachable"
        )
        self.assertEqual(
            PROBE.classify("ALSA_SEQ_PROBE_COMPLETE", self.RESULT),
            "clean-probe-rejection",
        )

    def test_kernel_fault_and_timeout_take_precedence(self):
        signatures = (
            "BUG: unable to handle kernel paging request",
            "kernel BUG at mm/slab.c:123!",
            "invalid opcode: 0000 [#1] SMP",
            "list_del corruption. next->prev should be prev",
            "WARNING: CPU: 0 PID: 42 at kernel/locking.c:7",
        )
        for signature in signatures:
            with self.subTest(signature=signature):
                serial = f"ALSA_SEQ_PROBE_BEGIN\n{signature}"
                self.assertEqual(PROBE.classify(serial, self.RESULT), "kernel-fault")
        timed = dict(self.RESULT, timeout=True)
        self.assertEqual(PROBE.classify("", timed), "timeout")

    def test_boot_warning_before_probe_marker_is_not_attributed_to_probe(self):
        serial = "WARNING: boot-only control\nALSA_SEQ_PROBE_BEGIN\nALSA_SEQ_PROBE_COMPLETE"
        self.assertEqual(PROBE.classify(serial, self.RESULT), "clean-probe-rejection")


if __name__ == "__main__":
    unittest.main()
