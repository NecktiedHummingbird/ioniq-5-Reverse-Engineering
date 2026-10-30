"""Safety and classification tests for the read-only Tuxera VM probe."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

TOOL = Path(__file__).parents[1] / "tools/uk_fw/tuxera_fs_probe.py"
SPEC = importlib.util.spec_from_file_location("tuxera_fs_probe", TOOL)
PROBE = importlib.util.module_from_spec(SPEC)
# The tool imports its sibling vm_boot when run as a script.
import sys
sys.path.insert(0, str(TOOL.parent))
try:
    SPEC.loader.exec_module(PROBE)
finally:
    sys.path.pop(0)


class ImageBoundaryTests(unittest.TestCase):
    def setUp(self):
        work = PROBE.vm_boot.PROJECT / "work"
        work.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=work)
        self.base = Path(self.temp.name)
        self.workspace = self.base / "vm"
        self.workspace.mkdir()
        (self.workspace / "rootfs.img").write_bytes(b"r" * PROBE.MIN_IMAGE_BYTES)
        self.image = self.base / "probe.img"
        self.image.write_bytes(b"p" * PROBE.MIN_IMAGE_BYTES)

    def tearDown(self):
        self.temp.cleanup()

    def test_accepts_project_local_regular_image_without_mutating_it(self):
        before = self.image.read_bytes()
        resolved = PROBE.validate_image(self.image, self.workspace)
        self.assertEqual(resolved, self.image.resolve())
        PROBE.extra_devices(resolved)
        self.assertEqual(self.image.read_bytes(), before)

    def test_rejects_rootfs_alias_and_hardlink(self):
        rootfs = self.workspace / "rootfs.img"
        with self.assertRaisesRegex(ValueError, "rootfs"):
            PROBE.validate_image(rootfs, self.workspace)
        hardlink = self.base / "rootfs-hardlink.img"
        hardlink.hardlink_to(rootfs)
        with self.assertRaisesRegex(ValueError, "rootfs"):
            PROBE.validate_image(hardlink, self.workspace)

    def test_rejects_symlink_directory_and_size_bounds(self):
        link = self.base / "link.img"
        link.symlink_to(self.image)
        with self.assertRaisesRegex(ValueError, "symlink"):
            PROBE.validate_image(link, self.workspace)
        with self.assertRaisesRegex(ValueError, "regular"):
            PROBE.validate_image(self.base, self.workspace)
        tiny = self.base / "tiny.img"
        tiny.write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "size"):
            PROBE.validate_image(tiny, self.workspace)

    def test_rejects_file_outside_project(self):
        with tempfile.NamedTemporaryFile() as outside:
            outside.write(b"x" * PROBE.MIN_IMAGE_BYTES)
            outside.flush()
            with self.assertRaisesRegex(ValueError, "inside the project"):
                PROBE.validate_image(Path(outside.name), self.workspace)


class QemuAndGuestContractTests(unittest.TestCase):
    def test_qemu_chain_is_read_only_and_vm_command_remains_offline(self):
        image = PROBE.vm_boot.PROJECT / "work/probe.img"
        extra = PROBE.extra_devices(image)
        self.assertIn("readonly=on", extra[1])
        self.assertIn("format=raw", extra[1])
        self.assertIn("usb-storage", extra[-1])
        self.assertIn("serial=TUXPROBE", extra[-1])
        cmd = PROBE.vm_boot.qemu_command(
            PROBE.vm_boot.PROJECT / "work/vm/example", "qemu", False,
            extra_devices=extra,
        )
        self.assertEqual(cmd[cmd.index("-nic") + 1], "none")
        self.assertIn("readonly=on", cmd[cmd.index("-drive") + 1])
        root_drive = [x for x in cmd if "rootfs.img" in x]
        self.assertEqual(len(root_drive), 1)
        self.assertIn("snapshot=on", root_drive[0])

    def test_guest_script_has_fixed_safe_mount_and_device_allowlist(self):
        script = PROBE.guest_script("texfat")
        self.assertIn("-o ro,nodev,nosuid,noexec", script)
        self.assertIn("ehci-pci usb-storage sd_mod", script)
        self.assertIn("/dev/sd[a-z]", script)
        self.assertIn("TUXERA_PROBE_DEVICE_AMBIGUOUS", script)
        self.assertNotIn("mmcblk0\" /tmp/tuxera-probe", script)
        self.assertIn("TUXERA_PROBE_COMPLETE", script)
        self.assertNotIn("exit ", script)
        with self.assertRaises(ValueError):
            PROBE.guest_script("ext4")


class ClassificationTests(unittest.TestCase):
    OK_RESULT = {"userspace": True, "root_mounted": True, "timeout": False,
                 "error": None, "command_exit_code": 0}

    def test_classifies_clean_mount(self):
        serial = "TUXERA_PROBE_MOUNT_OK\nTUXERA_PROBE_COMPLETE\n"
        self.assertEqual(PROBE.classify(serial, self.OK_RESULT), "clean-mount")

    def test_classifies_clean_rejection_despite_echoed_script_source(self):
        serial = (
            '>     echo TUXERA_PROBE_MOUNT_OK\n'
            '>     echo TUXERA_PROBE_MOUNT_REJECTED=$rc\n'
            "TUXERA_PROBE_MOUNT_REJECTED=22\nTUXERA_PROBE_COMPLETE\n"
        )
        self.assertEqual(PROBE.classify(serial, self.OK_RESULT), "clean-rejection")

    def test_kernel_fault_wins_over_other_markers(self):
        serial = "TUXERA_PROBE_MOUNT_OK\nBUG: unable to handle kernel paging request\n"
        self.assertEqual(PROBE.classify(serial, self.OK_RESULT), "kernel-fault")
        self.assertTrue(any("BUG:" in x for x in PROBE.salient_lines(serial)))

    def test_timeout_and_harness_error(self):
        timed = dict(self.OK_RESULT, timeout=True)
        self.assertEqual(PROBE.classify("", timed), "timeout")
        failed = dict(self.OK_RESULT, userspace=False)
        self.assertEqual(PROBE.classify("", failed), "harness-error")


if __name__ == "__main__":
    unittest.main()
