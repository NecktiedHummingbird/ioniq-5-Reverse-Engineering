"""Safety and classification tests for the bounded udev import probe."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

TOOL = Path(__file__).parents[1] / "tools/uk_fw/udev_import_probe.py"
SPEC = importlib.util.spec_from_file_location("udev_import_probe", TOOL)
PROBE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(TOOL.parent))
try:
    SPEC.loader.exec_module(PROBE)
finally:
    sys.path.pop(0)


class ProjectFixture(unittest.TestCase):
    def setUp(self):
        work = PROBE.vm_boot.PROJECT / "work"
        work.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=work)
        self.base = Path(self.temp.name)
        self.workspace = self.base / "vm"
        self.workspace.mkdir()

    def tearDown(self):
        self.temp.cleanup()


class OutputBoundaryTests(ProjectFixture):
    def test_accepts_new_project_local_output(self):
        output = self.base / "result"
        self.assertEqual(
            PROBE.validate_output(output, self.workspace), output.resolve()
        )

    def test_rejects_existing_or_workspace_aliasing_output(self):
        existing = self.base / "existing"
        existing.mkdir()
        with self.assertRaisesRegex(ValueError, "already exists"):
            PROBE.validate_output(existing, self.workspace)
        with self.assertRaisesRegex(ValueError, "workspace"):
            PROBE.validate_output(self.workspace / "report", self.workspace)
        outer = self.base / "outer"
        nested_workspace = outer / "vm"
        nested_workspace.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "workspace"):
            PROBE.validate_output(outer, nested_workspace)

    def test_rejects_output_outside_project(self):
        with tempfile.TemporaryDirectory() as outside:
            with self.assertRaisesRegex(ValueError, "subdirectory of the project"):
                PROBE.validate_output(Path(outside) / "result", self.workspace)


class GuestContractTests(unittest.TestCase):
    def test_script_uses_only_fixed_benign_properties_and_udevadm_test(self):
        script = PROBE.guest_script()
        self.assertIn("ID_SCSI_SERIAL=V014_BENIGN_CONTROL", script)
        self.assertIn(
            "' SYSTEMD_WANTS=v014-benign-nonexistent.service'", script
        )
        self.assertIn(
            'udevadm test --action=change "$TARGET"', script
        )
        self.assertIn("grep -Fx 'ID_SCSI_SERIAL=", script)
        self.assertIn("grep -Fx 'SYSTEMD_WANTS=", script)
        self.assertIn("TARGET=/sys/class/block/mmcblk0", script)
        self.assertIn(PROBE.EXPECTED_UDEVADM_SHA256, script)
        self.assertIn(PROBE.EXPECTED_UDEVD_SHA256, script)

    def test_script_has_no_activation_event_or_dangerous_property(self):
        script = PROBE.guest_script()
        self.assertNotIn("debug-shell", script)
        self.assertNotIn("REMOVE_CMD", script)
        self.assertNotIn("systemctl", script)
        self.assertNotIn("udevadm trigger", script)
        self.assertNotIn("echo change >", script)
        self.assertNotIn("RUN+=", script)
        self.assertNotIn("systemd-udevd </", script)
        self.assertNotIn("systemd-udevd &", script)
        self.assertNotIn("/uevent", script)

    def test_script_cleans_temporary_rule_and_helper(self):
        script = PROBE.guest_script()
        self.assertIn('$BB rm -f "$HELPER" "$RULE"', script)
        self.assertIn('for temp_path in "$HELPER" "$RULE" "$LOG"', script)
        self.assertIn('[ ! -e "$temp_path" ] && [ ! -L "$temp_path" ]', script)
        self.assertIn('[ ! -L "$unitdir/', script)
        self.assertIn("UDEV_IMPORT_HELPER_REMOVED=1", script)
        self.assertIn("UDEV_IMPORT_RULE_REMOVED=1", script)
        self.assertIn("UDEV_IMPORT_LOG_REMOVED=1", script)
        self.assertIn("UDEV_IMPORT_PROBE_COMPLETE", script)


class ClassificationTests(unittest.TestCase):
    OK_RESULT = {
        "userspace": True,
        "root_mounted": True,
        "timeout": False,
        "error": None,
        "command_exit_code": 0,
    }

    @staticmethod
    def success_serial() -> str:
        return "UDEV_IMPORT_PROBE_BEGIN\n" + "\n".join(PROBE.PASS_MARKERS) + "\n"

    def test_success_requires_every_fixed_marker(self):
        serial = self.success_serial()
        self.assertEqual(
            PROBE.classify(serial, self.OK_RESULT),
            "benign-second-property-retained",
        )
        lines = PROBE.salient_lines(serial)
        self.assertEqual(lines, list(PROBE.EXPECTED_SEQUENCE))

    def test_helper_trace_without_final_property_is_parser_rejection(self):
        serial = (
            "UDEV_IMPORT_PROBE_BEGIN\n"
            "'/tmp/helper'(out) ' SYSTEMD_WANTS=v014-benign-nonexistent.service'\n"
            "UDEV_IMPORT_SYSTEMD_WANTS_MISSING\n"
            "UDEV_IMPORT_PROBE_COMPLETE\n"
        )
        self.assertEqual(PROBE.classify(serial, self.OK_RESULT), "parser-rejected")

    def test_missing_second_property_is_parser_rejection(self):
        serial = (
            "UDEV_IMPORT_PROBE_BEGIN\n"
            "UDEV_IMPORT_SYSTEMD_WANTS_MISSING\n"
            "UDEV_IMPORT_PROBE_COMPLETE\n"
        )
        self.assertEqual(PROBE.classify(serial, self.OK_RESULT), "parser-rejected")

    def test_timeout_hash_mismatch_and_missing_completion(self):
        timed = dict(self.OK_RESULT, timeout=True)
        self.assertEqual(PROBE.classify("", timed), "timeout")
        mismatch = (
            "UDEV_IMPORT_PROBE_BEGIN\n"
            "UDEV_IMPORT_UDEVADM_HASH_MISMATCH\n"
        )
        self.assertEqual(PROBE.classify(mismatch, self.OK_RESULT), "artifact-mismatch")
        incomplete = self.success_serial().replace(
            "UDEV_IMPORT_PROBE_COMPLETE\n", ""
        )
        self.assertEqual(PROBE.classify(incomplete, self.OK_RESULT), "harness-error")

    def test_requires_one_exact_ordered_runtime_frame(self):
        no_begin = "\n".join(PROBE.PASS_MARKERS) + "\n"
        echoed_only = "> echo UDEV_IMPORT_PROBE_BEGIN\n" + no_begin
        duplicate = self.success_serial() + self.success_serial()
        out_of_order = self.success_serial().replace(
            "UDEV_IMPORT_TEST_RC=0\n"
            f"UDEV_IMPORT_ID_SCSI_SERIAL={PROBE.BENIGN_SERIAL}\n",
            f"UDEV_IMPORT_ID_SCSI_SERIAL={PROBE.BENIGN_SERIAL}\n"
            "UDEV_IMPORT_TEST_RC=0\n",
        )
        whitespace_decorated = self.success_serial().replace(
            "UDEV_IMPORT_PROBE_BEGIN\n", " UDEV_IMPORT_PROBE_BEGIN\n"
        )
        end_before = "UDEV_IMPORT_PROBE_COMPLETE\n" + self.success_serial()
        contradictory = self.success_serial().replace(
            "UDEV_IMPORT_TEST_RC=0\n",
            "UDEV_IMPORT_TEST_RC=0\nUDEV_IMPORT_TEMP_PATH_EXISTS\n",
        )
        contradictory_after = (
            self.success_serial() + "UDEV_IMPORT_TEMP_PATH_EXISTS\n"
        )
        embedded_carriage_return = self.success_serial().replace(
            "UDEV_IMPORT_PROBE_BEGIN", "UDEV_IMPORT_PROBE_\rBEGIN"
        )
        malformed_marker = self.success_serial().replace(
            "UDEV_IMPORT_TEST_RC=0", "UDEV_IMPORT_TEST_RC=0 trailing"
        )
        for serial in (
            no_begin,
            echoed_only,
            duplicate,
            out_of_order,
            whitespace_decorated,
            end_before,
            contradictory,
            contradictory_after,
            embedded_carriage_return,
            malformed_marker,
        ):
            self.assertEqual(
                PROBE.classify(serial, self.OK_RESULT), "harness-error"
            )

    def test_salient_lines_ignore_echoed_script_source(self):
        serial = (
            "> echo UDEV_IMPORT_PROBE_COMPLETE\n"
            "UDEV_IMPORT_PROBE_BEGIN\r\n"
            "UDEV_IMPORT_TEST_RC=0\r\n"
            "noise\n"
            "UDEV_IMPORT_PROBE_COMPLETE\r\n"
        )
        self.assertEqual(
            PROBE.salient_lines(serial),
            [
                "UDEV_IMPORT_PROBE_BEGIN",
                "UDEV_IMPORT_TEST_RC=0",
                "UDEV_IMPORT_PROBE_COMPLETE",
            ],
        )


class WorkspacePinTests(ProjectFixture):
    def test_requires_fixed_approved_workspace_manifest(self):
        (self.workspace / "prepare.json").write_text(
            json.dumps({"sha256": PROBE.EXPECTED_WORKSPACE_SHA256}),
            encoding="utf-8",
        )
        with mock.patch.object(PROBE.vm_boot, "verify_workspace"):
            self.assertEqual(
                PROBE.verify_exact_workspace(self.workspace),
                PROBE.EXPECTED_WORKSPACE_SHA256,
            )
        changed = dict(PROBE.EXPECTED_WORKSPACE_SHA256)
        changed["rootfs.img"] = "0" * 64
        (self.workspace / "prepare.json").write_text(
            json.dumps({"sha256": changed}), encoding="utf-8"
        )
        with mock.patch.object(PROBE.vm_boot, "verify_workspace"):
            with self.assertRaisesRegex(ValueError, "approved recovered VM"):
                PROBE.verify_exact_workspace(self.workspace)


class ReportTests(ProjectFixture):
    def test_run_report_shape_and_canonical_serialization(self):
        runs = self.workspace / "runs"
        runs.mkdir()
        output = self.base / "output"
        (self.workspace / "prepare.json").write_text(
            json.dumps({"sha256": PROBE.EXPECTED_WORKSPACE_SHA256}),
            encoding="utf-8",
        )

        def fake_run(*args, **kwargs):
            run = runs / "fixed-run"
            run.mkdir()
            result = dict(ClassificationTests.OK_RESULT)
            (run / "result.json").write_text(json.dumps(result), encoding="utf-8")
            (run / "serial.log").write_text(
                ClassificationTests.success_serial(), encoding="utf-8"
            )
            return 0

        with mock.patch.object(PROBE.vm_boot, "verify_workspace"), mock.patch.object(
            PROBE.vm_boot, "run", side_effect=fake_run
        ):
            report, rc = PROBE.run_probe(self.workspace, output, 60, 512)

        self.assertEqual(rc, 0)
        self.assertEqual(report["schema"], 1)
        self.assertEqual(
            report["classification"], "benign-second-property-retained"
        )
        self.assertEqual(
            report["synthetic_properties"]["SYSTEMD_WANTS"], PROBE.BENIGN_UNIT
        )
        saved = (output / "udev-import-probe.json").read_text(encoding="utf-8")
        self.assertEqual(saved, json.dumps(report, indent=2, sort_keys=True) + "\n")
        self.assertIn("not unit activation", saved)


if __name__ == "__main__":
    unittest.main()
