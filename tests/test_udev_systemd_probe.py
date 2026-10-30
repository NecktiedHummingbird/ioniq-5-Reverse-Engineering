"""Safety and classification tests for the offline udevd/systemd marker probe."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

TOOL = Path(__file__).parents[1] / "tools/uk_fw/udev_systemd_probe.py"
SPEC = importlib.util.spec_from_file_location("udev_systemd_probe", TOOL)
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
    def test_accepts_only_new_disjoint_project_output(self):
        output = self.base / "result"
        self.assertEqual(
            PROBE.validate_output(output, self.workspace), output.resolve()
        )
        output.mkdir()
        with self.assertRaisesRegex(ValueError, "already exists"):
            PROBE.validate_output(output, self.workspace)
        with self.assertRaisesRegex(ValueError, "workspace"):
            PROBE.validate_output(self.workspace / "report", self.workspace)

    def test_rejects_output_outside_project(self):
        with tempfile.TemporaryDirectory() as outside:
            with self.assertRaisesRegex(ValueError, "subdirectory of the project"):
                PROBE.validate_output(Path(outside) / "result", self.workspace)


class GuestContractTests(unittest.TestCase):
    def test_fixed_positive_and_negative_helper_outputs(self):
        negative = PROBE._helper_body("negative")
        positive = PROBE._helper_body("positive")
        self.assertIn("ID_SCSI_SERIAL=V014_SYSTEMD_CONTROL", negative)
        self.assertNotIn(" SYSTEMD_WANTS=", negative)
        self.assertIn(
            "' SYSTEMD_WANTS=v014-benign-marker.service'", positive
        )
        self.assertIn("V014_SYSTEMD_HELPER=positive", positive)

    def test_script_is_transient_offline_and_fixed(self):
        for variant in PROBE.VARIANTS:
            script = PROBE.guest_script(variant)
            self.assertIn("/bin/udevadm settle --timeout=30", script)
            self.assertIn(
                "/bin/udevadm trigger --action=add /sys/class/block/mmcblk0",
                script,
            )
            self.assertIn("touch /run/v014-trigger-armed", script)
            self.assertIn("mount -o remount,ro /", script)
            self.assertLess(
                script.index("mount -o remount,ro /"),
                script.index("exec /lib/systemd/systemd"),
            )
            self.assertIn("/run/udev/rules.d/00-v014-benign-systemd.rules", script)
            self.assertIn("/run/udev/rules.d/60-persistent-storage.rules", script)
            self.assertIn("/run/udev/rules.d/60-persistent-v4l.rules", script)
            self.assertIn('$BB ln -s /dev/null "/run/udev/rules.d/$rule"', script)
            self.assertIn('$BB readlink "/run/udev/rules.d/$rule"', script)
            self.assertIn("/run/systemd/system/v014-probe.target", script)
            self.assertIn("for unitdir in /etc/systemd/system", script)
            self.assertIn("/usr/local/lib/systemd/system", script)
            self.assertIn(f"{PROBE.BENIGN_UNIT}.d", script)
            self.assertIn('TEST!="/run/v014-trigger-armed"', script)
            self.assertIn('TEST=="/run/v014-trigger-armed"', script)
            self.assertIn('ENV{SYSTEMD_READY}="0"', script)
            self.assertIn('ENV{SYSTEMD_READY}="1"', script)
            self.assertNotIn("debug-shell", script)
            self.assertNotIn("REMOVE_CMD", script)
            self.assertNotIn("/lib/udev/scsi_id", script)
            self.assertNotIn("/lib/udev/v4l_id", script)
            self.assertGreaterEqual(script.count("DefaultDependencies=no"), 4)
            for network_command in ("curl ", "wget ", "ssh ", "nc "):
                self.assertNotIn(network_command, script)

    def test_marker_unit_has_only_fixed_busybox_touch_and_echo(self):
        script = PROBE.guest_script("positive")
        unit = script.split("<<'EOF_MARKER_UNIT'\n", 1)[1].split(
            "EOF_MARKER_UNIT\n", 1
        )[0]
        exec_lines = [line for line in unit.splitlines() if line.startswith("ExecStart=")]
        self.assertEqual(
            exec_lines,
            [
                "ExecStart=/bin/busybox touch /run/v014-benign-marker-fired",
                "ExecStart=/bin/busybox echo V014_SYSTEMD_MARKER_FIRED=positive",
            ],
        )
        self.assertNotIn("/bin/sh", unit)
        self.assertIn("StandardOutput=tty", unit)
        self.assertIn("TTYPath=/dev/console", unit)

    def test_variant_is_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            PROBE.guest_script("other")


class ClassificationTests(unittest.TestCase):
    @staticmethod
    def result(variant: str) -> dict:
        return {
            "userspace": True,
            "root_mounted": True,
            "timeout": False,
            "error": None,
            "serial_completion_marker": PROBE.completion_marker(variant),
            "serial_completion_seen": True,
        }

    @staticmethod
    def success_serial(variant: str) -> str:
        return "\n".join(PROBE.expected_markers(variant)) + "\n"

    def test_matched_success_classifications(self):
        self.assertEqual(
            PROBE.classify(
                self.success_serial("negative"), self.result("negative"), "negative"
            ),
            "negative-marker-absent",
        )
        self.assertEqual(
            PROBE.classify(
                self.success_serial("positive"), self.result("positive"), "positive"
            ),
            "benign-unit-activation-confirmed",
        )

    def test_negative_rejects_unexpected_marker_execution(self):
        serial = self.success_serial("negative").replace(
            "V014_SYSTEMD_ID_SERIAL=present\n",
            "V014_SYSTEMD_MARKER_FIRED=positive\n"
            "V014_SYSTEMD_ID_SERIAL=present\n",
        )
        self.assertEqual(
            PROBE.classify(serial, self.result("negative"), "negative"),
            "negative-control-failed",
        )

    def test_fails_closed_on_missing_reordered_or_contradictory_markers(self):
        positive = self.success_serial("positive")
        cases = (
            positive.replace("V014_SYSTEMD_MARKER_FILE=present\n", ""),
            positive.replace(
                "V014_SYSTEMD_TRIGGER=positive\nV014_SYSTEMD_HELPER=positive\n",
                "V014_SYSTEMD_HELPER=positive\nV014_SYSTEMD_TRIGGER=positive\n",
            ),
            positive.replace(
                "V014_SYSTEMD_HANDOFF=1\n",
                "V014_SYSTEMD_HANDOFF=1\nV014_SYSTEMD_FAIL=unexpected\n",
            ),
            positive + "V014_SYSTEMD_FAIL=outside\n",
            positive.replace(
                "V014_SYSTEMD_WANTS=present\n",
                "V014_SYSTEMD_WANTS=present\nV014_SYSTEMD_WANTS=absent\n",
            ),
            positive.replace(
                "V014_SYSTEMD_MARKER_FILE=present\n",
                "V014_SYSTEMD_MARKER_FILE=present\nV014_SYSTEMD_UNKNOWN=1\n",
            ),
            positive.replace(
                "V014_SYSTEMD_MARKER_ACTIVE=active\n",
                "V014_SYSTEMD_MARKER_ACTIVE=active\nV014_SYSTEMD malformed\n",
            ),
            "V014_SYSTEMD_PROBE_COMPLETE=positive\n" + positive,
            positive.replace(
                "V014_SYSTEMD_PROBE_BEGIN=positive",
                " V014_SYSTEMD_PROBE_BEGIN=positive",
            ),
        )
        for serial in cases:
            with self.subTest(serial=serial[:80]):
                self.assertEqual(
                    PROBE.classify(serial, self.result("positive"), "positive"),
                    "harness-error",
                )

    def test_vm_failure_states_fail_closed(self):
        serial = self.success_serial("positive")
        for update in (
            {"timeout": True},
            {"error": "failed"},
            {"userspace": False},
            {"root_mounted": False},
            {"serial_completion_seen": False},
            {"serial_completion_marker": PROBE.completion_marker("negative")},
        ):
            result = self.result("positive")
            result.update(update)
            self.assertEqual(
                PROBE.classify(serial, result, "positive"), "harness-error"
            )

    def test_unterminated_completion_fails_even_with_fabricated_metadata(self):
        serial = self.success_serial("positive").rstrip("\n")
        self.assertEqual(
            PROBE.classify(serial, self.result("positive"), "positive"),
            "harness-error",
        )

    def test_shell_echo_does_not_form_a_frame(self):
        marker = PROBE.begin_marker("positive")
        serial = f"> echo {marker}\n" + "\n".join(
            PROBE.expected_markers("positive")[1:]
        )
        self.assertEqual(
            PROBE.classify(serial, self.result("positive"), "positive"),
            "harness-error",
        )


class WorkspacePinTests(ProjectFixture):
    def test_requires_fixed_approved_manifest_after_host_verification(self):
        prepare = self.workspace / "prepare.json"
        prepare.write_text(
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
        prepare.write_text(json.dumps({"sha256": changed}), encoding="utf-8")
        with mock.patch.object(PROBE.vm_boot, "verify_workspace"):
            with self.assertRaisesRegex(ValueError, "approved recovered VM"):
                PROBE.verify_exact_workspace(self.workspace)


class ReportTests(ProjectFixture):
    def test_report_requires_both_matched_controls(self):
        output = self.base / "output"
        (self.workspace / "prepare.json").write_text(
            json.dumps({"sha256": PROBE.EXPECTED_WORKSPACE_SHA256}),
            encoding="utf-8",
        )

        def fake_variant(_workspace, variant, _timeout, _memory):
            classification = {
                "negative": "negative-marker-absent",
                "positive": "benign-unit-activation-confirmed",
            }[variant]
            return {
                "variant": variant,
                "classification": classification,
                "run_directory": f"work/runs/{variant}",
                "vm_return_code": 0,
                "vm_result": ClassificationTests.result(variant),
                "salient_lines": list(PROBE.expected_markers(variant)),
            }, 0

        with mock.patch.object(PROBE.vm_boot, "verify_workspace"), mock.patch.object(
            PROBE, "run_variant", side_effect=fake_variant
        ):
            report, rc = PROBE.run_probe(self.workspace, output, 60, 512)
        self.assertEqual(rc, 0)
        self.assertTrue(report["matched_controls_passed"])
        self.assertEqual([run["variant"] for run in report["runs"]], list(PROBE.VARIANTS))
        saved = (output / "udev-systemd-probe.json").read_text(encoding="utf-8")
        self.assertEqual(saved, json.dumps(report, indent=2, sort_keys=True) + "\n")
        self.assertIn("No pre-existing property-selected unit", saved)


if __name__ == "__main__":
    unittest.main()
