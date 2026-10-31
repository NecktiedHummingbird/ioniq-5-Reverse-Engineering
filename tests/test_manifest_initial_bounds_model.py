from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "uk_fw" / "manifest_initial_bounds_model.py"
SPEC = importlib.util.spec_from_file_location("manifest_initial_bounds_model", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
NULL_RESULTS = (
    "runtime_parameter_control_observed",
    "runtime_physical_memory_control_observed",
    "kernel_crash_observed",
    "controlled_memory_write_observed",
    "code_execution_observed",
    "privilege_escalation_observed",
    "persistence_observed",
)


class ManifestInitialBoundsModelTests(unittest.TestCase):
    def test_outer_size_boundaries_and_small_fixed_header(self) -> None:
        for size, oob in ((1, True), (0x1B, True), (0x1C, False),
                          (MODULE.MAX_COPY_SIZE, False)):
            result = MODULE.classify_initial_bounds(size, 0)
            with self.subTest(size=size):
                self.assertTrue(result["copy_size_accepted_by_reviewed_outer_guard"])
                self.assertEqual(
                    result["fixed_header_read_oob_candidate_after_required_header_values"],
                    oob,
                )
                self.assertFalse(result["complete_extension_walk_safety_established"])
                for key in NULL_RESULTS:
                    self.assertIsNone(result[key])

    def test_first_extension_boundary(self) -> None:
        no_entry = MODULE.classify_initial_bounds(0x48, 0x24)
        self.assertFalse(no_entry[
            "first_extension_read_would_be_attempted_after_header_acceptance"
        ])
        self.assertFalse(no_entry[
            "first_extension_stride_read_oob_candidate_after_header_acceptance"
        ])

        short = MODULE.classify_initial_bounds(0x47, 0x25)
        self.assertTrue(short[
            "first_extension_read_would_be_attempted_after_header_acceptance"
        ])
        self.assertTrue(short[
            "first_extension_stride_read_oob_candidate_after_header_acceptance"
        ])

        exact = MODULE.classify_initial_bounds(0x48, 0x25)
        self.assertTrue(exact[
            "first_extension_read_would_be_attempted_after_header_acceptance"
        ])
        self.assertFalse(exact[
            "first_extension_stride_read_oob_candidate_after_header_acceptance"
        ])

    def test_declared_extent_is_independent_of_initial_read_bounds(self) -> None:
        within = MODULE.classify_initial_bounds(0x100, 0xDC)
        self.assertFalse(within["declared_extent_exceeds_copy"])
        self.assertFalse(within["initial_or_declared_extent_oob_read_candidate"])

        beyond = MODULE.classify_initial_bounds(0x100, 0x101)
        self.assertTrue(beyond["declared_extent_exceeds_copy"])
        self.assertTrue(beyond[
            "extension_stride_read_oob_candidate_within_101_entry_cap_after_header_acceptance"
        ])
        self.assertTrue(beyond["initial_or_declared_extent_oob_read_candidate"])
        self.assertFalse(beyond["complete_extension_walk_safety_established"])

        no_loop = MODULE.classify_initial_bounds(0x20, 0x21)
        self.assertTrue(no_loop["declared_extent_exceeds_copy"])
        self.assertFalse(no_loop[
            "first_extension_read_would_be_attempted_after_header_acceptance"
        ])
        self.assertFalse(no_loop[
            "extension_stride_read_oob_candidate_within_101_entry_cap_after_header_acceptance"
        ])
        self.assertFalse(no_loop["initial_or_declared_extent_oob_read_candidate"])

        capped = MODULE.classify_initial_bounds(
            MODULE.MAX_COPY_SIZE, MODULE.MAX_COPY_SIZE + 1
        )
        self.assertTrue(capped["declared_extent_exceeds_copy"])
        self.assertEqual(capped["furthest_capped_stride_read_end"], 0x640DF4)
        self.assertFalse(capped[
            "extension_stride_read_oob_candidate_within_101_entry_cap_after_header_acceptance"
        ])
        self.assertFalse(capped["initial_or_declared_extent_oob_read_candidate"])

    def test_rejects_non_integer_out_of_range_and_partial_state(self) -> None:
        bad_values = (
            (True, 0), (1.0, 0), ("1", 0), (0, 0),
            (MODULE.MAX_COPY_SIZE + 1, 0), (1, -1),
            (1, MODULE.MAX_DECLARED_LENGTH + 1),
        )
        for copy_size, declared_length in bad_values:
            with self.subTest(values=(copy_size, declared_length)), self.assertRaises(
                MODULE.ModelError
            ):
                MODULE.classify_initial_bounds(copy_size, declared_length)
        with self.assertRaisesRegex(MODULE.ModelError, "supplied together"):
            MODULE.build_report(0x100, None)

    def test_cli_validation_is_fail_closed(self) -> None:
        good = subprocess.run(
            [sys.executable, str(TOOL), "--copy-size", "0x48",
             "--declared-length", "0x25"], capture_output=True, check=False,
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        parsed = json.loads(good.stdout)
        self.assertEqual(parsed["classification"]["input"]["copy_size"], 0x48)

        cases = (
            ["--copy-size", "0x48"],
            ["--declared-length", "0x25"],
            ["--copy-size", "0"],
            ["--copy-size", str(MODULE.MAX_COPY_SIZE + 1),
             "--declared-length", "0"],
            ["--copy-size", "1", "--declared-length", "-1"],
            ["--copy-size", "0x48", "--copy-size", "0x20",
             "--declared-length", "0x25"],
            ["--copy-size", "0x48", "--declared-length", "0x25",
             "--declared-length", "0x24"],
            ["--copy", "1", "--declared-length", "0"],
            ["--unknown", "1"],
        )
        for args in cases:
            with self.subTest(args=args):
                bad = subprocess.run(
                    [sys.executable, str(TOOL), *args], capture_output=True,
                    check=False,
                )
                self.assertNotEqual(bad.returncode, 0)

    def test_default_output_is_explicit_deterministic_utf8_lf(self) -> None:
        expected = json.dumps(
            MODULE.build_report(), indent=2, sort_keys=True
        ).encode("utf-8") + b"\n"
        outputs = []
        for encoding in ("ascii:strict", "utf-16:strict", "utf-8:strict"):
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = encoding
            proc = subprocess.run(
                [sys.executable, str(TOOL)], capture_output=True, env=env,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, expected)
            self.assertNotIn(b"\r", proc.stdout)
            outputs.append(proc.stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[1], outputs[2])
        self.assertEqual(
            hashlib.sha256(outputs[0]).hexdigest(), "495ef9bdd20e9bd52da8c92cf52a657d3f5d0d2c37722218ac7a51a7fd0a3c3d"
        )

    def test_report_contains_no_operational_material(self) -> None:
        encoded = json.dumps(MODULE.build_report(), sort_keys=True)
        for forbidden in ("oemkm=", "/dev/mem", "BEGIN PUBLIC KEY", "kexec -"):
            self.assertNotIn(forbidden, encoded)
        boundary = MODULE.build_report()["claim_boundary"]
        self.assertTrue(boundary["inputs_are_bounded_integers_only"])
        self.assertTrue(boundary[
            "emits_no_manifest_bytes_physical_address_key_signature_command_payload_or_firmware_image"
        ])


if __name__ == "__main__":
    unittest.main()
