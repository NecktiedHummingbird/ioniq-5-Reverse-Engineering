"""Tests for the bounded CVE-2016-9445 VMNC dimension-guard model."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

TOOL = Path(__file__).parents[1] / "tools" / "uk_fw" / "vmnc_dimension_guard_model.py"
SPEC = importlib.util.spec_from_file_location("vmnc_dimension_guard_model", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class VmncDimensionGuardModelTests(unittest.TestCase):
    def test_limit_is_accepted_and_product_is_safe(self) -> None:
        report = MODULE.classify(16_384, 16_384, 4)
        derived = report["derived"]
        self.assertFalse(derived["dimension_exceeds_limit"])
        self.assertTrue(derived["wmvi_handler_reachable"])
        self.assertEqual(derived["mathematical_allocation_product"], 1 << 30)
        self.assertTrue(derived["accepted_product_fits_signed_i32"])
        self.assertFalse(derived["cve_2016_9445_overflow_path_reachable"])
        self.assertTrue(report["fixed_semantics"]["all_feasible_wmvi_paths_pass_dimension_guard"])
        self.assertFalse(report["fixed_semantics"]["structural_cfg_dominance_claimed"])

    def test_each_dimension_above_limit_is_rejected_before_handler(self) -> None:
        for width, height in ((16_385, 1), (1, 16_385), (65_535, 65_535)):
            with self.subTest(width=width, height=height):
                report = MODULE.classify(width, height, 4)
                derived = report["derived"]
                self.assertTrue(derived["dimension_exceeds_limit"])
                self.assertTrue(derived["rejected_before_wmvi_handler"])
                self.assertFalse(derived["wmvi_handler_reachable"])
                self.assertFalse(derived["cve_2016_9445_overflow_path_reachable"])
                self.assertEqual(report["classification"], "rejected_before_wmvi_handler")

    def test_historical_unbounded_arithmetic_is_reported_without_claiming_reachability(self) -> None:
        report = MODULE.classify(65_535, 65_535, 4)
        derived = report["derived"]
        self.assertTrue(derived["would_exceed_signed_i32_without_guard"])
        self.assertTrue(derived["would_exceed_uint32_without_guard"])
        self.assertFalse(derived["cve_2016_9445_overflow_path_reachable"])

    def test_all_accepted_boundary_combinations_fit_signed_i32(self) -> None:
        values = (0, 1, 16_383, 16_384)
        for width in values:
            for height in values:
                for bpp in (1, 2, 4):
                    with self.subTest(width=width, height=height, bpp=bpp):
                        report = MODULE.classify(width, height, bpp)
                        derived = report["derived"]
                        self.assertTrue(derived["wmvi_handler_reachable"])
                        self.assertTrue(derived["accepted_product_fits_signed_i32"])
                        self.assertFalse(derived["cve_2016_9445_overflow_path_reachable"])

    def test_rejects_out_of_range_and_boolean_inputs(self) -> None:
        cases = (
            (-1, 1, 1),
            (65_536, 1, 1),
            (1, -1, 1),
            (1, 65_536, 1),
            (1, 1, 0),
            (1, 1, 3),
            (1, 1, 5),
            (True, 1, 1),
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(MODULE.InputError):
                    MODULE.classify(*values)

    def test_cli_is_deterministic_explicit_utf8_lf(self) -> None:
        command = [
            sys.executable,
            str(TOOL),
            "--width", "16384",
            "--height", "16384",
            "--bytes-per-pixel", "4",
        ]
        env_a = dict(os.environ, PYTHONIOENCODING="ascii:strict")
        env_b = dict(os.environ, PYTHONIOENCODING="utf-16")
        first = subprocess.run(command, check=True, capture_output=True, env=env_a).stdout
        second = subprocess.run(command, check=True, capture_output=True, env=env_b).stdout
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        self.assertNotIn(b"\r", first)
        report = json.loads(first.decode("utf-8"))
        self.assertEqual(report["schema"], MODULE.SCHEMA)

    def test_cli_fails_closed_on_invalid_input(self) -> None:
        command = [
            sys.executable,
            str(TOOL),
            "--width", "65536",
            "--height", "1",
            "--bytes-per-pixel", "4",
        ]
        result = subprocess.run(command, check=False, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
