"""Tests for the data-free BusyBox huft_build initialized-slot model."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

TOOL = Path(__file__).parents[1] / "tools/uk_fw/busybox_huft_bounds_model.py"
SPEC = importlib.util.spec_from_file_location("busybox_huft_bounds_model", TOOL)
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)


class BoundTests(unittest.TestCase):
    def test_exact_evidence_binding(self):
        binding = MODEL.build_report()["evidence_binding"]
        self.assertEqual(
            binding["busybox_sha256"],
            "95bab633630fb158344497af52dc112e9e777458b810860068d4daa257bd9ebc",
        )
        self.assertEqual(
            binding["busybox_build_ids"],
            [
                "42e0a4c7631667cf9106ca36a4f2e7886f6f72b0",
                "dc25533aa5ad984ec9a7ed388925f24d328c1836",
            ],
        )
        self.assertEqual(
            binding["initial_upstream_fix_commit"],
            "1de25a6e87e0e627aa34298105a3d17c60a1f44e",
        )
        self.assertEqual(
            binding["corrective_followup_commit"],
            "6bd3fff51aa74e2ee2d87887b12182a3b09792ef",
        )
        self.assertEqual(binding["virtual_addresses"]["v_entry_read"], "0x47938")

    def test_populated_entry_is_safe_in_both_versions(self):
        result = MODEL.classify(19, 18, 17, 19)
        self.assertTrue(result["recovered_reads_v_slot"])
        self.assertFalse(result["recovered_reads_uninitialized_v"])
        self.assertFalse(result["stable_slot_is_uint_max_sentinel"])
        self.assertEqual(result["stable_outcome"], "read-populated-v-entry")

    def test_recovered_bound_reads_first_uninitialized_entry(self):
        result = MODEL.classify(19, 18, 18, 19)
        self.assertTrue(result["recovered_reads_v_slot"])
        self.assertTrue(result["recovered_reads_uninitialized_v"])
        self.assertTrue(result["stable_slot_is_uint_max_sentinel"])
        self.assertEqual(
            result["stable_outcome"],
            "emit-invalid-code-from-initialized-sentinel",
        )
        self.assertEqual(result["uninitialized_window"], [18, 18])
        self.assertFalse(
            result["value_branch_if_uninitialized_read_occurs"]
            ["indeterminate_value_is_attacker_selected"]
        )

    def test_larger_uninitialized_window(self):
        result = MODEL.classify(286, 260, 270, 257)
        self.assertTrue(result["recovered_reads_uninitialized_v"])
        self.assertEqual(result["uninitialized_window"], [260, 285])
        self.assertEqual(result["uninitialized_window_entry_count"], 26)

    def test_at_n_recovered_skips_read_and_followup_uses_sentinel(self):
        result = MODEL.classify(30, 12, 30, 0)
        self.assertFalse(result["recovered_reads_v_slot"])
        self.assertEqual(
            result["recovered_outcome"], "emit-invalid-code-without-v-read"
        )
        self.assertTrue(result["stable_slot_is_uint_max_sentinel"])

    def test_complete_table_has_no_uninitialized_window(self):
        result = MODEL.classify(30, 30, 29, 0)
        self.assertFalse(result["recovered_reads_uninitialized_v"])
        self.assertIsNone(result["uninitialized_window"])
        self.assertEqual(result["uninitialized_window_entry_count"], 0)

    def test_invalid_inputs_fail_closed(self):
        invalid = [
            (0, 0, 0, 0),
            (289, 1, 0, 0),
            (19, 20, 0, 0),
            (19, 18, 20, 0),
            (19, 18, -1, 0),
            (19, 18, 1, 289),
            (True, 0, 0, 0),
        ]
        for state in invalid:
            with self.subTest(state=state):
                with self.assertRaises(MODEL.ModelError):
                    MODEL.classify(*state)
        with self.assertRaisesRegex(MODEL.ModelError, "supplied together"):
            MODEL.build_report(n=19)


class ReportTests(unittest.TestCase):
    def test_summary_and_claim_boundary(self):
        report = MODEL.build_report()
        self.assertEqual(report["summary"]["maximum_symbol_count"], 288)
        self.assertIn("initialized_count < n", report["summary"]["affected_when"])
        self.assertIn("UINT_MAX", report["summary"]["stable_behavior"])
        self.assertIn("does not equate v_end", report["semantics"]["initial_fix_note"])
        excluded = " ".join(report["claim_boundary"]["does_not_establish"])
        self.assertIn("compressed input", excluded)
        self.assertIn("short-lived v_end", excluded)
        self.assertIn("indeterminate stack value", excluded)
        self.assertIn("root access", excluded)

    def test_report_keys_contain_no_input_material(self):
        reports = [MODEL.build_report(), MODEL.build_report(19, 18, 18, 19)]
        forbidden = {"archive", "payload", "packet", "command", "compressed_bytes"}

        def keys(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield str(key).lower()
                    yield from keys(child)
            elif isinstance(value, list):
                for child in value:
                    yield from keys(child)

        for report in reports:
            report_keys = list(keys(report))
            for word in forbidden:
                self.assertFalse(any(word in key for key in report_keys))


class CliTests(unittest.TestCase):
    def test_cli_is_deterministic(self):
        command = [
            sys.executable,
            str(TOOL),
            "--n", "19",
            "--initialized-count", "18",
            "--p-index", "18",
            "--s", "19",
        ]
        first = subprocess.run(command, check=False, capture_output=True, text=True)
        second = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        report = json.loads(first.stdout)
        self.assertTrue(report["classification"]["recovered_reads_uninitialized_v"])

    def test_cli_rejects_partial_state(self):
        completed = subprocess.run(
            [sys.executable, str(TOOL), "--n", "19"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("must be supplied together", completed.stderr)


if __name__ == "__main__":
    unittest.main()
