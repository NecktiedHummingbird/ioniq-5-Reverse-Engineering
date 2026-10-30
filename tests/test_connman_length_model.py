"""Tests for the packet-free exact ConnMan length-control model."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

TOOL = Path(__file__).parents[1] / "tools/uk_fw/connman_length_model.py"
SPEC = importlib.util.spec_from_file_location("connman_length_model", TOOL)
MODEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODEL)


class BoundaryTests(unittest.TestCase):
    def test_read_error_and_short_read_precede_total_length(self):
        self.assertEqual(MODEL.classify(-1, 0)["outcome"], "read-error")
        self.assertEqual(MODEL.classify(27, 65535)["outcome"], "short-read-reject")

    def test_partial_read_rejects_larger_advertised_length(self):
        result = MODEL.classify(28, 29)
        self.assertEqual(result["outcome"], "partial-read-reject")
        self.assertIsNone(result["copy_length"])

    def test_pre_header_totals_underflow_to_fortify_abort(self):
        zero = MODEL.classify(28, 0)
        last = MODEL.classify(MODEL.READ_CAP, 27)
        self.assertEqual(zero["outcome"], "fortify-abort")
        self.assertEqual(zero["copy_length"], (1 << 64) - 28)
        self.assertEqual(last["outcome"], "fortify-abort")
        self.assertEqual(last["copy_length"], (1 << 64) - 1)

    def test_valid_length_range_is_bounded_by_destination(self):
        empty = MODEL.classify(28, 28)
        maximum = MODEL.classify(MODEL.READ_CAP, MODEL.READ_CAP)
        self.assertEqual(empty["outcome"], "bounded-copy")
        self.assertEqual(empty["copy_length"], 0)
        self.assertEqual(maximum["outcome"], "bounded-copy")
        self.assertEqual(maximum["copy_length"], MODEL.DESTINATION_SIZE)

    def test_invalid_model_inputs_fail_closed(self):
        for read_length, total_length in [(-2, 0), (657, 0), (28, -1), (28, 65536), (True, 0)]:
            with self.subTest(read_length=read_length, total_length=total_length):
                with self.assertRaises(MODEL.ModelError):
                    MODEL.classify(read_length, total_length)
        with self.assertRaisesRegex(MODEL.ModelError, "together"):
            MODEL.build_report(28, None)


class ExhaustiveSummaryTests(unittest.TestCase):
    def test_exact_full_domain_counts(self):
        counts = MODEL.exhaustive_counts()
        self.assertEqual(
            counts,
            {
                "read-error": 0,
                "short-read-reject": 1_835_008,
                "partial-read-reject": 41_006_397,
                "fortify-abort": 17_612,
                "bounded-copy": 198_135,
            },
        )
        self.assertEqual(sum(counts.values()), 657 * 65_536)

    def test_per_read_partition_matches_every_read_length(self):
        for read_length in range(MODEL.READ_CAP + 1):
            if read_length < MODEL.HEADER_SIZE:
                expected = MODEL.TOTAL_VALUE_COUNT
            else:
                aborts = MODEL.HEADER_SIZE
                bounded = read_length - MODEL.HEADER_SIZE + 1
                partial = MODEL.TOTAL_VALUE_COUNT - read_length - 1
                expected = aborts + bounded + partial
            self.assertEqual(expected, MODEL.TOTAL_VALUE_COUNT)

    def test_summary_boundaries_and_claim_boundary(self):
        report = MODEL.build_report()
        self.assertEqual(report["exhaustive_domain"]["pair_count"], 43_057_152)
        self.assertEqual(report["evidence_binding"]["connmand_sha256"], MODEL.CONNMAND_SHA256)
        self.assertEqual(report["evidence_binding"]["libc_sha256"], MODEL.LIBC_SHA256)
        self.assertEqual(
            [item["outcome"] for item in report["boundaries"]],
            [
                "short-read-reject",
                "fortify-abort",
                "fortify-abort",
                "bounded-copy",
                "bounded-copy",
                "partial-read-reject",
            ],
        )
        self.assertIn("does not establish", report["claim_boundary"])


class CliTests(unittest.TestCase):
    def test_cli_emits_deterministic_json_without_packet_material(self):
        command = [
            sys.executable,
            str(TOOL),
            "--read-length", "28",
            "--ip-total-length", "27",
        ]
        first = subprocess.run(command, check=False, capture_output=True, text=True)
        second = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        report = json.loads(first.stdout)
        self.assertEqual(report["classification"]["outcome"], "fortify-abort")
        self.assertNotIn("packet", report["classification"])

    def test_cli_rejects_half_supplied_pair(self):
        completed = subprocess.run(
            [sys.executable, str(TOOL), "--read-length", "28"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("must be supplied together", completed.stderr)


if __name__ == "__main__":
    unittest.main()
