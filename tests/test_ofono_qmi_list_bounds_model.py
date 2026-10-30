"""Tests for the message-free recovered oFono QMI list arithmetic model."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

TOOL = Path(__file__).parents[1] / "tools/uk_fw/ofono_qmi_list_bounds_model.py"
SPEC = importlib.util.spec_from_file_location("ofono_qmi_list_bounds_model", TOOL)
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)


class QmiListBoundsTests(unittest.TestCase):
    def test_exact_constants(self):
        self.assertEqual(MODEL.COUNT_MASK, 0xFFFF_FFFF)
        self.assertEqual(MODEL.TLV_LENGTH_MAX, 0xFFFF)
        self.assertEqual(MODEL.ENTRY_SIZE, 5)
        self.assertEqual(MODEL.COUNT_FIELD_SIZE, 4)
        self.assertEqual(MODEL.VENDOR_PRODUCT_LIMIT, 0xFFFF)
        self.assertEqual(MODEL.MULTIPLICATIVE_INVERSE_5, 0xCCCCCCCD)

    def test_ordinary_count_and_length_boundaries(self):
        consistent = MODEL.model_list_result(1, 9)
        short = MODEL.model_list_result(1, 8)
        trailing = MODEL.model_list_result(1, 10)
        short_header = MODEL.model_list_result(0, 3)
        fallback = MODEL.model_list_result(13_108, 0xFFFF)

        self.assertEqual(consistent.classification, "consistent")
        self.assertEqual(consistent.allocation_bytes, 9)
        self.assertEqual(short.classification, "selected_tlv_overread")
        self.assertEqual(short.missing_selected_tlv_bytes, 1)
        self.assertEqual(trailing.classification, "trailing_bytes_ignored")
        self.assertEqual(short_header.classification, "short_count_field")
        self.assertEqual(fallback.classification, "heap_underallocation")
        self.assertTrue(fallback.overflow_diagnostic)
        self.assertEqual(fallback.allocation_bytes, 4)

    def test_last_nonwrapping_count_has_no_representable_exact_length(self):
        result = MODEL.model_list_result(13_107, 0xFFFF)
        self.assertEqual(result.wrapped_product, 0xFFFF)
        self.assertEqual(result.allocation_bytes, 65_539)
        self.assertEqual(result.required_source_bytes, 65_539)
        self.assertEqual(result.classification, "selected_tlv_overread")
        self.assertEqual(result.missing_selected_tlv_bytes, 4)

    def test_wrapped_count_passes_vendor_test_but_underallocates(self):
        result = MODEL.model_list_result(0x33333334, 4)
        self.assertEqual(result.wrapped_product, 4)
        self.assertEqual(result.allocation_bytes, 8)
        self.assertEqual(result.classification, "heap_underallocation")
        self.assertGreater(result.heap_overflow_bytes_if_loop_completed, 0)

    def test_full_count_space_partition(self):
        report = MODEL.count_space_report()
        self.assertEqual(report["count_values"], 1 << 32)
        self.assertEqual(report["exact_allocation_count_values"], 13_108)
        self.assertEqual(report["consistent_length_representable_counts"], 13_107)
        self.assertEqual(report["exact_allocation_without_representable_length"], 1)
        self.assertEqual(report["wrapped_small_product_underallocations"], 52_428)
        self.assertEqual(
            report["overflow_diagnostic_four_byte_allocations"],
            (1 << 32) - 65_536,
        )
        self.assertEqual(
            report["total_heap_underallocation_values"],
            (1 << 32) - 13_108,
        )
        self.assertEqual(report["smallest_underallocated_count"], 13_108)
        self.assertEqual(report["smallest_wrapped_small_product_count"], 0x33333334)

    def test_invalid_values_fail_closed(self):
        for count, length in [(-1, 0), (1 << 32, 0), (0, -1), (0, 1 << 16), (True, 0)]:
            with self.subTest(count=count, length=length):
                with self.assertRaises((TypeError, ValueError)):
                    MODEL.model_list_result(count, length)


class CliTests(unittest.TestCase):
    def test_cli_is_deterministic_and_message_free(self):
        command = [
            sys.executable,
            str(TOOL),
            "--count",
            "1",
            "--tlv-length",
            "9",
            "--json",
        ]
        first = subprocess.run(command, check=False, capture_output=True, text=True)
        second = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        result = json.loads(first.stdout)
        self.assertEqual(result["classification"], "consistent")
        self.assertNotIn("payload", first.stdout.lower())
        self.assertNotIn("packet", first.stdout.lower())


if __name__ == "__main__":
    unittest.main()
