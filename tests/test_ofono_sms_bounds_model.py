"""Tests for the packet-free exact oFono SMS decoder bounds model."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

TOOL = Path(__file__).parents[1] / "tools/uk_fw/ofono_sms_bounds_model.py"
SPEC = importlib.util.spec_from_file_location("ofono_sms_bounds_model", TOOL)
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)


class AddressBoundsTests(unittest.TestCase):
    def test_exact_layout_constants(self):
        self.assertEqual(MODEL.ADDRESS_CAPACITY, 23)
        self.assertEqual(MODEL.DELIVER_UD_CAPACITY, 140)
        self.assertEqual(MODEL.SMS_SIZE, 0x128)
        self.assertEqual(MODEL.SMS_CALLER_BASE, 0x30)
        self.assertEqual(MODEL.SMS_CALLER_CANARY, 0x1F8)
        self.assertEqual(MODEL.SMS_RELATIVE_CANARY, 0x1C8)
        self.assertEqual(MODEL.SMS_RELATIVE_LATER_SCRATCH, 0x130)

    def test_address_boundaries(self):
        spec_max = MODEL.model_originating_address(20)
        oversized_21 = MODEL.model_originating_address(21)
        oversized_22 = MODEL.model_originating_address(22)
        first_overflow = MODEL.model_originating_address(23)
        maximum = MODEL.model_originating_address(255)

        self.assertEqual((spec_max.encoded_bytes, spec_max.output_bytes), (10, 21))
        self.assertEqual(spec_max.classification, "spec_bounded")
        self.assertEqual(oversized_21.output_bytes, 23)
        self.assertEqual(oversized_22.output_bytes, 23)
        self.assertEqual(oversized_21.classification, "oversized_but_array_bounded")
        self.assertEqual(first_overflow.output_bytes, 25)
        self.assertEqual(first_overflow.address_overflow_bytes, 2)
        self.assertEqual(first_overflow.classification, "address_array_overflow")
        self.assertEqual(maximum.output_bytes, 257)
        self.assertEqual(maximum.beyond_sms_bytes, 21)
        self.assertTrue(maximum.reaches_later_scratch)
        self.assertFalse(maximum.reaches_caller_canary)

    def test_all_address_lengths_form_complete_partition(self):
        counts = {}
        for value in range(256):
            outcome = MODEL.model_originating_address(value).classification
            counts[outcome] = counts.get(outcome, 0) + 1
        self.assertEqual(
            counts,
            {
                "spec_bounded": 21,
                "oversized_but_array_bounded": 2,
                "address_array_overflow": 233,
            },
        )
        self.assertEqual(sum(counts.values()), 256)


class DeliverDataBoundsTests(unittest.TestCase):
    def test_sms_udl_in_bytes_reproduces_dcs_branches(self):
        self.assertEqual(MODEL.sms_udl_in_bytes(160, 0x00), 140)
        self.assertEqual(MODEL.sms_udl_in_bytes(255, 0x04), 255)
        self.assertEqual(MODEL.sms_udl_in_bytes(255, 0x08), 255)
        self.assertEqual(MODEL.sms_udl_in_bytes(255, 0x0C), 0)
        self.assertEqual(MODEL.sms_udl_in_bytes(255, 0x80), 0)
        self.assertEqual(MODEL.sms_udl_in_bytes(255, 0xC0), 224)
        self.assertEqual(MODEL.sms_udl_in_bytes(255, 0xF4), 255)

    def test_deliver_copy_boundaries(self):
        bounded = MODEL.model_deliver_data(140, 0x04)
        intra = MODEL.model_deliver_data(141, 0x04)
        object_end = MODEL.model_deliver_data(191, 0x04)
        frame = MODEL.model_deliver_data(192, 0x04)
        scratch = MODEL.model_deliver_data(200, 0x04)
        maximum = MODEL.model_deliver_data(255, 0x04)

        self.assertEqual(bounded.classification, "bounded_copy")
        self.assertEqual(intra.classification, "intra_sms_object_overflow")
        self.assertEqual(object_end.write_end_in_sms, MODEL.SMS_SIZE)
        self.assertEqual(object_end.classification, "intra_sms_object_overflow")
        self.assertEqual(frame.classification, "caller_frame_overflow")
        self.assertEqual(frame.beyond_sms_bytes, 1)
        self.assertTrue(scratch.reaches_later_scratch)
        self.assertEqual(maximum.deliver_array_overflow_bytes, 115)
        self.assertEqual(maximum.beyond_sms_bytes, 64)
        self.assertFalse(maximum.reaches_caller_canary)

    def test_all_udl_dcs_pairs_form_complete_partition(self):
        report = MODEL.exhaustive_report()["deliver_data"]
        self.assertEqual(report["combinations"], 65_536)
        self.assertEqual(
            report["classifications"],
            {
                "bounded_copy": 46_416,
                "caller_frame_overflow": 9_752,
                "intra_sms_object_overflow": 9_368,
            },
        )
        self.assertEqual(sum(report["classifications"].values()), 65_536)
        self.assertEqual(report["maximum_copy_bytes"], 255)
        self.assertEqual(report["maximum_beyond_sms_bytes"], 64)
        self.assertEqual(report["reaches_later_scratch"], 8_288)
        self.assertEqual(report["reaches_caller_canary"], 0)

    def test_invalid_octets_fail_closed(self):
        for function, arguments in [
            (MODEL.model_originating_address, (-1,)),
            (MODEL.model_originating_address, (256,)),
            (MODEL.model_deliver_data, (0, -1)),
            (MODEL.model_deliver_data, (256, 0)),
            (MODEL.model_deliver_data, (True, 0)),
        ]:
            with self.subTest(function=function.__name__, arguments=arguments):
                with self.assertRaises((TypeError, ValueError)):
                    function(*arguments)


class CliTests(unittest.TestCase):
    def test_cli_is_deterministic_and_contains_no_pdu_material(self):
        command = [sys.executable, str(TOOL), "--deliver", "255", "4", "--json"]
        first = subprocess.run(command, check=False, capture_output=True, text=True)
        second = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        result = json.loads(first.stdout)
        self.assertEqual(result["copy_bytes"], 255)
        self.assertEqual(result["classification"], "caller_frame_overflow")
        self.assertNotIn("pdu", first.stdout.lower())
        self.assertNotIn("payload", first.stdout.lower())


if __name__ == "__main__":
    unittest.main()
