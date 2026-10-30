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
        self.assertEqual(MODEL.STATUS_REPORT_UD_CAPACITY, 143)
        self.assertEqual(MODEL.SUBMIT_ACK_REPORT_UD_CAPACITY, 152)
        self.assertEqual(MODEL.SUBMIT_ERROR_REPORT_UD_CAPACITY, 151)
        self.assertEqual(MODEL.DELIVER_ACK_REPORT_UD_CAPACITY, 159)
        self.assertEqual(MODEL.DELIVER_ERROR_REPORT_UD_CAPACITY, 158)
        self.assertEqual(MODEL.COMMAND_DATA_CAPACITY, 156)
        self.assertEqual(MODEL.STATUS_REPORT_UD_OFFSET, 0x7C)
        self.assertEqual(MODEL.SUBMIT_REPORT_UD_OFFSET, 0x3F)
        self.assertEqual(MODEL.DELIVER_ACK_REPORT_UD_OFFSET, 0x2C)
        self.assertEqual(MODEL.DELIVER_ERROR_REPORT_UD_OFFSET, 0x2D)
        self.assertEqual(MODEL.COMMAND_DATA_OFFSET, 0x59)
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
        self.assertEqual(MODEL.sms_udl_in_bytes(255, 0x0C), 255)
        self.assertEqual(MODEL.sms_udl_in_bytes(255, 0x80), 0)
        self.assertEqual(MODEL.sms_udl_in_bytes(255, 0x84), 255)
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
                "bounded_copy": 44_461,
                "caller_frame_overflow": 10_840,
                "intra_sms_object_overflow": 10_235,
            },
        )
        self.assertEqual(sum(report["classifications"].values()), 65_536)
        self.assertEqual(report["maximum_copy_bytes"], 255)
        self.assertEqual(report["maximum_beyond_sms_bytes"], 64)
        self.assertEqual(report["reaches_later_scratch"], 9_240)
        self.assertEqual(report["reaches_caller_canary"], 0)

    def test_report_copy_boundaries(self):
        status_bounded = MODEL.model_status_report_data(143, 0x04)
        status_intra = MODEL.model_status_report_data(144, 0x04)
        status_frame = MODEL.model_status_report_data(173, 0x04)
        status_maximum = MODEL.model_status_report_data(255, 0x04)
        submit_ack_maximum = MODEL.model_submit_report_data(255, 0x04)
        submit_error_maximum = MODEL.model_submit_report_data(
            255, 0x04, error_report=True
        )

        self.assertEqual(status_bounded.classification, "bounded_copy")
        self.assertEqual(status_intra.classification, "intra_sms_object_overflow")
        self.assertEqual(status_frame.classification, "caller_frame_overflow")
        self.assertEqual(status_maximum.array_overflow_bytes, 112)
        self.assertEqual(status_maximum.beyond_sms_bytes, 83)
        self.assertTrue(status_maximum.reaches_later_scratch)
        self.assertFalse(status_maximum.reaches_caller_canary)
        self.assertEqual(submit_ack_maximum.array_overflow_bytes, 103)
        self.assertEqual(submit_error_maximum.array_overflow_bytes, 104)
        self.assertEqual(submit_ack_maximum.beyond_sms_bytes, 22)
        self.assertTrue(submit_ack_maximum.reaches_later_scratch)
        self.assertFalse(submit_ack_maximum.reaches_caller_canary)

        deliver_ack = MODEL.model_deliver_report_data(255, 0x04)
        deliver_error = MODEL.model_deliver_report_data(
            255, 0x04, error_report=True
        )
        command = MODEL.model_command_data(255)
        self.assertEqual(deliver_ack.array_overflow_bytes, 96)
        self.assertEqual(deliver_ack.beyond_sms_bytes, 3)
        self.assertEqual(deliver_error.array_overflow_bytes, 97)
        self.assertEqual(deliver_error.beyond_sms_bytes, 4)
        self.assertIsNone(deliver_error.reaches_later_scratch)
        self.assertIsNone(deliver_error.reaches_caller_canary)
        self.assertEqual(command.array_overflow_bytes, 99)
        self.assertEqual(command.beyond_sms_bytes, 48)
        self.assertIsNone(command.reaches_later_scratch)
        self.assertIsNone(command.reaches_caller_canary)

    def test_all_report_udl_dcs_pairs_form_complete_partitions(self):
        report = MODEL.exhaustive_report()
        expected = {
            "status_report_data": {
                "bounded_copy": 45_040,
                "caller_frame_overflow": 14_675,
                "intra_sms_object_overflow": 5_821,
            },
            "submit_ack_report_data": {
                "bounded_copy": 46_833,
                "caller_frame_overflow": 3_014,
                "intra_sms_object_overflow": 15_689,
            },
            "submit_error_report_data": {
                "bounded_copy": 46_640,
                "caller_frame_overflow": 3_014,
                "intra_sms_object_overflow": 15_882,
            },
            "deliver_ack_report_data": {
                "bounded_copy": 48_240,
                "caller_frame_overflow": 411,
                "intra_sms_object_overflow": 16_885,
            },
            "deliver_error_report_data": {
                "bounded_copy": 48_047,
                "caller_frame_overflow": 548,
                "intra_sms_object_overflow": 16_941,
            },
        }
        for name, classifications in expected.items():
            with self.subTest(name=name):
                section = report[name]
                self.assertEqual(section["combinations"], 65_536)
                self.assertEqual(section["classifications"], classifications)
                self.assertEqual(sum(classifications.values()), 65_536)
                self.assertEqual(section["maximum_copy_bytes"], 255)
                expected_canary = None if name.startswith("deliver_") else 0
                self.assertEqual(section["reaches_caller_canary"], expected_canary)
        self.assertEqual(report["status_report_data"]["maximum_beyond_sms_bytes"], 83)
        self.assertEqual(report["status_report_data"]["reaches_later_scratch"], 13_075)
        self.assertEqual(report["submit_ack_report_data"]["maximum_beyond_sms_bytes"], 22)
        self.assertEqual(report["submit_ack_report_data"]["reaches_later_scratch"], 1_918)
        self.assertEqual(report["submit_error_report_data"]["maximum_beyond_sms_bytes"], 22)
        self.assertEqual(report["submit_error_report_data"]["reaches_later_scratch"], 1_918)
        self.assertEqual(report["deliver_ack_report_data"]["maximum_beyond_sms_bytes"], 3)
        self.assertIsNone(report["deliver_ack_report_data"]["reaches_later_scratch"])
        self.assertEqual(report["deliver_error_report_data"]["maximum_beyond_sms_bytes"], 4)
        self.assertIsNone(report["deliver_error_report_data"]["reaches_later_scratch"])
        self.assertEqual(
            report["command_data"]["classifications"],
            {
                "bounded_copy": 157,
                "caller_frame_overflow": 48,
                "intra_sms_object_overflow": 51,
            },
        )
        self.assertIsNone(report["command_data"]["reaches_later_scratch"])
        self.assertIsNone(report["command_data"]["reaches_caller_canary"])

    def test_invalid_octets_fail_closed(self):
        for function, arguments in [
            (MODEL.model_originating_address, (-1,)),
            (MODEL.model_originating_address, (256,)),
            (MODEL.model_deliver_data, (0, -1)),
            (MODEL.model_deliver_data, (256, 0)),
            (MODEL.model_deliver_data, (True, 0)),
            (MODEL.model_status_report_data, (0, 256)),
            (MODEL.model_submit_report_data, (-1, 0)),
            (MODEL.model_deliver_report_data, (0, -1)),
            (MODEL.model_command_data, (256,)),
        ]:
            with self.subTest(function=function.__name__, arguments=arguments):
                with self.assertRaises((TypeError, ValueError)):
                    function(*arguments)
        with self.assertRaises(TypeError):
            MODEL.model_submit_report_data(0, 0, error_report=1)
        with self.assertRaises(TypeError):
            MODEL.model_deliver_report_data(0, 0, error_report=1)


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

    def test_report_cli_modes(self):
        cases = [
            ("--status-report", "status_report", 83),
            ("--submit-ack-report", "submit_ack_report", 22),
            ("--submit-error-report", "submit_error_report", 22),
            ("--deliver-ack-report", "deliver_ack_report", 3),
            ("--deliver-error-report", "deliver_error_report", 4),
        ]
        for option, report_type, beyond in cases:
            with self.subTest(option=option):
                result = subprocess.run(
                    [sys.executable, str(TOOL), option, "255", "4", "--json"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                parsed = json.loads(result.stdout)
                self.assertEqual(parsed["report_type"], report_type)
                self.assertEqual(parsed["copy_bytes"], 255)
                self.assertEqual(parsed["beyond_sms_bytes"], beyond)

        command = subprocess.run(
            [sys.executable, str(TOOL), "--command-data-length", "255", "--json"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(command.returncode, 0, command.stderr)
        parsed = json.loads(command.stdout)
        self.assertEqual(parsed["copy_bytes"], 255)
        self.assertEqual(parsed["beyond_sms_bytes"], 48)


if __name__ == "__main__":
    unittest.main()
