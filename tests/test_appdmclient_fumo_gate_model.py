"""Tests for the numeric-only AppDMClient FUMO gate model."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

TOOL = Path(__file__).parents[1] / "tools/uk_fw/appdmclient_fumo_gate_model.py"
SPEC = importlib.util.spec_from_file_location("appdmclient_fumo_gate_model", TOOL)
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)


class TrailerModelTests(unittest.TestCase):
    def test_exact_evidence_binding(self) -> None:
        binding = MODEL.build_report()["evidence_binding"]
        self.assertEqual(
            binding["appdmclient_sha256"],
            "9a1fb796d7ac24fcce71c16e3dbee9306c888f43e705ee081f41b7d473978bd0",
        )
        self.assertEqual(
            binding["appdmclient_build_id"],
            "b2dbcc5231f444d8f1dd68eb7a2376323ce805df",
        )
        self.assertEqual(binding["virtual_addresses"]["trailer_parser"], "0x11fe20")
        self.assertEqual(binding["virtual_addresses"]["minus_404_store"], "0x11ff26")
        self.assertEqual(MODEL.TRAILER_SIZE, 16_420)

    def test_nonpositive_size_is_minus_401(self) -> None:
        result = MODEL.classify_trailer(0, 0, 0, 0, 0)
        self.assertEqual(result["parser_result"], -401)
        self.assertFalse(result["magic_examined"])

    def test_no_room_before_suffix_is_minus_404(self) -> None:
        for size in (1, MODEL.TRAILER_SIZE):
            with self.subTest(size=size):
                result = MODEL.classify_trailer(size, 0, 0x54, 0x45, 0x32)
                self.assertEqual(result["parser_result"], -404)
                self.assertFalse(result["magic_examined"])

    def test_incomplete_suffix_read_is_minus_402(self) -> None:
        result = MODEL.classify_trailer(
            MODEL.TRAILER_SIZE + 1,
            0,
            0x54,
            0x45,
            0x32,
        )
        self.assertEqual(result["parser_result"], -402)
        self.assertFalse(result["magic_examined"])

    def test_ter_and_te2_continue_but_do_not_verify(self) -> None:
        for magic2 in (0x52, 0x32):
            with self.subTest(magic2=magic2):
                result = MODEL.classify_trailer(
                    MODEL.TRAILER_SIZE + 1,
                    1,
                    0x54,
                    0x45,
                    magic2,
                )
                self.assertIsNone(result["parser_result"])
                self.assertTrue(result["recognized_magic"])
                self.assertTrue(result["continues_to_later_checks"])
                self.assertIsNone(result["cryptographic_verification_succeeded"])

    def test_other_magic_is_minus_404(self) -> None:
        result = MODEL.classify_trailer(
            MODEL.TRAILER_SIZE + 100,
            1,
            0x54,
            0x45,
            0x58,
        )
        self.assertEqual(result["parser_result"], -404)
        self.assertTrue(result["magic_examined"])
        self.assertFalse(result["recognized_magic"])

    def test_invalid_numeric_state_fails_closed(self) -> None:
        invalid = [
            (-1, 0, 0, 0, 0),
            (1, -1, 0, 0, 0),
            (1, 2, 0, 0, 0),
            (1, 0, 256, 0, 0),
            (True, 0, 0, 0, 0),
        ]
        for state in invalid:
            with self.subTest(state=state):
                with self.assertRaises(MODEL.ModelError):
                    MODEL.classify_trailer(*state)


class OuterGateModelTests(unittest.TestCase):
    def test_equal_path_skips_pair_contracts(self) -> None:
        for marker in (False, True):
            result = MODEL.classify_outer_gate(True, marker, 17, -99)
            self.assertEqual(result["retained_result_contract"], "pair-checks-skipped")
            self.assertTrue(result["outer_pair_gate_allows_progression"])
            self.assertIsNone(result["update_accepted"])

    def test_unequal_encrypted_mode_requires_zero_zero(self) -> None:
        self.assertTrue(
            MODEL.classify_outer_gate(False, False, 0, 0)[
                "outer_pair_gate_allows_progression"
            ]
        )
        for pair in ((-404, -404), (0, 1), (1, 0)):
            with self.subTest(pair=pair):
                self.assertFalse(
                    MODEL.classify_outer_gate(False, False, *pair)[
                        "outer_pair_gate_allows_progression"
                    ]
                )

    def test_unequal_nonencrypted_mode_requires_minus_404_pair(self) -> None:
        self.assertTrue(
            MODEL.classify_outer_gate(False, True, -404, -404)[
                "outer_pair_gate_allows_progression"
            ]
        )
        for pair in ((0, 0), (-404, 0), (0, -404), (-403, -404)):
            with self.subTest(pair=pair):
                self.assertFalse(
                    MODEL.classify_outer_gate(False, True, *pair)[
                        "outer_pair_gate_allows_progression"
                    ]
                )

    def test_gate_types_fail_closed(self) -> None:
        with self.assertRaises(MODEL.ModelError):
            MODEL.classify_outer_gate(1, False, 0, 0)
        with self.assertRaises(MODEL.ModelError):
            MODEL.classify_outer_gate(False, "false", 0, 0)
        with self.assertRaises(MODEL.ModelError):
            MODEL.classify_outer_gate(False, False, True, 0)


class ReportAndCliTests(unittest.TestCase):
    def test_summary_has_strict_claim_boundary(self) -> None:
        report = MODEL.build_report()
        self.assertEqual(report["summary"]["marker_present_unequal_contract"], [-404, -404])
        excluded = " ".join(report["claim_boundary"]["does_not_establish"])
        self.assertIn("signature", excluded)
        self.assertIn("root access", excluded)
        self.assertTrue(
            report["claim_boundary"][
                "contains_only_numeric_boolean_state_and_text_metadata"
            ]
        )

    def test_cli_is_deterministic_and_can_classify_both_gates(self) -> None:
        command = [
            sys.executable,
            str(TOOL),
            "--file-size",
            hex(MODEL.TRAILER_SIZE + 1),
            "--suffix-read-items",
            "1",
            "--magic0",
            "0x54",
            "--magic1",
            "0x45",
            "--magic2",
            "0x32",
            "--source-equal",
            "false",
            "--marker-present",
            "true",
            "--appupgrade-result",
            "-404",
            "--xml-result",
            "-404",
        ]
        first = subprocess.run(command, check=False, capture_output=True, text=True)
        second = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        report = json.loads(first.stdout)
        self.assertTrue(
            report["trailer_classification"]["continues_to_later_checks"]
        )
        self.assertTrue(
            report["outer_gate_classification"][
                "outer_pair_gate_allows_progression"
            ]
        )
        self.assertIsNone(report["outer_gate_classification"]["update_accepted"])

    def test_cli_rejects_partial_groups_and_non_boolean_text(self) -> None:
        partial = subprocess.run(
            [sys.executable, str(TOOL), "--file-size", "1"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(partial.returncode, 1)
        self.assertIn("all trailer arguments", partial.stderr)

        bad_boolean = subprocess.run(
            [sys.executable, str(TOOL), "--source-equal", "yes"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(bad_boolean.returncode, 2)
        self.assertIn("expected true or false", bad_boolean.stderr)


if __name__ == "__main__":
    unittest.main()
