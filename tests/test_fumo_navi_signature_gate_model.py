from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "tools" / "uk_fw" / "fumo_navi_signature_gate_model.py"
SPEC = importlib.util.spec_from_file_location("fumo_navi_signature_gate_model", MODEL_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FumoNaviSignatureGateModelTests(unittest.TestCase):
    def classify(self, **overrides: object) -> dict[str, object]:
        state: dict[str, object] = {
            "gate_already_complete": False,
            "disable_marker_present": False,
            "navi_update_app_present": True,
            "encryption_mode": True,
            "navi_map_candidate_present": True,
            "start_state": MODULE.ASYNC_SUCCESS,
            "start_timed_out": False,
            "result_state": MODULE.ASYNC_SUCCESS,
            "result_timed_out": False,
        }
        state.update(overrides)
        return MODULE.classify_gate(**state)

    def test_each_skip_condition_progresses_without_signature_claim(self) -> None:
        cases = (
            ({"gate_already_complete": True}, "gate-already-complete"),
            ({"disable_marker_present": True}, "skip-explicit-disable-marker"),
            ({"navi_update_app_present": False}, "skip-navi-update-app-absent"),
            ({"encryption_mode": False}, "skip-nonencrypted-mode"),
            (
                {"navi_map_candidate_present": False},
                "skip-no-navi-map-candidate",
            ),
        )
        for overrides, expected in cases:
            with self.subTest(expected=expected):
                result = self.classify(**overrides)
                self.assertEqual(result["outcome"], expected)
                self.assertFalse(result["signature_attempted"])
                self.assertIsNone(result["navigation_signature_succeeded"])
                self.assertTrue(result["navigation_signature_gate_allows_progression"])
                self.assertIsNone(result["update_accepted"])

    def test_signature_start_pending_waits(self) -> None:
        result = self.classify(
            start_state=MODULE.ASYNC_PENDING,
            result_state=MODULE.ASYNC_PENDING,
        )
        self.assertEqual(result["outcome"], "wait-signature-start-result")
        self.assertTrue(result["signature_attempted"])
        self.assertIsNone(result["navigation_signature_gate_allows_progression"])
        self.assertIsNone(result["navigation_signature_succeeded"])

    def test_signature_start_failure_or_timeout_stops(self) -> None:
        for overrides, expected in (
            (
                {
                    "start_state": MODULE.ASYNC_FAILURE,
                    "result_state": MODULE.ASYNC_PENDING,
                },
                "stop-signature-start-failure",
            ),
            (
                {
                    "start_state": MODULE.ASYNC_PENDING,
                    "start_timed_out": True,
                    "result_state": MODULE.ASYNC_PENDING,
                },
                "stop-signature-start-timeout",
            ),
        ):
            with self.subTest(expected=expected):
                result = self.classify(**overrides)
                self.assertEqual(result["outcome"], expected)
                self.assertFalse(result["navigation_signature_gate_allows_progression"])
                self.assertFalse(result["navigation_signature_succeeded"])

    def test_signature_result_pending_waits(self) -> None:
        result = self.classify(result_state=MODULE.ASYNC_PENDING)
        self.assertEqual(result["outcome"], "wait-signature-verification-result")
        self.assertIsNone(result["navigation_signature_gate_allows_progression"])
        self.assertIsNone(result["navigation_signature_succeeded"])

    def test_signature_result_failure_or_timeout_stops(self) -> None:
        for overrides, expected in (
            (
                {"result_state": MODULE.ASYNC_FAILURE},
                "stop-signature-verification-failure",
            ),
            (
                {
                    "result_state": MODULE.ASYNC_PENDING,
                    "result_timed_out": True,
                },
                "stop-signature-result-timeout",
            ),
        ):
            with self.subTest(expected=expected):
                result = self.classify(**overrides)
                self.assertEqual(result["outcome"], expected)
                self.assertFalse(result["navigation_signature_gate_allows_progression"])
                self.assertFalse(result["navigation_signature_succeeded"])

    def test_signature_success_reenters_gate(self) -> None:
        result = self.classify()
        self.assertEqual(result["outcome"], "signature-success-reenter-gate")
        self.assertTrue(result["signature_attempted"])
        self.assertTrue(result["navigation_signature_succeeded"])
        self.assertTrue(result["navigation_signature_gate_allows_progression"])
        self.assertIsNone(result["update_accepted"])

    def test_skip_precedence_ignores_unreached_async_state(self) -> None:
        result = self.classify(
            disable_marker_present=True,
            start_state=MODULE.ASYNC_PENDING,
            result_state=MODULE.ASYNC_PENDING,
        )
        self.assertEqual(result["outcome"], "skip-explicit-disable-marker")
        self.assertFalse(result["signature_attempted"])

    def test_rejects_non_boolean_and_unbounded_state(self) -> None:
        with self.assertRaises(MODULE.ModelError):
            self.classify(encryption_mode=1)
        with self.assertRaises(MODULE.ModelError):
            self.classify(start_state=2)
        with self.assertRaises(MODULE.ModelError):
            self.classify(result_state=True)
        with self.assertRaises(MODULE.ModelError):
            self.classify(start_state=MODULE.ASYNC_SUCCESS, start_timed_out=True)
        with self.assertRaises(MODULE.ModelError):
            self.classify(result_state=MODULE.ASYNC_SUCCESS, result_timed_out=True)
        with self.assertRaises(MODULE.ModelError):
            self.classify(
                start_state=MODULE.ASYNC_PENDING,
                result_state=MODULE.ASYNC_SUCCESS,
            )
        with self.assertRaises(MODULE.ModelError):
            self.classify(
                start_state=MODULE.ASYNC_FAILURE,
                result_state=MODULE.ASYNC_FAILURE,
            )
        with self.assertRaises(MODULE.ModelError):
            self.classify(
                start_state=MODULE.ASYNC_PENDING,
                result_state=MODULE.ASYNC_PENDING,
                result_timed_out=True,
            )

    def test_no_input_report_is_deterministic_and_bounded(self) -> None:
        first = MODULE.build_report()
        second = MODULE.build_report()
        self.assertEqual(first, second)
        serialized = json.dumps(first, sort_keys=True)
        self.assertNotIn("payload_bytes", serialized.lower())
        self.assertNotIn("command_bytes", serialized.lower())
        self.assertNotIn("archive_bytes", serialized.lower())
        self.assertTrue(
            first["claim_boundary"][
                "contains_only_numeric_boolean_state_and_text_metadata"
            ]
        )
        self.assertEqual(
            first["evidence_binding"]["embedded_fumo_sha256"],
            MODULE.FUMO_SHA256,
        )

    def test_cli_requires_complete_state_and_emits_json(self) -> None:
        incomplete = subprocess.run(
            [sys.executable, str(MODEL_PATH), "--encryption-mode", "true"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(incomplete.returncode, 0)
        self.assertIn("all gate-state arguments", incomplete.stderr)

        args = [
            sys.executable,
            str(MODEL_PATH),
            "--gate-already-complete",
            "false",
            "--disable-marker-present",
            "false",
            "--navi-update-app-present",
            "true",
            "--encryption-mode",
            "true",
            "--navi-map-candidate-present",
            "true",
            "--start-state",
            "0",
            "--start-timed-out",
            "false",
            "--result-state",
            "0",
            "--result-timed-out",
            "false",
        ]
        complete = subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        report = json.loads(complete.stdout)
        self.assertEqual(
            report["classification"]["outcome"],
            "signature-success-reenter-gate",
        )
        self.assertIsNone(report["classification"]["update_accepted"])


if __name__ == "__main__":
    unittest.main()
