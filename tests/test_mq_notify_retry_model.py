from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "tools" / "uk_fw" / "mq_notify_retry_model.py"
SPEC = importlib.util.spec_from_file_location("mq_notify_retry_model", MODEL_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ATTACH_OPTION = "--attach-return-one-drops-socket-reference"
CLEAR_OPTION = "--explicit-socket-clear-before-retry"
CLEANUP_OPTION = "--retry-fdget-failure-reaches-socket-detach-cleanup"


class MqNotifyRetryModelTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MODEL_PATH), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def test_complete_boolean_matrix(self) -> None:
        for attach_drops, explicit_clear, failure_reaches_detach in itertools.product(
            (False, True), repeat=3
        ):
            with self.subTest(
                attach_drops=attach_drops,
                explicit_clear=explicit_clear,
                failure_reaches_detach=failure_reaches_detach,
            ):
                result = MODULE.classify_retry_edge(
                    attach_drops,
                    explicit_clear,
                    failure_reaches_detach,
                )
                if not attach_drops:
                    expected = "cve-contract-not-modeled"
                    primitive = None
                    fixed = None
                elif explicit_clear:
                    expected = "fixed-explicit-clear"
                    primitive = False
                    fixed = True
                elif failure_reaches_detach:
                    expected = "vulnerable-stale-detach-path"
                    primitive = True
                    fixed = False
                else:
                    expected = "fixed-equivalent-cleanup-routing"
                    primitive = False
                    fixed = True
                self.assertEqual(result["outcome"], expected)
                self.assertIs(
                    result[
                        "cve_2017_11176_reference_overrelease_primitive_present"
                    ],
                    primitive,
                )
                self.assertIs(
                    result["cve_2017_11176_semantic_fix_present"], fixed
                )
                self.assertIsNone(result["local_privilege_escalation"])

    def test_vulnerable_source_shape_has_stale_detach_path(self) -> None:
        result = MODULE.classify_retry_edge(True, False, True)
        self.assertTrue(result["stale_pointer_at_retry"])
        self.assertTrue(result["stale_pointer_can_reach_detach"])

    def test_source_clear_and_equivalent_routing_are_distinct_fixes(self) -> None:
        explicit = MODULE.classify_retry_edge(True, True, True)
        routed = MODULE.classify_retry_edge(True, False, False)
        self.assertEqual(explicit["outcome"], "fixed-explicit-clear")
        self.assertEqual(routed["outcome"], "fixed-equivalent-cleanup-routing")
        self.assertFalse(explicit["stale_pointer_at_retry"])
        self.assertTrue(routed["stale_pointer_at_retry"])
        self.assertFalse(routed["stale_pointer_can_reach_detach"])

    def test_rejects_non_booleans(self) -> None:
        with self.assertRaises(MODULE.ModelError):
            MODULE.classify_retry_edge(1, False, False)
        with self.assertRaises(MODULE.ModelError):
            MODULE.classify_retry_edge(True, 0, False)
        with self.assertRaises(MODULE.ModelError):
            MODULE.classify_retry_edge(True, False, "false")

    def test_pre_recorded_report_is_bounded_and_explicitly_unverified(self) -> None:
        report = MODULE.build_report()
        recorded = report["pre_recorded_target_classification"]
        self.assertEqual(recorded["outcome"], "fixed-equivalent-cleanup-routing")
        self.assertTrue(recorded["cve_2017_11176_semantic_fix_present"])
        self.assertFalse(
            recorded["cve_2017_11176_reference_overrelease_primitive_present"]
        )
        state = dict(report["evidence_binding"]["pre_recorded_target_state"])
        source = state.pop("source")
        self.assertIn("not verified by this model execution", source)
        self.assertEqual(state, recorded["input"])
        self.assertEqual(state, MODULE.PRE_RECORDED_TARGET_STATE)
        boundary = report["claim_boundary"]
        self.assertTrue(boundary["inputs_are_boolean_only"])
        self.assertTrue(boundary["emits_no_binary_or_trigger_material"])
        serialized = json.dumps(report, sort_keys=True).lower()
        for forbidden in ("payload_bytes", "packet_bytes", "command_bytes"):
            self.assertNotIn(forbidden, serialized)

    def test_cli_no_argument_output_is_byte_deterministic(self) -> None:
        command = [sys.executable, str(MODEL_PATH)]
        first = subprocess.run(command, cwd=ROOT, capture_output=True)
        second = subprocess.run(command, cwd=ROOT, capture_output=True)
        self.assertEqual(first.returncode, 0, first.stderr.decode("utf-8"))
        self.assertEqual(second.returncode, 0, second.stderr.decode("utf-8"))
        self.assertEqual(first.stdout, second.stdout)
        self.assertTrue(first.stdout.endswith(b"\n"))
        self.assertEqual(
            hashlib.sha256(first.stdout).hexdigest(),
            "06d6a4354c2a6c4e1eeda1f7ff653a79a90b1ffdaca7029b62dc221a1ec8c3c4",
        )
        self.assertEqual(
            json.loads(first.stdout.decode("utf-8")), MODULE.build_report()
        )

    def test_cli_requires_complete_state_and_emits_json(self) -> None:
        incomplete = self.run_cli(ATTACH_OPTION, "true")
        self.assertNotEqual(incomplete.returncode, 0)
        self.assertIn("all retry-state arguments", incomplete.stderr)

        complete = self.run_cli(
            ATTACH_OPTION,
            "true",
            CLEAR_OPTION,
            "false",
            CLEANUP_OPTION,
            "false",
        )
        self.assertEqual(complete.returncode, 0, complete.stderr)
        report = json.loads(complete.stdout)
        self.assertEqual(
            report["classification"]["outcome"],
            "fixed-equivalent-cleanup-routing",
        )

    def test_cli_rejects_abbreviations_duplicates_unknowns_and_bad_tokens(self) -> None:
        complete_tail = (CLEAR_OPTION, "false", CLEANUP_OPTION, "false")
        cases = (
            (
                ("--attach-return-one-drops", "true", *complete_tail),
                "unrecognized arguments",
            ),
            (
                (
                    ATTACH_OPTION,
                    "true",
                    ATTACH_OPTION,
                    "true",
                    *complete_tail,
                ),
                "may be specified only once",
            ),
            (
                (
                    ATTACH_OPTION,
                    "true",
                    ATTACH_OPTION,
                    "false",
                    *complete_tail,
                ),
                "may be specified only once",
            ),
            (
                ("--unknown-state", "true", ATTACH_OPTION, "true", *complete_tail),
                "unrecognized arguments",
            ),
            (
                (ATTACH_OPTION, "yes", *complete_tail),
                "expected true or false",
            ),
        )
        for args, expected_error in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stderr)


if __name__ == "__main__":
    unittest.main()
