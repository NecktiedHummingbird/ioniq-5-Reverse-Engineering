from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "tools" / "uk_fw" / "unix_peek_gc_model.py"
SPEC = importlib.util.spec_from_file_location("unix_peek_gc_model", MODEL_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

OPTIONS = (
    "--datagram-peek-duplicates-attached-files",
    "--stream-peek-duplicates-attached-files",
    "--duplicated-file-lists-flow-to-scm-receive",
    "--gc-lock-barrier-absent-on-both-peek-paths",
)


class UnixPeekGcModelTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MODEL_PATH), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def test_complete_boolean_matrix(self) -> None:
        for values in itertools.product((False, True), repeat=4):
            with self.subTest(values=values):
                result = MODULE.classify_unix_peek_gc(*values)
                expected = all(values)
                self.assertIs(
                    result[
                        "cve_2021_0920_missing_gc_serialization_premise_present"
                    ],
                    expected,
                )
                self.assertIs(
                    result[
                        "peek_duplicate_can_reach_descriptor_delivery_without_gc_barrier"
                    ],
                    expected,
                )
                self.assertIsNone(result["runtime_module_load_observed"])
                self.assertIsNone(result["successful_gc_concurrency_observed"])
                self.assertIsNone(result["use_after_free_observed"])
                self.assertIsNone(result["privilege_escalation"])

    def test_rejects_non_boolean_state(self) -> None:
        for index, invalid in enumerate((0, 1, "true", None)):
            values: list[object] = [True] * 4
            values[index] = invalid
            with self.subTest(index=index, invalid=invalid):
                with self.assertRaises(MODULE.ModelError):
                    MODULE.classify_unix_peek_gc(*values)

    def test_pre_recorded_state_has_one_source(self) -> None:
        report = MODULE.build_report()
        state = dict(report["evidence_binding"]["pre_recorded_target_state"])
        source = state.pop("source")
        classification = report["pre_recorded_target_classification"]
        self.assertIn("not verified by this model execution", source)
        self.assertEqual(state, MODULE.PRE_RECORDED_TARGET_STATE)
        self.assertEqual(state, classification["input"])
        self.assertTrue(
            classification[
                "cve_2021_0920_missing_gc_serialization_premise_present"
            ]
        )
        self.assertIsNone(classification["use_after_free_observed"])
        self.assertIsNone(classification["privilege_escalation"])

    def test_no_argument_cli_is_byte_deterministic(self) -> None:
        command = [sys.executable, str(MODEL_PATH)]
        first = subprocess.run(command, cwd=ROOT, capture_output=True)
        second = subprocess.run(command, cwd=ROOT, capture_output=True)
        alternate_env = dict(os.environ)
        alternate_env["PYTHONIOENCODING"] = "utf-16"
        alternate = subprocess.run(
            command, cwd=ROOT, capture_output=True, env=alternate_env
        )
        self.assertEqual(first.returncode, 0, first.stderr.decode("utf-8"))
        self.assertEqual(second.returncode, 0, second.stderr.decode("utf-8"))
        self.assertEqual(
            alternate.returncode, 0, alternate.stderr.decode("utf-8")
        )
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stdout, alternate.stdout)
        self.assertTrue(first.stdout.endswith(b"\n"))
        self.assertEqual(
            hashlib.sha256(first.stdout).hexdigest(),
            "78c30164ed80f56dafed3f5f3845ad92a268cbdfc3fd5cc72b2b8fd13277a315",
        )
        self.assertEqual(
            json.loads(first.stdout.decode("utf-8")), MODULE.build_report()
        )

    def test_cli_complete_state_and_partial_rejection(self) -> None:
        partial = self.run_cli(OPTIONS[0], "true")
        self.assertNotEqual(partial.returncode, 0)
        self.assertIn("all AF_UNIX state arguments", partial.stderr)

        args: list[str] = []
        for option in OPTIONS:
            args.extend((option, "true"))
        complete = self.run_cli(*args)
        self.assertEqual(complete.returncode, 0, complete.stderr)
        report = json.loads(complete.stdout)
        self.assertTrue(
            report["classification"][
                "cve_2021_0920_missing_gc_serialization_premise_present"
            ]
        )

    def test_cli_rejects_abbreviation_duplicate_unknown_and_bad_token(self) -> None:
        full_args: list[str] = []
        for option in OPTIONS:
            full_args.extend((option, "true"))
        tail = full_args[2:]
        cases = (
            (("--datagram-peek", "true", *tail), "unrecognized arguments"),
            (
                (OPTIONS[0], "true", OPTIONS[0], "true", *tail),
                "may be specified only once",
            ),
            (
                (OPTIONS[0], "true", OPTIONS[0], "false", *tail),
                "may be specified only once",
            ),
            (("--unknown-state", "true", *full_args), "unrecognized arguments"),
            ((OPTIONS[0], "yes", *tail), "expected true or false"),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
