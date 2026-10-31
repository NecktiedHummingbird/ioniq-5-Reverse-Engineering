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
MODEL_PATH = ROOT / "tools" / "uk_fw" / "tty_pgrp_lock_model.py"
SPEC = importlib.util.spec_from_file_location("tty_pgrp_lock_model", MODEL_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

OPTIONS = (
    "--master-and-real-tty-are-distinct-linked-objects",
    "--master-setter-locks-master-and-updates-real-tty-pgrp",
    "--slave-setter-locks-slave-and-updates-same-pgrp",
    "--pgrp-pid-reference-is-released-and-replaced",
)


class TtyPgrpLockModelTests(unittest.TestCase):
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
                result = MODULE.classify_tty_pgrp_locking(*values)
                expected = all(values)
                self.assertIs(
                    result["cve_2020_29661_wrong_object_lock_premise_present"],
                    expected,
                )
                self.assertIs(
                    result["same_pgrp_can_be_updated_under_distinct_locks"], expected
                )
                self.assertIsNone(result["runtime_pty_reachability_observed"])
                self.assertIsNone(
                    result["successful_concurrent_interleaving_observed"]
                )
                self.assertIsNone(result["use_after_free_observed"])
                self.assertIsNone(result["privilege_escalation"])

    def test_rejects_non_boolean_state(self) -> None:
        for index, invalid in enumerate((0, 1, "true", None)):
            values: list[object] = [True] * 4
            values[index] = invalid
            with self.subTest(index=index, invalid=invalid):
                with self.assertRaises(MODULE.ModelError):
                    MODULE.classify_tty_pgrp_locking(*values)

    def test_pre_recorded_state_has_one_source(self) -> None:
        report = MODULE.build_report()
        state = dict(report["evidence_binding"]["pre_recorded_target_state"])
        source = state.pop("source")
        classification = report["pre_recorded_target_classification"]
        self.assertIn("not verified by this model execution", source)
        self.assertEqual(state, MODULE.PRE_RECORDED_TARGET_STATE)
        self.assertEqual(state, classification["input"])
        self.assertTrue(
            classification["cve_2020_29661_wrong_object_lock_premise_present"]
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
            "31d4a3a7615f88b095f8a629edbb12663288c0860c3813ffabaee36f8a148c25",
        )
        self.assertEqual(
            json.loads(first.stdout.decode("utf-8")), MODULE.build_report()
        )

    def test_cli_complete_state_and_partial_rejection(self) -> None:
        partial = self.run_cli(OPTIONS[0], "true")
        self.assertNotEqual(partial.returncode, 0)
        self.assertIn("all TTY pgrp state arguments", partial.stderr)

        args: list[str] = []
        for option in OPTIONS:
            args.extend((option, "true"))
        complete = self.run_cli(*args)
        self.assertEqual(complete.returncode, 0, complete.stderr)
        report = json.loads(complete.stdout)
        self.assertTrue(
            report["classification"][
                "cve_2020_29661_wrong_object_lock_premise_present"
            ]
        )

    def test_cli_rejects_abbreviation_duplicate_unknown_and_bad_token(self) -> None:
        full_args: list[str] = []
        for option in OPTIONS:
            full_args.extend((option, "true"))
        tail = full_args[2:]
        cases = (
            (("--master-and-real", "true", *tail), "unrecognized arguments"),
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
