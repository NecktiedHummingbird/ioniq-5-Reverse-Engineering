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
MODEL_PATH = ROOT / "tools" / "uk_fw" / "kernel_backport_matrix.py"
SPEC = importlib.util.spec_from_file_location("kernel_backport_matrix", MODEL_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

OPTIONS = (
    "--sysvipc-credentials-before-idr",
    "--sysvipc-message-init-before-addid",
    "--sysvipc-shm-init-before-addid",
    "--recvmmsg-skerr-before-fput",
    "--inet-child-mclist-cleared",
)


class KernelBackportMatrixTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MODEL_PATH), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def test_complete_boolean_matrix(self) -> None:
        for values in itertools.product((False, True), repeat=5):
            with self.subTest(values=values):
                result = MODULE.classify_backports(*values)
                expected_sysvipc = all(values[:3])
                self.assertIs(
                    result["cve_2015_7613"]["semantic_fix_present"],
                    expected_sysvipc,
                )
                self.assertIs(
                    result["cve_2015_7613"][
                        "publication_before_initialization_premise_present"
                    ],
                    not expected_sysvipc,
                )
                self.assertIs(
                    result["cve_2016_7117"]["semantic_fix_present"], values[3]
                )
                self.assertIs(
                    result["cve_2016_7117"][
                        "post_fput_socket_dereference_premise_present"
                    ],
                    not values[3],
                )
                self.assertIs(
                    result["cve_2017_8890"]["semantic_fix_present"], values[4]
                )
                self.assertIs(
                    result["cve_2017_8890"][
                        "inherited_multicast_list_premise_present"
                    ],
                    not values[4],
                )
                self.assertIs(
                    result["all_three_semantic_fixes_present"], all(values)
                )
                self.assertIsNone(result["local_privilege_escalation"])

    def test_rejects_non_boolean_state(self) -> None:
        baseline: list[object] = [True] * 5
        for index, invalid in enumerate((0, 1, "true", None, [])):
            values = baseline.copy()
            values[index] = invalid
            with self.subTest(index=index, invalid=invalid):
                with self.assertRaises(MODULE.ModelError):
                    MODULE.classify_backports(*values)

    def test_pre_recorded_state_has_one_source_and_is_unverified(self) -> None:
        report = MODULE.build_report()
        state = dict(report["evidence_binding"]["pre_recorded_target_state"])
        source = state.pop("source")
        classification = report["pre_recorded_target_classification"]
        self.assertIn("not verified by this model execution", source)
        self.assertEqual(state, MODULE.PRE_RECORDED_TARGET_STATE)
        self.assertEqual(state, classification["input"])
        self.assertTrue(classification["all_three_semantic_fixes_present"])
        boundary = report["claim_boundary"]
        self.assertTrue(boundary["inputs_are_boolean_only"])
        self.assertTrue(boundary["emits_no_binary_or_trigger_material"])

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
            "01a8084d9c9f00885777163a895e9d7aae86629897509c01a4a4253b69df2905",
        )
        self.assertEqual(
            json.loads(first.stdout.decode("utf-8")), MODULE.build_report()
        )

    def test_cli_complete_state_and_partial_rejection(self) -> None:
        partial = self.run_cli(OPTIONS[0], "true")
        self.assertNotEqual(partial.returncode, 0)
        self.assertIn("all backport-state arguments", partial.stderr)

        args: list[str] = []
        for option in OPTIONS:
            args.extend((option, "true"))
        complete = self.run_cli(*args)
        self.assertEqual(complete.returncode, 0, complete.stderr)
        report = json.loads(complete.stdout)
        self.assertTrue(report["classification"]["all_three_semantic_fixes_present"])

    def test_cli_rejects_abbreviation_duplicate_unknown_and_bad_token(self) -> None:
        full_args: list[str] = []
        for option in OPTIONS:
            full_args.extend((option, "true"))
        tail = full_args[2:]
        cases = (
            (
                ("--sysvipc-credentials", "true", *tail),
                "unrecognized arguments",
            ),
            (
                (OPTIONS[0], "true", OPTIONS[0], "true", *tail),
                "may be specified only once",
            ),
            (
                (OPTIONS[0], "true", OPTIONS[0], "false", *tail),
                "may be specified only once",
            ),
            (
                ("--unknown-state", "true", *full_args),
                "unrecognized arguments",
            ),
            (
                (OPTIONS[0], "yes", *tail),
                "expected true or false",
            ),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
