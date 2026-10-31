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
TOOL = ROOT / "tools/uk_fw/assoc_array_leaf_guard_model.py"
SPEC = importlib.util.spec_from_file_location("assoc_array_leaf_guard_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OPTIONS = tuple(M.PRE_RECORDED_TARGET_STATE)
GUARD_FACTS = OPTIONS[:-1]


def args_for(state: dict[str, bool]) -> list[str]:
    result: list[str] = []
    for name in OPTIONS:
        result += [f"--{name.replace('_', '-')}", str(state[name]).lower()]
    return result


class AssocArrayLeafGuardModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_premise(self) -> None:
        result = M.classify_leaf_guard(**M.PRE_RECORDED_TARGET_STATE)
        self.assertTrue(result["complete_terminal_leaf_guard_present"])
        self.assertFalse(result["cve_2016_7914_nonleaf_callback_premise_present"])
        self.assertTrue(result["cve_2016_7914_rejected_by_supplied_guard_effects"])
        self.assertFalse(result["cve_2016_7914_not_rejected_by_complete_guard_effects"])
        for name, value in result.items():
            if name.endswith("_observed"):
                self.assertIsNone(value)

    def test_exhaustive_boolean_domain(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            with self.subTest(bits=bits):
                result = M.classify_leaf_guard(**state)
                complete = all(state[name] for name in GUARD_FACTS)
                bad_path = state["nonleaf_compare_callback_path_present"]
                rejected = complete and not bad_path
                premise = False if rejected else (True if bad_path else None)
                self.assertEqual(result["complete_terminal_leaf_guard_present"], complete)
                self.assertEqual(
                    result["cve_2016_7914_nonleaf_callback_premise_present"], premise
                )
                self.assertEqual(
                    result["cve_2016_7914_rejected_by_supplied_guard_effects"],
                    rejected,
                )
                self.assertEqual(
                    result["cve_2016_7914_not_rejected_by_complete_guard_effects"],
                    not rejected,
                )

    def test_each_guard_fact_is_required_for_rejection(self) -> None:
        for name in GUARD_FACTS:
            state = dict(M.PRE_RECORDED_TARGET_STATE)
            state[name] = False
            with self.subTest(name=name):
                result = M.classify_leaf_guard(**state)
                self.assertIsNone(result["cve_2016_7914_nonleaf_callback_premise_present"])
                self.assertFalse(result["cve_2016_7914_rejected_by_supplied_guard_effects"])

    def test_explicit_nonleaf_path_marks_premise_present(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["nonleaf_compare_callback_path_present"] = True
        result = M.classify_leaf_guard(**state)
        self.assertTrue(result["cve_2016_7914_nonleaf_callback_premise_present"])
        self.assertFalse(result["cve_2016_7914_rejected_by_supplied_guard_effects"])

    def test_rejects_wrong_keys_and_non_booleans(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_leaf_guard(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
            M.classify_leaf_guard(**state)

    def test_cli_complete_and_fail_closed_cases(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        run = subprocess.run(
            [sys.executable, str(TOOL), *args_for(state)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["classification"]["input"], state)
        option = f"--{OPTIONS[0].replace('_', '-')}"
        for argv, text in (
            ([option, "true"], "all associative-array guard arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--terminal-node-path", "true"], "unrecognized arguments"),
            ([option, "yes"], "expected true or false"),
        ):
            with self.subTest(argv=argv):
                run = subprocess.run(
                    [sys.executable, str(TOOL), *argv],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(run.returncode, 0)
                self.assertIn(text, run.stderr)

    def test_default_output_deterministic_utf8_lf(self) -> None:
        expected = json.dumps(M.build_report(), indent=2, sort_keys=True).encode() + b"\n"
        outputs = []
        for encoding in ("ascii:strict", "latin-1:strict", "utf-16:strict"):
            env = dict(os.environ, PYTHONIOENCODING=encoding)
            run = subprocess.run(
                [sys.executable, str(TOOL)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            self.assertEqual(run.stdout, expected)
            self.assertNotIn(b"\r", run.stdout)
            outputs.append(run.stdout)
        self.assertEqual(len(set(outputs)), 1)
        self.assertEqual(hashlib.sha256(outputs[0]).hexdigest(), "8e05d9116d95742d33ec070ab880ade4c1a72a0d4690bd411fafdff30fd40c01")

    def test_report_has_no_operational_material(self) -> None:
        encoded = json.dumps(M.build_report(), sort_keys=True).lower()
        for forbidden in ("0xffffffff", "add_key(", "keyctl(", "syscall("):
            self.assertNotIn(forbidden, encoded)
        self.assertTrue(
            M.build_report()["claim_boundary"][
                "emits_no_target_syscall_key_descriptor_race_schedule_command_payload_instructions_or_firmware_bytes"
            ]
        )


if __name__ == "__main__":
    unittest.main()
