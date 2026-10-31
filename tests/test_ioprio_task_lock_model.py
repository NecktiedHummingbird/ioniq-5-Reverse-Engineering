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
TOOL = ROOT / "tools/uk_fw/ioprio_task_lock_model.py"
SPEC = importlib.util.spec_from_file_location("ioprio_task_lock_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OPTIONS = tuple(M.PRE_RECORDED_TARGET_STATE)
LOCK_FACTS = OPTIONS[:-1]


def args_for(state: dict[str, bool]) -> list[str]:
    result: list[str] = []
    for name in OPTIONS:
        result += [f"--{name.replace('_', '-')}", str(state[name]).lower()]
    return result


class IoprioTaskLockModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_premise(self) -> None:
        result = M.classify_ioprio_locking(**M.PRE_RECORDED_TARGET_STATE)
        self.assertTrue(result["complete_same_lock_discipline_present"])
        self.assertFalse(result["cve_2016_7911_unlocked_io_context_read_premise_present"])
        self.assertTrue(result["cve_2016_7911_rejected_by_supplied_lock_effects"])
        self.assertFalse(result["cve_2016_7911_not_rejected_by_complete_lock_effects"])
        for name, value in result.items():
            if name.endswith("_observed"):
                self.assertIsNone(value)

    def test_exhaustive_boolean_domain(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            with self.subTest(bits=bits):
                result = M.classify_ioprio_locking(**state)
                complete = all(state[name] for name in LOCK_FACTS)
                unlocked = state["unlocked_io_context_priority_read_present"]
                rejected = complete and not unlocked
                premise = False if rejected else (True if unlocked else None)
                self.assertEqual(result["complete_same_lock_discipline_present"], complete)
                self.assertEqual(
                    result["cve_2016_7911_unlocked_io_context_read_premise_present"],
                    premise,
                )
                self.assertEqual(
                    result["cve_2016_7911_rejected_by_supplied_lock_effects"],
                    rejected,
                )
                self.assertEqual(
                    result["cve_2016_7911_not_rejected_by_complete_lock_effects"],
                    not rejected,
                )

    def test_each_lock_effect_is_required_for_rejection(self) -> None:
        for name in LOCK_FACTS:
            state = dict(M.PRE_RECORDED_TARGET_STATE)
            state[name] = False
            with self.subTest(name=name):
                result = M.classify_ioprio_locking(**state)
                self.assertIsNone(
                    result["cve_2016_7911_unlocked_io_context_read_premise_present"]
                )
                self.assertFalse(result["cve_2016_7911_rejected_by_supplied_lock_effects"])

    def test_explicit_unlocked_read_marks_premise_present(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["unlocked_io_context_priority_read_present"] = True
        result = M.classify_ioprio_locking(**state)
        self.assertTrue(result["cve_2016_7911_unlocked_io_context_read_premise_present"])
        self.assertFalse(result["cve_2016_7911_rejected_by_supplied_lock_effects"])

    def test_rejects_wrong_keys_and_non_booleans(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_ioprio_locking(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
            M.classify_ioprio_locking(**state)

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
            ([option, "true"], "all ioprio task-lock arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--getter-acquires", "true"], "unrecognized arguments"),
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
        self.assertEqual(hashlib.sha256(outputs[0]).hexdigest(), "b1ddc09f0f555188b85ab5f1cab1fa23a3f790844a81967e72bfcc9aeca612c8")

    def test_report_has_no_operational_material(self) -> None:
        encoded = json.dumps(M.build_report(), sort_keys=True).lower()
        for forbidden in ("0xffffffff", "syscall(", "fork(", "ioprio_get("):
            self.assertNotIn(forbidden, encoded)
        self.assertTrue(
            M.build_report()["claim_boundary"][
                "emits_no_target_syscall_task_race_schedule_command_payload_instructions_or_firmware_bytes"
            ]
        )


if __name__ == "__main__":
    unittest.main()
