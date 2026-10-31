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
TOOL = ROOT / "tools/uk_fw/tty_ldisc_getd_lock_model.py"
SPEC = importlib.util.spec_from_file_location("tty_ldisc_getd_lock_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OPTIONS = tuple(M.PRE_RECORDED_TARGET_STATE)
FIX_FACTS = tuple(M.FIX_FACTS)
CONTRARY_FACT = M.CONTRARY_FACT
OBSERVED_FIELDS = {
    "installed_kernel_identity_observed",
    "runtime_line_discipline_transition_observed",
    "concurrent_read_and_change_observed",
    "unlocked_dereference_observed",
    "stale_or_freed_reference_access_observed",
    "kernel_disclosure_observed",
    "kernel_crash_observed",
    "memory_corruption_observed",
    "privilege_escalation_observed",
    "persistence_observed",
}
EXPECTED_FIELDS = {
    "input",
    "complete_retained_reference_fix_effect_present",
    "cve_2016_0723_unlocked_dereference_race_premise_present",
    "cve_2016_0723_rejected_by_supplied_fix_effects",
    "cve_2016_0723_not_rejected_by_complete_fix_effects",
    *OBSERVED_FIELDS,
}


def args_for(state: dict[str, bool]) -> list[str]:
    result: list[str] = []
    for name in OPTIONS:
        result += [f"--{name.replace('_', '-')}", str(state[name]).lower()]
    return result


class TtyLdiscGetdLockModelTests(unittest.TestCase):
    def assert_classification(self, result: dict, state: dict[str, bool]) -> None:
        complete = all(state[name] for name in FIX_FACTS)
        contrary = state[CONTRARY_FACT]
        rejected = complete and not contrary
        premise = False if rejected else (True if contrary else None)

        self.assertEqual(set(result), EXPECTED_FIELDS)
        self.assertEqual(result["input"], state)
        self.assertEqual(
            result["complete_retained_reference_fix_effect_present"], complete
        )
        self.assertEqual(
            result["cve_2016_0723_unlocked_dereference_race_premise_present"],
            premise,
        )
        self.assertEqual(
            result["cve_2016_0723_rejected_by_supplied_fix_effects"], rejected
        )
        self.assertEqual(
            result["cve_2016_0723_not_rejected_by_complete_fix_effects"],
            not rejected,
        )
        for name in OBSERVED_FIELDS:
            self.assertIsNone(result[name])

    def test_pre_recorded_state_rejects_named_race(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        result = M.classify_ldisc_reference(**state)
        self.assert_classification(result, state)
        self.assertTrue(result["complete_retained_reference_fix_effect_present"])
        self.assertFalse(
            result["cve_2016_0723_unlocked_dereference_race_premise_present"]
        )
        self.assertTrue(result["cve_2016_0723_rejected_by_supplied_fix_effects"])

    def test_exhaustive_boolean_domain_and_every_output(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            with self.subTest(bits=bits):
                self.assert_classification(
                    M.classify_ldisc_reference(**state), state
                )

    def test_each_fix_fact_is_required_for_rejection(self) -> None:
        for name in FIX_FACTS:
            state = dict(M.PRE_RECORDED_TARGET_STATE)
            state[name] = False
            with self.subTest(name=name):
                result = M.classify_ldisc_reference(**state)
                self.assert_classification(result, state)
                self.assertIsNone(
                    result[
                        "cve_2016_0723_unlocked_dereference_race_premise_present"
                    ]
                )
                self.assertFalse(
                    result["cve_2016_0723_rejected_by_supplied_fix_effects"]
                )

    def test_explicit_unlocked_path_marks_premise_present(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state[CONTRARY_FACT] = True
        result = M.classify_ldisc_reference(**state)
        self.assert_classification(result, state)
        self.assertTrue(
            result["cve_2016_0723_unlocked_dereference_race_premise_present"]
        )
        self.assertFalse(result["cve_2016_0723_rejected_by_supplied_fix_effects"])

    def test_rejects_wrong_keys_and_non_booleans(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_ldisc_reference(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
            M.classify_ldisc_reference(**state)

    def test_cli_complete_and_fail_closed_cases(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        run = subprocess.run(
            [sys.executable, str(TOOL), *args_for(state)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["classification"]["input"], state)
        self.assert_classification(report["classification"], state)

        option = f"--{OPTIONS[0].replace('_', '-')}"
        for argv, text in (
            ([option, "true"], "all line-discipline reference arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--dispatch-reaches", "true"], "unrecognized arguments"),
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
        self.assertEqual(
            hashlib.sha256(outputs[0]).hexdigest(),
            "26ada294eb83e8d7986a00fadf0b2a458dc5332ae331fa95d8adb174bf47e3c7",
        )

    def test_report_has_no_operational_material(self) -> None:
        report = M.build_report()
        encoded = json.dumps(report, sort_keys=True).lower()
        for forbidden in (
            "0xffffffff",
            "0x5424",
            "tiocgetd",
            "syscall(",
            "ioctl(",
            "openpty(",
            "pthread_create(",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertTrue(
            report["claim_boundary"]["emits_no_operational_material_or_target_bytes"]
        )


if __name__ == "__main__":
    unittest.main()
