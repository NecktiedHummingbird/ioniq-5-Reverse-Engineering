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
TOOL = ROOT / "tools/uk_fw/pipe_iov_iterator_model.py"
SPEC = importlib.util.spec_from_file_location("pipe_iov_iterator_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OPTIONS = tuple(M.PRE_RECORDED_EXACT_STATE)
REQUIRED_FIXED_FACTS = (
    "public_cve_requires_legacy_mutable_iovec_fallback",
    *M.SITE_FACTS,
    *M.FROM_EFFECT_FACTS,
    *M.TO_EFFECT_FACTS,
)
NULL_FIELDS = {
    "every_vendor_equivalent_defect_absent",
    *M.RUNTIME_NULL_FIELDS,
}
EXPECTED_FIELDS = {
    "input",
    "all_three_copy_sites_iterator_based",
    "from_iterator_bounded_progress_effects_complete",
    "to_iterator_bounded_progress_effects_complete",
    "complete_iterator_architecture_present",
    "progress_preserving_effects_present",
    "broken_legacy_path_precedence_applied",
    "cve_2015_1805_required_legacy_premise_present",
    "cve_2015_1805_rejected_for_supplied_exact_static_state",
    "cve_2015_1805_not_rejected_for_supplied_exact_static_state",
    "ordinary_local_pipe_functionality_present",
    "ordinary_local_pipe_absence_established",
    "general_pipe_or_iterator_safety_established",
    *NULL_FIELDS,
}


def cli_args(state: dict[str, bool]) -> list[str]:
    args: list[str] = []
    for name in OPTIONS:
        args.extend([f"--{name.replace('_', '-')}", str(state[name]).lower()])
    return args


def expected_classification(state: dict[str, bool]) -> dict[str, object]:
    sites = all(state[name] for name in M.SITE_FACTS)
    from_effects = all(state[name] for name in M.FROM_EFFECT_FACTS)
    to_effects = all(state[name] for name in M.TO_EFFECT_FACTS)
    iterator_architecture = sites and from_effects and to_effects
    progress_preserving = (
        iterator_architecture
        or state["legacy_progress_preserving_alternative_present"]
    )
    broken = state["broken_legacy_mutable_iovec_path_present"]
    rejected = (
        state["public_cve_requires_legacy_mutable_iovec_fallback"]
        and progress_preserving
        and not broken
    )
    premise = True if broken else (False if rejected else None)
    ordinary = state["ordinary_local_pipe_functionality_present"]
    result: dict[str, object] = {
        "input": state,
        "all_three_copy_sites_iterator_based": sites,
        "from_iterator_bounded_progress_effects_complete": from_effects,
        "to_iterator_bounded_progress_effects_complete": to_effects,
        "complete_iterator_architecture_present": iterator_architecture,
        "progress_preserving_effects_present": progress_preserving,
        "broken_legacy_path_precedence_applied": broken,
        "cve_2015_1805_required_legacy_premise_present": premise,
        "cve_2015_1805_rejected_for_supplied_exact_static_state": rejected,
        "cve_2015_1805_not_rejected_for_supplied_exact_static_state": not rejected,
        "ordinary_local_pipe_functionality_present": ordinary,
        "ordinary_local_pipe_absence_established": False if ordinary else None,
        "general_pipe_or_iterator_safety_established": False,
        "every_vendor_equivalent_defect_absent": None,
    }
    result.update({name: None for name in M.RUNTIME_NULL_FIELDS})
    return result


class PipeIovIteratorModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_only_exact_cve_premise(self) -> None:
        result = M.classify_pipe_iterator_state(**M.PRE_RECORDED_EXACT_STATE)
        self.assertEqual(set(result), EXPECTED_FIELDS)
        self.assertTrue(result["all_three_copy_sites_iterator_based"])
        self.assertTrue(result["from_iterator_bounded_progress_effects_complete"])
        self.assertTrue(result["to_iterator_bounded_progress_effects_complete"])
        self.assertTrue(result["complete_iterator_architecture_present"])
        self.assertFalse(result["broken_legacy_path_precedence_applied"])
        self.assertFalse(result["cve_2015_1805_required_legacy_premise_present"])
        self.assertTrue(
            result["cve_2015_1805_rejected_for_supplied_exact_static_state"]
        )
        self.assertTrue(result["ordinary_local_pipe_functionality_present"])
        self.assertFalse(result["ordinary_local_pipe_absence_established"])
        self.assertFalse(result["general_pipe_or_iterator_safety_established"])
        for name in NULL_FIELDS:
            self.assertIsNone(result[name])

    def test_exhaustive_domain_asserts_every_classification_field(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            with self.subTest(bits=bits):
                result = M.classify_pipe_iterator_state(**state)
                self.assertEqual(set(result), EXPECTED_FIELDS)
                self.assertEqual(result, expected_classification(state))

    def test_every_required_fixed_fact_is_needed_without_alternative(self) -> None:
        for name in REQUIRED_FIXED_FACTS:
            state = dict(M.PRE_RECORDED_EXACT_STATE)
            state[name] = False
            with self.subTest(name=name):
                result = M.classify_pipe_iterator_state(**state)
                self.assertFalse(
                    result[
                        "cve_2015_1805_rejected_for_supplied_exact_static_state"
                    ]
                )
                self.assertIsNone(
                    result["cve_2015_1805_required_legacy_premise_present"]
                )

    def test_explicit_broken_legacy_path_takes_precedence(self) -> None:
        state = dict(M.PRE_RECORDED_EXACT_STATE)
        state["broken_legacy_mutable_iovec_path_present"] = True
        state["legacy_progress_preserving_alternative_present"] = True
        result = M.classify_pipe_iterator_state(**state)
        self.assertTrue(result["complete_iterator_architecture_present"])
        self.assertTrue(result["progress_preserving_effects_present"])
        self.assertTrue(result["broken_legacy_path_precedence_applied"])
        self.assertTrue(result["cve_2015_1805_required_legacy_premise_present"])
        self.assertFalse(
            result["cve_2015_1805_rejected_for_supplied_exact_static_state"]
        )

    def test_progress_preserving_legacy_alternative_is_optional_and_bounded(self) -> None:
        state = {name: False for name in OPTIONS}
        state["public_cve_requires_legacy_mutable_iovec_fallback"] = True
        state["legacy_progress_preserving_alternative_present"] = True
        for ordinary in (False, True):
            state["ordinary_local_pipe_functionality_present"] = ordinary
            with self.subTest(ordinary=ordinary):
                result = M.classify_pipe_iterator_state(**state)
                self.assertFalse(result["complete_iterator_architecture_present"])
                self.assertTrue(result["progress_preserving_effects_present"])
                self.assertTrue(
                    result[
                        "cve_2015_1805_rejected_for_supplied_exact_static_state"
                    ]
                )
                self.assertFalse(
                    result["cve_2015_1805_required_legacy_premise_present"]
                )

    def test_ordinary_functionality_scope_never_broadens_verdict(self) -> None:
        for ordinary in (False, True):
            state = dict(M.PRE_RECORDED_EXACT_STATE)
            state["ordinary_local_pipe_functionality_present"] = ordinary
            with self.subTest(ordinary=ordinary):
                result = M.classify_pipe_iterator_state(**state)
                self.assertEqual(
                    result["ordinary_local_pipe_functionality_present"], ordinary
                )
                self.assertEqual(
                    result["ordinary_local_pipe_absence_established"],
                    False if ordinary else None,
                )
                self.assertFalse(result["general_pipe_or_iterator_safety_established"])
                self.assertTrue(
                    result[
                        "cve_2015_1805_rejected_for_supplied_exact_static_state"
                    ]
                )

    def test_rejects_wrong_keys_and_non_boolean_values(self) -> None:
        state = dict(M.PRE_RECORDED_EXACT_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_pipe_iterator_state(**state)
        state = dict(M.PRE_RECORDED_EXACT_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
            M.classify_pipe_iterator_state(**state)

    def test_cli_complete_and_fail_closed_cases(self) -> None:
        state = dict(M.PRE_RECORDED_EXACT_STATE)
        run = subprocess.run(
            [sys.executable, str(TOOL), *cli_args(state)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["classification"]["input"], state)

        option = f"--{OPTIONS[0].replace('_', '-')}"
        cases = (
            ([option, "true"], "all exact-static applicability arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--public-cve-requires-legacy", "true"], "unrecognized arguments"),
            ([option, "yes"], "expected true or false"),
        )
        for argv, message in cases:
            with self.subTest(argv=argv):
                run = subprocess.run(
                    [sys.executable, str(TOOL), *argv],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, "")
                self.assertIn(message, run.stderr)

    def test_default_output_is_deterministic_explicit_utf8_lf(self) -> None:
        expected = (
            json.dumps(M.build_report(), indent=2, sort_keys=True).encode("utf-8")
            + b"\n"
        )
        outputs = []
        for encoding in ("ascii:strict", "latin-1:strict", "utf-16:strict"):
            with self.subTest(encoding=encoding):
                env = dict(os.environ, PYTHONIOENCODING=encoding)
                run = subprocess.run(
                    [sys.executable, str(TOOL)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                self.assertEqual(run.stdout, expected)
                self.assertTrue(run.stdout.endswith(b"\n"))
                self.assertNotIn(b"\r", run.stdout)
                outputs.append(run.stdout)
        self.assertEqual(len(set(outputs)), 1)
        self.assertEqual(
            hashlib.sha256(outputs[0]).hexdigest(),
            "3f5dd658e3bdb5dab12e91537c9d26455d11b43826e7dce22932ab0ebc8649b0",
        )

    def test_report_emits_only_non_operational_classification_metadata(self) -> None:
        report = M.build_report()
        encoded = json.dumps(report, sort_keys=True).lower()
        for forbidden in (
            "0xffffffff",
            "construction",
            "syscall",
            "fault",
            "address",
            "instruction",
            "trigger",
            "race",
            "allocation",
            "payload",
            "command",
            "target",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, encoded)
        self.assertTrue(report["claim_boundary"]["inputs_are_boolean_only"])
        self.assertTrue(
            report["claim_boundary"][
                "emits_only_non_operational_classification_metadata"
            ]
        )


if __name__ == "__main__":
    unittest.main()
