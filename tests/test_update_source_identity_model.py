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
TOOL = ROOT / "tools/uk_fw/update_source_identity_model.py"
SPEC = importlib.util.spec_from_file_location("update_source_identity_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OPTIONS = tuple(M.PRE_RECORDED_TARGET_STATE)


def args_for(state: dict[str, bool]) -> list[str]:
    result: list[str] = []
    for name in OPTIONS:
        result += [f"--{name.replace('_', '-')}", str(state[name]).lower()]
    return result


class UpdateSourceIdentityModelTests(unittest.TestCase):
    def test_pre_recorded_state_is_static_boundary_not_runtime_bypass(self) -> None:
        result = M.classify_source_identity(**M.PRE_RECORDED_TARGET_STATE)
        self.assertTrue(result["complete_path_reopen_facts"])
        self.assertTrue(result["complete_verification_consumer_sequence_facts"])
        self.assertFalse(result["identity_continuity_mechanism_present"])
        self.assertTrue(result["reviewed_code_lacks_verified_object_identity_binding"])
        self.assertTrue(
            result["conditional_identity_gap_launch_structure_present"]
        )
        self.assertIsNone(result["runtime_name_mapping_substitution_feasible"])
        self.assertIsNone(result["runtime_content_change_feasible"])
        self.assertIsNone(result["runtime_authenticated_content_divergence_feasible"])
        self.assertIsNone(result["runtime_unverified_staged_launch_feasible"])
        for name, value in result.items():
            if name.endswith("_observed") or name.startswith("later_update"):
                self.assertIsNone(value)

    def test_exhaustive_valid_boolean_domain(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            name_mutable = state["runtime_name_mapping_mutability_established"]
            content_mutable = state["runtime_content_mutability_established"]
            mutable = name_mutable or content_mutable
            immutable = state["runtime_source_immutability_established"]
            with self.subTest(bits=bits):
                if mutable and immutable:
                    with self.assertRaisesRegex(M.ModelError, "both mutable and immutable"):
                        M.classify_source_identity(**state)
                    continue
                if (
                    state["later_consumer_reopens_by_pathname"]
                    and state["consumer_uses_verifier_open_description"]
                ):
                    with self.assertRaisesRegex(
                        M.ModelError, "cannot both reopen by pathname"
                    ):
                        M.classify_source_identity(**state)
                    continue

                result = M.classify_source_identity(**state)
                continuity = (
                    state["consumer_uses_verifier_open_description"]
                    or state["consumed_open_object_identity_revalidated"]
                )
                complete = all(
                    state[name]
                    for name in (
                        "verification_receives_pathname",
                        "verifier_returns_status_only",
                        "verification_finishes_before_later_consumer",
                        "later_consumer_reopens_by_pathname",
                    )
                )
                consumer_present = (
                    state["later_consumer_reopens_by_pathname"]
                    or state["consumer_uses_verifier_open_description"]
                    or state["consumed_open_object_identity_revalidated"]
                )
                complete_sequence = (
                    state["verification_receives_pathname"]
                    and state["verifier_returns_status_only"]
                    and state["verification_finishes_before_later_consumer"]
                    and consumer_present
                )
                lacks = False if continuity else (True if complete else None)
                name_substitution = (
                    False
                    if continuity or immutable
                    else (True if lacks is True and name_mutable else None)
                )
                content_change = False if immutable else (True if content_mutable else None)
                authenticated_divergence = (
                    False
                    if immutable
                    or state[
                        "post_stage_authenticated_content_binding_established"
                    ]
                    else (
                        True
                        if name_substitution is True
                        or (complete_sequence and content_change is True)
                        else None
                    )
                )
                if (
                    lacks is False
                    or not state["staged_path_reaches_launch_attempt"]
                    or state[
                        "post_stage_authenticated_content_binding_established"
                    ]
                ):
                    conditional = False
                elif lacks is True:
                    conditional = True
                else:
                    conditional = None
                if (
                    immutable
                    or not state["staged_path_reaches_launch_attempt"]
                    or state[
                        "post_stage_authenticated_content_binding_established"
                    ]
                ):
                    feasible = False
                elif authenticated_divergence is True:
                    feasible = True
                else:
                    feasible = None

                self.assertEqual(result["complete_path_reopen_facts"], complete)
                self.assertEqual(
                    result["complete_verification_consumer_sequence_facts"],
                    complete_sequence,
                )
                self.assertEqual(result["identity_continuity_mechanism_present"], continuity)
                self.assertEqual(
                    result["reviewed_code_lacks_verified_object_identity_binding"], lacks
                )
                self.assertEqual(
                    result["runtime_name_mapping_substitution_feasible"],
                    name_substitution,
                )
                self.assertEqual(result["runtime_content_change_feasible"], content_change)
                self.assertEqual(
                    result["runtime_authenticated_content_divergence_feasible"],
                    authenticated_divergence,
                )
                self.assertEqual(
                    result["conditional_identity_gap_launch_structure_present"],
                    conditional,
                )
                self.assertEqual(
                    result["runtime_unverified_staged_launch_feasible"], feasible
                )

    def test_continuity_or_reauthentication_closes_the_modeled_name_candidate(self) -> None:
        for fact in (
            "consumer_uses_verifier_open_description",
            "consumed_open_object_identity_revalidated",
            "post_stage_authenticated_content_binding_established",
            "runtime_source_immutability_established",
        ):
            state = dict(M.PRE_RECORDED_TARGET_STATE)
            state[fact] = True
            if fact == "consumer_uses_verifier_open_description":
                state["later_consumer_reopens_by_pathname"] = False
            with self.subTest(fact=fact):
                result = M.classify_source_identity(**state)
                if fact in (
                    "post_stage_authenticated_content_binding_established",
                    "runtime_source_immutability_established",
                ):
                    self.assertFalse(result["runtime_unverified_staged_launch_feasible"])
                else:
                    self.assertFalse(
                        result["runtime_name_mapping_substitution_feasible"]
                    )

    def test_explicit_name_mutability_makes_only_the_bounded_candidate_feasible(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["runtime_name_mapping_mutability_established"] = True
        result = M.classify_source_identity(**state)
        self.assertTrue(result["runtime_name_mapping_substitution_feasible"])
        self.assertTrue(result["runtime_authenticated_content_divergence_feasible"])
        self.assertTrue(result["runtime_unverified_staged_launch_feasible"])
        self.assertIsNone(result["later_update_acceptance_observed"])
        self.assertIsNone(result["privilege_transition_observed"])
        self.assertIsNone(result["persistence_observed"])

    def test_content_mutability_is_distinct_from_name_identity(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["later_consumer_reopens_by_pathname"] = False
        state["consumer_uses_verifier_open_description"] = True
        state["runtime_content_mutability_established"] = True
        result = M.classify_source_identity(**state)
        self.assertFalse(result["runtime_name_mapping_substitution_feasible"])
        self.assertTrue(result["runtime_content_change_feasible"])
        self.assertTrue(result["runtime_authenticated_content_divergence_feasible"])
        self.assertTrue(result["runtime_unverified_staged_launch_feasible"])

    def test_rejects_wrong_keys_non_booleans_and_conflicting_source_state(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_source_identity(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
            M.classify_source_identity(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["runtime_content_mutability_established"] = True
        state["runtime_source_immutability_established"] = True
        with self.assertRaisesRegex(M.ModelError, "both mutable and immutable"):
            M.classify_source_identity(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["consumer_uses_verifier_open_description"] = True
        with self.assertRaisesRegex(M.ModelError, "cannot both reopen by pathname"):
            M.classify_source_identity(**state)

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
            ([option, "true"], "all update source-identity arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--verification-path", "true"], "unrecognized arguments"),
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
            "6cbfb25c4b2eaa23da5499f20660ca5208e247be6651ccbc6e68d927155fc23b",
        )

    def test_report_has_no_operational_material(self) -> None:
        report = M.build_report()
        self.assertTrue(
            report["claim_boundary"][
                "emits_no_firmware_update_archive_command_path_payload_launch_message_or_race_schedule"
            ]
        )
        encoded = json.dumps(report, sort_keys=True).lower()
        for forbidden in ("cp -f", "decrypttopipe", "/update/", "qprocess::start"):
            self.assertNotIn(forbidden, encoded)


if __name__ == "__main__":
    unittest.main()
