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
TOOL = ROOT / "tools/uk_fw/fumo_auth_coverage_model.py"
ASSEMBLY = (
    ROOT
    / "evidence/artifacts/update-candidates/appfumo-authentication-coverage.asm"
)
SPEC = importlib.util.spec_from_file_location("fumo_auth_coverage_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OPTIONS = tuple(M.PRE_RECORDED_TARGET_STATE)


def args_for(state: dict[str, bool]) -> list[str]:
    result: list[str] = []
    for name in OPTIONS:
        result += [f"--{name.replace('_', '-')}", str(state[name]).lower()]
    return result


def invalid_reason(state: dict[str, bool]) -> str | None:
    if (
        state["startup_path_reduced_to_base_directory"]
        and not state["startup_executable_path_use_traced"]
    ):
        return "base-directory derivation"
    if (
        state["direct_signature_verifier_targets_classified"]
        and not state["direct_signature_verifier_calls_complete"]
    ):
        return "signature-target classification"
    if (
        state["direct_file_hash_targets_classified"]
        and not state["direct_file_hash_calls_complete"]
    ):
        return "file-hash target classification"
    if (
        state["relaunch_target_verified_before_exec"]
        and not state["relaunch_exec_target_traced"]
    ):
        return "pre-exec verification"
    return None


class FumoAuthCoverageModelTests(unittest.TestCase):
    def test_pre_recorded_state_keeps_parameterized_target_provenance_unknown(self) -> None:
        result = M.classify_auth_coverage(**M.PRE_RECORDED_TARGET_STATE)
        self.assertFalse(result["complete_reviewed_direct_coverage"])
        self.assertIsNone(
            result["inner_reviewed_direct_executable_reauthentication_found"]
        )
        self.assertIsNone(
            result["inner_reviewed_direct_executable_reauthentication_absent"]
        )
        self.assertIsNone(
            result[
                "inner_reviewed_direct_paths_close_outer_executable_identity_gap"
            ]
        )
        self.assertIsNone(
            result[
                "all_inner_and_external_executable_reauthentication_absence_proven"
            ]
        )
        self.assertTrue(result["later_payload_or_descriptor_verification_present"])
        self.assertIsNone(
            result[
                "later_payload_authentication_is_separate_from_outer_executable_authentication"
            ]
        )
        for name, value in result.items():
            if name.endswith("_observed") or name.startswith("runtime_source"):
                self.assertIsNone(value)

    def test_exhaustive_boolean_domain_and_all_classification_fields(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            reason = invalid_reason(state)
            with self.subTest(bits=bits):
                if reason is not None:
                    with self.assertRaisesRegex(M.ModelError, reason):
                        M.classify_auth_coverage(**state)
                    continue

                result = M.classify_auth_coverage(**state)
                complete = all(
                    state[name]
                    for name in (
                        "exact_fumo_identity_bound",
                        "startup_executable_path_use_traced",
                        "startup_path_reduced_to_base_directory",
                        "direct_signature_verifier_calls_complete",
                        "direct_signature_verifier_targets_classified",
                        "direct_file_hash_calls_complete",
                        "direct_file_hash_targets_classified",
                        "relaunch_exec_target_traced",
                    )
                )
                positive = any(
                    state[name]
                    for name in (
                        "running_executable_is_direct_signature_target",
                        "running_executable_is_direct_file_hash_target",
                        "relaunch_target_verified_before_exec",
                    )
                )
                found = True if positive else (False if complete else None)
                absent = False if found is True else (True if found is False else None)
                closes = True if found is True else (False if absent is True else None)
                all_absent = (
                    False
                    if found is True
                    else (
                        True
                        if absent is True
                        and state[
                            "indirect_or_external_executable_reauthentication_excluded"
                        ]
                        else None
                    )
                )
                separate = (
                    True
                    if state["payload_or_descriptor_verification_present"]
                    and absent is True
                    else None
                )

                self.assertEqual(result["input"], state)
                self.assertEqual(result["complete_reviewed_direct_coverage"], complete)
                self.assertEqual(
                    result[
                        "inner_reviewed_direct_executable_reauthentication_found"
                    ],
                    found,
                )
                self.assertEqual(
                    result[
                        "inner_reviewed_direct_executable_reauthentication_absent"
                    ],
                    absent,
                )
                self.assertEqual(
                    result[
                        "inner_reviewed_direct_paths_close_outer_executable_identity_gap"
                    ],
                    closes,
                )
                self.assertEqual(
                    result[
                        "all_inner_and_external_executable_reauthentication_absence_proven"
                    ],
                    all_absent,
                )
                self.assertEqual(
                    result["later_payload_or_descriptor_verification_present"],
                    state["payload_or_descriptor_verification_present"],
                )
                self.assertEqual(
                    result[
                        "later_payload_authentication_is_separate_from_outer_executable_authentication"
                    ],
                    separate,
                )
                for name in (
                    "runtime_source_mutability_established",
                    "verified_and_consumed_executables_observed_different",
                    "successful_inner_process_creation_observed",
                    "later_update_acceptance_observed",
                    "partition_write_observed",
                    "slot_switch_observed",
                    "boot_acceptance_observed",
                    "privilege_transition_observed",
                    "persistence_observed",
                ):
                    self.assertIsNone(result[name])

    def test_positive_direct_paths_override_incomplete_negative_coverage(self) -> None:
        for fact in (
            "running_executable_is_direct_signature_target",
            "running_executable_is_direct_file_hash_target",
            "relaunch_target_verified_before_exec",
        ):
            state = {name: False for name in OPTIONS}
            state[fact] = True
            if fact == "relaunch_target_verified_before_exec":
                state["relaunch_exec_target_traced"] = True
            result = M.classify_auth_coverage(**state)
            with self.subTest(fact=fact):
                self.assertTrue(
                    result[
                        "inner_reviewed_direct_executable_reauthentication_found"
                    ]
                )
                self.assertFalse(
                    result[
                        "inner_reviewed_direct_executable_reauthentication_absent"
                    ]
                )
                self.assertTrue(
                    result[
                        "inner_reviewed_direct_paths_close_outer_executable_identity_gap"
                    ]
                )
                self.assertFalse(
                    result[
                        "all_inner_and_external_executable_reauthentication_absence_proven"
                    ]
                )

    def test_incomplete_negative_facts_remain_unknown(self) -> None:
        state = {name: False for name in OPTIONS}
        result = M.classify_auth_coverage(**state)
        self.assertIsNone(
            result["inner_reviewed_direct_executable_reauthentication_found"]
        )
        self.assertIsNone(
            result["inner_reviewed_direct_executable_reauthentication_absent"]
        )
        self.assertIsNone(
            result[
                "inner_reviewed_direct_paths_close_outer_executable_identity_gap"
            ]
        )

    def test_absolute_absence_requires_complete_targets_and_external_exclusion(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["direct_signature_verifier_targets_classified"] = True
        state["indirect_or_external_executable_reauthentication_excluded"] = True
        result = M.classify_auth_coverage(**state)
        self.assertTrue(
            result[
                "all_inner_and_external_executable_reauthentication_absence_proven"
            ]
        )

    def test_rejects_wrong_keys_non_booleans_and_dependency_conflicts(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_auth_coverage(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
            M.classify_auth_coverage(**state)

        conflicts = (
            (
                "startup_executable_path_use_traced",
                "base-directory derivation",
            ),
            (
                "direct_signature_verifier_calls_complete",
                "signature-target classification",
            ),
            (
                "direct_file_hash_calls_complete",
                "file-hash target classification",
            ),
            ("relaunch_exec_target_traced", "pre-exec verification"),
        )
        for fact, message in conflicts:
            state = dict(M.PRE_RECORDED_TARGET_STATE)
            state[fact] = False
            if fact == "direct_signature_verifier_calls_complete":
                state["direct_signature_verifier_targets_classified"] = True
            if fact == "relaunch_exec_target_traced":
                state["relaunch_target_verified_before_exec"] = True
            with self.subTest(fact=fact):
                with self.assertRaisesRegex(M.ModelError, message):
                    M.classify_auth_coverage(**state)

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
            ([option, "true"], "all FUMO authentication-coverage arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--fumo-auth", "true"], "unrecognized arguments"),
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
            "1192767f643c2cb075cb6f8f80e6fe7ce4555e7104daa7cf63a3735f7460c39f",
        )

    def test_retained_assembly_hash_and_report_binding(self) -> None:
        digest = hashlib.sha256(ASSEMBLY.read_bytes()).hexdigest()
        self.assertEqual(digest, M.ASSEMBLY_SHA256)
        self.assertEqual(
            M.build_report()["evidence_binding"]["retained_assembly_sha256"],
            digest,
        )

    def test_report_has_no_operational_material(self) -> None:
        report = M.build_report()
        self.assertTrue(
            report["claim_boundary"][
                "emits_no_firmware_update_archive_command_path_payload_launch_message_or_race_schedule"
            ]
        )
        encoded = json.dumps(report, sort_keys=True).lower()
        for forbidden in ("cp -f", "decrypttopipe", "/update/", "/navi/", "qprocess"):
            self.assertNotIn(forbidden, encoded)


if __name__ == "__main__":
    unittest.main()
