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
MODEL_PATH = ROOT / "tools" / "uk_fw" / "socket_clone_creator_model.py"
SPEC = importlib.util.spec_from_file_location("socket_clone_creator_model", MODEL_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

RESULT_KEYS = {
    "input",
    "classification",
    "route_components_complete",
    "allocator_creator_free_contract_complete",
    "correction_ordering_complete",
    "conflicting_evidence",
    "cve_2018_9568_rejected_for_exact_state",
    "direct_patch_provenance_established",
    "general_socket_or_allocator_safety_established",
    "runtime_reachability_established",
    "wrong_cache_free_observed",
    "memory_corruption_observed",
    "privilege_escalation_observed",
    "unrestricted_root_observed",
    "persistence_observed",
    "owner_installed_identity_established",
}
OBSERVATION_KEYS = {
    "direct_patch_provenance_established",
    "general_socket_or_allocator_safety_established",
    "runtime_reachability_established",
    "wrong_cache_free_observed",
    "memory_corruption_observed",
    "privilege_escalation_observed",
    "unrestricted_root_observed",
    "persistence_observed",
    "owner_installed_identity_established",
}
OPTIONS = tuple("--" + key.replace("_", "-") for key in MODULE.STATE_KEYS)
RESET_ORDERING_KEYS = (
    "reset_after_every_creator_overwriting_copy",
    "reset_before_every_in_function_post_copy_free",
    "no_creator_overwrite_after_reset",
    "all_successful_returns_follow_reset",
    "caller_cleanup_only_after_corrected_return",
)
EXPECTED_EVIDENCE_BINDING = {
    "vmlinux_sha256": "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b",
    "vmlinux_build_id": "273378887b4cf563c10862fdf18b2292765df781",
    "authoritative_kallsyms_sha256": "2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f",
    "kernel_config_sha256": "987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56",
    "canonical_public_source_directory": (
        "work/online-kernel-candidates-20261107/cve-2018-9568/"
    ),
    "mainline_commit": "9d538fa60bad4f7b23193c89e843797a1cf71ef3",
    "mainline_parent": "b32ca44a88def4bf92626d8777494c6f14638c42",
    "mainline_patch_sha256": "c1f7389124f499cc764ce39a25f841bc701f0d3e8e4ab6a86f3c578941ed085d",
    "stable_commit": "0a11ea32304f6ad6daf5589b6626775b7f00015c",
    "stable_parent": "cafd2b53da565ca30c48a146635c95d385d83b81",
    "stable_patch_sha256": "756c9749346bda510e242b02b849448418196bc1f95684dbcbbf362eff60d8ba",
    "exact_static_artifact_sha256": "e876c4eddfc08de17ded57371c447a93c44a44031265c34fb5ffa1decb253273",
    "assessment": "evidence/vendor-kernel-socket-clone-cve-2018-9568.md",
    "pre_recorded_target_state_source": (
        "separate bounded instruction-level review; not verified by model execution"
    ),
}
EXPECTED_CLAIM_BOUNDARY = {
    "inputs_are_boolean_only": True,
    "observational_outputs_are_boolean_only": True,
    "classification_is_one_hot": True,
    "fail_closed_to_indeterminate": True,
    "separates_direct_equivalent_vulnerable_absent_and_unknown": True,
    "emits_only_non_operational_classification_metadata": True,
}


def expected_values(state: dict[str, bool]) -> tuple[dict[str, bool], dict[str, bool]]:
    route = (
        state["ipv6_addrform_protocol_divergence_present"]
        and state["tcp_child_clone_route_present"]
    )
    allocator_free = (
        state["allocation_uses_source_current_protocol"]
        and state["clone_copy_overwrites_creator"]
        and state["final_free_uses_creator_protocol_cache"]
    )
    direct_reset = state["direct_creator_reset_to_allocator_protocol"]
    equivalent_binding = state[
        "equivalent_creator_cache_binding_dominates_all_cleanup"
    ]
    ordering_values = tuple(state[key] for key in RESET_ORDERING_KEYS)
    ordering = all(ordering_values)
    conflicting = (
        (
            state["named_route_absence_established"]
            and (
                state["ipv6_addrform_protocol_divergence_present"]
                or state["tcp_child_clone_route_present"]
            )
        )
        or (direct_reset and equivalent_binding)
        or (
            state["reset_absence_established"]
            and (direct_reset or equivalent_binding or any(ordering_values))
        )
        or (any(ordering_values) and not direct_reset)
    )
    fix_contract = state["public_issue_contract_matches"] and allocator_free
    direct = not conflicting and fix_contract and direct_reset and ordering
    equivalent = (
        not conflicting
        and not direct
        and fix_contract
        and equivalent_binding
    )
    vulnerable = (
        not conflicting
        and not direct
        and not equivalent
        and fix_contract
        and route
        and state["reset_absence_established"]
    )
    absent = (
        not conflicting
        and not direct
        and not equivalent
        and not vulnerable
        and state["public_issue_contract_matches"]
        and state["named_route_absence_established"]
        and not state["ipv6_addrform_protocol_divergence_present"]
        and not state["tcp_child_clone_route_present"]
    )
    classification = {
        "direct_patch_shape": direct,
        "equivalent_fix": equivalent,
        "vulnerable_semantics": vulnerable,
        "absent_route": absent,
        "indeterminate": not (direct or equivalent or vulnerable or absent),
    }
    derived = {
        "route_components_complete": route,
        "allocator_creator_free_contract_complete": allocator_free,
        "correction_ordering_complete": ordering,
        "conflicting_evidence": conflicting,
        "cve_2018_9568_rejected_for_exact_state": direct or equivalent or absent,
    }
    return classification, derived


class SocketCloneCreatorModelTests(unittest.TestCase):
    maxDiff = None

    def run_cli(
        self, *args: str, text: bool = True, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(MODEL_PATH), *args],
            cwd=ROOT,
            text=text,
            capture_output=True,
            env=env,
        )

    def test_complete_boolean_matrix_and_every_emitted_result_field(self) -> None:
        self.assertEqual(len(MODULE.STATE_KEYS), 15)
        for values in itertools.product((False, True), repeat=len(MODULE.STATE_KEYS)):
            state = dict(zip(MODULE.STATE_KEYS, values, strict=True))
            with self.subTest(values=values):
                result = MODULE.classify_cve_2018_9568(state)
                self.assertEqual(set(result), RESULT_KEYS)
                self.assertEqual(list(result["input"]), list(MODULE.STATE_KEYS))
                self.assertEqual(result["input"], state)
                self.assertEqual(
                    list(result["classification"]),
                    list(MODULE.CLASSIFICATION_KEYS),
                )
                expected_classification, expected_derived = expected_values(state)
                self.assertEqual(result["classification"], expected_classification)
                self.assertEqual(sum(result["classification"].values()), 1)
                for key in MODULE.CLASSIFICATION_KEYS:
                    self.assertIs(type(result["classification"][key]), bool)
                for key, expected in expected_derived.items():
                    self.assertIs(result[key], expected)
                for key in OBSERVATION_KEYS:
                    self.assertIs(result[key], False)
                for key in RESULT_KEYS - {"input", "classification"}:
                    self.assertIs(type(result[key]), bool)

    def test_named_classification_vectors_and_conflicts(self) -> None:
        base = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        cases: list[tuple[str, dict[str, bool]]] = [("direct_patch_shape", base)]

        equivalent = dict(base)
        equivalent["direct_creator_reset_to_allocator_protocol"] = False
        equivalent[
            "equivalent_creator_cache_binding_dominates_all_cleanup"
        ] = True
        for key in RESET_ORDERING_KEYS:
            equivalent[key] = False
        cases.append(("equivalent_fix", equivalent))

        vulnerable = dict(equivalent)
        vulnerable[
            "equivalent_creator_cache_binding_dominates_all_cleanup"
        ] = False
        vulnerable["reset_absence_established"] = True
        cases.append(("vulnerable_semantics", vulnerable))

        absent = dict(vulnerable)
        absent["reset_absence_established"] = False
        absent["ipv6_addrform_protocol_divergence_present"] = False
        absent["tcp_child_clone_route_present"] = False
        absent["named_route_absence_established"] = True
        cases.append(("absent_route", absent))

        conflicting = dict(base)
        conflicting[
            "equivalent_creator_cache_binding_dominates_all_cleanup"
        ] = True
        cases.append(("indeterminate", conflicting))

        incomplete = dict(base)
        incomplete["public_issue_contract_matches"] = False
        cases.append(("indeterminate", incomplete))

        for expected_name, state in cases:
            with self.subTest(expected_name=expected_name, state=state):
                classification = MODULE.classify_cve_2018_9568(state)[
                    "classification"
                ]
                self.assertTrue(classification[expected_name])
                self.assertEqual(
                    [key for key, value in classification.items() if value],
                    [expected_name],
                )

    def test_each_missing_direct_ordering_fact_fails_closed(self) -> None:
        for key in RESET_ORDERING_KEYS:
            state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
            state[key] = False
            with self.subTest(missing_ordering_fact=key):
                result = MODULE.classify_cve_2018_9568(state)
                self.assertFalse(result["correction_ordering_complete"])
                self.assertEqual(
                    result["classification"],
                    {
                        "direct_patch_shape": False,
                        "equivalent_fix": False,
                        "vulnerable_semantics": False,
                        "absent_route": False,
                        "indeterminate": True,
                    },
                )

    def test_rejects_missing_unknown_keys_and_invalid_types(self) -> None:
        valid = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        for key in MODULE.STATE_KEYS:
            missing = dict(valid)
            del missing[key]
            with self.subTest(kind="missing", key=key):
                with self.assertRaisesRegex(MODULE.ModelError, "missing state key"):
                    MODULE.classify_cve_2018_9568(missing)

        unknown = dict(valid)
        unknown["unknown_fact"] = True
        with self.assertRaisesRegex(MODULE.ModelError, "unknown state key"):
            MODULE.classify_cve_2018_9568(unknown)

        for key in MODULE.STATE_KEYS:
            for invalid in (0, 1, "true", None, [], {}):
                bad = dict(valid)
                bad[key] = invalid
                with self.subTest(kind="type", key=key, invalid=invalid):
                    with self.assertRaisesRegex(MODULE.ModelError, "must be a boolean"):
                        MODULE.classify_cve_2018_9568(bad)

        for invalid_state in (None, [], "state", True):
            with self.subTest(kind="mapping", invalid_state=invalid_state):
                with self.assertRaisesRegex(MODULE.ModelError, "must be a mapping"):
                    MODULE.classify_cve_2018_9568(invalid_state)

    def test_pre_recorded_target_is_direct_fix_with_separate_boundaries(self) -> None:
        report = MODULE.build_report()
        self.assertEqual(
            set(report),
            {
                "schema_version",
                "model",
                "cve",
                "evidence_binding",
                "claim_boundary",
                "pre_recorded_target_classification",
            },
        )
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(
            report["model"], "exact-static-cve-2018-9568-socket-clone-creator"
        )
        self.assertEqual(report["cve"], "CVE-2018-9568")
        self.assertEqual(report["evidence_binding"], EXPECTED_EVIDENCE_BINDING)
        self.assertEqual(report["claim_boundary"], EXPECTED_CLAIM_BOUNDARY)
        for key, expected in EXPECTED_EVIDENCE_BINDING.items():
            with self.subTest(evidence_binding=key):
                self.assertEqual(report["evidence_binding"][key], expected)
        for key, expected in EXPECTED_CLAIM_BOUNDARY.items():
            with self.subTest(claim_boundary=key):
                self.assertIs(report["claim_boundary"][key], expected)
        result = report["pre_recorded_target_classification"]
        self.assertEqual(set(result), RESULT_KEYS)
        self.assertEqual(result["input"], MODULE.PRE_RECORDED_TARGET_STATE)
        self.assertEqual(
            result["classification"],
            {
                "direct_patch_shape": True,
                "equivalent_fix": False,
                "vulnerable_semantics": False,
                "absent_route": False,
                "indeterminate": False,
            },
        )
        self.assertTrue(result["route_components_complete"])
        self.assertTrue(result["allocator_creator_free_contract_complete"])
        self.assertTrue(result["correction_ordering_complete"])
        self.assertFalse(result["conflicting_evidence"])
        self.assertTrue(result["cve_2018_9568_rejected_for_exact_state"])
        for key in OBSERVATION_KEYS:
            self.assertFalse(result[key])
        self.assertEqual(
            set(report["evidence_binding"]), set(EXPECTED_EVIDENCE_BINDING)
        )
        self.assertEqual(set(report["claim_boundary"]), set(EXPECTED_CLAIM_BOUNDARY))

    def test_no_argument_cli_is_deterministic_explicit_utf8_fixed_lf(self) -> None:
        first = self.run_cli(text=False)
        second = self.run_cli(text=False)
        alternate_env = dict(os.environ)
        alternate_env["PYTHONIOENCODING"] = "utf-16"
        alternate = self.run_cli(text=False, env=alternate_env)
        self.assertEqual(first.returncode, 0, first.stderr.decode("utf-8"))
        self.assertEqual(second.returncode, 0, second.stderr.decode("utf-8"))
        self.assertEqual(alternate.returncode, 0, alternate.stderr.decode("utf-8"))
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stdout, alternate.stdout)
        self.assertTrue(first.stdout.endswith(b"\n"))
        self.assertEqual(first.stdout.count(b"\n\n"), 0)
        self.assertNotIn(b"\r", first.stdout)
        decoded = first.stdout.decode("utf-8")
        self.assertEqual(decoded.encode("utf-8"), first.stdout)
        self.assertEqual(json.loads(decoded), MODULE.build_report())
        self.assertEqual(
            hashlib.sha256(first.stdout).hexdigest(),
            "aa495e1103098e4926d1996a9bf31c4bdea8b0c3c8a6358f0cb71c6ea60cc1cd",
        )

    def test_cli_complete_state_and_partial_rejection(self) -> None:
        partial = self.run_cli(OPTIONS[0], "true")
        self.assertNotEqual(partial.returncode, 0)
        self.assertIn("all socket-clone state arguments", partial.stderr)

        args: list[str] = []
        for key, option in zip(MODULE.STATE_KEYS, OPTIONS, strict=True):
            args.extend(
                (
                    option,
                    "true" if MODULE.PRE_RECORDED_TARGET_STATE[key] else "false",
                )
            )
        complete = self.run_cli(*args)
        self.assertEqual(complete.returncode, 0, complete.stderr)
        report = json.loads(complete.stdout)
        self.assertEqual(
            set(report),
            {
                "schema_version",
                "model",
                "cve",
                "evidence_binding",
                "claim_boundary",
                "pre_recorded_target_classification",
                "classification",
            },
        )
        self.assertTrue(report["classification"]["classification"]["direct_patch_shape"])

    def test_cli_rejects_abbreviation_duplicate_unknown_and_bad_token(self) -> None:
        full_args: list[str] = []
        for key, option in zip(MODULE.STATE_KEYS, OPTIONS, strict=True):
            value = "true" if MODULE.PRE_RECORDED_TARGET_STATE[key] else "false"
            full_args.extend((option, value))
        tail = full_args[2:]
        cases = (
            (("--public-issue-contract", "true", *tail), "unrecognized arguments"),
            (
                (OPTIONS[0], "true", OPTIONS[0], "true", *tail),
                "may be specified only once",
            ),
            (("--unknown-state", "true", *full_args), "unrecognized arguments"),
            ((OPTIONS[0], "yes", *tail), "expected true or false"),
            ((OPTIONS[0], "TRUE", *tail), "expected true or false"),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main()
