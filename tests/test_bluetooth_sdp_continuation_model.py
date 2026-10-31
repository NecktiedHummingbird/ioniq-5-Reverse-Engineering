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
TOOL = ROOT / "tools/uk_fw/bluetooth_sdp_continuation_model.py"
PATCH = (
    ROOT
    / "evidence/artifacts/network-candidates/226ea26684d4cd609a5b456d3d2cc762453c2d75.patch"
)
SPEC = importlib.util.spec_from_file_location(
    "bluetooth_sdp_continuation_model", TOOL
)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

EXPECTED_FIELDS = {
    "input",
    "syntax_and_continuation_path_available",
    "successful_result_count_role",
    "continuation_offset_role",
    "continuation_offset_relation_to_result_count",
    "bound_check_semantics",
    "unsigned_result_count_bound_check_present",
    "unsigned_result_count_bound_rejects",
    "unsigned_bound_accepts_equality",
    "expected_ccb_offset_match_check_present",
    "expected_ccb_offset_matches",
    "expected_ccb_offset_check_rejects",
    "bound_and_expected_checks_are_independent",
    "both_checks_dominate_subtraction_when_present",
    "both_checks_dominate_later_handle_indexing_when_present",
    "remaining_handle_subtraction_reachable",
    "remaining_handle_difference_relation",
    "later_handle_indexing_reachable_through_modeled_checks",
    "named_underflow_oob_disclosure_mechanism_applicable",
    "named_underflow_oob_disclosure_mechanism_verdict",
    "runtime_sdp_path_observed",
    "malformed_input_behavior_observed",
    "information_disclosure_observed",
    "code_execution_observed",
    "unrestricted_root_observed",
    "persistence_observed",
}
UNKNOWN_FIELDS = {
    "runtime_sdp_path_observed",
    "malformed_input_behavior_observed",
    "information_disclosure_observed",
    "code_execution_observed",
    "unrestricted_root_observed",
    "persistence_observed",
}
DEFAULT_REPORT_SHA256 = (
    "d7db08cc11dd1affbf5bfd086bdbac166c28854ff419b49cebe6717aefeb04ec"
)


def state_for(
    path_available: bool,
    relation: str,
    semantics: str,
    expected_matches: bool,
) -> dict[str, object]:
    return {
        "syntax_and_continuation_path_available": path_available,
        "continuation_offset_relation_to_result_count": relation,
        "bound_check_semantics": semantics,
        "expected_offset_matches": expected_matches,
    }


def expected_classification(state: dict[str, object]) -> dict[str, object]:
    path_available = state["syntax_and_continuation_path_available"]
    relation = state["continuation_offset_relation_to_result_count"]
    semantics = state["bound_check_semantics"]
    expected_matches = state["expected_offset_matches"]
    assert type(path_available) is bool
    assert type(relation) is str
    assert type(semantics) is str
    assert type(expected_matches) is bool

    bound_present = semantics == M.FIXED_SEMANTICS
    if not path_available:
        bound_rejects = None
        expected_rejects = None
    else:
        bound_rejects = relation == "greater-than" if bound_present else None
        expected_rejects = not expected_matches
    subtraction_reachable = bool(
        path_available
        and bound_rejects is not True
        and expected_rejects is False
    )
    difference = "not-reached"
    if subtraction_reachable:
        difference = {
            "less-than": "positive",
            "equal": "zero",
            "greater-than": "unsigned-underflow-candidate",
        }[relation]
    if relation != "greater-than":
        verdict = "not-applicable"
    elif not path_available or not expected_matches or bound_rejects is True:
        verdict = "rejected"
    else:
        verdict = "not-rejected"

    result: dict[str, object] = {
        "input": state,
        "syntax_and_continuation_path_available": path_available,
        "successful_result_count_role": "current-recomputed-successful-result-count",
        "continuation_offset_role": "parsed-current-continuation-offset",
        "continuation_offset_relation_to_result_count": relation,
        "bound_check_semantics": semantics,
        "unsigned_result_count_bound_check_present": bound_present,
        "unsigned_result_count_bound_rejects": bound_rejects,
        "unsigned_bound_accepts_equality": bound_present,
        "expected_ccb_offset_match_check_present": True,
        "expected_ccb_offset_matches": expected_matches,
        "expected_ccb_offset_check_rejects": expected_rejects,
        "bound_and_expected_checks_are_independent": True,
        "both_checks_dominate_subtraction_when_present": bound_present,
        "both_checks_dominate_later_handle_indexing_when_present": bound_present,
        "remaining_handle_subtraction_reachable": subtraction_reachable,
        "remaining_handle_difference_relation": difference,
        "later_handle_indexing_reachable_through_modeled_checks": bool(
            subtraction_reachable and relation != "equal"
        ),
        "named_underflow_oob_disclosure_mechanism_applicable": (
            relation == "greater-than"
        ),
        "named_underflow_oob_disclosure_mechanism_verdict": verdict,
    }
    result.update({name: None for name in UNKNOWN_FIELDS})
    return result


def cli_args(state: dict[str, object]) -> list[str]:
    return [
        "--syntax-and-continuation-path-available",
        str(state["syntax_and_continuation_path_available"]).lower(),
        "--continuation-offset-relation-to-result-count",
        str(state["continuation_offset_relation_to_result_count"]),
        "--bound-check-semantics",
        str(state["bound_check_semantics"]),
        "--expected-offset-matches",
        str(state["expected_offset_matches"]).lower(),
    ]


class BluetoothSdpContinuationModelTests(unittest.TestCase):
    def test_exhaustive_domain_asserts_every_classification_field(self) -> None:
        seen: set[tuple[bool, str, str, bool]] = set()
        for path_available, relation, semantics, expected_matches in itertools.product(
            (False, True), M.RELATIONS, M.BOUND_CHECK_SEMANTICS, (False, True)
        ):
            state = state_for(
                path_available, relation, semantics, expected_matches
            )
            with self.subTest(state=state):
                result = M.classify_continuation(state)
                self.assertEqual(set(result), EXPECTED_FIELDS)
                self.assertEqual(result, expected_classification(state))
                seen.add((path_available, relation, semantics, expected_matches))
        self.assertEqual(len(seen), 24)

    def test_fixed_and_legacy_semantics_distinguish_named_mechanism(self) -> None:
        for semantics, verdict, subtraction, difference, indexing in (
            (M.FIXED_SEMANTICS, "rejected", False, "not-reached", False),
            (
                "expected-offset-only",
                "not-rejected",
                True,
                "unsigned-underflow-candidate",
                True,
            ),
        ):
            state = state_for(True, "greater-than", semantics, True)
            result = M.classify_continuation(state)
            with self.subTest(semantics=semantics):
                self.assertEqual(
                    result["named_underflow_oob_disclosure_mechanism_verdict"],
                    verdict,
                )
                self.assertEqual(
                    result["remaining_handle_subtraction_reachable"], subtraction
                )
                self.assertEqual(
                    result["remaining_handle_difference_relation"], difference
                )
                self.assertEqual(
                    result[
                        "later_handle_indexing_reachable_through_modeled_checks"
                    ],
                    indexing,
                )

    def test_equality_passes_unsigned_bound_and_yields_zero_not_applicable(self) -> None:
        result = M.classify_continuation(
            state_for(True, "equal", M.FIXED_SEMANTICS, True)
        )
        self.assertFalse(result["unsigned_result_count_bound_rejects"])
        self.assertFalse(result["expected_ccb_offset_check_rejects"])
        self.assertTrue(result["remaining_handle_subtraction_reachable"])
        self.assertEqual(result["remaining_handle_difference_relation"], "zero")
        self.assertFalse(
            result["later_handle_indexing_reachable_through_modeled_checks"]
        )
        self.assertFalse(
            result["named_underflow_oob_disclosure_mechanism_applicable"]
        )
        self.assertEqual(
            result["named_underflow_oob_disclosure_mechanism_verdict"],
            "not-applicable",
        )

    def test_expected_offset_gate_is_independent_of_result_count_bound(self) -> None:
        result = M.classify_continuation(
            state_for(True, "less-than", M.FIXED_SEMANTICS, False)
        )
        self.assertFalse(result["unsigned_result_count_bound_rejects"])
        self.assertTrue(result["expected_ccb_offset_check_rejects"])
        self.assertFalse(result["remaining_handle_subtraction_reachable"])
        self.assertTrue(result["bound_and_expected_checks_are_independent"])

    def test_api_rejects_missing_unknown_keys_and_invalid_types(self) -> None:
        valid = state_for(True, "greater-than", M.FIXED_SEMANTICS, True)
        cases: list[tuple[object, str]] = [
            (None, "mapping object"),
            ([], "mapping object"),
            ({key: value for key, value in valid.items() if key != M.INPUT_KEYS[0]}, "keys mismatch"),
            ({**valid, "unknown": True}, "keys mismatch"),
            ({**valid, "syntax_and_continuation_path_available": 1}, "must be a boolean"),
            ({**valid, "expected_offset_matches": 0}, "must be a boolean"),
            ({**valid, "continuation_offset_relation_to_result_count": True}, "must be one of"),
            ({**valid, "continuation_offset_relation_to_result_count": "other"}, "must be one of"),
            ({**valid, "bound_check_semantics": False}, "must be one of"),
            ({**valid, "bound_check_semantics": "other"}, "must be one of"),
        ]
        for state, message in cases:
            with self.subTest(state=state), self.assertRaisesRegex(
                M.ModelError, message
            ):
                M.classify_continuation(state)

    def test_report_binds_exact_public_and_static_facts(self) -> None:
        report = M.build_report()
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["finite_domain"]["case_count"], 24)
        self.assertEqual(len(report["bounded_matrix"]), 24)
        self.assertEqual(
            report["evidence_binding"]["public_fix"],
            {
                "commit": "226ea26684d4cd609a5b456d3d2cc762453c2d75",
                "patch_sha256": "6f80d9cd3534d00e24c9c33717a282f1e6ae180f05f833e502c7a361e86b2721",
                "source_effect": "reject expected-offset mismatch or result-count-less-than-continuation-offset before subtraction",
                "retained_patch": "evidence/artifacts/network-candidates/226ea26684d4cd609a5b456d3d2cc762453c2d75.patch",
            },
        )
        binaries = report["evidence_binding"]["binaries"]
        expected = {
            "vbtd-51": (
                "55e21d077082e97f56fb113a1d3b216c0f2e63aa02fc4cd754a6593bc6cec9e0",
                "12175aa88ccff70cc56498e0208c9a51aac0c9e9",
                "[0x841a40,0x841dbe)",
                "c91b38ace847bee71d0ab971c7f90d5d3fe5d5347296991b6961e91780cae5f4",
                "0x841b54",
                "0x841b58 -> 0x841bb0",
                "0x841b65",
                "0x841cc8",
            ),
            "vbtd-63": (
                "c56b68fdd35b16b95688ab54a48ffb9f18034d925c057e86f8b9fe304f8b26b9",
                "04141ed222ee8f150c0eb0e46fdb73624d168920",
                "[0x842230,0x8425a6)",
                "c35ecefa9aa2f28268df0c697c79e31c4fe000a1fc56c6ab9aff004dd1a36ef7",
                "0x842344",
                "0x842348 -> 0x8423a0",
                "0x842355",
                "0x8424b0",
            ),
        }
        self.assertEqual(set(binaries), set(expected))
        for name, facts in expected.items():
            with self.subTest(binary=name):
                binding = binaries[name]
                self.assertEqual(binding["sha256"], facts[0])
                self.assertEqual(binding["build_id"], facts[1])
                self.assertEqual(binding["process_service_search_fde"], facts[2])
                self.assertEqual(
                    binding["process_service_search_raw_sha256"], facts[3]
                )
                self.assertEqual(
                    binding["addresses"]["unsigned_bound_compare"], facts[4]
                )
                self.assertEqual(
                    binding["addresses"]["unsigned_above_error_branch"], facts[5]
                )
                self.assertEqual(
                    binding["addresses"]["remaining_handle_subtraction"], facts[6]
                )
                self.assertEqual(
                    binding["addresses"]["later_handle_index_read"], facts[7]
                )
                self.assertEqual(
                    binding["register_bindings"],
                    {
                        "successful_result_count": "bp",
                        "continuation_offset": "r13w",
                        "remaining_handle_count": "ebx",
                    },
                )

    def test_pre_recorded_exact_targets_reject_greater_offset_candidate(self) -> None:
        target = M.build_report()["pre_recorded_exact_target_classification"]
        self.assertEqual(set(target), {"vbtd-51", "vbtd-63"})
        for name, result in target.items():
            with self.subTest(binary=name):
                self.assertEqual(result["input"], M.PRE_RECORDED_TARGET_STATE)
                self.assertTrue(
                    result["unsigned_result_count_bound_check_present"]
                )
                self.assertTrue(result["unsigned_result_count_bound_rejects"])
                self.assertFalse(result["remaining_handle_subtraction_reachable"])
                self.assertEqual(
                    result["named_underflow_oob_disclosure_mechanism_verdict"],
                    "rejected",
                )

    def test_retained_public_patch_has_fixed_authoritative_bytes(self) -> None:
        patch_bytes = PATCH.read_bytes()
        self.assertEqual(
            hashlib.sha256(patch_bytes).hexdigest(),
            "6f80d9cd3534d00e24c9c33717a282f1e6ae180f05f833e502c7a361e86b2721",
        )
        self.assertEqual(
            patch_bytes,
            (
                b"diff --git a/stack/sdp/sdp_server.cc b/stack/sdp/sdp_server.cc\n"
                b"index fe67be1..24a168c 100644\n"
                b"--- a/stack/sdp/sdp_server.cc\n"
                b"+++ b/stack/sdp/sdp_server.cc\n"
                b"@@ -218,7 +218,7 @@\n"
                b"     }\n"
                b"     BE_STREAM_TO_UINT16(cont_offset, p_req);\n"
                b" \n"
                b"-    if (cont_offset != p_ccb->cont_offset) {\n"
                b"+    if (cont_offset != p_ccb->cont_offset || num_rsp_handles < cont_offset) {\n"
                b"       sdpu_build_n_send_error(p_ccb, trans_num, SDP_INVALID_CONT_STATE,\n"
                b"                               SDP_TEXT_BAD_CONT_INX);\n"
                b"       return;\n"
            ),
        )

    def test_cli_complete_and_fail_closed(self) -> None:
        state = state_for(True, "greater-than", M.FIXED_SEMANTICS, True)
        good = subprocess.run(
            [sys.executable, str(TOOL), *cli_args(state)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(
            json.loads(good.stdout)["classification"],
            expected_classification(state),
        )

        option = "--syntax-and-continuation-path-available"
        cases = (
            ([option, "true"], "must be supplied together"),
            ([option, "true", option, "false"], "only once"),
            ([option, "1"], "expected true or false"),
            (["--syntax-and-continuation-path", "true"], "unrecognized arguments"),
            (["--unknown", "true"], "unrecognized arguments"),
            (
                [
                    option,
                    "true",
                    "--continuation-offset-relation-to-result-count",
                    "other",
                ],
                "invalid choice",
            ),
        )
        for argv, message in cases:
            with self.subTest(argv=argv):
                bad = subprocess.run(
                    [sys.executable, str(TOOL), *argv],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertNotEqual(bad.returncode, 0)
                self.assertEqual(bad.stdout, b"")
                self.assertIn(message.encode("utf-8"), bad.stderr)

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
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    check=False,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout, expected)
                self.assertTrue(run.stdout.endswith(b"\n"))
                self.assertNotIn(b"\r", run.stdout)
                outputs.append(run.stdout)
        self.assertEqual(len(set(outputs)), 1)
        self.assertEqual(
            hashlib.sha256(outputs[0]).hexdigest(), DEFAULT_REPORT_SHA256
        )

    def test_report_and_source_contain_no_operational_target_material(self) -> None:
        report_text = json.dumps(M.build_report(), sort_keys=True).lower()
        source_text = TOOL.read_text(encoding="utf-8").lower()
        for forbidden in (
            "import socket",
            "import scapy",
            "import bluetooth",
            "l2cap",
            "payload bytes",
            "target command",
            "radio address",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source_text)
                self.assertNotIn(forbidden, report_text)
        boundary = M.build_report()["claim_boundary"]
        self.assertTrue(
            boundary["inputs_are_bounded_booleans_and_finite_states_only"]
        )
        self.assertTrue(boundary["pure_deterministic_host_model"])
        self.assertTrue(
            boundary["emits_no_target_material_or_operational_bluetooth_input"]
        )
        self.assertFalse(boundary["target_execution_performed"])


if __name__ == "__main__":
    unittest.main()
