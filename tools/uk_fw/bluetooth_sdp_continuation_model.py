#!/usr/bin/env python3
"""Classify bounded Broadcom BSA SDP continuation-check semantics.

The model consumes only Booleans and finite abstract states. It does not parse
or produce Bluetooth messages and does not execute or inspect a recovered target.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
RELATIONS = ("less-than", "equal", "greater-than")
BOUND_CHECK_SEMANTICS = (
    "expected-offset-only",
    "unsigned-result-bound-then-expected-offset",
)
INPUT_KEYS = (
    "syntax_and_continuation_path_available",
    "continuation_offset_relation_to_result_count",
    "bound_check_semantics",
    "expected_offset_matches",
)

PUBLIC_FIX_COMMIT = "226ea26684d4cd609a5b456d3d2cc762453c2d75"
PUBLIC_PATCH_SHA256 = (
    "6f80d9cd3534d00e24c9c33717a282f1e6ae180f05f833e502c7a361e86b2721"
)
FIXED_SEMANTICS = "unsigned-result-bound-then-expected-offset"

BINARY_BINDINGS: dict[str, dict[str, Any]] = {
    "vbtd-51": {
        "installed_path": "/app/bin/vbtd-51",
        "sha256": "55e21d077082e97f56fb113a1d3b216c0f2e63aa02fc4cd754a6593bc6cec9e0",
        "build_id": "12175aa88ccff70cc56498e0208c9a51aac0c9e9",
        "elf_type": "ET_DYN",
        "address_basis": "PIE image virtual address before runtime relocation",
        "process_service_search_fde": "[0x841a40,0x841dbe)",
        "process_service_search_raw_sha256": (
            "c91b38ace847bee71d0ab971c7f90d5d3fe5d5347296991b6961e91780cae5f4"
        ),
        "register_bindings": {
            "successful_result_count": "bp",
            "continuation_offset": "r13w",
            "remaining_handle_count": "ebx",
        },
        "addresses": {
            "successful_result_increment": "0x841af2",
            "continuation_offset_assembly": "0x841b36-0x841b46",
            "ccb_expected_offset_load": "0x841b4d (+0xb6)",
            "unsigned_bound_compare": "0x841b54",
            "unsigned_above_error_branch": "0x841b58 -> 0x841bb0",
            "expected_offset_compare": "0x841b5a",
            "expected_offset_mismatch_error_branch": "0x841b5e -> 0x841bb0",
            "remaining_handle_subtraction": "0x841b65",
            "later_handle_index_read": "0x841cc8",
            "code_5_error_call": "0x841bc0",
        },
    },
    "vbtd-63": {
        "installed_path": "/app/bin/vbtd-63",
        "sha256": "c56b68fdd35b16b95688ab54a48ffb9f18034d925c057e86f8b9fe304f8b26b9",
        "build_id": "04141ed222ee8f150c0eb0e46fdb73624d168920",
        "elf_type": "ET_DYN",
        "address_basis": "PIE image virtual address before runtime relocation",
        "process_service_search_fde": "[0x842230,0x8425a6)",
        "process_service_search_raw_sha256": (
            "c35ecefa9aa2f28268df0c697c79e31c4fe000a1fc56c6ab9aff004dd1a36ef7"
        ),
        "register_bindings": {
            "successful_result_count": "bp",
            "continuation_offset": "r13w",
            "remaining_handle_count": "ebx",
        },
        "addresses": {
            "successful_result_increment": "0x8422e2",
            "continuation_offset_assembly": "0x842326-0x842336",
            "ccb_expected_offset_load": "0x84233d (+0xb6)",
            "unsigned_bound_compare": "0x842344",
            "unsigned_above_error_branch": "0x842348 -> 0x8423a0",
            "expected_offset_compare": "0x84234a",
            "expected_offset_mismatch_error_branch": "0x84234e -> 0x8423a0",
            "remaining_handle_subtraction": "0x842355",
            "later_handle_index_read": "0x8424b0",
            "code_5_error_call": "0x8423b0",
        },
    },
}

PRE_RECORDED_TARGET_STATE: dict[str, object] = {
    "syntax_and_continuation_path_available": True,
    "continuation_offset_relation_to_result_count": "greater-than",
    "bound_check_semantics": FIXED_SEMANTICS,
    "expected_offset_matches": True,
}


class ModelError(ValueError):
    """Raised when supplied input is outside the finite model domain."""


def _validate_state(state: object) -> dict[str, object]:
    if not isinstance(state, dict):
        raise ModelError("state must be a mapping object")
    expected = set(INPUT_KEYS)
    actual = set(state)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ModelError(f"state keys mismatch: missing={missing}, extra={extra}")

    path_available = state["syntax_and_continuation_path_available"]
    expected_matches = state["expected_offset_matches"]
    if type(path_available) is not bool:
        raise ModelError("syntax_and_continuation_path_available must be a boolean")
    if type(expected_matches) is not bool:
        raise ModelError("expected_offset_matches must be a boolean")

    relation = state["continuation_offset_relation_to_result_count"]
    if type(relation) is not str or relation not in RELATIONS:
        raise ModelError(
            "continuation_offset_relation_to_result_count must be one of "
            f"{RELATIONS}"
        )
    semantics = state["bound_check_semantics"]
    if type(semantics) is not str or semantics not in BOUND_CHECK_SEMANTICS:
        raise ModelError(
            f"bound_check_semantics must be one of {BOUND_CHECK_SEMANTICS}"
        )
    return {name: state[name] for name in INPUT_KEYS}


def classify_continuation(state: object) -> dict[str, Any]:
    """Classify one finite abstract continuation-check state."""
    checked = _validate_state(state)
    path_available = checked["syntax_and_continuation_path_available"]
    relation = checked["continuation_offset_relation_to_result_count"]
    semantics = checked["bound_check_semantics"]
    expected_matches = checked["expected_offset_matches"]
    assert isinstance(path_available, bool)
    assert isinstance(relation, str)
    assert isinstance(semantics, str)
    assert isinstance(expected_matches, bool)

    bound_present = semantics == FIXED_SEMANTICS
    bound_rejects: bool | None
    expected_rejects: bool | None
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
    if not subtraction_reachable:
        difference = "not-reached"
    elif relation == "less-than":
        difference = "positive"
    elif relation == "equal":
        difference = "zero"
    else:
        difference = "unsigned-underflow-candidate"

    later_indexing_reachable = bool(
        subtraction_reachable and relation != "equal"
    )
    if relation != "greater-than":
        verdict = "not-applicable"
    elif not path_available or not expected_matches or bound_rejects is True:
        verdict = "rejected"
    else:
        verdict = "not-rejected"

    return {
        "input": checked,
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
        "later_handle_indexing_reachable_through_modeled_checks": (
            later_indexing_reachable
        ),
        "named_underflow_oob_disclosure_mechanism_applicable": (
            relation == "greater-than"
        ),
        "named_underflow_oob_disclosure_mechanism_verdict": verdict,
        "runtime_sdp_path_observed": None,
        "malformed_input_behavior_observed": None,
        "information_disclosure_observed": None,
        "code_execution_observed": None,
        "unrestricted_root_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, object] | None = None) -> dict[str, Any]:
    """Build the deterministic report, optionally adding one classification."""
    target_classification = classify_continuation(PRE_RECORDED_TARGET_STATE)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "broadcom-bsa-sdp-continuation-cve-2017-0785-exact-static",
        "finite_domain": {
            "syntax_and_continuation_path_available": [False, True],
            "continuation_offset_relation_to_result_count": list(RELATIONS),
            "bound_check_semantics": list(BOUND_CHECK_SEMANTICS),
            "expected_offset_matches": [False, True],
            "case_count": 24,
            "uses_abstract_relations_not_concrete_message_bytes": True,
        },
        "evidence_binding": {
            "binaries": BINARY_BINDINGS,
            "public_fix": {
                "commit": PUBLIC_FIX_COMMIT,
                "patch_sha256": PUBLIC_PATCH_SHA256,
                "source_effect": (
                    "reject expected-offset mismatch or result-count-less-than-"
                    "continuation-offset before subtraction"
                ),
                "retained_patch": (
                    "evidence/artifacts/network-candidates/"
                    "226ea26684d4cd609a5b456d3d2cc762453c2d75.patch"
                ),
            },
            "assessment": (
                "evidence/broadcom-bsa-sdp-continuation-cve-2017-0785.md"
            ),
            "static_excerpt": (
                "evidence/artifacts/network-candidates/"
                "broadcom-bsa-sdp-continuation-exact-static.txt"
            ),
            "pre_recorded_target_state_source": (
                "separate FDE-bounded instruction review; not verified by model execution"
            ),
        },
        "claim_boundary": {
            "establishes": [
                "finite classification of abstract continuation-offset relations",
                "separate result-count bound and expected-CCB-offset gates",
                "safe equality treatment as a zero remaining-handle difference",
                "rejection of the named continuation-offset unsigned-underflow mechanism by the supplied fixed semantics",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions",
                "upstream cherry-pick provenance",
                "general SDP or other-handler safety",
                "runtime handler or channel reachability",
                "installed identity, adapter state, or channel policy",
                "malformed-input behavior or actual information disclosure",
                "code execution, unrestricted root, persistence, or owner-device applicability",
            ],
            "inputs_are_bounded_booleans_and_finite_states_only": True,
            "pure_deterministic_host_model": True,
            "emits_no_target_material_or_operational_bluetooth_input": True,
            "target_execution_performed": False,
        },
        "pre_recorded_exact_target_classification": {
            name: target_classification for name in BINARY_BINDINGS
        },
        "bounded_matrix": [
            classify_continuation(
                {
                    "syntax_and_continuation_path_available": path_available,
                    "continuation_offset_relation_to_result_count": relation,
                    "bound_check_semantics": semantics,
                    "expected_offset_matches": expected_matches,
                }
            )
            for path_available in (False, True)
            for relation in RELATIONS
            for semantics in BOUND_CHECK_SEMANTICS
            for expected_matches in (False, True)
        ],
    }
    if state is not None:
        report["classification"] = classify_continuation(state)
    return report


def _cli_boolean(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _Once(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "--syntax-and-continuation-path-available",
        type=_cli_boolean,
        action=_Once,
    )
    parser.add_argument(
        "--continuation-offset-relation-to-result-count",
        choices=RELATIONS,
        action=_Once,
    )
    parser.add_argument(
        "--bound-check-semantics",
        choices=BOUND_CHECK_SEMANTICS,
        action=_Once,
    )
    parser.add_argument("--expected-offset-matches", type=_cli_boolean, action=_Once)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {
        "syntax_and_continuation_path_available": (
            args.syntax_and_continuation_path_available
        ),
        "continuation_offset_relation_to_result_count": (
            args.continuation_offset_relation_to_result_count
        ),
        "bound_check_semantics": args.bound_check_semantics,
        "expected_offset_matches": args.expected_offset_matches,
    }
    supplied = tuple(value is not None for value in state.values())
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all continuation model arguments must be supplied together")
    try:
        report = build_report(state if all(supplied) else None)
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    sys.stdout.buffer.write(
        json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
