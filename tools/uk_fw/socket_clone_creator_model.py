#!/usr/bin/env python3
"""Classify bounded exact-static CVE-2018-9568 socket-clone facts.

Every semantic input and every observational output is Boolean. The one-hot
classification is deterministic and fails closed to ``indeterminate`` when
required facts are incomplete or contradictory. This host-only model performs
no target execution, socket operation, clone, traffic, trigger, exploit,
privilege action, or persistence action.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
VMLINUX_BUILD_ID = "273378887b4cf563c10862fdf18b2292765df781"
KALLSYMS_SHA256 = "2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f"
CONFIG_SHA256 = "987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56"
CANONICAL_PUBLIC_SOURCE_DIRECTORY = (
    "work/online-kernel-candidates-20261107/cve-2018-9568/"
)
MAINLINE_COMMIT = "9d538fa60bad4f7b23193c89e843797a1cf71ef3"
MAINLINE_PARENT = "b32ca44a88def4bf92626d8777494c6f14638c42"
MAINLINE_PATCH_SHA256 = (
    "c1f7389124f499cc764ce39a25f841bc701f0d3e8e4ab6a86f3c578941ed085d"
)
STABLE_COMMIT = "0a11ea32304f6ad6daf5589b6626775b7f00015c"
STABLE_PARENT = "cafd2b53da565ca30c48a146635c95d385d83b81"
STABLE_PATCH_SHA256 = (
    "756c9749346bda510e242b02b849448418196bc1f95684dbcbbf362eff60d8ba"
)
ARTIFACT_SHA256 = "e876c4eddfc08de17ded57371c447a93c44a44031265c34fb5ffa1decb253273"

STATE_KEYS = (
    "public_issue_contract_matches",
    "ipv6_addrform_protocol_divergence_present",
    "tcp_child_clone_route_present",
    "named_route_absence_established",
    "allocation_uses_source_current_protocol",
    "clone_copy_overwrites_creator",
    "final_free_uses_creator_protocol_cache",
    "direct_creator_reset_to_allocator_protocol",
    "equivalent_creator_cache_binding_dominates_all_cleanup",
    "reset_after_every_creator_overwriting_copy",
    "reset_before_every_in_function_post_copy_free",
    "no_creator_overwrite_after_reset",
    "all_successful_returns_follow_reset",
    "caller_cleanup_only_after_corrected_return",
    "reset_absence_established",
)
CLASSIFICATION_KEYS = (
    "direct_patch_shape",
    "equivalent_fix",
    "vulnerable_semantics",
    "absent_route",
    "indeterminate",
)
PRE_RECORDED_TARGET_STATE = {
    "public_issue_contract_matches": True,
    "ipv6_addrform_protocol_divergence_present": True,
    "tcp_child_clone_route_present": True,
    "named_route_absence_established": False,
    "allocation_uses_source_current_protocol": True,
    "clone_copy_overwrites_creator": True,
    "final_free_uses_creator_protocol_cache": True,
    "direct_creator_reset_to_allocator_protocol": True,
    "equivalent_creator_cache_binding_dominates_all_cleanup": False,
    "reset_after_every_creator_overwriting_copy": True,
    "reset_before_every_in_function_post_copy_free": True,
    "no_creator_overwrite_after_reset": True,
    "all_successful_returns_follow_reset": True,
    "caller_cleanup_only_after_corrected_return": True,
    "reset_absence_established": False,
}


class ModelError(ValueError):
    """Raised when state keys or values violate the Boolean-only contract."""


def validate_state(state: Mapping[str, object]) -> dict[str, bool]:
    if not isinstance(state, Mapping):
        raise ModelError("state must be a mapping")
    supplied = set(state)
    expected = set(STATE_KEYS)
    missing = sorted(expected - supplied)
    unknown = sorted(supplied - expected)
    if missing:
        raise ModelError("missing state key(s): " + ", ".join(missing))
    if unknown:
        raise ModelError("unknown state key(s): " + ", ".join(unknown))
    result: dict[str, bool] = {}
    for key in STATE_KEYS:
        value = state[key]
        if not isinstance(value, bool):
            raise ModelError(f"{key} must be a boolean")
        result[key] = value
    return result


def classify_cve_2018_9568(state: Mapping[str, object]) -> dict[str, Any]:
    """Return exact Boolean outputs and a mutually exclusive classification."""

    values = validate_state(state)
    route_complete = (
        values["ipv6_addrform_protocol_divergence_present"]
        and values["tcp_child_clone_route_present"]
    )
    allocator_creator_free_contract_complete = (
        values["allocation_uses_source_current_protocol"]
        and values["clone_copy_overwrites_creator"]
        and values["final_free_uses_creator_protocol_cache"]
    )
    direct_reset = values["direct_creator_reset_to_allocator_protocol"]
    equivalent_binding = values[
        "equivalent_creator_cache_binding_dominates_all_cleanup"
    ]
    reset_ordering_facts = (
        values["reset_after_every_creator_overwriting_copy"],
        values["reset_before_every_in_function_post_copy_free"],
        values["no_creator_overwrite_after_reset"],
        values["all_successful_returns_follow_reset"],
        values["caller_cleanup_only_after_corrected_return"],
    )
    correction_ordering_complete = all(reset_ordering_facts)
    conflicting_evidence = (
        (
            values["named_route_absence_established"]
            and (
                values["ipv6_addrform_protocol_divergence_present"]
                or values["tcp_child_clone_route_present"]
            )
        )
        or (direct_reset and equivalent_binding)
        or (
            values["reset_absence_established"]
            and (direct_reset or equivalent_binding or any(reset_ordering_facts))
        )
        or (any(reset_ordering_facts) and not direct_reset)
    )
    fix_contract_complete = (
        values["public_issue_contract_matches"]
        and allocator_creator_free_contract_complete
    )
    vulnerable_contract_complete = fix_contract_complete and route_complete

    direct = (
        not conflicting_evidence
        and fix_contract_complete
        and direct_reset
        and correction_ordering_complete
    )
    equivalent = (
        not conflicting_evidence
        and not direct
        and fix_contract_complete
        and equivalent_binding
    )
    vulnerable = (
        not conflicting_evidence
        and not direct
        and not equivalent
        and vulnerable_contract_complete
        and values["reset_absence_established"]
    )
    absent = (
        not conflicting_evidence
        and not direct
        and not equivalent
        and not vulnerable
        and values["public_issue_contract_matches"]
        and values["named_route_absence_established"]
        and not values["ipv6_addrform_protocol_divergence_present"]
        and not values["tcp_child_clone_route_present"]
    )
    indeterminate = not (direct or equivalent or vulnerable or absent)
    classification = {
        "direct_patch_shape": direct,
        "equivalent_fix": equivalent,
        "vulnerable_semantics": vulnerable,
        "absent_route": absent,
        "indeterminate": indeterminate,
    }
    assert sum(classification.values()) == 1
    rejected = direct or equivalent or absent
    return {
        "input": values,
        "classification": classification,
        "route_components_complete": route_complete,
        "allocator_creator_free_contract_complete": (
            allocator_creator_free_contract_complete
        ),
        "correction_ordering_complete": correction_ordering_complete,
        "conflicting_evidence": conflicting_evidence,
        "cve_2018_9568_rejected_for_exact_state": rejected,
        "direct_patch_provenance_established": False,
        "general_socket_or_allocator_safety_established": False,
        "runtime_reachability_established": False,
        "wrong_cache_free_observed": False,
        "memory_corruption_observed": False,
        "privilege_escalation_observed": False,
        "unrestricted_root_observed": False,
        "persistence_observed": False,
        "owner_installed_identity_established": False,
    }


def build_report(state: Mapping[str, object] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "exact-static-cve-2018-9568-socket-clone-creator",
        "cve": "CVE-2018-9568",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "authoritative_kallsyms_sha256": KALLSYMS_SHA256,
            "kernel_config_sha256": CONFIG_SHA256,
            "canonical_public_source_directory": CANONICAL_PUBLIC_SOURCE_DIRECTORY,
            "mainline_commit": MAINLINE_COMMIT,
            "mainline_parent": MAINLINE_PARENT,
            "mainline_patch_sha256": MAINLINE_PATCH_SHA256,
            "stable_commit": STABLE_COMMIT,
            "stable_parent": STABLE_PARENT,
            "stable_patch_sha256": STABLE_PATCH_SHA256,
            "exact_static_artifact_sha256": ARTIFACT_SHA256,
            "assessment": "evidence/vendor-kernel-socket-clone-cve-2018-9568.md",
            "pre_recorded_target_state_source": (
                "separate bounded instruction-level review; not verified by model execution"
            ),
        },
        "claim_boundary": {
            "inputs_are_boolean_only": True,
            "observational_outputs_are_boolean_only": True,
            "classification_is_one_hot": True,
            "fail_closed_to_indeterminate": True,
            "separates_direct_equivalent_vulnerable_absent_and_unknown": True,
            "emits_only_non_operational_classification_metadata": True,
        },
        "pre_recorded_target_classification": classify_cve_2018_9568(
            PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_cve_2018_9568(state)
    return report


def _cli_boolean(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _SingleBooleanAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: bool,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for key in STATE_KEYS:
        parser.add_argument(
            "--" + key.replace("_", "-"),
            dest=key,
            type=_cli_boolean,
            action=_SingleBooleanAction,
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {key: getattr(args, key) for key in STATE_KEYS}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all socket-clone state arguments must be supplied together")
    try:
        report = build_report(state if all(supplied) else None)
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    serialized = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    sys.stdout.buffer.write(serialized + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
