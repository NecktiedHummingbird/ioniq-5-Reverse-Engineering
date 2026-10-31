#!/usr/bin/env python3
"""Classify bounded exact-static CVE-2015-1805 applicability facts.

Inputs are booleans only. The output is deterministic classification metadata;
it does not perform dynamic kernel interaction or emit an operational procedure.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
VMLINUX_BUILD_ID = "273378887b4cf563c10862fdf18b2292765df781"
CONFIG_SHA256 = "987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56"
KALLSYMS_SHA256 = "2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f"
INTRODUCING_COMMIT = "f6762b7ad8edd6abc802542ce845d3bc8adcb92f"
INTRODUCING_PATCH_SHA256 = (
    "ad43bba30d7d3be2e15c17b605f6d17d92f17fa3ebb239bd2bdc457b10746aec"
)
READ_ITERATOR_COMMIT = "637b58c2887e5e57850865839cc75f59184b23d1"
READ_ITERATOR_PATCH_SHA256 = (
    "d44d40a61f9746ec3a8fd2ab6c88f74f0ce09617786ac27f59174effbabaeb5c"
)
WRITE_ITERATOR_COMMIT = "f0d1bec9d58d4c038d0ac958c9af82be6eb18045"
WRITE_ITERATOR_PATCH_SHA256 = (
    "c5966a0a700deb343e5599a716fb116988a85238134099925ced6fda3524340a"
)

PRE_RECORDED_EXACT_STATE = {
    "public_cve_requires_legacy_mutable_iovec_fallback": True,
    "write_merge_site_uses_from_iterator_helper": True,
    "write_new_buffer_site_uses_from_iterator_helper": True,
    "read_site_uses_to_iterator_helper": True,
    "from_helper_clamps_to_iterator_count": True,
    "from_helper_traverses_fixed_descriptors_without_mutation": True,
    "from_helper_accounts_requested_minus_residual": True,
    "from_helper_carries_progress_into_fallback": True,
    "from_helper_commits_bounded_iterator_state": True,
    "to_helper_clamps_to_iterator_count": True,
    "to_helper_traverses_fixed_descriptors_without_mutation": True,
    "to_helper_accounts_requested_minus_residual": True,
    "to_helper_carries_progress_into_fallback": True,
    "to_helper_commits_bounded_iterator_state": True,
    "broken_legacy_mutable_iovec_path_present": False,
    "legacy_progress_preserving_alternative_present": False,
    "ordinary_local_pipe_functionality_present": True,
}

FROM_EFFECT_FACTS = (
    "from_helper_clamps_to_iterator_count",
    "from_helper_traverses_fixed_descriptors_without_mutation",
    "from_helper_accounts_requested_minus_residual",
    "from_helper_carries_progress_into_fallback",
    "from_helper_commits_bounded_iterator_state",
)
TO_EFFECT_FACTS = (
    "to_helper_clamps_to_iterator_count",
    "to_helper_traverses_fixed_descriptors_without_mutation",
    "to_helper_accounts_requested_minus_residual",
    "to_helper_carries_progress_into_fallback",
    "to_helper_commits_bounded_iterator_state",
)
SITE_FACTS = (
    "write_merge_site_uses_from_iterator_helper",
    "write_new_buffer_site_uses_from_iterator_helper",
    "read_site_uses_to_iterator_helper",
)
RUNTIME_NULL_FIELDS = (
    "installed_kernel_identity_observed",
    "runtime_local_access_policy_observed",
    "runtime_copy_failure_observed",
    "memory_corruption_observed",
    "privilege_escalation_observed",
    "root_observed",
    "persistence_observed",
)


class ModelError(ValueError):
    """Raised when supplied state is outside the Boolean-only contract."""


def classify_pipe_iterator_state(**values: bool) -> dict[str, Any]:
    expected = set(PRE_RECORDED_EXACT_STATE)
    if set(values) != expected:
        raise ModelError(
            f"state keys mismatch: missing={sorted(expected - set(values))}, "
            f"extra={sorted(set(values) - expected)}"
        )

    state: dict[str, bool] = {}
    for name in PRE_RECORDED_EXACT_STATE:
        value = values[name]
        if not isinstance(value, bool):
            raise ModelError(f"{name} must be a boolean")
        state[name] = value

    all_sites = all(state[name] for name in SITE_FACTS)
    from_effects = all(state[name] for name in FROM_EFFECT_FACTS)
    to_effects = all(state[name] for name in TO_EFFECT_FACTS)
    complete_iterator_architecture = all_sites and from_effects and to_effects
    progress_preserving_effects = (
        complete_iterator_architecture
        or state["legacy_progress_preserving_alternative_present"]
    )
    broken_legacy_path = state["broken_legacy_mutable_iovec_path_present"]
    rejected = (
        state["public_cve_requires_legacy_mutable_iovec_fallback"]
        and progress_preserving_effects
        and not broken_legacy_path
    )

    required_legacy_premise: bool | None
    if broken_legacy_path:
        required_legacy_premise = True
    elif rejected:
        required_legacy_premise = False
    else:
        required_legacy_premise = None

    ordinary_present = state["ordinary_local_pipe_functionality_present"]
    result: dict[str, Any] = {
        "input": state,
        "all_three_copy_sites_iterator_based": all_sites,
        "from_iterator_bounded_progress_effects_complete": from_effects,
        "to_iterator_bounded_progress_effects_complete": to_effects,
        "complete_iterator_architecture_present": complete_iterator_architecture,
        "progress_preserving_effects_present": progress_preserving_effects,
        "broken_legacy_path_precedence_applied": broken_legacy_path,
        "cve_2015_1805_required_legacy_premise_present": required_legacy_premise,
        "cve_2015_1805_rejected_for_supplied_exact_static_state": rejected,
        "cve_2015_1805_not_rejected_for_supplied_exact_static_state": not rejected,
        "ordinary_local_pipe_functionality_present": ordinary_present,
        "ordinary_local_pipe_absence_established": False if ordinary_present else None,
        "general_pipe_or_iterator_safety_established": False,
        "every_vendor_equivalent_defect_absent": None,
    }
    result.update({name: None for name in RUNTIME_NULL_FIELDS})
    return result


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "exact-static-pipe-iterator-applicability",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "configuration_sha256": CONFIG_SHA256,
            "authoritative_map_sha256": KALLSYMS_SHA256,
            "introducing_commit": INTRODUCING_COMMIT,
            "introducing_patch_sha256": INTRODUCING_PATCH_SHA256,
            "read_iterator_commit": READ_ITERATOR_COMMIT,
            "read_iterator_patch_sha256": READ_ITERATOR_PATCH_SHA256,
            "write_iterator_commit": WRITE_ITERATOR_COMMIT,
            "write_iterator_patch_sha256": WRITE_ITERATOR_PATCH_SHA256,
            "pre_recorded_exact_state": {
                "source": "separate complete static review; not verified by this model run",
                **PRE_RECORDED_EXACT_STATE,
            },
            "assessment": "evidence/vendor-kernel-pipe-cve-2015-1805.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied exact-static architecture facts",
                "unknown when required fixed-effect facts are incomplete",
                "explicit precedence for a contrary broken legacy path",
                "separate ordinary local functionality scope",
            ],
            "does_not_establish": [
                "automatic verification of the bound static evidence",
                "general subsystem safety or every vendor-equivalent defect",
                "installed identity or runtime policy",
                "any dynamic or impact outcome",
            ],
            "inputs_are_boolean_only": True,
            "emits_only_non_operational_classification_metadata": True,
        },
        "pre_recorded_exact_classification": classify_pipe_iterator_state(
            **PRE_RECORDED_EXACT_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_pipe_iterator_state(**state)
    return report


def _boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _Once(argparse.Action):
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
    for name in PRE_RECORDED_EXACT_STATE:
        parser.add_argument(
            f"--{name.replace('_', '-')}", dest=name, type=_boolean, action=_Once
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {name: getattr(args, name) for name in PRE_RECORDED_EXACT_STATE}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit(
            "error: all exact-static applicability arguments must be supplied together"
        )
    try:
        report = build_report(state if all(supplied) else None)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    sys.stdout.buffer.write(
        json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
