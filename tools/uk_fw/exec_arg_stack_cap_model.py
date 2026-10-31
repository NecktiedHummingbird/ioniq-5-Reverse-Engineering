#!/usr/bin/env python3
"""Classify bounded CVE-2018-14634 preventive argument-stack-cap facts.

This Boolean-only host model performs no recovered-kernel exec syscall, target
process/vector creation, privileged target-binary execution, recovered-code
execution, or target interaction. Host validation may create Python subprocesses
outside those target claims.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
FIX_COMMIT = "da029c11e6b12f321f36dac8771e833b65cec962"

PRE_RECORDED_TARGET_STATE = {
    "candidate_size_combines_vma_span_and_pointer_table_bytes": True,
    "cumulative_size_addition_overflow_routes_to_failure": True,
    "argmax_allowance_bound_to_reviewed_path": True,
    "size_above_argmax_routes_to_limit_check": True,
    "stack_rlimit_loaded_and_quartered": True,
    "six_mib_cap_materialized": True,
    "minimum_of_quarter_rlimit_and_six_mib_selected": True,
    "size_compared_against_selected_limit": True,
    "oversize_routes_to_page_release_and_failure": True,
    "all_reviewed_large_acceptance_paths_guarded": True,
    "rlimit_only_unbounded_acceptance_path_present": False,
}


class ModelError(ValueError):
    pass


def classify_arg_cap(**values: bool) -> dict[str, Any]:
    expected = set(PRE_RECORDED_TARGET_STATE)
    if set(values) != expected:
        raise ModelError(
            f"state keys mismatch: missing={sorted(expected - set(values))}, "
            f"extra={sorted(set(values) - expected)}"
        )
    state: dict[str, bool] = {}
    for name in PRE_RECORDED_TARGET_STATE:
        value = values[name]
        if not isinstance(value, bool):
            raise ModelError(f"{name} must be a boolean")
        state[name] = value

    complete_cap = all(
        state[name]
        for name in (
            "candidate_size_combines_vma_span_and_pointer_table_bytes",
            "cumulative_size_addition_overflow_routes_to_failure",
            "argmax_allowance_bound_to_reviewed_path",
            "size_above_argmax_routes_to_limit_check",
            "stack_rlimit_loaded_and_quartered",
            "six_mib_cap_materialized",
            "minimum_of_quarter_rlimit_and_six_mib_selected",
            "size_compared_against_selected_limit",
            "oversize_routes_to_page_release_and_failure",
            "all_reviewed_large_acceptance_paths_guarded",
        )
    )
    explicit_unbounded = state["rlimit_only_unbounded_acceptance_path_present"]
    rejected = complete_cap and not explicit_unbounded
    if rejected:
        premise: bool | None = False
    elif explicit_unbounded:
        premise = True
    else:
        premise = None

    return {
        "input": state,
        "complete_six_mib_argument_cap_present": complete_cap,
        "cve_2018_14634_unbounded_argument_space_premise_present": premise,
        "cve_2018_14634_rejected_by_supplied_cap_effects": rejected,
        "cve_2018_14634_not_rejected_by_complete_cap_effects": not rejected,
        "runtime_exec_reachability_observed": None,
        "privileged_executable_presence_observed": None,
        "large_argument_vector_observed": None,
        "stack_corruption_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "exec-argument-stack-cap",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "upstream_fix_commit": FIX_COMMIT,
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-exec-cve-2018-14634.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied argument-space construction and cap facts",
                "whether cumulative-size overflow fails and reviewed large argument space is capped by min(quarter stack rlimit, six MiB)",
                "unknown rather than affected when cap facts are incomplete and no unbounded path is supplied",
            ],
            "does_not_establish": [
                "automatic instruction verification",
                "installed-kernel identity, privileged executable presence, or runtime exec policy",
                "argument construction, stack corruption, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_target_syscall_argument_vector_command_payload_instructions_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_arg_cap(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_arg_cap(**state)
    return report


def _bool(value: str) -> bool:
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in PRE_RECORDED_TARGET_STATE:
        parser.add_argument(
            f"--{name.replace('_', '-')}", dest=name, type=_bool, action=_Once
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {name: getattr(args, name) for name in PRE_RECORDED_TARGET_STATE}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all exec argument-cap arguments must be supplied together")
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
