#!/usr/bin/env python3
"""Classify bounded CVE-2016-7914 terminal-node leaf-guard facts.

This Boolean-only host model performs no target or key syscall, key creation,
associative-array mutation, race, recovered-code execution, or target
interaction. Ordinary host runtime operations remain outside that claim.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
FIX_COMMIT = "8d4a2ec1e0b41b0cf9a0c5cd4511da7f8e4f3de2"

PRE_RECORDED_TARGET_STATE = {
    "terminal_node_path_bound_to_reviewed_loop": True,
    "slot_load_bound_to_loop_index": True,
    "non_null_slot_check_before_leaf_check": True,
    "meta_tag_test_before_compare_callback": True,
    "meta_tag_branch_skips_compare_callback": True,
    "leaf_tag_fallthrough_reaches_compare_callback": True,
    "callback_receives_untagged_slot_and_index_key": True,
    "loop_covers_all_terminal_slots": True,
    "nonleaf_compare_callback_path_present": False,
}


class ModelError(ValueError):
    pass


def classify_leaf_guard(**values: bool) -> dict[str, Any]:
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

    complete_guard = all(
        state[name]
        for name in (
            "terminal_node_path_bound_to_reviewed_loop",
            "slot_load_bound_to_loop_index",
            "non_null_slot_check_before_leaf_check",
            "meta_tag_test_before_compare_callback",
            "meta_tag_branch_skips_compare_callback",
            "leaf_tag_fallthrough_reaches_compare_callback",
            "callback_receives_untagged_slot_and_index_key",
            "loop_covers_all_terminal_slots",
        )
    )
    explicit_bad_path = state["nonleaf_compare_callback_path_present"]
    rejected = complete_guard and not explicit_bad_path
    if rejected:
        premise: bool | None = False
    elif explicit_bad_path:
        premise = True
    else:
        premise = None

    return {
        "input": state,
        "complete_terminal_leaf_guard_present": complete_guard,
        "cve_2016_7914_nonleaf_callback_premise_present": premise,
        "cve_2016_7914_rejected_by_supplied_guard_effects": rejected,
        "cve_2016_7914_not_rejected_by_complete_guard_effects": not rejected,
        "runtime_key_syscall_reachability_observed": None,
        "nonleaf_callback_observed": None,
        "out_of_bounds_read_observed": None,
        "kernel_disclosure_observed": None,
        "kernel_crash_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "assoc-array-terminal-leaf-guard",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "upstream_fix_commit": FIX_COMMIT,
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-assoc-array-cve-2016-7914.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied terminal-node leaf-guard facts",
                "whether nonleaf slots skip the compare_object callback on the reviewed loop",
                "unknown rather than affected when guard facts are incomplete and no bad path is supplied",
            ],
            "does_not_establish": [
                "automatic instruction verification",
                "installed-kernel identity or runtime key policy",
                "key creation, callback execution, disclosure, crash, corruption, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_target_syscall_key_descriptor_race_schedule_command_payload_instructions_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_leaf_guard(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_leaf_guard(**state)
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
        raise SystemExit("error: all associative-array guard arguments must be supplied together")
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
