#!/usr/bin/env python3
"""Classify bounded CVE-2016-0723 retained line-discipline reference facts.

This Boolean-only host model performs no target interaction, device operation,
terminal allocation, threading, race, recovered-code execution, or trigger
construction. Ordinary host runtime operations remain outside that claim.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
FIX_COMMIT = "5c17c861a357e9458001f021a7afa7aab9937439"
ASSEMBLY_SHA256 = "358b8e8b4402841fcfc834a2ad23535274b0cd2804114fd78d6c70d5bac903cb"
PATCH_SHA256 = "b99eb5238c54e8d49834ef225761ded17ebf0d130ea11ea3e4206bad619586c1"

PRE_RECORDED_TARGET_STATE = {
    "dispatch_reaches_reviewed_reader": True,
    "wait_reference_acquired_before_ops_load": True,
    "retained_object_ops_loaded_after_acquisition": True,
    "discipline_number_loaded_from_retained_ops": True,
    "user_copy_occurs_while_reference_held": True,
    "copy_success_reaches_reference_release": True,
    "copy_failure_reaches_reference_release": True,
    "reference_release_precedes_return": True,
    "wait_helper_takes_read_ownership": True,
    "nonblocking_helper_takes_try_read_ownership": True,
    "release_helper_drops_read_ownership": True,
    "explicit_unlocked_dereference_path_present": False,
}

FIX_FACTS = tuple(PRE_RECORDED_TARGET_STATE)[:-1]
CONTRARY_FACT = "explicit_unlocked_dereference_path_present"


class ModelError(ValueError):
    pass


def classify_ldisc_reference(**values: bool) -> dict[str, Any]:
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

    complete_fix_effect = all(state[name] for name in FIX_FACTS)
    explicit_unlocked_path = state[CONTRARY_FACT]
    rejected = complete_fix_effect and not explicit_unlocked_path
    if rejected:
        race_premise: bool | None = False
    elif explicit_unlocked_path:
        race_premise = True
    else:
        race_premise = None

    return {
        "input": state,
        "complete_retained_reference_fix_effect_present": complete_fix_effect,
        "cve_2016_0723_unlocked_dereference_race_premise_present": race_premise,
        "cve_2016_0723_rejected_by_supplied_fix_effects": rejected,
        "cve_2016_0723_not_rejected_by_complete_fix_effects": not rejected,
        "installed_kernel_identity_observed": None,
        "runtime_line_discipline_transition_observed": None,
        "concurrent_read_and_change_observed": None,
        "unlocked_dereference_observed": None,
        "stale_or_freed_reference_access_observed": None,
        "kernel_disclosure_observed": None,
        "kernel_crash_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "tty-line-discipline-retained-reference",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "upstream_fix_commit": FIX_COMMIT,
            "retained_assembly_sha256": ASSEMBLY_SHA256,
            "upstream_patch_sha256": PATCH_SHA256,
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-tty-ldisc-cve-2016-0723.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied retained-reference ordering facts",
                "whether complete acquisition, protected access, and release effects reject the named race premise",
                "unknown rather than affected when fix facts are incomplete and no explicit unlocked path is supplied",
            ],
            "does_not_establish": [
                "automatic instruction verification or historical patch provenance",
                "installed-kernel identity or runtime policy",
                "concurrency, stale access, disclosure, crash, corruption, privilege gain, root, or persistence",
                "general terminal-subsystem safety",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_operational_material_or_target_bytes": True,
        },
        "pre_recorded_target_classification": classify_ldisc_reference(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_ldisc_reference(**state)
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
        raise SystemExit(
            "error: all line-discipline reference arguments must be supplied together"
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
