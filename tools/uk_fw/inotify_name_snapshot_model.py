#!/usr/bin/env python3
"""Classify bounded CVE-2017-7533 dentry-name snapshot premises.

Inputs are booleans only. This model does not open inotify, add a watch, rename a
file, create concurrency, execute recovered code, or emit a filename, command,
race schedule, trigger, payload, target instructions, or firmware bytes.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
VMLINUX_BUILD_ID = "273378887b4cf563c10862fdf18b2292765df781"

PRE_RECORDED_TARGET_STATE = {
    "inotify_separate_length_and_copy_present": True,
    "parent_snapshot_wraps_notification": True,
    "rename_snapshot_wraps_mutation_and_notification": True,
    "inline_name_copied_under_dentry_lock": True,
    "external_name_reference_retained_under_dentry_lock": True,
    "external_name_reference_released_after_use": True,
    "mutable_dentry_name_reaches_inotify": False,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this Boolean-only model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_name_snapshot(**values: bool) -> dict[str, Any]:
    if set(values) != set(PRE_RECORDED_TARGET_STATE):
        missing = sorted(set(PRE_RECORDED_TARGET_STATE) - set(values))
        extra = sorted(set(values) - set(PRE_RECORDED_TARGET_STATE))
        raise ModelError(f"state keys mismatch: missing={missing}, extra={extra}")
    state = {
        name: _boolean(name, values[name]) for name in PRE_RECORDED_TARGET_STATE
    }

    snapshot_fix_effect_present = all(
        state[name]
        for name in (
            "parent_snapshot_wraps_notification",
            "rename_snapshot_wraps_mutation_and_notification",
            "inline_name_copied_under_dentry_lock",
            "external_name_reference_retained_under_dentry_lock",
            "external_name_reference_released_after_use",
        )
    )
    cve_specific_mutable_name_premise = (
        state["inotify_separate_length_and_copy_present"]
        and state["mutable_dentry_name_reaches_inotify"]
    )
    rejected_by_supplied_fix_effects = (
        state["inotify_separate_length_and_copy_present"]
        and snapshot_fix_effect_present
        and not state["mutable_dentry_name_reaches_inotify"]
    )

    return {
        "input": state,
        "snapshot_fix_effect_present": snapshot_fix_effect_present,
        "cve_2017_7533_mutable_name_premise_present": (
            cve_specific_mutable_name_premise
        ),
        "cve_2017_7533_rejected_by_supplied_fix_effects": (
            rejected_by_supplied_fix_effects
        ),
        "runtime_inotify_and_rename_reachability_observed": None,
        "harmful_interleaving_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "inotify-dentry-name-snapshot",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "upstream_fix_commit": "49d31c2f389acfe83417083e1208422b4091cd9e",
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-inotify-cve-2017-7533.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied inotify sink and name-snapshot facts",
                "whether the complete reviewed snapshot effect and a mutable-name premise are supplied",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions",
                "absence of unrelated inotify, fsnotify, dcache, or VFS defects",
                "runtime watch or rename reachability, concurrency, or a harmful interleaving",
                "memory corruption, code execution, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_filename_command_race_schedule_trigger_payload_instructions_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_name_snapshot(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_name_snapshot(**state)
    return report


def _cli_boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
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
    for option in PRE_RECORDED_TARGET_STATE:
        parser.add_argument(
            f"--{option.replace('_', '-')}",
            dest=option,
            type=_cli_boolean,
            action=_SingleBooleanAction,
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {name: getattr(args, name) for name in PRE_RECORDED_TARGET_STATE}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all inotify snapshot state arguments must be supplied together")
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
