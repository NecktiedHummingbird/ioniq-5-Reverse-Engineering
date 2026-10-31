#!/usr/bin/env python3
"""Model bounded CVE-2017-10661 timerfd cancellation-lock semantics.

Inputs are booleans only. The model does not create a timerfd, change a clock,
share a descriptor, create concurrency, execute recovered code, or emit a
command, timer configuration, race schedule, trigger, payload, or firmware
bytes. Pre-recorded target state comes from separate instruction-level review
and is not verified by this model execution.
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
    "shared_file_operations_resolve_same_live_context": True,
    "setup_changes_membership_before_only_global_list_lock": True,
    "removal_clears_membership_before_only_global_list_lock": True,
    "common_context_cancel_lock_absent_across_transitions": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this bounded model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_timerfd_cancel_locking(
    shared_file_operations_resolve_same_live_context: bool,
    setup_changes_membership_before_only_global_list_lock: bool,
    removal_clears_membership_before_only_global_list_lock: bool,
    common_context_cancel_lock_absent_across_transitions: bool,
) -> dict[str, Any]:
    state = {
        "shared_file_operations_resolve_same_live_context": _boolean(
            "shared_file_operations_resolve_same_live_context",
            shared_file_operations_resolve_same_live_context,
        ),
        "setup_changes_membership_before_only_global_list_lock": _boolean(
            "setup_changes_membership_before_only_global_list_lock",
            setup_changes_membership_before_only_global_list_lock,
        ),
        "removal_clears_membership_before_only_global_list_lock": _boolean(
            "removal_clears_membership_before_only_global_list_lock",
            removal_clears_membership_before_only_global_list_lock,
        ),
        "common_context_cancel_lock_absent_across_transitions": _boolean(
            "common_context_cancel_lock_absent_across_transitions",
            common_context_cancel_lock_absent_across_transitions,
        ),
    }
    premise = all(state.values())
    return {
        "input": state,
        "cve_2017_10661_missing_context_serialization_premise_present": premise,
        "same_context_membership_can_be_decided_outside_global_lock": premise,
        "successful_concurrent_interleaving_observed": None,
        "list_corruption_or_use_after_free_observed": None,
        "kernel_crash_observed": None,
        "privilege_escalation": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "timerfd-cancellation-context-lock",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "pre_recorded_target_state": {
                "source": (
                    "separate instruction-level review; not verified by this "
                    "model execution"
                ),
                **PRE_RECORDED_TARGET_STATE,
            },
            "virtual_addresses": {
                "timerfd_remove_cancel": (
                    "[0xffffffff8114551c,0xffffffff81145570)"
                ),
                "timerfd_release": "[0xffffffff81145570,0xffffffff811455c2)",
                "timerfd_settime": "[0xffffffff81145a49,0xffffffff81145e35)",
                "setup_membership_region": (
                    "0xffffffff81145cb7..0xffffffff81145d22"
                ),
                "global_cancel_lock": "0xffffffff81c27410",
            },
        },
        "claim_boundary": {
            "establishes": [
                "classification of the four supplied object and lock facts",
                "whether same-context membership decisions lack context serialization",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions",
                "a successful harmful interleaving or list invariant violation",
                "list corruption, use-after-free, crash, or controlled reuse",
                "code execution, root access, policy escape, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_trigger_or_target_material": True,
        },
    }
    report["pre_recorded_target_classification"] = (
        classify_timerfd_cancel_locking(**PRE_RECORDED_TARGET_STATE)
    )
    if state is not None:
        report["classification"] = classify_timerfd_cancel_locking(**state)
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
    for option in (
        "shared-file-operations-resolve-same-live-context",
        "setup-changes-membership-before-only-global-list-lock",
        "removal-clears-membership-before-only-global-list-lock",
        "common-context-cancel-lock-absent-across-transitions",
    ):
        parser.add_argument(
            f"--{option}", type=_cli_boolean, action=_SingleBooleanAction
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {
        "shared_file_operations_resolve_same_live_context": (
            args.shared_file_operations_resolve_same_live_context
        ),
        "setup_changes_membership_before_only_global_list_lock": (
            args.setup_changes_membership_before_only_global_list_lock
        ),
        "removal_clears_membership_before_only_global_list_lock": (
            args.removal_clears_membership_before_only_global_list_lock
        ),
        "common_context_cancel_lock_absent_across_transitions": (
            args.common_context_cancel_lock_absent_across_transitions
        ),
    }
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all timerfd state arguments must be supplied together")
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
