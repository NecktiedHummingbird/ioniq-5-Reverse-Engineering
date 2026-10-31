#!/usr/bin/env python3
"""Classify bounded CVE-2017-6001 perf move-group locking facts.

Inputs are booleans only. This host-only model does not call perf_event_open,
create an event, start a thread, schedule a race, execute recovered code, access
a target, or emit a syscall sequence, event attribute, command, payload, or
firmware bytes.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
VMLINUX_BUILD_ID = "273378887b4cf563c10862fdf18b2292765df781"
FIX_COMMIT = "321027c1fe77f892f4ea07846aeae08cefbbb290"

PRE_RECORDED_TARGET_STATE = {
    "perf_events_compiled": True,
    "perf_event_open_syscall_present": True,
    "software_group_to_hardware_context_move_present": True,
    "group_context_loaded_before_double_mutex_wait": True,
    "group_context_nonzero_reference_acquired_before_wait": False,
    "group_context_revalidated_after_double_mutex_lock": False,
    "changed_group_context_retries_lock_acquisition": False,
    "post_lock_group_move_state_revalidated": False,
    "existing_single_context_helper_uses_reference_lock_revalidate_retry": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this Boolean-only model."""


def classify_move_group(**values: bool) -> dict[str, Any]:
    expected = set(PRE_RECORDED_TARGET_STATE)
    if set(values) != expected:
        missing = sorted(expected - set(values))
        extra = sorted(set(values) - expected)
        raise ModelError(f"state keys mismatch: missing={missing}, extra={extra}")

    state: dict[str, bool] = {}
    for name in PRE_RECORDED_TARGET_STATE:
        value = values[name]
        if not isinstance(value, bool):
            raise ModelError(f"{name} must be a boolean")
        state[name] = value

    affected_move_path_present = (
        state["perf_events_compiled"]
        and state["perf_event_open_syscall_present"]
        and state["software_group_to_hardware_context_move_present"]
        and state["group_context_loaded_before_double_mutex_wait"]
    )
    complete_reference_identity_fix = (
        state["group_context_nonzero_reference_acquired_before_wait"]
        and state["group_context_revalidated_after_double_mutex_lock"]
        and state["changed_group_context_retries_lock_acquisition"]
    )
    complete_upstream_effects = (
        complete_reference_identity_fix
        and state["post_lock_group_move_state_revalidated"]
    )
    cve_candidate = affected_move_path_present and not complete_upstream_effects
    local_equivalent_pattern_available_but_not_move_path_proof = (
        state["existing_single_context_helper_uses_reference_lock_revalidate_retry"]
        and affected_move_path_present
        and not complete_upstream_effects
    )

    return {
        "input": state,
        "affected_move_group_path_present": affected_move_path_present,
        "complete_reference_identity_fix_present": complete_reference_identity_fix,
        "complete_upstream_fix_effects_present": complete_upstream_effects,
        "cve_2017_6001_static_candidate": cve_candidate,
        "safe_single_context_pattern_does_not_close_move_path": (
            local_equivalent_pattern_available_but_not_move_path_proof
        ),
        "installed_kernel_identity_observed": None,
        "runtime_perf_event_paranoid_observed": None,
        "hardware_pmu_available_observed": None,
        "unprivileged_software_group_creation_observed": None,
        "concurrent_move_group_race_observed": None,
        "stale_or_dead_context_use_observed": None,
        "kernel_crash_observed": None,
        "controlled_kernel_memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "unrestricted_root_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "perf-move-group-context-race",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "kernel_config": "CONFIG_PERF_EVENTS=y",
            "upstream_fix_commit": FIX_COMMIT,
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-perf-cve-2017-6001.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied Boolean move-group locking facts",
                "whether reference, identity revalidation, retry, and post-lock state checks are all supplied",
                "whether the supplied facts retain the static CVE-2017-6001 candidate mechanism",
            ],
            "does_not_establish": [
                "automatic extraction or verification of kernel instructions",
                "the installed kernel identity or runtime perf_event_paranoid value",
                "hardware PMU availability or unprivileged event acceptance",
                "a concurrent race, stale context use, crash, memory corruption, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_syscall_event_attribute_thread_schedule_race_command_payload_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_move_group(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_move_group(**state)
    return report


def _cli_boolean(value: str) -> bool:
    if value.lower() == "true":
        return True
    if value.lower() == "false":
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
        raise SystemExit("error: all perf move-group state arguments must be supplied together")
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
