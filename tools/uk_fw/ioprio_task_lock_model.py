#!/usr/bin/env python3
"""Classify bounded CVE-2016-7911 task/io_context lock facts.

This Boolean-only host model performs no target or ioprio syscall, task
creation, concurrency, allocation pressure, recovered-code execution, or
target interaction. Ordinary host runtime operations remain outside that claim.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
FIX_COMMIT = "8ba8682107ee2ca3347354e018865d8e1967c5f4"

PRE_RECORDED_TARGET_STATE = {
    "getter_acquires_task_lock_before_io_context_load": True,
    "getter_loads_io_context_under_task_lock": True,
    "getter_loads_ioprio_under_task_lock": True,
    "getter_releases_task_lock_after_ioprio_load": True,
    "exit_path_acquires_same_task_lock": True,
    "exit_path_clears_io_context_under_task_lock": True,
    "exit_path_releases_task_lock_before_object_release": True,
    "unlocked_io_context_priority_read_present": False,
}


class ModelError(ValueError):
    pass


def classify_ioprio_locking(**values: bool) -> dict[str, Any]:
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

    complete_lock_discipline = all(
        state[name]
        for name in (
            "getter_acquires_task_lock_before_io_context_load",
            "getter_loads_io_context_under_task_lock",
            "getter_loads_ioprio_under_task_lock",
            "getter_releases_task_lock_after_ioprio_load",
            "exit_path_acquires_same_task_lock",
            "exit_path_clears_io_context_under_task_lock",
            "exit_path_releases_task_lock_before_object_release",
        )
    )
    rejected = complete_lock_discipline and not state[
        "unlocked_io_context_priority_read_present"
    ]
    if rejected:
        premise: bool | None = False
    elif state["unlocked_io_context_priority_read_present"]:
        premise = True
    else:
        premise = None

    return {
        "input": state,
        "complete_same_lock_discipline_present": complete_lock_discipline,
        "cve_2016_7911_unlocked_io_context_read_premise_present": premise,
        "cve_2016_7911_rejected_by_supplied_lock_effects": rejected,
        "cve_2016_7911_not_rejected_by_complete_lock_effects": not rejected,
        "runtime_ioprio_syscall_reachability_observed": None,
        "concurrent_task_exit_observed": None,
        "stale_io_context_read_observed": None,
        "kernel_crash_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "ioprio-task-lock-lifetime",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "upstream_fix_commit": FIX_COMMIT,
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-ioprio-cve-2016-7911.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied getter/exit lock-order facts",
                "whether the same task lock protects pointer publication and priority reads",
                "unknown rather than affected when fix facts are incomplete and no unlocked read is supplied",
            ],
            "does_not_establish": [
                "automatic instruction verification",
                "installed-kernel identity or runtime syscall policy",
                "concurrency, stale access, crash, corruption, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_target_syscall_task_race_schedule_command_payload_instructions_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_ioprio_locking(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_ioprio_locking(**state)
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
        raise SystemExit("error: all ioprio task-lock arguments must be supplied together")
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
