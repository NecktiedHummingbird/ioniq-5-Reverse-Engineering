#!/usr/bin/env python3
"""Classify bounded CVE-2015-7550 key read/revoke lock facts.

This Boolean-only host model performs no target or keyctl syscall, key creation,
threading, race, allocation pressure, recovered-code execution, or target
interaction. Ordinary host runtime operations remain outside that claim.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
FIX_COMMIT = "b4a1b4f5047e4f54e194681125c74c0aa64d637d"

PRE_RECORDED_TARGET_STATE = {
    "reader_acquires_key_sem_before_validation": True,
    "reader_validates_under_read_lock": True,
    "reader_callback_runs_under_read_lock": True,
    "reader_unlocks_after_validation_or_callback": True,
    "revoke_state_and_callback_run_under_same_sem_write_lock": True,
    "explicit_unlocked_validation_to_read_window_present": False,
}


class ModelError(ValueError):
    pass


def classify_key_locking(**values: bool) -> dict[str, Any]:
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

    complete_lock_effect = all(
        state[name]
        for name in (
            "reader_acquires_key_sem_before_validation",
            "reader_validates_under_read_lock",
            "reader_callback_runs_under_read_lock",
            "reader_unlocks_after_validation_or_callback",
            "revoke_state_and_callback_run_under_same_sem_write_lock",
        )
    )
    explicit_window = state["explicit_unlocked_validation_to_read_window_present"]
    rejected = complete_lock_effect and not explicit_window
    if rejected:
        race_premise: bool | None = False
    elif explicit_window:
        race_premise = True
    else:
        race_premise = None

    return {
        "input": state,
        "complete_same_rwsem_fix_effect_present": complete_lock_effect,
        "cve_2015_7550_unlocked_validation_to_read_race_premise_present": race_premise,
        "cve_2015_7550_rejected_by_supplied_lock_effects": rejected,
        "cve_2015_7550_not_rejected_by_complete_lock_effects": not rejected,
        "installed_kernel_identity_observed": None,
        "runtime_keyctl_policy_observed": None,
        "concurrent_read_and_revoke_observed": None,
        "stale_or_freed_payload_access_observed": None,
        "kernel_crash_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "key-read-revoke-rwsem-order",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "upstream_fix_commit": FIX_COMMIT,
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-key-read-revoke-cve-2015-7550.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied read/revoke rwsem-order facts",
                "whether complete same-rwsem effects reject the named race premise",
                "unknown rather than affected when fix facts are incomplete and no explicit unlocked window is supplied",
            ],
            "does_not_establish": [
                "automatic instruction verification or historical patch provenance",
                "installed-kernel identity or runtime keyctl policy",
                "concurrency, stale access, crash, corruption, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_target_syscall_key_race_schedule_command_payload_instructions_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_key_locking(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_key_locking(**state)
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
        raise SystemExit("error: all key read/revoke lock arguments must be supplied together")
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
