#!/usr/bin/env python3
"""Classify bounded CVE-2016-7910 block seq-iterator lifetime facts.

Inputs are booleans only. This host-only model does not open a proc file,
allocate kernel memory, create memory pressure, execute recovered code, or emit
a path, file operation, allocation schedule, command, payload, target
instruction, or firmware bytes.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
VMLINUX_BUILD_ID = "273378887b4cf563c10862fdf18b2292765df781"
FIX_COMMIT = "77da160530dd1dc94f6ae15a981f24e5f0021e84"

PRE_RECORDED_TARGET_STATE = {
    "successful_start_stores_iterator_in_private": True,
    "stop_loads_iterator_from_private": True,
    "stop_exits_iterator": True,
    "stop_frees_iterator": True,
    "stop_clears_private_after_free": True,
    "stop_retains_freed_iterator_in_private": False,
    "later_start_allocation_failure_skips_private_store": True,
    "same_seq_file_stop_runs_after_start_failure": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this Boolean-only model."""


def classify_iterator_lifetime(**values: bool) -> dict[str, Any]:
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

    if (
        state["stop_clears_private_after_free"]
        and state["stop_retains_freed_iterator_in_private"]
    ):
        raise ModelError(
            "stop cannot both clear private and retain the freed iterator in private"
        )

    repeated_cleanup_path = all(
        state[name]
        for name in (
            "successful_start_stores_iterator_in_private",
            "stop_loads_iterator_from_private",
            "stop_exits_iterator",
            "stop_frees_iterator",
            "later_start_allocation_failure_skips_private_store",
            "same_seq_file_stop_runs_after_start_failure",
        )
    )
    rejected_by_private_clear = (
        repeated_cleanup_path
        and state["stop_clears_private_after_free"]
        and not state["stop_retains_freed_iterator_in_private"]
    )
    vulnerable_stale_cleanup_premise: bool | None
    if not repeated_cleanup_path or rejected_by_private_clear:
        vulnerable_stale_cleanup_premise = False
    elif state["stop_retains_freed_iterator_in_private"]:
        vulnerable_stale_cleanup_premise = True
    else:
        # Absence of the reviewed cleanup-side clear does not prove that no
        # equivalent start-side or detachment fix exists. Without an explicit
        # retained-pointer fact, the CVE-specific premise remains unknown.
        vulnerable_stale_cleanup_premise = None

    return {
        "input": state,
        "repeated_cleanup_path_present": repeated_cleanup_path,
        "cve_2016_7910_stale_iterator_cleanup_premise_present": (
            vulnerable_stale_cleanup_premise
        ),
        "cve_2016_7910_rejected_by_supplied_private_clear_effect": (
            rejected_by_private_clear
        ),
        "cve_2016_7910_not_rejected_by_supplied_private_clear_effect": (
            repeated_cleanup_path and not rejected_by_private_clear
        ),
        "runtime_proc_entry_reachability_observed": None,
        "iterator_allocation_failure_observed": None,
        "stale_iterator_dereference_observed": None,
        "double_free_observed": None,
        "kernel_crash_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "block-seq-iterator-lifetime",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "upstream_fix_commit": FIX_COMMIT,
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-block-cve-2016-7910.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied block seq-iterator lifetime facts",
                "whether the repeated cleanup path is present in the supplied state",
                "whether a private-pointer clear rejects the CVE-specific stale cleanup premise",
                "unknown rather than affected when neither a clear nor an explicit retained-pointer fact is supplied",
            ],
            "does_not_establish": [
                "automatic extraction or verification of kernel instructions",
                "absence of unrelated block, proc, seq-file, allocator, or lifetime defects",
                "installed-kernel identity or runtime proc visibility and policy",
                "an allocation failure, stale dereference, double free, crash, corruption, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_path_file_operation_allocation_schedule_command_payload_instructions_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_iterator_lifetime(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_iterator_lifetime(**state)
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
        raise SystemExit(
            "error: all block seq-iterator lifetime arguments must be supplied together"
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
