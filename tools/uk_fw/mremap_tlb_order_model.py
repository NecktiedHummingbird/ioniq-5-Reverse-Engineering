#!/usr/bin/env python3
"""Model bounded CVE-2018-18281 PTE-move and TLB-flush ordering.

Inputs are booleans only. The model does not create or remap a mapping, alter a
file, create concurrency, release or reuse a page, execute recovered code, or
emit a command, race schedule, trigger, payload, or firmware byte sequence.
Pre-recorded target state is from separate instruction-level review and is not
verified by model execution.
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
    "ordinary_pte_move_path_present": True,
    "source_pte_cleared_and_destination_written": True,
    "page_table_locks_release_before_tlb_flush": True,
    "old_range_flush_deferred_to_outer_exit": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this bounded model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_mremap_order(
    ordinary_pte_move_path_present: bool,
    source_pte_cleared_and_destination_written: bool,
    page_table_locks_release_before_tlb_flush: bool,
    old_range_flush_deferred_to_outer_exit: bool,
) -> dict[str, Any]:
    """Classify the named stale-translation ordering premise."""

    state = {
        "ordinary_pte_move_path_present": _boolean(
            "ordinary_pte_move_path_present", ordinary_pte_move_path_present
        ),
        "source_pte_cleared_and_destination_written": _boolean(
            "source_pte_cleared_and_destination_written",
            source_pte_cleared_and_destination_written,
        ),
        "page_table_locks_release_before_tlb_flush": _boolean(
            "page_table_locks_release_before_tlb_flush",
            page_table_locks_release_before_tlb_flush,
        ),
        "old_range_flush_deferred_to_outer_exit": _boolean(
            "old_range_flush_deferred_to_outer_exit",
            old_range_flush_deferred_to_outer_exit,
        ),
    }
    premise = all(state.values())
    return {
        "input": state,
        "cve_2018_18281_named_ordering_premise_present": premise,
        "stale_translation_window_semantics_present": premise,
        "concurrent_invalidation_observed": None,
        "page_release_or_reuse_observed": None,
        "stale_access_observed": None,
        "privilege_escalation": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "mremap-pte-tlb-order",
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
                "move_page_tables": (
                    "[0xffffffff810f5067,0xffffffff810f54b0)"
                ),
                "pte_transfer_loop": (
                    "0xffffffff810f53e2..0xffffffff810f5410"
                ),
                "ptl_release_region": (
                    "0xffffffff810f5412..0xffffffff810f542b"
                ),
                "deferred_flag_store": "0xffffffff810f5448",
                "outer_flush_call": "0xffffffff810f5479",
            },
        },
        "claim_boundary": {
            "establishes": [
                "classification of the four supplied move and ordering facts",
                "whether the named stale-translation window semantics are present",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions",
                "concurrent invalidation, physical-page release, or page reuse",
                "a populated stale translation or access through it",
                "corruption, code execution, root access, policy escape, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_trigger_or_target_material": True,
        },
    }
    report["pre_recorded_target_classification"] = classify_mremap_order(
        **PRE_RECORDED_TARGET_STATE
    )
    if state is not None:
        report["classification"] = classify_mremap_order(**state)
    return report


def _cli_boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _SingleBooleanAction(argparse.Action):
    """Reject duplicate state options instead of taking the final value."""

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
        "ordinary-pte-move-path-present",
        "source-pte-cleared-and-destination-written",
        "page-table-locks-release-before-tlb-flush",
        "old-range-flush-deferred-to-outer-exit",
    ):
        parser.add_argument(
            f"--{option}", type=_cli_boolean, action=_SingleBooleanAction
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {
        "ordinary_pte_move_path_present": args.ordinary_pte_move_path_present,
        "source_pte_cleared_and_destination_written": (
            args.source_pte_cleared_and_destination_written
        ),
        "page_table_locks_release_before_tlb_flush": (
            args.page_table_locks_release_before_tlb_flush
        ),
        "old_range_flush_deferred_to_outer_exit": (
            args.old_range_flush_deferred_to_outer_exit
        ),
    }
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all mremap-state arguments must be supplied together")
    try:
        report = build_report(state if all(supplied) else None)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    serialized = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    sys.stdout.buffer.write(serialized + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
