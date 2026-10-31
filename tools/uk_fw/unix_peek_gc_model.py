#!/usr/bin/env python3
"""Model bounded CVE-2021-0920 AF_UNIX MSG_PEEK/GC semantics.

Inputs are booleans only. The model does not create a socket, pass a file
descriptor, invoke garbage collection, create concurrency, execute recovered
code, or emit a packet, descriptor graph, command, race schedule, trigger,
payload, or firmware bytes. Pre-recorded target state comes from separate
instruction-level review and is not verified by this model execution.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
MODULE_SHA256 = "e1841632fee9f70eb8f97204cf629a2b34c9e21136fda9236a971ca2d8758ecb"
MODULE_BUILD_ID = "cc807f3b2bce8d7023b7945ec2919698f1034e42"
PRE_RECORDED_TARGET_STATE = {
    "datagram_peek_duplicates_attached_files": True,
    "stream_peek_duplicates_attached_files": True,
    "duplicated_file_lists_flow_to_scm_receive": True,
    "gc_lock_barrier_absent_on_both_peek_paths": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this bounded model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_unix_peek_gc(
    datagram_peek_duplicates_attached_files: bool,
    stream_peek_duplicates_attached_files: bool,
    duplicated_file_lists_flow_to_scm_receive: bool,
    gc_lock_barrier_absent_on_both_peek_paths: bool,
) -> dict[str, Any]:
    state = {
        "datagram_peek_duplicates_attached_files": _boolean(
            "datagram_peek_duplicates_attached_files",
            datagram_peek_duplicates_attached_files,
        ),
        "stream_peek_duplicates_attached_files": _boolean(
            "stream_peek_duplicates_attached_files",
            stream_peek_duplicates_attached_files,
        ),
        "duplicated_file_lists_flow_to_scm_receive": _boolean(
            "duplicated_file_lists_flow_to_scm_receive",
            duplicated_file_lists_flow_to_scm_receive,
        ),
        "gc_lock_barrier_absent_on_both_peek_paths": _boolean(
            "gc_lock_barrier_absent_on_both_peek_paths",
            gc_lock_barrier_absent_on_both_peek_paths,
        ),
    }
    premise = all(state.values())
    return {
        "input": state,
        "cve_2021_0920_missing_gc_serialization_premise_present": premise,
        "peek_duplicate_can_reach_descriptor_delivery_without_gc_barrier": premise,
        "runtime_module_load_observed": None,
        "successful_gc_concurrency_observed": None,
        "use_after_free_observed": None,
        "privilege_escalation": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "af-unix-peek-gc-serialization",
        "evidence_binding": {
            "module_sha256": MODULE_SHA256,
            "module_build_id": MODULE_BUILD_ID,
            "pre_recorded_target_state": {
                "source": (
                    "separate instruction-level review; not verified by this "
                    "model execution"
                ),
                **PRE_RECORDED_TARGET_STATE,
            },
            "section_relative_addresses": {
                "unix_stream_recvmsg": "[.text+0x23a6,.text+0x2a8f)",
                "stream_duplicate_call": ".text+0x29c3",
                "unix_dgram_recvmsg": "[.text+0x355b,.text+0x3824)",
                "datagram_duplicate_call": ".text+0x37b9",
                "unix_gc_lock": ".bss+0x102e",
            },
        },
        "claim_boundary": {
            "establishes": [
                "classification of the four supplied PEEK and GC-lock facts",
                "whether duplicate-to-delivery lacks the named GC barrier",
            ],
            "does_not_establish": [
                "automatic extraction or verification of module instructions",
                "runtime module load, socket policy, or ordinary-user reachability",
                "a concurrent GC pass, candidate selection, or object lifetime failure",
                "corruption, code execution, root access, policy escape, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_trigger_or_target_material": True,
        },
    }
    report["pre_recorded_target_classification"] = classify_unix_peek_gc(
        **PRE_RECORDED_TARGET_STATE
    )
    if state is not None:
        report["classification"] = classify_unix_peek_gc(**state)
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
        "datagram-peek-duplicates-attached-files",
        "stream-peek-duplicates-attached-files",
        "duplicated-file-lists-flow-to-scm-receive",
        "gc-lock-barrier-absent-on-both-peek-paths",
    ):
        parser.add_argument(
            f"--{option}", type=_cli_boolean, action=_SingleBooleanAction
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {
        "datagram_peek_duplicates_attached_files": (
            args.datagram_peek_duplicates_attached_files
        ),
        "stream_peek_duplicates_attached_files": (
            args.stream_peek_duplicates_attached_files
        ),
        "duplicated_file_lists_flow_to_scm_receive": (
            args.duplicated_file_lists_flow_to_scm_receive
        ),
        "gc_lock_barrier_absent_on_both_peek_paths": (
            args.gc_lock_barrier_absent_on_both_peek_paths
        ),
    }
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all AF_UNIX state arguments must be supplied together")
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
