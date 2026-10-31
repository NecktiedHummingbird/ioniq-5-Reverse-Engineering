#!/usr/bin/env python3
"""Classify bounded FLIC ByteReader/ByteWriter remediation facts.

Inputs are booleans only. This model does not create media, compressed data,
parser input, a command, target path, executable, payload, or trigger, and does
not execute a recovered parser.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
PLUGIN_SHA256 = "46886e9a31e21efca01b68c56c8e879d06902b9b7343530cf518ee908fb96b16"
PLUGIN_BUILD_ID = "67b88ba2c35738081fe1397cf7d10a1375d0525b"

PRE_RECORDED_TARGET_STATE = {
    "chunk_payload_bounded_by_subreader": True,
    "writer_bound_to_frame_buffer_and_size": True,
    "previous_frame_copy_checked": True,
    "fli_start_plus_lines_checked": True,
    "flc_line_count_checked": True,
    "position_changes_use_cumulative_writer_position_and_are_checked": True,
    "reader_failures_propagate": True,
    "writer_failures_propagate": True,
    "decoder_failure_propagates_to_chain_error": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this Boolean-only model."""


def classify_flic_bounds(**values: bool) -> dict[str, Any]:
    if set(values) != set(PRE_RECORDED_TARGET_STATE):
        missing = sorted(set(PRE_RECORDED_TARGET_STATE) - set(values))
        extra = sorted(set(values) - set(PRE_RECORDED_TARGET_STATE))
        raise ModelError(f"state keys mismatch: missing={missing}, extra={extra}")
    state: dict[str, bool] = {}
    for name in PRE_RECORDED_TARGET_STATE:
        value = values[name]
        if not isinstance(value, bool):
            raise ModelError(f"{name} must be a boolean")
        state[name] = value
    complete_writer_remediation = all(state.values())
    return {
        "input": state,
        "complete_reviewed_byte_reader_writer_effect": complete_writer_remediation,
        "named_flic_write_bounds_family_rejected_by_supplied_effects": complete_writer_remediation,
        "production_media_delivery_observed": None,
        "parser_execution_observed": None,
        "out_of_bounds_write_observed": None,
        "code_execution_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "flic-byte-reader-writer-remediation",
        "evidence_binding": {
            "plugin_sha256": PLUGIN_SHA256,
            "plugin_build_id": PLUGIN_BUILD_ID,
            "upstream_rewrite_commit": "153a8ae752c90d07190ef45803422a4f71ea8bff",
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/gstreamer-flxdec-cve-2016-9634-9636-9808.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied bounded-reader, bounded-writer, and failure-routing facts",
                "whether every reviewed effect of the comprehensive FLIC rewrite is supplied",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions",
                "absence of unrelated FLIC, GStreamer, allocator, or media defects",
                "production delivery or parser execution",
                "memory corruption, code execution, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_media_compressed_data_parser_input_command_target_path_executable_payload_or_trigger": True,
        },
        "pre_recorded_target_classification": classify_flic_bounds(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_flic_bounds(**state)
    return report


def _cli_boolean(value: str) -> bool:
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _SingleBooleanAction(argparse.Action):
    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: bool, option_string: str | None = None) -> None:
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for option in PRE_RECORDED_TARGET_STATE:
        parser.add_argument(
            f"--{option.replace('_', '-')}", dest=option, type=_cli_boolean,
            action=_SingleBooleanAction,
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {name: getattr(args, name) for name in PRE_RECORDED_TARGET_STATE}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all FLIC remediation state arguments must be supplied together")
    try:
        report = build_report(state if all(supplied) else None)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    sys.stdout.buffer.write(json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
