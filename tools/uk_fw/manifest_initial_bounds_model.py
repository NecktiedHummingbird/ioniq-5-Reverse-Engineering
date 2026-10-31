#!/usr/bin/env python3
"""Model bounded initial reads in the reviewed boot-manifest parser.

The model consumes two integers only. It does not construct a manifest, emit
bytes, access physical memory, alter a boot command line, execute a parser, or
produce a key, signature, target address, command, payload, or firmware image.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
MIN_COPY_SIZE = 1
MAX_COPY_SIZE = 0x04000000
MAX_DECLARED_LENGTH = 0xFFFFFFFF
FIXED_HEADER_BYTES_READ = 0x1C
FIRST_EXTENSION_OFFSET = 0x24
FIRST_EXTENSION_STRIDE_END = 0x48
MAX_EXTENSION_ENTRIES = 101
MAX_EXTENSION_STRIDE = 0xFFFF
EXTENSION_ENTRY_OVERHEAD = 0x24
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"


class ModelError(ValueError):
    """Raised for values outside the exact bounded domain."""


def _integer(name: str, value: int, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ModelError(f"{name} must be in [{minimum}, {maximum}]")
    return value


def classify_initial_bounds(copy_size: int, declared_length: int) -> dict[str, Any]:
    copy_size = _integer("copy_size", copy_size, MIN_COPY_SIZE, MAX_COPY_SIZE)
    declared_length = _integer(
        "declared_length", declared_length, 0, MAX_DECLARED_LENGTH
    )
    fixed_header_read_oob_candidate = copy_size < FIXED_HEADER_BYTES_READ
    first_extension_would_be_attempted = declared_length > FIRST_EXTENSION_OFFSET
    first_extension_stride_read_oob_candidate = (
        first_extension_would_be_attempted
        and copy_size < FIRST_EXTENSION_STRIDE_END
    )
    declared_extent_exceeds_copy = declared_length > copy_size
    extension_stride_oob_candidate = False
    for index in range(MAX_EXTENSION_ENTRIES):
        minimum_entry_offset = (
            FIRST_EXTENSION_OFFSET + index * EXTENSION_ENTRY_OVERHEAD
        )
        maximum_entry_offset = FIRST_EXTENSION_OFFSET + index * (
            EXTENSION_ENTRY_OVERHEAD + MAX_EXTENSION_STRIDE
        )
        first_offset_reading_beyond_copy = max(
            FIRST_EXTENSION_OFFSET, copy_size - EXTENSION_ENTRY_OVERHEAD + 1
        )
        feasible_minimum = max(
            minimum_entry_offset, first_offset_reading_beyond_copy
        )
        feasible_maximum = min(maximum_entry_offset, declared_length - 1)
        if feasible_minimum <= feasible_maximum:
            extension_stride_oob_candidate = True
            break
    furthest_capped_stride_read_end = (
        FIRST_EXTENSION_OFFSET
        + (MAX_EXTENSION_ENTRIES - 1)
        * (EXTENSION_ENTRY_OVERHEAD + MAX_EXTENSION_STRIDE)
        + EXTENSION_ENTRY_OVERHEAD
    )
    initial_or_extent_oob_candidate = (
        fixed_header_read_oob_candidate or extension_stride_oob_candidate
    )
    return {
        "input": {
            "copy_size": copy_size,
            "declared_length": declared_length,
        },
        "copy_size_accepted_by_reviewed_outer_guard": True,
        "fixed_header_read_oob_candidate_after_required_header_values": (
            fixed_header_read_oob_candidate
        ),
        "first_extension_read_would_be_attempted_after_header_acceptance": (
            first_extension_would_be_attempted
        ),
        "first_extension_stride_read_oob_candidate_after_header_acceptance": (
            first_extension_stride_read_oob_candidate
        ),
        "declared_extent_exceeds_copy": declared_extent_exceeds_copy,
        "extension_stride_read_oob_candidate_within_101_entry_cap_after_header_acceptance": (
            extension_stride_oob_candidate
        ),
        "furthest_capped_stride_read_end": furthest_capped_stride_read_end,
        "initial_or_declared_extent_oob_read_candidate": (
            initial_or_extent_oob_candidate
        ),
        "complete_extension_walk_safety_established": False,
        "runtime_parameter_control_observed": None,
        "runtime_physical_memory_control_observed": None,
        "kernel_crash_observed": None,
        "controlled_memory_write_observed": None,
        "code_execution_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(copy_size: int | None = None,
                 declared_length: int | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "boot-manifest-initial-read-bounds",
        "constants": {
            "accepted_copy_size_min": MIN_COPY_SIZE,
            "accepted_copy_size_max": MAX_COPY_SIZE,
            "fixed_header_bytes_read": FIXED_HEADER_BYTES_READ,
            "first_extension_offset": FIRST_EXTENSION_OFFSET,
            "first_extension_stride_end": FIRST_EXTENSION_STRIDE_END,
            "maximum_extension_entries": MAX_EXTENSION_ENTRIES,
            "maximum_extension_stride": MAX_EXTENSION_STRIDE,
            "extension_entry_overhead": EXTENSION_ENTRY_OVERHEAD,
            "declared_length_max": MAX_DECLARED_LENGTH,
        },
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "assessment": "evidence/eu-keystore-secure-boot-ignore.md",
            "source": "separate instruction-level review; not verified by this model execution",
        },
        "claim_boundary": {
            "establishes": [
                "arithmetic classification of supplied copied and internally declared lengths",
                "whether reviewed fixed-header or first-extension reads could exceed the copied allocation after required header predicates",
                "whether an entered extension walk has an internal extent beyond the copied allocation",
            ],
            "does_not_establish": [
                "automatic extraction or verification of kernel instructions",
                "complete safety or exact later behavior of an arbitrary extension sequence",
                "runtime control of a boot parameter, physical memory, manifest, or trust anchor",
                "a kernel crash, controlled write, code execution, privilege gain, root, or persistence",
            ],
            "inputs_are_bounded_integers_only": True,
            "emits_no_manifest_bytes_physical_address_key_signature_command_payload_or_firmware_image": True,
        },
    }
    supplied = (copy_size is not None, declared_length is not None)
    if any(supplied) and not all(supplied):
        raise ModelError("copy_size and declared_length must be supplied together")
    if all(supplied):
        report["classification"] = classify_initial_bounds(
            copy_size, declared_length  # type: ignore[arg-type]
        )
    return report


def _bounded_cli_integer(name: str, minimum: int, maximum: int):
    def parse(value: str) -> int:
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer") from exc
        try:
            return _integer(name, parsed, minimum, maximum)
        except ModelError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc
    return parse


class _SingleValueAction(argparse.Action):
    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: int, option_string: str | None = None) -> None:
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "--copy-size", type=_bounded_cli_integer(
            "copy_size", MIN_COPY_SIZE, MAX_COPY_SIZE
        ), action=_SingleValueAction
    )
    parser.add_argument(
        "--declared-length", type=_bounded_cli_integer(
            "declared_length", 0, MAX_DECLARED_LENGTH
        ), action=_SingleValueAction
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = build_report(args.copy_size, args.declared_length)
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    sys.stdout.buffer.write(json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
