#!/usr/bin/env python3
"""Classify supplied AF_PACKET frame-geometry evidence without creating a ring.

The public CLI accepts Boolean evidence only.  Its reduced-width arithmetic
checks are abstract proofs over toy bit widths; they do not emit request values,
socket options, packet data, commands, target paths, or trigger material.
Nothing here opens a socket, maps memory, executes a target, or verifies a binary.
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
MODULE_SHA256 = "c810265b3c22f95d2b90494cc206abd6b4e67b7710bff2adcb177ee4867f467b"

EVIDENCE_FACTS = {
    "request_and_ring_geometry_fields_are_u32": True,
    "frame_product_equality_uses_wrapping_u32": True,
    "allocation_uses_block_count_not_frame_count": True,
    "frame_max_is_wrapped_frame_count_minus_one": True,
    "v1_v2_positions_are_bounded_by_frame_max": True,
    "lookup_block_index_is_position_div_frames_per_block": True,
    "lookup_offset_is_remainder_times_frame_size": True,
    "frames_per_block_is_floor_block_size_div_frame_size": True,
    "mmap_insert_rejects_addresses_outside_vma": True,
}


class ModelError(ValueError):
    """Raised when state is outside the model's bounded domain."""


def classify_geometry(
    *,
    bit_width: int,
    frames_per_block: int,
    block_count: int,
    block_size: int,
    frame_size: int,
    frame_count: int,
) -> dict[str, bool]:
    """Classify one abstract unsigned geometry without returning its values."""
    if not isinstance(bit_width, int) or isinstance(bit_width, bool) or not 2 <= bit_width <= 16:
        raise ModelError("bit_width must be an integer in [2, 16]")
    limit = 1 << bit_width
    named = {
        "frames_per_block": frames_per_block,
        "block_count": block_count,
        "block_size": block_size,
        "frame_size": frame_size,
        "frame_count": frame_count,
    }
    for name, value in named.items():
        if not isinstance(value, int) or isinstance(value, bool):
            raise ModelError(f"{name} must be an integer")
        minimum = 0 if name == "frame_count" else 1
        if not minimum <= value < limit:
            raise ModelError(f"{name} outside unsigned {bit_width}-bit model domain")
    if frames_per_block != block_size // frame_size:
        raise ModelError("frames_per_block must equal floor(block_size / frame_size)")

    wrapped_product = (frames_per_block * block_count) & (limit - 1)
    accepted = frame_count == wrapped_product
    if not accepted:
        return {
            "accepted_by_wrapping_equality": False,
            "block_index_in_allocated_vector": False,
            "offset_inside_allocated_block": False,
            "lookup_geometry_safe": False,
        }

    maximum_position = frame_count - 1 if frame_count else limit - 1
    maximum_block_index = maximum_position // frames_per_block
    maximum_remainder = min(frames_per_block - 1, maximum_position)
    maximum_offset = maximum_remainder * frame_size
    block_safe = maximum_block_index < block_count
    offset_safe = maximum_offset < block_size
    return {
        "accepted_by_wrapping_equality": True,
        "block_index_in_allocated_vector": block_safe,
        "offset_inside_allocated_block": offset_safe,
        "lookup_geometry_safe": block_safe and offset_safe,
    }


def reduced_width_summary(bit_width: int) -> dict[str, int | bool]:
    """Exhaust the frame-count/index theorem over a non-operational toy width."""
    if not isinstance(bit_width, int) or isinstance(bit_width, bool) or not 2 <= bit_width <= 8:
        raise ModelError("reduced proof width must be an integer in [2, 8]")
    limit = 1 << bit_width
    accepted = 0
    zero_count = 0
    index_violations = 0
    for frames_per_block, block_count in itertools.product(range(1, limit), repeat=2):
        frame_count = (frames_per_block * block_count) & (limit - 1)
        result = classify_geometry(
            bit_width=bit_width,
            frames_per_block=frames_per_block,
            block_count=block_count,
            block_size=frames_per_block,
            frame_size=1,
            frame_count=frame_count,
        )
        accepted += 1
        zero_count += int(frame_count == 0)
        index_violations += int(not result["block_index_in_allocated_vector"])
    return {
        "bit_width": bit_width,
        "accepted_states": accepted,
        "zero_wrapped_count_states": zero_count,
        "block_index_violations": index_violations,
        "all_accepted_block_indices_safe": index_violations == 0,
    }


def classify_evidence(**values: bool) -> dict[str, Any]:
    if set(values) != set(EVIDENCE_FACTS):
        missing = sorted(set(EVIDENCE_FACTS) - set(values))
        extra = sorted(set(values) - set(EVIDENCE_FACTS))
        raise ModelError(f"evidence keys mismatch: missing={missing}, extra={extra}")
    state: dict[str, bool] = {}
    for name in EVIDENCE_FACTS:
        value = values[name]
        if not isinstance(value, bool):
            raise ModelError(f"{name} must be boolean")
        state[name] = value

    lookup_complete = all(state[name] for name in (
        "request_and_ring_geometry_fields_are_u32",
        "frame_product_equality_uses_wrapping_u32",
        "allocation_uses_block_count_not_frame_count",
        "frame_max_is_wrapped_frame_count_minus_one",
        "v1_v2_positions_are_bounded_by_frame_max",
        "lookup_block_index_is_position_div_frames_per_block",
        "lookup_offset_is_remainder_times_frame_size",
        "frames_per_block_is_floor_block_size_div_frame_size",
    ))
    mmap_fail_closed = state["mmap_insert_rejects_addresses_outside_vma"]
    return {
        "schema_version": SCHEMA_VERSION,
        "module_sha256": MODULE_SHA256,
        "supplied_evidence": state,
        "v1_v2_frame_lookup_oob_rejected_by_supplied_effects": lookup_complete,
        "out_of_vma_page_insert_rejected_by_supplied_effects": mmap_fail_closed,
        "missing_guard_has_proven_memory_corruption": False,
        "runtime_ring_creation_observed": None,
        "privilege_transition_observed": None,
        "root_observed": None,
        "persistence_observed": None,
        "claim_boundary": {
            "establishes": [
                "classification of the supplied Boolean machine-code facts",
                "reduced-width arithmetic checks including zero wrapped frame count",
            ],
            "does_not_establish": [
                "binary verification by this model",
                "successful allocation or mmap",
                "socket or capability reachability",
                "a crash, out-of-bounds access, corruption, code execution, root, or persistence",
            ],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name, default in EVIDENCE_FACTS.items():
        parser.add_argument(
            f"--{name.replace('_', '-')}",
            type=int,
            choices=(0, 1),
            default=int(default),
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    option_names = [item.split("=", 1)[0] for item in actual_argv if item.startswith("--")]
    duplicates = sorted({name for name in option_names if option_names.count(name) > 1})
    parser = build_parser()
    if duplicates:
        parser.error(f"duplicate option(s): {', '.join(duplicates)}")
    args = parser.parse_args(actual_argv)
    supplied = {
        name: bool(getattr(args, name))
        for name in EVIDENCE_FACTS
    }
    report = classify_evidence(**supplied)
    report["reduced_width_checks"] = [reduced_width_summary(width) for width in range(2, 9)]
    payload = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.buffer.write(payload.encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
