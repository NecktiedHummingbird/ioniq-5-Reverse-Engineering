#!/usr/bin/env python3
"""Classify the fixed VMNC dimension guard with bounded numeric inputs.

This is a deterministic arithmetic/control-flow model of the recovered
``libgstvmnc.so`` behavior relevant to CVE-2016-9445. It does not parse media,
create a media file, execute a target binary, or model exploitation.

The recovered packet parser reads width and height as unsigned 16-bit values.
For a WMVi rectangle it rejects either value above 16384 before dispatching the
rectangle handler. The handler's allocation then multiplies width, height and
bytes-per-pixel with 32-bit instructions; the recovered build calls
``g_malloc0`` rather than ``g_malloc``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, Sequence

SCHEMA = "uk-fw.vmnc-dimension-guard-model.v1"
DIMENSION_LIMIT = 16_384
UINT16_MAX = (1 << 16) - 1
INT32_MAX = (1 << 31) - 1
UINT32_MAX = (1 << 32) - 1


class InputError(ValueError):
    """Raised when supplied numeric state is outside the bounded model."""


def _bounded(name: str, value: int, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise InputError(f"{name} must be in [{minimum}, {maximum}]")
    return value


def classify(width: int, height: int, bytes_per_pixel: int) -> Dict[str, object]:
    """Classify one supplied WMVi dimension tuple under exact fixed semantics."""

    width = _bounded("width", width, 0, UINT16_MAX)
    height = _bounded("height", height, 0, UINT16_MAX)
    bytes_per_pixel = _bounded("bytes_per_pixel", bytes_per_pixel, 1, 4)
    if bytes_per_pixel not in (1, 2, 4):
        raise InputError("bytes_per_pixel must be one of 1, 2, or 4")

    exceeds_limit = width > DIMENSION_LIMIT or height > DIMENSION_LIMIT
    mathematical_product = width * height * bytes_per_pixel
    low_u32 = mathematical_product & UINT32_MAX
    signed_i32 = low_u32 if low_u32 <= INT32_MAX else low_u32 - (1 << 32)
    rejected = exceeds_limit
    handler_reachable = not rejected
    maximum_fixed_product = DIMENSION_LIMIT * DIMENSION_LIMIT * 4

    if rejected:
        classification = "rejected_before_wmvi_handler"
    else:
        classification = "accepted_without_32bit_allocation_overflow"

    return {
        "schema": SCHEMA,
        "inputs": {
            "width": width,
            "height": height,
            "bytes_per_pixel": bytes_per_pixel,
        },
        "fixed_semantics": {
            "dimension_limit": DIMENSION_LIMIT,
            "reject_comparison": "width > 16384 or height > 16384",
            "all_feasible_wmvi_paths_pass_dimension_guard": True,
            "structural_cfg_dominance_claimed": False,
            "allocation_is_zero_initialized": True,
            "maximum_accepted_product": maximum_fixed_product,
        },
        "derived": {
            "dimension_exceeds_limit": exceeds_limit,
            "rejected_before_wmvi_handler": rejected,
            "wmvi_handler_reachable": handler_reachable,
            "mathematical_allocation_product": mathematical_product,
            "product_low_u32": low_u32,
            "product_as_signed_i32": signed_i32,
            "would_exceed_signed_i32_without_guard": mathematical_product > INT32_MAX,
            "would_exceed_uint32_without_guard": mathematical_product > UINT32_MAX,
            "accepted_product_fits_signed_i32": (
                handler_reachable and mathematical_product <= INT32_MAX
            ),
            "cve_2016_9445_overflow_path_reachable": (
                handler_reachable and mathematical_product > INT32_MAX
            ),
        },
        "classification": classification,
        "limitations": [
            "Classifies supplied bounded numeric state only.",
            "Does not prove media delivery, plugin selection, parsing, process identity, or runtime behavior.",
            "Does not emit a media file, payload, command, or exploitation schedule.",
        ],
    }


def _report_bytes(report: Dict[str, object]) -> bytes:
    text = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False)
    return (text + "\n").encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--width", type=int, required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--bytes-per-pixel", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        report = classify(args.width, args.height, args.bytes_per_pixel)
    except InputError as exc:
        parser.error(str(exc))
    sys.stdout.buffer.write(_report_bytes(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
