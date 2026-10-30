#!/usr/bin/env python3
"""Message-free arithmetic model for recovered oFono QMI list handling.

This module models only the count, TLV-length, allocation, and loop arithmetic
observed in the exact EU Gen5W 260128 ``ofonod`` callback at file VA 0x48d00.
It does not parse or produce QMI messages and does not communicate with a modem.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass

COUNT_MASK = 0xFFFF_FFFF
TLV_LENGTH_MAX = 0xFFFF
ENTRY_SIZE = 5
COUNT_FIELD_SIZE = 4
VENDOR_PRODUCT_LIMIT = 0xFFFF
MULTIPLICATIVE_INVERSE_5 = pow(ENTRY_SIZE, -1, 1 << 32)


@dataclass(frozen=True)
class ListBounds:
    count: int
    tlv_length: int
    wrapped_product: int
    allocation_bytes: int
    required_source_bytes: int
    loop_copy_bytes: int
    overflow_diagnostic: bool
    classification: str
    missing_selected_tlv_bytes: int
    heap_overflow_bytes_if_loop_completed: int


def _uint32(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= COUNT_MASK:
        raise ValueError(f"{name} must be in range 0..{COUNT_MASK}")
    return value


def _uint16(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= TLV_LENGTH_MAX:
        raise ValueError(f"{name} must be in range 0..{TLV_LENGTH_MAX}")
    return value


def model_list_result(count: int, tlv_length: int) -> ListBounds:
    """Model the vendor callback's arithmetic for one count/length pair."""

    count = _uint32("count", count)
    tlv_length = _uint16("tlv_length", tlv_length)
    wrapped_product = (count * ENTRY_SIZE) & COUNT_MASK
    required = COUNT_FIELD_SIZE + count * ENTRY_SIZE
    copied = count * ENTRY_SIZE

    overflow_diagnostic = wrapped_product > VENDOR_PRODUCT_LIMIT
    allocation = (
        COUNT_FIELD_SIZE
        if overflow_diagnostic
        else COUNT_FIELD_SIZE + (wrapped_product & TLV_LENGTH_MAX)
    )
    heap_overflow = max(0, required - allocation)
    if heap_overflow:
        classification = "heap_underallocation"
    elif tlv_length < COUNT_FIELD_SIZE:
        classification = "short_count_field"
    elif tlv_length < required:
        classification = "selected_tlv_overread"
    elif tlv_length == required:
        classification = "consistent"
    else:
        classification = "trailing_bytes_ignored"

    return ListBounds(
        count=count,
        tlv_length=tlv_length,
        wrapped_product=wrapped_product,
        allocation_bytes=allocation,
        required_source_bytes=required,
        loop_copy_bytes=copied,
        overflow_diagnostic=overflow_diagnostic,
        classification=classification,
        missing_selected_tlv_bytes=max(0, required - tlv_length),
        heap_overflow_bytes_if_loop_completed=heap_overflow,
    )


def count_space_report() -> dict[str, object]:
    """Partition all 32-bit counts using exact callback control flow."""

    modulus = 1 << 32
    small_product_counts = [
        (product * MULTIPLICATIVE_INVERSE_5) % modulus
        for product in range(VENDOR_PRODUCT_LIMIT + 1)
    ]
    exact_allocation = list(range((VENDOR_PRODUCT_LIMIT // ENTRY_SIZE) + 1))
    exact_allocation_set = set(exact_allocation)
    wrapped_small_product = [
        count for count in small_product_counts if count not in exact_allocation_set
    ]
    representable = [
        count
        for count in exact_allocation
        if COUNT_FIELD_SIZE + count * ENTRY_SIZE <= TLV_LENGTH_MAX
    ]
    diagnostic_fallback = modulus - len(small_product_counts)
    underallocated = modulus - len(exact_allocation)
    return {
        "constants": {
            "count_mask": COUNT_MASK,
            "tlv_length_max": TLV_LENGTH_MAX,
            "entry_size": ENTRY_SIZE,
            "count_field_size": COUNT_FIELD_SIZE,
            "vendor_product_limit": VENDOR_PRODUCT_LIMIT,
            "multiplicative_inverse_5": MULTIPLICATIVE_INVERSE_5,
        },
        "count_values": modulus,
        "exact_allocation_count_values": len(exact_allocation),
        "consistent_length_representable_counts": len(representable),
        "exact_allocation_without_representable_length": len(exact_allocation)
        - len(representable),
        "wrapped_small_product_underallocations": len(wrapped_small_product),
        "overflow_diagnostic_four_byte_allocations": diagnostic_fallback,
        "total_heap_underallocation_values": underallocated,
        "smallest_underallocated_count": len(exact_allocation),
        "smallest_wrapped_small_product_count": min(wrapped_small_product),
        "largest_wrapped_small_product_count": max(wrapped_small_product),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Model recovered oFono QMI list count/length arithmetic"
    )
    parser.add_argument("--count", type=int)
    parser.add_argument("--tlv-length", type=int)
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if (args.count is None) != (args.tlv_length is None):
        raise SystemExit("--count and --tlv-length must be supplied together")
    report: object
    if args.count is None:
        report = count_space_report()
    else:
        report = asdict(model_list_result(args.count, args.tlv_length))

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("Recovered oFono QMI list arithmetic (no message generation)")
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
