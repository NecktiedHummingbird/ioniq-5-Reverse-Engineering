#!/usr/bin/env python3
"""Model the exact ConnMan CVE-2023-28488 length path without packets.

This is a pure arithmetic model of the recovered ``connmand`` instructions.  It
opens no socket, emits no frame bytes, and does not execute target code.  The
model stops at the fortified copy boundary; protocol, checksum, DHCP-state, and
interface reachability checks are intentionally outside its claim.
"""
from __future__ import annotations

import argparse
import json
from typing import Any

SCHEMA_VERSION = 1
READ_CAP = 0x290
HEADER_SIZE = 0x1C
DESTINATION_SIZE = 0x274
IP_TOTAL_BITS = 16
HOST_SIZE_BITS = 64
TOTAL_VALUE_COUNT = 1 << IP_TOTAL_BITS
HOST_SIZE_MODULUS = 1 << HOST_SIZE_BITS
CONNMAND_SHA256 = "d82d4018bfa9d8f8d67407453bd783a3c896f6764f147dcf23cf06b978024c28"
LIBC_SHA256 = "04946077dfd7554a20438ee581367e3995931b26c9ee516ffeeecdc0ee9f331f"
UPSTREAM_FIX = "99e2c16ea1cced34a5dc450d76287a1c3e762138"

OUTCOMES = (
    "read-error",
    "short-read-reject",
    "partial-read-reject",
    "fortify-abort",
    "bounded-copy",
)


class ModelError(ValueError):
    """Invalid fixed-path model input."""


def _integer(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelError(f"{name} must be an integer")
    return value


def classify(read_length: int, ip_total_length: int) -> dict[str, Any]:
    """Classify one pair using the exact pre-fix ordering and fortified call."""
    read_length = _integer("read_length", read_length)
    ip_total_length = _integer("ip_total_length", ip_total_length)
    if read_length < -1 or read_length > READ_CAP:
        raise ModelError(f"read_length must be between -1 and {READ_CAP}")
    if ip_total_length < 0 or ip_total_length >= TOTAL_VALUE_COUNT:
        raise ModelError("ip_total_length must fit an unsigned 16-bit field")

    result: dict[str, Any] = {
        "read_length": read_length,
        "ip_total_length": ip_total_length,
        "copy_length": None,
    }
    if read_length < 0:
        result["outcome"] = "read-error"
        result["reason"] = "read returned a negative value"
        return result
    if read_length < HEADER_SIZE:
        result["outcome"] = "short-read-reject"
        result["reason"] = "fewer than the 28 IPv4+UDP header bytes were read"
        return result
    if read_length < ip_total_length:
        result["outcome"] = "partial-read-reject"
        result["reason"] = "the advertised IPv4 total length exceeds bytes read"
        return result

    copy_length = (ip_total_length - HEADER_SIZE) % HOST_SIZE_MODULUS
    result["copy_length"] = copy_length
    if copy_length > DESTINATION_SIZE:
        result["outcome"] = "fortify-abort"
        result["reason"] = (
            "__memcpy_chk receives a copy size larger than its 628-byte "
            "destination object"
        )
    else:
        result["outcome"] = "bounded-copy"
        result["reason"] = "the length-derived copy fits the fortified destination"
    return result


def exhaustive_counts() -> dict[str, int]:
    """Count every read length 0..0x290 and every 16-bit total length exactly."""
    short_reads = HEADER_SIZE * TOTAL_VALUE_COUNT
    active_read_count = READ_CAP - HEADER_SIZE + 1
    fortify_aborts = active_read_count * HEADER_SIZE
    bounded_copies = active_read_count * (active_read_count + 1) // 2
    total_pairs = (READ_CAP + 1) * TOTAL_VALUE_COUNT
    partial_rejects = total_pairs - short_reads - fortify_aborts - bounded_copies
    counts = {
        "read-error": 0,
        "short-read-reject": short_reads,
        "partial-read-reject": partial_rejects,
        "fortify-abort": fortify_aborts,
        "bounded-copy": bounded_copies,
    }
    if sum(counts.values()) != total_pairs:
        raise AssertionError("exhaustive count invariant failed")
    return counts


def build_report(read_length: int | None = None, ip_total_length: int | None = None) -> dict[str, Any]:
    if (read_length is None) != (ip_total_length is None):
        raise ModelError("read_length and ip_total_length must be supplied together")

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "exact-connmand-cve-2023-28488-length-path",
        "evidence_binding": {
            "connmand_sha256": CONNMAND_SHA256,
            "libc_sha256": LIBC_SHA256,
            "upstream_fix": UPSTREAM_FIX,
            "receive_callback_virtual_address": "0x23390",
            "checked_copy_call_virtual_address": "0x2365b",
        },
        "constants": {
            "read_cap": READ_CAP,
            "header_size": HEADER_SIZE,
            "destination_size": DESTINATION_SIZE,
            "ip_total_bits": IP_TOTAL_BITS,
            "host_size_bits": HOST_SIZE_BITS,
        },
        "ordering": [
            "reject read_length < 28",
            "reject read_length < ip_total_length",
            "compute size_t(ip_total_length - 28)",
            "call __memcpy_chk with destination object size 628",
        ],
        "claim_boundary": (
            "Length-control-flow model only. It does not establish that protocol, "
            "checksum, DHCP-state, interface, or physical-delivery gates pass."
        ),
    }
    if read_length is not None and ip_total_length is not None:
        report["classification"] = classify(read_length, ip_total_length)
        return report

    counts = exhaustive_counts()
    report["exhaustive_domain"] = {
        "read_lengths": [0, READ_CAP],
        "ip_total_lengths": [0, TOTAL_VALUE_COUNT - 1],
        "pair_count": (READ_CAP + 1) * TOTAL_VALUE_COUNT,
        "outcome_counts": counts,
    }
    report["boundaries"] = [
        classify(27, 0),
        classify(28, 0),
        classify(28, 27),
        classify(28, 28),
        classify(READ_CAP, READ_CAP),
        classify(READ_CAP, READ_CAP + 1),
    ]
    report["interpretation"] = (
        "For every read of at least 28 bytes, all advertised total lengths below "
        "28 reach an oversized fortified-copy request; exact recovered libc "
        "routes that request to __chk_fail before copying. Lengths 28..read_length "
        "produce at most 628 copied bytes, and larger advertised lengths are rejected."
    )
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read-length", type=int)
    parser.add_argument("--ip-total-length", type=int)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = build_report(args.read_length, args.ip_total_length)
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
