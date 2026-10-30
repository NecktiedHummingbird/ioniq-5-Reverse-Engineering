#!/usr/bin/env python3
"""Packet-free arithmetic model for recovered oFono SMS decoder bounds.

This module models only lengths and destination ranges observed in the exact
EU Gen5W 260128 ``ofonod``.  It does not parse or produce SMS PDUs and does not
communicate with a modem or network.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from typing import Iterable

ADDRESS_CAPACITY = 23
DELIVER_UD_CAPACITY = 140
SMS_SIZE = 0x128
SMS_CALLER_BASE = 0x30
SMS_CALLER_CANARY = 0x1F8
SMS_RELATIVE_CANARY = SMS_CALLER_CANARY - SMS_CALLER_BASE
SMS_RELATIVE_LATER_SCRATCH = 0x160 - SMS_CALLER_BASE
DELIVER_ADDRESS_OFFSET = 0x3C
DELIVER_UD_OFFSET = 0x69


@dataclass(frozen=True)
class AddressBounds:
    address_length: int
    encoded_bytes: int
    output_bytes: int
    classification: str
    address_overflow_bytes: int
    write_end_in_sms: int
    beyond_sms_bytes: int
    reaches_later_scratch: bool
    reaches_caller_canary: bool


@dataclass(frozen=True)
class DeliverDataBounds:
    udl: int
    dcs: int
    copy_bytes: int
    classification: str
    deliver_array_overflow_bytes: int
    write_end_in_sms: int
    beyond_sms_bytes: int
    reaches_later_scratch: bool
    reaches_caller_canary: bool


def _octet(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= 0xFF:
        raise ValueError(f"{name} must be in range 0..255")
    return value


def sms_udl_in_bytes(udl: int, dcs: int) -> int:
    """Reproduce the exact ``sms_udl_in_bytes`` arithmetic at file VA 0xad1c0."""

    udl = _octet("udl", udl)
    dcs = _octet("dcs", dcs)
    len_7bit = ((udl + 1) * 7) // 8

    if dcs == 0:
        return len_7bit

    upper = (dcs & 0xC0) >> 6
    if upper in (0, 1):
        if dcs & 0x20:
            return udl
        alphabet = (dcs & 0x0C) >> 2
        if alphabet == 0:
            return len_7bit
        if alphabet in (1, 2):
            return udl
        return 0

    if upper == 2:
        return 0

    message_class_group = (dcs & 0x30) >> 4
    if message_class_group in (0, 1):
        return len_7bit
    if message_class_group == 2:
        return udl
    if dcs & 0x04:
        return udl
    return len_7bit


def model_originating_address(address_length: int) -> AddressBounds:
    """Model the vulnerable non-alphanumeric TP-OA BCD write.

    The recovered decoder computes ``byte_len = (address_length + 1) / 2`` and
    writes two decoded bytes for every input byte plus a NUL terminator.
    """

    address_length = _octet("address_length", address_length)
    encoded = (address_length + 1) // 2
    output = encoded * 2 + 1
    end = DELIVER_ADDRESS_OFFSET + output

    if address_length <= 20:
        classification = "spec_bounded"
    elif output <= ADDRESS_CAPACITY:
        classification = "oversized_but_array_bounded"
    else:
        classification = "address_array_overflow"

    return AddressBounds(
        address_length=address_length,
        encoded_bytes=encoded,
        output_bytes=output,
        classification=classification,
        address_overflow_bytes=max(0, output - ADDRESS_CAPACITY),
        write_end_in_sms=end,
        beyond_sms_bytes=max(0, end - SMS_SIZE),
        reaches_later_scratch=end > SMS_RELATIVE_LATER_SCRATCH,
        reaches_caller_canary=end > SMS_RELATIVE_CANARY,
    )


def model_deliver_data(udl: int, dcs: int) -> DeliverDataBounds:
    """Model the recovered ``decode_deliver`` copy when source bytes exist."""

    udl = _octet("udl", udl)
    dcs = _octet("dcs", dcs)
    copied = sms_udl_in_bytes(udl, dcs)
    end = DELIVER_UD_OFFSET + copied

    if copied <= DELIVER_UD_CAPACITY:
        classification = "bounded_copy"
    elif end <= SMS_SIZE:
        classification = "intra_sms_object_overflow"
    else:
        classification = "caller_frame_overflow"

    return DeliverDataBounds(
        udl=udl,
        dcs=dcs,
        copy_bytes=copied,
        classification=classification,
        deliver_array_overflow_bytes=max(0, copied - DELIVER_UD_CAPACITY),
        write_end_in_sms=end,
        beyond_sms_bytes=max(0, end - SMS_SIZE),
        reaches_later_scratch=end > SMS_RELATIVE_LATER_SCRATCH,
        reaches_caller_canary=end > SMS_RELATIVE_CANARY,
    )


def _counts(items: Iterable[object], attribute: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for item in items:
        key = str(getattr(item, attribute))
        result[key] = result.get(key, 0) + 1
    return dict(sorted(result.items()))


def exhaustive_report() -> dict[str, object]:
    address = [model_originating_address(value) for value in range(256)]
    deliver = [
        model_deliver_data(udl, dcs)
        for udl in range(256)
        for dcs in range(256)
    ]
    return {
        "constants": {
            "address_capacity": ADDRESS_CAPACITY,
            "deliver_ud_capacity": DELIVER_UD_CAPACITY,
            "sms_size": SMS_SIZE,
            "sms_caller_base": SMS_CALLER_BASE,
            "sms_caller_canary": SMS_CALLER_CANARY,
            "sms_relative_canary": SMS_RELATIVE_CANARY,
            "sms_relative_later_scratch": SMS_RELATIVE_LATER_SCRATCH,
            "deliver_address_offset": DELIVER_ADDRESS_OFFSET,
            "deliver_ud_offset": DELIVER_UD_OFFSET,
        },
        "address": {
            "combinations": len(address),
            "classifications": _counts(address, "classification"),
            "maximum": asdict(address[-1]),
        },
        "deliver_data": {
            "combinations": len(deliver),
            "classifications": _counts(deliver, "classification"),
            "maximum_copy_bytes": max(item.copy_bytes for item in deliver),
            "maximum_beyond_sms_bytes": max(item.beyond_sms_bytes for item in deliver),
            "reaches_later_scratch": sum(item.reaches_later_scratch for item in deliver),
            "reaches_caller_canary": sum(item.reaches_caller_canary for item in deliver),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Model exact recovered oFono SMS decoder length boundaries"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--address-length", type=int, metavar="N")
    group.add_argument("--deliver", nargs=2, type=int, metavar=("UDL", "DCS"))
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.address_length is not None:
        report: object = asdict(model_originating_address(args.address_length))
    elif args.deliver is not None:
        report = asdict(model_deliver_data(*args.deliver))
    else:
        report = exhaustive_report()

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif isinstance(report, dict) and "constants" in report:
        print("Recovered oFono SMS decoder arithmetic (no PDU generation)")
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for key, value in report.items():
            print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
