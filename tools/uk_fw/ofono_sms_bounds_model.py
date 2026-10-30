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
STATUS_REPORT_UD_CAPACITY = 143
SUBMIT_ACK_REPORT_UD_CAPACITY = 152
SUBMIT_ERROR_REPORT_UD_CAPACITY = 151
DELIVER_ACK_REPORT_UD_CAPACITY = 159
DELIVER_ERROR_REPORT_UD_CAPACITY = 158
COMMAND_DATA_CAPACITY = 156
SMS_SIZE = 0x128
SMS_CALLER_BASE = 0x30
SMS_CALLER_CANARY = 0x1F8
SMS_RELATIVE_CANARY = SMS_CALLER_CANARY - SMS_CALLER_BASE
SMS_RELATIVE_LATER_SCRATCH = 0x160 - SMS_CALLER_BASE
DELIVER_ADDRESS_OFFSET = 0x3C
DELIVER_UD_OFFSET = 0x69
STATUS_REPORT_UD_OFFSET = 0x7C
SUBMIT_REPORT_UD_OFFSET = 0x3F
DELIVER_ACK_REPORT_UD_OFFSET = 0x2C
DELIVER_ERROR_REPORT_UD_OFFSET = 0x2D
COMMAND_DATA_OFFSET = 0x59


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


@dataclass(frozen=True)
class ReportDataBounds:
    report_type: str
    udl: int
    dcs: int
    copy_bytes: int
    destination_capacity: int
    destination_offset: int
    classification: str
    array_overflow_bytes: int
    write_end_in_sms: int
    beyond_sms_bytes: int
    reaches_later_scratch: bool | None
    reaches_caller_canary: bool | None


@dataclass(frozen=True)
class CommandDataBounds:
    command_data_length: int
    copy_bytes: int
    classification: str
    array_overflow_bytes: int
    write_end_in_sms: int
    beyond_sms_bytes: int
    reaches_later_scratch: None
    reaches_caller_canary: None


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

    if dcs == 0x84:
        return udl
    if dcs == 0:
        return len_7bit

    upper = (dcs & 0xC0) >> 6
    if upper in (0, 1):
        if dcs & 0x20:
            return udl
        alphabet = (dcs & 0x0C) >> 2
        if alphabet == 0:
            return len_7bit
        return udl

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


def _model_report_data(
    report_type: str,
    udl: int,
    dcs: int,
    capacity: int,
    offset: int,
    *,
    delivery_caller_layout: bool = True,
) -> ReportDataBounds:
    """Model a report decoder's user-data copy when source bytes exist."""

    udl = _octet("udl", udl)
    dcs = _octet("dcs", dcs)
    copied = sms_udl_in_bytes(udl, dcs)
    end = offset + copied

    if copied <= capacity:
        classification = "bounded_copy"
    elif end <= SMS_SIZE:
        classification = "intra_sms_object_overflow"
    else:
        classification = "caller_frame_overflow"

    return ReportDataBounds(
        report_type=report_type,
        udl=udl,
        dcs=dcs,
        copy_bytes=copied,
        destination_capacity=capacity,
        destination_offset=offset,
        classification=classification,
        array_overflow_bytes=max(0, copied - capacity),
        write_end_in_sms=end,
        beyond_sms_bytes=max(0, end - SMS_SIZE),
        reaches_later_scratch=(
            end > SMS_RELATIVE_LATER_SCRATCH if delivery_caller_layout else None
        ),
        reaches_caller_canary=(
            end > SMS_RELATIVE_CANARY if delivery_caller_layout else None
        ),
    )


def model_status_report_data(udl: int, dcs: int) -> ReportDataBounds:
    """Model CVE-2023-4232's recovered status-report copy."""

    return _model_report_data(
        "status_report", udl, dcs, STATUS_REPORT_UD_CAPACITY, STATUS_REPORT_UD_OFFSET
    )


def model_submit_report_data(
    udl: int, dcs: int, *, error_report: bool = False
) -> ReportDataBounds:
    """Model CVE-2023-4234's ACK or ERROR submit-report copy."""

    if not isinstance(error_report, bool):
        raise TypeError("error_report must be a boolean")
    report_type = "submit_error_report" if error_report else "submit_ack_report"
    capacity = (
        SUBMIT_ERROR_REPORT_UD_CAPACITY
        if error_report
        else SUBMIT_ACK_REPORT_UD_CAPACITY
    )
    return _model_report_data(
        report_type, udl, dcs, capacity, SUBMIT_REPORT_UD_OFFSET
    )


def model_deliver_report_data(
    udl: int, dcs: int, *, error_report: bool = False
) -> ReportDataBounds:
    """Model CVE-2023-4235's ACK or ERROR deliver-report copy."""

    if not isinstance(error_report, bool):
        raise TypeError("error_report must be a boolean")
    if error_report:
        return _model_report_data(
            "deliver_error_report",
            udl,
            dcs,
            DELIVER_ERROR_REPORT_UD_CAPACITY,
            DELIVER_ERROR_REPORT_UD_OFFSET,
            delivery_caller_layout=False,
        )
    return _model_report_data(
        "deliver_ack_report",
        udl,
        dcs,
        DELIVER_ACK_REPORT_UD_CAPACITY,
        DELIVER_ACK_REPORT_UD_OFFSET,
        delivery_caller_layout=False,
    )


def model_command_data(command_data_length: int) -> CommandDataBounds:
    """Model CVE-2024-7547's command-data copy when source bytes exist."""

    copied = _octet("command_data_length", command_data_length)
    end = COMMAND_DATA_OFFSET + copied
    if copied <= COMMAND_DATA_CAPACITY:
        classification = "bounded_copy"
    elif end <= SMS_SIZE:
        classification = "intra_sms_object_overflow"
    else:
        classification = "caller_frame_overflow"
    return CommandDataBounds(
        command_data_length=copied,
        copy_bytes=copied,
        classification=classification,
        array_overflow_bytes=max(0, copied - COMMAND_DATA_CAPACITY),
        write_end_in_sms=end,
        beyond_sms_bytes=max(0, end - SMS_SIZE),
        reaches_later_scratch=None,
        reaches_caller_canary=None,
    )


def _counts(items: Iterable[object], attribute: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for item in items:
        key = str(getattr(item, attribute))
        result[key] = result.get(key, 0) + 1
    return dict(sorted(result.items()))


def _copy_report(
    items: list[DeliverDataBounds | ReportDataBounds | CommandDataBounds],
) -> dict[str, object]:
    scratch = [item.reaches_later_scratch for item in items]
    canary = [item.reaches_caller_canary for item in items]
    return {
        "combinations": len(items),
        "classifications": _counts(items, "classification"),
        "maximum_copy_bytes": max(item.copy_bytes for item in items),
        "maximum_beyond_sms_bytes": max(item.beyond_sms_bytes for item in items),
        "reaches_later_scratch": (
            sum(bool(value) for value in scratch) if None not in scratch else None
        ),
        "reaches_caller_canary": (
            sum(bool(value) for value in canary) if None not in canary else None
        ),
    }


def exhaustive_report() -> dict[str, object]:
    address = [model_originating_address(value) for value in range(256)]
    pairs = [(udl, dcs) for udl in range(256) for dcs in range(256)]
    deliver = [model_deliver_data(*pair) for pair in pairs]
    status_report = [model_status_report_data(*pair) for pair in pairs]
    submit_ack_report = [model_submit_report_data(*pair) for pair in pairs]
    submit_error_report = [
        model_submit_report_data(*pair, error_report=True) for pair in pairs
    ]
    deliver_ack_report = [model_deliver_report_data(*pair) for pair in pairs]
    deliver_error_report = [
        model_deliver_report_data(*pair, error_report=True) for pair in pairs
    ]
    command = [model_command_data(length) for length in range(256)]
    return {
        "constants": {
            "address_capacity": ADDRESS_CAPACITY,
            "deliver_ud_capacity": DELIVER_UD_CAPACITY,
            "status_report_ud_capacity": STATUS_REPORT_UD_CAPACITY,
            "submit_ack_report_ud_capacity": SUBMIT_ACK_REPORT_UD_CAPACITY,
            "submit_error_report_ud_capacity": SUBMIT_ERROR_REPORT_UD_CAPACITY,
            "deliver_ack_report_ud_capacity": DELIVER_ACK_REPORT_UD_CAPACITY,
            "deliver_error_report_ud_capacity": DELIVER_ERROR_REPORT_UD_CAPACITY,
            "command_data_capacity": COMMAND_DATA_CAPACITY,
            "sms_size": SMS_SIZE,
            "sms_caller_base": SMS_CALLER_BASE,
            "sms_caller_canary": SMS_CALLER_CANARY,
            "sms_relative_canary": SMS_RELATIVE_CANARY,
            "sms_relative_later_scratch": SMS_RELATIVE_LATER_SCRATCH,
            "deliver_address_offset": DELIVER_ADDRESS_OFFSET,
            "deliver_ud_offset": DELIVER_UD_OFFSET,
            "status_report_ud_offset": STATUS_REPORT_UD_OFFSET,
            "submit_report_ud_offset": SUBMIT_REPORT_UD_OFFSET,
            "deliver_ack_report_ud_offset": DELIVER_ACK_REPORT_UD_OFFSET,
            "deliver_error_report_ud_offset": DELIVER_ERROR_REPORT_UD_OFFSET,
            "command_data_offset": COMMAND_DATA_OFFSET,
        },
        "address": {
            "combinations": len(address),
            "classifications": _counts(address, "classification"),
            "maximum": asdict(address[-1]),
        },
        "deliver_data": _copy_report(deliver),
        "status_report_data": _copy_report(status_report),
        "submit_ack_report_data": _copy_report(submit_ack_report),
        "submit_error_report_data": _copy_report(submit_error_report),
        "deliver_ack_report_data": _copy_report(deliver_ack_report),
        "deliver_error_report_data": _copy_report(deliver_error_report),
        "command_data": _copy_report(command),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Model exact recovered oFono SMS decoder length boundaries"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--address-length", type=int, metavar="N")
    group.add_argument("--deliver", nargs=2, type=int, metavar=("UDL", "DCS"))
    group.add_argument(
        "--status-report", nargs=2, type=int, metavar=("UDL", "DCS")
    )
    group.add_argument(
        "--submit-ack-report", nargs=2, type=int, metavar=("UDL", "DCS")
    )
    group.add_argument(
        "--submit-error-report", nargs=2, type=int, metavar=("UDL", "DCS")
    )
    group.add_argument(
        "--deliver-ack-report", nargs=2, type=int, metavar=("UDL", "DCS")
    )
    group.add_argument(
        "--deliver-error-report", nargs=2, type=int, metavar=("UDL", "DCS")
    )
    group.add_argument("--command-data-length", type=int, metavar="N")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.address_length is not None:
        report: object = asdict(model_originating_address(args.address_length))
    elif args.deliver is not None:
        report = asdict(model_deliver_data(*args.deliver))
    elif args.status_report is not None:
        report = asdict(model_status_report_data(*args.status_report))
    elif args.submit_ack_report is not None:
        report = asdict(model_submit_report_data(*args.submit_ack_report))
    elif args.submit_error_report is not None:
        report = asdict(
            model_submit_report_data(*args.submit_error_report, error_report=True)
        )
    elif args.deliver_ack_report is not None:
        report = asdict(model_deliver_report_data(*args.deliver_ack_report))
    elif args.deliver_error_report is not None:
        report = asdict(
            model_deliver_report_data(*args.deliver_error_report, error_report=True)
        )
    elif args.command_data_length is not None:
        report = asdict(model_command_data(args.command_data_length))
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
