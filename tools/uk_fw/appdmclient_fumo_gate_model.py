#!/usr/bin/env python3
"""Model exact numeric AppDMClient FUMO trailer and outer pair gates.

This model consumes integers and booleans only.  It does not read or create an
update file, trailer, archive, compressed stream, command, or executable input.
A recognized trailer classification only means the recovered parser would
continue to later parsing and cryptographic checks; it is not verification.
Likewise, passing the outer pair gate is not update acceptance.
"""
from __future__ import annotations

import argparse
import json
from typing import Any

SCHEMA_VERSION = 1
APPDMCLIENT_SHA256 = "9a1fb796d7ac24fcce71c16e3dbee9306c888f43e705ee081f41b7d473978bd0"
APPDMCLIENT_BUILD_ID = "b2dbcc5231f444d8f1dd68eb7a2376323ce805df"
TRAILER_SIZE = 0x4024
RESULT_NONPOSITIVE_SIZE = -401
RESULT_READ_FAILURE = -402
RESULT_32_BYTE_MISMATCH = -403
RESULT_UNRECOGNIZED_TRAILER = -404


class ModelError(ValueError):
    """Raised when supplied state lies outside this bounded numeric model."""


def _integer(name: str, value: int, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ModelError(f"{name} must be in range {minimum}..{maximum}")
    return value


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_trailer(
    file_size: int,
    suffix_read_items: int,
    magic0: int,
    magic1: int,
    magic2: int,
) -> dict[str, Any]:
    """Classify state after the parser has successfully opened and end-sought.

    The three magic values are numeric octets observed at the start of the fixed
    suffix.  They are considered only when a complete suffix read is supplied.
    """

    file_size = _integer("file_size", file_size, 0, (1 << 63) - 1)
    suffix_read_items = _integer("suffix_read_items", suffix_read_items, 0, 1)
    magic0 = _integer("magic0", magic0, 0, 255)
    magic1 = _integer("magic1", magic1, 0, 255)
    magic2 = _integer("magic2", magic2, 0, 255)

    recognized_magic = magic0 == 0x54 and magic1 == 0x45 and magic2 in (0x52, 0x32)
    if file_size <= 0:
        parser_result: int | None = RESULT_NONPOSITIVE_SIZE
        outcome = "reject-nonpositive-size"
        magic_examined = False
    elif file_size <= TRAILER_SIZE:
        parser_result = RESULT_UNRECOGNIZED_TRAILER
        outcome = "reject-no-room-before-fixed-suffix"
        magic_examined = False
    elif suffix_read_items != 1:
        parser_result = RESULT_READ_FAILURE
        outcome = "reject-incomplete-fixed-suffix-read"
        magic_examined = False
    elif not recognized_magic:
        parser_result = RESULT_UNRECOGNIZED_TRAILER
        outcome = "reject-unrecognized-ter-te2-magic"
        magic_examined = True
    else:
        parser_result = None
        outcome = "recognized-trailer-candidate-continue-downstream"
        magic_examined = True

    return {
        "input": {
            "file_size": file_size,
            "suffix_read_items": suffix_read_items,
            "magic_octets": [magic0, magic1, magic2],
        },
        "fixed_suffix_size": TRAILER_SIZE,
        "fixed_suffix_size_hex": f"0x{TRAILER_SIZE:x}",
        "magic_examined": magic_examined,
        "recognized_magic": recognized_magic if magic_examined else None,
        "parser_result": parser_result,
        "outcome": outcome,
        "continues_to_later_checks": parser_result is None,
        "cryptographic_verification_succeeded": None,
    }


def classify_outer_gate(
    source_equal: bool,
    marker_present: bool,
    appupgrade_result: int,
    xml_result: int,
) -> dict[str, Any]:
    """Classify only the recovered AppDMClient retained-result pair gate."""

    source_equal = _boolean("source_equal", source_equal)
    marker_present = _boolean("marker_present", marker_present)
    appupgrade_result = _integer(
        "appupgrade_result", appupgrade_result, -(1 << 31), (1 << 31) - 1
    )
    xml_result = _integer("xml_result", xml_result, -(1 << 31), (1 << 31) - 1)

    if source_equal:
        mode = "equal-prestaged-local-path"
        contract = "pair-checks-skipped"
        allows_progression = True
    elif marker_present:
        mode = "unequal-explicit-nonencrypted-mode"
        contract = "both-results-must-be-minus-404"
        allows_progression = (
            appupgrade_result == RESULT_UNRECOGNIZED_TRAILER
            and xml_result == RESULT_UNRECOGNIZED_TRAILER
        )
    else:
        mode = "unequal-encrypted-mode"
        contract = "both-results-must-be-zero"
        allows_progression = appupgrade_result == 0 and xml_result == 0

    return {
        "input": {
            "source_equal": source_equal,
            "marker_present": marker_present,
            "appupgrade_result": appupgrade_result,
            "xml_result": xml_result,
        },
        "mode": mode,
        "retained_result_contract": contract,
        "outer_pair_gate_allows_progression": allows_progression,
        "update_accepted": None,
    }


def build_report(
    trailer_state: tuple[int, int, int, int, int] | None = None,
    gate_state: tuple[bool, bool, int, int] | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "appdmclient-fumo-trailer-and-retained-result-gates",
        "evidence_binding": {
            "appdmclient_sha256": APPDMCLIENT_SHA256,
            "appdmclient_build_id": APPDMCLIENT_BUILD_ID,
            "virtual_addresses": {
                "verifier_wrapper": "0x34870",
                "verifier": "0x121040",
                "trailer_parser": "0x11fe20",
                "minus_404_store": "0x11ff26",
                "minus_402_store": "0x11ff70",
                "minus_403_compare": "0x120f73..0x120f7a",
                "source_destination_compare": "0x80ba2..0x80bb2",
                "marker_present_pair_checks": "0x80bc8,0x80bd6",
                "marker_absent_pair_check": "0x815e0..0x815e8",
                "equal_path_jump": "0x80bb2->0x80ea7",
            },
        },
        "result_meanings": {
            str(RESULT_NONPOSITIVE_SIZE): "nonpositive-size path in the trailer parser",
            str(RESULT_READ_FAILURE): "fixed-suffix read or adjacent parser failure path",
            str(RESULT_32_BYTE_MISMATCH): "later 32-byte comparison mismatch",
            str(RESULT_UNRECOGNIZED_TRAILER): (
                "no recognized fixed-size TER/TE2 trailer candidate"
            ),
        },
        "claim_boundary": {
            "establishes": [
                "the recovered parser outcome for supplied numeric size/read/magic state",
                "the recovered retained-result pair-gate outcome for supplied numeric and boolean state",
            ],
            "does_not_establish": [
                "reachability of supplied state from removable media",
                "successful trailer parsing after recognized magic",
                "signature, digest, decryption, descriptor, version, model, or region acceptance",
                "partition writes, slot switching, boot acceptance, root access, or persistence",
                "applicability to an owner build with a different binary identity",
            ],
            "contains_only_numeric_boolean_state_and_text_metadata": True,
        },
    }
    if trailer_state is not None:
        report["trailer_classification"] = classify_trailer(*trailer_state)
    if gate_state is not None:
        report["outer_gate_classification"] = classify_outer_gate(*gate_state)
    if trailer_state is None and gate_state is None:
        report["summary"] = {
            "fixed_suffix_size": TRAILER_SIZE,
            "recognized_magic_octets": [[0x54, 0x45, 0x52], [0x54, 0x45, 0x32]],
            "marker_absent_unequal_contract": [0, 0],
            "marker_present_unequal_contract": [
                RESULT_UNRECOGNIZED_TRAILER,
                RESULT_UNRECOGNIZED_TRAILER,
            ],
            "equal_prestaged_path_skips_pair_contracts": True,
        }
    return report


def _cli_integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc


def _cli_boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file-size", type=_cli_integer)
    parser.add_argument("--suffix-read-items", type=_cli_integer)
    parser.add_argument("--magic0", type=_cli_integer)
    parser.add_argument("--magic1", type=_cli_integer)
    parser.add_argument("--magic2", type=_cli_integer)
    parser.add_argument("--source-equal", type=_cli_boolean)
    parser.add_argument("--marker-present", type=_cli_boolean)
    parser.add_argument("--appupgrade-result", type=_cli_integer)
    parser.add_argument("--xml-result", type=_cli_integer)
    return parser.parse_args(argv)


def _complete_group(name: str, values: tuple[Any, ...]) -> tuple[Any, ...] | None:
    supplied = [value is not None for value in values]
    if any(supplied) and not all(supplied):
        raise ModelError(f"all {name} arguments must be supplied together")
    return values if all(supplied) else None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        trailer_state = _complete_group(
            "trailer",
            (
                args.file_size,
                args.suffix_read_items,
                args.magic0,
                args.magic1,
                args.magic2,
            ),
        )
        gate_state = _complete_group(
            "outer-gate",
            (
                args.source_equal,
                args.marker_present,
                args.appupgrade_result,
                args.xml_result,
            ),
        )
        report = build_report(trailer_state, gate_state)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
