#!/usr/bin/env python3
"""Model the recovered FUMO navigation-map signature gate.

The model accepts booleans and bounded integers only. It does not read or create
firmware, map data, signatures, archives, commands, markers, or executable
inputs. A skipped or successful navigation-map gate is only local control-flow
progression; it is not package acceptance, a partition write, or boot trust.
"""
from __future__ import annotations

import argparse
import json
from typing import Any

SCHEMA_VERSION = 1
FUMO_SHA256 = "464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7"
FUMO_BUILD_ID = "863a8730e66a1c5245a1bf458fe2554adee0351a"
ASYNC_PENDING = -1
ASYNC_SUCCESS = 0
ASYNC_FAILURE = 1


class ModelError(ValueError):
    """Raised when supplied state is outside this bounded model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def _state(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelError(f"{name} must be an integer")
    if value not in (ASYNC_PENDING, ASYNC_SUCCESS, ASYNC_FAILURE):
        raise ModelError(f"{name} must be -1 (pending), 0 (success), or 1 (failure)")
    return value


def classify_gate(
    gate_already_complete: bool,
    disable_marker_present: bool,
    navi_update_app_present: bool,
    encryption_mode: bool,
    navi_map_candidate_present: bool,
    start_state: int,
    start_timed_out: bool,
    result_state: int,
    result_timed_out: bool,
) -> dict[str, Any]:
    """Classify only the exact local navigation-map signature gate."""

    gate_already_complete = _boolean("gate_already_complete", gate_already_complete)
    disable_marker_present = _boolean(
        "disable_marker_present", disable_marker_present
    )
    navi_update_app_present = _boolean(
        "navi_update_app_present", navi_update_app_present
    )
    encryption_mode = _boolean("encryption_mode", encryption_mode)
    navi_map_candidate_present = _boolean(
        "navi_map_candidate_present", navi_map_candidate_present
    )
    start_state = _state("start_state", start_state)
    start_timed_out = _boolean("start_timed_out", start_timed_out)
    result_state = _state("result_state", result_state)
    result_timed_out = _boolean("result_timed_out", result_timed_out)

    signature_attempted = False
    signature_succeeded: bool | None = None
    allows_progression: bool | None

    if gate_already_complete:
        outcome = "gate-already-complete"
        allows_progression = True
    elif disable_marker_present:
        outcome = "skip-explicit-disable-marker"
        allows_progression = True
    elif not navi_update_app_present:
        outcome = "skip-navi-update-app-absent"
        allows_progression = True
    elif not encryption_mode:
        outcome = "skip-nonencrypted-mode"
        allows_progression = True
    elif not navi_map_candidate_present:
        outcome = "skip-no-navi-map-candidate"
        allows_progression = True
    else:
        signature_attempted = True
        if start_timed_out and start_state != ASYNC_PENDING:
            raise ModelError("start_timed_out requires pending start_state")
        if result_timed_out and result_state != ASYNC_PENDING:
            raise ModelError("result_timed_out requires pending result_state")
        if (start_timed_out or start_state != ASYNC_SUCCESS) and (
            result_timed_out or result_state != ASYNC_PENDING
        ):
            raise ModelError(
                "result stage must be pending and not timed out until start succeeds"
            )
        if start_timed_out:
            outcome = "stop-signature-start-timeout"
            allows_progression = False
            signature_succeeded = False
        elif start_state == ASYNC_PENDING:
            outcome = "wait-signature-start-result"
            allows_progression = None
        elif start_state == ASYNC_FAILURE:
            outcome = "stop-signature-start-failure"
            allows_progression = False
            signature_succeeded = False
        elif result_timed_out:
            outcome = "stop-signature-result-timeout"
            allows_progression = False
            signature_succeeded = False
        elif result_state == ASYNC_PENDING:
            outcome = "wait-signature-verification-result"
            allows_progression = None
        elif result_state == ASYNC_FAILURE:
            outcome = "stop-signature-verification-failure"
            allows_progression = False
            signature_succeeded = False
        else:
            outcome = "signature-success-reenter-gate"
            allows_progression = True
            signature_succeeded = True

    return {
        "input": {
            "gate_already_complete": gate_already_complete,
            "disable_marker_present": disable_marker_present,
            "navi_update_app_present": navi_update_app_present,
            "encryption_mode": encryption_mode,
            "navi_map_candidate_present": navi_map_candidate_present,
            "start_state": start_state,
            "start_timed_out": start_timed_out,
            "result_state": result_state,
            "result_timed_out": result_timed_out,
        },
        "outcome": outcome,
        "signature_attempted": signature_attempted,
        "navigation_signature_succeeded": signature_succeeded,
        "navigation_signature_gate_allows_progression": allows_progression,
        "update_accepted": None,
    }


def build_report(state: tuple[bool, bool, bool, bool, bool, int, bool, int, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "fumo-navigation-map-signature-gate",
        "evidence_binding": {
            "embedded_fumo_sha256": FUMO_SHA256,
            "embedded_fumo_build_id": FUMO_BUILD_ID,
            "virtual_addresses": {
                "gate": "0x128070..0x128c52",
                "disable_marker_check": "0x128128..0x12816a",
                "disable_marker_skip": "0x128720..0x128745",
                "encryption_mode_test": "0x128940..0x128947",
                "nonencrypted_skip_target": "0x128330..0x128364",
                "no_candidate_skip": "0x128a32..0x128a54",
                "signature_start_poll_function": "0x128c60..0x128e37",
                "signature_result_poll_function": "0x128e40..0x129037",
                "successful_reentry": "0x128f40..0x128f75",
            },
            "state": {
                "gate_complete_byte": "this+0xd5",
                "encryption_mode_byte": "0x6d20b4",
                "disable_marker": "/update/disableNaviMapSignatureCheck_20230207",
                "navi_signature_provider": "/app/bin/NaviUpdateApp",
            },
        },
        "async_state_values": {
            str(ASYNC_PENDING): "pending",
            str(ASYNC_SUCCESS): "success",
            str(ASYNC_FAILURE): "failure",
        },
        "claim_boundary": {
            "establishes": [
                "the recovered navigation-map signature-gate outcome for supplied boolean and numeric state",
                "which supplied states skip, wait, stop, or progress through this one gate",
            ],
            "does_not_establish": [
                "who can create either local marker or provider file",
                "reachability of supplied state from removable media",
                "signature coverage, key provenance, or resistance of the signature implementation",
                "descriptor, version, model, region, digest, payload, partition, or boot acceptance",
                "root access, policy escape, persistence, or applicability to another binary identity",
            ],
            "contains_only_numeric_boolean_state_and_text_metadata": True,
        },
    }
    if state is None:
        report["summary"] = {
            "skip_conditions": [
                "gate-already-complete",
                "explicit-disable-marker",
                "navi-update-app-absent",
                "nonencrypted-mode",
                "no-navi-map-candidate",
            ],
            "signature_required_condition": (
                "incomplete gate, no disable marker, NaviUpdateApp present, "
                "encrypted mode, and navigation-map candidate present"
            ),
        }
    else:
        report["classification"] = classify_gate(*state)
    return report


def _cli_boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def _cli_integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate-already-complete", type=_cli_boolean)
    parser.add_argument("--disable-marker-present", type=_cli_boolean)
    parser.add_argument("--navi-update-app-present", type=_cli_boolean)
    parser.add_argument("--encryption-mode", type=_cli_boolean)
    parser.add_argument("--navi-map-candidate-present", type=_cli_boolean)
    parser.add_argument("--start-state", type=_cli_integer)
    parser.add_argument("--start-timed-out", type=_cli_boolean)
    parser.add_argument("--result-state", type=_cli_integer)
    parser.add_argument("--result-timed-out", type=_cli_boolean)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    values = (
        args.gate_already_complete,
        args.disable_marker_present,
        args.navi_update_app_present,
        args.encryption_mode,
        args.navi_map_candidate_present,
        args.start_state,
        args.start_timed_out,
        args.result_state,
        args.result_timed_out,
    )
    supplied = [value is not None for value in values]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all gate-state arguments must be supplied together")
    try:
        state = values if all(supplied) else None
        report = build_report(state)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
