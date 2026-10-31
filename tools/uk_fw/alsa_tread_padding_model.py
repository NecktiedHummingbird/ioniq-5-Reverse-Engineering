#!/usr/bin/env python3
"""Model ALSA extended-timer-record initialization and copy decisions.

Inputs are booleans only. This model does not open a device, issue an ioctl,
configure a timer, read target data, execute a recovered module, or emit a
packet, command, trigger, payload, or firmware byte sequence. The exact target
state is pre-recorded from separate instruction-level review and is not verified
by model execution.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
MODULE_SHA256 = "3b2fa4e722ff210c2643089b2035a4ba93134ad1624e0c520bafa6debac46a91"
MODULE_BUILD_ID = "42457bdb4c6cd4911a707afac6912e23d735b68a"
PRE_RECORDED_TARGET_STATE = {
    "params_record_fully_initialized": True,
    "ccallback_record_fully_initialized": True,
    "tinterrupt_resolution_record_fully_initialized": False,
    "tinterrupt_tick_record_fully_initialized": False,
    "queue_copies_complete_record": True,
    "read_returns_complete_record": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this bounded model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_padding_paths(
    params_record_fully_initialized: bool,
    ccallback_record_fully_initialized: bool,
    tinterrupt_resolution_record_fully_initialized: bool,
    tinterrupt_tick_record_fully_initialized: bool,
    queue_copies_complete_record: bool,
    read_returns_complete_record: bool,
) -> dict[str, Any]:
    """Classify user-visible uninitialized-record paths for supplied state."""

    state = {
        "params_record_fully_initialized": _boolean(
            "params_record_fully_initialized", params_record_fully_initialized
        ),
        "ccallback_record_fully_initialized": _boolean(
            "ccallback_record_fully_initialized", ccallback_record_fully_initialized
        ),
        "tinterrupt_resolution_record_fully_initialized": _boolean(
            "tinterrupt_resolution_record_fully_initialized",
            tinterrupt_resolution_record_fully_initialized,
        ),
        "tinterrupt_tick_record_fully_initialized": _boolean(
            "tinterrupt_tick_record_fully_initialized",
            tinterrupt_tick_record_fully_initialized,
        ),
        "queue_copies_complete_record": _boolean(
            "queue_copies_complete_record", queue_copies_complete_record
        ),
        "read_returns_complete_record": _boolean(
            "read_returns_complete_record", read_returns_complete_record
        ),
    }
    reaches_read = (
        state["queue_copies_complete_record"]
        and state["read_returns_complete_record"]
    )
    paths = {
        "params_early_event": (
            reaches_read and not state["params_record_fully_initialized"]
        ),
        "ccallback_event": (
            reaches_read and not state["ccallback_record_fully_initialized"]
        ),
        "tinterrupt_resolution_event": (
            reaches_read
            and not state["tinterrupt_resolution_record_fully_initialized"]
        ),
        "tinterrupt_tick_event": (
            reaches_read
            and not state["tinterrupt_tick_record_fully_initialized"]
        ),
    }
    return {
        "input": state,
        "complete_record_reaches_read": reaches_read,
        "uninitialized_user_visible_paths": paths,
        "any_uninitialized_user_visible_path": any(paths.values()),
        "runtime_disclosure_observed": None,
        "privilege_escalation": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "alsa-tread-padding-flow",
        "evidence_binding": {
            "module_sha256": MODULE_SHA256,
            "module_build_id": MODULE_BUILD_ID,
            "elf": {
                "type": "ET_REL",
                "text_file_offset": "0x64",
                "text_size": "0x2d44",
                "addresses": "section-relative",
            },
            "pre_recorded_target_state": {
                "source": (
                    "separate instruction-level review; not verified by this "
                    "model execution"
                ),
                **PRE_RECORDED_TARGET_STATE,
            },
            "section_relative_addresses": {
                "queue_append": "[0xb9b,0xbdf)",
                "ccallback": "[0xbdf,0xcc3)",
                "tinterrupt": "[0xcc3,0xe43)",
                "read": "[0x182f,0x1a4a)",
                "params": "[0x2153,0x236d)",
            },
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied record-initialization and full-copy facts",
                "which supplied paths can carry uninitialized record bytes to read",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions",
                "runtime module load or device-node availability",
                "event-provider availability or successful event generation",
                "actual target bytes, stack contents, or observed disclosure",
                "code execution, root access, policy escape, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_trigger_or_target_material": True,
        },
    }
    report["pre_recorded_target_classification"] = classify_padding_paths(
        **PRE_RECORDED_TARGET_STATE
    )
    if state is not None:
        report["classification"] = classify_padding_paths(**state)
    return report


def _cli_boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _SingleBooleanAction(argparse.Action):
    """Reject duplicate state options rather than taking the final value."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: bool,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for option in (
        "params-record-fully-initialized",
        "ccallback-record-fully-initialized",
        "tinterrupt-resolution-record-fully-initialized",
        "tinterrupt-tick-record-fully-initialized",
        "queue-copies-complete-record",
        "read-returns-complete-record",
    ):
        parser.add_argument(
            f"--{option}", type=_cli_boolean, action=_SingleBooleanAction
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {
        "params_record_fully_initialized": args.params_record_fully_initialized,
        "ccallback_record_fully_initialized": (
            args.ccallback_record_fully_initialized
        ),
        "tinterrupt_resolution_record_fully_initialized": (
            args.tinterrupt_resolution_record_fully_initialized
        ),
        "tinterrupt_tick_record_fully_initialized": (
            args.tinterrupt_tick_record_fully_initialized
        ),
        "queue_copies_complete_record": args.queue_copies_complete_record,
        "read_returns_complete_record": args.read_returns_complete_record,
    }
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all padding-state arguments must be supplied together")
    try:
        report = build_report(state if all(supplied) else None)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    serialized = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    sys.stdout.buffer.write(serialized + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
