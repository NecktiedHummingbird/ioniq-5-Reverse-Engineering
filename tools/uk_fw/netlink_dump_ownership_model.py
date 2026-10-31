#!/usr/bin/env python3
"""Classify bounded CVE-2016-9806 netlink dump cleanup ownership facts.

Inputs are booleans only. This host-only model does not open a netlink socket,
send a message, start a dump, create concurrency, execute recovered code, or
emit a socket address, message, race schedule, command, payload, or firmware
bytes.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
VMLINUX_BUILD_ID = "273378887b4cf563c10862fdf18b2292765df781"
FIX_COMMIT = "92964c79b357efd980812c4de5c1fd2ec8bb5520"

PRE_RECORDED_TARGET_STATE = {
    "netlink_dump_completion_path_present": True,
    "callback_fields_may_change_after_mutex_unlock": True,
    "module_pointer_captured_before_mutex_unlock": True,
    "callback_skb_captured_before_mutex_unlock": True,
    "module_release_uses_captured_pointer": True,
    "skb_consume_uses_captured_pointer": True,
    "captured_objects_released_after_mutex_unlock": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this Boolean-only model."""


def classify_dump_ownership(**values: bool) -> dict[str, Any]:
    expected = set(PRE_RECORDED_TARGET_STATE)
    if set(values) != expected:
        missing = sorted(expected - set(values))
        extra = sorted(set(values) - expected)
        raise ModelError(f"state keys mismatch: missing={missing}, extra={extra}")

    state: dict[str, bool] = {}
    for name in PRE_RECORDED_TARGET_STATE:
        value = values[name]
        if not isinstance(value, bool):
            raise ModelError(f"{name} must be a boolean")
        state[name] = value

    complete_saved_object_cleanup = all(
        state[name]
        for name in (
            "module_pointer_captured_before_mutex_unlock",
            "callback_skb_captured_before_mutex_unlock",
            "module_release_uses_captured_pointer",
            "skb_consume_uses_captured_pointer",
        )
    )
    post_unlock_mutable_callback_window = (
        state["netlink_dump_completion_path_present"]
        and state["callback_fields_may_change_after_mutex_unlock"]
        and state["captured_objects_released_after_mutex_unlock"]
    )
    rejected_by_saved_object_cleanup = (
        post_unlock_mutable_callback_window and complete_saved_object_cleanup
    )
    if not post_unlock_mutable_callback_window or complete_saved_object_cleanup:
        mutable_callback_cleanup_premise: bool | None = False
    else:
        # Missing one or more saved-object effects does not prove that cleanup
        # reloads a mutable callback field. Without an explicit reload fact,
        # the CVE-specific vulnerable premise remains unknown.
        mutable_callback_cleanup_premise = None
    not_rejected_by_complete_saved_object_effects = (
        post_unlock_mutable_callback_window and not complete_saved_object_cleanup
    )

    return {
        "input": state,
        "complete_saved_object_cleanup_present": complete_saved_object_cleanup,
        "post_unlock_mutable_callback_window_present": (
            post_unlock_mutable_callback_window
        ),
        "cve_2016_9806_mutable_callback_cleanup_premise_present": (
            mutable_callback_cleanup_premise
        ),
        "cve_2016_9806_rejected_by_supplied_fix_effects": (
            rejected_by_saved_object_cleanup
        ),
        "cve_2016_9806_not_rejected_by_complete_saved_object_effects": (
            not_rejected_by_complete_saved_object_effects
        ),
        "runtime_netlink_dump_reachability_observed": None,
        "concurrent_replacement_observed": None,
        "old_or_new_skb_double_free_observed": None,
        "kernel_crash_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "netlink-dump-saved-object-ownership",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "upstream_fix_commit": FIX_COMMIT,
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-netlink-cve-2016-9806.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied netlink callback ownership facts",
                "whether module and skb identities are captured under the callback mutex and consumed after unlock",
                "whether complete saved-object effects reject the CVE-specific mutable-callback cleanup premise",
                "unknown rather than affected when supplied fix effects are incomplete and no vulnerable reload fact is provided",
            ],
            "does_not_establish": [
                "automatic extraction or verification of kernel instructions",
                "absence of unrelated netlink defects",
                "installed-kernel identity or runtime netlink policy and reachability",
                "a concurrent replacement, double free, crash, corruption, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_socket_message_race_schedule_command_payload_instructions_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_dump_ownership(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_dump_ownership(**state)
    return report


def _cli_boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _SingleBooleanAction(argparse.Action):
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
    for option in PRE_RECORDED_TARGET_STATE:
        parser.add_argument(
            f"--{option.replace('_', '-')}",
            dest=option,
            type=_cli_boolean,
            action=_SingleBooleanAction,
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {name: getattr(args, name) for name in PRE_RECORDED_TARGET_STATE}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all netlink dump ownership arguments must be supplied together")
    try:
        report = build_report(state if all(supplied) else None)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    sys.stdout.buffer.write(
        json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
