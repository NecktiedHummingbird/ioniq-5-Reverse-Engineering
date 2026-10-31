#!/usr/bin/env python3
"""Classify bounded CVE-2017-9242 IPv6 append-data premises.

Inputs are booleans only. This model does not open a socket, issue a syscall,
construct a packet or IPv6 header, execute recovered code, or emit an option,
fragment, target address, command, trigger, payload, or firmware bytes.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
VMLINUX_BUILD_ID = "273378887b4cf563c10862fdf18b2292765df781"

PRE_RECORDED_TARGET_STATE = {
    "config_ipv6_builtin": True,
    "udpv6_send_reaches_ip6_append_data": True,
    "skb_allocation_before_negative_copy_check": True,
    "fraggap_copy_before_negative_copy_check": True,
    "negative_cleanup_after_fraggap_copy": True,
    "upstream_early_reject_effect_present": False,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this Boolean-only model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_ipv6_append_bounds(**values: bool) -> dict[str, Any]:
    if set(values) != set(PRE_RECORDED_TARGET_STATE):
        missing = sorted(set(PRE_RECORDED_TARGET_STATE) - set(values))
        extra = sorted(set(values) - set(PRE_RECORDED_TARGET_STATE))
        raise ModelError(f"state keys mismatch: missing={missing}, extra={extra}")
    state = {
        name: _boolean(name, values[name]) for name in PRE_RECORDED_TARGET_STATE
    }
    affected_ordering = all(
        state[name]
        for name in (
            "config_ipv6_builtin",
            "udpv6_send_reaches_ip6_append_data",
            "skb_allocation_before_negative_copy_check",
            "fraggap_copy_before_negative_copy_check",
            "negative_cleanup_after_fraggap_copy",
        )
    ) and not state["upstream_early_reject_effect_present"]

    return {
        "input": state,
        "cve_2017_9242_affected_ordering_present": affected_ordering,
        "runtime_socket_policy_observed": None,
        "crafted_internal_state_achieved": None,
        "out_of_bounds_write_observed": None,
        "controlled_corruption_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "ipv6-append-data-bounds-ordering",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "upstream_fix_commit": "232cd35d0804cc241eb887bb8d4d9b3b9881c64a",
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-ipv6-cve-2017-9242.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied IPv6 configuration, call-route, and bounds-check ordering facts",
                "whether the reviewed affected ordering is supplied",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions",
                "runtime uid, SMACK, seccomp, socket policy, or installed kernel identity",
                "achievement of the required internal skb and fraggap state",
                "an overwrite, crash, controlled corruption, code execution, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_socket_option_syscall_packet_header_fragment_address_command_trigger_payload_instructions_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_ipv6_append_bounds(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_ipv6_append_bounds(**state)
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
        raise SystemExit("error: all IPv6 append state arguments must be supplied together")
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
