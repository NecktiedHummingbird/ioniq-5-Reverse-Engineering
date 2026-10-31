#!/usr/bin/env python3
"""Model the CVE-2017-11176 mq_notify retry ownership edge.

The model accepts booleans only. It does not invoke message-queue or netlink
system calls, create race conditions, read a target binary, or emit trigger,
packet, command, or payload bytes. Its purpose is to prevent a false static
classification when a compiler represents ``sock = NULL`` by routing retry
failures directly to skb-only cleanup instead of emitting an explicit zeroing
instruction.
"""
from __future__ import annotations

import argparse
import json
from typing import Any

SCHEMA_VERSION = 1
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
VMLINUX_BUILD_ID = "273378887b4cf563c10862fdf18b2292765df781"
PRE_RECORDED_TARGET_STATE = {
    "attach_return_one_drops_socket_reference": True,
    "explicit_socket_clear_before_retry": False,
    "retry_fdget_failure_reaches_socket_detach_cleanup": False,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this bounded model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_retry_edge(
    attach_return_one_drops_socket_reference: bool,
    explicit_socket_clear_before_retry: bool,
    retry_fdget_failure_reaches_socket_detach_cleanup: bool,
) -> dict[str, Any]:
    """Classify the ownership consequence of the return-one retry edge.

    The first boolean records the callee's reference transition. The second
    records caller data flow. The third records only whether the failed-retry
    control-flow edge reaches socket-detach cleanup; it does not assert what
    pointer value a detach block would observe. The CVE primitive requires the
    dropped reference, preserved old pointer, and detach-cleanup edge together.
    An explicit clear is one fix representation. Routing failed retry lookup
    directly to skb-only cleanup is another equivalent representation.
    """

    attach_return_one_drops_socket_reference = _boolean(
        "attach_return_one_drops_socket_reference",
        attach_return_one_drops_socket_reference,
    )
    explicit_socket_clear_before_retry = _boolean(
        "explicit_socket_clear_before_retry", explicit_socket_clear_before_retry
    )
    retry_fdget_failure_reaches_socket_detach_cleanup = _boolean(
        "retry_fdget_failure_reaches_socket_detach_cleanup",
        retry_fdget_failure_reaches_socket_detach_cleanup,
    )

    stale_pointer_at_retry = (
        attach_return_one_drops_socket_reference
        and not explicit_socket_clear_before_retry
    )
    stale_detach_path = (
        stale_pointer_at_retry
        and retry_fdget_failure_reaches_socket_detach_cleanup
    )

    if not attach_return_one_drops_socket_reference:
        outcome = "cve-contract-not-modeled"
        semantic_fix_present: bool | None = None
        primitive_present: bool | None = None
    elif stale_detach_path:
        outcome = "vulnerable-stale-detach-path"
        semantic_fix_present = False
        primitive_present = True
    elif explicit_socket_clear_before_retry:
        outcome = "fixed-explicit-clear"
        semantic_fix_present = True
        primitive_present = False
    else:
        outcome = "fixed-equivalent-cleanup-routing"
        semantic_fix_present = True
        primitive_present = False

    return {
        "input": {
            "attach_return_one_drops_socket_reference": (
                attach_return_one_drops_socket_reference
            ),
            "explicit_socket_clear_before_retry": (
                explicit_socket_clear_before_retry
            ),
            "retry_fdget_failure_reaches_socket_detach_cleanup": (
                retry_fdget_failure_reaches_socket_detach_cleanup
            ),
        },
        "outcome": outcome,
        "stale_pointer_at_retry": stale_pointer_at_retry,
        "stale_pointer_can_reach_detach": stale_detach_path,
        "cve_2017_11176_semantic_fix_present": semantic_fix_present,
        "cve_2017_11176_reference_overrelease_primitive_present": primitive_present,
        "local_privilege_escalation": None,
    }


def build_report(state: tuple[bool, bool, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "mq-notify-return-one-reference-ownership",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "virtual_addresses": {
                "sys_mq_notify": "[0xffffffff811b1580,0xffffffff811b18da)",
                "retry_head": "0xffffffff811b1694",
                "netlink_attachskb_call": "0xffffffff811b16f2",
                "return_one_retry_branch": "0xffffffff811b16f7..0xffffffff811b16ff",
                "retry_fdget_failure": "0xffffffff811b16a9 -> 0xffffffff811b1709",
                "skb_only_cleanup": "0xffffffff811b18a4",
                "socket_detach_cleanup": "0xffffffff811b1892",
                "netlink_attachskb_return_one_release": (
                    "0xffffffff814a8d56..0xffffffff814a8d70"
                ),
            },
            "pre_recorded_target_state": {
                "source": (
                    "separate instruction-level review; not verified by this "
                    "model execution"
                ),
                **PRE_RECORDED_TARGET_STATE,
            },
        },
        "claim_boundary": {
            "establishes": [
                "the ownership result for supplied boolean control-flow state",
                "that explicit pointer-zeroing is not the only machine-code representation of the fix",
            ],
            "does_not_establish": [
                (
                    "verification that the named hash or Build ID has the "
                    "pre-recorded control-flow state"
                ),
                "automatic extraction of control flow or data flow from an arbitrary binary",
                "absence of unrelated POSIX-message-queue or netlink defects",
                "runtime syscall availability, SMACK policy, seccomp state, or owner-device applicability",
                "kernel corruption, code execution, root access, policy escape, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_binary_or_trigger_material": True,
        },
    }
    report["pre_recorded_target_classification"] = classify_retry_edge(
        **PRE_RECORDED_TARGET_STATE
    )
    if state is not None:
        report["classification"] = classify_retry_edge(*state)
    return report


def _cli_boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _SingleBooleanAction(argparse.Action):
    """Reject duplicate state options instead of silently taking the last."""

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
    parser.add_argument(
        "--attach-return-one-drops-socket-reference",
        type=_cli_boolean,
        action=_SingleBooleanAction,
    )
    parser.add_argument(
        "--explicit-socket-clear-before-retry",
        type=_cli_boolean,
        action=_SingleBooleanAction,
    )
    parser.add_argument(
        "--retry-fdget-failure-reaches-socket-detach-cleanup",
        type=_cli_boolean,
        action=_SingleBooleanAction,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    values = (
        args.attach_return_one_drops_socket_reference,
        args.explicit_socket_clear_before_retry,
        args.retry_fdget_failure_reaches_socket_detach_cleanup,
    )
    supplied = [value is not None for value in values]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all retry-state arguments must be supplied together")
    try:
        state = values if all(supplied) else None
        report = build_report(state)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
