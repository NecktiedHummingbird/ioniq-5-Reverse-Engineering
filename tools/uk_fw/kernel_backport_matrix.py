#!/usr/bin/env python3
"""Model three recovered kernel semantic-backport decisions.

Inputs are booleans only. The model does not read a kernel, extract control
flow, invoke syscalls, create sockets or IPC objects, race target code, or emit
trigger, packet, command, firmware, or payload bytes. Pre-recorded target state
comes from separate instruction-level review and is not verified by execution
of this model.
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
    "sysvipc_credentials_before_idr": True,
    "sysvipc_message_init_before_addid": True,
    "sysvipc_shm_init_before_addid": True,
    "recvmmsg_skerr_before_fput": True,
    "inet_child_mclist_cleared": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this bounded model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_backports(
    sysvipc_credentials_before_idr: bool,
    sysvipc_message_init_before_addid: bool,
    sysvipc_shm_init_before_addid: bool,
    recvmmsg_skerr_before_fput: bool,
    inet_child_mclist_cleared: bool,
) -> dict[str, Any]:
    """Classify supplied semantic ordering and initialization facts."""

    values = {
        "sysvipc_credentials_before_idr": _boolean(
            "sysvipc_credentials_before_idr", sysvipc_credentials_before_idr
        ),
        "sysvipc_message_init_before_addid": _boolean(
            "sysvipc_message_init_before_addid",
            sysvipc_message_init_before_addid,
        ),
        "sysvipc_shm_init_before_addid": _boolean(
            "sysvipc_shm_init_before_addid", sysvipc_shm_init_before_addid
        ),
        "recvmmsg_skerr_before_fput": _boolean(
            "recvmmsg_skerr_before_fput", recvmmsg_skerr_before_fput
        ),
        "inet_child_mclist_cleared": _boolean(
            "inet_child_mclist_cleared", inet_child_mclist_cleared
        ),
    }

    sysvipc_fixed = all(
        values[name]
        for name in (
            "sysvipc_credentials_before_idr",
            "sysvipc_message_init_before_addid",
            "sysvipc_shm_init_before_addid",
        )
    )
    recvmmsg_fixed = values["recvmmsg_skerr_before_fput"]
    inet_multicast_fixed = values["inet_child_mclist_cleared"]

    return {
        "input": values,
        "cve_2015_7613": {
            "semantic_fix_present": sysvipc_fixed,
            "publication_before_initialization_premise_present": not sysvipc_fixed,
        },
        "cve_2016_7117": {
            "semantic_fix_present": recvmmsg_fixed,
            "post_fput_socket_dereference_premise_present": not recvmmsg_fixed,
        },
        "cve_2017_8890": {
            "semantic_fix_present": inet_multicast_fixed,
            "inherited_multicast_list_premise_present": not inet_multicast_fixed,
        },
        "all_three_semantic_fixes_present": (
            sysvipc_fixed and recvmmsg_fixed and inet_multicast_fixed
        ),
        "local_privilege_escalation": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "kernel-semantic-backport-matrix",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "pre_recorded_target_state": {
                "source": (
                    "separate instruction-level review; not verified by this "
                    "model execution"
                ),
                **PRE_RECORDED_TARGET_STATE,
            },
            "virtual_addresses": {
                "ipc_addid": "[0xffffffff811aa199,0xffffffff811aa294)",
                "newque": "[0xffffffff811aaa0c,0xffffffff811aab37)",
                "newseg": "[0xffffffff811ae626,0xffffffff811ae919)",
                "sysvipc_idr_alloc_call": "0xffffffff811aa22c",
                "sysvipc_message_addid_call": "0xffffffff811aaafc",
                "sysvipc_shm_addid_call": "0xffffffff811ae84a",
                "recvmmsg": "[0xffffffff81475c1d,0xffffffff81475e13)",
                "recvmmsg_skerr_store": "0xffffffff81475dd0",
                "recvmmsg_fput_call": "0xffffffff81475de5",
                "inet_csk_clone_lock": (
                    "[0xffffffff814d22f5,0xffffffff814d23ab)"
                ),
                "inet_child_mclist_clear": "0xffffffff814d2357",
            },
        },
        "claim_boundary": {
            "establishes": [
                "the three semantic classifications for supplied boolean state",
                "that all required SysV IPC initialization facts participate in its classification",
            ],
            "does_not_establish": [
                "verification that the named kernel has the pre-recorded state",
                "automatic extraction of control flow or data flow from a binary",
                "absence of unrelated socket, multicast, or IPC defects",
                "runtime syscall, interface, namespace, SMACK, seccomp, or owner-device state",
                "corruption, code execution, root access, policy escape, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_binary_or_trigger_material": True,
        },
    }
    report["pre_recorded_target_classification"] = classify_backports(
        **PRE_RECORDED_TARGET_STATE
    )
    if state is not None:
        report["classification"] = classify_backports(**state)
    return report


def _cli_boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _SingleBooleanAction(argparse.Action):
    """Reject duplicate state options instead of taking the final value."""

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
        "sysvipc-credentials-before-idr",
        "sysvipc-message-init-before-addid",
        "sysvipc-shm-init-before-addid",
        "recvmmsg-skerr-before-fput",
        "inet-child-mclist-cleared",
    ):
        parser.add_argument(
            f"--{option}", type=_cli_boolean, action=_SingleBooleanAction
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {
        "sysvipc_credentials_before_idr": args.sysvipc_credentials_before_idr,
        "sysvipc_message_init_before_addid": (
            args.sysvipc_message_init_before_addid
        ),
        "sysvipc_shm_init_before_addid": args.sysvipc_shm_init_before_addid,
        "recvmmsg_skerr_before_fput": args.recvmmsg_skerr_before_fput,
        "inet_child_mclist_cleared": args.inet_child_mclist_cleared,
    }
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all backport-state arguments must be supplied together")
    try:
        report = build_report(state if all(supplied) else None)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    serialized = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    sys.stdout.buffer.write(serialized + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
