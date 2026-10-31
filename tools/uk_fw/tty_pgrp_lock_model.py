#!/usr/bin/env python3
"""Model bounded CVE-2020-29661 TTY pgrp lock/object semantics.

Inputs are booleans only. The model does not open a PTY, issue an ioctl, create
concurrency, manipulate PID lifetimes, execute recovered code, or emit a command,
race schedule, trigger, payload, or firmware bytes. Pre-recorded target state
comes from separate instruction-level review and is not verified by this model.
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
    "master_and_real_tty_are_distinct_linked_objects": True,
    "master_setter_locks_master_and_updates_real_tty_pgrp": True,
    "slave_setter_locks_slave_and_updates_same_pgrp": True,
    "pgrp_pid_reference_is_released_and_replaced": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this bounded model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_tty_pgrp_locking(
    master_and_real_tty_are_distinct_linked_objects: bool,
    master_setter_locks_master_and_updates_real_tty_pgrp: bool,
    slave_setter_locks_slave_and_updates_same_pgrp: bool,
    pgrp_pid_reference_is_released_and_replaced: bool,
) -> dict[str, Any]:
    state = {
        "master_and_real_tty_are_distinct_linked_objects": _boolean(
            "master_and_real_tty_are_distinct_linked_objects",
            master_and_real_tty_are_distinct_linked_objects,
        ),
        "master_setter_locks_master_and_updates_real_tty_pgrp": _boolean(
            "master_setter_locks_master_and_updates_real_tty_pgrp",
            master_setter_locks_master_and_updates_real_tty_pgrp,
        ),
        "slave_setter_locks_slave_and_updates_same_pgrp": _boolean(
            "slave_setter_locks_slave_and_updates_same_pgrp",
            slave_setter_locks_slave_and_updates_same_pgrp,
        ),
        "pgrp_pid_reference_is_released_and_replaced": _boolean(
            "pgrp_pid_reference_is_released_and_replaced",
            pgrp_pid_reference_is_released_and_replaced,
        ),
    }
    premise = all(state.values())
    return {
        "input": state,
        "cve_2020_29661_wrong_object_lock_premise_present": premise,
        "same_pgrp_can_be_updated_under_distinct_locks": premise,
        "runtime_pty_reachability_observed": None,
        "successful_concurrent_interleaving_observed": None,
        "use_after_free_observed": None,
        "privilege_escalation": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "tty-pgrp-wrong-object-lock",
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
                "tty_ioctl": "[0xffffffff812871f8,0xffffffff81287d46)",
                "tiocspgrp_branch": (
                    "0xffffffff81287857..0xffffffff812879a4"
                ),
                "tty_get_pgrp": "[0xffffffff81285310,0xffffffff81285354)",
                "pty_unix98_install": (
                    "[0xffffffff8128f8ed,0xffffffff8128fa8d)"
                ),
            },
        },
        "claim_boundary": {
            "establishes": [
                "classification of the four supplied object and lock facts",
                "whether the same pgrp update is protected by distinct locks",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions",
                "runtime PTY node, mount, ownership, or policy reachability",
                "a successful concurrent interleaving or PID use-after-free",
                "corruption, code execution, root access, policy escape, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_trigger_or_target_material": True,
        },
    }
    report["pre_recorded_target_classification"] = classify_tty_pgrp_locking(
        **PRE_RECORDED_TARGET_STATE
    )
    if state is not None:
        report["classification"] = classify_tty_pgrp_locking(**state)
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
    for option in (
        "master-and-real-tty-are-distinct-linked-objects",
        "master-setter-locks-master-and-updates-real-tty-pgrp",
        "slave-setter-locks-slave-and-updates-same-pgrp",
        "pgrp-pid-reference-is-released-and-replaced",
    ):
        parser.add_argument(
            f"--{option}", type=_cli_boolean, action=_SingleBooleanAction
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {
        "master_and_real_tty_are_distinct_linked_objects": (
            args.master_and_real_tty_are_distinct_linked_objects
        ),
        "master_setter_locks_master_and_updates_real_tty_pgrp": (
            args.master_setter_locks_master_and_updates_real_tty_pgrp
        ),
        "slave_setter_locks_slave_and_updates_same_pgrp": (
            args.slave_setter_locks_slave_and_updates_same_pgrp
        ),
        "pgrp_pid_reference_is_released_and_replaced": (
            args.pgrp_pid_reference_is_released_and_replaced
        ),
    }
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all TTY pgrp state arguments must be supplied together")
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
