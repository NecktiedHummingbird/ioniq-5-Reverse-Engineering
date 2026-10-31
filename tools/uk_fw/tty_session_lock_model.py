#!/usr/bin/env python3
"""Model bounded CVE-2020-29660 TTY session-lock premises.

Inputs are booleans only. This model does not open a PTY, issue an ioctl,
create concurrency, manipulate PID lifetimes, execute recovered code, or emit a
command, race schedule, trigger, payload, or firmware bytes.
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
    "tiocgsid_reads_session_without_ctrl_lock_or_reference": True,
    "pid_vnr_dereferences_the_supplied_pid": True,
    "writer_releases_session_reference_before_clearing_or_replacing_field": True,
    "upstream_fix_effect_absent": True,
    "config_preempt_full": False,
    "config_smp": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this Boolean-only model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_tty_session_locking(
    tiocgsid_reads_session_without_ctrl_lock_or_reference: bool,
    pid_vnr_dereferences_the_supplied_pid: bool,
    writer_releases_session_reference_before_clearing_or_replacing_field: bool,
    upstream_fix_effect_absent: bool,
    config_preempt_full: bool,
    config_smp: bool,
) -> dict[str, Any]:
    state = {
        "tiocgsid_reads_session_without_ctrl_lock_or_reference": _boolean(
            "tiocgsid_reads_session_without_ctrl_lock_or_reference",
            tiocgsid_reads_session_without_ctrl_lock_or_reference,
        ),
        "pid_vnr_dereferences_the_supplied_pid": _boolean(
            "pid_vnr_dereferences_the_supplied_pid",
            pid_vnr_dereferences_the_supplied_pid,
        ),
        "writer_releases_session_reference_before_clearing_or_replacing_field": _boolean(
            "writer_releases_session_reference_before_clearing_or_replacing_field",
            writer_releases_session_reference_before_clearing_or_replacing_field,
        ),
        "upstream_fix_effect_absent": _boolean(
            "upstream_fix_effect_absent", upstream_fix_effect_absent
        ),
        "config_preempt_full": _boolean("config_preempt_full", config_preempt_full),
        "config_smp": _boolean("config_smp", config_smp),
    }
    locking_premise = all(
        state[name]
        for name in (
            "tiocgsid_reads_session_without_ctrl_lock_or_reference",
            "pid_vnr_dereferences_the_supplied_pid",
            "writer_releases_session_reference_before_clearing_or_replacing_field",
            "upstream_fix_effect_absent",
        )
    )
    return {
        "input": state,
        "cve_2020_29660_locking_premise_present": locking_premise,
        "config_preempt_full": state["config_preempt_full"],
        "config_smp": state["config_smp"],
        "upstream_documented_preempt_leak_premise": (
            locking_premise and state["config_preempt_full"]
        ),
        "locking_premise_and_smp_configuration": (
            locking_premise and state["config_smp"]
        ),
        "runtime_pty_reachability_observed": None,
        "harmful_interleaving_observed": None,
        "four_byte_freed_memory_read_observed": None,
        "privilege_escalation": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "tty-session-locking",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-tty-session-cve-2020-29660.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied TTY session-lock and configuration facts",
                "whether the upstream-documented full-preemption condition is supplied",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions",
                "runtime PTY, ioctl, uid, SMACK, or syscall-policy reachability",
                "a realizable or successful harmful interleaving",
                "a freed-memory read, corruption, code execution, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_trigger_command_race_schedule_payload_instructions_or_firmware_bytes": True,
        },
    }
    report["pre_recorded_target_classification"] = classify_tty_session_locking(
        **PRE_RECORDED_TARGET_STATE
    )
    if state is not None:
        report["classification"] = classify_tty_session_locking(**state)
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
        "tiocgsid-reads-session-without-ctrl-lock-or-reference",
        "pid-vnr-dereferences-the-supplied-pid",
        "writer-releases-session-reference-before-clearing-or-replacing-field",
        "upstream-fix-effect-absent",
        "config-preempt-full",
        "config-smp",
    ):
        parser.add_argument(
            f"--{option}", type=_cli_boolean, action=_SingleBooleanAction
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {
        name: getattr(args, name) for name in PRE_RECORDED_TARGET_STATE
    }
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all TTY session state arguments must be supplied together")
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
