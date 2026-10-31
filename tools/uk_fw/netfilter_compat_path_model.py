#!/usr/bin/env python3
"""Classify bounded CVE-2016-4997 compat-netfilter path facts.

This Boolean-only host model performs no target syscall, socket operation,
namespace creation, packet/filter construction, target execution, or target
interaction. Ordinary host runtime operations remain outside that claim.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
FIX_COMMIT = "ce683e5f9d045e5d67d1312a42b359cb2ab2a13c"

PRE_RECORDED_TARGET_STATE = {
    "public_cve_requires_compat_setsockopt": True,
    "ia32_emulation_disabled": True,
    "compat_config_absent": True,
    "compat_sys_setsockopt_is_enosys_stub": True,
    "compat_iptables_translation_symbols_present": False,
}


class ModelError(ValueError):
    pass


def classify_compat_path(**values: bool) -> dict[str, Any]:
    expected = set(PRE_RECORDED_TARGET_STATE)
    if set(values) != expected:
        raise ModelError(
            f"state keys mismatch: missing={sorted(expected - set(values))}, "
            f"extra={sorted(set(values) - expected)}"
        )
    state: dict[str, bool] = {}
    for name in PRE_RECORDED_TARGET_STATE:
        value = values[name]
        if not isinstance(value, bool):
            raise ModelError(f"{name} must be a boolean")
        state[name] = value

    absence_complete = (
        state["public_cve_requires_compat_setsockopt"]
        and state["ia32_emulation_disabled"]
        and state["compat_config_absent"]
        and state["compat_sys_setsockopt_is_enosys_stub"]
        and not state["compat_iptables_translation_symbols_present"]
    )
    explicit_presence = (
        state["public_cve_requires_compat_setsockopt"]
        and not state["ia32_emulation_disabled"]
        and not state["compat_config_absent"]
        and not state["compat_sys_setsockopt_is_enosys_stub"]
        and state["compat_iptables_translation_symbols_present"]
    )
    path_present: bool | None
    if absence_complete:
        path_present = False
    elif explicit_presence:
        path_present = True
    else:
        path_present = None

    return {
        "input": state,
        "complete_compat_prerequisite_absence_present": absence_complete,
        "compat_netfilter_replace_path_compiled_and_dispatchable": path_present,
        "cve_2016_4997_rejected_by_absent_compat_path": absence_complete,
        "cve_2016_4997_not_rejected_by_complete_absence": not absence_complete,
        "installed_kernel_identity_observed": None,
        "runtime_syscall_filter_observed": None,
        "compat_setsockopt_request_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "netfilter-compat-path-prerequisite",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "upstream_fix_commit": FIX_COMMIT,
            "pre_recorded_target_state": {
                "source": "separate configuration, symbol, and instruction review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-netfilter-cve-2016-4997.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied compat-path prerequisite facts",
                "unknown rather than affected when absence and presence are both incomplete",
            ],
            "does_not_establish": [
                "automatic configuration, symbol, or instruction verification",
                "general native netfilter safety or installed-kernel identity",
                "request delivery, corruption, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_target_syscall_socket_filter_packet_namespace_command_payload_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_compat_path(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_compat_path(**state)
    return report


def _bool(value: str) -> bool:
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in PRE_RECORDED_TARGET_STATE:
        parser.add_argument(
            f"--{name.replace('_', '-')}", dest=name, type=_bool, action=_Once
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {name: getattr(args, name) for name in PRE_RECORDED_TARGET_STATE}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all netfilter compat-path arguments must be supplied together")
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
