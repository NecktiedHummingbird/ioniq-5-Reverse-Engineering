#!/usr/bin/env python3
"""Classify bounded CVE-2017-16995 syscall-path applicability facts.

This Boolean-only host model performs no recovered-target execution or target
operation. It does not create verifier input or exercise a verifier. Ordinary
host validation remains outside those target claims.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
CONFIG_SHA256 = "987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56"
KALLSYMS_SHA256 = "2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f"
FIX_COMMIT = "95a762e2c8c942780948091f8f2a4f32fce1ac6f"
FIX_PATCH_SHA256 = "d09d5733423b14add9cb9d9a25487a088cba449d1ca5c614b55dad307f73f557"

PRE_RECORDED_TARGET_STATE = {
    "public_cve_uses_syscall_ebpf_verifier_path": True,
    "bpf_core_config_enabled": True,
    "bpf_syscall_config_enabled": False,
    "bpf_jit_config_enabled": False,
    "sys_bpf_is_enosys_stub": True,
    "native_syscall_slot_targets_enosys_stub": True,
    "functional_bpf_syscall_path_present": False,
    "alternate_ebpf_verifier_entry_path_present": False,
    "classic_bpf_compiled": True,
}


class ModelError(ValueError):
    pass


def classify_bpf_syscall_path(**values: bool) -> dict[str, Any]:
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

    functional_path = state["functional_bpf_syscall_path_present"]
    complete_absence = (
        state["public_cve_uses_syscall_ebpf_verifier_path"]
        and not state["bpf_syscall_config_enabled"]
        and state["sys_bpf_is_enosys_stub"]
        and state["native_syscall_slot_targets_enosys_stub"]
        and not functional_path
    )

    named_path: bool | None
    if functional_path:
        named_path = True
    elif complete_absence:
        named_path = False
    else:
        named_path = None

    alternate_path: bool | None = (
        True if state["alternate_ebpf_verifier_entry_path_present"] else None
    )
    any_bpf_presence = (
        state["classic_bpf_compiled"]
        or functional_path
        or state["alternate_ebpf_verifier_entry_path_present"]
    )

    return {
        "input": state,
        "complete_named_syscall_prerequisite_absence_present": complete_absence,
        "named_syscall_ebpf_verifier_path_available": named_path,
        "cve_2017_16995_rejected_for_named_syscall_path": complete_absence,
        "cve_2017_16995_not_rejected_for_named_syscall_path_by_complete_absence": not complete_absence,
        "alternate_ebpf_verifier_entry_path_presence": alternate_path,
        "bpf_core_config_enabled": state["bpf_core_config_enabled"],
        "bpf_jit_config_enabled": state["bpf_jit_config_enabled"],
        "classic_bpf_compiled": state["classic_bpf_compiled"],
        "general_bpf_absence_established": False if any_bpf_presence else None,
        "other_ebpf_entry_cve_applicability_established": None,
        "verifier_internals_audited": None,
        "installed_device_identity_observed": None,
        "runtime_dispatch_result_observed": None,
        "verifier_execution_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "root_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "bpf-syscall-path-applicability",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "configuration_sha256": CONFIG_SHA256,
            "authoritative_map_sha256": KALLSYMS_SHA256,
            "upstream_fix_commit": FIX_COMMIT,
            "upstream_fix_patch_sha256": FIX_PATCH_SHA256,
            "pre_recorded_target_state": {
                "source": "separate static configuration, symbol, dispatch, and machine-code review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-bpf-cve-2017-16995.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied facts for the named syscall-based eBPF verifier path",
                "unknown rather than present or absent when named-path absence facts are incomplete",
                "classic BPF presence as an explicit scope fact",
            ],
            "does_not_establish": [
                "automatic verification of configuration, symbols, dispatch, or machine code",
                "installed-device identity or runtime behavior",
                "absence of every alternate eBPF entry or safety of classic BPF",
                "verifier-internal correctness, impact, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_address_invocation_verifier_input_endpoint_command_trigger_target_bytes_race_or_payload": True,
        },
        "pre_recorded_target_classification": classify_bpf_syscall_path(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_bpf_syscall_path(**state)
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
        raise SystemExit("error: all BPF syscall-path arguments must be supplied together")
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
