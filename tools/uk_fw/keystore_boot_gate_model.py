#!/usr/bin/env python3
"""Classify bounded keystore secure-boot-gate and verifier-chain facts.

Inputs are booleans only. This model does not inspect a kernel, construct a
manifest, access physical memory, invoke a verifier, alter a command line, boot
a target, or emit a key, signature, command, payload, or firmware bytes.
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
    "secure_boot_ignore_config_enabled": True,
    "not_checking_status_branch_compiled": True,
    "hardware_status_check_before_seed_fill_present": False,
    "seed_fill_failure_still_fatal_to_keystore_init": True,
    "registration_secure_boot_status_check_present": False,
    "registration_continues_to_client_derivation": True,
    "manifest_init_is_separate_initcall": True,
    "manifest_allocation_pointer_shifted_before_header_validation": True,
    "manifest_header_rejection_frees_shifted_pointer": True,
    "verify_oem_signature_hashes_input": True,
    "verify_oem_signature_calls_manifest_key_verifier": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this Boolean-only model."""


def classify_boot_gate(**values: bool) -> dict[str, Any]:
    if set(values) != set(PRE_RECORDED_TARGET_STATE):
        missing = sorted(set(PRE_RECORDED_TARGET_STATE) - set(values))
        extra = sorted(set(values) - set(PRE_RECORDED_TARGET_STATE))
        raise ModelError(f"state keys mismatch: missing={missing}, extra={extra}")
    state: dict[str, bool] = {}
    for name in PRE_RECORDED_TARGET_STATE:
        value = values[name]
        if not isinstance(value, bool):
            raise ModelError(f"{name} must be a boolean")
        state[name] = value

    status_prerequisite_skipped = (
        state["secure_boot_ignore_config_enabled"]
        and state["not_checking_status_branch_compiled"]
        and not state["hardware_status_check_before_seed_fill_present"]
    )
    registration_status_prerequisite_skipped = (
        state["secure_boot_ignore_config_enabled"]
        and not state["registration_secure_boot_status_check_present"]
        and state["registration_continues_to_client_derivation"]
    )
    verifier_chain_present = (
        state["verify_oem_signature_hashes_input"]
        and state["verify_oem_signature_calls_manifest_key_verifier"]
    )
    general_signature_bypass_rejected = (
        status_prerequisite_skipped
        and state["seed_fill_failure_still_fatal_to_keystore_init"]
        and state["manifest_init_is_separate_initcall"]
        and verifier_chain_present
    )
    manifest_interior_pointer_free_candidate = (
        state["manifest_allocation_pointer_shifted_before_header_validation"]
        and state["manifest_header_rejection_frees_shifted_pointer"]
    )

    return {
        "input": state,
        "keystore_hardware_secure_boot_status_prerequisite_skipped": (
            status_prerequisite_skipped
        ),
        "keystore_registration_secure_boot_status_prerequisite_skipped": (
            registration_status_prerequisite_skipped
        ),
        "oem_signature_verifier_chain_present": verifier_chain_present,
        "secure_boot_ignore_as_general_signature_bypass_rejected_by_supplied_facts": (
            general_signature_bypass_rejected
        ),
        "manifest_interior_pointer_free_candidate": (
            manifest_interior_pointer_free_candidate
        ),
        "keystore_runtime_initialization_observed": None,
        "manifest_runtime_initialization_observed": None,
        "signature_acceptance_observed": None,
        "manifest_invalid_free_observed": None,
        "kernel_memory_corruption_observed": None,
        "update_acceptance_observed": None,
        "boot_acceptance_observed": None,
        "privilege_escalation_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "keystore-secure-boot-status-gate",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "kernel_config": "CONFIG_KEYSTORE_SECURE_BOOT_IGNORE=y",
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/eu-keystore-secure-boot-ignore.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied keystore-init and registration status-gate facts",
                "whether the independently reviewed OEM signature-verifier chain remains supplied",
                "whether a header-rejection path supplies an interior-pointer free candidate",
                "whether treating the IGNORE option as a general signature bypass is rejected by all supplied facts",
            ],
            "does_not_establish": [
                "automatic extraction or verification of kernel instructions",
                "runtime keystore or manifest initialization, invalid free, or kernel memory corruption",
                "control of a boot command line, physical memory, manifest, key, or trust anchor",
                "signature, update, image, slot, or boot acceptance",
                "code execution, privilege gain, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_manifest_physical_address_key_signature_command_payload_or_firmware_bytes": True,
        },
        "pre_recorded_target_classification": classify_boot_gate(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_boot_gate(**state)
    return report


def _cli_boolean(value: str) -> bool:
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _SingleBooleanAction(argparse.Action):
    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: bool, option_string: str | None = None) -> None:
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for option in PRE_RECORDED_TARGET_STATE:
        parser.add_argument(
            f"--{option.replace('_', '-')}", dest=option, type=_cli_boolean,
            action=_SingleBooleanAction,
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {name: getattr(args, name) for name in PRE_RECORDED_TARGET_STATE}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all keystore gate state arguments must be supplied together")
    try:
        report = build_report(state if all(supplied) else None)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    sys.stdout.buffer.write(json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
