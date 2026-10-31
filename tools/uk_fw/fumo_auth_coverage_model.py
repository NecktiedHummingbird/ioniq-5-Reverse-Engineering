#!/usr/bin/env python3
"""Classify bounded inner-updater executable-authentication coverage facts.

This Boolean-only host model does not open update media or a target pathname,
construct a package or command, execute recovered code, send a launch request,
write a partition, or emit firmware/update material. It distinguishes reviewed
direct executable reauthentication from later descriptor/payload verification
and from any runtime update, boot, privilege, or persistence result.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
FUMO_SHA256 = "464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7"
FUMO_BUILD_ID = "863a8730e66a1c5245a1bf458fe2554adee0351a"
ASSEMBLY_SHA256 = "44d9192098bb6384a793ffe204727d0f7c409479caf2f46463793ba5c658f068"

PRE_RECORDED_TARGET_STATE = {
    "exact_fumo_identity_bound": True,
    "startup_executable_path_use_traced": True,
    "startup_path_reduced_to_base_directory": True,
    "direct_signature_verifier_calls_complete": True,
    "direct_signature_verifier_targets_classified": False,
    "running_executable_is_direct_signature_target": False,
    "direct_file_hash_calls_complete": True,
    "direct_file_hash_targets_classified": True,
    "running_executable_is_direct_file_hash_target": False,
    "relaunch_exec_target_traced": True,
    "relaunch_target_verified_before_exec": False,
    "payload_or_descriptor_verification_present": True,
    "indirect_or_external_executable_reauthentication_excluded": False,
}


class ModelError(ValueError):
    pass


def classify_auth_coverage(**values: bool) -> dict[str, Any]:
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

    if (
        state["startup_path_reduced_to_base_directory"]
        and not state["startup_executable_path_use_traced"]
    ):
        raise ModelError("base-directory derivation requires traced startup path use")
    if (
        state["direct_signature_verifier_targets_classified"]
        and not state["direct_signature_verifier_calls_complete"]
    ):
        raise ModelError(
            "complete direct signature-target classification requires complete call inventory"
        )
    if (
        state["direct_file_hash_targets_classified"]
        and not state["direct_file_hash_calls_complete"]
    ):
        raise ModelError(
            "complete direct file-hash target classification requires complete call inventory"
        )
    if (
        state["relaunch_target_verified_before_exec"]
        and not state["relaunch_exec_target_traced"]
    ):
        raise ModelError("pre-exec verification requires a traced relaunch target")

    complete_reviewed_direct_coverage = all(
        state[name]
        for name in (
            "exact_fumo_identity_bound",
            "startup_executable_path_use_traced",
            "startup_path_reduced_to_base_directory",
            "direct_signature_verifier_calls_complete",
            "direct_signature_verifier_targets_classified",
            "direct_file_hash_calls_complete",
            "direct_file_hash_targets_classified",
            "relaunch_exec_target_traced",
        )
    )

    positive_direct_path = any(
        state[name]
        for name in (
            "running_executable_is_direct_signature_target",
            "running_executable_is_direct_file_hash_target",
            "relaunch_target_verified_before_exec",
        )
    )
    if positive_direct_path:
        direct_reauthentication_found: bool | None = True
    elif complete_reviewed_direct_coverage:
        direct_reauthentication_found = False
    else:
        direct_reauthentication_found = None

    if direct_reauthentication_found is True:
        direct_reauthentication_absent: bool | None = False
    elif direct_reauthentication_found is False:
        direct_reauthentication_absent = True
    else:
        direct_reauthentication_absent = None

    if direct_reauthentication_found is True:
        direct_paths_close_outer_gap: bool | None = True
    elif direct_reauthentication_absent is True:
        direct_paths_close_outer_gap = False
    else:
        direct_paths_close_outer_gap = None

    if direct_reauthentication_found is True:
        all_reauthentication_absent: bool | None = False
    elif (
        direct_reauthentication_absent is True
        and state["indirect_or_external_executable_reauthentication_excluded"]
    ):
        all_reauthentication_absent = True
    else:
        all_reauthentication_absent = None

    payload_is_separate = (
        True
        if state["payload_or_descriptor_verification_present"]
        and direct_reauthentication_absent is True
        else None
    )

    return {
        "input": state,
        "complete_reviewed_direct_coverage": complete_reviewed_direct_coverage,
        "inner_reviewed_direct_executable_reauthentication_found": (
            direct_reauthentication_found
        ),
        "inner_reviewed_direct_executable_reauthentication_absent": (
            direct_reauthentication_absent
        ),
        "inner_reviewed_direct_paths_close_outer_executable_identity_gap": (
            direct_paths_close_outer_gap
        ),
        "all_inner_and_external_executable_reauthentication_absence_proven": (
            all_reauthentication_absent
        ),
        "later_payload_or_descriptor_verification_present": state[
            "payload_or_descriptor_verification_present"
        ],
        "later_payload_authentication_is_separate_from_outer_executable_authentication": (
            payload_is_separate
        ),
        "runtime_source_mutability_established": None,
        "verified_and_consumed_executables_observed_different": None,
        "successful_inner_process_creation_observed": None,
        "later_update_acceptance_observed": None,
        "partition_write_observed": None,
        "slot_switch_observed": None,
        "boot_acceptance_observed": None,
        "privilege_transition_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "fumo-executable-authentication-coverage",
        "evidence_binding": {
            "embedded_fumo_sha256": FUMO_SHA256,
            "embedded_fumo_build_id": FUMO_BUILD_ID,
            "retained_assembly_sha256": ASSEMBLY_SHA256,
            "virtual_addresses": {
                "startup_argument_derivation": "0x1259e3..0x125a4e",
                "base_directory_initializer_fde": "0x8dc60..0x8dd51",
                "file_verifier_fde": "0x45820..0x45d75",
                "direct_file_verifier_calls": (
                    "0x7be3a,0x80095,0x802f0,0x9d1d2,0x100bb0,0x140092"
                ),
                "file_hash_fde": "0x140f50..0x1413e4",
                "direct_file_hash_calls": "0x1432f6,0x15170c",
                "relaunch_exec_wrapper_fde": "0x6c9a0..0x6cab5",
                "exec_call": "0x6caa8",
            },
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/appfumo-authentication-coverage.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied direct verifier, file-hash, startup-path, and relaunch facts",
                "whether reviewed direct paths reauthenticate the updater executable",
                "separation of later descriptor or payload authentication from outer executable authentication",
            ],
            "does_not_establish": [
                "automatic instruction verification or installed-device identity",
                "absence of every indirect, external, loader, or boot-stage verification mechanism",
                "runtime source mutability, changed-object observation, successful process creation, or authentication bypass",
                "update acceptance, partition writes, slot selection, boot acceptance, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_firmware_update_archive_command_path_payload_launch_message_or_race_schedule": True,
        },
        "pre_recorded_target_classification": classify_auth_coverage(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_auth_coverage(**state)
    return report


def _bool(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
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
        raise SystemExit("all FUMO authentication-coverage arguments are required")
    report = build_report(state if all(supplied) else None)
    payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
