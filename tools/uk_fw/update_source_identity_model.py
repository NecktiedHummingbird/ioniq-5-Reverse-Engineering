#!/usr/bin/env python3
"""Classify bounded path-reopen and object-identity facts in an updater.

This Boolean-only host model does not read update media, open a target path,
create an archive, construct a command, execute recovered code, send a launch
request, write a partition, or emit firmware/update material. It distinguishes
a static pathname-reopen boundary from runtime source mutability and from any
later update, boot, privilege, or persistence result.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
APPDMCLIENT_SHA256 = "9a1fb796d7ac24fcce71c16e3dbee9306c888f43e705ee081f41b7d473978bd0"
APPDMCLIENT_BUILD_ID = "b2dbcc5231f444d8f1dd68eb7a2376323ce805df"

PRE_RECORDED_TARGET_STATE = {
    "verification_receives_pathname": True,
    "verifier_returns_status_only": True,
    "verification_finishes_before_later_consumer": True,
    "later_consumer_reopens_by_pathname": True,
    "consumer_uses_verifier_open_description": False,
    "consumed_open_object_identity_revalidated": False,
    "runtime_name_mapping_mutability_established": False,
    "runtime_content_mutability_established": False,
    "runtime_source_immutability_established": False,
    "post_stage_authenticated_content_binding_established": False,
    "staged_path_reaches_launch_attempt": True,
}


class ModelError(ValueError):
    pass


def classify_source_identity(**values: bool) -> dict[str, Any]:
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

    runtime_mutability = (
        state["runtime_name_mapping_mutability_established"]
        or state["runtime_content_mutability_established"]
    )
    if runtime_mutability and state["runtime_source_immutability_established"]:
        raise ModelError("runtime source cannot be both mutable and immutable")

    if (
        state["later_consumer_reopens_by_pathname"]
        and state["consumer_uses_verifier_open_description"]
    ):
        raise ModelError(
            "security-relevant consumer cannot both reopen by pathname and use the verifier open description"
        )

    continuity_mechanism = (
        state["consumer_uses_verifier_open_description"]
        or state["consumed_open_object_identity_revalidated"]
    )
    complete_path_reopen_facts = all(
        state[name]
        for name in (
            "verification_receives_pathname",
            "verifier_returns_status_only",
            "verification_finishes_before_later_consumer",
            "later_consumer_reopens_by_pathname",
        )
    )
    later_consumer_present = (
        state["later_consumer_reopens_by_pathname"]
        or state["consumer_uses_verifier_open_description"]
        or state["consumed_open_object_identity_revalidated"]
    )
    complete_verification_consumer_sequence_facts = (
        state["verification_receives_pathname"]
        and state["verifier_returns_status_only"]
        and state["verification_finishes_before_later_consumer"]
        and later_consumer_present
    )

    if continuity_mechanism:
        lacks_identity_binding: bool | None = False
    elif complete_path_reopen_facts:
        lacks_identity_binding = True
    else:
        lacks_identity_binding = None

    if continuity_mechanism or state["runtime_source_immutability_established"]:
        name_mapping_substitution_feasible: bool | None = False
    elif (
        lacks_identity_binding is True
        and state["runtime_name_mapping_mutability_established"]
    ):
        name_mapping_substitution_feasible = True
    else:
        name_mapping_substitution_feasible = None

    if state["runtime_source_immutability_established"]:
        content_change_feasible: bool | None = False
    elif state["runtime_content_mutability_established"]:
        content_change_feasible = True
    else:
        content_change_feasible = None

    if (
        state["runtime_source_immutability_established"]
        or state["post_stage_authenticated_content_binding_established"]
    ):
        authenticated_content_divergence_feasible: bool | None = False
    elif (
        name_mapping_substitution_feasible is True
        or (
            complete_verification_consumer_sequence_facts
            and content_change_feasible is True
        )
    ):
        authenticated_content_divergence_feasible = True
    else:
        authenticated_content_divergence_feasible = None

    if (
        lacks_identity_binding is False
        or not state["staged_path_reaches_launch_attempt"]
        or state["post_stage_authenticated_content_binding_established"]
    ):
        conditional_unverified_launch: bool | None = False
    elif lacks_identity_binding is True:
        conditional_unverified_launch = True
    else:
        conditional_unverified_launch = None

    if (
        state["runtime_source_immutability_established"]
        or not state["staged_path_reaches_launch_attempt"]
        or state["post_stage_authenticated_content_binding_established"]
    ):
        unverified_launch_feasible: bool | None = False
    elif authenticated_content_divergence_feasible is True:
        unverified_launch_feasible = True
    else:
        unverified_launch_feasible = None

    return {
        "input": state,
        "complete_path_reopen_facts": complete_path_reopen_facts,
        "complete_verification_consumer_sequence_facts": (
            complete_verification_consumer_sequence_facts
        ),
        "identity_continuity_mechanism_present": continuity_mechanism,
        "reviewed_code_lacks_verified_object_identity_binding": lacks_identity_binding,
        "runtime_name_mapping_substitution_feasible": (
            name_mapping_substitution_feasible
        ),
        "runtime_content_change_feasible": content_change_feasible,
        "runtime_authenticated_content_divergence_feasible": (
            authenticated_content_divergence_feasible
        ),
        "conditional_identity_gap_launch_structure_present": (
            conditional_unverified_launch
        ),
        "runtime_unverified_staged_launch_feasible": unverified_launch_feasible,
        "verified_and_consumed_objects_observed_different": None,
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
        "model": "update-source-object-identity-boundary",
        "evidence_binding": {
            "appdmclient_sha256": APPDMCLIENT_SHA256,
            "appdmclient_build_id": APPDMCLIENT_BUILD_ID,
            "virtual_addresses": {
                "verifier_wrapper_fde": "0x34870..0x34d43",
                "staging_fde": "0x7ff60..0x830e4",
                "initial_verifier_calls": "0x802db,0x80320",
                "later_path_copy_call": "0x8296b",
                "xml_reader_fde": "0xe1e90..0xe3166",
                "xml_reader_verifier_call": "0xe1ff7",
                "xml_reader_later_direct_open": "0xe22d5",
                "xml_reader_later_temporary_open": "0xe281f",
            },
            "pre_recorded_target_state": {
                "source": "separate instruction-level review; not verified by this model execution",
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/appdmclient-source-identity-boundary.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied pathname verification, later pathname reopen, and identity-binding facts",
                "whether the supplied code facts form a conditional object-substitution boundary",
                "unknown runtime feasibility when neither source mutability nor immutability is established",
            ],
            "does_not_establish": [
                "automatic instruction verification or installed-device identity",
                "runtime source mutability, a changed object, successful staging, or successful process creation",
                "authentication bypass, update acceptance, partition writes, slot selection, boot acceptance, root, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_firmware_update_archive_command_path_payload_launch_message_or_race_schedule": True,
        },
        "pre_recorded_target_classification": classify_source_identity(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_source_identity(**state)
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
        raise SystemExit(
            "error: all update source-identity arguments must be supplied together"
        )
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
