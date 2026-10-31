#!/usr/bin/env python3
"""Classify bounded AppLauncher on-demand launch premises.

Inputs are booleans only. This model does not connect to D-Bus, create or write an
executable, invoke a launcher method, start a process, change credentials or
labels, or emit a command, message, target path, payload, or firmware bytes.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
APPLAUNCHER_SHA256 = "c8d6d56bc254ad0731e81f40bd83aa9b3be6b49bcbd8efb291157a06c4a84268"
APPLAUNCHER_BUILD_ID = "0452df1033bd1bbae15727a83d4d56576d8b9444"

STATIC_TARGET_FACTS = {
    "request_object_registration_attempted": True,
    "launch_method_forwards_caller_path": True,
    "existing_process_path_is_overwritten": True,
    "new_app_process_object_helper_requires_appid_range_and_existing_path": True,
    "dispatcher_sets_direct_launch_flag": True,
    "direct_flag_bypasses_both_identified_verifier_calls": True,
    "verified_path_failure_is_terminal": True,
    "service_has_configured_uid_zero_default": True,
    "session_bus_policy_allows_authenticated_method_calls": True,
    "session_bus_default_connection_rule_is_same_uid": True,
}

RUNTIME_OPTIONS = (
    "service_name_owned",
    "request_object_registered",
    "caller_same_bus_uid",
    "bus_connection_authenticated",
    "bus_policy_allows_method",
    "smack_allows_bus_access",
    "existing_process_found_for_appid",
    "appid_in_create_range",
    "target_exists_for_create",
    "new_app_process_object_constructed",
    "direct_launch_flag_set",
    "identified_qprocess_start_site_reached",
    "qprocess_accepts_start",
    "target_is_executable_at_exec",
    "launcher_can_execute_target_at_exec",
    "caller_controls_target_at_exec",
    "launcher_effectively_privileged_at_exec",
)


class ModelError(ValueError):
    """Raised when supplied state is outside this Boolean-only model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_launch_route(**values: bool) -> dict[str, Any]:
    if set(values) != set(RUNTIME_OPTIONS):
        missing = sorted(set(RUNTIME_OPTIONS) - set(values))
        extra = sorted(set(values) - set(RUNTIME_OPTIONS))
        raise ModelError(f"runtime state keys mismatch: missing={missing}, extra={extra}")
    state = {name: _boolean(name, values[name]) for name in RUNTIME_OPTIONS}

    request_delivered = all(
        state[name]
        for name in (
            "service_name_owned",
            "request_object_registered",
            "caller_same_bus_uid",
            "bus_connection_authenticated",
            "bus_policy_allows_method",
            "smack_allows_bus_access",
        )
    )
    new_object_creation_route_eligible = (
        not state["existing_process_found_for_appid"]
        and state["appid_in_create_range"]
        and state["target_exists_for_create"]
    )
    new_app_process_object_available = (
        new_object_creation_route_eligible
        and state["new_app_process_object_constructed"]
    )
    app_process_object_available = (
        state["existing_process_found_for_appid"]
        or new_app_process_object_available
    )
    dispatcher_reached = request_delivered and app_process_object_available
    direct_route_selected = dispatcher_reached and state["direct_launch_flag_set"]
    qprocess_start_attempted = (
        direct_route_selected and state["identified_qprocess_start_site_reached"]
    )
    exec_preconditions = (
        qprocess_start_attempted
        and state["qprocess_accepts_start"]
        and state["target_is_executable_at_exec"]
        and state["launcher_can_execute_target_at_exec"]
    )
    controlled_privileged_exec_candidate = (
        exec_preconditions
        and state["caller_controls_target_at_exec"]
        and state["launcher_effectively_privileged_at_exec"]
    )

    return {
        "input": state,
        "request_delivered": request_delivered,
        "new_object_creation_route_eligible": new_object_creation_route_eligible,
        "new_app_process_object_available": new_app_process_object_available,
        "app_process_object_available": app_process_object_available,
        "dispatcher_reached": dispatcher_reached,
        "caller_path_installed": dispatcher_reached,
        "direct_route_selected": direct_route_selected,
        "identified_verifier_called_on_direct_route": False if direct_route_selected else None,
        "qprocess_start_attempted": qprocess_start_attempted,
        "exec_preconditions_supplied": exec_preconditions,
        "controlled_privileged_exec_candidate": controlled_privileged_exec_candidate,
        "runtime_request_observed": None,
        "runtime_exec_observed": None,
        "credential_or_smack_transition_observed": None,
        "update_trust_anchor_write_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "applauncher-dbus-on-demand-launch",
        "evidence_binding": {
            "applauncher_sha256": APPLAUNCHER_SHA256,
            "applauncher_build_id": APPLAUNCHER_BUILD_ID,
            "static_target_facts": {
                "source": "separate instruction-level and configuration review; not verified by this model execution",
                **STATIC_TARGET_FACTS,
            },
            "assessment": "evidence/applauncher-dbus-launch-bypass.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied Boolean delivery, direct-route, start-attempt, and execution preconditions",
                "the distinct relevant-existing-object and new-object construction branches",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions or configuration",
                "runtime service ownership, Request-object registration, caller uid, bus authentication, SMACK access, AppProcess-object construction, QProcess state, or executable control at exec time",
                "that the two identified verifier calls are the platform's only possible executable-enforcement mechanisms",
                "a delivered request, successful exec, credential or label transition, root, trust-anchor write, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_command_message_target_path_payload_or_firmware_bytes": True,
        },
    }
    if state is not None:
        report["classification"] = classify_launch_route(**state)
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
    for option in RUNTIME_OPTIONS:
        parser.add_argument(
            f"--{option.replace('_', '-')}",
            dest=option,
            type=_cli_boolean,
            action=_SingleBooleanAction,
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {name: getattr(args, name) for name in RUNTIME_OPTIONS}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all AppLauncher runtime state arguments must be supplied together")
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
