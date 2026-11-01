#!/usr/bin/env python3
"""Classify bounded AppFUMO shell-boundary facts without emitting commands.

The model accepts Boolean evidence facts only. False means "not established",
not that the corresponding runtime condition is disproved. It does not read an
update, pathname, archive, command, or target artifact and does not execute any
recovered code.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
EXACT_ELF_SHA256 = "464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7"
EXACT_ELF_BUILD_ID = "863a8730e66a1c5245a1bf458fe2554adee0351a"
STATIC_ARTIFACT_SHA256 = "a6bbe8e74630e7a64001a8bad2b5f67846f465473612a14e8bccf3aad47c5510"

SINK_STRUCTURE_FACTS = (
    "exact_elf_identity_bound",
    "decryption_fde_bound",
    "command_substitutions_bound",
    "encfile_inserted_without_quoting_or_escaping",
    "destpath_inserted_without_quoting_or_escaping",
    "direct_helper_call_bound",
    "helper_fde_bound",
    "popen_shell_contract_bound",
)
STATIC_OUTCOME_FACTS = (
    "pclose_status_ignored",
    "post_sink_return_independent_of_helper_status",
)
STATIC_FACTS = SINK_STRUCTURE_FACTS + STATIC_OUTCOME_FACTS
RUNTIME_FACTS = (
    "pathname_influence_established",
    "shell_sensitive_character_survival_established",
    "invocation_reachability_established",
    "authentication_acceptance_established",
    "process_security_context_established",
    "command_success_observed",
    "privilege_or_domain_amplification_observed",
    "root_impact_observed",
    "persistence_observed",
)
FACTS = STATIC_FACTS + RUNTIME_FACTS
PRE_RECORDED_STATE = {
    **{name: True for name in STATIC_FACTS},
    **{name: False for name in RUNTIME_FACTS},
}


class ModelError(ValueError):
    """Raised when input is outside the strict Boolean evidence schema."""


def _established(value: bool) -> bool | None:
    return True if value else None


def classify_shell_boundary(**values: bool) -> dict[str, Any]:
    expected = set(FACTS)
    supplied = set(values)
    if supplied != expected:
        raise ModelError(
            f"state keys mismatch: missing={sorted(expected - supplied)}, "
            f"extra={sorted(supplied - expected)}"
        )

    state: dict[str, bool] = {}
    for name in FACTS:
        value = values[name]
        if not isinstance(value, bool):
            raise ModelError(f"{name} must be a boolean")
        state[name] = value

    contradictions = []
    if (
        state["shell_sensitive_character_survival_established"]
        and not state["pathname_influence_established"]
    ):
        contradictions.append(
            "shell-sensitive character survival requires pathname influence"
        )
    if (
        state["command_success_observed"]
        and not state["invocation_reachability_established"]
    ):
        contradictions.append("command success requires invocation reachability")
    if (
        state["privilege_or_domain_amplification_observed"]
        and not state["command_success_observed"]
    ):
        contradictions.append("amplification requires command success")
    if (
        state["root_impact_observed"]
        and not state["privilege_or_domain_amplification_observed"]
    ):
        contradictions.append("root impact requires privilege or domain amplification")
    if contradictions:
        raise ModelError("contradictory state: " + "; ".join(contradictions))

    sink_structure_complete = all(state[name] for name in SINK_STRUCTURE_FACTS)
    static_complete = all(state[name] for name in STATIC_FACTS)
    runtime_shell_syntax_delivery = sink_structure_complete and all(
        state[name]
        for name in (
            "pathname_influence_established",
            "shell_sensitive_character_survival_established",
            "invocation_reachability_established",
        )
    )
    runtime_command_success = (
        runtime_shell_syntax_delivery and state["command_success_observed"]
    )

    return {
        "input": state,
        "exact_static_fact_set_complete": static_complete,
        "exact_unquoted_shell_sink_structure_established": (
            True if sink_structure_complete else None
        ),
        "runtime_shell_syntax_delivery_established": (
            True if runtime_shell_syntax_delivery else None
        ),
        "runtime_command_success_established": (
            True if runtime_command_success else None
        ),
        "pathname_influence_established": _established(
            state["pathname_influence_established"]
        ),
        "shell_sensitive_character_survival_established": _established(
            state["shell_sensitive_character_survival_established"]
        ),
        "invocation_reachability_established": _established(
            state["invocation_reachability_established"]
        ),
        "authentication_acceptance_established": _established(
            state["authentication_acceptance_established"]
        ),
        "process_security_context_established": _established(
            state["process_security_context_established"]
        ),
        "command_success_observed": _established(state["command_success_observed"]),
        "privilege_or_domain_amplification_observed": _established(
            state["privilege_or_domain_amplification_observed"]
        ),
        "root_impact_observed": _established(state["root_impact_observed"]),
        "persistence_observed": _established(state["persistence_observed"]),
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "appfumo-exact-shell-boundary",
        "evidence_binding": {
            "exact_elf_sha256": EXACT_ELF_SHA256,
            "exact_elf_build_id": EXACT_ELF_BUILD_ID,
            "retained_static_artifact_sha256": STATIC_ARTIFACT_SHA256,
            "virtual_addresses": {
                "decryption_fde": "0x100b30..0x10110c",
                "direct_helper_call": "0x100e0c->0x1397c0",
                "helper_fde": "0x1397c0..0x1398fb",
                "shell_library_call": "0x139867",
                "mode_pointer": "0x211c8b",
                "distinct_neighbor_fde": "0x139900..0x139b46",
                "direct_producer_calls": "0x10281c,0x102de9,0x103398",
                "separate_generated_meta_call": "0x16e030",
            },
            "assessment": "evidence/appfumo-shell-command-boundary.md",
            "pre_recorded_state_source": (
                "separate exact-static review; not verified by model execution"
            ),
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied exact-static shell-boundary facts",
                "separation of static structure from runtime and impact prerequisites",
            ],
            "does_not_establish": [
                "automatic instruction verification or installed-device identity",
                "pathname control or shell-sensitive-character survival",
                "invocation reachability, authentication acceptance, or process security context",
                "command success, privilege or domain amplification, root impact, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "causally_contradictory_inputs_are_rejected": True,
            "false_input_means_not_established_not_disproved": True,
            "emits_no_command_target_pathname_payload_trigger_archive_or_update_material": True,
        },
        "pre_recorded_target_classification": classify_shell_boundary(
            **PRE_RECORDED_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_shell_boundary(**state)
    return report


def _boolean(value: str) -> bool:
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
    for name in FACTS:
        parser.add_argument(
            f"--{name.replace('_', '-')}", dest=name, type=_boolean, action=_Once
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {name: getattr(args, name) for name in FACTS}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("all AppFUMO shell-boundary arguments are required")
    report = build_report(state if all(supplied) else None)
    payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
