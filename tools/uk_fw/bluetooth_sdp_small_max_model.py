#!/usr/bin/env python3
"""Model exact-static Broadcom BSA SDP small-maximum write bounds.

This pure host model classifies only pre-established facts for two recovered
binaries. It performs no I/O beyond deterministic JSON output and emits no
operational message material.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 2
HANDLERS = ("service-attr", "service-search-attr")
REQUEST_STATES = ("initial", "continuation")
EFFECTIVE_SMALL_MAXIMA = (0, 1, 2, 3)
MINIMUM_SUCCESSFUL_GKI_USER_CAPACITY_BYTES = 0x40
PUBLIC_FIX_COMMIT = "f0edf6571d2d58e66ee0b100ebe49c585d31489f"
PUBLIC_FIX_PARENT = "ec16f7d8c7e359a68ffe6b76e88add2210bf2cbd"
PUBLIC_FIX_PATCH_SHA256 = (
    "a0470c20592473144f8114cf41ab4cb2479fe2c108a4aa73fa4864eabd02ca34"
)

BINARY_BINDINGS: dict[str, dict[str, Any]] = {
    "vbtd-51": {
        "installed_path": "/app/bin/vbtd-51",
        "sha256": "55e21d077082e97f56fb113a1d3b216c0f2e63aa02fc4cd754a6593bc6cec9e0",
        "build_id": "12175aa88ccff70cc56498e0208c9a51aac0c9e9",
        "bsa_version": "BSA0107_00.51.00",
        "elf_type": "ET_DYN",
        "address_basis": "PIE image virtual address before runtime relocation",
        "partial_attribute_helper_disassembly_sha256": (
            "a6299c8bf1761a5f4f706a635b292e4410356ebb295cd51b7c8a882efc84f235"
        ),
        "fde_ranges": {
            "service_search_attribute": "[0x841dc0,0x842628)",
            "service_attribute_dispatcher": "[0x842630,0x842e0b)",
            "gki_getbuf_r": "[0x7ad2e0,0x7ad690)",
            "gki_buffer_init": "[0x7ac590,0x7ad284)",
            "sdpu_build_partial_attrib_entry": "[0x8445f0,0x8448bf)",
        },
        "addresses": {
            "service_search_attribute_maximum_parse_and_cap": "0x841e60-0x841e9a",
            "service_search_attribute_scratch_request_and_call": "0x84254b/0x84255d",
            "service_search_attribute_initial_space_test": "0x841fcf-0x841fea",
            "service_search_attribute_state_gate": "0x8421a1",
            "service_search_attribute_response_copy_call": "0x84223c",
            "service_attribute_maximum_parse_and_cap": "0x8427ae-0x8427e8",
            "service_attribute_scratch_request_and_call": "0x842d32/0x842d43",
            "service_attribute_space_test": "0x842a04-0x842a1d",
            "service_attribute_state_gate": "0x842b01",
            "service_attribute_response_copy_call": "0x842b97",
            "partial_attribute_valid_state_clamp_copy_and_advance": "0x8446ec-0x84472a",
            "pool_capacity_selection_compare": "0x7ad32b",
            "pool_0_capacity_store": "0x7acbc4",
            "user_pointer_return": "0x7ad581",
        },
    },
    "vbtd-63": {
        "installed_path": "/app/bin/vbtd-63",
        "sha256": "c56b68fdd35b16b95688ab54a48ffb9f18034d925c057e86f8b9fe304f8b26b9",
        "build_id": "04141ed222ee8f150c0eb0e46fdb73624d168920",
        "bsa_version": "BSA0107_00.63.00",
        "elf_type": "ET_DYN",
        "address_basis": "PIE image virtual address before runtime relocation",
        "partial_attribute_helper_disassembly_sha256": (
            "206c2f60f1bd6c96642dda82eeca69a19ccb0a698adc806418fddb0ad533ce96"
        ),
        "fde_ranges": {
            "service_search_attribute": "[0x8425b0,0x842e00)",
            "service_attribute_dispatcher": "[0x842e00,0x8435c3)",
            "gki_getbuf": "[0x7af2f0,0x7af633)",
            "gki_buffer_init": "[0x7ae5a0,0x7af294)",
            "sdpu_build_partial_attrib_entry": "[0x844d90,0x84504f)",
        },
        "addresses": {
            "service_search_attribute_maximum_parse_and_cap": "0x842650-0x84268a",
            "service_search_attribute_scratch_request_and_call": "0x842d2b/0x842d31",
            "service_search_attribute_initial_space_test": "0x8427bf-0x8427da",
            "service_search_attribute_state_gate": "0x842991",
            "service_search_attribute_response_copy_call": "0x842a20",
            "service_attribute_maximum_parse_and_cap": "0x842f7e-0x842fb8",
            "service_attribute_scratch_request_and_call": "0x8434f6/0x8434fb",
            "service_attribute_space_test": "0x8431d4-0x8431ed",
            "service_attribute_state_gate": "0x8432d1",
            "service_attribute_response_copy_call": "0x84335b",
            "partial_attribute_valid_state_clamp_copy_and_advance": "0x844e84-0x844eb6",
            "pool_capacity_selection_compare": "0x7af332",
            "pool_0_capacity_store": "0x7aebd4",
            "user_pointer_return": "0x7af56b",
        },
    },
}


class ModelError(ValueError):
    """Raised when an input falls outside the finite model domain."""


def classify_small_maximum(
    handler: str, request_state: str, effective_max_list_len: int
) -> dict[str, Any]:
    """Classify one conditional handler/state/effective-maximum tuple."""
    if isinstance(handler, bool) or not isinstance(handler, str):
        raise ModelError("handler must be a string")
    if handler not in HANDLERS:
        raise ModelError(f"handler must be one of {HANDLERS}")
    if isinstance(request_state, bool) or not isinstance(request_state, str):
        raise ModelError("request_state must be a string")
    if request_state not in REQUEST_STATES:
        raise ModelError(f"request_state must be one of {REQUEST_STATES}")
    if isinstance(effective_max_list_len, bool) or not isinstance(
        effective_max_list_len, int
    ):
        raise ModelError(
            "effective_max_list_len must be an integer, not a boolean"
        )
    if effective_max_list_len not in EFFECTIVE_SMALL_MAXIMA:
        raise ModelError(
            "effective_max_list_len must be one of "
            f"{EFFECTIVE_SMALL_MAXIMA}"
        )

    initial = request_state == "initial"
    write_extent = 3 if initial else effective_max_list_len
    highest_offset = 2 if initial else (
        effective_max_list_len - 1 if effective_max_list_len else None
    )
    logical_exceedance = initial and effective_max_list_len < 3
    physical_exceedance = (
        highest_offset is not None
        and highest_offset >= MINIMUM_SUCCESSFUL_GKI_USER_CAPACITY_BYTES
    )

    return {
        "input": {
            "handler": handler,
            "request_state": request_state,
            "effective_internal_max_list_len": effective_max_list_len,
        },
        "classification_path": "feasible_ordinary_response_list_construction",
        "classification_is_conditional_on_path_prerequisites": True,
        "syntactically_valid_handler_input_required": True,
        "ordinary_response_list_construction_reached_required": True,
        "scratch_allocation_or_reuse_success_required": True,
        "valid_internal_continuation_state_required": not initial,
        "early_error_exits_classified_by_write_matrix": False,
        "path_prerequisites_observed_by_model": None,
        "matrix_quantity_is_effective_internal_maximum_after_cap": True,
        "peer_requested_max_list_len": None,
        "ordinary_protocol_valid_remote_mtu_required_for_peer_equivalence": True,
        "ordinary_protocol_valid_remote_mtu_observed": None,
        "small_peer_maximum_maps_to_effective_maximum_under_precondition": True,
        "low_or_invalid_remote_mtu_cap_behavior_classified": False,
        "source_like_less_than_four_guard_present": False,
        "scratch_allocation_operand": "remote_mtu",
        "scratch_allocation_uses_effective_internal_maximum": False,
        "scratch_allocation_failure_allows_scratch_writes": False,
        "minimum_successful_gki_user_capacity_bytes": (
            MINIMUM_SUCCESSFUL_GKI_USER_CAPACITY_BYTES
        ),
        "partial_attribute_helper_complete_ranges_bound": True,
        "partial_attribute_helper_valid_state_copy_length_clamped_to_remaining": True,
        "partial_attribute_helper_valid_state_destination_advance_clamped_to_remaining": True,
        "valid_internal_attr_offset_required_for_partial_helper_bound": not initial,
        "corrupted_or_impossible_internal_attr_offset_safety_established": None,
        "partial_attribute_helper_general_memory_safety_established": None,
        "initial_header_maximum_written_offset_on_feasible_path": (
            2 if initial else None
        ),
        "initial_header_write_extent_on_feasible_path_bytes": (
            3 if initial else 0
        ),
        "continuation_write_extent_upper_bound_on_feasible_path_bytes": (
            0 if initial else effective_max_list_len
        ),
        "scratch_write_extent_upper_bound_on_feasible_path_bytes": write_extent,
        "highest_scratch_offset_upper_bound_on_feasible_path": highest_offset,
        "response_copy_length_upper_bound_on_feasible_path_bytes": write_extent,
        "logical_effective_limit_exceedance_on_feasible_path": logical_exceedance,
        "successful_gki_scratch_capacity_exceeded_on_feasible_path": (
            physical_exceedance
        ),
        "public_small_maximum_physical_oob_write_mechanism_rejected_on_stated_preconditions": (
            not physical_exceedance
        ),
        "general_sdp_memory_safety_established": False,
        "other_sdp_handler_safety_established": None,
        "negotiated_mtu_edge_case_safety_established": None,
        "allocator_corruption_absence_established": None,
        "vendor_equivalent_unnamed_path_absence_established": None,
        "runtime_handler_reachability_observed": None,
        "runtime_adapter_policy_observed": None,
        "runtime_channel_security_observed": None,
        "owner_device_applicability_established": None,
        "memory_corruption_observed": None,
        "code_execution_observed": None,
        "unrestricted_root_observed": None,
        "persistence_observed": None,
    }


def build_report(
    selection: tuple[str, str, int] | None = None,
) -> dict[str, Any]:
    """Build the deterministic bound report, optionally with one selection."""
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "broadcom-bsa-sdp-small-maximum-exact-static",
        "evidence_binding": {
            "binaries": BINARY_BINDINGS,
            "public_fix": {
                "commit": PUBLIC_FIX_COMMIT,
                "parent": PUBLIC_FIX_PARENT,
                "patch_sha256": PUBLIC_FIX_PATCH_SHA256,
                "android_bug_by_handler": {
                    "service-attr": "68776054",
                    "service-search-attr": "68817966",
                },
                "added_check": "max_list_len < 4",
            },
            "gki_minimum_successful_user_capacity_bytes": (
                MINIMUM_SUCCESSFUL_GKI_USER_CAPACITY_BYTES
            ),
            "assessment": "evidence/broadcom-bsa-sdp-small-max-cves.md",
            "static_excerpt": (
                "evidence/artifacts/network-candidates/"
                "broadcom-bsa-sdp-small-max-exact-static.txt"
            ),
            "retained_public_patch": (
                "evidence/artifacts/network-candidates/"
                "f0edf6571d2d58e66ee0b100ebe49c585d31489f.patch"
            ),
        },
        "claim_boundary": {
            "establishes": [
                "conditional finite exact-static write bounds for both named handlers",
                "separate initial and continuation classifications for effective internal maxima zero through three",
                "valid-state partial-helper copy and destination-advance clamps",
                "rejection only of the public small-maximum physical out-of-bounds-write mechanism on the stated feasible path",
                "logical effective-limit exceedance on the feasible initial path below three",
            ],
            "does_not_establish": [
                "automatic verification of the bound static evidence",
                "coverage of syntactic, allocation, reuse, or continuation-state error exits by the write matrix",
                "small peer-request equivalence without an ordinary protocol-valid remote MTU",
                "corrupted or impossible internal attribute-offset safety",
                "general partial-helper, SDP, or other-handler memory safety",
                "negotiated-MTU edge-case safety or allocator-corruption absence",
                "absence of every vendor-equivalent unnamed path",
                "installed runtime identity, reachability, adapter policy, or channel security",
                "owner-device applicability or any dynamic impact outcome",
            ],
            "pure_deterministic_model": True,
            "emits_only_non_operational_classification_metadata": True,
            "controlled_execution_performed": False,
        },
        "bounded_matrix": [
            classify_small_maximum(handler, state, maximum)
            for handler in HANDLERS
            for state in REQUEST_STATES
            for maximum in EFFECTIVE_SMALL_MAXIMA
        ],
    }
    if selection is not None:
        report["classification"] = classify_small_maximum(*selection)
    return report


class _Once(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--handler", action=_Once)
    parser.add_argument("--request-state", action=_Once)
    parser.add_argument("--effective-max-list-len", type=int, action=_Once)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    values = (args.handler, args.request_state, args.effective_max_list_len)
    supplied = tuple(value is not None for value in values)
    if any(supplied) and not all(supplied):
        raise SystemExit(
            "error: handler, request-state, and effective-max-list-len "
            "must be supplied together"
        )
    try:
        selection = values if all(supplied) else None
        report = build_report(selection)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    sys.stdout.buffer.write(
        json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
