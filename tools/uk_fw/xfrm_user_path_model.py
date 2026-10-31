#!/usr/bin/env python3
"""Classify bounded CVE-2017-7184 named-path applicability facts.

This Boolean-only host model consumes pre-established static facts. It performs
no recovered-target execution or dynamic target interaction.
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
STOCK_ROOTFS_ARCHIVE_SHA256 = (
    "423491fd8b86bd815d4e12f47054e08a589a5159f87213f08980fcc3a0e47c84"
)
INITIAL_FIX_COMMIT = "677e806da4d916052585301785d847c3b3e6186a"
INITIAL_FIX_PATCH_SHA256 = (
    "5d419e4862b608a9372f4c93bf27c9a3014fe6598d38f148fa8eeea71fab905e"
)
FOLLOWUP_FIX_COMMIT = "f843ee6dd019bcece3e74e76ad9df0155655d0df"
FOLLOWUP_FIX_PATCH_SHA256 = (
    "3e0699ff6c4811470a4007bdb7bff86a72b12ddad739d01a3cc135e3b17ccd75"
)

PRE_RECORDED_TARGET_STATE = {
    "public_cve_requires_named_xfrm_user_newae_path": True,
    "xfrm_core_config_enabled": True,
    "xfrm_core_functionality_present": True,
    "xfrm_user_config_enabled": False,
    "xfrm_user_translation_unit_built_in": False,
    "recovered_module_inventory_complete": True,
    "xfrm_user_module_shipped": False,
    "queried_named_path_symbols_present": False,
    "functional_named_xfrm_user_newae_path_present": False,
    "net_key_config_enabled": False,
}


class ModelError(ValueError):
    pass


def classify_xfrm_user_path(**values: bool) -> dict[str, Any]:
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

    functional_path = state["functional_named_xfrm_user_newae_path_present"]
    complete_absence = (
        state["public_cve_requires_named_xfrm_user_newae_path"]
        and not state["xfrm_user_config_enabled"]
        and not state["xfrm_user_translation_unit_built_in"]
        and state["recovered_module_inventory_complete"]
        and not state["xfrm_user_module_shipped"]
        and not state["queried_named_path_symbols_present"]
        and not functional_path
    )

    named_path: bool | None
    if functional_path:
        named_path = True
    elif complete_absence:
        named_path = False
    else:
        named_path = None

    translation_unit_present: bool | None
    if (
        state["xfrm_user_translation_unit_built_in"]
        or state["xfrm_user_module_shipped"]
        or functional_path
    ):
        translation_unit_present = True
    elif complete_absence:
        translation_unit_present = False
    else:
        translation_unit_present = None

    core_present = (
        state["xfrm_core_config_enabled"]
        or state["xfrm_core_functionality_present"]
    )

    return {
        "input": state,
        "complete_named_path_absence_present": complete_absence,
        "named_xfrm_user_newae_path_available": named_path,
        "named_xfrm_user_translation_unit_present": translation_unit_present,
        "cve_2017_7184_rejected_for_named_path": complete_absence,
        "cve_2017_7184_not_rejected_for_named_path_by_complete_absence": (
            not complete_absence
        ),
        "queried_named_path_symbol_inventory_has_presence": state[
            "queried_named_path_symbols_present"
        ],
        "xfrm_core_config_enabled": state["xfrm_core_config_enabled"],
        "xfrm_core_functionality_present": state[
            "xfrm_core_functionality_present"
        ],
        "general_xfrm_absence_established": False if core_present else None,
        "separate_net_key_interface_config_enabled": state[
            "net_key_config_enabled"
        ],
        "net_key_interface_is_named_xfrm_user_path": False,
        "unnamed_vendor_equivalent_path_presence": None,
        "upstream_fix_effects_in_recovered_package_established": None,
        "installed_runtime_identity_observed": None,
        "runtime_named_path_behavior_observed": None,
        "runtime_access_policy_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation_observed": None,
        "root_observed": None,
        "persistence_observed": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "xfrm-user-named-path-static-applicability",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "configuration_sha256": CONFIG_SHA256,
            "authoritative_map_sha256": KALLSYMS_SHA256,
            "canonical_stock_rootfs_archive_sha256": STOCK_ROOTFS_ARCHIVE_SHA256,
            "initial_fix_commit": INITIAL_FIX_COMMIT,
            "initial_fix_patch_sha256": INITIAL_FIX_PATCH_SHA256,
            "followup_fix_commit": FOLLOWUP_FIX_COMMIT,
            "followup_fix_patch_sha256": FOLLOWUP_FIX_PATCH_SHA256,
            "pre_recorded_target_state": {
                "source": (
                    "separate static configuration, symbol, canonical decrypted "
                    "stock archive member inventory, and source-contract review; "
                    "not verified by this model run"
                ),
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-xfrm-cve-2017-7184.md",
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied facts for one named upstream path",
                "unknown when named-path absence facts are incomplete",
                "continued core-subsystem presence as an explicit scope fact",
                "a separate legacy-interface fact without equivalence",
            ],
            "does_not_establish": [
                "automatic verification of the bound static evidence or "
                "archive members",
                "absence of every unnamed or vendor-equivalent route",
                "installed-environment identity or dynamic behavior",
                "correctness of unavailable code or any impact outcome",
            ],
            "inputs_are_boolean_only": True,
            "emits_only_non_operational_classification_metadata": True,
        },
        "pre_recorded_target_classification": classify_xfrm_user_path(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_xfrm_user_path(**state)
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
        raise SystemExit(
            "error: all XFRM-user named-path arguments must be supplied together"
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
