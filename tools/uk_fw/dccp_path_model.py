#!/usr/bin/env python3
"""Classify bounded CVE-2017-6074 DCCPv6-path applicability facts.

This Boolean-only host model consumes pre-established static facts. It performs
no target or named-target interaction and emits no operational material.
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
DCCP_KCONFIG_SHA256 = (
    "377e8d4e5dc101ea5a5d83b4c8c2ad64806c3c13f8947459b2e30755dd70949b"
)
NET_MAKEFILE_SHA256 = (
    "83765cc8e3ee9ea64c98b3987d6eb9b3311639c6393ec559bb694830b21080af"
)
DCCP_MAKEFILE_SHA256 = (
    "1eb466fb84ea75bcc7109ee8604166789a2e12a225f315f61eee4bdb5d05d042"
)
MAINLINE_FIX_COMMIT = "5edabca9d4cff7f1f2b68f0bac55ef99d9798ba4"
MAINLINE_FIX_PATCH_SHA256 = (
    "e5ac35f2d2b4129e3fca80a5b7d9200035bfd79f703b3045d7b28c9868179eb9"
)
STABLE_FIX_COMMIT = "98442999b9671784e659b205be8b5b6be8e81629"
STABLE_FIX_PATCH_SHA256 = (
    "116e4a0d21907c0271cd76e45c2fda40c9c349ef8d0cb59184aba23bcc573c9c"
)
CHANGELOG_4_1_41_SHA256 = (
    "4205336d83ed496dd809a692f5200a70c6e51007f5ca3ad60d9aed013ac471de"
)

PRE_RECORDED_TARGET_STATE = {
    "public_cve_requires_named_dccpv6_request_path": True,
    "public_v4_1_build_rules_applicable": True,
    "ip_dccp_config_enabled": False,
    "inet_config_enabled": True,
    "ipv6_config_enabled": True,
    "user_ns_config_enabled": False,
    "dccp_core_translation_units_built_in": False,
    "dccpv6_translation_unit_built_in": False,
    "recovered_module_inventory_complete": True,
    "dccp_core_named_modules_shipped": False,
    "dccpv6_named_module_shipped": False,
    "queried_named_core_symbols_present": False,
    "queried_named_dccpv6_symbols_present": False,
    "functional_ipv4_only_dccp_path_present": False,
    "functional_named_dccpv6_request_path_present": False,
}


class ModelError(ValueError):
    pass


def _presence(
    *, positive: bool, negative: bool
) -> tuple[bool | None, bool]:
    """Return positive-precedence presence and whether evidence conflicts."""
    if positive:
        return True, negative
    if negative:
        return False, False
    return None, False


def classify_dccp_path(**values: bool) -> dict[str, Any]:
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

    complete_functional_path = state[
        "functional_named_dccpv6_request_path_present"
    ]
    exact_default_subtree_exclusion = (
        state["public_v4_1_build_rules_applicable"]
        and not state["ip_dccp_config_enabled"]
    )

    # The second formally complete absence route combines a precise no-built-in
    # fact with a complete recovered-module inventory containing no named module.
    # Exact symbol or functional presence is positive evidence and takes
    # precedence over either negative route for the corresponding component.
    core_inventory_absence = (
        not state["dccp_core_translation_units_built_in"]
        and state["recovered_module_inventory_complete"]
        and not state["dccp_core_named_modules_shipped"]
    )
    dccpv6_inventory_absence = (
        not state["dccpv6_translation_unit_built_in"]
        and state["recovered_module_inventory_complete"]
        and not state["dccpv6_named_module_shipped"]
    )

    core_positive = (
        state["dccp_core_translation_units_built_in"]
        or state["dccp_core_named_modules_shipped"]
        or state["queried_named_core_symbols_present"]
        or state["functional_ipv4_only_dccp_path_present"]
        or complete_functional_path
    )
    dccpv6_positive = (
        state["dccpv6_translation_unit_built_in"]
        or state["dccpv6_named_module_shipped"]
        or state["queried_named_dccpv6_symbols_present"]
        or complete_functional_path
    )
    core_negative = exact_default_subtree_exclusion or core_inventory_absence
    dccpv6_negative = (
        exact_default_subtree_exclusion or dccpv6_inventory_absence
    )

    core_present, core_conflict = _presence(
        positive=core_positive, negative=core_negative
    )
    dccpv6_present, dccpv6_conflict = _presence(
        positive=dccpv6_positive, negative=dccpv6_negative
    )

    # CVE-2017-6074's named public request route needs both the DCCP core and
    # DCCPv6 translation unit. One conclusively absent component establishes
    # physical route absence. Positive complete-route evidence overrides every
    # absence inference. Component conflicts cannot themselves establish route
    # absence; another independently absent component still can.
    physical_path_absence = (
        not complete_functional_path
        and (core_present is False or dccpv6_present is False)
    )
    if complete_functional_path:
        named_path: bool | None = True
    elif physical_path_absence:
        named_path = False
    else:
        named_path = None

    dependency = state["public_cve_requires_named_dccpv6_request_path"]
    rejected = dependency and physical_path_absence

    return {
        "input": state,
        "public_cve_requires_named_dccpv6_request_path": dependency,
        "public_v4_1_build_rules_applicable": state[
            "public_v4_1_build_rules_applicable"
        ],
        "public_build_rules_ip_dccp_disabled_excludes_named_subtree": (
            exact_default_subtree_exclusion
        ),
        "dccp_core_physical_absence_established": core_present is False,
        "dccpv6_physical_absence_established": dccpv6_present is False,
        "physical_named_dccpv6_request_path_absence_established": (
            physical_path_absence
        ),
        "named_dccpv6_request_path_available": named_path,
        "dccp_core_translation_units_present": core_present,
        "dccpv6_translation_unit_present": dccpv6_present,
        "dccp_core_evidence_conflict": core_conflict,
        "dccpv6_evidence_conflict": dccpv6_conflict,
        "cve_2017_6074_dependency_satisfied": dependency,
        "cve_2017_6074_rejected_for_named_dccpv6_path": rejected,
        "cve_2017_6074_not_rejected_for_named_dccpv6_path_by_physical_absence": (
            not rejected
        ),
        "queried_named_core_symbol_inventory_has_presence": state[
            "queried_named_core_symbols_present"
        ],
        "queried_named_dccpv6_symbol_inventory_has_presence": state[
            "queried_named_dccpv6_symbols_present"
        ],
        "functional_ipv4_only_dccp_path_present": state[
            "functional_ipv4_only_dccp_path_present"
        ],
        "functional_named_dccpv6_request_path_present": complete_functional_path,
        "inet_config_enabled": state["inet_config_enabled"],
        "ipv6_config_enabled": state["ipv6_config_enabled"],
        "general_inet_absence_established": (
            False if state["inet_config_enabled"] else None
        ),
        "general_ipv6_absence_established": (
            False if state["ipv6_config_enabled"] else None
        ),
        "user_ns_config_enabled": state["user_ns_config_enabled"],
        "disabled_user_ns_is_decisive_exclusion": False,
        "if_built_ordinary_dccp_socket_creation_inherently_capability_gated": (
            False
        ),
        "unnamed_vendor_equivalent_path_presence": None,
        "upstream_fix_effect_in_recovered_package_established": None,
        "installed_runtime_identity_observed": None,
        "runtime_named_path_reachability_observed": None,
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
        "model": "dccpv6-named-request-path-static-applicability",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "configuration_sha256": CONFIG_SHA256,
            "authoritative_map_sha256": KALLSYMS_SHA256,
            "canonical_stock_rootfs_archive_sha256": STOCK_ROOTFS_ARCHIVE_SHA256,
            "public_v4_1_dccp_kconfig_sha256": DCCP_KCONFIG_SHA256,
            "public_v4_1_net_makefile_sha256": NET_MAKEFILE_SHA256,
            "public_v4_1_dccp_makefile_sha256": DCCP_MAKEFILE_SHA256,
            "mainline_fix_commit": MAINLINE_FIX_COMMIT,
            "mainline_fix_patch_sha256": MAINLINE_FIX_PATCH_SHA256,
            "stable_4_1_fix_commit": STABLE_FIX_COMMIT,
            "stable_4_1_fix_patch_sha256": STABLE_FIX_PATCH_SHA256,
            "stable_fix_first_release": "Linux 4.1.41",
            "stable_fix_release_date": "2017-06-15",
            "stable_fix_release_date_source": (
                "retained official ChangeLog-4.1.41 release commit/date"
            ),
            "official_changelog_4_1_41_sha256": CHANGELOG_4_1_41_SHA256,
            "pre_recorded_target_state": {
                "source": (
                    "separate static configuration, applicable public build "
                    "contract, authoritative-map, and canonical decrypted stock "
                    "archive member review; not verified by this model run"
                ),
                **PRE_RECORDED_TARGET_STATE,
            },
            "assessment": "evidence/vendor-kernel-dccp-cve-2017-6074.md",
            "static_evidence": (
                "evidence/artifacts/kernel-candidates/"
                "kernel-dccp-cve-2017-6074.txt"
            ),
        },
        "claim_boundary": {
            "establishes": [
                "classification of supplied facts for the named public DCCPv6 request path",
                "physical component and path classification independent of CVE dependency",
                "CVE rejection only when dependency and physical path absence both hold",
                "unknown when component or named-path facts are incomplete or conflicting",
                "positive complete DCCPv6 functional-path evidence takes precedence",
                "IPv4-only functional evidence establishes DCCP core presence only",
                "disabled USER_NS is not treated as the decisive exclusion",
            ],
            "does_not_establish": [
                "automatic verification of bound static evidence or archive members",
                "general IPv6 absence from a disabled bounded configuration fact",
                "absence of every unnamed or vendor-equivalent route",
                "installed identity, runtime reachability, behavior, or policy",
                "fix provenance, recovered-code fix effects, or any impact outcome",
            ],
            "inputs_are_boolean_only": True,
            "emits_only_non_operational_classification_metadata": True,
            "target_or_named_target_interaction_performed": False,
        },
        "pre_recorded_target_classification": classify_dccp_path(
            **PRE_RECORDED_TARGET_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_dccp_path(**state)
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
            "error: all DCCPv6 named-path arguments must be supplied together"
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
