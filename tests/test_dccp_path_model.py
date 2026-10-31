from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/uk_fw/dccp_path_model.py"
SPEC = importlib.util.spec_from_file_location("dccp_path_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OPTIONS = tuple(M.PRE_RECORDED_TARGET_STATE)
NULL_FIELDS = {
    "unnamed_vendor_equivalent_path_presence",
    "upstream_fix_effect_in_recovered_package_established",
    "installed_runtime_identity_observed",
    "runtime_named_path_reachability_observed",
    "runtime_named_path_behavior_observed",
    "runtime_access_policy_observed",
    "memory_corruption_observed",
    "privilege_escalation_observed",
    "root_observed",
    "persistence_observed",
}
EXPECTED_FIELDS = {
    "input",
    "public_cve_requires_named_dccpv6_request_path",
    "public_v4_1_build_rules_applicable",
    "public_build_rules_ip_dccp_disabled_excludes_named_subtree",
    "dccp_core_physical_absence_established",
    "dccpv6_physical_absence_established",
    "physical_named_dccpv6_request_path_absence_established",
    "named_dccpv6_request_path_available",
    "dccp_core_translation_units_present",
    "dccpv6_translation_unit_present",
    "dccp_core_evidence_conflict",
    "dccpv6_evidence_conflict",
    "cve_2017_6074_dependency_satisfied",
    "cve_2017_6074_rejected_for_named_dccpv6_path",
    "cve_2017_6074_not_rejected_for_named_dccpv6_path_by_physical_absence",
    "queried_named_core_symbol_inventory_has_presence",
    "queried_named_dccpv6_symbol_inventory_has_presence",
    "functional_ipv4_only_dccp_path_present",
    "functional_named_dccpv6_request_path_present",
    "inet_config_enabled",
    "ipv6_config_enabled",
    "general_inet_absence_established",
    "general_ipv6_absence_established",
    "user_ns_config_enabled",
    "disabled_user_ns_is_decisive_exclusion",
    "if_built_ordinary_dccp_socket_creation_inherently_capability_gated",
    *NULL_FIELDS,
}
DEFAULT_REPORT_SHA256 = (
    "34874b60979ffda6a01ff527ddb36b26a7bdf2eb2f723217e0921ee84862df4e"
)


def args_for(state: dict[str, bool]) -> list[str]:
    result: list[str] = []
    for name in OPTIONS:
        result += [f"--{name.replace('_', '-')}", str(state[name]).lower()]
    return result


def expected_component_state(
    state: dict[str, bool], *, dccpv6: bool
) -> tuple[bool | None, bool]:
    complete = state["functional_named_dccpv6_request_path_present"]
    default_negative = (
        state["public_v4_1_build_rules_applicable"]
        and not state["ip_dccp_config_enabled"]
    )
    if dccpv6:
        positive = (
            state["dccpv6_translation_unit_built_in"]
            or state["dccpv6_named_module_shipped"]
            or state["queried_named_dccpv6_symbols_present"]
            or complete
        )
        inventory_negative = (
            not state["dccpv6_translation_unit_built_in"]
            and state["recovered_module_inventory_complete"]
            and not state["dccpv6_named_module_shipped"]
        )
    else:
        positive = (
            state["dccp_core_translation_units_built_in"]
            or state["dccp_core_named_modules_shipped"]
            or state["queried_named_core_symbols_present"]
            or state["functional_ipv4_only_dccp_path_present"]
            or complete
        )
        inventory_negative = (
            not state["dccp_core_translation_units_built_in"]
            and state["recovered_module_inventory_complete"]
            and not state["dccp_core_named_modules_shipped"]
        )
    negative = default_negative or inventory_negative
    if positive:
        return True, negative
    if negative:
        return False, False
    return None, False


class DccpPathModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_specific_named_dccpv6_path(self) -> None:
        result = M.classify_dccp_path(**M.PRE_RECORDED_TARGET_STATE)
        self.assertEqual(set(result), EXPECTED_FIELDS)
        self.assertTrue(
            result["physical_named_dccpv6_request_path_absence_established"]
        )
        self.assertFalse(result["named_dccpv6_request_path_available"])
        self.assertFalse(result["dccp_core_translation_units_present"])
        self.assertFalse(result["dccpv6_translation_unit_present"])
        self.assertTrue(result["cve_2017_6074_dependency_satisfied"])
        self.assertTrue(result["cve_2017_6074_rejected_for_named_dccpv6_path"])
        self.assertTrue(result["inet_config_enabled"])
        self.assertTrue(result["ipv6_config_enabled"])
        self.assertFalse(result["general_inet_absence_established"])
        self.assertFalse(result["general_ipv6_absence_established"])
        self.assertFalse(result["user_ns_config_enabled"])
        self.assertFalse(result["disabled_user_ns_is_decisive_exclusion"])
        for name in NULL_FIELDS:
            self.assertIsNone(result[name])

    def test_dependency_false_does_not_hide_physical_absence(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["public_cve_requires_named_dccpv6_request_path"] = False
        result = M.classify_dccp_path(**state)
        self.assertTrue(
            result["physical_named_dccpv6_request_path_absence_established"]
        )
        self.assertFalse(result["named_dccpv6_request_path_available"])
        self.assertFalse(result["dccp_core_translation_units_present"])
        self.assertFalse(result["dccpv6_translation_unit_present"])
        self.assertFalse(result["cve_2017_6074_dependency_satisfied"])
        self.assertFalse(result["cve_2017_6074_rejected_for_named_dccpv6_path"])

    def test_queried_core_symbol_presence_establishes_core_units(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["queried_named_core_symbols_present"] = True
        result = M.classify_dccp_path(**state)
        self.assertTrue(result["dccp_core_translation_units_present"])
        self.assertTrue(result["dccp_core_evidence_conflict"])
        self.assertFalse(result["dccpv6_translation_unit_present"])
        self.assertTrue(
            result["physical_named_dccpv6_request_path_absence_established"]
        )

    def test_queried_dccpv6_symbol_presence_establishes_dccpv6_unit(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["queried_named_dccpv6_symbols_present"] = True
        result = M.classify_dccp_path(**state)
        self.assertTrue(result["dccpv6_translation_unit_present"])
        self.assertTrue(result["dccpv6_evidence_conflict"])
        self.assertFalse(result["dccp_core_translation_units_present"])
        self.assertTrue(
            result["physical_named_dccpv6_request_path_absence_established"]
        )

    def test_core_present_but_dccpv6_absent_rejects_specific_path(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["ip_dccp_config_enabled"] = True
        state["dccp_core_translation_units_built_in"] = True
        result = M.classify_dccp_path(**state)
        self.assertTrue(result["dccp_core_translation_units_present"])
        self.assertFalse(result["dccpv6_translation_unit_present"])
        self.assertFalse(result["named_dccpv6_request_path_available"])
        self.assertTrue(result["cve_2017_6074_rejected_for_named_dccpv6_path"])

    def test_ipv4_only_functional_evidence_establishes_only_core(self) -> None:
        state = {name: False for name in OPTIONS}
        state["public_cve_requires_named_dccpv6_request_path"] = True
        state["functional_ipv4_only_dccp_path_present"] = True
        result = M.classify_dccp_path(**state)
        self.assertTrue(result["dccp_core_translation_units_present"])
        self.assertIsNone(result["dccpv6_translation_unit_present"])
        self.assertIsNone(result["named_dccpv6_request_path_available"])
        self.assertFalse(
            result["physical_named_dccpv6_request_path_absence_established"]
        )
        self.assertFalse(result["cve_2017_6074_rejected_for_named_dccpv6_path"])

    def test_positive_complete_dccpv6_path_overrides_all_absence(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["functional_named_dccpv6_request_path_present"] = True
        result = M.classify_dccp_path(**state)
        self.assertTrue(result["named_dccpv6_request_path_available"])
        self.assertTrue(result["dccp_core_translation_units_present"])
        self.assertTrue(result["dccpv6_translation_unit_present"])
        self.assertFalse(
            result["physical_named_dccpv6_request_path_absence_established"]
        )
        self.assertFalse(result["cve_2017_6074_rejected_for_named_dccpv6_path"])

    def test_incomplete_component_facts_and_bounded_config_scope_are_unknown(self) -> None:
        state = {name: False for name in OPTIONS}
        result = M.classify_dccp_path(**state)
        self.assertIsNone(result["dccp_core_translation_units_present"])
        self.assertIsNone(result["dccpv6_translation_unit_present"])
        self.assertIsNone(result["named_dccpv6_request_path_available"])
        self.assertFalse(
            result["physical_named_dccpv6_request_path_absence_established"]
        )
        self.assertIsNone(result["general_inet_absence_established"])
        self.assertIsNone(result["general_ipv6_absence_established"])

        state["user_ns_config_enabled"] = True
        result = M.classify_dccp_path(**state)
        self.assertFalse(result["disabled_user_ns_is_decisive_exclusion"])
        self.assertIsNone(result["named_dccpv6_request_path_available"])

    def test_exhaustive_domain_and_every_classification_field(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            with self.subTest(bits=bits):
                result = M.classify_dccp_path(**state)
                core, core_conflict = expected_component_state(state, dccpv6=False)
                dccpv6, dccpv6_conflict = expected_component_state(
                    state, dccpv6=True
                )
                complete = state[
                    "functional_named_dccpv6_request_path_present"
                ]
                absent = not complete and (core is False or dccpv6 is False)
                path = True if complete else (False if absent else None)
                dependency = state[
                    "public_cve_requires_named_dccpv6_request_path"
                ]
                rejected = dependency and absent
                default_exclusion = (
                    state["public_v4_1_build_rules_applicable"]
                    and not state["ip_dccp_config_enabled"]
                )

                self.assertEqual(set(result), EXPECTED_FIELDS)
                self.assertEqual(result["input"], state)
                self.assertEqual(
                    result["public_cve_requires_named_dccpv6_request_path"],
                    dependency,
                )
                self.assertEqual(
                    result["public_v4_1_build_rules_applicable"],
                    state["public_v4_1_build_rules_applicable"],
                )
                self.assertEqual(
                    result[
                        "public_build_rules_ip_dccp_disabled_excludes_named_subtree"
                    ],
                    default_exclusion,
                )
                self.assertEqual(
                    result["dccp_core_physical_absence_established"],
                    core is False,
                )
                self.assertEqual(
                    result["dccpv6_physical_absence_established"],
                    dccpv6 is False,
                )
                self.assertEqual(
                    result[
                        "physical_named_dccpv6_request_path_absence_established"
                    ],
                    absent,
                )
                self.assertEqual(
                    result["named_dccpv6_request_path_available"], path
                )
                self.assertEqual(
                    result["dccp_core_translation_units_present"], core
                )
                self.assertEqual(
                    result["dccpv6_translation_unit_present"], dccpv6
                )
                self.assertEqual(
                    result["dccp_core_evidence_conflict"], core_conflict
                )
                self.assertEqual(
                    result["dccpv6_evidence_conflict"], dccpv6_conflict
                )
                self.assertEqual(
                    result["cve_2017_6074_dependency_satisfied"], dependency
                )
                self.assertEqual(
                    result["cve_2017_6074_rejected_for_named_dccpv6_path"],
                    rejected,
                )
                self.assertEqual(
                    result[
                        "cve_2017_6074_not_rejected_for_named_dccpv6_path_by_physical_absence"
                    ],
                    not rejected,
                )
                self.assertEqual(
                    result[
                        "queried_named_core_symbol_inventory_has_presence"
                    ],
                    state["queried_named_core_symbols_present"],
                )
                self.assertEqual(
                    result[
                        "queried_named_dccpv6_symbol_inventory_has_presence"
                    ],
                    state["queried_named_dccpv6_symbols_present"],
                )
                self.assertEqual(
                    result["functional_ipv4_only_dccp_path_present"],
                    state["functional_ipv4_only_dccp_path_present"],
                )
                self.assertEqual(
                    result["functional_named_dccpv6_request_path_present"],
                    complete,
                )
                self.assertEqual(
                    result["inet_config_enabled"], state["inet_config_enabled"]
                )
                self.assertEqual(
                    result["ipv6_config_enabled"], state["ipv6_config_enabled"]
                )
                self.assertEqual(
                    result["general_inet_absence_established"],
                    False if state["inet_config_enabled"] else None,
                )
                self.assertEqual(
                    result["general_ipv6_absence_established"],
                    False if state["ipv6_config_enabled"] else None,
                )
                self.assertEqual(
                    result["user_ns_config_enabled"],
                    state["user_ns_config_enabled"],
                )
                self.assertFalse(result["disabled_user_ns_is_decisive_exclusion"])
                self.assertFalse(
                    result[
                        "if_built_ordinary_dccp_socket_creation_inherently_capability_gated"
                    ]
                )
                for name in NULL_FIELDS:
                    self.assertIsNone(result[name])

    def test_rejects_wrong_keys_and_non_booleans(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_dccp_path(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
            M.classify_dccp_path(**state)

    def test_cli_complete_and_fail_closed_cases(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        run = subprocess.run(
            [sys.executable, str(TOOL), *args_for(state)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["classification"]["input"], state)

        option = f"--{OPTIONS[0].replace('_', '-')}"
        for argv, text in (
            ([option, "true"], "all DCCPv6 named-path arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--public-cve-requires-named-dccp", "true"], "unrecognized arguments"),
            ([option, "yes"], "expected true or false"),
        ):
            with self.subTest(argv=argv):
                run = subprocess.run(
                    [sys.executable, str(TOOL), *argv],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, "")
                self.assertIn(text, run.stderr)

    def test_default_output_deterministic_explicit_utf8_lf(self) -> None:
        expected = (
            json.dumps(M.build_report(), indent=2, sort_keys=True).encode("utf-8")
            + b"\n"
        )
        outputs = []
        for encoding in ("ascii:strict", "latin-1:strict", "utf-16:strict"):
            with self.subTest(encoding=encoding):
                env = dict(os.environ, PYTHONIOENCODING=encoding)
                run = subprocess.run(
                    [sys.executable, str(TOOL)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                self.assertEqual(run.stdout, expected)
                self.assertNotIn(b"\r", run.stdout)
                outputs.append(run.stdout)
        self.assertEqual(len(set(outputs)), 1)
        self.assertEqual(hashlib.sha256(outputs[0]).hexdigest(), DEFAULT_REPORT_SHA256)

    def test_report_is_bound_and_contains_no_operational_material(self) -> None:
        report = M.build_report()
        encoded = json.dumps(report, sort_keys=True).lower()
        for forbidden in (
            "0xffffffff",
            "af_inet",
            "ipv6_recvpktinfo",
            "consume_skb",
            "__kfree_skb",
            "dccp_pkt_request",
            "packet",
            "syscall",
            "modprobe",
            "insmod",
            "rmmod",
            "command",
            "instruction",
            "target_byte",
            "trigger",
            "race",
            "payload",
            "firmware",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, encoded)
        binding = report["evidence_binding"]
        self.assertEqual(
            binding["canonical_stock_rootfs_archive_sha256"],
            "423491fd8b86bd815d4e12f47054e08a589a5159f87213f08980fcc3a0e47c84",
        )
        self.assertEqual(binding["stable_fix_release_date"], "2017-06-15")
        self.assertEqual(
            binding["stable_fix_release_date_source"],
            "retained official ChangeLog-4.1.41 release commit/date",
        )
        self.assertIn(
            "canonical decrypted stock archive member review",
            binding["pre_recorded_target_state"]["source"],
        )
        self.assertNotIn("archive index", encoded)
        self.assertNotIn("extracted-safe", encoded)
        self.assertTrue(report["claim_boundary"]["inputs_are_boolean_only"])
        self.assertTrue(
            report["claim_boundary"][
                "emits_only_non_operational_classification_metadata"
            ]
        )
        self.assertFalse(
            report["claim_boundary"]["target_or_named_target_interaction_performed"]
        )
        self.assertNotIn("no syscall", encoded)


if __name__ == "__main__":
    unittest.main()
