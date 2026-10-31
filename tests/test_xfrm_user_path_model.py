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
TOOL = ROOT / "tools/uk_fw/xfrm_user_path_model.py"
SPEC = importlib.util.spec_from_file_location("xfrm_user_path_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OPTIONS = tuple(M.PRE_RECORDED_TARGET_STATE)
ABSENCE_FACTS = (
    "public_cve_requires_named_xfrm_user_newae_path",
    "xfrm_user_config_enabled",
    "xfrm_user_translation_unit_built_in",
    "recovered_module_inventory_complete",
    "xfrm_user_module_shipped",
    "queried_named_path_symbols_present",
    "functional_named_xfrm_user_newae_path_present",
)
NULL_FIELDS = {
    "unnamed_vendor_equivalent_path_presence",
    "upstream_fix_effects_in_recovered_package_established",
    "installed_runtime_identity_observed",
    "runtime_named_path_behavior_observed",
    "runtime_access_policy_observed",
    "memory_corruption_observed",
    "privilege_escalation_observed",
    "root_observed",
    "persistence_observed",
}
EXPECTED_FIELDS = {
    "input",
    "complete_named_path_absence_present",
    "named_xfrm_user_newae_path_available",
    "named_xfrm_user_translation_unit_present",
    "cve_2017_7184_rejected_for_named_path",
    "cve_2017_7184_not_rejected_for_named_path_by_complete_absence",
    "queried_named_path_symbol_inventory_has_presence",
    "xfrm_core_config_enabled",
    "xfrm_core_functionality_present",
    "general_xfrm_absence_established",
    "separate_net_key_interface_config_enabled",
    "net_key_interface_is_named_xfrm_user_path",
    *NULL_FIELDS,
}


def args_for(state: dict[str, bool]) -> list[str]:
    result: list[str] = []
    for name in OPTIONS:
        result += [f"--{name.replace('_', '-')}", str(state[name]).lower()]
    return result


class XfrmUserPathModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_only_named_path(self) -> None:
        result = M.classify_xfrm_user_path(**M.PRE_RECORDED_TARGET_STATE)
        self.assertTrue(result["complete_named_path_absence_present"])
        self.assertFalse(result["named_xfrm_user_newae_path_available"])
        self.assertFalse(result["named_xfrm_user_translation_unit_present"])
        self.assertTrue(result["cve_2017_7184_rejected_for_named_path"])
        self.assertTrue(result["xfrm_core_functionality_present"])
        self.assertFalse(result["general_xfrm_absence_established"])
        self.assertFalse(result["separate_net_key_interface_config_enabled"])
        self.assertFalse(result["net_key_interface_is_named_xfrm_user_path"])
        for name in NULL_FIELDS:
            self.assertIsNone(result[name])

    def test_exhaustive_domain_and_every_classification_field(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            with self.subTest(bits=bits):
                result = M.classify_xfrm_user_path(**state)
                functional = state[
                    "functional_named_xfrm_user_newae_path_present"
                ]
                absent = (
                    state["public_cve_requires_named_xfrm_user_newae_path"]
                    and not state["xfrm_user_config_enabled"]
                    and not state["xfrm_user_translation_unit_built_in"]
                    and state["recovered_module_inventory_complete"]
                    and not state["xfrm_user_module_shipped"]
                    and not state["queried_named_path_symbols_present"]
                    and not functional
                )
                path = True if functional else (False if absent else None)
                unit_presence = (
                    True
                    if (
                        state["xfrm_user_translation_unit_built_in"]
                        or state["xfrm_user_module_shipped"]
                        or functional
                    )
                    else (False if absent else None)
                )
                core_present = (
                    state["xfrm_core_config_enabled"]
                    or state["xfrm_core_functionality_present"]
                )

                self.assertEqual(set(result), EXPECTED_FIELDS)
                self.assertEqual(result["input"], state)
                self.assertEqual(
                    result["complete_named_path_absence_present"], absent
                )
                self.assertEqual(
                    result["named_xfrm_user_newae_path_available"], path
                )
                self.assertEqual(
                    result["named_xfrm_user_translation_unit_present"],
                    unit_presence,
                )
                self.assertEqual(
                    result["cve_2017_7184_rejected_for_named_path"], absent
                )
                self.assertEqual(
                    result[
                        "cve_2017_7184_not_rejected_for_named_path_by_complete_absence"
                    ],
                    not absent,
                )
                self.assertEqual(
                    result["queried_named_path_symbol_inventory_has_presence"],
                    state["queried_named_path_symbols_present"],
                )
                self.assertEqual(
                    result["xfrm_core_config_enabled"],
                    state["xfrm_core_config_enabled"],
                )
                self.assertEqual(
                    result["xfrm_core_functionality_present"],
                    state["xfrm_core_functionality_present"],
                )
                self.assertEqual(
                    result["general_xfrm_absence_established"],
                    False if core_present else None,
                )
                self.assertEqual(
                    result["separate_net_key_interface_config_enabled"],
                    state["net_key_config_enabled"],
                )
                self.assertFalse(
                    result["net_key_interface_is_named_xfrm_user_path"]
                )
                for name in NULL_FIELDS:
                    self.assertIsNone(result[name])

    def test_each_named_path_absence_fact_is_required(self) -> None:
        for name in ABSENCE_FACTS:
            state = dict(M.PRE_RECORDED_TARGET_STATE)
            state[name] = not state[name]
            with self.subTest(name=name):
                result = M.classify_xfrm_user_path(**state)
                self.assertFalse(result["cve_2017_7184_rejected_for_named_path"])
                if name == "functional_named_xfrm_user_newae_path_present":
                    self.assertTrue(
                        result["named_xfrm_user_newae_path_available"]
                    )
                else:
                    self.assertIsNone(
                        result["named_xfrm_user_newae_path_available"]
                    )

    def test_core_and_separate_interface_scope_never_broaden_verdict(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["net_key_config_enabled"] = True
        result = M.classify_xfrm_user_path(**state)
        self.assertTrue(result["cve_2017_7184_rejected_for_named_path"])
        self.assertTrue(result["separate_net_key_interface_config_enabled"])
        self.assertFalse(result["net_key_interface_is_named_xfrm_user_path"])
        self.assertFalse(result["general_xfrm_absence_established"])

    def test_rejects_wrong_keys_and_non_booleans(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_xfrm_user_path(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
            M.classify_xfrm_user_path(**state)

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
            ([option, "true"], "all XFRM-user named-path arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--public-cve-requires-named-xfrm", "true"], "unrecognized arguments"),
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
        self.assertEqual(
            hashlib.sha256(outputs[0]).hexdigest(),
            "0a62022f8e95045fed37132684c5979e2845c1bbea997a9f8d9cbad5b2da9645",
        )

    def test_report_contains_only_non_operational_metadata(self) -> None:
        report = M.build_report()
        encoded = json.dumps(report, sort_keys=True).lower()
        for forbidden in (
            "0xffffffff",
            "netlink",
            "socket",
            "namespace",
            "cap_net_admin",
            "xfrm_msg",
            "xfrma_",
            "packet",
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
        self.assertIn(
            "canonical decrypted stock archive member inventory",
            binding["pre_recorded_target_state"]["source"],
        )
        self.assertNotIn("extracted-safe", encoded)
        self.assertTrue(
            report["claim_boundary"]["inputs_are_boolean_only"]
        )
        self.assertTrue(
            report["claim_boundary"][
                "emits_only_non_operational_classification_metadata"
            ]
        )


if __name__ == "__main__":
    unittest.main()
