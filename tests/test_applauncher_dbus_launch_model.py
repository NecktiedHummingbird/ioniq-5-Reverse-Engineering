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
TOOL = ROOT / "tools" / "uk_fw" / "applauncher_dbus_launch_model.py"
SPEC = importlib.util.spec_from_file_location("applauncher_dbus_launch_model", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
OPTIONS = tuple(MODULE.RUNTIME_OPTIONS)


def cli_args(state: dict[str, bool]) -> list[str]:
    args: list[str] = []
    for name in OPTIONS:
        args.extend([f"--{name.replace('_', '-')}", str(state[name]).lower()])
    return args


class AppLauncherDbusLaunchModelTests(unittest.TestCase):
    def test_default_report_records_static_facts_without_runtime_classification(self) -> None:
        report = MODULE.build_report()
        self.assertNotIn("classification", report)
        facts = report["evidence_binding"]["static_target_facts"]
        for name in MODULE.STATIC_TARGET_FACTS:
            self.assertTrue(facts[name])

    def test_complete_boolean_matrix_preserves_branch_logic_and_unknown_outcomes(self) -> None:
        for values in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, values))
            result = MODULE.classify_launch_route(**state)
            delivered = all(
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
            eligible = (
                not state["existing_process_found_for_appid"]
                and state["appid_in_create_range"]
                and state["target_exists_for_create"]
            )
            new_object_available = (
                eligible and state["new_app_process_object_constructed"]
            )
            available = (
                state["existing_process_found_for_appid"] or new_object_available
            )
            reached = delivered and available
            direct = reached and state["direct_launch_flag_set"]
            start_attempted = direct and state["identified_qprocess_start_site_reached"]
            exec_preconditions = (
                start_attempted
                and state["qprocess_accepts_start"]
                and state["target_is_executable_at_exec"]
                and state["launcher_can_execute_target_at_exec"]
            )
            with self.subTest(state=state):
                self.assertEqual(result["request_delivered"], delivered)
                self.assertEqual(result["new_object_creation_route_eligible"], eligible)
                self.assertEqual(
                    result["new_app_process_object_available"], new_object_available
                )
                self.assertEqual(result["app_process_object_available"], available)
                self.assertEqual(result["dispatcher_reached"], reached)
                self.assertEqual(result["caller_path_installed"], reached)
                self.assertEqual(result["direct_route_selected"], direct)
                self.assertEqual(result["qprocess_start_attempted"], start_attempted)
                self.assertEqual(
                    result["identified_verifier_called_on_direct_route"],
                    False if direct else None,
                )
                self.assertEqual(result["exec_preconditions_supplied"], exec_preconditions)
                self.assertEqual(
                    result["controlled_privileged_exec_candidate"],
                    exec_preconditions
                    and state["caller_controls_target_at_exec"]
                    and state["launcher_effectively_privileged_at_exec"],
                )
                for key in (
                    "runtime_request_observed",
                    "runtime_exec_observed",
                    "credential_or_smack_transition_observed",
                    "update_trust_anchor_write_observed",
                    "persistence_observed",
                ):
                    self.assertIsNone(result[key])

    def test_existing_process_branch_does_not_require_create_gates(self) -> None:
        state = {name: True for name in OPTIONS}
        state["appid_in_create_range"] = False
        state["target_exists_for_create"] = False
        result = MODULE.classify_launch_route(**state)
        self.assertTrue(result["app_process_object_available"])
        self.assertTrue(result["qprocess_start_attempted"])

    def test_new_object_branch_fails_closed_on_each_create_gate(self) -> None:
        for gate in (
            "appid_in_create_range",
            "target_exists_for_create",
            "new_app_process_object_constructed",
        ):
            state = {name: True for name in OPTIONS}
            state["existing_process_found_for_appid"] = False
            state[gate] = False
            with self.subTest(gate=gate):
                result = MODULE.classify_launch_route(**state)
                self.assertFalse(result["new_app_process_object_available"])
                self.assertFalse(result["app_process_object_available"])
                self.assertFalse(result["qprocess_start_attempted"])

    def test_request_registration_failure_prevents_delivery(self) -> None:
        state = {name: True for name in OPTIONS}
        state["request_object_registered"] = False
        result = MODULE.classify_launch_route(**state)
        self.assertFalse(result["request_delivered"])
        self.assertFalse(result["dispatcher_reached"])
        self.assertFalse(result["qprocess_start_attempted"])

    def test_non_boolean_and_key_mismatch_rejected(self) -> None:
        for name in OPTIONS:
            state = {option: True for option in OPTIONS}
            state[name] = 1
            with self.subTest(name=name), self.assertRaisesRegex(
                MODULE.ModelError, "must be a boolean"
            ):
                MODULE.classify_launch_route(**state)
        state = {option: True for option in OPTIONS}
        state.pop(OPTIONS[0])
        with self.assertRaisesRegex(MODULE.ModelError, "keys mismatch"):
            MODULE.classify_launch_route(**state)
        state = {option: True for option in OPTIONS}
        state["unexpected"] = True
        with self.assertRaisesRegex(MODULE.ModelError, "keys mismatch"):
            MODULE.classify_launch_route(**state)

    def test_cli_accepts_complete_state(self) -> None:
        state = {name: True for name in OPTIONS}
        state["existing_process_found_for_appid"] = False
        proc = subprocess.run(
            [sys.executable, str(TOOL), *cli_args(state)],
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(parsed["classification"]["input"], state)
        self.assertTrue(parsed["classification"]["new_app_process_object_available"])

    def test_cli_rejects_partial_duplicate_malformed_and_abbreviated_arguments(self) -> None:
        option = OPTIONS[0].replace("_", "-")
        cases = (
            [f"--{option}", "true"],
            [f"--{option}", "true", f"--{option}", "true"],
            [f"--{option}", "true", f"--{option}", "false"],
            [f"--{option}", "maybe"],
            [f"--{option}"],
            [f"--{option[:-1]}", "true"],
            ["--unknown", "true"],
        )
        for args in cases:
            with self.subTest(args=args):
                proc = subprocess.run(
                    [sys.executable, str(TOOL), *args],
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(proc.returncode, 0)

    def test_default_cli_output_is_deterministic_utf8_lf_and_matches_builder(self) -> None:
        expected = (
            json.dumps(MODULE.build_report(), indent=2, sort_keys=True).encode("utf-8")
            + b"\n"
        )
        outputs = []
        for encoding in ("ascii:strict", "utf-16:strict", "utf-8:strict"):
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = encoding
            proc = subprocess.run(
                [sys.executable, str(TOOL)],
                capture_output=True,
                env=env,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, expected)
            self.assertTrue(proc.stdout.endswith(b"\n"))
            self.assertNotIn(b"\r", proc.stdout)
            outputs.append(proc.stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[1], outputs[2])
        self.assertEqual(
            hashlib.sha256(outputs[0]).hexdigest(),
            "ee8949cec8c7a9832f7794b59f3552a3237c5f3b0e00777ae95bc5487e629530",
        )

    def test_report_contains_no_operational_material(self) -> None:
        encoded = json.dumps(MODULE.build_report(), sort_keys=True)
        self.assertNotIn("0x", encoded)
        self.assertNotIn("/tmp/", encoded)
        self.assertNotIn("dbus-send", encoded)
        boundary = MODULE.build_report()["claim_boundary"]
        self.assertTrue(boundary["inputs_are_boolean_only"])
        self.assertTrue(
            boundary["emits_no_command_message_target_path_payload_or_firmware_bytes"]
        )


if __name__ == "__main__":
    unittest.main()
