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
TOOL = ROOT / "tools" / "uk_fw" / "keystore_boot_gate_model.py"
SPEC = importlib.util.spec_from_file_location("keystore_boot_gate_model", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
OPTIONS = tuple(MODULE.PRE_RECORDED_TARGET_STATE)
NULL_RESULTS = (
    "keystore_runtime_initialization_observed",
    "manifest_runtime_initialization_observed",
    "signature_acceptance_observed",
    "manifest_invalid_free_observed",
    "kernel_memory_corruption_observed",
    "update_acceptance_observed",
    "boot_acceptance_observed",
    "privilege_escalation_observed",
    "persistence_observed",
)


def cli_args(state: dict[str, bool]) -> list[str]:
    args: list[str] = []
    for name in OPTIONS:
        args.extend([f"--{name.replace('_', '-')}", str(state[name]).lower()])
    return args


class KeystoreBootGateModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_general_signature_bypass(self) -> None:
        result = MODULE.build_report()["pre_recorded_target_classification"]
        self.assertTrue(
            result["keystore_hardware_secure_boot_status_prerequisite_skipped"]
        )
        self.assertTrue(result[
            "keystore_registration_secure_boot_status_prerequisite_skipped"
        ])
        self.assertTrue(result["oem_signature_verifier_chain_present"])
        self.assertTrue(result[
            "secure_boot_ignore_as_general_signature_bypass_rejected_by_supplied_facts"
        ])
        self.assertTrue(result["manifest_interior_pointer_free_candidate"])
        for key in NULL_RESULTS:
            self.assertIsNone(result[key])

    def test_complete_boolean_matrix_keeps_gates_independent(self) -> None:
        for values in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, values))
            result = MODULE.classify_boot_gate(**state)
            status_skipped = (
                state["secure_boot_ignore_config_enabled"]
                and state["not_checking_status_branch_compiled"]
                and not state["hardware_status_check_before_seed_fill_present"]
            )
            registration_skipped = (
                state["secure_boot_ignore_config_enabled"]
                and not state["registration_secure_boot_status_check_present"]
                and state["registration_continues_to_client_derivation"]
            )
            verifier = (
                state["verify_oem_signature_hashes_input"]
                and state["verify_oem_signature_calls_manifest_key_verifier"]
            )
            rejected = (
                status_skipped
                and state["seed_fill_failure_still_fatal_to_keystore_init"]
                and state["manifest_init_is_separate_initcall"]
                and verifier
            )
            invalid_free_candidate = (
                state["manifest_allocation_pointer_shifted_before_header_validation"]
                and state["manifest_header_rejection_frees_shifted_pointer"]
            )
            with self.subTest(state=state):
                self.assertEqual(
                    result["keystore_hardware_secure_boot_status_prerequisite_skipped"],
                    status_skipped,
                )
                self.assertEqual(
                    result["keystore_registration_secure_boot_status_prerequisite_skipped"],
                    registration_skipped,
                )
                self.assertEqual(
                    result["oem_signature_verifier_chain_present"], verifier
                )
                self.assertEqual(result[
                    "secure_boot_ignore_as_general_signature_bypass_rejected_by_supplied_facts"
                ], rejected)
                self.assertEqual(
                    result["manifest_interior_pointer_free_candidate"],
                    invalid_free_candidate,
                )
                for key in NULL_RESULTS:
                    self.assertIsNone(result[key])

    def test_non_boolean_and_key_mismatch_rejected(self) -> None:
        for name in OPTIONS:
            state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
            state[name] = 1
            with self.subTest(name=name), self.assertRaisesRegex(
                MODULE.ModelError, "must be a boolean"
            ):
                MODULE.classify_boot_gate(**state)
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state.pop(OPTIONS[0])
        with self.assertRaisesRegex(MODULE.ModelError, "keys mismatch"):
            MODULE.classify_boot_gate(**state)
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state["unexpected"] = True
        with self.assertRaisesRegex(MODULE.ModelError, "keys mismatch"):
            MODULE.classify_boot_gate(**state)

    def test_cli_accepts_complete_and_rejects_partial_duplicate_bad_or_abbreviated(self) -> None:
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        good = subprocess.run(
            [sys.executable, str(TOOL), *cli_args(state)], capture_output=True,
            check=False,
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        parsed = json.loads(good.stdout)
        self.assertEqual(parsed["classification"]["input"], state)

        option = OPTIONS[0].replace("_", "-")
        cases = (
            [f"--{option}", "true"],
            [f"--{option}", "true", f"--{option}", "false"],
            [f"--{option}", "maybe"],
            [f"--{option[:-1]}", "true"],
            ["--unknown", "true"],
        )
        for args in cases:
            with self.subTest(args=args):
                bad = subprocess.run(
                    [sys.executable, str(TOOL), *args], capture_output=True,
                    check=False,
                )
                self.assertNotEqual(bad.returncode, 0)

    def test_default_output_is_explicit_deterministic_utf8_lf(self) -> None:
        expected = json.dumps(
            MODULE.build_report(), indent=2, sort_keys=True
        ).encode("utf-8") + b"\n"
        outputs = []
        for encoding in ("ascii:strict", "utf-16:strict", "utf-8:strict"):
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = encoding
            proc = subprocess.run(
                [sys.executable, str(TOOL)], capture_output=True, env=env,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, expected)
            self.assertNotIn(b"\r", proc.stdout)
            outputs.append(proc.stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[1], outputs[2])
        self.assertEqual(
            hashlib.sha256(outputs[0]).hexdigest(), "e5d935fe17a05d2304ced562a515e3dd964b1bae993e300985a0c9aaf3f20926"
        )

    def test_report_contains_no_operational_material(self) -> None:
        encoded = json.dumps(MODULE.build_report(), sort_keys=True)
        for forbidden in ("kexec -", "/dev/mem", "BEGIN PUBLIC KEY", "0xffffffff"):
            self.assertNotIn(forbidden, encoded)
        boundary = MODULE.build_report()["claim_boundary"]
        self.assertTrue(boundary["inputs_are_boolean_only"])
        self.assertTrue(boundary[
            "emits_no_manifest_physical_address_key_signature_command_payload_or_firmware_bytes"
        ])


if __name__ == "__main__":
    unittest.main()
