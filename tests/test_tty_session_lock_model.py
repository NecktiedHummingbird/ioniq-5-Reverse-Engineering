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
TOOL = ROOT / "tools" / "uk_fw" / "tty_session_lock_model.py"
SPEC = importlib.util.spec_from_file_location("tty_session_lock_model", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
OPTIONS = tuple(MODULE.PRE_RECORDED_TARGET_STATE)
LOCK_FACTS = OPTIONS[:4]


def cli_args(state: dict[str, bool]) -> list[str]:
    args: list[str] = []
    for name in OPTIONS:
        args.extend([f"--{name.replace('_', '-')}", str(state[name]).lower()])
    return args


class TtySessionLockModelTests(unittest.TestCase):
    def test_pre_recorded_state_has_defect_but_not_full_preemption(self) -> None:
        report = MODULE.build_report()
        result = report["pre_recorded_target_classification"]
        self.assertTrue(result["cve_2020_29660_locking_premise_present"])
        self.assertFalse(result["config_preempt_full"])
        self.assertTrue(result["config_smp"])
        self.assertFalse(result["upstream_documented_preempt_leak_premise"])
        self.assertTrue(result["locking_premise_and_smp_configuration"])
        self.assertIsNone(result["harmful_interleaving_observed"])
        self.assertIsNone(result["four_byte_freed_memory_read_observed"])
        self.assertIsNone(result["privilege_escalation"])

    def test_complete_boolean_matrix_preserves_logic_and_unknown_outcomes(self) -> None:
        for values in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, values))
            result = MODULE.classify_tty_session_locking(**state)
            premise = all(state[name] for name in LOCK_FACTS)
            with self.subTest(state=state):
                self.assertEqual(
                    result["cve_2020_29660_locking_premise_present"], premise
                )
                self.assertEqual(result["config_preempt_full"], state["config_preempt_full"])
                self.assertEqual(result["config_smp"], state["config_smp"])
                self.assertEqual(
                    result["upstream_documented_preempt_leak_premise"],
                    premise and state["config_preempt_full"],
                )
                self.assertEqual(
                    result["locking_premise_and_smp_configuration"],
                    premise and state["config_smp"],
                )
                for key in (
                    "runtime_pty_reachability_observed",
                    "harmful_interleaving_observed",
                    "four_byte_freed_memory_read_observed",
                    "privilege_escalation",
                ):
                    self.assertIsNone(result[key])

    def test_non_boolean_rejected_in_every_position(self) -> None:
        for name in OPTIONS:
            state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
            state[name] = 1
            with self.subTest(name=name), self.assertRaisesRegex(
                MODULE.ModelError, "must be a boolean"
            ):
                MODULE.classify_tty_session_locking(**state)

    def test_cli_accepts_complete_mixed_state(self) -> None:
        state = {
            "tiocgsid_reads_session_without_ctrl_lock_or_reference": True,
            "pid_vnr_dereferences_the_supplied_pid": False,
            "writer_releases_session_reference_before_clearing_or_replacing_field": True,
            "upstream_fix_effect_absent": False,
            "config_preempt_full": True,
            "config_smp": False,
        }
        proc = subprocess.run(
            [sys.executable, str(TOOL), *cli_args(state)],
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(parsed["classification"]["input"], state)

    def test_cli_rejects_partial_duplicate_and_malformed_arguments(self) -> None:
        cases = (
            ["--config-smp", "true"],
            ["--config-smp", "true", "--config-smp", "true"],
            ["--config-smp", "true", "--config-smp", "false"],
            ["--config-smp", "maybe"],
            ["--config-smp"],
            ["--config-sm", "true"],
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
            "453e0fee85ba1c3bc675d4322bf14e240ef4d659beb4cffb7a892cf04c015b46",
        )

    def test_report_claim_boundary_matches_emitted_content(self) -> None:
        report = MODULE.build_report()
        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn("0xffffffff", encoded)
        self.assertNotIn("virtual_addresses", encoded)
        boundary = report["claim_boundary"]
        self.assertTrue(boundary["inputs_are_boolean_only"])
        self.assertTrue(
            boundary[
                "emits_no_trigger_command_race_schedule_payload_instructions_or_firmware_bytes"
            ]
        )
        for result_name in ("pre_recorded_target_classification",):
            result = report[result_name]
            self.assertIsNone(result["harmful_interleaving_observed"])
            self.assertIsNone(result["four_byte_freed_memory_read_observed"])
            self.assertIsNone(result["privilege_escalation"])


if __name__ == "__main__":
    unittest.main()
