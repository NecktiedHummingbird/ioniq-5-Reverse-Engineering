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
TOOL = ROOT / "tools" / "uk_fw" / "inotify_name_snapshot_model.py"
SPEC = importlib.util.spec_from_file_location("inotify_name_snapshot_model", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
OPTIONS = tuple(MODULE.PRE_RECORDED_TARGET_STATE)
FIX_FACTS = OPTIONS[1:6]


def cli_args(state: dict[str, bool]) -> list[str]:
    args: list[str] = []
    for name in OPTIONS:
        args.extend([f"--{name.replace('_', '-')}", str(state[name]).lower()])
    return args


class InotifyNameSnapshotModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_cve_specific_mutable_name_premise(self) -> None:
        report = MODULE.build_report()
        result = report["pre_recorded_target_classification"]
        self.assertTrue(result["snapshot_fix_effect_present"])
        self.assertFalse(result["cve_2017_7533_mutable_name_premise_present"])
        self.assertTrue(result["cve_2017_7533_rejected_by_supplied_fix_effects"])
        for key in (
            "runtime_inotify_and_rename_reachability_observed",
            "harmful_interleaving_observed",
            "memory_corruption_observed",
            "privilege_escalation_observed",
            "persistence_observed",
        ):
            self.assertIsNone(result[key])

    def test_complete_boolean_matrix_preserves_independent_premises(self) -> None:
        for values in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, values))
            result = MODULE.classify_name_snapshot(**state)
            fix = all(state[name] for name in FIX_FACTS)
            mutable = (
                state["inotify_separate_length_and_copy_present"]
                and state["mutable_dentry_name_reaches_inotify"]
            )
            rejected = (
                state["inotify_separate_length_and_copy_present"]
                and fix
                and not state["mutable_dentry_name_reaches_inotify"]
            )
            with self.subTest(state=state):
                self.assertEqual(result["snapshot_fix_effect_present"], fix)
                self.assertEqual(
                    result["cve_2017_7533_mutable_name_premise_present"], mutable
                )
                self.assertEqual(
                    result["cve_2017_7533_rejected_by_supplied_fix_effects"],
                    rejected,
                )
                for key in (
                    "runtime_inotify_and_rename_reachability_observed",
                    "harmful_interleaving_observed",
                    "memory_corruption_observed",
                    "privilege_escalation_observed",
                    "persistence_observed",
                ):
                    self.assertIsNone(result[key])

    def test_non_boolean_and_key_mismatch_rejected(self) -> None:
        for name in OPTIONS:
            state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
            state[name] = 1
            with self.subTest(name=name), self.assertRaisesRegex(
                MODULE.ModelError, "must be a boolean"
            ):
                MODULE.classify_name_snapshot(**state)
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state.pop(OPTIONS[0])
        with self.assertRaisesRegex(MODULE.ModelError, "keys mismatch"):
            MODULE.classify_name_snapshot(**state)
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state["unexpected"] = True
        with self.assertRaisesRegex(MODULE.ModelError, "keys mismatch"):
            MODULE.classify_name_snapshot(**state)

    def test_cli_accepts_complete_state(self) -> None:
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        proc = subprocess.run(
            [sys.executable, str(TOOL), *cli_args(state)],
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(parsed["classification"]["input"], state)
        self.assertTrue(
            parsed["classification"][
                "cve_2017_7533_rejected_by_supplied_fix_effects"
            ]
        )

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
            "08b97fdaee4272a4ecc337eeed1eb7831f56a242d374912e477b97b2764a9df1",
        )

    def test_report_contains_no_operational_material(self) -> None:
        encoded = json.dumps(MODULE.build_report(), sort_keys=True)
        self.assertNotIn("0xffffffff", encoded)
        self.assertNotIn("rename(", encoded)
        self.assertNotIn("inotify_add_watch", encoded)
        boundary = MODULE.build_report()["claim_boundary"]
        self.assertTrue(boundary["inputs_are_boolean_only"])
        self.assertTrue(
            boundary[
                "emits_no_filename_command_race_schedule_trigger_payload_instructions_or_firmware_bytes"
            ]
        )


if __name__ == "__main__":
    unittest.main()
