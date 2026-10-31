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
TOOL = ROOT / "tools" / "uk_fw" / "flic_writer_bounds_model.py"
SPEC = importlib.util.spec_from_file_location("flic_writer_bounds_model", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
OPTIONS = tuple(MODULE.PRE_RECORDED_TARGET_STATE)
NULL_RESULTS = (
    "production_media_delivery_observed",
    "parser_execution_observed",
    "out_of_bounds_write_observed",
    "code_execution_observed",
    "privilege_escalation_observed",
    "persistence_observed",
)


def cli_args(state: dict[str, bool]) -> list[str]:
    args: list[str] = []
    for name in OPTIONS:
        args.extend([f"--{name.replace('_', '-')}", str(state[name]).lower()])
    return args


class FlicWriterBoundsModelTests(unittest.TestCase):
    def test_pre_recorded_state_has_complete_reviewed_effect(self) -> None:
        result = MODULE.build_report()["pre_recorded_target_classification"]
        self.assertTrue(result["complete_reviewed_byte_reader_writer_effect"])
        self.assertTrue(
            result["named_flic_write_bounds_family_rejected_by_supplied_effects"]
        )
        self.assertTrue(
            result["cve_2016_9807_invalid_read_rejected_by_supplied_effects"]
        )
        for key in NULL_RESULTS:
            self.assertIsNone(result[key])

    def test_complete_boolean_matrix_requires_every_fact(self) -> None:
        for values in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, values))
            result = MODULE.classify_flic_bounds(**state)
            expected = all(values)
            with self.subTest(state=state):
                self.assertEqual(
                    result["complete_reviewed_byte_reader_writer_effect"], expected
                )
                self.assertEqual(
                    result["named_flic_write_bounds_family_rejected_by_supplied_effects"],
                    expected,
                )
                self.assertEqual(
                    result["cve_2016_9807_invalid_read_rejected_by_supplied_effects"],
                    expected,
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
                MODULE.classify_flic_bounds(**state)
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state.pop(OPTIONS[0])
        with self.assertRaisesRegex(MODULE.ModelError, "keys mismatch"):
            MODULE.classify_flic_bounds(**state)
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state["unexpected"] = True
        with self.assertRaisesRegex(MODULE.ModelError, "keys mismatch"):
            MODULE.classify_flic_bounds(**state)

    def test_cli_accepts_only_complete_state(self) -> None:
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        good = subprocess.run(
            [sys.executable, str(TOOL), *cli_args(state)], capture_output=True,
            check=False,
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertTrue(json.loads(good.stdout)["classification"][
            "named_flic_write_bounds_family_rejected_by_supplied_effects"
        ])
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
            hashlib.sha256(outputs[0]).hexdigest(),
            "cae4cff4233aa2739d563956624065d1d55ce83c82ff595b6d7383662cee701e",
        )

    def test_report_contains_no_operational_material(self) -> None:
        encoded = json.dumps(MODULE.build_report(), sort_keys=True)
        for forbidden in ("0xffffffff", "gst-launch", "filesrc", "hex bytes"):
            self.assertNotIn(forbidden, encoded)
        boundary = MODULE.build_report()["claim_boundary"]
        self.assertTrue(boundary["inputs_are_boolean_only"])
        self.assertTrue(boundary[
            "emits_no_media_compressed_data_parser_input_command_target_path_executable_payload_or_trigger"
        ])


if __name__ == "__main__":
    unittest.main()
