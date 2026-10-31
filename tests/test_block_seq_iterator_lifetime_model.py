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
TOOL = ROOT / "tools" / "uk_fw" / "block_seq_iterator_lifetime_model.py"
SPEC = importlib.util.spec_from_file_location("block_seq_iterator_lifetime_model", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
OPTIONS = tuple(MODULE.PRE_RECORDED_TARGET_STATE)


def cli_args(state: dict[str, bool]) -> list[str]:
    args: list[str] = []
    for name in OPTIONS:
        args.extend([f"--{name.replace('_', '-')}", str(state[name]).lower()])
    return args


class BlockSeqIteratorLifetimeModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_stale_cleanup_premise(self) -> None:
        result = MODULE.classify_iterator_lifetime(**MODULE.PRE_RECORDED_TARGET_STATE)
        self.assertTrue(result["repeated_cleanup_path_present"])
        self.assertFalse(
            result["cve_2016_7910_stale_iterator_cleanup_premise_present"]
        )
        self.assertTrue(
            result["cve_2016_7910_rejected_by_supplied_private_clear_effect"]
        )
        self.assertFalse(
            result["cve_2016_7910_not_rejected_by_supplied_private_clear_effect"]
        )
        for name in (
            "runtime_proc_entry_reachability_observed",
            "iterator_allocation_failure_observed",
            "stale_iterator_dereference_observed",
            "double_free_observed",
            "kernel_crash_observed",
            "memory_corruption_observed",
            "privilege_escalation_observed",
            "persistence_observed",
        ):
            self.assertIsNone(result[name])

    def test_exhaustive_boolean_domain_matches_formulas_or_rejects_inconsistency(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            with self.subTest(bits=bits):
                inconsistent = (
                    state["stop_clears_private_after_free"]
                    and state["stop_retains_freed_iterator_in_private"]
                )
                if inconsistent:
                    with self.assertRaisesRegex(MODULE.ModelError, "cannot both clear"):
                        MODULE.classify_iterator_lifetime(**state)
                    continue
                result = MODULE.classify_iterator_lifetime(**state)
                repeated = all(
                    state[name]
                    for name in (
                        "successful_start_stores_iterator_in_private",
                        "stop_loads_iterator_from_private",
                        "stop_exits_iterator",
                        "stop_frees_iterator",
                        "later_start_allocation_failure_skips_private_store",
                        "same_seq_file_stop_runs_after_start_failure",
                    )
                )
                rejected = repeated and state["stop_clears_private_after_free"]
                if not repeated or rejected:
                    premise = False
                elif state["stop_retains_freed_iterator_in_private"]:
                    premise = True
                else:
                    premise = None
                self.assertEqual(result["repeated_cleanup_path_present"], repeated)
                self.assertEqual(
                    result["cve_2016_7910_stale_iterator_cleanup_premise_present"],
                    premise,
                )
                self.assertEqual(
                    result[
                        "cve_2016_7910_rejected_by_supplied_private_clear_effect"
                    ],
                    rejected,
                )
                self.assertEqual(
                    result[
                        "cve_2016_7910_not_rejected_by_supplied_private_clear_effect"
                    ],
                    repeated and not rejected,
                )

    def test_explicit_retained_pointer_classifies_premise_present(self) -> None:
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state["stop_clears_private_after_free"] = False
        state["stop_retains_freed_iterator_in_private"] = True
        result = MODULE.classify_iterator_lifetime(**state)
        self.assertTrue(
            result["cve_2016_7910_stale_iterator_cleanup_premise_present"]
        )
        self.assertFalse(
            result["cve_2016_7910_rejected_by_supplied_private_clear_effect"]
        )

    def test_incomplete_fix_facts_remain_unknown_not_affected(self) -> None:
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state["stop_clears_private_after_free"] = False
        result = MODULE.classify_iterator_lifetime(**state)
        self.assertIsNone(
            result["cve_2016_7910_stale_iterator_cleanup_premise_present"]
        )
        self.assertTrue(
            result["cve_2016_7910_not_rejected_by_supplied_private_clear_effect"]
        )

    def test_absent_repeated_cleanup_path_makes_premise_false(self) -> None:
        for name in (
            "successful_start_stores_iterator_in_private",
            "stop_loads_iterator_from_private",
            "stop_exits_iterator",
            "stop_frees_iterator",
            "later_start_allocation_failure_skips_private_store",
            "same_seq_file_stop_runs_after_start_failure",
        ):
            state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
            state[name] = False
            with self.subTest(name=name):
                result = MODULE.classify_iterator_lifetime(**state)
                self.assertFalse(result["repeated_cleanup_path_present"])
                self.assertFalse(
                    result["cve_2016_7910_stale_iterator_cleanup_premise_present"]
                )

    def test_rejects_wrong_keys_non_boolean_and_inconsistent_values(self) -> None:
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(MODULE.ModelError, "state keys mismatch"):
            MODULE.classify_iterator_lifetime(**state)
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(MODULE.ModelError, "must be a boolean"):
            MODULE.classify_iterator_lifetime(**state)
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state["stop_retains_freed_iterator_in_private"] = True
        with self.assertRaisesRegex(MODULE.ModelError, "cannot both clear"):
            MODULE.classify_iterator_lifetime(**state)

    def test_cli_accepts_complete_state(self) -> None:
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        run = subprocess.run(
            [sys.executable, str(TOOL), *cli_args(state)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        parsed = json.loads(run.stdout.decode("utf-8"))
        self.assertEqual(parsed["classification"]["input"], state)

    def test_cli_rejects_partial_duplicate_alias_non_boolean_and_inconsistent_input(self) -> None:
        option = f"--{OPTIONS[0].replace('_', '-')}"
        inconsistent = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        inconsistent["stop_retains_freed_iterator_in_private"] = True
        cases = (
            ([option, "true"], "all block seq-iterator lifetime arguments"),
            ([option, "true", option, "false"], "may be specified only once"),
            (["--successful-start", "true"], "unrecognized arguments"),
            ([option, "yes"], "expected true or false"),
            (cli_args(inconsistent), "cannot both clear"),
        )
        for args, message in cases:
            with self.subTest(args=args):
                run = subprocess.run(
                    [sys.executable, str(TOOL), *args],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertNotEqual(run.returncode, 0)
                self.assertIn(message, run.stderr)

    def test_default_output_is_deterministic_utf8_lf(self) -> None:
        expected = (
            json.dumps(MODULE.build_report(), indent=2, sort_keys=True).encode("utf-8")
            + b"\n"
        )
        outputs = []
        for encoding in ("ascii:strict", "latin-1:strict", "utf-16:strict"):
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = encoding
            run = subprocess.run(
                [sys.executable, str(TOOL)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            self.assertEqual(run.stdout, expected)
            self.assertTrue(run.stdout.endswith(b"\n"))
            self.assertNotIn(b"\r", run.stdout)
            outputs.append(run.stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[1], outputs[2])
        # Updated only when a reviewed schema/output change is intentional.
        self.assertEqual(
            hashlib.sha256(outputs[0]).hexdigest(),
            "e32657eeb22a870d596956c9f4fb2450dd8d3539c95fff646f6534491aee443b",
        )

    def test_report_contains_no_operational_material(self) -> None:
        encoded = json.dumps(MODULE.build_report(), sort_keys=True).lower()
        for forbidden in (
            "0xffffffff",
            "/proc/",
            "pread(",
            "kmalloc(",
            "memory pressure",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertTrue(
            MODULE.build_report()["claim_boundary"][
                "emits_no_path_file_operation_allocation_schedule_command_payload_instructions_or_firmware_bytes"
            ]
        )


if __name__ == "__main__":
    unittest.main()
