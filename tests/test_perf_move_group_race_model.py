from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import subprocess
import sys
import unittest
from pathlib import Path

TOOL = Path(__file__).parents[1] / "tools" / "uk_fw" / "perf_move_group_race_model.py"
SPEC = importlib.util.spec_from_file_location("perf_move_group_race_model", TOOL)
assert SPEC and SPEC.loader
MODEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODEL)


class PerfMoveGroupRaceModelTests(unittest.TestCase):
    def test_pre_recorded_state_retains_candidate_without_overstating_impact(self) -> None:
        result = MODEL.classify_move_group(**MODEL.PRE_RECORDED_TARGET_STATE)
        self.assertTrue(result["affected_move_group_path_present"])
        self.assertFalse(result["complete_reference_identity_fix_present"])
        self.assertFalse(result["complete_upstream_fix_effects_present"])
        self.assertTrue(result["cve_2017_6001_static_candidate"])
        self.assertTrue(result["safe_single_context_pattern_does_not_close_move_path"])
        for name in (
            "installed_kernel_identity_observed",
            "runtime_perf_event_paranoid_observed",
            "hardware_pmu_available_observed",
            "unprivileged_software_group_creation_observed",
            "concurrent_move_group_race_observed",
            "stale_or_dead_context_use_observed",
            "kernel_crash_observed",
            "controlled_kernel_memory_corruption_observed",
            "privilege_escalation_observed",
            "unrestricted_root_observed",
            "persistence_observed",
        ):
            self.assertIsNone(result[name])

    def test_exhaustive_boolean_domain_matches_exact_formulas(self) -> None:
        names = tuple(MODEL.PRE_RECORDED_TARGET_STATE)
        for bits in itertools.product((False, True), repeat=len(names)):
            state = dict(zip(names, bits))
            with self.subTest(bits=bits):
                result = MODEL.classify_move_group(**state)
                affected = all(
                    state[name]
                    for name in (
                        "perf_events_compiled",
                        "perf_event_open_syscall_present",
                        "software_group_to_hardware_context_move_present",
                        "group_context_loaded_before_double_mutex_wait",
                    )
                )
                identity_fix = all(
                    state[name]
                    for name in (
                        "group_context_nonzero_reference_acquired_before_wait",
                        "group_context_revalidated_after_double_mutex_lock",
                        "changed_group_context_retries_lock_acquisition",
                    )
                )
                complete = identity_fix and state["post_lock_group_move_state_revalidated"]
                self.assertEqual(result["affected_move_group_path_present"], affected)
                self.assertEqual(result["complete_reference_identity_fix_present"], identity_fix)
                self.assertEqual(result["complete_upstream_fix_effects_present"], complete)
                self.assertEqual(result["cve_2017_6001_static_candidate"], affected and not complete)
                self.assertEqual(
                    result["safe_single_context_pattern_does_not_close_move_path"],
                    state["existing_single_context_helper_uses_reference_lock_revalidate_retry"]
                    and affected
                    and not complete,
                )

    def test_single_context_helper_comparison_tracks_full_move_path_gap(self) -> None:
        state = dict(MODEL.PRE_RECORDED_TARGET_STATE)
        state.update(
            group_context_nonzero_reference_acquired_before_wait=True,
            group_context_revalidated_after_double_mutex_lock=True,
            changed_group_context_retries_lock_acquisition=True,
            post_lock_group_move_state_revalidated=False,
        )
        result = MODEL.classify_move_group(**state)
        self.assertTrue(result["complete_reference_identity_fix_present"])
        self.assertFalse(result["complete_upstream_fix_effects_present"])
        self.assertTrue(result["cve_2017_6001_static_candidate"])
        self.assertTrue(result["safe_single_context_pattern_does_not_close_move_path"])

        state["software_group_to_hardware_context_move_present"] = False
        result = MODEL.classify_move_group(**state)
        self.assertFalse(result["affected_move_group_path_present"])
        self.assertFalse(result["cve_2017_6001_static_candidate"])
        self.assertFalse(result["safe_single_context_pattern_does_not_close_move_path"])

    def test_rejects_wrong_keys_and_non_boolean_values(self) -> None:
        state = dict(MODEL.PRE_RECORDED_TARGET_STATE)
        del state["perf_events_compiled"]
        with self.assertRaisesRegex(MODEL.ModelError, "state keys mismatch"):
            MODEL.classify_move_group(**state)
        state = dict(MODEL.PRE_RECORDED_TARGET_STATE)
        state["perf_events_compiled"] = 1
        with self.assertRaisesRegex(MODEL.ModelError, "must be a boolean"):
            MODEL.classify_move_group(**state)

    def test_report_is_deterministic_and_has_no_operational_fields(self) -> None:
        report = MODEL.build_report()
        raw = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "7d12b7cd0cf1ae0a7b64336a823d96c633255e48106eb1079b1f6936ef2e2eca",
        )
        flattened = raw.lower()
        for forbidden in (
            b"sample_period",
            b"group_fd",
            b"sched_yield",
            b"pthread",
            b"ioctl",
            b"shellcode",
        ):
            self.assertNotIn(forbidden, flattened)

    def test_cli_rejects_partial_duplicate_alias_and_non_boolean_input(self) -> None:
        option = "--perf-events-compiled"
        cases = (
            ([option, "true"], "all perf move-group state arguments"),
            ([option, "true", option, "false"], "may be specified only once"),
            (["--perf-events", "true"], "unrecognized arguments"),
            ([option, "yes"], "expected true or false"),
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

    def test_cli_bytes_are_independent_of_pythonioencoding(self) -> None:
        import os

        outputs = []
        for encoding in ("ascii", "latin-1", "utf-16"):
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = encoding
            run = subprocess.run(
                [sys.executable, str(TOOL)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            outputs.append(run.stdout)
            self.assertTrue(run.stdout.endswith(b"\n"))
            json.loads(run.stdout.decode("utf-8"))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[1], outputs[2])


if __name__ == "__main__":
    unittest.main()
