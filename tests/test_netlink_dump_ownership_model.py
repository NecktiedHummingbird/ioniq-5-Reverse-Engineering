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
TOOL = ROOT / "tools" / "uk_fw" / "netlink_dump_ownership_model.py"
SPEC = importlib.util.spec_from_file_location("netlink_dump_ownership_model", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
OPTIONS = tuple(MODULE.PRE_RECORDED_TARGET_STATE)
FIX_FACTS = OPTIONS[2:6]


def cli_args(state: dict[str, bool]) -> list[str]:
    args: list[str] = []
    for name in OPTIONS:
        args.extend([f"--{name.replace('_', '-')}", str(state[name]).lower()])
    return args


class NetlinkDumpOwnershipModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_mutable_callback_cleanup_premise(self) -> None:
        result = MODULE.classify_dump_ownership(**MODULE.PRE_RECORDED_TARGET_STATE)
        self.assertTrue(result["complete_saved_object_cleanup_present"])
        self.assertFalse(
            result["cve_2016_9806_mutable_callback_cleanup_premise_present"]
        )
        self.assertTrue(result["cve_2016_9806_rejected_by_supplied_fix_effects"])
        self.assertFalse(
            result[
                "cve_2016_9806_not_rejected_by_complete_saved_object_effects"
            ]
        )
        for name in (
            "runtime_netlink_dump_reachability_observed",
            "concurrent_replacement_observed",
            "old_or_new_skb_double_free_observed",
            "kernel_crash_observed",
            "memory_corruption_observed",
            "privilege_escalation_observed",
            "persistence_observed",
        ):
            self.assertIsNone(result[name])

    def test_exhaustive_boolean_domain_matches_exact_formulas(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            with self.subTest(bits=bits):
                result = MODULE.classify_dump_ownership(**state)
                complete = all(state[name] for name in FIX_FACTS)
                window = (
                    state["netlink_dump_completion_path_present"]
                    and state["callback_fields_may_change_after_mutex_unlock"]
                    and state["captured_objects_released_after_mutex_unlock"]
                )
                premise = False if not window or complete else None
                rejected = window and complete
                not_rejected = window and not complete
                self.assertEqual(
                    result["complete_saved_object_cleanup_present"], complete
                )
                self.assertEqual(
                    result["post_unlock_mutable_callback_window_present"], window
                )
                self.assertEqual(
                    result[
                        "cve_2016_9806_mutable_callback_cleanup_premise_present"
                    ],
                    premise,
                )
                self.assertEqual(
                    result["cve_2016_9806_rejected_by_supplied_fix_effects"],
                    rejected,
                )
                self.assertEqual(
                    result[
                        "cve_2016_9806_not_rejected_by_complete_saved_object_effects"
                    ],
                    not_rejected,
                )

    def test_each_saved_object_fix_effect_is_required_for_conclusive_rejection(self) -> None:
        for name in FIX_FACTS:
            state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
            state[name] = False
            with self.subTest(name=name):
                result = MODULE.classify_dump_ownership(**state)
                self.assertFalse(result["complete_saved_object_cleanup_present"])
                self.assertIsNone(
                    result[
                        "cve_2016_9806_mutable_callback_cleanup_premise_present"
                    ]
                )
                self.assertFalse(
                    result["cve_2016_9806_rejected_by_supplied_fix_effects"]
                )
                self.assertTrue(
                    result[
                        "cve_2016_9806_not_rejected_by_complete_saved_object_effects"
                    ]
                )

    def test_cleanup_under_mutex_has_no_post_unlock_race_window(self) -> None:
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state["captured_objects_released_after_mutex_unlock"] = False
        result = MODULE.classify_dump_ownership(**state)
        self.assertTrue(result["complete_saved_object_cleanup_present"])
        self.assertFalse(result["post_unlock_mutable_callback_window_present"])
        self.assertFalse(
            result["cve_2016_9806_mutable_callback_cleanup_premise_present"]
        )
        self.assertFalse(result["cve_2016_9806_rejected_by_supplied_fix_effects"])
        self.assertFalse(
            result[
                "cve_2016_9806_not_rejected_by_complete_saved_object_effects"
            ]
        )

    def test_rejects_wrong_keys_and_non_boolean_values(self) -> None:
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(MODULE.ModelError, "state keys mismatch"):
            MODULE.classify_dump_ownership(**state)
        state = dict(MODULE.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(MODULE.ModelError, "must be a boolean"):
            MODULE.classify_dump_ownership(**state)

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

    def test_cli_rejects_partial_duplicate_alias_and_non_boolean_input(self) -> None:
        option = f"--{OPTIONS[0].replace('_', '-')}"
        cases = (
            ([option, "true"], "all netlink dump ownership arguments"),
            ([option, "true", option, "false"], "may be specified only once"),
            (["--netlink-dump", "true"], "unrecognized arguments"),
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
        self.assertEqual(
            hashlib.sha256(outputs[0]).hexdigest(),
            "76a84531d28215fa7a690bb8d66c27badc8e12825f563a5e94c9938e6f2dca09",
        )

    def test_report_contains_no_operational_material(self) -> None:
        encoded = json.dumps(MODULE.build_report(), sort_keys=True).lower()
        for forbidden in (
            "0xffffffff",
            "sendmsg(",
            "netlink_route",
            "nlmsg_type",
            "socket(",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertTrue(
            MODULE.build_report()["claim_boundary"][
                "emits_no_socket_message_race_schedule_command_payload_instructions_or_firmware_bytes"
            ]
        )


if __name__ == "__main__":
    unittest.main()
