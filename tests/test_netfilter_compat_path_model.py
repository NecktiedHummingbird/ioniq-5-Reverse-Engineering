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
TOOL = ROOT / "tools/uk_fw/netfilter_compat_path_model.py"
SPEC = importlib.util.spec_from_file_location("netfilter_compat_path_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OPTIONS = tuple(M.PRE_RECORDED_TARGET_STATE)


def args_for(state: dict[str, bool]) -> list[str]:
    out: list[str] = []
    for name in OPTIONS:
        out += [f"--{name.replace('_', '-')}", str(state[name]).lower()]
    return out


class NetfilterCompatPathModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_absent_path(self) -> None:
        result = M.classify_compat_path(**M.PRE_RECORDED_TARGET_STATE)
        self.assertTrue(result["complete_compat_prerequisite_absence_present"])
        self.assertFalse(result["compat_netfilter_replace_path_compiled_and_dispatchable"])
        self.assertTrue(result["cve_2016_4997_rejected_by_absent_compat_path"])
        self.assertFalse(result["cve_2016_4997_not_rejected_by_complete_absence"])

    def test_exhaustive_domain_and_all_outputs(self) -> None:
        observed = {
            "installed_kernel_identity_observed",
            "runtime_syscall_filter_observed",
            "compat_setsockopt_request_observed",
            "memory_corruption_observed",
            "privilege_escalation_observed",
            "persistence_observed",
        }
        expected = {
            "input",
            "complete_compat_prerequisite_absence_present",
            "compat_netfilter_replace_path_compiled_and_dispatchable",
            "cve_2016_4997_rejected_by_absent_compat_path",
            "cve_2016_4997_not_rejected_by_complete_absence",
            *observed,
        }
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            with self.subTest(bits=bits):
                result = M.classify_compat_path(**state)
                absent = (
                    state[OPTIONS[0]]
                    and state[OPTIONS[1]]
                    and state[OPTIONS[2]]
                    and state[OPTIONS[3]]
                    and not state[OPTIONS[4]]
                )
                present = (
                    state[OPTIONS[0]]
                    and not state[OPTIONS[1]]
                    and not state[OPTIONS[2]]
                    and not state[OPTIONS[3]]
                    and state[OPTIONS[4]]
                )
                path = False if absent else (True if present else None)
                self.assertEqual(set(result), expected)
                self.assertEqual(result["input"], state)
                self.assertEqual(result["complete_compat_prerequisite_absence_present"], absent)
                self.assertEqual(result["compat_netfilter_replace_path_compiled_and_dispatchable"], path)
                self.assertEqual(result["cve_2016_4997_rejected_by_absent_compat_path"], absent)
                self.assertEqual(result["cve_2016_4997_not_rejected_by_complete_absence"], not absent)
                for name in observed:
                    self.assertIsNone(result[name])

    def test_rejects_wrong_keys_non_booleans_and_partial_cli(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_compat_path(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
            M.classify_compat_path(**state)
        option = f"--{OPTIONS[0].replace('_', '-')}"
        for argv, text in (
            ([option, "true"], "all netfilter compat-path arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--public-cve-requires", "true"], "unrecognized arguments"),
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
                self.assertIn(text, run.stderr)

    def test_cli_complete(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        run = subprocess.run(
            [sys.executable, str(TOOL), *args_for(state)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(json.loads(run.stdout)["classification"]["input"], state)

    def test_default_output_deterministic_utf8_lf(self) -> None:
        expected = json.dumps(M.build_report(), indent=2, sort_keys=True).encode() + b"\n"
        outputs = []
        for encoding in ("ascii:strict", "latin-1:strict", "utf-16:strict"):
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
        self.assertEqual(hashlib.sha256(outputs[0]).hexdigest(), "e5d16ebcb6e7d4841e8c6f741a92dd91889dd002645d59c7699d416c8d933cd5")

    def test_report_has_no_operational_material(self) -> None:
        report = M.build_report()
        encoded = json.dumps(report, sort_keys=True).lower()
        for forbidden in ("0xffffffff", "setsockopt(", "unshare(", "iptables("):
            self.assertNotIn(forbidden, encoded)
        self.assertTrue(
            report["claim_boundary"][
                "emits_no_target_syscall_socket_filter_packet_namespace_command_payload_or_firmware_bytes"
            ]
        )


if __name__ == "__main__":
    unittest.main()
