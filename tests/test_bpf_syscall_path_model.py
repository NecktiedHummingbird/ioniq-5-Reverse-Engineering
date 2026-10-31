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
TOOL = ROOT / "tools/uk_fw/bpf_syscall_path_model.py"
SPEC = importlib.util.spec_from_file_location("bpf_syscall_path_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OPTIONS = tuple(M.PRE_RECORDED_TARGET_STATE)
ABSENCE_FACTS = (
    "public_cve_uses_syscall_ebpf_verifier_path",
    "bpf_syscall_config_enabled",
    "sys_bpf_is_enosys_stub",
    "native_syscall_slot_targets_enosys_stub",
    "functional_bpf_syscall_path_present",
)
NULL_FIELDS = {
    "other_ebpf_entry_cve_applicability_established",
    "verifier_internals_audited",
    "installed_device_identity_observed",
    "runtime_dispatch_result_observed",
    "verifier_execution_observed",
    "memory_corruption_observed",
    "privilege_escalation_observed",
    "root_observed",
    "persistence_observed",
}
EXPECTED_FIELDS = {
    "input",
    "complete_named_syscall_prerequisite_absence_present",
    "named_syscall_ebpf_verifier_path_available",
    "cve_2017_16995_rejected_for_named_syscall_path",
    "cve_2017_16995_not_rejected_for_named_syscall_path_by_complete_absence",
    "alternate_ebpf_verifier_entry_path_presence",
    "bpf_core_config_enabled",
    "bpf_jit_config_enabled",
    "classic_bpf_compiled",
    "general_bpf_absence_established",
    *NULL_FIELDS,
}


def args_for(state: dict[str, bool]) -> list[str]:
    result: list[str] = []
    for name in OPTIONS:
        result += [f"--{name.replace('_', '-')}", str(state[name]).lower()]
    return result


class BpfSyscallPathModelTests(unittest.TestCase):
    def test_pre_recorded_state_rejects_only_named_path(self) -> None:
        result = M.classify_bpf_syscall_path(**M.PRE_RECORDED_TARGET_STATE)
        self.assertTrue(result["complete_named_syscall_prerequisite_absence_present"])
        self.assertFalse(result["named_syscall_ebpf_verifier_path_available"])
        self.assertTrue(result["cve_2017_16995_rejected_for_named_syscall_path"])
        self.assertIsNone(result["alternate_ebpf_verifier_entry_path_presence"])
        self.assertTrue(result["classic_bpf_compiled"])
        self.assertFalse(result["general_bpf_absence_established"])
        self.assertIsNone(result["verifier_internals_audited"])

    def test_exhaustive_domain_and_every_classification_field(self) -> None:
        for bits in itertools.product((False, True), repeat=len(OPTIONS)):
            state = dict(zip(OPTIONS, bits))
            with self.subTest(bits=bits):
                result = M.classify_bpf_syscall_path(**state)
                functional = state["functional_bpf_syscall_path_present"]
                absent = (
                    state["public_cve_uses_syscall_ebpf_verifier_path"]
                    and not state["bpf_syscall_config_enabled"]
                    and state["sys_bpf_is_enosys_stub"]
                    and state["native_syscall_slot_targets_enosys_stub"]
                    and not functional
                )
                named = True if functional else (False if absent else None)
                alternate = (
                    True
                    if state["alternate_ebpf_verifier_entry_path_present"]
                    else None
                )
                any_bpf = (
                    state["classic_bpf_compiled"]
                    or functional
                    or state["alternate_ebpf_verifier_entry_path_present"]
                )

                self.assertEqual(set(result), EXPECTED_FIELDS)
                self.assertEqual(result["input"], state)
                self.assertEqual(
                    result["complete_named_syscall_prerequisite_absence_present"],
                    absent,
                )
                self.assertEqual(
                    result["named_syscall_ebpf_verifier_path_available"], named
                )
                self.assertEqual(
                    result["cve_2017_16995_rejected_for_named_syscall_path"], absent
                )
                self.assertEqual(
                    result[
                        "cve_2017_16995_not_rejected_for_named_syscall_path_by_complete_absence"
                    ],
                    not absent,
                )
                self.assertEqual(
                    result["alternate_ebpf_verifier_entry_path_presence"], alternate
                )
                self.assertEqual(
                    result["bpf_core_config_enabled"],
                    state["bpf_core_config_enabled"],
                )
                self.assertEqual(
                    result["bpf_jit_config_enabled"],
                    state["bpf_jit_config_enabled"],
                )
                self.assertEqual(
                    result["classic_bpf_compiled"], state["classic_bpf_compiled"]
                )
                self.assertEqual(
                    result["general_bpf_absence_established"],
                    False if any_bpf else None,
                )
                for name in NULL_FIELDS:
                    self.assertIsNone(result[name])

    def test_each_named_path_absence_fact_is_required(self) -> None:
        for name in ABSENCE_FACTS:
            state = dict(M.PRE_RECORDED_TARGET_STATE)
            state[name] = not state[name]
            with self.subTest(name=name):
                result = M.classify_bpf_syscall_path(**state)
                self.assertFalse(
                    result["cve_2017_16995_rejected_for_named_syscall_path"]
                )
                if name == "functional_bpf_syscall_path_present":
                    self.assertTrue(
                        result["named_syscall_ebpf_verifier_path_available"]
                    )
                else:
                    self.assertIsNone(
                        result["named_syscall_ebpf_verifier_path_available"]
                    )

    def test_alternate_entry_is_explicit_but_does_not_broaden_verdict(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state["alternate_ebpf_verifier_entry_path_present"] = True
        result = M.classify_bpf_syscall_path(**state)
        self.assertTrue(result["alternate_ebpf_verifier_entry_path_presence"])
        self.assertTrue(result["cve_2017_16995_rejected_for_named_syscall_path"])
        self.assertIsNone(result["other_ebpf_entry_cve_applicability_established"])
        self.assertFalse(result["general_bpf_absence_established"])

    def test_rejects_wrong_keys_and_non_booleans(self) -> None:
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        del state[OPTIONS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_bpf_syscall_path(**state)
        state = dict(M.PRE_RECORDED_TARGET_STATE)
        state[OPTIONS[0]] = 1
        with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
            M.classify_bpf_syscall_path(**state)

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
            ([option, "true"], "all BPF syscall-path arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--public-cve-uses-syscall", "true"], "unrecognized arguments"),
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
            "48e9d32f190d56c1b0a0b8a3ee5240a2964d15e45a75d18d2d9f1a7ca531295b",
        )

    def test_report_contains_no_operational_material(self) -> None:
        report = M.build_report()
        encoded = json.dumps(report, sort_keys=True).lower()
        for forbidden in (
            "0xffffffff",
            "syscall(",
            "bpf(",
            "socket(",
            "struct bpf_insn",
            "cb220781ffffffff",
            "race schedule",
            "payload bytes",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, encoded)
        self.assertTrue(
            report["claim_boundary"][
                "emits_no_address_invocation_verifier_input_endpoint_command_trigger_target_bytes_race_or_payload"
            ]
        )


if __name__ == "__main__":
    unittest.main()
