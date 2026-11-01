from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/uk_fw/appfumo_shell_boundary_model.py"
ARTIFACT = ROOT / "evidence/artifacts/update-candidates/appfumo-shell-boundary-exact-static.asm"
EXACT_ELF = ROOT / "work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf"
EXPECTED_DEFAULT_SHA256 = "7702f40e87033dfb9bbb271b3615c0ec5212d17c16c3965b151306e62b38bfc3"

SPEC = importlib.util.spec_from_file_location("appfumo_shell_boundary_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def args_for(state: dict[str, bool]) -> list[str]:
    argv: list[str] = []
    for name in M.FACTS:
        argv.extend([f"--{name.replace('_', '-')}", str(state[name]).lower()])
    return argv


class AppFumoShellBoundaryModelTests(unittest.TestCase):
    def test_pre_recorded_state_establishes_only_exact_static_structure(self) -> None:
        result = M.classify_shell_boundary(**M.PRE_RECORDED_STATE)
        self.assertTrue(result["exact_static_fact_set_complete"])
        self.assertTrue(result["exact_unquoted_shell_sink_structure_established"])
        self.assertIsNone(result["runtime_shell_syntax_delivery_established"])
        self.assertIsNone(result["runtime_command_success_established"])
        for name in (
            "pathname_influence_established",
            "shell_sensitive_character_survival_established",
            "invocation_reachability_established",
            "authentication_acceptance_established",
            "process_security_context_established",
            "command_success_observed",
            "privilege_or_domain_amplification_observed",
            "root_impact_observed",
            "persistence_observed",
        ):
            self.assertIsNone(result[name], name)

    def test_sink_structure_uses_only_necessary_static_facts(self) -> None:
        for name in M.SINK_STRUCTURE_FACTS:
            state = dict(M.PRE_RECORDED_STATE)
            state[name] = False
            result = M.classify_shell_boundary(**state)
            with self.subTest(name=name):
                self.assertFalse(result["exact_static_fact_set_complete"])
                self.assertIsNone(
                    result["exact_unquoted_shell_sink_structure_established"]
                )
        for name in M.STATIC_OUTCOME_FACTS:
            state = dict(M.PRE_RECORDED_STATE)
            state[name] = False
            result = M.classify_shell_boundary(**state)
            with self.subTest(name=name):
                self.assertFalse(result["exact_static_fact_set_complete"])
                self.assertTrue(
                    result["exact_unquoted_shell_sink_structure_established"]
                )

    def test_runtime_dimensions_do_not_collapse_into_delivery_or_success(self) -> None:
        for name in (
            "pathname_influence_established",
            "invocation_reachability_established",
            "authentication_acceptance_established",
            "process_security_context_established",
            "persistence_observed",
        ):
            state = dict(M.PRE_RECORDED_STATE)
            state[name] = True
            result = M.classify_shell_boundary(**state)
            with self.subTest(name=name):
                self.assertIs(result[name], True)
                self.assertIsNone(result["runtime_shell_syntax_delivery_established"])
                self.assertIsNone(result["runtime_command_success_established"])

    def test_delivery_success_authentication_and_context_are_separate(self) -> None:
        state = dict(M.PRE_RECORDED_STATE)
        state.update(
            pathname_influence_established=True,
            shell_sensitive_character_survival_established=True,
            invocation_reachability_established=True,
        )
        result = M.classify_shell_boundary(**state)
        self.assertTrue(result["runtime_shell_syntax_delivery_established"])
        self.assertIsNone(result["runtime_command_success_established"])
        self.assertIsNone(result["authentication_acceptance_established"])
        self.assertIsNone(result["process_security_context_established"])

        state["command_success_observed"] = True
        result = M.classify_shell_boundary(**state)
        self.assertTrue(result["runtime_shell_syntax_delivery_established"])
        self.assertTrue(result["runtime_command_success_established"])
        self.assertIsNone(result["authentication_acceptance_established"])
        self.assertIsNone(result["process_security_context_established"])

    def test_rejects_causally_contradictory_states(self) -> None:
        contradictions = (
            ("shell_sensitive_character_survival_established",),
            ("command_success_observed",),
            ("invocation_reachability_established", "privilege_or_domain_amplification_observed"),
            (
                "invocation_reachability_established",
                "command_success_observed",
                "root_impact_observed",
            ),
        )
        for enabled in contradictions:
            state = dict(M.PRE_RECORDED_STATE)
            for name in enabled:
                state[name] = True
            with self.subTest(enabled=enabled):
                with self.assertRaisesRegex(M.ModelError, "contradictory state"):
                    M.classify_shell_boundary(**state)

    def test_exhaustive_boolean_state_policy(self) -> None:
        accepted = rejected = 0
        for bits in itertools.product((False, True), repeat=len(M.FACTS)):
            state = dict(zip(M.FACTS, bits, strict=True))
            contradictory = (
                (state["shell_sensitive_character_survival_established"] and not state["pathname_influence_established"])
                or (state["command_success_observed"] and not state["invocation_reachability_established"])
                or (state["privilege_or_domain_amplification_observed"] and not state["command_success_observed"])
                or (state["root_impact_observed"] and not state["privilege_or_domain_amplification_observed"])
            )
            if contradictory:
                with self.assertRaises(M.ModelError):
                    M.classify_shell_boundary(**state)
                rejected += 1
                continue
            result = M.classify_shell_boundary(**state)
            sink = all(state[name] for name in M.SINK_STRUCTURE_FACTS)
            delivery = sink and all(
                state[name]
                for name in (
                    "pathname_influence_established",
                    "shell_sensitive_character_survival_established",
                    "invocation_reachability_established",
                )
            )
            self.assertEqual(
                result["exact_unquoted_shell_sink_structure_established"],
                True if sink else None,
            )
            self.assertEqual(
                result["runtime_shell_syntax_delivery_established"],
                True if delivery else None,
            )
            self.assertEqual(
                result["runtime_command_success_established"],
                True if delivery and state["command_success_observed"] else None,
            )
            accepted += 1
        self.assertEqual(accepted + rejected, 1 << len(M.FACTS))
        self.assertGreater(accepted, 0)
        self.assertGreater(rejected, 0)

    def test_rejects_missing_extra_and_non_boolean_values(self) -> None:
        state = dict(M.PRE_RECORDED_STATE)
        del state[M.FACTS[0]]
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_shell_boundary(**state)
        state = dict(M.PRE_RECORDED_STATE, unexpected=False)
        with self.assertRaisesRegex(M.ModelError, "state keys mismatch"):
            M.classify_shell_boundary(**state)
        for value in (0, 1, None, "true"):
            state = dict(M.PRE_RECORDED_STATE)
            state[M.FACTS[0]] = value  # type: ignore[assignment]
            with self.subTest(value=value):
                with self.assertRaisesRegex(M.ModelError, "must be a boolean"):
                    M.classify_shell_boundary(**state)

    def test_cli_complete_and_fail_closed_cases(self) -> None:
        state = dict(M.PRE_RECORDED_STATE)
        completed = subprocess.run(
            [sys.executable, str(TOOL), *args_for(state)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["classification"]["input"], state)
        option = f"--{M.FACTS[0].replace('_', '-')}"
        for argv, message in (
            ([option, "true"], "all AppFUMO shell-boundary arguments"),
            ([option, "true", option, "false"], "only once"),
            (["--exact-elf", "true"], "unrecognized arguments"),
            ([option, "yes"], "expected true or false"),
        ):
            with self.subTest(argv=argv):
                failed = subprocess.run(
                    [sys.executable, str(TOOL), *argv],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(message, failed.stderr)

    def test_default_output_is_deterministic_utf8_lf(self) -> None:
        expected = json.dumps(M.build_report(), indent=2, sort_keys=True).encode() + b"\n"
        outputs = []
        for encoding in ("ascii:strict", "latin-1:strict", "utf-16:strict"):
            environment = dict(os.environ, PYTHONIOENCODING=encoding)
            completed = subprocess.run(
                [sys.executable, str(TOOL)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            self.assertEqual(completed.stdout, expected)
            self.assertNotIn(b"\r", completed.stdout)
            outputs.append(completed.stdout)
        self.assertEqual(len(set(outputs)), 1)
        self.assertEqual(hashlib.sha256(outputs[0]).hexdigest(), EXPECTED_DEFAULT_SHA256)

    def test_retained_artifact_hash_and_required_anchors(self) -> None:
        raw = ARTIFACT.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(digest, M.STATIC_ARTIFACT_SHA256)
        text = raw.decode("utf-8")
        for anchor in (
            "FDE pc=00100b30...0010110c",
            "FDE pc=001397c0...001398fb",
            "FDE pc=00139900...00139b46",
            "100e0c:",
            "139867:",
            "1398b0:",
            "0x20b4d8",
            "0x20b500",
            "0x20b530",
            "0x20b81c",
            "0x211c8b",
            "0x10281c, 0x102de9, 0x103398",
            "0x16e030",
        ):
            with self.subTest(anchor=anchor):
                self.assertIn(anchor, text)

    @unittest.skipUnless(EXACT_ELF.is_file(), "ignored exact ELF is unavailable")
    def test_exact_elf_identity_calls_and_literal_bytes(self) -> None:
        raw = EXACT_ELF.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), M.EXACT_ELF_SHA256)
        self.assertEqual(len(raw), 5_066_264)
        self.assertEqual(raw[0x100E0C:0x100E11], bytes.fromhex("e8af890300"))
        self.assertEqual(raw[0x139867:0x13986C], bytes.fromhex("e8949feeff"))
        self.assertEqual(raw[0x1398B0:0x1398B5], bytes.fromhex("e82b87eeff"))
        literals = {
            0x20B4D8: b"/app/share/AppUpgrade/DecryptToPIPE\0",
            0x20B500: b"%1 -d %2 %3 0 | pv -q -L 8m | dd of=%4 bs=512\0",
            0x20B530: b"%1 -d %2 %3 0 | dd of=%4 bs=512\0",
            0x20B81C: b" 2>&1\0",
            0x211C8B: b"r\0",
            0x212297: b"%1 -d %2 %3 0\0",
            0x2122A5: b" | dd of=%1 bs=512\0",
        }
        for address, expected in literals.items():
            with self.subTest(address=hex(address)):
                self.assertEqual(raw[address : address + len(expected)], expected)

        instruction_rows = 0
        for line in ARTIFACT.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^\s*([0-9a-f]+): ((?:[0-9a-f]{2} )+)", line)
            if match is None:
                continue
            address = int(match.group(1), 16)
            expected = bytes.fromhex(match.group(2))
            with self.subTest(artifact_instruction=hex(address)):
                self.assertEqual(raw[address : address + len(expected)], expected)
            instruction_rows += 1
        self.assertEqual(instruction_rows, 121)

    def test_report_contains_no_operational_material(self) -> None:
        report = M.build_report()
        self.assertTrue(
            report["claim_boundary"][
                "emits_no_command_target_pathname_payload_trigger_archive_or_update_material"
            ]
        )
        encoded = json.dumps(report, sort_keys=True).lower()
        for forbidden in (
            "decrypttopipe",
            "dd of=",
            "2>&1",
            "/tmp",
            "/update/",
            "pv -q",
        ):
            self.assertNotIn(forbidden, encoded)


if __name__ == "__main__":
    unittest.main()
