from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "uk_fw" / "bench_candidate_triage.py"
SPEC = importlib.util.spec_from_file_location("bench_candidate_triage", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
PYTHON = sys.executable


def sha_json(value: object) -> str:
    raw = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def report(records: list[tuple[str, str]], *, complete: bool = True) -> dict[str, object]:
    by_section: dict[str, list[dict[str, str]]] = {
        name: [] for name in MODULE.EXPECTED_SECTIONS
    }
    by_section["meta"] = [{"key": "schema", "value": MODULE.SCHEMA}]
    by_section["complete"] = [{"key": "result", "value": "complete"}]
    for key, value in records:
        if key == "uname":
            section = "identity"
        elif key == "hash":
            section = "hashes"
        else:
            section = "storage"
        by_section[section].append({"key": key, "value": value})
    sections = []
    for name in MODULE.EXPECTED_SECTIONS:
        section: dict[str, object] = {
            "name": name,
            "complete": True,
            "end_status": 0,
            "records": by_section[name],
            "raw": [],
            "captured_bytes": 0,
        }
        section["sha256"] = sha_json(section)
        sections.append(section)
    value: dict[str, object] = {
        "schema": MODULE.SCHEMA,
        "capture_sha256": "0" * 64,
        "capture_bytes": 0,
        "complete": complete,
        "section_order": list(MODULE.EXPECTED_SECTIONS),
        "sections": sections,
        "facts": {},
        "warnings": [] if complete else ["incomplete"],
    }
    value["canonical_sha256"] = sha_json(value)
    return value


def write_report(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


class BenchCandidateTriageTests(unittest.TestCase):
    def test_classifies_module_name_current_file_and_pty_runtime_gates(self) -> None:
        value = report(
            [
                ("uname", "Linux ihu 4.1.27-abl #1 SMP x86_64 GNU/Linux"),
                ("file", "/dev/ptmx|present|0666|0|0|0|symbolic link|0|0|/dev/pts/ptmx"),
                ("file", "/dev/pts|present|0755|0|0|0|directory|0|0|"),
                ("file", "/dev/pts/ptmx|present|0666|0|0|0|character special file|5|2|"),
                ("mounts", "devpts /dev/pts devpts rw,nosuid,noexec 0 0"),
                ("modules", "unix 28672 12 - Live 0xffffffffa0000000"),
                ("hash", f"{MODULE.UNIX_MODULE_PATH}|{MODULE.UNIX_MODULE_SHA256}"),
            ]
        )
        triage = MODULE.build_triage(value)
        observations = triage["observations"]
        self.assertTrue(observations["kernel_banner_match"])
        self.assertTrue(observations["ptmx_record_world_read_write"])
        self.assertTrue(observations["ptmx_effective_world_read_write"])
        self.assertTrue(observations["ptmx_endpoint_valid"])
        self.assertTrue(observations["devpts_directory_valid"])
        self.assertTrue(observations["devpts_mounted"])
        self.assertTrue(observations["unix_module_name_loaded"])
        self.assertTrue(observations["unix_module_file_hash_matches_recovered"])
        gates = triage["candidate_runtime_gates"]
        self.assertTrue(gates["V-024"]["pty_surface_observed"])
        self.assertTrue(gates["V-025"]["module_name_loaded_and_current_file_matches"])
        self.assertIsNone(gates["V-025"]["loaded_module_bound_to_current_file"])
        self.assertIsNone(gates["V-024"]["race_or_uaf_observed"])

    def test_absent_surfaces_are_false_not_unknown(self) -> None:
        value = report(
            [
                ("uname", "Linux other 5.10.0 x86_64 GNU/Linux"),
                ("file", "/dev/ptmx|absent"),
                ("file", "/dev/pts|absent"),
                ("mounts", "rootfs / ext4 rw 0 0"),
                ("modules", ""),
                ("hash", f"{MODULE.UNIX_MODULE_PATH}|absent"),
            ]
        )
        triage = MODULE.build_triage(value)
        observations = triage["observations"]
        self.assertFalse(observations["kernel_banner_match"])
        self.assertFalse(observations["ptmx"]["present"])
        self.assertFalse(observations["devpts_mounted"])
        self.assertFalse(observations["unix_module_name_loaded"])
        self.assertFalse(observations["unix_module_file_hash_matches_recovered"])
        self.assertFalse(triage["candidate_runtime_gates"]["V-024"]["pty_surface_observed"])
        self.assertFalse(
            triage["candidate_runtime_gates"]["V-025"]
            ["module_name_loaded_and_current_file_matches"]
        )

    def test_false_dominates_unknown_in_three_valued_conjunction(self) -> None:
        value = report([("file", "/dev/ptmx|absent"), ("modules", "")])
        triage = MODULE.build_triage(value)
        self.assertFalse(triage["candidate_runtime_gates"]["V-024"]["pty_surface_observed"])
        self.assertFalse(
            triage["candidate_runtime_gates"]["V-025"]
            ["module_name_loaded_and_current_file_matches"]
        )

    def test_missing_providers_remain_unknown(self) -> None:
        triage = MODULE.build_triage(report([]))
        observations = triage["observations"]
        self.assertIsNone(observations["kernel_banner_match"])
        self.assertIsNone(observations["devpts_mounted"])
        self.assertIsNone(observations["unix_module_name_loaded"])
        self.assertIsNone(observations["unix_module_file_hash_matches_recovered"])
        self.assertIsNone(triage["candidate_runtime_gates"]["V-024"]["pty_surface_observed"])

    def test_wrong_ptmx_type_or_target_does_not_confirm_surface(self) -> None:
        base = [
            ("file", "/dev/pts|present|0755|0|0|0|directory|0|0|"),
            ("file", "/dev/pts/ptmx|present|0666|0|0|0|character special file|5|2|"),
            ("mounts", "devpts /dev/pts devpts rw 0 0"),
        ]
        for ptmx in (
            "/dev/ptmx|present|0666|0|0|0|regular file|0|0|",
            "/dev/ptmx|present|0666|0|0|0|symbolic link|0|0|/tmp/not-ptmx",
        ):
            triage = MODULE.build_triage(report([("file", ptmx), *base]))
            self.assertFalse(triage["observations"]["ptmx_endpoint_valid"])
            self.assertFalse(
                triage["candidate_runtime_gates"]["V-024"]["pty_surface_observed"]
            )

    def test_wrong_ptmx_device_identity_does_not_confirm_surface(self) -> None:
        value = report(
            [
                ("file", "/dev/ptmx|present|0666|0|0|0|character special file|1|3|"),
                ("file", "/dev/pts|present|0755|0|0|0|directory|0|0|"),
                ("mounts", "devpts /dev/pts devpts rw 0 0"),
            ]
        )
        triage = MODULE.build_triage(value)
        self.assertFalse(triage["observations"]["ptmx_endpoint_valid"])
        self.assertFalse(
            triage["candidate_runtime_gates"]["V-024"]["pty_surface_observed"]
        )

    def test_unavailable_link_metadata_and_fallback_remain_unknown(self) -> None:
        structured = report(
            [
                ("file", "/dev/ptmx|present|0777|0|0|0|symbolic link|0|0|unavailable"),
                ("file", "/dev/pts|present|0755|0|0|0|directory|0|0|"),
                ("file", "/dev/pts/ptmx|present|0666|0|0|0|character special file|5|2|"),
                ("mounts", "devpts /dev/pts devpts rw 0 0"),
            ]
        )
        triage = MODULE.build_triage(structured)
        self.assertIsNone(triage["observations"]["ptmx_endpoint_valid"])
        self.assertIsNone(
            triage["candidate_runtime_gates"]["V-024"]["pty_surface_observed"]
        )

        fallback = report([("file", "/dev/ptmx|present|unavailable|pts/ptmx")])
        fallback_triage = MODULE.build_triage(fallback)
        self.assertTrue(fallback_triage["observations"]["ptmx"]["present"])
        self.assertFalse(
            fallback_triage["observations"]["ptmx"]["metadata_structured"]
        )
        self.assertIsNone(fallback_triage["observations"]["ptmx_endpoint_valid"])

    def test_symlink_target_must_exist_and_supply_effective_permissions(self) -> None:
        base = [
            ("file", "/dev/ptmx|present|0777|0|0|0|symbolic link|0|0|pts/ptmx"),
            ("file", "/dev/pts|present|0755|0|0|0|directory|0|0|"),
            ("mounts", "devpts /dev/pts devpts rw 0 0"),
        ]
        dangling = MODULE.build_triage(
            report([*base, ("file", "/dev/pts/ptmx|absent")])
        )
        self.assertFalse(dangling["observations"]["ptmx_endpoint_valid"])
        self.assertFalse(
            dangling["candidate_runtime_gates"]["V-024"]["pty_surface_observed"]
        )

        restricted = MODULE.build_triage(
            report(
                [
                    *base,
                    ("file", "/dev/pts/ptmx|present|0600|0|0|0|character special file|5|2|"),
                ]
            )
        )
        self.assertTrue(restricted["observations"]["ptmx_endpoint_valid"])
        self.assertFalse(restricted["observations"]["ptmx_effective_world_read_write"])
        self.assertFalse(
            restricted["candidate_runtime_gates"]["V-024"]["pty_surface_observed"]
        )

    def test_absent_pts_directory_prevents_surface_confirmation(self) -> None:
        value = report(
            [
                ("file", "/dev/ptmx|present|0666|0|0|0|character special file|5|2|"),
                ("file", "/dev/pts|absent"),
                ("mounts", "devpts /dev/pts devpts rw 0 0"),
            ]
        )
        triage = MODULE.build_triage(value)
        self.assertFalse(triage["candidate_runtime_gates"]["V-024"]["pty_surface_observed"])

    def test_kernel_release_must_be_exact_uname_release_token(self) -> None:
        suffix = report([("uname", "Linux node 4.1.27-abl-extra #1 x86_64")])
        self.assertFalse(MODULE.build_triage(suffix)["observations"]["kernel_banner_match"])
        conflicting = report(
            [("uname", "Linux a 4.1.27-abl #1"), ("uname", "Linux b 5.10 #1")]
        )
        with self.assertRaisesRegex(MODULE.TriageError, "conflicting uname"):
            MODULE.build_triage(conflicting)

    def test_malformed_octal_mode_is_rejected_as_triage_error(self) -> None:
        value = report([("file", "/dev/ptmx|present|0999|0|0|0|character special file|5|2|")])
        with self.assertRaisesRegex(MODULE.TriageError, "malformed mode"):
            MODULE.build_triage(value)

    def test_incomplete_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            write_report(path, report([], complete=False))
            with self.assertRaisesRegex(MODULE.TriageError, "not complete"):
                MODULE.load_report(path)

    def test_impossible_empty_complete_report_is_rejected(self) -> None:
        value = report([])
        value["sections"] = []
        value["section_order"] = []
        value["canonical_sha256"] = sha_json({k: v for k, v in value.items() if k != "canonical_sha256"})
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            write_report(path, value)
            with self.assertRaisesRegex(MODULE.TriageError, "section order"):
                MODULE.load_report(path)

    def test_mutated_report_without_rehash_is_rejected(self) -> None:
        value = report([])
        value["capture_bytes"] = 1
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            write_report(path, value)
            with self.assertRaisesRegex(MODULE.TriageError, "canonical report SHA-256"):
                MODULE.load_report(path)

    def test_boolean_section_status_is_rejected_even_when_hashes_match(self) -> None:
        value = report([])
        section = value["sections"][1]  # type: ignore[index]
        section["end_status"] = False
        section["sha256"] = sha_json({k: v for k, v in section.items() if k != "sha256"})
        value["canonical_sha256"] = sha_json({k: v for k, v in value.items() if k != "canonical_sha256"})
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            write_report(path, value)
            with self.assertRaisesRegex(MODULE.TriageError, "invalid status"):
                MODULE.load_report(path)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text('{"schema":"ioniq-bench-state/v1","schema":"x"}')
            with self.assertRaisesRegex(MODULE.TriageError, "duplicate JSON key"):
                MODULE.load_report(path)

    def test_conflicting_path_records_are_rejected(self) -> None:
        value = report(
            [
                ("file", "/dev/ptmx|absent"),
                ("file", "/dev/ptmx|present|0666|0|0|0|character special file|5|2|"),
            ]
        )
        with self.assertRaisesRegex(MODULE.TriageError, "conflicting file records"):
            MODULE.build_triage(value)

    def test_cli_output_is_utf8_lf_and_environment_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            write_report(path, report([]))
            outputs = []
            for encoding in ("ascii:strict", "utf-16:strict"):
                env = dict(os.environ)
                env["PYTHONIOENCODING"] = encoding
                proc = subprocess.run(
                    [PYTHON, str(TOOL), str(path)],
                    capture_output=True,
                    env=env,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertTrue(proc.stdout.endswith(b"\n"))
                json.loads(proc.stdout.decode("utf-8"))
                outputs.append(proc.stdout)
            self.assertEqual(outputs[0], outputs[1])

    def test_cli_rejects_abbreviated_options(self) -> None:
        proc = subprocess.run(
            [PYTHON, str(TOOL), "--he"], capture_output=True, check=False
        )
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
