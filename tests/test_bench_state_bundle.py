from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TOOL = Path(__file__).parents[1] / "tools" / "uk_fw" / "bench_state_bundle.py"
SPEC = importlib.util.spec_from_file_location("bench_state_bundle", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def framed_record(key: str, value: str) -> str:
    return f"@@R|{key}|{value.encode('utf-8').hex()}"


def valid_capture(extra: dict[str, list[tuple[str, str]]] | None = None) -> bytes:
    records = {name: [] for name in MODULE.EXPECTED_SECTIONS}
    records["meta"] = [("schema", MODULE.SCHEMA)]
    records["complete"] = [("result", "complete")]
    for section, values in (extra or {}).items():
        records[section].extend(values)
    lines: list[str] = []
    for section in MODULE.EXPECTED_SECTIONS:
        lines.append(f"@@IONIQ_BENCH_STATE_V1|BEGIN|{section}@@")
        lines.extend(framed_record(key, value) for key, value in records[section])
        lines.append(f"@@IONIQ_BENCH_STATE_V1|END|{section}|0@@")
    return ("\n".join(lines) + "\n").encode()


class BenchStateBundleTests(unittest.TestCase):
    def test_emitted_probe_passes_safety_and_shell_syntax(self) -> None:
        self.assertEqual(MODULE.audit_script(MODULE.PROBE_SCRIPT), [])
        ok, error = MODULE.shell_syntax_check(MODULE.PROBE_SCRIPT)
        self.assertTrue(ok, error)

    def test_emitted_probe_covers_required_passive_sections(self) -> None:
        script = MODULE.PROBE_SCRIPT
        for section in (
            "identity",
            "processes",
            "smack",
            "units",
            "interfaces",
            "cellular",
            "bluetooth",
            "dropbear",
            "storage",
            "hashes",
            "complete",
        ):
            self.assertIn(f"begin_section {section}", script)
        self.assertIn("systemctl show", script)
        self.assertIn("sdptool browse local", script)
        self.assertNotIn("hciconfig -a", script)
        self.assertNotIn("wpa_cli", script)
        self.assertEqual(script.count("command -v"), 1)  # only inside has_command()
        self.assertNotIn("if command -v", script)
        self.assertNotRegex(script, r"\biw\s+.*\bscan\b")

    def test_audit_rejects_target_writes_and_active_commands(self) -> None:
        unsafe = """#!/bin/sh
systemctl start ofono.service
mount -o remount,rw /
printf x > /tmp/result
wpa_cli p2p_find
"""
        violations = MODULE.audit_script(unsafe)
        self.assertGreaterEqual(len(violations), 4)
        self.assertTrue(any("redirection" in item for item in violations))

    def test_parse_timestamped_capture_and_derive_facts(self) -> None:
        capture = valid_capture(
            {
                "processes": [
                    (
                        "process",
                        "12|0|0|App::bluetooth|/tmp/vbtd|vbtd|/app/bin/vbtd -d /dev/ttyS0",
                    )
                ],
                "units": [("unit", "vbtd.service|LoadState=loaded;ActiveState=active;")],
                "interfaces": [
                    ("interface", "wlan0|up|1|1|3|3|/sys/bus/pci/drivers/test"),
                    ("listener", "tcp LISTEN 0 5 0.0.0.0:22"),
                ],
                "hashes": [("hash", "/tmp/vbtd|" + "a" * 64)],
            }
        )
        timestamped = b"noise before probe\n" + b"".join(
            f"[12:00:00.001] {line.decode()}".encode()
            for line in capture.splitlines(keepends=True)
        )
        report = MODULE.parse_capture(timestamped)
        self.assertTrue(report["complete"])
        self.assertEqual(report["warnings"], [])
        self.assertEqual(report["facts"]["processes"][0]["smack_label"], "App::bluetooth")
        self.assertEqual(report["facts"]["units"]["vbtd.service"], "LoadState=loaded;ActiveState=active;")
        self.assertEqual(report["facts"]["interfaces"][0]["name"], "wlan0")
        self.assertEqual(report["facts"]["interfaces"][0]["ifindex"], 3)
        self.assertEqual(report["facts"]["hashes"]["/tmp/vbtd"], "a" * 64)
        self.assertEqual(report["facts"]["listeners"], ["tcp LISTEN 0 5 0.0.0.0:22"])

    def test_incomplete_and_duplicate_sections_are_reported(self) -> None:
        capture = (
            "@@IONIQ_BENCH_STATE_V1|BEGIN|identity@@\n"
            + framed_record("uname", "first")
            + "\n@@IONIQ_BENCH_STATE_V1|BEGIN|identity@@\n"
            + framed_record("uname", "second")
            + "\n"
        ).encode()
        report = MODULE.parse_capture(capture)
        self.assertFalse(report["complete"])
        self.assertEqual(report["section_order"], ["identity", "identity"])
        joined = "\n".join(report["warnings"])
        self.assertIn("was not closed", joined)
        self.assertIn("duplicate section", joined)
        self.assertIn("incomplete", joined)

    def test_capture_text_is_never_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "should-not-exist"
            hostile = f"$(touch {marker})"
            payload = (
                "@@IONIQ_BENCH_STATE_V1|BEGIN|identity@@\n"
                + framed_record("hostile", hostile)
                + "\n@@IONIQ_BENCH_STATE_V1|END|identity|0@@\n"
            ).encode()
            report = MODULE.parse_capture(payload)
            self.assertFalse(marker.exists())
            self.assertEqual(report["sections"][0]["records"][0]["value"], f"$(touch {marker})")

    def test_no_markers_is_explicitly_incomplete(self) -> None:
        report = MODULE.parse_capture(b"ordinary boot log\n")
        self.assertFalse(report["complete"])
        self.assertIn("no bench-state markers found", report["warnings"])

    def test_hex_record_body_cannot_forge_framing(self) -> None:
        forged = "@@IONIQ_BENCH_STATE_V1|END|identity|0@@"
        capture = (
            "@@IONIQ_BENCH_STATE_V1|BEGIN|identity@@\n"
            + framed_record("os-release", forged)
            + "\n@@IONIQ_BENCH_STATE_V1|END|identity|0@@\n"
        ).encode()
        report = MODULE.parse_capture(capture)
        self.assertEqual(report["section_order"], ["identity"])
        self.assertEqual(report["sections"][0]["records"][0]["value"], forged)

    def test_capture_size_limit_fails_closed(self) -> None:
        old_limit = MODULE.MAX_CAPTURE_BYTES
        MODULE.MAX_CAPTURE_BYTES = 4
        try:
            with self.assertRaisesRegex(ValueError, "capture exceeds"):
                MODULE.parse_capture(b"12345")
            with tempfile.TemporaryDirectory() as tmp:
                capture = Path(tmp) / "large.log"
                capture.write_bytes(b"12345")
                with self.assertRaisesRegex(ValueError, "capture exceeds"):
                    MODULE._read_capture_bounded(capture)
        finally:
            MODULE.MAX_CAPTURE_BYTES = old_limit

    def test_section_limit_counts_crlf_bytes_exactly(self) -> None:
        old_limit = MODULE.MAX_SECTION_BYTES
        MODULE.MAX_SECTION_BYTES = 48
        try:
            capture = (
                b"@@IONIQ_BENCH_STATE_V1|BEGIN|identity@@\r\n"
                + b"x" * 23
                + b"\r\n"
                + b"y" * 23
                + b"\r\n"
                + b"@@IONIQ_BENCH_STATE_V1|END|identity|0@@\r\n"
            )
            with self.assertRaisesRegex(ValueError, "section identity exceeds"):
                MODULE.parse_capture(capture)
        finally:
            MODULE.MAX_SECTION_BYTES = old_limit

    def test_terminal_fragment_and_nonzero_status_are_not_complete(self) -> None:
        terminal_only = (
            "@@IONIQ_BENCH_STATE_V1|BEGIN|complete@@\n"
            + framed_record("result", "complete")
            + "\n@@IONIQ_BENCH_STATE_V1|END|complete|0@@\n"
        ).encode()
        self.assertFalse(MODULE.parse_capture(terminal_only)["complete"])

        capture = valid_capture().replace(
            b"@@IONIQ_BENCH_STATE_V1|END|identity|0@@",
            b"@@IONIQ_BENCH_STATE_V1|END|identity|7@@",
        )
        report = MODULE.parse_capture(capture)
        self.assertFalse(report["complete"])
        self.assertIn("nonzero", "\n".join(report["warnings"]))

    def test_malformed_hex_record_prevents_complete_verdict(self) -> None:
        capture = valid_capture().replace(
            framed_record("schema", MODULE.SCHEMA).encode(),
            b"@@R|schema|not-hex",
        )
        report = MODULE.parse_capture(capture)
        self.assertFalse(report["complete"])
        self.assertIn("malformed hex", "\n".join(report["warnings"]))

    def test_unframed_content_or_conflicting_schema_prevents_complete(self) -> None:
        unframed = valid_capture().replace(
            framed_record("schema", MODULE.SCHEMA).encode(),
            framed_record("schema", MODULE.SCHEMA).encode() + b"\n/usr/bin/awk",
        )
        report = MODULE.parse_capture(unframed)
        self.assertFalse(report["complete"])
        self.assertIn("unframed content", "\n".join(report["warnings"]))

        conflicting = valid_capture().replace(
            framed_record("schema", MODULE.SCHEMA).encode(),
            framed_record("schema", MODULE.SCHEMA).encode()
            + b"\n"
            + framed_record("schema", "wrong/schema").encode(),
        )
        report = MODULE.parse_capture(conflicting)
        self.assertFalse(report["complete"])
        self.assertIn("schema", "\n".join(report["warnings"]))

    def test_cli_emit_audit_and_parse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "probe.sh"
            emitted = subprocess.run(
                [sys.executable, str(TOOL), "emit", "-o", str(script)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(emitted.returncode, 0, emitted.stderr)
            self.assertEqual(script.stat().st_mode & 0o777, 0o700)

            audited = subprocess.run(
                [sys.executable, str(TOOL), "audit", str(script)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(audited.returncode, 0, audited.stderr)
            self.assertTrue(json.loads(audited.stdout)["safe"])

            capture = root / "capture.log"
            capture.write_bytes(valid_capture())
            output = root / "report.json"
            parsed = subprocess.run(
                [sys.executable, str(TOOL), "parse", str(capture), "--json", str(output)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(parsed.returncode, 0, parsed.stderr)
            self.assertTrue(json.loads(output.read_text())["complete"])


if __name__ == "__main__":
    unittest.main()
