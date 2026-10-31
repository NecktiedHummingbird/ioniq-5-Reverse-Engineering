from __future__ import annotations

import importlib.util
import json
import os
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
        for process_name in ("AppLauncher", "AppDMClient", "AppScomoDM", "AppUpgrade"):
            self.assertIn(process_name, script)
        for update_path in (
            "/bin/busybox",
            "/usr/bin/unzip",
            "/usr/bin/unzip64",
            "/app/bin/AppLauncher",
            "/app/bin/AppDMClient",
            "/app/bin/AppScomoDM",
            "/app/bin/AppUpgrade",
            "/app/bin/NaviUpdateApp",
            "/app/bin/CarOption.csv",
            "/app/share/AppUpgrade/DecryptToPIPE",
            "/app/share/AppUpgrade/teruten5_pub.key",
            "/update/sysroot",
            "/update/usb/upgrade",
            "/update/usb/bin",
            "/update/usb/bin/AppUpgrade",
            "/update/usb/bin/.lge.upgrade.xml",
            "/tmp/AppUpgrade",
        ):
            self.assertIn(update_path, script)
        for update_flag in (
            "disableNaviMapSignatureCheck_20230207",
            "force_launch",
            "system_update_complete",
            "system_update_completed",
            "firmware_update_complete",
            "scheduled_update_complete",
            "scheduled_update_complete_for_DM",
        ):
            self.assertRegex(script, rf"for S_FLAG in [^\n]*\b{update_flag}\b")
        self.assertIn('capture_file update-flag "/update/$S_FLAG"', script)
        self.assertNotIn('[ -r "/update/$S_FLAG" ]', script)
        self.assertIn('P_STATUS=$?', script)
        self.assertIn('U_STATUS=$?', script)
        self.assertIn('read_scalar interface-operstate', script)
        self.assertIn('record unreadable-file', script)

    def test_probe_helpers_fail_closed_on_collection_errors(self) -> None:
        preamble = MODULE.PROBE_SCRIPT.split("if ! has_command od", 1)[0]
        exercise = r'''
begin_section storage
read_scalar scalar "$1"
capture_file read-error "$2"
file_meta "$3"
file_meta "$4"
hash_file "$5"
hash_file "$6"
hash_file "$7"
hash_file "$8"
capture_file update-flag "$9"
capture_unit test.service
capture_interface "${10}"
capture_command command-test probe-fail
record collect-failure "$COLLECT_FAILURE"
end_section storage "$COLLECT_FAILURE"
begin_section complete
if [ "$COLLECT_FAILURE" -eq 0 ]; then
    record result complete
    end_section complete 0
else
    record result collection-error
    end_section complete 1
fi
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_awk = fake_bin / "awk"
            fake_awk.write_text("#!/bin/sh\nexit 9\n")
            fake_awk.chmod(0o700)
            fake_cat = fake_bin / "cat"
            fake_cat.write_text(
                "#!/bin/sh\ncase \"$1\" in *scalar-read-error|*/operstate) exit 6;; esac\n"
                "exec /bin/cat \"$@\"\n"
            )
            fake_cat.chmod(0o700)
            fake_stat = fake_bin / "stat"
            fake_stat.write_text(
                "#!/bin/sh\nfor LAST do :; done\n"
                "case \"$LAST\" in *meta-fail) exit 7;; esac\n"
                "printf '644|0|0|1|regular file\\n'\n"
            )
            fake_stat.chmod(0o700)
            fake_readlink = fake_bin / "readlink"
            fake_readlink.write_text("#!/bin/sh\nexit 5\n")
            fake_readlink.chmod(0o700)
            fake_sha = fake_bin / "sha256sum"
            fake_sha.write_text(
                "#!/bin/sh\ncase \"$1\" in\n"
                "  *hash-empty) exit 0;;\n"
                "  *hash-fail) exit 8;;\n"
                "  *hash-garbage) printf '%064d  %s garbage\\n' 0 \"$1\";;\n"
                "  *) printf 'not-a-digest  %s\\n' \"$1\";;\n"
                "esac\n"
            )
            fake_sha.chmod(0o700)
            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text("#!/bin/sh\nexit 12\n")
            fake_systemctl.chmod(0o700)
            fake_command = fake_bin / "probe-fail"
            fake_command.write_text("#!/bin/sh\nexit 11\n")
            fake_command.chmod(0o700)

            scalar_error = root / "scalar-read-error"
            scalar_error.write_text("scalar")
            read_error = root / "directory"
            read_error.mkdir()
            meta_fail = root / "meta-fail"
            meta_fail.write_text("meta")
            link_fail = root / "link-fail"
            link_fail.symlink_to(meta_fail)
            hash_bad = root / "hash-bad"
            hash_bad.write_text("bad")
            hash_empty = root / "hash-empty"
            hash_empty.write_text("empty")
            hash_fail = root / "hash-fail"
            hash_fail.write_text("fail")
            hash_garbage = root / "hash-garbage"
            hash_garbage.write_text("garbage")
            update_marker = root / "force_launch"
            update_marker.write_text("run")
            update_marker.chmod(0)
            interface = root / "interface"
            interface.mkdir()
            for name, value in (
                ("operstate", "up"),
                ("carrier", "1"),
                ("type", "1"),
                ("ifindex", "3"),
                ("iflink", "3"),
            ):
                (interface / name).write_text(value)

            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}:/usr/bin:/bin"
            proc = subprocess.run(
                [
                    "/bin/sh",
                    "-s",
                    "--",
                    str(scalar_error),
                    str(read_error),
                    str(meta_fail),
                    str(link_fail),
                    str(hash_bad),
                    str(hash_empty),
                    str(hash_fail),
                    str(hash_garbage),
                    str(update_marker),
                    str(interface),
                ],
                input=preamble + exercise,
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = MODULE.parse_capture(proc.stdout.encode())
            records = [
                (item["key"], item["value"])
                for section in report["sections"]
                for item in section["records"]
            ]
            keys = {key for key, _ in records}
            self.assertIn("file-read-error", keys)
            self.assertIn("file-meta-error", keys)
            self.assertIn("file-link-error", keys)
            self.assertIn("hash-error", keys)
            self.assertIn("command-error", keys)
            self.assertIn("unit-error", keys)
            self.assertIn("interface-read-error", keys)
            self.assertTrue("unreadable-file" in keys or "file-read-error" in keys)
            hash_errors = [value for key, value in records if key == "hash-error"]
            self.assertEqual(len(hash_errors), 4)
            self.assertTrue(any("hash-empty" in value for value in hash_errors))
            self.assertTrue(any("hash-fail" in value for value in hash_errors))
            self.assertTrue(any("hash-garbage" in value for value in hash_errors))
            values = dict(records)
            self.assertEqual(values["collect-failure"], "1")
            self.assertEqual(values["result"], "collection-error")
            complete = next(
                section for section in report["sections"] if section["name"] == "complete"
            )
            self.assertEqual(complete["end_status"], 1)
            self.assertFalse(report["complete"])

    def test_process_environ_partial_output_failure_is_not_complete(self) -> None:
        preamble = MODULE.PROBE_SCRIPT.split("if ! has_command od", 1)[0]
        exercise = r'''
begin_section processes
capture_process_path 42 "$1"
record collect-failure "$COLLECT_FAILURE"
end_section processes "$COLLECT_FAILURE"
begin_section complete
if [ "$COLLECT_FAILURE" -eq 0 ]; then
    record result complete
    end_section complete 0
else
    record result collection-error
    end_section complete 1
fi
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc_dir = root / "42"
            proc_dir.mkdir()
            (proc_dir / "environ").write_bytes(b"PATH=/real/bin\0OTHER=value\0")
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_tr = fake_bin / "tr"
            fake_tr.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = '\\000' ] && [ \"$2\" = '\\n' ]; then\n"
                "  printf 'PATH=/partial/bin\\n'\n"
                "  exit 7\n"
                "fi\n"
                "exec /usr/bin/tr \"$@\"\n"
            )
            fake_tr.chmod(0o700)
            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}:/usr/bin:/bin"
            proc = subprocess.run(
                ["/bin/sh", "-s", "--", str(proc_dir)],
                input=preamble + exercise,
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = MODULE.parse_capture(proc.stdout.encode())
            records = [
                (item["key"], item["value"])
                for section in report["sections"]
                for item in section["records"]
            ]
            self.assertIn(("process-path", "42|/partial/bin"), records)
            errors = [value for key, value in records if key == "process-read-error"]
            self.assertTrue(any("producer=7" in value for value in errors))
            complete = next(
                section for section in report["sections"] if section["name"] == "complete"
            )
            self.assertEqual(complete["end_status"], 1)
            self.assertFalse(report["complete"])

    def test_missing_hash_and_readlink_providers_are_explicit_nonfailures(self) -> None:
        preamble = MODULE.PROBE_SCRIPT.split("if ! has_command od", 1)[0]
        exercise = r'''
has_command() {
    case "$1" in sha256sum|openssl|readlink|stat|ls) return 1 ;; esac
    command -v "$1" >/dev/null 2>&1
}
begin_section hashes
hash_file "$1"
file_meta "$2"
read_link_value test-link "$2"
record collect-failure "$COLLECT_FAILURE"
end_section hashes "$COLLECT_FAILURE"
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_text("target")
            link = root / "link"
            link.symlink_to(target)
            env = dict(os.environ)
            env["PATH"] = "/usr/bin:/bin"
            proc = subprocess.run(
                ["/bin/sh", "-s", "--", str(target), str(link)],
                input=preamble + exercise,
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = MODULE.parse_capture(proc.stdout.encode())
            records = [
                (item["key"], item["value"])
                for section in report["sections"]
                for item in section["records"]
            ]
            self.assertIn(("hash", f"{target}|unavailable"), records)
            self.assertTrue(any(key == "file-meta-unavailable" for key, _ in records))
            self.assertTrue(any(key == "file-link-unavailable" for key, _ in records))
            self.assertIn(("collect-failure", "0"), records)

    def test_record_encoder_faults_are_fatal(self) -> None:
        preamble = MODULE.PROBE_SCRIPT.split("if ! has_command od", 1)[0]
        exercise = r'''
begin_section complete
record result complete
end_section complete "$COLLECT_FAILURE"
'''
        for failed_tool in ("od", "tr"):
            with self.subTest(failed_tool=failed_tool), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                fake_bin = root / "bin"
                fake_bin.mkdir()
                fake_tool = fake_bin / failed_tool
                if failed_tool == "od":
                    fake_tool.write_text("#!/bin/sh\nprintf ' 72 65 63 6f 72 64'\nexit 7\n")
                else:
                    fake_tool.write_text("#!/bin/sh\n/bin/cat\nexit 8\n")
                fake_tool.chmod(0o700)
                env = dict(os.environ)
                env["PATH"] = f"{fake_bin}:/usr/bin:/bin"
                proc = subprocess.run(
                    ["/bin/sh", "-s"],
                    input=preamble + exercise,
                    text=True,
                    capture_output=True,
                    env=env,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                report = MODULE.parse_capture(proc.stdout.encode())
                fatal = [
                    item["value"]
                    for section in report["sections"]
                    for item in section["records"]
                    if item["key"] == "fatal"
                ]
                self.assertEqual(fatal, ["record-encode-error"])
                self.assertIn("probe reported fatal collection error", report["warnings"])
                complete = report["sections"][0]
                self.assertEqual(complete["end_status"], 1)
                self.assertFalse(report["complete"])

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

    def test_audit_rejects_non_allowlisted_environment_read(self) -> None:
        unsafe_lines = (
            '''P_PATH=$(cat < "$P_DIR/environ" 2>/dev/null)\n''',
            '''P_PATH=$(cat "$P_DIR/environ" 2>/dev/null)\n''',
            '''capture_file process-env "$P_DIR/environ"\n''',
        )
        for unsafe in unsafe_lines:
            with self.subTest(unsafe=unsafe):
                violations = MODULE.audit_script(unsafe)
                self.assertTrue(
                    any("non-allowlisted environment read" in item for item in violations)
                )
        self.assertEqual(MODULE.audit_script(MODULE.SAFE_ENVIRON_READ_LINE + "\n"), [])

    def test_parse_timestamped_capture_and_derive_facts(self) -> None:
        capture = valid_capture(
            {
                "processes": [
                    (
                        "process",
                        "12|0|0|App::bluetooth|/tmp/vbtd|vbtd|/app/bin/vbtd -d /dev/ttyS0",
                    ),
                    ("process-path", "12|/usr/local/bin:/usr/bin:/bin"),
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
        self.assertEqual(
            report["facts"]["process_paths"]["12"],
            "/usr/local/bin:/usr/bin:/bin",
        )
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
