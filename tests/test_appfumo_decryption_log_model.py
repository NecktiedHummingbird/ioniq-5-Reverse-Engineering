#!/usr/bin/env python3
"""Tests for the bounded AppFUMO decryption/copy log model."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "uk_fw" / "appfumo_decryption_log_model.py"
PUBLIC_LOG = (
    ROOT
    / "evidence"
    / "upstream"
    / "Ioniq5_Gen5W_Log_Dump"
    / "2024-10-13T14_08_30"
    / "AppUpgrade"
    / "upgrade_log"
)
EXACT_ELF = (
    ROOT
    / "work"
    / "public-vuln-research-20261101"
    / "appupgrade-exact-extract"
    / "AppUpgrade.embedded-5721c8.elf"
)
STATIC_ARTIFACT = (
    ROOT
    / "evidence"
    / "artifacts"
    / "update-candidates"
    / "appfumo-decryption-producer-exact-static.asm"
)
EXPECTED_STATIC_ARTIFACT_SHA256 = "d8783cbdc41f5aae6663f339ff2debe2c3e425c8a243845e823b53f087099eb1"
if str(TOOL.parent) not in sys.path:
    sys.path.insert(0, str(TOOL.parent))

import appfumo_decryption_log_model as model  # noqa: E402


def synthetic_log(*, token: str = "0" * 32, extra: str = "") -> bytes:
    lines = [
        "[01-02-24 03:04:05:001] [copyWhatsNewFiles] s_package_systemdir /media/usb/1/VOLUME-1/whatsnew/whatsnew ",
        "[01-02-24 03:04:05:002] [copyWhatsNewFiles] s_package_controlsdir /media/usb/1/VOLUME-1/whatsnew/whatsnew_controls ",
        "[01-02-24 03:04:05:003] [copyWhatsNewFiles] s_whatsnew_systemdir /update/whatsnew/whatsnew_new ",
        "[01-02-24 03:04:05:004] [copyWhatsNewFiles] s_whatsnew_controlsdir /update/whatsnew/whatsnew_controls_new ",
        "[01-02-24 03:04:05:005] unrelated bounded text",
        "[01-02-24 03:04:05:006] [decryptionFile] command /app/share/AppUpgrade/DecryptToPIPE -d "
        f"/tmp/{token} /media/usb/1/VOLUME-1/.whatsnew.tar.gz 0 | dd "
        "of=/update/whatsnew/temp/.whatsnew.tar.gz bs=512",
        "[01-02-24 03:04:05:007] [copyWhatsNewFiles] /media/usb/1/VOLUME-1/.whatsnew.tar.gz --> /update/whatsnew/temp/.whatsnew.tar.gz",
        "[01-02-24 03:04:05:008] [copyWhatsNewFiles] system countdirs   8",
        "[01-02-24 03:04:05:009] [copyWhatsNewFiles] control countdirs   0",
    ]
    if extra:
        lines.append(extra)
    return ("\n".join(lines) + "\n").encode("utf-8")


class AppFumoDecryptionLogModelTests(unittest.TestCase):
    def test_synthetic_report_is_normalized_and_does_not_emit_command_or_token(self) -> None:
        raw = synthetic_log(token="a" * 32)
        report = model.build_report(raw, synthetic_test=True)
        observation = report["observation"]
        self.assertEqual(observation["decryption_file_record_count"], 1)
        self.assertEqual(observation["copy_whats_new_files_record_count"], 7)
        self.assertEqual(observation["events"][0]["line"], 6)
        self.assertEqual(
            observation["events"][0]["context"]["status"],
            "matched_copyWhatsNewFiles_context",
        )
        encoded = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
        self.assertNotIn(b"DecryptToPIPE", encoded)
        self.assertNotIn(b"| dd", encoded)
        self.assertNotIn(b"a" * 32, encoded)
        self.assertNotIn(b"VOLUME-1", encoded)

    def test_hash_is_required_outside_explicit_synthetic_mode(self) -> None:
        with self.assertRaisesRegex(model.ParseError, "SHA-256"):
            model.build_report(synthetic_log(), synthetic_test=False)

    def test_unexpected_command_shape_is_rejected(self) -> None:
        raw = synthetic_log().replace(b" bs=512", b" bs=1024")
        with self.assertRaisesRegex(model.ParseError, "unexpected decryptionFile command shape"):
            model.build_report(raw, synthetic_test=True)

    def test_non_utf8_and_crlf_are_rejected(self) -> None:
        with self.assertRaisesRegex(model.ParseError, "UTF-8"):
            model.build_report(synthetic_log() + b"\xff\n", synthetic_test=True)
        with self.assertRaisesRegex(model.ParseError, "LF rather than CR"):
            model.build_report(synthetic_log().replace(b"\n", b"\r\n"), synthetic_test=True)
        with self.assertRaisesRegex(model.ParseError, "unsupported control"):
            model.build_report(synthetic_log() + b"unrelated\x00record\n", synthetic_test=True)

    def test_traversal_and_control_characters_cannot_match_paths(self) -> None:
        for replacement in (b"../VOLUME-1", b"VOLUME\t1"):
            raw = synthetic_log().replace(b"VOLUME-1", replacement)
            with self.subTest(replacement=replacement):
                with self.assertRaises(model.ParseError):
                    model.build_report(raw, synthetic_test=True)

    def test_duplicate_invocation_is_rejected(self) -> None:
        base = synthetic_log().decode("utf-8").splitlines()
        duplicate_invocation = ("\n".join(base + [base[5]]) + "\n").encode()
        with self.assertRaisesRegex(model.ParseError, "duplicate transient token"):
            model.build_report(duplicate_invocation, synthetic_test=True)

    def test_distinct_same_kind_context_is_rejected_as_ambiguous(self) -> None:
        base = synthetic_log().decode("utf-8").splitlines()
        distinct_second_system_context = (
            "[01-02-24 03:04:05:005] [copyWhatsNewFiles] "
            "s_package_systemdir /media/usb/1/OTHER-VOLUME/whatsnew/whatsnew "
        )
        raw = ("\n".join(base[:5] + [distinct_second_system_context] + base[5:]) + "\n").encode()
        with self.assertRaisesRegex(
            model.ParseError,
            "ambiguous preceding config:s_package_systemdir context",
        ):
            model.build_report(raw, synthetic_test=True)

    def test_context_conflict_is_rejected(self) -> None:
        base = synthetic_log().decode("utf-8").splitlines()
        base[0] = base[0].replace("VOLUME-1", "OTHER-VOLUME")
        raw = ("\n".join(base) + "\n").encode()
        with self.assertRaisesRegex(model.ParseError, "context conflicts with invocation"):
            model.build_report(raw, synthetic_test=True)

    def test_line_size_line_count_and_relevant_record_bounds_are_rejected(self) -> None:
        oversized_line = synthetic_log(extra="x" * (model.MAX_LINE_BYTES + 1))
        with self.assertRaisesRegex(model.ParseError, "line-size bound"):
            model.build_report(oversized_line, synthetic_test=True)

        too_many_lines = (("unrelated\n" * (model.MAX_LINES + 1))).encode()
        with self.assertRaisesRegex(model.ParseError, "too many lines"):
            model.build_report(too_many_lines, synthetic_test=True)

        start = dt.datetime(2024, 1, 2, 3, 4, 5)
        records = []
        for index in range(model.MAX_RELEVANT_RECORDS + 1):
            stamp = start + dt.timedelta(seconds=index)
            timestamp = stamp.strftime("%m-%d-%y %H:%M:%S") + ":000"
            records.append(
                f"[{timestamp}] [copyWhatsNewFiles] system countdirs   {index}"
            )
        excessive_relevant = ("\n".join(records) + "\n").encode()
        with self.assertRaisesRegex(model.ParseError, "too many relevant records"):
            model.build_report(excessive_relevant, synthetic_test=True)

    def test_excessive_invocation_count_is_rejected(self) -> None:
        records = []
        for index in range(model.MAX_INVOCATIONS + 1):
            token = f"{index:032x}"
            records.append(
                f"[01-02-24 03:{4 + index // 60:02d}:{index % 60:02d}:006] [decryptionFile] command "
                f"/app/share/AppUpgrade/DecryptToPIPE -d /tmp/{token} "
                "/media/usb/1/VOLUME-1/.whatsnew.tar.gz 0 | dd "
                "of=/update/whatsnew/temp/.whatsnew.tar.gz bs=512"
            )
        raw = ("\n".join(records) + "\n").encode()
        with self.assertRaisesRegex(model.ParseError, "too many decryption invocations"):
            model.build_report(raw, synthetic_test=True)

    def test_regular_file_reader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "log"
            regular.write_bytes(synthetic_log())
            link = root / "link"
            link.symlink_to(regular)
            with self.assertRaisesRegex(model.ParseError, "non-symlink"):
                model._read_stable_regular_file(link)

    def test_regular_file_reader_rejects_pre_read_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.log"
            with path.open("wb") as handle:
                handle.truncate(model.MAX_LOG_BYTES + 1)
            with self.assertRaisesRegex(model.ParseError, "pre-read size bound"):
                model._read_stable_regular_file(path)

    def test_regular_file_reader_rejects_observed_stability_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stable.log"
            path.write_bytes(synthetic_log())
            real_fstat = os.fstat
            call_count = 0

            def changed_second_fstat(fd: int):
                nonlocal call_count
                current = real_fstat(fd)
                call_count += 1
                if call_count == 1:
                    return current
                return SimpleNamespace(
                    st_mode=current.st_mode,
                    st_dev=current.st_dev,
                    st_ino=current.st_ino,
                    st_size=current.st_size,
                    st_mtime_ns=current.st_mtime_ns + 1,
                    st_ctime_ns=current.st_ctime_ns,
                )

            with mock.patch.object(model.os, "fstat", side_effect=changed_second_fstat):
                with self.assertRaisesRegex(model.ParseError, "changed while being read"):
                    model._read_stable_regular_file(path)

    def test_cli_rejects_abbreviations_and_unknown_options(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.log"
            path.write_bytes(synthetic_log())
            for option in ("--synthetic", "--synthetic-t", "--unknown"):
                with self.subTest(option=option):
                    completed = subprocess.run(
                        [sys.executable, str(TOOL), "--log", str(path), option],
                        cwd=ROOT,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stdout, b"")
                    self.assertIn(b"unrecognized arguments", completed.stderr)

            exact = subprocess.run(
                [sys.executable, str(TOOL), "--log", str(path), "--synthetic-test"],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(exact.returncode, 0, exact.stderr)
            self.assertEqual(exact.stderr, b"")
            json.loads(exact.stdout.decode("utf-8"))

    def test_cli_output_is_utf8_lf_and_encoding_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.log"
            path.write_bytes(synthetic_log())
            outputs = []
            for encoding in ("ascii", "latin-1", "utf-16"):
                environment = os.environ.copy()
                environment["PYTHONIOENCODING"] = encoding
                completed = subprocess.run(
                    [sys.executable, str(TOOL), "--log", str(path), "--synthetic-test"],
                    cwd=ROOT,
                    env=environment,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, b"")
                self.assertTrue(completed.stdout.endswith(b"\n"))
                self.assertNotIn(b"\r", completed.stdout)
                json.loads(completed.stdout.decode("utf-8"))
                outputs.append(completed.stdout)
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(outputs[1], outputs[2])

    def test_retained_static_artifact_hash_and_required_anchors(self) -> None:
        raw = STATIC_ARTIFACT.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), EXPECTED_STATIC_ARTIFACT_SHA256)
        text = raw.decode("utf-8")
        for anchor in (
            "0x444600",
            "0x4446f0",
            "0xffd29f9f",
            "-2973793",
            "0x16e59f",
            "0x101110",
            "0x102c90",
            "102ca4:",
            "0x20bb63",
            "0x20bdad",
            "0x20be21",
            "0x20bd9f",
            "0x20bdbe",
            "0x21f8f8",
            "0x222d88",
        ):
            with self.subTest(anchor=anchor):
                self.assertIn(anchor, text)

    @unittest.skipUnless(EXACT_ELF.is_file(), "ignored exact ELF is unavailable")
    def test_exact_elf_static_anchor_bytes(self) -> None:
        raw = EXACT_ELF.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), model.EXACT_ELF_SHA256)
        self.assertEqual(raw[0x4446F0:0x4446F4], bytes.fromhex("9f9fd2ff"))
        signed = int.from_bytes(raw[0x4446F0:0x4446F4], "little", signed=True)
        self.assertEqual(signed, -2973793)
        self.assertEqual(0x444600 + signed, 0x16E59F)
        self.assertEqual(raw[0x16E59F:0x16E5A4], bytes.fromhex("e86c2bf9ff"))
        self.assertEqual(
            raw[0x102C90:0x102CA9],
            bytes.fromhex(
                "488dbc2440010000488d3509235d0048897c2460e86713f2ff"
            ),
        )
        literals = {
            0x20BB63: b".whatsnew.tar.gz\0",
            0x20BDAD: b"/update/whatsnew\0",
            0x20BE21: b"temp\0",
            0x20BD9F: b"/whatsnew_new\0",
            0x20BDBE: b"/whatsnew_controls_new\0",
            0x21F8F8: b"/whatsnew_new_usb_in_ota\0",
            0x222D88: b"/whatsnew_controls_new_usb_in_ota\0",
        }
        for address, expected in literals.items():
            with self.subTest(address=hex(address)):
                self.assertEqual(raw[address : address + len(expected)], expected)

    @unittest.skipUnless(PUBLIC_LOG.is_file(), "tracked public log is unavailable")
    def test_exact_public_log_identity_count_lines_and_context(self) -> None:
        raw = model._read_stable_regular_file(PUBLIC_LOG)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), model.EXPECTED_LOG_SHA256)
        report = model.build_report(raw, synthetic_test=False)
        observation = report["observation"]
        self.assertEqual(observation["decryption_file_record_count"], 7)
        self.assertEqual(observation["copy_whats_new_files_record_count"], 49)
        self.assertEqual(
            [event["line"] for event in observation["events"]],
            [1414, 1710, 7279, 11714, 11975, 17205, 21713],
        )
        self.assertEqual(
            observation["copy_context_status_counts"],
            {"matched_copyWhatsNewFiles_context": 7},
        )
        self.assertEqual(
            report["identity_and_mechanism"]["logged_build_equals_exact_elf_status"],
            "unknown",
        )
        self.assertEqual(
            report["identity_and_mechanism"]["invocation_mechanism_status"],
            "unknown_log_does_not_distinguish_direct_meta_or_indirect_dispatch",
        )


if __name__ == "__main__":
    unittest.main()
