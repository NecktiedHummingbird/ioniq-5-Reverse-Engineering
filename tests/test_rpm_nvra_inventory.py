"""Tests for the read-only RPM Nvra Berkeley DB dump parser."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).parents[1] / "tools/uk_fw/rpm_nvra_inventory.py"
SPEC = importlib.util.spec_from_file_location("rpm_nvra_inventory", TOOL)
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)


def dump_bytes(*fields: bytes, headers: tuple[bytes, ...] = ()) -> bytes:
    base = [
        b"VERSION=3",
        b"format=print",
        b"type=btree",
        b"duplicates=1",
        *headers,
        b"HEADER=END",
        *fields,
        b"DATA=END",
    ]
    return b"\n".join(base) + b"\n"


class ParsingTests(unittest.TestCase):
    def test_parses_escapes_nvra_and_opaque_record_id(self):
        data = dump_bytes(
            b" foo\\2dbar-1.2+vendor-r7.corei7_64",
            b" \\00\\00\\03\\f3",
        )
        headers, packages = INVENTORY.parse_dump(data)
        self.assertEqual(headers["format"], "print")
        self.assertEqual(
            packages,
            [{
                "nvra": "foo-bar-1.2+vendor-r7.corei7_64",
                "name": "foo-bar",
                "version": "1.2+vendor",
                "release": "r7",
                "arch": "corei7_64",
                "record_id_hex": "000003f3",
            }],
        )

    def test_report_is_deterministic_and_selectors_are_exact(self):
        data = dump_bytes(
            b" zlib-1.0-r0.x86_64", b" \\01",
            b" connman-1.29+vendor-r1.corei7_64", b" \\02",
            b" connman-tools-1.29-r1.corei7_64", b" \\03",
        )
        first = INVENTORY.build_report(data, "Nvra.dump", ["missing", "connman"])
        second = INVENTORY.build_report(data, "Nvra.dump", ["connman", "missing"])
        self.assertEqual(first, second)
        self.assertEqual(first["package_count"], 3)
        self.assertEqual(first["unique_name_count"], 3)
        self.assertEqual([item["name"] for item in first["selected"]], ["connman"])
        self.assertEqual(first["missing_selectors"], ["missing"])
        self.assertNotIn("packages", first)

    def test_include_all_sorts_records(self):
        data = dump_bytes(
            b" z-2-r0.x86", b" \\02",
            b" a-1-r0.x86", b" \\01",
        )
        report = INVENTORY.build_report(data, "Nvra.dump", include_all=True)
        self.assertEqual([item["name"] for item in report["packages"]], ["a", "z"])

    def test_rejects_bad_structure_and_print_escapes(self):
        cases = [
            b"VERSION=3\nformat=print\ntype=btree\nDATA=END\n",
            dump_bytes(b" package-1-r0.x86"),
            dump_bytes(b" package-1-r0.x86", b" \\q1"),
            dump_bytes(b" not-an-nvra", b" \\01"),
            dump_bytes(b" package-1-r0.x86", b" \\01", headers=(b"format=bytevalue",)),
        ]
        for data in cases:
            with self.subTest(data=data):
                with self.assertRaises(INVENTORY.InventoryError):
                    INVENTORY.parse_dump(data)


class FileSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.source = self.directory / "Nvra.dump"
        self.source.write_bytes(dump_bytes(b" connman-1-r0.x86", b" \\01"))

    def tearDown(self):
        self.temp.cleanup()

    def test_rejects_symlink_input_and_output(self):
        source_link = self.directory / "source-link"
        source_link.symlink_to(self.source)
        with self.assertRaisesRegex(INVENTORY.InventoryError, "symlink"):
            INVENTORY.validate_input(source_link)

        output_link = self.directory / "output.json"
        output_link.symlink_to(self.source)
        with self.assertRaisesRegex(INVENTORY.InventoryError, "symlink"):
            INVENTORY.validate_output(output_link, self.source.resolve())

    def test_atomic_output_breaks_existing_hardlink(self):
        output = self.directory / "report.json"
        original = self.source.read_bytes()
        os.link(self.source, output)
        validated = INVENTORY.validate_output(output, self.source.resolve())
        INVENTORY.write_output_atomic(validated, '{"safe": true}\n')
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(output.read_text(encoding="utf-8"), '{"safe": true}\n')
        self.assertNotEqual(self.source.stat().st_ino, output.stat().st_ino)

    def test_cli_writes_selected_json(self):
        output = self.directory / "report.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                str(self.source),
                "--select", "connman",
                "--output", str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["selected"][0]["nvra"], "connman-1-r0.x86")
        self.assertEqual(report["missing_selectors"], [])


if __name__ == "__main__":
    unittest.main()
