"""Tests for the bounded Qt 5 revision-7 meta-object decoder."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/uk_fw/qt5_metaobject_rev7.py"
EXACT_ELF = (
    ROOT
    / "work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf"
)
EXACT_MANIFEST = (
    ROOT
    / "evidence/artifacts/update-candidates/appfumo-qt-metaobject-forwarding-manifest.json"
)
EXACT_EXCERPT = (
    ROOT
    / "evidence/artifacts/update-candidates/appfumo-qt-metaobject-exact-static.txt"
)
EXACT_REPORT = (
    ROOT
    / "evidence/artifacts/update-candidates/appfumo-qt-metaobject-index-64.json"
)
SPEC = importlib.util.spec_from_file_location("qt5_metaobject_rev7", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
QBYTEARRAYDATA = struct.Struct("<iiIIq")
METADATA_VA = 0x400
STRINGDATA_VA = 0x1000


def align(value: int, amount: int = 8) -> int:
    return (value + amount - 1) & ~(amount - 1)


def make_elf(
    methods: list[dict],
    *,
    class_name: str = "SyntheticClass",
    revision: int = 7,
    signal_count: int = 0,
    negative_string: str | None = None,
) -> tuple[bytes, dict[str, int]]:
    """Build a bounded valid ELF/data fixture; it is bytes only, never executable."""
    strings: list[str] = [class_name, ""]

    def string_index(text: str) -> int:
        if text not in strings:
            strings.append(text)
        return strings.index(text)

    rows: list[list[int]] = []
    params: list[list[int]] = []
    for method in methods:
        name_index = string_index(method["name"])
        tag_index = string_index(method.get("tag", ""))
        arg_types = []
        for type_value in method.get("types", []):
            if isinstance(type_value, str):
                arg_types.append(0x80000000 | string_index(type_value))
            else:
                arg_types.append(type_value)
        arg_names = [string_index(name) for name in method.get("names", [])]
        assert len(arg_types) == len(arg_names)
        return_type = method.get("return", 43)
        if isinstance(return_type, str):
            return_type = 0x80000000 | string_index(return_type)
        params.append([return_type, *arg_types, *arg_names])
        rows.append([name_index, len(arg_types), 0, tag_index, method.get("flags", 0x0A)])

    method_word_offset = 14
    parameter_cursor = method_word_offset + 5 * len(rows)
    for row, record in zip(rows, params):
        row[2] = parameter_cursor
        parameter_cursor += len(record)
    header = [
        revision,
        0,
        0,
        0,
        len(rows),
        method_word_offset,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        signal_count,
    ]

    size = 0x3000
    data = bytearray(size)
    metadata_words = header + [word for row in rows for word in row] + [
        word for record in params for word in record
    ]
    struct.pack_into(f"<{len(metadata_words)}I", data, METADATA_VA, *metadata_words)

    payload_cursor = align(STRINGDATA_VA + len(strings) * QBYTEARRAYDATA.size, 16)
    string_info: dict[str, int] = {}
    for index, text in enumerate(strings):
        encoded = text.encode("utf-8")
        descriptor_va = STRINGDATA_VA + index * QBYTEARRAYDATA.size
        if text == negative_string:
            data_va = STRINGDATA_VA - 0x200 + index * 32
        else:
            data_va = payload_cursor
            payload_cursor += len(encoded) + 1
        data[data_va : data_va + len(encoded) + 1] = encoded + b"\0"
        QBYTEARRAYDATA.pack_into(
            data,
            descriptor_va,
            -1,
            len(encoded),
            0,
            0,
            data_va - descriptor_va,
        )
        string_info[f"string_{index}_descriptor"] = descriptor_va
        string_info[f"string_{index}_data"] = data_va

    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    data[: ELF_HEADER.size] = ELF_HEADER.pack(
        ident,
        3,
        62,
        1,
        0,
        ELF_HEADER.size,
        0,
        0,
        ELF_HEADER.size,
        PROGRAM_HEADER.size,
        1,
        0,
        0,
        0,
    )
    data[ELF_HEADER.size : ELF_HEADER.size + PROGRAM_HEADER.size] = PROGRAM_HEADER.pack(
        1, 5, 0, 0, 0, size, size, 0x1000
    )
    return bytes(data), string_info


def decode(data: bytes, index: int = 0, **kwargs):
    return M.decode(
        data,
        metadata_va=kwargs.pop("metadata_va", METADATA_VA),
        stringdata_va=kwargs.pop("stringdata_va", STRINGDATA_VA),
        local_method_index=index,
        **kwargs,
    )


def synthetic_manifest(data: bytes, excerpt: bytes) -> dict:
    return {
        "schema_version": 1,
        "artifact_sha256": hashlib.sha256(data).hexdigest(),
        "local_method_index": 0,
        "evidence_excerpt_sha256": hashlib.sha256(excerpt).hexdigest(),
        "forwarding": {
            "status": "resolved",
            "static_metacall_va": 0x300,
            "dispatcher_end_va_exclusive": 0x400,
            "jump_table_base_va": 0x200,
            "jump_table_entry_size_bytes": 4,
            "jump_table_entry_va": 0x200,
            "jump_table_entry_raw_u32": 0x100,
            "case_target_va": 0x300,
            "callee_va": 0x500,
            "verifier_call_va": 0x520,
            "argument_semantics": {
                "a_2": "destPath",
                "a_1": "encFile",
                "call_rdx": "encFile",
                "call_rcx": "destPath",
                "return": "QString -> a[0]",
            },
        },
        "producer_provenance": {
            "status": "unresolved",
            "direct_reference_search": {
                "kind": "x86-64 direct call/lea",
                "target_va": 0x500,
                "observed_internal_call_vas": [0x350],
                "generated_metacall_call_va": 0x350,
                "complete_producer_absence_proven": False,
            },
            "remaining_unknowns": [
                "dynamic meta-invocation",
                "indirect calls",
                "external paths",
                "runtime invocation",
                "external reachability",
                "attacker control",
            ],
        },
    }


class Qt5MetaObjectRev7Tests(unittest.TestCase):
    def test_valid_zero_argument_public_slot(self) -> None:
        data, _ = make_elf([{"name": "refresh", "types": [], "names": []}])
        report = decode(data)
        method = report["metaobject"]["method"]
        self.assertEqual(method["signature"], "refresh()")
        self.assertEqual(method["declaration"], "void refresh()")
        self.assertEqual(method["parameter_record"]["raw_words"], [43])
        self.assertEqual(
            method["parameter_record"]["word_interval"],
            {"start": 19, "end_exclusive": 20},
        )
        self.assertEqual(method["flags"]["access"], "public")
        self.assertEqual(method["flags"]["method_type"], "slot")
        self.assertEqual(report["analysis_status"]["metadata_binding"]["status"], "resolved")
        self.assertEqual(report["analysis_status"]["forwarding"]["status"], "unresolved")
        self.assertEqual(report["analysis_status"]["producer_provenance"]["status"], "unresolved")

    def test_two_arguments_builtin_and_string_referenced_types(self) -> None:
        data, _ = make_elf(
            [
                {
                    "name": "convert",
                    "types": [10, "CustomType"],
                    "names": ["source", ""],
                    "return": 10,
                }
            ]
        )
        method = decode(data)["metaobject"]["method"]
        self.assertEqual(method["signature"], "convert(QString source, CustomType)")
        self.assertEqual(method["return_type"]["encoding"], "built-in")
        self.assertEqual(method["return_type"]["metatype_id"], 10)
        self.assertEqual(method["parameters"][1]["type"]["encoding"], "string-reference")
        self.assertEqual(method["parameters"][1]["name"]["text"], "")
        self.assertEqual(method["parameter_record"]["word_count"], 5)

    def test_signed_negative_descriptor_relative_offset(self) -> None:
        data, info = make_elf(
            [{"name": "backward", "types": [], "names": []}],
            negative_string="backward",
        )
        name = decode(data)["metaobject"]["method"]["name"]
        self.assertLess(name["descriptor_fields"]["signed_data_offset"], 0)
        self.assertEqual(name["data_va"], hex(info["string_2_data"]))

    def test_overloads_and_empty_parameter_names(self) -> None:
        data, _ = make_elf(
            [
                {"name": "overloaded", "types": [], "names": []},
                {"name": "overloaded", "types": [2], "names": [""]},
            ]
        )
        self.assertEqual(decode(data, 0)["metaobject"]["method"]["signature"], "overloaded()")
        second = decode(data, 1)["metaobject"]["method"]
        self.assertEqual(second["signature"], "overloaded(int)")
        self.assertEqual(second["name"]["string_index"], 2)

    def test_local_index_and_signal_count_are_explicit(self) -> None:
        data, _ = make_elf(
            [
                {"name": "slotZero", "types": [], "names": []},
                {"name": "slotOne", "types": [], "names": []},
            ],
            signal_count=1,
        )
        with self.assertRaisesRegex(M.DecodeError, "signal prefix"):
            decode(data, 0)
        second = decode(data, 1)["metaobject"]["method"]
        self.assertIsNone(second["signal_number"])
        self.assertEqual(second["index_scope"], "local-to-declaring-metaobject")
        self.assertTrue(second["declared_in_selected_metaobject"])
        self.assertIsNone(second["absolute_method_index"])
        self.assertIn("methodOffset", second["index_scope_basis"])

    def test_rejects_out_of_range_index_revision_and_flags(self) -> None:
        base = [{"name": "slot", "types": [], "names": []}]
        data, _ = make_elf(base)
        with self.assertRaisesRegex(M.DecodeError, "outside the method table"):
            decode(data, 1)
        data, _ = make_elf(base, revision=8)
        with self.assertRaisesRegex(M.DecodeError, "revision"):
            decode(data)
        for flags in (0x02, 0x06, 0x0C, 0x20A):
            data, _ = make_elf([{**base[0], "flags": flags}])
            with self.subTest(flags=flags):
                with self.assertRaisesRegex(M.DecodeError, "flags|not a Qt slot"):
                    decode(data)

    def test_rejects_unsupported_elf_abi_endianness_and_machine(self) -> None:
        data, _ = make_elf([{"name": "slot", "types": [], "names": []}])
        mutations = (
            (4, 1, "ELF class"),
            (5, 2, "endianness"),
            (18, 3, "machine"),
            (54, 55, "program-header ABI"),
        )
        for offset, value, message in mutations:
            changed = bytearray(data)
            changed[offset] = value
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(M.DecodeError, message):
                    decode(bytes(changed))

    def test_rejects_ambiguous_and_unmapped_load_ranges(self) -> None:
        data, _ = make_elf([{"name": "slot", "types": [], "names": []}])
        ambiguous = bytearray(data)
        struct.pack_into("<H", ambiguous, 56, 2)
        ambiguous[ELF_HEADER.size + PROGRAM_HEADER.size : ELF_HEADER.size + 2 * PROGRAM_HEADER.size] = (
            PROGRAM_HEADER.pack(1, 5, 0, 0, 0, len(data), len(data), 0x1000)
        )
        with self.assertRaisesRegex(M.DecodeError, "ambiguous"):
            decode(bytes(ambiguous))
        with self.assertRaisesRegex(M.DecodeError, "not in a file-backed"):
            decode(data, metadata_va=0x5000)

    def test_rejects_count_range_and_overflow_bounds(self) -> None:
        data, _ = make_elf([{"name": "slot", "types": [], "names": []}])
        excessive = bytearray(data)
        struct.pack_into("<I", excessive, METADATA_VA + 4 * 4, M.MAX_METHODS + 1)
        with self.assertRaisesRegex(M.DecodeError, "method count"):
            decode(bytes(excessive))

        bad_signals = bytearray(data)
        struct.pack_into("<I", bad_signals, METADATA_VA + 13 * 4, 2)
        with self.assertRaisesRegex(M.DecodeError, "signal count"):
            decode(bytes(bad_signals))

        bad_table = bytearray(data)
        struct.pack_into("<I", bad_table, METADATA_VA + 5 * 4, 0xFFFFFFFF)
        with self.assertRaisesRegex(M.DecodeError, "method table"):
            decode(bytes(bad_table))

        with self.assertRaisesRegex(M.DecodeError, "overflows uint64"):
            M.ElfView(data).map_range(M.U64_MAX - 1, 4, "overflow probe")

    def test_rejects_invalid_utf8_string_bounds_and_layout(self) -> None:
        data, info = make_elf([{"name": "slot", "types": [], "names": []}])
        invalid = bytearray(data)
        invalid[info["string_2_data"]] = 0xFF
        with self.assertRaisesRegex(M.DecodeError, "UTF-8"):
            decode(bytes(invalid))

        unterminated = bytearray(data)
        name_data = info["string_2_data"]
        unterminated[name_data + len("slot")] = ord("X")
        with self.assertRaisesRegex(M.DecodeError, "NUL terminated"):
            decode(bytes(unterminated))

        layout = bytearray(data)
        struct.pack_into("<I", layout, info["string_2_descriptor"] + 12, 1)
        with self.assertRaisesRegex(M.DecodeError, "layout"):
            decode(bytes(layout))

    def test_rejects_parameter_overlap_with_method_and_auxiliary_tables(self) -> None:
        data, _ = make_elf([{"name": "slot", "types": [], "names": []}])
        row = METADATA_VA + 14 * 4

        method_overlap = bytearray(data)
        struct.pack_into("<I", method_overlap, row + 8, 18)
        with self.assertRaisesRegex(M.DecodeError, "parameter record overlaps method table"):
            decode(bytes(method_overlap))

        auxiliary_overlap = bytearray(data)
        struct.pack_into("<I", auxiliary_overlap, METADATA_VA + 6 * 4, 1)
        struct.pack_into("<I", auxiliary_overlap, METADATA_VA + 7 * 4, 19)
        with self.assertRaisesRegex(M.DecodeError, "parameter record overlaps property table"):
            decode(bytes(auxiliary_overlap))

    def test_rejects_inter_parameter_overlap_and_unselected_malformed_row(self) -> None:
        data, _ = make_elf(
            [
                {"name": "first", "types": [], "names": []},
                {"name": "second", "types": [], "names": []},
            ]
        )
        second_row = METADATA_VA + (14 + 5) * 4
        overlap = bytearray(data)
        first_parameter_offset = struct.unpack_from("<I", overlap, METADATA_VA + 14 * 4 + 8)[0]
        struct.pack_into("<I", overlap, second_row + 8, first_parameter_offset)
        with self.assertRaisesRegex(M.DecodeError, "method parameter record overlap"):
            decode(bytes(overlap), 0)

        malformed_unselected = bytearray(data)
        struct.pack_into("<I", malformed_unselected, second_row + 4, M.MAX_ARGUMENTS + 1)
        with self.assertRaisesRegex(M.DecodeError, "local method 1 argument count"):
            decode(bytes(malformed_unselected), 0)

    def test_rejects_truncated_parameter_record_and_unknown_type(self) -> None:
        data, _ = make_elf([{"name": "slot", "types": [10], "names": ["arg"]}])
        malformed = bytearray(data)
        row = METADATA_VA + 14 * 4
        struct.pack_into("<I", malformed, row + 8, (len(data) - METADATA_VA) // 4)
        with self.assertRaisesRegex(M.DecodeError, "local method 0 parameter record"):
            decode(bytes(malformed))

        unknown, _ = make_elf([{"name": "slot", "types": [999], "names": ["arg"]}])
        with self.assertRaisesRegex(M.DecodeError, "metatype ID"):
            decode(unknown)

    def test_cli_is_deterministic_utf8_lf_independent_of_stdio_encoding(self) -> None:
        data, _ = make_elf([{"name": "méthod", "types": [10], "names": ["路径"]}])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.elf"
            path.write_bytes(data)
            command = [
                sys.executable,
                str(TOOL),
                "--elf",
                str(path),
                "--metadata-va",
                hex(METADATA_VA),
                "--stringdata-va",
                hex(STRINGDATA_VA),
                "--local-method-index",
                "0",
            ]
            outputs = []
            for encoding in ("ascii:strict", "latin-1:strict", "utf-16:strict"):
                env = dict(os.environ, PYTHONIOENCODING=encoding)
                run = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                self.assertNotIn(b"\r", run.stdout)
                self.assertEqual(json.loads(run.stdout)["metaobject"]["method"]["name"]["text"], "méthod")
                outputs.append(run.stdout)
            self.assertEqual(len(set(outputs)), 1)

    def test_manifest_requires_verified_current_evidence_excerpt(self) -> None:
        raw, _ = make_elf([{"name": "slot", "types": [], "names": []}])
        changed = bytearray(raw)
        struct.pack_into("<I", changed, 0x200, 0x100)
        data = bytes(changed)
        excerpt = b"bounded synthetic forwarding evidence\n"
        valid = synthetic_manifest(data, excerpt)
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            excerpt_path = Path(tmp) / "excerpt.txt"
            manifest_path.write_text(json.dumps(valid), encoding="utf-8")
            excerpt_path.write_bytes(excerpt)

            report = decode(
                data,
                evidence_manifest=manifest_path,
                evidence_excerpt=excerpt_path,
            )
            self.assertEqual(report["analysis_status"]["forwarding"]["status"], "resolved")
            self.assertEqual(report["analysis_status"]["producer_provenance"]["status"], "unresolved")
            self.assertEqual(
                report["evidence_manifest"]["evidence_excerpt_sha256"],
                hashlib.sha256(excerpt).hexdigest(),
            )
            self.assertNotIn(str(excerpt_path), json.dumps(report))

            with self.assertRaisesRegex(M.DecodeError, "supplied together"):
                decode(data, evidence_manifest=manifest_path)
            with self.assertRaisesRegex(M.DecodeError, "supplied together"):
                decode(data, evidence_excerpt=excerpt_path)

            excerpt_path.write_bytes(excerpt + b"changed")
            with self.assertRaisesRegex(M.DecodeError, "does not match current bytes"):
                decode(
                    data,
                    evidence_manifest=manifest_path,
                    evidence_excerpt=excerpt_path,
                )
            excerpt_path.unlink()
            with self.assertRaisesRegex(M.DecodeError, "cannot stat evidence excerpt"):
                decode(
                    data,
                    evidence_manifest=manifest_path,
                    evidence_excerpt=excerpt_path,
                )

            excerpt_path.write_bytes(excerpt)
            wrong_digest = json.loads(json.dumps(valid))
            wrong_digest["evidence_excerpt_sha256"] = "11" * 32
            manifest_path.write_text(json.dumps(wrong_digest), encoding="utf-8")
            with self.assertRaisesRegex(M.DecodeError, "does not match current bytes"):
                decode(
                    data,
                    evidence_manifest=manifest_path,
                    evidence_excerpt=excerpt_path,
                )

    def test_manifest_rejects_strict_type_identity_and_boundary_failures(self) -> None:
        raw, _ = make_elf([{"name": "slot", "types": [], "names": []}])
        changed = bytearray(raw)
        struct.pack_into("<I", changed, 0x200, 0x100)
        data = bytes(changed)
        excerpt = b"bounded synthetic forwarding evidence\n"
        valid = synthetic_manifest(data, excerpt)

        def mutation(path: tuple[str, ...], value) -> dict:
            result = json.loads(json.dumps(valid))
            cursor = result
            for part in path[:-1]:
                cursor = cursor[part]
            cursor[path[-1]] = value
            return result

        extra_nested = json.loads(json.dumps(valid))
        extra_nested["forwarding"]["argument_semantics"]["unexpected"] = "value"
        extra_search = json.loads(json.dumps(valid))
        extra_search["producer_provenance"]["direct_reference_search"]["extra"] = 1
        calls_without_metacall = mutation(
            ("producer_provenance", "direct_reference_search", "observed_internal_call_vas"),
            [0x351],
        )
        cases = (
            ({"schema_version": 1}, "keys mismatch"),
            ([], "must be an object"),
            (mutation(("schema_version",), True), "uint64 integer"),
            (mutation(("local_method_index",), False), "uint64 integer"),
            (mutation(("artifact_sha256",), "g" * 64), "lowercase hexadecimal"),
            (mutation(("evidence_excerpt_sha256",), "0" * 63), "lowercase hexadecimal"),
            (mutation(("artifact_sha256",), "11" * 32), "artifact identity"),
            (mutation(("local_method_index",), 1), "method index does not match"),
            (mutation(("forwarding", "callee_va"), "0x500"), "uint64 integer"),
            (mutation(("forwarding", "case_target_va"), 0x301), "displacement"),
            (mutation(("forwarding", "argument_semantics", "a_1"), "destPath"), "semantics"),
            (extra_nested, "keys mismatch"),
            (mutation(("producer_provenance", "status"), "resolved"), "must remain unresolved"),
            (
                mutation(
                    ("producer_provenance", "direct_reference_search", "complete_producer_absence_proven"),
                    0,
                ),
                "scope is unsupported",
            ),
            (calls_without_metacall, "facts are inconsistent"),
            (extra_search, "keys mismatch"),
            (
                mutation(("producer_provenance", "remaining_unknowns"), ["indirect calls"]),
                "unknowns are unsupported",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            excerpt_path = Path(tmp) / "excerpt.txt"
            excerpt_path.write_bytes(excerpt)
            for value, message in cases:
                manifest_path.write_text(json.dumps(value), encoding="utf-8")
                with self.subTest(message=message):
                    with self.assertRaisesRegex(M.DecodeError, message):
                        decode(
                            data,
                            evidence_manifest=manifest_path,
                            evidence_excerpt=excerpt_path,
                        )

    def test_manifest_rejects_signed_target_underflow_and_dispatcher_escape(self) -> None:
        raw, _ = make_elf([{"name": "slot", "types": [], "names": []}])
        excerpt = b"bounded synthetic forwarding evidence\n"
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            excerpt_path = Path(tmp) / "excerpt.txt"
            excerpt_path.write_bytes(excerpt)

            underflow = bytearray(raw)
            struct.pack_into("<I", underflow, 0x200, 0xFFFFFD00)
            underflow_data = bytes(underflow)
            underflow_manifest = synthetic_manifest(underflow_data, excerpt)
            underflow_manifest["forwarding"]["jump_table_entry_raw_u32"] = 0xFFFFFD00
            underflow_manifest["forwarding"]["case_target_va"] = 0
            manifest_path.write_text(json.dumps(underflow_manifest), encoding="utf-8")
            with self.assertRaisesRegex(M.DecodeError, "displacement"):
                decode(
                    underflow_data,
                    evidence_manifest=manifest_path,
                    evidence_excerpt=excerpt_path,
                )

            escaped = bytearray(raw)
            struct.pack_into("<I", escaped, 0x200, 0x500)
            escaped_data = bytes(escaped)
            escaped_manifest = synthetic_manifest(escaped_data, excerpt)
            escaped_manifest["forwarding"]["jump_table_entry_raw_u32"] = 0x500
            escaped_manifest["forwarding"]["case_target_va"] = 0x700
            manifest_path.write_text(json.dumps(escaped_manifest), encoding="utf-8")
            with self.assertRaisesRegex(M.DecodeError, "outside dispatcher range"):
                decode(
                    escaped_data,
                    evidence_manifest=manifest_path,
                    evidence_excerpt=excerpt_path,
                )

    def test_regular_file_reader_rejects_oversize_before_open_and_changed_size(self) -> None:
        regular_mode = stat.S_IFREG | 0o600
        oversized = mock.Mock()
        oversized.stat.return_value = SimpleNamespace(
            st_mode=regular_mode,
            st_size=M.MAX_FILE_SIZE + 1,
            st_dev=1,
            st_ino=2,
            st_mtime_ns=3,
        )
        with self.assertRaisesRegex(M.DecodeError, "bounded size limit"):
            M._read_regular_file(oversized, M.MAX_FILE_SIZE, "ELF input")
        oversized.open.assert_not_called()

        nonregular = mock.Mock()
        nonregular.stat.return_value = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_size=0,
            st_dev=1,
            st_ino=2,
            st_mtime_ns=3,
        )
        with self.assertRaisesRegex(M.DecodeError, "not a regular file"):
            M._read_regular_file(nonregular, M.MAX_FILE_SIZE, "ELF input")
        nonregular.open.assert_not_called()

        before = SimpleNamespace(
            st_mode=regular_mode,
            st_size=1,
            st_dev=1,
            st_ino=2,
            st_mtime_ns=3,
        )
        after = SimpleNamespace(
            st_mode=regular_mode,
            st_size=2,
            st_dev=1,
            st_ino=2,
            st_mtime_ns=4,
        )
        changed = mock.Mock()
        changed.stat.side_effect = [before, after]
        changed.open = mock.mock_open(read_data=b"x")
        with self.assertRaisesRegex(M.DecodeError, "changed while being read"):
            M._read_regular_file(changed, M.MAX_FILE_SIZE, "ELF input")

    @unittest.skipUnless(EXACT_ELF.is_file(), "authorized ignored exact ELF is absent")
    def test_exact_artifact_anchors_and_pinned_report(self) -> None:
        self.assertTrue(EXACT_MANIFEST.is_file())
        self.assertTrue(EXACT_EXCERPT.is_file())
        self.assertTrue(EXACT_REPORT.is_file())
        report = M.decode(
            EXACT_ELF.read_bytes(),
            metadata_va=0x444760,
            stringdata_va=0x445260,
            local_method_index=64,
            evidence_manifest=EXACT_MANIFEST,
            evidence_excerpt=EXACT_EXCERPT,
        )
        payload = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
        self.assertEqual(payload, EXACT_REPORT.read_bytes())
        self.assertEqual(report["input"]["sha256"], "464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7")
        meta = report["metaobject"]
        method = meta["method"]
        self.assertEqual((meta["method_count"], meta["method_table_word_offset"], meta["signal_count"]), (85, 14, 7))
        self.assertEqual(method["row_va"], "0x444c98")
        self.assertEqual(method["raw_words"], [98, 2, 631, 2, 10])
        self.assertEqual(method["parameter_record"]["va"], "0x44513c")
        self.assertEqual(method["parameter_record"]["raw_words"], [10, 10, 10, 99, 100])
        self.assertEqual(method["declaration"], "QString decryptionFile(QString encFile, QString destPath)")
        self.assertEqual(method["flags"]["raw"], 0x0A)
        self.assertEqual(method["index_scope"], "local-to-declaring-metaobject")
        self.assertTrue(method["declared_in_selected_metaobject"])
        self.assertIsNone(method["absolute_method_index"])
        self.assertIsNone(method["signal_number"])
        self.assertEqual(report["analysis_status"]["forwarding"]["case_target_va"], "0x16dfc6")
        self.assertEqual(report["analysis_status"]["forwarding"]["jump_table_entry_raw_u32"], "0xffd299c6")
        self.assertEqual(report["analysis_status"]["producer_provenance"]["status"], "unresolved")
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "330799c5215a0d3fda7c8870820240cb023c9b3a6c9673100778a038fe1d14a3",
        )


if __name__ == "__main__":
    unittest.main()
