"""Tests for the exact AppFUMO PartitionUpdater integrity analyzer."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/uk_fw/appfumo_partition_write_integrity.py"
ELF = ROOT / "work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf"
MANIFEST = ROOT / "evidence/artifacts/update-candidates/appfumo-partition-write-integrity-manifest.json"
REPORT = ROOT / "evidence/artifacts/update-candidates/appfumo-partition-write-integrity.json"
EXCERPT = ROOT / "evidence/artifacts/update-candidates/appfumo-partition-write-integrity-exact-static.asm"
BREW = shutil.which("brew")
LLVM_BIN = Path(subprocess.check_output([BREW, "--prefix", "llvm"], text=True).strip()) / "bin" if BREW else Path("/nonexistent")
OBJDUMP = LLVM_BIN / "llvm-objdump"
READELF = LLVM_BIN / "llvm-readelf"
EXACT_AVAILABLE = all(path.is_file() for path in (ELF, MANIFEST, REPORT, EXCERPT, OBJDUMP, READELF))

SPEC = importlib.util.spec_from_file_location("appfumo_partition_write_integrity", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")


def minimal_elf(*, duplicate_load: bool = False) -> bytes:
    size = 0x3000
    raw = bytearray(size)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    phnum = 2 if duplicate_load else 1
    raw[:ELF_HEADER.size] = ELF_HEADER.pack(
        ident, 3, 62, 1, 0, ELF_HEADER.size, 0, 0,
        ELF_HEADER.size, PROGRAM_HEADER.size, phnum, 0, 0, 0,
    )
    row = PROGRAM_HEADER.pack(1, 5, 0, 0, 0, size, size, 0x1000)
    raw[ELF_HEADER.size:ELF_HEADER.size + PROGRAM_HEADER.size] = row
    if duplicate_load:
        offset = ELF_HEADER.size + PROGRAM_HEADER.size
        raw[offset:offset + PROGRAM_HEADER.size] = row
    return bytes(raw)


def exact_command() -> list[str]:
    return [
        sys.executable, str(TOOL), "--elf", str(ELF),
        "--llvm-objdump", str(OBJDUMP), "--llvm-readelf", str(READELF),
        "--manifest", str(MANIFEST),
    ]


@lru_cache(maxsize=4)
def run_exact(encoding: str) -> bytes:
    env = dict(os.environ, PYTHONIOENCODING=encoding)
    completed = subprocess.run(exact_command(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if completed.stderr:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    return completed.stdout


@lru_cache(maxsize=1)
def exact_instructions() -> tuple:
    raw = subprocess.run([str(OBJDUMP), "-d", "--no-show-raw-insn", str(ELF)], check=True, stdout=subprocess.PIPE).stdout
    return tuple(M.parse_disassembly(raw))


class ParserAndSafetyTests(unittest.TestCase):
    def test_disassembly_rejects_empty_malformed_duplicate_and_ordering(self) -> None:
        with self.assertRaisesRegex(M.IntegrityError, "no decoded instructions"):
            M.parse_disassembly(b"Disassembly of section .text:\n")
        with self.assertRaisesRegex(M.IntegrityError, "mnemonic"):
            M.parse_disassembly(b"Disassembly of section .text:\n  10: ??? operand\n")
        with self.assertRaisesRegex(M.IntegrityError, "duplicate"):
            M.parse_disassembly(b"Disassembly of section .text:\n  10: nop\n  10: retq\n")
        with self.assertRaisesRegex(M.IntegrityError, "strictly increasing"):
            M.parse_disassembly(b"Disassembly of section .text:\n  11: nop\n  10: retq\n")
        with self.assertRaisesRegex(M.IntegrityError, "malformed or truncated"):
            M.parse_disassembly(b"Disassembly of section .text:\n  10:\n")

    def test_fde_and_build_id_parsers_fail_closed(self) -> None:
        valid = (b"  [0x20] FDE length=10 cie=[0x10]\n"
                 b"    initial_location: 0x100\n"
                 b"    address_range: 0x20 (end : 0x120)\n")
        self.assertEqual(M.parse_fdes(valid), [(0x100, 0x120)])
        with self.assertRaisesRegex(M.IntegrityError, "malformed FDE"):
            M.parse_fdes(valid.replace(b"0x120", b"0x121"))
        with self.assertRaisesRegex(M.IntegrityError, "duplicate"):
            M.parse_fdes(valid + valid)
        with self.assertRaisesRegex(M.IntegrityError, "no FDE"):
            M.parse_fdes(b"truncated\n")
        with self.assertRaisesRegex(M.IntegrityError, "malformed or truncated FDE"):
            M.parse_fdes(b"  [0x20] FDE length=10 cie=[0x10]\n    initial_location: 0x100\n")
        with self.assertRaisesRegex(M.IntegrityError, "absent or ambiguous"):
            M.parse_build_id(b"Build ID: aa\nBuild ID: bb\n")

    def test_elf_mapping_rejects_truncated_ambiguous_and_unmapped(self) -> None:
        with self.assertRaisesRegex(M.IntegrityError, "truncated"):
            M.ElfView(b"\x7fELF")
        with self.assertRaisesRegex(M.IntegrityError, "ambiguous"):
            M.ElfView(minimal_elf(duplicate_load=True)).map(0x100, 1, "fixture")
        with self.assertRaisesRegex(M.IntegrityError, "unmapped"):
            M.ElfView(minimal_elf()).map(0x4000, 1, "fixture")

    def test_regular_reader_rejects_nonregular_oversized_and_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with self.assertRaisesRegex(M.IntegrityError, "not a regular file"):
                M._read_regular(directory, 8, "fixture")
            item = directory / "input"
            item.write_bytes(b"12345")
            with self.assertRaisesRegex(M.IntegrityError, "size limit"):
                M._read_regular(item, 4, "fixture")
            before = item.stat()
            changed = SimpleNamespace(**{key: getattr(before, key) for key in ("st_mode", "st_size", "st_dev", "st_ino", "st_mtime_ns")})
            changed.st_mtime_ns += 1
            with mock.patch.object(Path, "stat", side_effect=(before, changed)):
                with self.assertRaisesRegex(M.IntegrityError, "changed while being read"):
                    M._read_regular(item, 8, "fixture")

    def test_manifest_rejects_unknown_missing_wrong_type_bool_and_drift(self) -> None:
        source = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutations = []
        value = json.loads(json.dumps(source)); value["extra"] = 1; mutations.append(value)
        value = json.loads(json.dumps(source)); del value["artifact"]["build_id"]; mutations.append(value)
        value = json.loads(json.dumps(source)); value["artifact"]["size"] = True; mutations.append(value)
        value = json.loads(json.dumps(source)); value["expected"]["anchors"] = {}; mutations.append(value)
        value = json.loads(json.dumps(source)); value["expected"]["direct_transfers"][0]["call_vas"] = []; mutations.append(value)
        value = json.loads(json.dumps(source)); value["expected"]["fdes"][0]["end_exclusive"] += 1; mutations.append(value)
        value = json.loads(json.dumps(source)); value["expected"]["blobs"][0]["length"] += 1; mutations.append(value)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            for index, mutation in enumerate(mutations):
                with self.subTest(index=index):
                    path.write_text(json.dumps(mutation), encoding="utf-8")
                    with self.assertRaises(M.IntegrityError):
                        M._load_manifest(path)
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(M.IntegrityError, "duplicate JSON key"):
                M._load_manifest(path)

    @unittest.skipUnless(EXACT_AVAILABLE, "authorized ignored exact ELF or Homebrew LLVM is unavailable")
    def test_post_write_direct_crypto_edge_fails_closed(self) -> None:
        manifest = M._load_manifest(MANIFEST)
        rows = list(exact_instructions())
        rows.append(M.Instruction(0xD1000, "callq", "0xc1ff0 <.text+0x9d7c0>"))
        rows.sort(key=lambda item: item.address)
        with self.assertRaisesRegex(M.IntegrityError, "direct-transfer inventory drift"):
            M._validate_semantics(rows, manifest["expected"])

    @unittest.skipUnless(EXACT_AVAILABLE, "authorized ignored exact ELF or Homebrew LLVM is unavailable")
    def test_mismatch_and_mode_gate_drift_fail_closed(self) -> None:
        manifest = M._load_manifest(MANIFEST)
        rows = list(exact_instructions())
        index = next(i for i, item in enumerate(rows) if item.address == 0xCD70B)
        rows[index] = M.Instruction(0xCD70B, "je", "0xcda20 <.text+0xa91f0>")
        with self.assertRaises(M.IntegrityError):
            M._validate_semantics(rows, manifest["expected"])

    @unittest.skipUnless(OBJDUMP.is_file(), "Homebrew llvm-objdump is unavailable")
    def test_tool_file_identity_is_enforced(self) -> None:
        raw = OBJDUMP.read_bytes()
        version = subprocess.check_output([str(OBJDUMP), "--version"], text=True).splitlines()[0]
        with self.assertRaisesRegex(M.IntegrityError, "file identity"):
            M._validate_tool(OBJDUMP, version, len(raw), "00" * 32, "llvm-objdump")


@unittest.skipUnless(EXACT_AVAILABLE, "authorized ignored exact ELF or Homebrew LLVM is unavailable")
class ExactArtifactTests(unittest.TestCase):
    def test_cli_is_utf8_lf_deterministic_and_matches_report(self) -> None:
        outputs = [run_exact(value) for value in ("ascii:strict", "latin-1:strict", "utf-16:strict")]
        self.assertEqual(len(set(outputs)), 1)
        self.assertNotIn(b"\r", outputs[0])
        self.assertEqual(outputs[0], REPORT.read_bytes())

    def test_exact_route_and_direct_inventory(self) -> None:
        report = json.loads(run_exact("ascii:strict"))
        self.assertEqual(report["evidence"]["selected_fdes"]["slot-hash-check"], {"start": "0xcd640", "end_exclusive": "0xce067"})
        self.assertEqual(report["evidence"]["direct_transfers"]["0xc1ff0"]["calls"], ["0xcd6fa", "0xcdbae"])
        self.assertEqual(report["evidence"]["direct_transfers"]["0xc53d0"]["jumps"], ["0xcd5db", "0xce110"])
        self.assertEqual(report["evidence"]["direct_transfers"]["0xd1e70"], {"calls": [], "jumps": []})

    def test_mode_mismatch_and_source_binding_are_narrow(self) -> None:
        report = json.loads(run_exact("ascii:strict"))
        integrity = report["pre_write_integrity"]
        self.assertTrue(integrity["both_source_verifier_results_must_equal_zero"])
        self.assertFalse(integrity["mismatch_reaches_write_starter"])
        self.assertIsNone(integrity["exact_signed_byte_ranges"])
        self.assertIsNone(integrity["rsa_padding_or_signature_encoding"])
        binding = report["source_binding"]
        self.assertTrue(binding["same_stored_qstring_pathname_value_reaches_verifier_and_writer"])
        self.assertTrue(binding["verifier_and_writer_reopen_pathname_independently"])
        self.assertFalse(binding["retained_file_descriptor_or_open_object"])
        self.assertIsNone(binding["same_source_byte_identity"])
        self.assertIsNone(binding["source_package_integrity_bound_to_transformed_final_partition_bytes"])

    def test_target_completion_and_boot_boundaries(self) -> None:
        report = json.loads(run_exact("ascii:strict"))
        target = report["target_selection"]
        self.assertEqual(target["writer_target_field_offset"], "0x28")
        self.assertIsNone(target["inactive_helper_output_to_exact_runtime_record_instance"])
        self.assertIsNone(target["bootloader_slot_activation"])
        self.assertIsNone(target["bootloader_mark_good"])
        completion = report["write_and_completion"]
        self.assertFalse(completion["process_completion_is_cryptographic_readback"])
        self.assertFalse(completion["same_source_verifier_directly_reinvoked_post_write"])
        self.assertIsNone(completion["all_indirect_external_or_inlined_destination_verification_absent"])
        self.assertIsNone(completion["final_partition_byte_identity"])

    def test_privacy_and_unknown_outcomes(self) -> None:
        output = run_exact("ascii:strict")
        report = json.loads(output)
        combined = output + REPORT.read_bytes() + MANIFEST.read_bytes() + EXCERPT.read_bytes()
        self.assertNotIn(b"/Users/", combined)
        self.assertNotIn(str(ELF).encode("utf-8"), output)
        self.assertFalse(report["scope"]["operator_paths_emitted"])
        self.assertFalse(report["scope"]["target_pathnames_or_commands_emitted"])
        self.assertFalse(report["scope"]["proprietary_binary_bytes_emitted"])
        self.assertIsNone(report["scope"]["slot_change"])
        self.assertIsNone(report["scope"]["root"])
        self.assertIsNone(report["scope"]["persistence"])

    def test_complete_instruction_and_fde_identity_reject_truncation(self) -> None:
        manifest = M._load_manifest(MANIFEST)
        instructions = list(exact_instructions())
        self.assertNotEqual(len(instructions) - 1, manifest["llvm"]["instruction_count"])
        self.assertNotEqual(M._canonical_hash(item.canonical for item in instructions[:-1]), manifest["llvm"]["instruction_sha256"])
        unwind = subprocess.run([str(READELF), "--unwind", str(ELF)], check=True, stdout=subprocess.PIPE).stdout
        fdes = M.parse_fdes(unwind)
        self.assertNotEqual(M._canonical_hash(f"{start:x}-{end:x}" for start, end in fdes[:-1]), manifest["llvm"]["fde_sha256"])


if __name__ == "__main__":
    unittest.main()
