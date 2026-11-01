"""Tests for the exact AppUpgrade parameterized-verifier analyzer."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
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
TOOL = ROOT / "tools/uk_fw/appfumo_parameterized_verifier_provenance.py"
ELF = ROOT / "work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf"
MANIFEST = ROOT / "evidence/artifacts/update-candidates/appfumo-parameterized-verifier-provenance-manifest.json"
REPORT = ROOT / "evidence/artifacts/update-candidates/appfumo-parameterized-verifier-provenance.json"
EXCERPT = ROOT / "evidence/artifacts/update-candidates/appfumo-parameterized-verifier-provenance-exact-static.asm"
BREW = shutil.which("brew")
LLVM_BIN = Path(subprocess.check_output([BREW, "--prefix", "llvm"], text=True).strip()) / "bin" if BREW else Path("/nonexistent")
OBJDUMP = LLVM_BIN / "llvm-objdump"
READELF = LLVM_BIN / "llvm-readelf"
EXACT_AVAILABLE = all(path.is_file() for path in (ELF, MANIFEST, REPORT, EXCERPT, OBJDUMP, READELF))

SPEC = importlib.util.spec_from_file_location("appfumo_parameterized_verifier_provenance", TOOL)
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
    raw[: ELF_HEADER.size] = ELF_HEADER.pack(
        ident, 3, 62, 1, 0, ELF_HEADER.size, 0, 0,
        ELF_HEADER.size, PROGRAM_HEADER.size, phnum, 0, 0, 0,
    )
    row = PROGRAM_HEADER.pack(1, 5, 0, 0, 0, size, size, 0x1000)
    raw[ELF_HEADER.size : ELF_HEADER.size + PROGRAM_HEADER.size] = row
    if duplicate_load:
        offset = ELF_HEADER.size + PROGRAM_HEADER.size
        raw[offset : offset + PROGRAM_HEADER.size] = row
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
        with self.assertRaisesRegex(M.ProvenanceError, "no decoded instructions"):
            M.parse_disassembly(b"Disassembly of section .text:\n")
        with self.assertRaisesRegex(M.ProvenanceError, "mnemonic"):
            M.parse_disassembly(b"Disassembly of section .text:\n  10: ??? operand\n")
        with self.assertRaisesRegex(M.ProvenanceError, "duplicate"):
            M.parse_disassembly(b"Disassembly of section .text:\n  10: nop\n  10: retq\n")
        with self.assertRaisesRegex(M.ProvenanceError, "strictly increasing"):
            M.parse_disassembly(b"Disassembly of section .text:\n  11: nop\n  10: retq\n")
        with self.assertRaisesRegex(M.ProvenanceError, "malformed or truncated"):
            M.parse_disassembly(b"Disassembly of section .text:\n  10:\n")

    def test_fde_and_build_id_parsers_fail_closed(self) -> None:
        valid = (
            b"  [0x20] FDE length=10 cie=[0x10]\n"
            b"    initial_location: 0x100\n"
            b"    address_range: 0x20 (end : 0x120)\n"
        )
        self.assertEqual(M.parse_fdes(valid), [(0x100, 0x120)])
        with self.assertRaisesRegex(M.ProvenanceError, "malformed FDE"):
            M.parse_fdes(valid.replace(b"0x120", b"0x121"))
        with self.assertRaisesRegex(M.ProvenanceError, "duplicate"):
            M.parse_fdes(valid + valid)
        with self.assertRaisesRegex(M.ProvenanceError, "no FDE"):
            M.parse_fdes(b"truncated\n")
        with self.assertRaisesRegex(M.ProvenanceError, "absent or ambiguous"):
            M.parse_build_id(b"Build ID: aa\nBuild ID: bb\n")

    def test_elf_mapping_rejects_truncated_ambiguous_and_unmapped(self) -> None:
        with self.assertRaisesRegex(M.ProvenanceError, "truncated"):
            M.ElfView(b"\x7fELF")
        with self.assertRaisesRegex(M.ProvenanceError, "ambiguous"):
            M.ElfView(minimal_elf(duplicate_load=True)).map(0x100, 1, "fixture")
        with self.assertRaisesRegex(M.ProvenanceError, "unmapped"):
            M.ElfView(minimal_elf()).map(0x4000, 1, "fixture")

    def test_regular_reader_rejects_nonregular_oversized_and_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with self.assertRaisesRegex(M.ProvenanceError, "not a regular file"):
                M._read_regular(directory, 8, "fixture")
            path = directory / "input"
            path.write_bytes(b"12345")
            with self.assertRaisesRegex(M.ProvenanceError, "size limit"):
                M._read_regular(path, 4, "fixture")
            before = path.stat()
            changed = SimpleNamespace(**{name: getattr(before, name) for name in ("st_mode", "st_size", "st_dev", "st_ino", "st_mtime_ns")})
            changed.st_mtime_ns += 1
            with mock.patch.object(Path, "stat", side_effect=(before, changed)):
                with self.assertRaisesRegex(M.ProvenanceError, "changed while being read"):
                    M._read_regular(path, 8, "fixture")

    def test_manifest_rejects_unknown_missing_wrong_type_bool_and_drift(self) -> None:
        source = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutations = []
        extra = json.loads(json.dumps(source)); extra["extra"] = 1; mutations.append(extra)
        missing = json.loads(json.dumps(source)); del missing["artifact"]["build_id"]; mutations.append(missing)
        boolean = json.loads(json.dumps(source)); boolean["artifact"]["size"] = True; mutations.append(boolean)
        wrong = json.loads(json.dumps(source)); wrong["expected"]["anchors"] = {}; mutations.append(wrong)
        caller = json.loads(json.dumps(source)); caller["expected"]["direct_calls"][1]["call_vas"] = []; mutations.append(caller)
        fde = json.loads(json.dumps(source)); fde["expected"]["fdes"][1]["end_exclusive"] += 1; mutations.append(fde)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            for index, value in enumerate(mutations):
                with self.subTest(index=index):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaises(M.ProvenanceError):
                        M._load_manifest(path)

    @unittest.skipUnless(EXACT_AVAILABLE, "authorized ignored exact ELF or Homebrew LLVM is unavailable")
    def test_unsupported_rbx_operand_provenance_fails_closed(self) -> None:
        manifest = M._load_manifest(MANIFEST)
        rows = list(exact_instructions())
        insertion = M.Instruction(0x9D100, "movq", "%rax, %rbx")
        rows.append(insertion)
        rows.sort(key=lambda item: item.address)
        with self.assertRaisesRegex(M.ProvenanceError, "RBX provenance is overwritten"):
            M._validate_semantics(rows, manifest["expected"])

    @unittest.skipUnless(OBJDUMP.is_file(), "Homebrew llvm-objdump is unavailable")
    def test_tool_file_identity_is_enforced(self) -> None:
        raw = OBJDUMP.read_bytes()
        version = subprocess.check_output([str(OBJDUMP), "--version"], text=True).splitlines()[0]
        with self.assertRaisesRegex(M.ProvenanceError, "file identity"):
            M._validate_tool(OBJDUMP, version, len(raw), "00" * 32, "llvm-objdump")


@unittest.skipUnless(EXACT_AVAILABLE, "authorized ignored exact ELF or Homebrew LLVM is unavailable")
class ExactArtifactTests(unittest.TestCase):
    def test_cli_is_utf8_lf_deterministic_and_matches_report(self) -> None:
        outputs = [run_exact(value) for value in ("ascii:strict", "latin-1:strict", "utf-16:strict")]
        self.assertEqual(len(set(outputs)), 1)
        self.assertNotIn(b"\r", outputs[0])
        self.assertEqual(outputs[0], REPORT.read_bytes())

    def test_exact_report_schema_and_operand_classification(self) -> None:
        report = json.loads(run_exact("ascii:strict"))
        self.assertEqual(set(report), {"schema_version", "tool", "artifact", "evidence", "call_0x9d1d2", "call_0x140092", "binding", "scope"})
        self.assertEqual(report["call_0x9d1d2"]["bounded_producer_classes"], ["mkbd-resource", "amp-resource", "adp-resource", "vess-resource"])
        self.assertFalse(report["call_0x9d1d2"]["can_be_running_or_staged_updater"])
        self.assertFalse(report["call_0x9d1d2"]["can_be_descriptor"])
        self.assertFalse(report["call_0x9d1d2"]["can_be_general_firmware_member"])
        self.assertTrue(report["call_0x9d1d2"]["can_be_controller_resource_member"])
        self.assertEqual(report["call_0x140092"]["immediate_direct_callers"], ["0x9d4fe"])
        self.assertEqual(report["evidence"]["selected_fdes"]["resource-route"], {"start": "0x9cbc0", "end_exclusive": "0x9e260"})
        self.assertEqual(report["evidence"]["selected_fdes"]["navigation-transform"], {"start": "0x140030", "end_exclusive": "0x1405da"})

    def test_binding_fails_closed_at_pathname_reopen(self) -> None:
        binding = json.loads(run_exact("ascii:strict"))["binding"]
        self.assertTrue(binding["same_pathname_value_reaches_both_verifiers_and_decrypt_source"])
        self.assertTrue(binding["pathname_reopened_by_verifier_and_transform"])
        self.assertFalse(binding["retained_descriptor_or_open_object"])
        self.assertFalse(binding["destination_exists_or_size_checked"])
        self.assertFalse(binding["transform_status_propagated"])
        self.assertIsNone(binding["authenticated_bytes_bound_to_transformed_bytes"])
        self.assertIsNone(binding["transformed_bytes_bound_to_final_consumed_image"])

    def test_scope_and_privacy_are_narrow(self) -> None:
        output = run_exact("ascii:strict")
        report = json.loads(output)
        self.assertEqual(report["artifact"]["sha256"], M._load_manifest(MANIFEST)["artifact"]["sha256"])
        self.assertIsNone(report["scope"]["unbounded_virtual_indirect_cross_process_producers"])
        self.assertFalse(report["scope"]["authentication_acceptance_proven"])
        self.assertFalse(report["scope"]["command_success_proven"])
        self.assertFalse(report["scope"]["root_or_persistence_proven"])
        self.assertNotIn(b"/Users/", output + REPORT.read_bytes() + MANIFEST.read_bytes() + EXCERPT.read_bytes())
        self.assertNotIn(str(ELF).encode("utf-8"), output)
        self.assertFalse(report["scope"]["operator_paths_emitted"])
        self.assertFalse(report["scope"]["proprietary_binary_bytes_emitted"])

    def test_exact_instruction_and_fde_identity_reject_truncation(self) -> None:
        manifest = M._load_manifest(MANIFEST)
        instructions = list(exact_instructions())
        truncated_hash = M._canonical_hash(item.canonical for item in instructions[:-1])
        self.assertNotEqual(len(instructions) - 1, manifest["llvm"]["instruction_count"])
        self.assertNotEqual(truncated_hash, manifest["llvm"]["instruction_sha256"])
        unwind = subprocess.run([str(READELF), "--unwind", str(ELF)], check=True, stdout=subprocess.PIPE).stdout
        fdes = M.parse_fdes(unwind)
        self.assertNotEqual(M._canonical_hash(f"{start:x}-{end:x}" for start, end in fdes[:-1]), manifest["llvm"]["fde_sha256"])


if __name__ == "__main__":
    unittest.main()
