"""Tests for the bounded AppUpgrade decryption dispatch analyzer."""
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
TOOL = ROOT / "tools/uk_fw/appfumo_decryption_dispatch_provenance.py"
ELF = ROOT / "work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf"
MANIFEST = ROOT / "evidence/artifacts/update-candidates/appfumo-decryption-dispatch-provenance-manifest.json"
REPORT = ROOT / "evidence/artifacts/update-candidates/appfumo-decryption-dispatch-provenance.json"
EXCERPT = ROOT / "evidence/artifacts/update-candidates/appfumo-decryption-dispatch-provenance-exact-static.txt"
BREW = shutil.which("brew")
if BREW:
    LLVM_BIN = Path(subprocess.check_output([BREW, "--prefix", "llvm"], text=True).strip()) / "bin"
else:
    LLVM_BIN = Path("/nonexistent")
OBJDUMP = LLVM_BIN / "llvm-objdump"
READELF = LLVM_BIN / "llvm-readelf"
EXACT_AVAILABLE = all(path.is_file() for path in (ELF, MANIFEST, REPORT, OBJDUMP, READELF))

SPEC = importlib.util.spec_from_file_location("appfumo_decryption_dispatch_provenance", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")


def minimal_elf(payloads: dict[int, bytes] | None = None, *, duplicate_load: bool = False) -> bytes:
    size = 0x3000
    raw = bytearray(size)
    for offset, value in (payloads or {}).items():
        raw[offset : offset + len(value)] = value
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    phnum = 2 if duplicate_load else 1
    raw[: ELF_HEADER.size] = ELF_HEADER.pack(
        ident, 3, 62, 1, 0, ELF_HEADER.size, 0, 0,
        ELF_HEADER.size, PROGRAM_HEADER.size, phnum, 0, 0, 0,
    )
    row = PROGRAM_HEADER.pack(1, 5, 0, 0, 0, size, size, 0x1000)
    raw[ELF_HEADER.size : ELF_HEADER.size + PROGRAM_HEADER.size] = row
    if duplicate_load:
        start = ELF_HEADER.size + PROGRAM_HEADER.size
        raw[start : start + PROGRAM_HEADER.size] = row
    return bytes(raw)


def exact_command() -> list[str]:
    return [
        sys.executable,
        str(TOOL),
        "--elf", str(ELF),
        "--llvm-objdump", str(OBJDUMP),
        "--llvm-readelf", str(READELF),
        "--manifest", str(MANIFEST),
    ]


@lru_cache(maxsize=4)
def run_exact(encoding: str) -> bytes:
    env = dict(os.environ, PYTHONIOENCODING=encoding)
    completed = subprocess.run(exact_command(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if completed.stderr:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    return completed.stdout


class ParserAndSafetyTests(unittest.TestCase):
    def test_disassembly_parser_rejects_empty_malformed_duplicate_and_ordering(self) -> None:
        with self.assertRaisesRegex(M.ProvenanceError, "no decoded instructions"):
            M.parse_disassembly(b"Disassembly of section .text:\n")
        with self.assertRaisesRegex(M.ProvenanceError, "mnemonic"):
            M.parse_disassembly(b"Disassembly of section .text:\n  10: ??? operand\n")
        with self.assertRaisesRegex(M.ProvenanceError, "duplicate"):
            M.parse_disassembly(b"Disassembly of section .text:\n  10: nop\n  10: retq\n")
        with self.assertRaisesRegex(M.ProvenanceError, "strictly increasing"):
            M.parse_disassembly(b"Disassembly of section .text:\n  11: nop\n  10: retq\n")

    def test_relocation_and_build_id_parsers_fail_closed(self) -> None:
        duplicate = (
            b"0000000000000010  0000000000000008 R_X86_64_RELATIVE                 20\n"
            b"0000000000000010  0000000000000008 R_X86_64_RELATIVE                 30\n"
        )
        with self.assertRaisesRegex(M.ProvenanceError, "duplicate"):
            M.parse_relocations(duplicate)
        with self.assertRaisesRegex(M.ProvenanceError, "absent or ambiguous"):
            M.parse_build_id(b"no note\n")
        with self.assertRaisesRegex(M.ProvenanceError, "absent or ambiguous"):
            M.parse_build_id(b"Build ID: aa\nBuild ID: bb\n")

    def test_elf_rejects_truncated_and_ambiguous_mappings(self) -> None:
        with self.assertRaisesRegex(M.ProvenanceError, "truncated"):
            M.ElfView(b"\x7fELF")
        view = M.ElfView(minimal_elf(duplicate_load=True))
        with self.assertRaisesRegex(M.ProvenanceError, "ambiguous"):
            view.map(0x100, 4, "probe")
        with self.assertRaisesRegex(M.ProvenanceError, "unmapped"):
            M.ElfView(minimal_elf()).map(0x4000, 1, "probe")

    def test_regular_file_reader_rejects_nonregular_oversized_and_change(self) -> None:
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

    def test_manifest_rejects_unknown_missing_keys_and_boolean_integer(self) -> None:
        source = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutations = []
        extra = json.loads(json.dumps(source)); extra["unexpected"] = 1; mutations.append(extra)
        missing = json.loads(json.dumps(source)); del missing["artifact"]["build_id"]; mutations.append(missing)
        boolean = json.loads(json.dumps(source)); boolean["artifact"]["size"] = True; mutations.append(boolean)
        wrong_type = json.loads(json.dumps(source)); wrong_type["expected"]["direct_edges"] = {}; mutations.append(wrong_type)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            for value in mutations:
                with self.subTest(value=list(value)):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaises(M.ProvenanceError):
                        M.load_manifest(path)

    def test_old_connect_operand_provenance_and_mutation(self) -> None:
        elf = M.ElfView(minimal_elf({0x1000: b"1member()\0", 0x1020: b"2signal()\0"}))
        rows = [
            M.Instruction(0x100, "leaq", "0x0(%rip), %rdi # 0x1000"),
            M.Instruction(0x107, "callq", f"0x200 <{M.QFLAG}>"),
            M.Instruction(0x10C, "movq", "%rax, %r12"),
            M.Instruction(0x110, "leaq", "0x0(%rip), %rdi # 0x1020"),
            M.Instruction(0x117, "callq", f"0x200 <{M.QFLAG}>"),
            M.Instruction(0x11C, "movq", "%r12, %r8"),
            M.Instruction(0x120, "movq", "%rax, %rdx"),
            M.Instruction(0x124, "xorl", "%r9d, %r9d"),
            M.Instruction(0x128, "callq", f"0x300 <{M.OLD_CONNECT}>"),
        ]
        report = M.analyze_old_connects(rows, elf)
        self.assertEqual(report, [{"call_va": 0x128, "signal": "2signal()", "member": "1member()", "connection_type": 0}])
        changed = list(rows); changed[6] = M.Instruction(0x120, "movq", "%rax, %rcx")
        with self.assertRaisesRegex(M.ProvenanceError, "operands lack"):
            M.analyze_old_connects(changed, elf)

    @unittest.skipUnless(OBJDUMP.is_file(), "Homebrew llvm-objdump is unavailable")
    def test_tool_file_identity_is_enforced(self) -> None:
        raw = OBJDUMP.read_bytes()
        version = subprocess.check_output([str(OBJDUMP), "--version"], text=True).splitlines()[0]
        with self.assertRaisesRegex(M.ProvenanceError, "file identity"):
            M._validate_tool(OBJDUMP, version, len(raw), "00" * 32, "llvm-objdump")

    def test_invoke_member_and_connection_type_provenance_and_mutation(self) -> None:
        elf = M.ElfView(minimal_elf({0x1000: b"member\0"}))
        rows = [
            M.Instruction(0x100, "xorl", "%edx, %edx"),
            M.Instruction(0x104, "leaq", "0x0(%rip), %rsi # 0x1000"),
            M.Instruction(0x10B, "pushq", "$0x0"),
            M.Instruction(0x10D, "callq", f"0x300 <{M.INVOKE_METHOD}@plt>"),
        ]
        self.assertEqual(M.analyze_invokes(rows, elf)[0]["connection_type"], 0)
        changed = list(rows); changed[0] = M.Instruction(0x100, "movl", "$0x1, %edx")
        with self.assertRaisesRegex(M.ProvenanceError, "AutoConnection"):
            M.analyze_invokes(changed, elf)

    def test_registration_helper_and_option_are_machine_bound(self) -> None:
        rows = [
            M.Instruction(0x100, "movq", "%rdi, %rbx"),
            M.Instruction(0x104, "movq", "%rbx, %rdi"),
            M.Instruction(0x108, "callq", "0x200 <helper>"),
            M.Instruction(0x200, "movq", "%rdi, %rbx"),
            M.Instruction(0x204, "movq", "%rbx, %rdx"),
            M.Instruction(0x208, "movl", "$0x1, %ecx"),
            M.Instruction(0x20D, "callq", f"0x300 <{M.REGISTER_OBJECT}>"),
        ]
        result = M.analyze_registration_binding(rows, 0x100, 0x110, M.REGISTER_OBJECT, 0x200, 1)
        self.assertEqual(result["option_name"], "ExportAdaptors")
        self.assertEqual(result["option_definition_va"], 0x208)

        helper_target = list(rows); helper_target[2] = M.Instruction(0x108, "callq", "0x201 <helper>")
        with self.assertRaisesRegex(M.ProvenanceError, "helper target"):
            M.analyze_registration_binding(helper_target, 0x100, 0x110, M.REGISTER_OBJECT, 0x200, 1)
        with self.assertRaisesRegex(M.ProvenanceError, "helper target"):
            M.analyze_registration_binding(rows, 0x100, 0x110, M.REGISTER_OBJECT, 0x201, 1)
        with self.assertRaisesRegex(M.ProvenanceError, "does not match manifest"):
            M.analyze_registration_binding(rows, 0x100, 0x110, M.REGISTER_OBJECT, 0x200, 2)

        option_instruction = list(rows); option_instruction[5] = M.Instruction(0x208, "movl", "$0x2, %ecx")
        with self.assertRaisesRegex(M.ProvenanceError, "does not match manifest"):
            M.analyze_registration_binding(option_instruction, 0x100, 0x110, M.REGISTER_OBJECT, 0x200, 1)
        with self.assertRaisesRegex(M.ProvenanceError, "not supported ExportAdaptors"):
            M.analyze_registration_binding(option_instruction, 0x100, 0x110, M.REGISTER_OBJECT, 0x200, 2)

    def test_connect_impl_slot_object_callback_def_use_and_mutations(self) -> None:
        def block(base: int, callback: int, call: int) -> list:
            return [
                M.Instruction(base, "leaq", f"0x0(%rip), %rax # 0x{callback:x}"),
                M.Instruction(base + 4, "movq", "%rax, -0x10(%rbp)"),
                M.Instruction(base + 8, "callq", "0x900 <_Znwm@plt>"),
                M.Instruction(base + 0xC, "movq", "%rax, %r9"),
                M.Instruction(base + 0x10, "movq", "-0x10(%rbp), %rax"),
                M.Instruction(base + 0x14, "movq", "%rax, 0x10(%r9)"),
                M.Instruction(base + 0x18, "pushq", "%rax"),
                M.Instruction(base + 0x1C, "pushq", "$0x0"),
                M.Instruction(base + 0x20, "pushq", "$0x0"),
                M.Instruction(call, "callq", f"0x800 <{M.CONNECT_IMPL}>"),
            ]
        rows = block(0x100, 0x500, 0x124) + block(0x200, 0x600, 0x224)
        result = M.analyze_connect_impl_bindings(rows, [0x124, 0x224], [0x500, 0x600])
        self.assertEqual([row["callback_va"] for row in result], [0x500, 0x600])

        overwrite = list(rows); overwrite[5] = M.Instruction(0x114, "movq", "%rcx, 0x10(%r9)")
        with self.assertRaisesRegex(M.ProvenanceError, "callback def-use"):
            M.analyze_connect_impl_bindings(overwrite, [0x124, 0x224], [0x500, 0x600])
        swap = list(rows)
        swap[0] = M.Instruction(0x100, "leaq", "0x0(%rip), %rax # 0x600")
        swap[10] = M.Instruction(0x200, "leaq", "0x0(%rip), %rax # 0x500")
        with self.assertRaisesRegex(M.ProvenanceError, "callback def-use"):
            M.analyze_connect_impl_bindings(swap, [0x124, 0x224], [0x500, 0x600])
        slot_overwrite = list(rows); slot_overwrite[6] = M.Instruction(0x118, "xorl", "%r9d, %r9d")
        with self.assertRaisesRegex(M.ProvenanceError, "slot-object operand"):
            M.analyze_connect_impl_bindings(slot_overwrite, [0x124, 0x224], [0x500, 0x600])

    def test_adaptor_public_rows_bind_to_bodies_and_invoke_members(self) -> None:
        table = struct.pack("<ii", 0x200 - 0x1800, 0x220 - 0x1800)
        elf = M.ElfView(minimal_elf({0x1000: b"alpha\0", 0x1020: b"beta\0", 0x1800: table}))
        rows = [
            M.Instruction(0x100, "testl", "%esi, %esi"),
            M.Instruction(0x102, "cmpl", "$0x1, %edx"),
            M.Instruction(0x105, "leaq", "0x0(%rip), %rax # 0x1800"),
            M.Instruction(0x10C, "movl", "%edx, %edx"),
            M.Instruction(0x10E, "movslq", "(%rax,%rdx,4), %rdx"),
            M.Instruction(0x112, "addq", "%rdx, %rax"),
            M.Instruction(0x115, "jmpq", "*%rax"),
            M.Instruction(0x200, "callq", "0x500 <impl-alpha>"),
            M.Instruction(0x220, "callq", "0x600 <impl-beta>"),
            M.Instruction(0x500, "xorl", "%edx, %edx"),
            M.Instruction(0x504, "leaq", "0x0(%rip), %rsi # 0x1000"),
            M.Instruction(0x50B, "callq", f"0x900 <{M.INVOKE_METHOD}@plt>"),
            M.Instruction(0x510, "retq", ""),
            M.Instruction(0x600, "xorl", "%edx, %edx"),
            M.Instruction(0x604, "leaq", "0x0(%rip), %rsi # 0x1020"),
            M.Instruction(0x60B, "callq", f"0x900 <{M.INVOKE_METHOD}@plt>"),
            M.Instruction(0x610, "retq", ""),
        ]
        invokes = M.analyze_invokes(rows, elf)
        meta = [{
            "role": "adaptor_fixture", "method_count": 2, "static_metacall_va": 0x100,
            "methods": [
                {"index": 0, "name": "alpha", "flags": 0x0A, "access": "public"},
                {"index": 1, "name": "beta", "flags": 0x0A, "access": "public"},
            ],
        }]
        bound = M.bind_adaptor_forwarders(rows, elf, meta, {row["call_va"]: row for row in invokes})
        self.assertEqual([(row["row_name"], row["member"]) for row in bound], [("alpha", "alpha"), ("beta", "beta")])

        protected = json.loads(json.dumps(meta)); protected[0]["methods"][0]["flags"] = 0x09; protected[0]["methods"][0]["access"] = "protected"
        with self.assertRaisesRegex(M.ProvenanceError, "protected/private"):
            M.bind_adaptor_forwarders(rows, elf, protected, {row["call_va"]: row for row in invokes})

        swapped_elf = M.ElfView(minimal_elf({0x1000: b"alpha\0", 0x1020: b"beta\0", 0x1800: struct.pack("<ii", 0x220 - 0x1800, 0x200 - 0x1800)}))
        with self.assertRaisesRegex(M.ProvenanceError, "row/body/invoke"):
            M.bind_adaptor_forwarders(rows, swapped_elf, meta, {row["call_va"]: row for row in invokes})

        substituted = list(rows); substituted[11] = M.Instruction(0x50B, "callq", "0x900 <unrelated@plt>")
        changed_invokes = M.analyze_invokes(substituted, elf)
        with self.assertRaisesRegex(M.ProvenanceError, "returns before invokeMethod"):
            M.bind_adaptor_forwarders(substituted, elf, meta, {row["call_va"]: row for row in changed_invokes})

        mutated_name_elf = M.ElfView(minimal_elf({0x1000: b"beta\0", 0x1020: b"beta\0", 0x1800: table}))
        mutated_names = M.analyze_invokes(rows, mutated_name_elf)
        with self.assertRaisesRegex(M.ProvenanceError, "row/body/invoke"):
            M.bind_adaptor_forwarders(rows, mutated_name_elf, meta, {row["call_va"]: row for row in mutated_names})


@unittest.skipUnless(EXACT_AVAILABLE, "authorized ignored exact ELF or Homebrew LLVM is unavailable")
class ExactArtifactTests(unittest.TestCase):
    def test_exact_cli_is_utf8_lf_deterministic_and_matches_retained_report(self) -> None:
        outputs = [run_exact(value) for value in ("ascii:strict", "latin-1:strict", "utf-16:strict")]
        self.assertEqual(len(set(outputs)), 1)
        self.assertNotIn(b"\r", outputs[0])
        self.assertEqual(outputs[0], REPORT.read_bytes())

    def test_report_has_all_and_only_schema_keys(self) -> None:
        report = json.loads(run_exact("ascii:strict"))
        self.assertEqual(set(report), {"schema_version", "tool", "artifact", "target_name_inventory", "direct_target_edges", "meta_call_chain", "dispatch_inventory", "dbus_registration", "scope"})
        self.assertEqual(set(report["tool"]), {"name", "version"})
        self.assertEqual(set(report["artifact"]), {"sha256", "size", "build_id"})
        self.assertEqual(set(report["target_name_inventory"]), {"bare_name_count", "occurrences", "absent_signature_form_count"})
        self.assertEqual(set(report["direct_target_edges"]), {"count", "edges"})
        self.assertEqual(set(report["meta_call_chain"]), {"parent_local_method_count", "selected_local_method_count", "target_local_index", "index_scope", "absolute_method_index", "generated_forwarding"})
        self.assertEqual(set(report["meta_call_chain"]["generated_forwarding"]), {"case_va", "call_va", "argument_copy", "return"})
        self.assertEqual(set(report["dispatch_inventory"]), {"direct_call_counts", "bounded_zero_counts", "old_style_connect", "named_invoke", "string_timer", "selected_constructor"})
        dispatch = report["dispatch_inventory"]
        self.assertEqual(set(dispatch["direct_call_counts"]), {"old_connect", "connect_impl", "invoke_method", "dbus_connect", "timer_string", "register_service", "register_object"})
        self.assertEqual(set(dispatch["bounded_zero_counts"]), {"connect_slots_by_name", "post_event", "send_event", "qobject_disconnect", "qmeta_call_event_import"})
        self.assertEqual(set(dispatch["old_style_connect"]), {"count", "target_matches", "connection_types", "ordered_provenance_sha256"})
        self.assertEqual(set(dispatch["old_style_connect"]["connection_types"]), {"AutoConnection", "DirectConnection"})
        self.assertEqual(set(dispatch["named_invoke"]), {"count", "distinct_member_count", "target_matches", "connection_type", "ordered_provenance_sha256"})
        self.assertEqual(set(dispatch["string_timer"]), {"count", "target_matches", "ordered_member_sha256"})
        self.assertEqual(set(dispatch["selected_constructor"]), {"old_style_connect_count", "connect_impl_count", "connect_impl_connection_type", "connect_impl_callback_binding", "connection_types", "ordered_provenance_sha256", "connect_impl_call_vas", "callback_ranges"})
        for item in dispatch["selected_constructor"]["callback_ranges"]:
            self.assertEqual(set(item), {"start_va", "end_va_exclusive", "direct_target_references"})
        self.assertEqual(set(report["dbus_registration"]), {"same_object_helper_chain", "helper_va", "helper_call_va", "register_option_definition_va", "register_option_value", "register_option_name", "selected_adaptor_count", "selected_adaptor_totals", "selected_forwarders", "same_object_subscriptions", "privacy"})
        registration = report["dbus_registration"]
        self.assertEqual(set(registration["selected_adaptor_totals"]), {"public_slots", "signals", "target_rows"})
        self.assertEqual(set(registration["selected_forwarders"]), {"count", "target_matches", "ordered_member_sha256"})
        self.assertEqual(set(registration["same_object_subscriptions"]), {"count", "target_matches", "ordered_member_sha256"})
        self.assertEqual(set(report["scope"]), {"exact_static", "runtime_invocation_proven", "complete_dynamic_producer_absence_proven", "attacker_control_proven"})
        for item in report["target_name_inventory"]["occurrences"]:
            self.assertEqual(set(item), {"offset", "classification", "xref_count"})
        for item in report["direct_target_edges"]["edges"]:
            self.assertEqual(set(item), {"call_va", "classification"})
        privacy = report["dbus_registration"]["privacy"]
        self.assertEqual(set(privacy), {"service_template", "service_token", "final_service", "object_path", "callable_coordinates_emitted"})
        for name in ("service_template", "service_token", "final_service", "object_path"):
            self.assertEqual(set(privacy[name]), {"length", "sha256"})

    def test_exact_counts_hashes_and_fail_closed_scope(self) -> None:
        report = json.loads(run_exact("ascii:strict"))
        self.assertEqual(report["target_name_inventory"]["bare_name_count"], 4)
        self.assertEqual(report["target_name_inventory"]["absent_signature_form_count"], 4)
        self.assertEqual(report["direct_target_edges"]["count"], 4)
        self.assertEqual(report["meta_call_chain"]["parent_local_method_count"], 11)
        self.assertEqual(report["meta_call_chain"]["selected_local_method_count"], 85)
        self.assertEqual(report["meta_call_chain"]["target_local_index"], 64)
        self.assertIsNone(report["meta_call_chain"]["absolute_method_index"])
        self.assertEqual(report["dispatch_inventory"]["direct_call_counts"], {"old_connect": 90, "connect_impl": 18, "invoke_method": 105, "dbus_connect": 32, "timer_string": 4, "register_service": 1, "register_object": 1})
        self.assertEqual(report["dispatch_inventory"]["selected_constructor"]["connect_impl_callback_binding"], "resolved")
        self.assertEqual(report["dbus_registration"]["helper_va"], "0xb8b40")
        self.assertEqual(report["dbus_registration"]["register_option_definition_va"], "0xb8e41")
        self.assertEqual(report["dbus_registration"]["register_option_value"], 1)
        self.assertEqual(report["dbus_registration"]["register_option_name"], "ExportAdaptors")
        self.assertEqual(report["dispatch_inventory"]["bounded_zero_counts"], {"connect_slots_by_name": 0, "post_event": 0, "send_event": 0, "qobject_disconnect": 0, "qmeta_call_event_import": 0})
        self.assertEqual(report["dispatch_inventory"]["old_style_connect"]["target_matches"], 0)
        self.assertEqual(report["dispatch_inventory"]["named_invoke"]["target_matches"], 0)
        self.assertEqual(report["dbus_registration"]["selected_adaptor_totals"], {"public_slots": 16, "signals": 14, "target_rows": 0})
        self.assertEqual(report["dbus_registration"]["same_object_subscriptions"]["count"], 12)
        self.assertEqual(report["dbus_registration"]["selected_forwarders"]["count"], 16)
        self.assertEqual(report["scope"], {"exact_static": True, "runtime_invocation_proven": False, "complete_dynamic_producer_absence_proven": False, "attacker_control_proven": False})

    def test_privacy_sensitive_coordinates_and_operator_paths_are_not_emitted(self) -> None:
        output = run_exact("ascii:strict")
        generated = REPORT.read_bytes() + MANIFEST.read_bytes()
        retained = b"\n".join(path.read_bytes() for path in (REPORT, MANIFEST, EXCERPT, TOOL))
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        specs = manifest["expected"]["registration"]["privacy"]
        data = ELF.read_bytes()
        values: dict[str, bytes] = {}
        for name in ("service_template", "service_token", "object_path"):
            spec = specs[name]
            candidates = []
            for end in range(spec["length"], len(data)):
                if data[end] == 0:
                    value = data[end - spec["length"] : end]
                    if hashlib.sha256(value).hexdigest() == spec["sha256"]:
                        candidates.append(value)
            self.assertTrue(candidates)
            values[name] = candidates[0]
            if name == "service_token":
                # The token bytes also occur as a substring of the selected
                # class name in the strict manifest; the generated report must
                # still not disclose them as a coordinate/value.
                self.assertNotIn(candidates[0], output)
            else:
                self.assertNotIn(candidates[0], generated)
                self.assertNotIn(candidates[0], retained)
        final_service = values["service_template"].replace(b"%1", values["service_token"])
        self.assertNotIn(final_service, retained)
        self.assertNotIn(b"/Users/", generated)
        self.assertFalse(json.loads(output)["dbus_registration"]["privacy"]["callable_coordinates_emitted"])

    def test_exact_manifest_rejects_mismatched_direct_call_count(self) -> None:
        source = json.loads(MANIFEST.read_text(encoding="utf-8"))
        source["expected"]["call_counts"]["old_connect"] = 91
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(M.ProvenanceError, "direct-call counts"):
                M.analyze(ELF, OBJDUMP, READELF, path)

    def test_exact_manifest_registration_helper_and_option_are_consumed(self) -> None:
        source = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutations = [
            ("helper", source["expected"]["registration"]["helper_va"] + 1, "helper target"),
            ("option", 2, "does not match manifest"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            for field, value, message in mutations:
                changed = json.loads(json.dumps(source))
                changed["expected"]["registration"]["helper_va" if field == "helper" else "option_value"] = value
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.subTest(field=field):
                    with self.assertRaisesRegex(M.ProvenanceError, message):
                        M.analyze(ELF, OBJDUMP, READELF, path)

    def test_exact_manifest_instruction_identity_rejects_truncation(self) -> None:
        manifest = M.load_manifest(MANIFEST)
        raw = subprocess.run([str(OBJDUMP), "-d", "--no-show-raw-insn", str(ELF)], check=True, stdout=subprocess.PIPE).stdout
        instructions = M.parse_disassembly(raw)
        canonical = "".join(item.canonical + "\n" for item in instructions[:-1]).encode("utf-8")
        self.assertNotEqual(len(instructions) - 1, manifest["llvm"]["instruction_count"])
        self.assertNotEqual(hashlib.sha256(canonical).hexdigest(), manifest["llvm"]["instruction_sha256"])


if __name__ == "__main__":
    unittest.main()
