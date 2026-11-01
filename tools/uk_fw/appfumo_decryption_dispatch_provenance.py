#!/usr/bin/env python3
"""Deterministically audit bounded AppUpgrade decryption dispatch provenance.

The tool reads one explicitly identified x86-64 ELF, invokes only the supplied
Homebrew LLVM objdump/readelf executables, and checks an exact evidence manifest.
It never loads or executes target code and never emits callable D-Bus coordinates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1
TOOL_VERSION = "1.1.0"
TOOL_NAME = "appfumo-decryption-dispatch-provenance"
MAX_ELF_SIZE = 64 << 20
MAX_MANIFEST_SIZE = 1 << 20
MAX_TOOL_OUTPUT = 192 << 20
MAX_METHODS = 512
MAX_ARGUMENTS = 64
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
QBYTEARRAYDATA = struct.Struct("<iiIIq")
U32 = struct.Struct("<I")
PT_LOAD = 1

OLD_CONNECT = "_ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE@plt"
CONNECT_IMPL = "_ZN7QObject11connectImplEPKS_PPvS1_S3_PN9QtPrivate15QSlotObjectBaseEN2Qt14ConnectionTypeEPKiPK11QMetaObject@plt"
INVOKE_METHOD = "_ZN11QMetaObject12invokeMethodEP7QObjectPKcN2Qt14ConnectionTypeE"
DBUS_CONNECT = "_ZN15QDBusConnection7connect"
TIMER_STRING = "_ZN6QTimer10singleShotEiPK7QObjectPKc@plt"
REGISTER_SERVICE = "_ZN15QDBusConnection15registerServiceERK7QString@plt"
REGISTER_OBJECT = "_ZN15QDBusConnection14registerObjectERK7QStringP7QObject6QFlagsINS_14RegisterOptionEE@plt"
QFLAG = "_Z13qFlagLocationPKc@plt"


class ProvenanceError(ValueError):
    """Input or evidence does not satisfy the bounded audit contract."""


@dataclass(frozen=True)
class Segment:
    offset: int
    vaddr: int
    filesz: int


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str

    @property
    def canonical(self) -> str:
        return f"{self.address:x}\t{self.mnemonic}\t{self.operands}"


class ElfView:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < ELF_HEADER.size:
            raise ProvenanceError("ELF header is truncated")
        fields = ELF_HEADER.unpack_from(data)
        ident = fields[0]
        if ident[:4] != b"\x7fELF" or ident[4:7] != bytes((2, 1, 1)):
            raise ProvenanceError("unsupported ELF identity")
        if fields[1] not in (2, 3) or fields[2] != 62 or fields[3] != 1:
            raise ProvenanceError("unsupported ELF ABI")
        phoff, ehsize, phentsize, phnum = fields[5], fields[8], fields[9], fields[10]
        if ehsize != ELF_HEADER.size or phentsize != PROGRAM_HEADER.size:
            raise ProvenanceError("unsupported ELF header layout")
        if not 0 < phnum <= 256:
            raise ProvenanceError("unsupported ELF program-header count")
        if phoff + phnum * phentsize > len(data):
            raise ProvenanceError("ELF program-header table is truncated")
        segments: list[Segment] = []
        for index in range(phnum):
            row = PROGRAM_HEADER.unpack_from(data, phoff + index * phentsize)
            if row[0] != PT_LOAD:
                continue
            offset, vaddr, filesz, memsz = row[2], row[3], row[5], row[6]
            if filesz > memsz or offset + filesz > len(data):
                raise ProvenanceError("ELF PT_LOAD range is malformed")
            segments.append(Segment(offset, vaddr, filesz))
        if not segments:
            raise ProvenanceError("ELF has no file-backed PT_LOAD segment")
        self.segments = segments

    def map(self, va: int, size: int, what: str) -> int:
        if type(va) is not int or type(size) is not int or va < 0 or size < 0:
            raise ProvenanceError(f"{what} range is invalid")
        end = va + size
        if end > (1 << 64):
            raise ProvenanceError(f"{what} range overflows")
        candidates = [
            segment.offset + va - segment.vaddr
            for segment in self.segments
            if segment.vaddr <= va and end <= segment.vaddr + segment.filesz
        ]
        if len(candidates) != 1:
            qualifier = "ambiguous" if candidates else "unmapped"
            raise ProvenanceError(f"{what} range is {qualifier}")
        return candidates[0]

    def bytes_at(self, va: int, size: int, what: str) -> bytes:
        offset = self.map(va, size, what)
        return self.data[offset : offset + size]

    def u32(self, va: int, what: str) -> int:
        return U32.unpack(self.bytes_at(va, 4, what))[0]

    def cstring_at_va(self, va: int, what: str, maximum: int = 4096) -> str:
        offset = self.map(va, 1, what)
        end = self.data.find(b"\0", offset, min(len(self.data), offset + maximum + 1))
        if end < 0:
            raise ProvenanceError(f"{what} is not bounded by NUL")
        try:
            return self.data[offset:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProvenanceError(f"{what} is not UTF-8") from exc

    def qt_string_location(self, stringdata_va: int, index: int, what: str) -> tuple[str, int]:
        if type(index) is not int or not 0 <= index < 4096:
            raise ProvenanceError(f"{what} string index is unsupported")
        descriptor_va = stringdata_va + index * QBYTEARRAYDATA.size
        raw = self.bytes_at(descriptor_va, QBYTEARRAYDATA.size, f"{what} descriptor")
        ref, size, alloc, capacity, relative = QBYTEARRAYDATA.unpack(raw)
        if ref != -1 or size < 0 or size > 4096 or alloc != 0 or capacity != 0:
            raise ProvenanceError(f"{what} QString descriptor is unsupported")
        data_va = descriptor_va + relative
        payload = self.bytes_at(data_va, size + 1, f"{what} payload")
        if payload[-1:] != b"\0" or b"\0" in payload[:-1]:
            raise ProvenanceError(f"{what} payload is not exactly NUL terminated")
        try:
            return payload[:-1].decode("utf-8"), data_va
        except UnicodeDecodeError as exc:
            raise ProvenanceError(f"{what} payload is not UTF-8") from exc

    def qt_string(self, stringdata_va: int, index: int, what: str) -> str:
        return self.qt_string_location(stringdata_va, index, what)[0]


def _read_regular(path: Path, maximum: int, what: str) -> bytes:
    try:
        before = path.stat()
    except OSError as exc:
        raise ProvenanceError(f"cannot stat {what}: {exc.strerror}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ProvenanceError(f"{what} is not a regular file")
    if before.st_size > maximum:
        raise ProvenanceError(f"{what} exceeds the size limit")
    try:
        with path.open("rb") as handle:
            raw = handle.read(before.st_size + 1)
    except OSError as exc:
        raise ProvenanceError(f"cannot read {what}: {exc.strerror}") from exc
    try:
        after = path.stat()
    except OSError as exc:
        raise ProvenanceError(f"cannot restat {what}: {exc.strerror}") from exc
    if (
        len(raw) != before.st_size
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or not stat.S_ISREG(after.st_mode)
    ):
        raise ProvenanceError(f"{what} changed while being read")
    return raw


def _object(value: Any, keys: Iterable[str], what: str) -> dict[str, Any]:
    expected = set(keys)
    if type(value) is not dict:
        raise ProvenanceError(f"{what} must be an object")
    actual = set(value)
    if actual != expected:
        raise ProvenanceError(
            f"{what} keys mismatch: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}"
        )
    return value


def _array(value: Any, what: str, maximum: int = 4096) -> list[Any]:
    if type(value) is not list or len(value) > maximum:
        raise ProvenanceError(f"{what} must be a bounded array")
    return value


def _integer(value: Any, what: str, maximum: int = (1 << 64) - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ProvenanceError(f"{what} must be a bounded non-Boolean integer")
    return value


def _string(value: Any, what: str, maximum: int = 4096) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise ProvenanceError(f"{what} must be a bounded non-empty string")
    return value


def _digest(value: Any, what: str) -> str:
    text = _string(value, what, 64)
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ProvenanceError(f"{what} must be lowercase SHA-256")
    return text


def _boolean(value: Any, what: str) -> bool:
    if type(value) is not bool:
        raise ProvenanceError(f"{what} must be a Boolean")
    return value


def load_manifest(path: Path) -> dict[str, Any]:
    raw = _read_regular(path, MAX_MANIFEST_SIZE, "manifest")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError("manifest is not valid UTF-8 JSON") from exc
    top = _object(value, {"schema_version", "artifact", "llvm", "expected"}, "manifest")
    if _integer(top["schema_version"], "schema_version") != 1:
        raise ProvenanceError("unsupported manifest schema version")
    artifact = _object(top["artifact"], {"sha256", "size", "build_id"}, "artifact")
    artifact = {
        "sha256": _digest(artifact["sha256"], "artifact.sha256"),
        "size": _integer(artifact["size"], "artifact.size", MAX_ELF_SIZE),
        "build_id": _string(artifact["build_id"], "artifact.build_id", 128),
    }
    if not re.fullmatch(r"[0-9a-f]+", artifact["build_id"]):
        raise ProvenanceError("artifact.build_id must be lowercase hexadecimal")
    llvm = _object(top["llvm"], {"version", "instruction_count", "instruction_sha256", "objdump_size", "objdump_sha256", "readelf_size", "readelf_sha256"}, "llvm")
    llvm = {
        "version": _string(llvm["version"], "llvm.version", 128),
        "instruction_count": _integer(llvm["instruction_count"], "llvm.instruction_count", 2_000_000),
        "instruction_sha256": _digest(llvm["instruction_sha256"], "llvm.instruction_sha256"),
        "objdump_size": _integer(llvm["objdump_size"], "llvm.objdump_size", 16 << 20),
        "objdump_sha256": _digest(llvm["objdump_sha256"], "llvm.objdump_sha256"),
        "readelf_size": _integer(llvm["readelf_size"], "llvm.readelf_size", 16 << 20),
        "readelf_sha256": _digest(llvm["readelf_sha256"], "llvm.readelf_sha256"),
    }
    expected = _load_expected(top["expected"])
    return {"artifact": artifact, "llvm": llvm, "expected": expected, "manifest_sha256": hashlib.sha256(raw).hexdigest()}


def _load_expected(value: Any) -> dict[str, Any]:
    exp = _object(
        value,
        {
            "bare_name", "absent_forms", "direct_edges", "metaobjects", "machine_anchors",
            "call_counts", "bounded_zeros", "ordered_hashes", "constructor", "registration",
        },
        "expected",
    )
    bare = _object(exp["bare_name"], {"text", "occurrences"}, "bare_name")
    occurrences = []
    for index, item in enumerate(_array(bare["occurrences"], "bare_name.occurrences", 16)):
        row = _object(item, {"offset", "classification", "xref_vas"}, f"bare occurrence {index}")
        occurrences.append({
            "offset": _integer(row["offset"], "bare offset"),
            "classification": _string(row["classification"], "bare classification", 64),
            "xref_vas": [_integer(v, "bare xref") for v in _array(row["xref_vas"], "bare xrefs", 32)],
        })
    bare_out = {"text": _string(bare["text"], "bare_name.text", 128), "occurrences": occurrences}
    absent = [_string(v, "absent form", 256) for v in _array(exp["absent_forms"], "absent_forms", 32)]
    edges = []
    for index, item in enumerate(_array(exp["direct_edges"], "direct_edges", 16)):
        row = _object(item, {"call_va", "classification"}, f"direct edge {index}")
        edges.append({"call_va": _integer(row["call_va"], "edge call_va"), "classification": _string(row["classification"], "edge classification", 64)})
    metas = []
    for index, item in enumerate(_array(exp["metaobjects"], "metaobjects", 16)):
        row = _object(item, {"role", "class_name", "static_object_va", "stringdata_va", "metadata_va", "static_metacall_va", "method_count", "signal_count"}, f"metaobject {index}")
        metas.append({
            "role": _string(row["role"], "metaobject role", 64),
            "class_name": _string(row["class_name"], "metaobject class", 128),
            "static_object_va": _integer(row["static_object_va"], "static object"),
            "stringdata_va": _integer(row["stringdata_va"], "stringdata"),
            "metadata_va": _integer(row["metadata_va"], "metadata"),
            "static_metacall_va": _integer(row["static_metacall_va"], "static metacall"),
            "method_count": _integer(row["method_count"], "method count", MAX_METHODS),
            "signal_count": _integer(row["signal_count"], "signal count", MAX_METHODS),
        })
    anchors = []
    for index, item in enumerate(_array(exp["machine_anchors"], "machine_anchors", 256)):
        row = _object(item, {"va", "mnemonic", "operands"}, f"machine anchor {index}")
        anchors.append({"va": _integer(row["va"], "anchor va"), "mnemonic": _string(row["mnemonic"], "anchor mnemonic", 32), "operands": _string(row["operands"], "anchor operands", 512)})
    counts_obj = _object(exp["call_counts"], {"old_connect", "connect_impl", "invoke_method", "dbus_connect", "timer_string", "register_service", "register_object"}, "call_counts")
    counts = {key: _integer(val, f"call_counts.{key}", 10000) for key, val in counts_obj.items()}
    zeros_obj = _object(exp["bounded_zeros"], {"connect_slots_by_name", "post_event", "send_event", "qobject_disconnect", "qmeta_call_event_import"}, "bounded_zeros")
    zeros = {key: _integer(val, f"bounded_zeros.{key}", 10000) for key, val in zeros_obj.items()}
    hashes_obj = _object(exp["ordered_hashes"], {"old_connect_pairs", "constructor_connect_pairs", "invoke_members", "timer_members", "dbus_subscriptions", "adaptor_forwarders"}, "ordered_hashes")
    hashes = {key: _digest(val, f"ordered_hashes.{key}") for key, val in hashes_obj.items()}
    ctor = _object(exp["constructor"], {"start_va", "end_va_exclusive", "old_connect_count", "connect_impl_calls", "connection_types", "callbacks"}, "constructor")
    ctor_types = _object(ctor["connection_types"], {"AutoConnection", "DirectConnection"}, "constructor.connection_types")
    callbacks = []
    for index, item in enumerate(_array(ctor["callbacks"], "constructor.callbacks", 8)):
        row = _object(item, {"start_va", "end_va_exclusive"}, f"constructor callback {index}")
        callbacks.append({"start_va": _integer(row["start_va"], "callback start"), "end_va_exclusive": _integer(row["end_va_exclusive"], "callback end")})
    ctor_out = {
        "start_va": _integer(ctor["start_va"], "constructor start"),
        "end_va_exclusive": _integer(ctor["end_va_exclusive"], "constructor end"),
        "old_connect_count": _integer(ctor["old_connect_count"], "constructor old count"),
        "connect_impl_calls": [_integer(v, "connectImpl call") for v in _array(ctor["connect_impl_calls"], "constructor connectImpl calls", 8)],
        "connection_types": {key: _integer(val, f"constructor connection type {key}") for key, val in ctor_types.items()},
        "callbacks": callbacks,
    }
    registration = _load_registration(exp["registration"])
    return {"bare_name": bare_out, "absent_forms": absent, "direct_edges": edges, "metaobjects": metas, "machine_anchors": anchors, "call_counts": counts, "bounded_zeros": zeros, "ordered_hashes": hashes, "constructor": ctor_out, "registration": registration}


def _load_registration(value: Any) -> dict[str, Any]:
    row = _object(value, {"helper_va", "option_value", "adaptor_calls", "subscription_call_vas", "privacy"}, "registration")
    adaptors = []
    for index, item in enumerate(_array(row["adaptor_calls"], "registration.adaptor_calls", 16)):
        entry = _object(item, {"call_va", "constructor_va", "vptr_va", "metaobject_fn_va", "metaobject_role"}, f"adaptor call {index}")
        adaptors.append({
            "call_va": _integer(entry["call_va"], "adaptor call"),
            "constructor_va": _integer(entry["constructor_va"], "adaptor constructor"),
            "vptr_va": _integer(entry["vptr_va"], "adaptor vptr"),
            "metaobject_fn_va": _integer(entry["metaobject_fn_va"], "adaptor metaobject function"),
            "metaobject_role": _string(entry["metaobject_role"], "adaptor role", 64),
        })
    privacy_obj = _object(row["privacy"], {"service_template", "service_token", "final_service", "object_path"}, "registration.privacy")
    privacy: dict[str, dict[str, Any]] = {}
    for name, item in privacy_obj.items():
        if name == "service_template":
            keys = {"length", "sha256", "placeholder_count"}
        elif name == "service_token":
            keys = {"length", "sha256", "anchor_instruction_va"}
        else:
            keys = {"length", "sha256"}
        entry = _object(item, keys, f"privacy.{name}")
        converted = {"length": _integer(entry["length"], f"privacy.{name}.length", 4096), "sha256": _digest(entry["sha256"], f"privacy.{name}.sha256")}
        if name == "service_template":
            converted["placeholder_count"] = _integer(entry["placeholder_count"], "template placeholder_count", 8)
        elif name == "service_token":
            converted["anchor_instruction_va"] = _integer(entry["anchor_instruction_va"], "token anchor instruction")
        privacy[name] = converted
    return {
        "helper_va": _integer(row["helper_va"], "registration helper"),
        "option_value": _integer(row["option_value"], "registration option", 255),
        "adaptor_calls": adaptors,
        "subscription_call_vas": [_integer(v, "subscription call") for v in _array(row["subscription_call_vas"], "subscription calls", 64)],
        "privacy": privacy,
    }


def _validate_tool(path: Path, expected_version: str, expected_size: int, expected_sha256: str, name: str) -> None:
    try:
        st = path.stat()
    except OSError as exc:
        raise ProvenanceError(f"cannot stat {name}: {exc.strerror}") from exc
    if not stat.S_ISREG(st.st_mode) or not os.access(path, os.X_OK):
        raise ProvenanceError(f"{name} is not a regular executable")
    raw = _read_regular(path, 16 << 20, name)
    if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ProvenanceError(f"{name} file identity does not match manifest")
    output = _run_tool([str(path), "--version"], f"{name} version", 1 << 20)
    first = output.decode("utf-8", "strict").splitlines()
    if not first or first[0] != expected_version:
        raise ProvenanceError(f"{name} version identity does not match manifest")


def _run_tool(command: list[str], what: str, maximum: int = MAX_TOOL_OUTPUT) -> bytes:
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        raise ProvenanceError(f"cannot run {what}: {exc.strerror}") from exc
    if completed.returncode != 0:
        raise ProvenanceError(f"{what} failed with status {completed.returncode}")
    if len(completed.stdout) > maximum or len(completed.stderr) > (1 << 20):
        raise ProvenanceError(f"{what} output exceeds bound")
    if completed.stderr:
        raise ProvenanceError(f"{what} produced unexpected stderr")
    return completed.stdout


def parse_disassembly(raw: bytes) -> list[Instruction]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProvenanceError("objdump output is not UTF-8") from exc
    result: list[Instruction] = []
    seen: set[int] = set()
    in_disassembly = False
    line_re = re.compile(r"^\s*([0-9a-f]+):\s+([^\s]+)(?:\s+(.*?))?\s*$")
    malformed_re = re.compile(r"^\s*[0-9a-f]+:")
    for line in text.splitlines():
        if line.startswith("Disassembly of section "):
            in_disassembly = True
            continue
        match = line_re.match(line)
        if match:
            address = int(match.group(1), 16)
            mnemonic = match.group(2)
            operands = (match.group(3) or "").strip()
            if not re.fullmatch(r"[a-z][a-z0-9.]*", mnemonic):
                raise ProvenanceError("objdump instruction mnemonic is malformed")
            if address in seen:
                raise ProvenanceError("objdump contains an ambiguous duplicate instruction address")
            seen.add(address)
            result.append(Instruction(address, mnemonic, operands))
        elif in_disassembly and malformed_re.match(line):
            raise ProvenanceError("objdump contains a malformed instruction line")
    if not result:
        raise ProvenanceError("objdump contains no decoded instructions")
    if any(a.address >= b.address for a, b in zip(result, result[1:])):
        raise ProvenanceError("objdump instruction addresses are not strictly increasing")
    return result


def parse_relocations(raw: bytes) -> dict[int, int]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProvenanceError("readelf relocation output is not UTF-8") from exc
    result: dict[int, int] = {}
    pattern = re.compile(r"^([0-9a-f]{16})\s+[0-9a-f]{16}\s+R_X86_64_RELATIVE\s+([0-9a-f]+)\s*$")
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        offset, addend = (int(match.group(i), 16) for i in (1, 2))
        if offset in result:
            raise ProvenanceError("readelf contains duplicate relative relocation offsets")
        result[offset] = addend
    if not result:
        raise ProvenanceError("readelf contains no relative relocations")
    return result


def parse_build_id(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProvenanceError("readelf notes output is not UTF-8") from exc
    values = re.findall(r"Build ID: ([0-9a-f]+)", text)
    if len(values) != 1:
        raise ProvenanceError("readelf Build ID is absent or ambiguous")
    return values[0]


def _instruction_map(instructions: list[Instruction]) -> dict[int, Instruction]:
    return {item.address: item for item in instructions}


def _target_va(operands: str) -> int | None:
    match = re.search(r"# 0x([0-9a-f]+)(?:\s|$)", operands)
    return int(match.group(1), 16) if match else None


def _call_symbol(item: Instruction) -> str:
    if not item.mnemonic.startswith("call"):
        return ""
    match = re.search(r"<([^>]+)>", item.operands)
    return match.group(1) if match else ""


def _branch_target(item: Instruction) -> int | None:
    if not item.mnemonic.startswith(("call", "j")):
        return None
    match = re.match(r"0x([0-9a-f]+)(?:\s|$)", item.operands)
    return int(match.group(1), 16) if match else None


def _call_target(item: Instruction) -> int | None:
    return _branch_target(item) if item.mnemonic.startswith("call") else None


def _cstring_by_va(elf: ElfView, va: int, what: str) -> str:
    return elf.cstring_at_va(va, what, 1024)


def _canonical_hash(values: Iterable[str]) -> str:
    raw = "".join(value + "\n" for value in values).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _register(name: str) -> str | None:
    aliases = {
        "%eax": "rax", "%ax": "rax", "%al": "rax", "%rax": "rax",
        "%ebx": "rbx", "%bx": "rbx", "%bl": "rbx", "%rbx": "rbx",
        "%ecx": "rcx", "%cx": "rcx", "%cl": "rcx", "%rcx": "rcx",
        "%edx": "rdx", "%dx": "rdx", "%dl": "rdx", "%rdx": "rdx",
        "%esi": "rsi", "%si": "rsi", "%sil": "rsi", "%rsi": "rsi",
        "%edi": "rdi", "%di": "rdi", "%dil": "rdi", "%rdi": "rdi",
        "%r8d": "r8", "%r8": "r8", "%r9d": "r9", "%r9": "r9",
        "%r10d": "r10", "%r10": "r10", "%r11d": "r11", "%r11": "r11",
        "%r12d": "r12", "%r12": "r12", "%r13d": "r13", "%r13": "r13",
        "%r14d": "r14", "%r14": "r14", "%r15d": "r15", "%r15": "r15",
        "%ebp": "rbp", "%rbp": "rbp", "%esp": "rsp", "%rsp": "rsp",
    }
    return aliases.get(name)


def _split_operands(operands: str) -> list[str]:
    before_comment = operands.split("#", 1)[0].rstrip()
    return [part.strip() for part in before_comment.split(",")] if before_comment else []


def _writes_register(item: Instruction, target: str) -> bool:
    parts = _split_operands(item.operands)
    return bool(parts and _register(parts[-1]) == target and item.mnemonic.startswith(("mov", "lea", "xor", "sub", "add", "pop")))


def _simulate_qflag_segment(segment: list[Instruction], elf: ElfView) -> tuple[dict[str, Any], dict[str, Any]]:
    regs: dict[str, Any] = {}
    qflags: list[dict[str, Any]] = []
    caller_saved = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
    for item in segment:
        parts = _split_operands(item.operands)
        if item.mnemonic == "leaq" and len(parts) == 2:
            dest = _register(parts[1])
            target = _target_va(item.operands)
            if dest:
                regs[dest] = ("address", target) if target is not None else ("unknown",)
        elif item.mnemonic == "movl" and len(parts) == 2 and parts[0].startswith("$0x"):
            dest = _register(parts[1])
            if dest:
                regs[dest] = ("integer", int(parts[0][3:], 16))
        elif item.mnemonic.startswith("mov") and len(parts) == 2:
            dest = _register(parts[1])
            source = _register(parts[0])
            if dest:
                regs[dest] = regs.get(source, ("unknown",)) if source else ("unknown",)
        elif item.mnemonic.startswith("xor") and len(parts) == 2 and parts[0] == parts[1]:
            dest = _register(parts[1])
            if dest:
                regs[dest] = ("integer", 0)
        if item.mnemonic.startswith("call"):
            symbol = _call_symbol(item)
            if symbol == QFLAG:
                source = regs.get("rdi")
                if not source or source[0] != "address" or source[1] is None:
                    raise ProvenanceError(f"qFlagLocation at 0x{item.address:x} lacks literal provenance")
                text = _cstring_by_va(elf, source[1], "qFlagLocation literal")
                tag = ("qflag", source[1], text, item.address)
                for reg in caller_saved:
                    regs.pop(reg, None)
                regs["rax"] = tag
                qflags.append({"call_va": item.address, "literal_va": source[1], "text": text})
            else:
                for reg in caller_saved:
                    regs.pop(reg, None)
    return regs, {"qflags": qflags}


def analyze_old_connects(instructions: list[Instruction], elf: ElfView) -> list[dict[str, Any]]:
    calls = [index for index, item in enumerate(instructions) if _call_symbol(item) == OLD_CONNECT]
    result = []
    for index in calls:
        prior_qflags = [j for j in range(index - 1, max(-1, index - 80), -1) if _call_symbol(instructions[j]) == QFLAG]
        if len(prior_qflags) < 2:
            raise ProvenanceError("old-style connect lacks two bounded qFlagLocation calls")
        selected = sorted(prior_qflags[:2])
        start = selected[0] - 1
        while start >= 0 and start >= selected[0] - 4 and not (_writes_register(instructions[start], "rdi") and _target_va(instructions[start].operands) is not None):
            start -= 1
        if start < 0 or start < selected[0] - 4:
            raise ProvenanceError("old-style connect first literal setup is ambiguous")
        segment = instructions[start:index]
        for item in segment:
            if item.mnemonic.startswith("j") or (item.mnemonic.startswith("call") and _call_symbol(item) != QFLAG):
                raise ProvenanceError("old-style connect provenance crosses unsupported control flow")
        regs, detail = _simulate_qflag_segment(segment, elf)
        if len(detail["qflags"]) != 2:
            raise ProvenanceError("old-style connect qFlagLocation cardinality is ambiguous")
        signal = regs.get("rdx")
        member = regs.get("r8")
        connection = regs.get("r9")
        if not signal or signal[0] != "qflag" or not member or member[0] != "qflag":
            raise ProvenanceError("old-style connect operands lack qFlagLocation provenance")
        if signal[2][:1] != "2" or member[2][:1] not in ("1", "2"):
            raise ProvenanceError("old-style connect signal/member encodings are unsupported")
        if not connection or connection[0] != "integer" or connection[1] not in (0, 1, 2, 3):
            raise ProvenanceError("old-style connect connection type is unresolved")
        if {signal[3], member[3]} != {row["call_va"] for row in detail["qflags"]}:
            raise ProvenanceError("old-style connect operand provenance is inconsistent")
        result.append({"call_va": instructions[index].address, "signal": signal[2], "member": member[2], "connection_type": connection[1]})
    return result


def analyze_invokes(instructions: list[Instruction], elf: ElfView) -> list[dict[str, Any]]:
    result = []
    for index, call in enumerate(instructions):
        if INVOKE_METHOD not in _call_symbol(call):
            continue
        name_setup = None
        for cursor in range(index - 1, max(-1, index - 100), -1):
            item = instructions[cursor]
            if _writes_register(item, "rsi") and item.mnemonic == "leaq" and _target_va(item.operands) is not None:
                name_setup = cursor
                break
            if item.mnemonic.startswith(("j", "call")):
                raise ProvenanceError("invokeMethod member provenance crosses control flow")
        if name_setup is None:
            raise ProvenanceError("invokeMethod member literal is unresolved")
        name_va = _target_va(instructions[name_setup].operands)
        assert name_va is not None
        for item in instructions[name_setup + 1 : index]:
            if _writes_register(item, "rsi"):
                raise ProvenanceError("invokeMethod member register is overwritten")
            if item.mnemonic.startswith(("j", "call")):
                raise ProvenanceError("invokeMethod provenance crosses control flow")
        type_write = None
        for cursor in range(index - 1, max(-1, index - 120), -1):
            item = instructions[cursor]
            if _writes_register(item, "rdx"):
                type_write = item
                break
            if item.mnemonic.startswith(("j", "call")):
                raise ProvenanceError("invokeMethod connection type crosses control flow")
        if type_write is None or type_write.mnemonic != "xorl" or _split_operands(type_write.operands) != ["%edx", "%edx"]:
            raise ProvenanceError("invokeMethod connection type is not uniquely AutoConnection")
        result.append({"call_va": call.address, "member": _cstring_by_va(elf, name_va, "invokeMethod member"), "connection_type": 0})
    return result


def analyze_timer_members(instructions: list[Instruction], elf: ElfView) -> list[dict[str, Any]]:
    result = []
    for index, call in enumerate(instructions):
        if _call_symbol(call) != TIMER_STRING:
            continue
        qflags = [j for j in range(index - 1, max(-1, index - 32), -1) if _call_symbol(instructions[j]) == QFLAG]
        if not qflags:
            raise ProvenanceError("QTimer string member lacks qFlagLocation provenance")
        qindex = qflags[0]
        setup = next((item for item in reversed(instructions[max(0, qindex - 4):qindex]) if _writes_register(item, "rdi") and _target_va(item.operands) is not None), None)
        if setup is None:
            raise ProvenanceError("QTimer string member literal is unresolved")
        segment = instructions[instructions.index(setup):index]
        if any(item.mnemonic.startswith("j") or (item.mnemonic.startswith("call") and _call_symbol(item) != QFLAG) for item in segment):
            raise ProvenanceError("QTimer string member provenance crosses control flow")
        regs, detail = _simulate_qflag_segment(segment, elf)
        member = regs.get("rdx")
        if len(detail["qflags"]) != 1 or not member or member[0] != "qflag" or member[2][:1] not in ("1", "2"):
            raise ProvenanceError("QTimer string member operand is unresolved")
        result.append({"call_va": call.address, "member": member[2]})
    return result


def analyze_subscriptions(instructions: list[Instruction], elf: ElfView, call_vas: list[int]) -> list[dict[str, Any]]:
    by_address = {item.address: index for index, item in enumerate(instructions)}
    result = []
    for call_va in call_vas:
        if call_va not in by_address or DBUS_CONNECT not in _call_symbol(instructions[by_address[call_va]]):
            raise ProvenanceError("selected D-Bus subscription call does not match")
        index = by_address[call_va]
        qflags = [j for j in range(index - 1, max(-1, index - 160), -1) if _call_symbol(instructions[j]) == QFLAG]
        if not qflags:
            raise ProvenanceError("D-Bus subscription lacks qFlagLocation provenance")
        qindex = qflags[0]
        literal_setup = None
        for cursor in range(qindex - 1, max(-1, qindex - 5), -1):
            if _writes_register(instructions[cursor], "rdi") and _target_va(instructions[cursor].operands) is not None:
                literal_setup = cursor
                break
        if literal_setup is None:
            raise ProvenanceError("D-Bus subscription member literal is unresolved")
        name_va = _target_va(instructions[literal_setup].operands)
        assert name_va is not None
        member = _cstring_by_va(elf, name_va, "D-Bus subscription member")
        if not member.startswith("1"):
            raise ProvenanceError("D-Bus subscription member is not a slot encoding")
        stores = []
        for cursor in range(qindex + 1, index):
            candidate = instructions[cursor]
            if candidate.mnemonic.startswith("call"):
                break
            parts = _split_operands(candidate.operands)
            if candidate.mnemonic == "movq" and len(parts) == 2 and parts[0] == "%rax" and "(%rbp)" in parts[1]:
                stores.append(parts[1])
        if len(stores) != 1:
            raise ProvenanceError("D-Bus subscription qFlag result storage is ambiguous")
        pushed = [item for item in instructions[qindex + 1:index] if item.mnemonic == "pushq" and _split_operands(item.operands) == [stores[0]]]
        if len(pushed) != 1:
            raise ProvenanceError("D-Bus subscription member is not passed from qFlag result")
        receiver = [item for item in instructions[max(qindex, index - 40):index] if item.mnemonic == "movq" and _split_operands(item.operands) == ["%rbx", "%r9"]]
        if len(receiver) != 1:
            raise ProvenanceError("D-Bus subscription receiver is not uniquely the helper object")
        result.append({"call_va": call_va, "member": member})
    return result


def decode_metaobject(elf: ElfView, spec: dict[str, Any], relocations: dict[int, int]) -> dict[str, Any]:
    static_va = spec["static_object_va"]
    expected_links = {static_va + 8: spec["stringdata_va"], static_va + 16: spec["metadata_va"], static_va + 24: spec["static_metacall_va"]}
    for offset, expected in expected_links.items():
        if relocations.get(offset) != expected:
            raise ProvenanceError(f"selected metaobject relocation 0x{offset:x} does not match")
    metadata = spec["metadata_va"]
    header = [elf.u32(metadata + 4 * index, "metaobject header") for index in range(14)]
    if header[0] != 7 or header[4] != spec["method_count"] or header[13] != spec["signal_count"]:
        raise ProvenanceError("selected metaobject header does not match manifest")
    if header[4] > MAX_METHODS or header[13] > header[4]:
        raise ProvenanceError("selected metaobject counts are unsupported")
    class_name = elf.qt_string(spec["stringdata_va"], header[1], "metaobject class name")
    if class_name != spec["class_name"]:
        raise ProvenanceError("selected metaobject class does not match manifest")
    table = header[5]
    if table < 14:
        raise ProvenanceError("selected method table overlaps header")
    methods = []
    occupied: list[tuple[int, int]] = []
    for index in range(header[4]):
        base = metadata + 4 * (table + index * 5)
        name_i, argc, params, tag_i, flags = [elf.u32(base + 4 * word, "method row") for word in range(5)]
        if argc > MAX_ARGUMENTS or params < table + header[4] * 5:
            raise ProvenanceError("selected method parameter record is unsupported")
        interval = (params, params + 1 + 2 * argc)
        if any(interval[0] < other[1] and other[0] < interval[1] for other in occupied):
            raise ProvenanceError("selected method parameter records overlap")
        occupied.append(interval)
        words = [elf.u32(metadata + 4 * (params + word), "method parameters") for word in range(1 + 2 * argc)]
        name, name_va = elf.qt_string_location(spec["stringdata_va"], name_i, "method name")
        elf.qt_string(spec["stringdata_va"], tag_i, "method tag")
        method_type = flags & 0x0C
        access = flags & 0x03
        if method_type not in (0x04, 0x08) or access not in (0, 1, 2):
            raise ProvenanceError("selected metaobject contains unsupported method flags")
        methods.append({"index": index, "name": name, "name_va": name_va, "argc": argc, "flags": flags, "access": ("private", "protected", "public")[access], "parameter_words": words})
    slots = sum((row["flags"] & 0x0C) == 0x08 and row["access"] == "public" for row in methods)
    signals = sum((row["flags"] & 0x0C) == 0x04 for row in methods)
    if signals != header[13] or any((row["flags"] & 0x0C) != 0x04 for row in methods[:header[13]]):
        raise ProvenanceError("selected metaobject signal prefix is inconsistent")
    return {"role": spec["role"], "class_name": class_name, "static_metacall_va": spec["static_metacall_va"], "method_count": len(methods), "slot_count": slots, "signal_count": signals, "methods": methods}


def _simulate_object_origin(
    instructions: list[Instruction],
    start_index: int,
    end_index: int,
    initial: dict[str, Any],
) -> tuple[dict[str, Any], list[tuple[Instruction, str, Any]]]:
    """Track only register origins needed by constructor/helper binding."""
    regs = dict(initial)
    writes: list[tuple[Instruction, str, Any]] = []
    caller_saved = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
    for item in instructions[start_index:end_index]:
        parts = _split_operands(item.operands)
        if item.mnemonic.startswith("mov") and len(parts) == 2:
            dest = _register(parts[1])
            source = _register(parts[0])
            if dest:
                value: Any
                if parts[0].startswith("$0x"):
                    value = ("integer", int(parts[0][3:], 16))
                elif source:
                    value = regs.get(source, ("unknown",))
                else:
                    value = ("unknown",)
                regs[dest] = value
                writes.append((item, dest, value))
        elif item.mnemonic.startswith("xor") and len(parts) == 2 and parts[0] == parts[1]:
            dest = _register(parts[1])
            if dest:
                regs[dest] = ("integer", 0)
                writes.append((item, dest, regs[dest]))
        elif item.mnemonic.startswith("call"):
            for register in caller_saved:
                regs.pop(register, None)
    return regs, writes


def analyze_registration_binding(
    instructions: list[Instruction],
    constructor_start: int,
    constructor_end: int,
    register_object_symbol: str,
    helper_va: int,
    option_value: int,
) -> dict[str, Any]:
    by_address = {item.address: index for index, item in enumerate(instructions)}
    constructor = [
        (index, item)
        for index, item in enumerate(instructions)
        if constructor_start <= item.address < constructor_end
    ]
    helper_calls = [(index, item) for index, item in constructor if _call_target(item) == helper_va]
    if len(helper_calls) != 1:
        raise ProvenanceError("registration helper target is absent or ambiguous")
    helper_call_index, helper_call = helper_calls[0]
    ctor_start_index = by_address.get(constructor_start)
    if ctor_start_index is None:
        raise ProvenanceError("selected constructor entry is absent")
    regs, _writes = _simulate_object_origin(
        instructions, ctor_start_index, helper_call_index, {"rdi": ("constructor_this",)}
    )
    if regs.get("rdi") != ("constructor_this",):
        raise ProvenanceError("registration helper argument is not constructor this")
    helper_start_index = by_address.get(helper_va)
    if helper_start_index is None:
        raise ProvenanceError("registration helper entry is absent")
    register_calls = [
        (index, item)
        for index, item in enumerate(instructions)
        if helper_start_index <= index and register_object_symbol in _call_symbol(item)
    ]
    if not register_calls:
        raise ProvenanceError("registerObject call is absent after helper entry")
    register_index, register_call = register_calls[0]
    if register_call.address - helper_va > 0x1000:
        raise ProvenanceError("registerObject call is outside the bounded helper")
    helper_regs, writes = _simulate_object_origin(
        instructions, helper_start_index, register_index, {"rdi": ("helper_this",)}
    )
    if helper_regs.get("rdx") != ("helper_this",):
        raise ProvenanceError("registerObject object is not helper this")
    rcx_writes = [(item, value) for item, register, value in writes if register == "rcx"]
    if not rcx_writes:
        raise ProvenanceError("registerObject option has no defining operand")
    defining_instruction, actual = rcx_writes[-1]
    if actual[0] != "integer":
        raise ProvenanceError("registerObject option is not an immediate integer")
    # The last definition must survive directly to registerObject; generic calls
    # clear caller-saved RCX in the origin simulation.
    if helper_regs.get("rcx") != actual:
        raise ProvenanceError("registerObject option definition does not dominate the call")
    if defining_instruction.mnemonic != "movl" or _split_operands(defining_instruction.operands)[-1] != "%ecx":
        raise ProvenanceError("registerObject option defining instruction is unsupported")
    if actual[1] != option_value:
        raise ProvenanceError("registerObject option does not match manifest")
    if actual[1] != 1:
        raise ProvenanceError("registerObject option is not supported ExportAdaptors value 1")
    return {
        "helper_call_va": helper_call.address,
        "helper_va": helper_va,
        "register_object_call_va": register_call.address,
        "option_definition_va": defining_instruction.address,
        "option_value": actual[1],
        "option_name": "ExportAdaptors",
    }


def analyze_connect_impl_bindings(
    instructions: list[Instruction],
    call_vas: list[int],
    expected_callback_vas: list[int],
) -> list[dict[str, Any]]:
    if len(call_vas) != len(expected_callback_vas):
        raise ProvenanceError("connectImpl callback expectation count does not match")
    by_address = {item.address: index for index, item in enumerate(instructions)}
    results = []
    caller_saved = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
    for call_va, expected_callback in zip(call_vas, expected_callback_vas):
        call_index = by_address.get(call_va)
        if call_index is None or _call_symbol(instructions[call_index]) != CONNECT_IMPL:
            raise ProvenanceError("selected connectImpl call is absent")
        allocations = [
            index
            for index in range(max(0, call_index - 100), call_index)
            if "_Znwm@plt" in _call_symbol(instructions[index])
        ]
        if not allocations:
            raise ProvenanceError("connectImpl slot object allocation is unresolved")
        allocation_index = allocations[-1]
        start = max(0, allocation_index - 24)
        regs: dict[str, Any] = {}
        memory: dict[Any, Any] = {}
        slot_fields: dict[tuple[Any, int], Any] = {}
        pushes: list[Any] = []
        slot_token = ("slot_object", instructions[allocation_index].address)
        for index in range(start, call_index):
            item = instructions[index]
            parts = _split_operands(item.operands)
            if item.mnemonic == "leaq" and len(parts) == 2:
                dest = _register(parts[1])
                target = _target_va(item.operands)
                if dest:
                    regs[dest] = ("address", target) if target is not None else ("unknown",)
            elif item.mnemonic.startswith("mov") and len(parts) == 2:
                source_reg = _register(parts[0])
                dest_reg = _register(parts[1])
                if parts[0].startswith("$0x"):
                    value: Any = ("integer", int(parts[0][3:], 16))
                elif source_reg:
                    value = regs.get(source_reg, ("unknown",))
                else:
                    value = memory.get(parts[0], ("unknown",))
                if dest_reg:
                    regs[dest_reg] = value
                elif "(%r9)" in parts[1] and regs.get("r9", (None,))[0] == "slot_object":
                    displacement = int(parts[1].split("(", 1)[0], 16) if parts[1].split("(", 1)[0] else 0
                    slot_fields[(regs["r9"], displacement)] = value
                else:
                    memory[parts[1]] = value
            elif item.mnemonic.startswith("xor") and len(parts) == 2 and parts[0] == parts[1]:
                dest = _register(parts[1])
                if dest:
                    regs[dest] = ("integer", 0)
            elif item.mnemonic == "pushq" and len(parts) == 1:
                if parts[0].startswith("$0x"):
                    pushes.append(("integer", int(parts[0][3:], 16)))
                else:
                    source_reg = _register(parts[0])
                    pushes.append(regs.get(source_reg, memory.get(parts[0], ("unknown",))))
            elif item.mnemonic.startswith("call"):
                for register in caller_saved:
                    regs.pop(register, None)
                if index == allocation_index:
                    regs["rax"] = slot_token
        actual_slot = regs.get("r9")
        callback = slot_fields.get((actual_slot, 0x10)) if actual_slot else None
        if actual_slot != slot_token:
            raise ProvenanceError("connectImpl slot-object operand lacks allocation def-use")
        if callback != ("address", expected_callback):
            raise ProvenanceError("connectImpl callback def-use does not match expected body")
        if not pushes or pushes[-1] != ("integer", 0):
            raise ProvenanceError("connectImpl connection type is not AutoConnection")
        results.append({"call_va": call_va, "slot_allocation_va": instructions[allocation_index].address, "callback_va": expected_callback, "connection_type": 0})
    return results


def _dispatch_table_base_and_row_register(
    instructions: list[Instruction], start_va: int
) -> tuple[int, str]:
    """Follow a bounded linear invocation path to a generated jump table."""
    by_address = {item.address: index for index, item in enumerate(instructions)}
    index = by_address.get(start_va)
    if index is None:
        raise ProvenanceError("selected static metacall entry is absent")
    regs: dict[str, Any] = {"rdx": ("row",), "rsi": ("call",), "rcx": ("args",)}
    visited: set[int] = set()
    for _step in range(256):
        if index >= len(instructions) or index in visited:
            raise ProvenanceError("static metacall dispatch is cyclic or truncated")
        visited.add(index)
        item = instructions[index]
        parts = _split_operands(item.operands)
        if item.mnemonic == "leaq" and len(parts) == 2:
            dest = _register(parts[1])
            if dest:
                target = _target_va(item.operands)
                regs[dest] = ("address", target) if target is not None else ("unknown",)
        elif item.mnemonic.startswith("mov") and len(parts) == 2:
            dest = _register(parts[1])
            source = _register(parts[0])
            if dest and not (item.mnemonic == "movslq" and ",4)" in item.operands):
                regs[dest] = regs.get(source, ("unknown",)) if source else ("unknown",)
        elif item.mnemonic.startswith("xor") and len(parts) == 2 and parts[0] == parts[1]:
            dest = _register(parts[1])
            if dest:
                regs[dest] = ("integer", 0)
        if item.mnemonic == "jmpq" and item.operands.startswith("*"):
            loads = [candidate for candidate in instructions[max(0, index - 12):index] if candidate.mnemonic == "movslq" and ",4)" in candidate.operands]
            if len(loads) != 1:
                raise ProvenanceError("static metacall jump table load is absent or ambiguous")
            match = re.search(r"\(%([a-z0-9]+),%([a-z0-9]+),4\)", loads[0].operands)
            if not match:
                raise ProvenanceError("static metacall jump table addressing is unsupported")
            base_reg, row_reg = match.groups()
            base = regs.get(base_reg)
            if base is None or base[0] != "address" or regs.get(row_reg) != ("row",):
                raise ProvenanceError("static metacall jump table lacks row/base provenance")
            return base[1], row_reg
        if item.mnemonic in ("jmp", "jmpq") and not item.operands.startswith("*"):
            target = _branch_target(item)
            if target is None or target not in by_address:
                raise ProvenanceError("static metacall tail dispatcher is unresolved")
            index = by_address[target]
            continue
        index += 1
    raise ProvenanceError("static metacall dispatch exceeds bound")


def _single_slot_case(instructions: list[Instruction], static_va: int) -> int:
    by_address = {item.address: index for index, item in enumerate(instructions)}
    start = by_address.get(static_va)
    if start is None:
        raise ProvenanceError("single-slot static metacall is absent")
    window = instructions[start:start + 40]
    row_test = next((index for index, item in enumerate(window) if item.mnemonic == "testl" and _split_operands(item.operands) == ["%edx", "%edx"]), None)
    if row_test is None:
        raise ProvenanceError("single-slot static metacall lacks row-zero test")
    branch = next((item for item in window[row_test + 1:row_test + 4] if item.mnemonic in ("je", "jz")), None)
    target = _branch_target(branch) if branch else None
    if target is None or target not in by_address:
        raise ProvenanceError("single-slot static metacall case is unresolved")
    return target


def _resolve_forwarder_implementation(
    instructions: list[Instruction],
    start_va: int,
    invoke_by_va: dict[int, dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    by_address = {item.address: index for index, item in enumerate(instructions)}
    current = start_va
    visited: set[int] = set()
    for _depth in range(6):
        if current in visited or current not in by_address:
            raise ProvenanceError("adaptor row implementation chain is cyclic or absent")
        visited.add(current)
        start = by_address[current]
        direct_candidates: list[int] = []
        for item in instructions[start:start + 96]:
            if item.address in invoke_by_va:
                return current, invoke_by_va[item.address]
            if item.mnemonic.startswith("ret"):
                raise ProvenanceError("adaptor implementation returns before invokeMethod")
            target = _branch_target(item)
            if target is None or item.mnemonic.startswith(("je", "jne", "jg", "jl", "ja", "jb", "js", "jz")):
                continue
            if "@plt" in item.operands:
                continue
            direct_candidates.append(target)
            break
        if len(direct_candidates) != 1:
            raise ProvenanceError("adaptor row implementation target is absent or ambiguous")
        current = direct_candidates[0]
    raise ProvenanceError("adaptor row implementation chain exceeds bound")


def bind_adaptor_forwarders(
    instructions: list[Instruction],
    elf: ElfView,
    adaptor_metaobjects: list[dict[str, Any]],
    invoke_by_va: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    by_address = {item.address: index for index, item in enumerate(instructions)}
    results = []
    for meta in adaptor_metaobjects:
        slot_rows = [row for row in meta["methods"] if (row["flags"] & 0x0C) == 0x08]
        if any(row["access"] != "public" for row in slot_rows):
            raise ProvenanceError("selected adaptor contains protected/private slot")
        if not slot_rows:
            continue
        static_va = meta["static_metacall_va"]
        if meta["method_count"] == 1:
            cases = {0: _single_slot_case(instructions, static_va)}
        else:
            table_base, _row_register = _dispatch_table_base_and_row_register(instructions, static_va)
            cases = {}
            for row in slot_rows:
                raw = elf.bytes_at(table_base + 4 * row["index"], 4, "adaptor jump-table entry")
                case_va = table_base + struct.unpack("<i", raw)[0]
                if case_va not in by_address:
                    raise ProvenanceError("adaptor jump-table case is not an instruction")
                cases[row["index"]] = case_va
        for row in slot_rows:
            implementation_va, invoke = _resolve_forwarder_implementation(
                instructions, cases[row["index"]], invoke_by_va
            )
            if invoke["member"] != row["name"] or invoke["connection_type"] != 0:
                raise ProvenanceError("adaptor row/body/invoke member binding does not match")
            results.append({
                "role": meta["role"],
                "row_index": row["index"],
                "row_name": row["name"],
                "case_va": cases[row["index"]],
                "implementation_va": implementation_va,
                "invoke_call_va": invoke["call_va"],
                "member": invoke["member"],
            })
    if len({(row["role"], row["row_index"]) for row in results}) != len(results):
        raise ProvenanceError("adaptor row forwarding bindings are ambiguous")
    return results


def _validate_anchors(instruction_map: dict[int, Instruction], anchors: list[dict[str, Any]]) -> None:
    addresses: set[int] = set()
    for row in anchors:
        if row["va"] in addresses:
            raise ProvenanceError("manifest contains duplicate machine anchors")
        addresses.add(row["va"])
        actual = instruction_map.get(row["va"])
        if actual is None or actual.mnemonic != row["mnemonic"] or actual.operands != row["operands"]:
            raise ProvenanceError(f"machine anchor 0x{row['va']:x} does not match")


def _scan_privacy(data: bytes, elf: ElfView, instructions: dict[int, Instruction], privacy: dict[str, dict[str, Any]]) -> dict[str, Any]:
    strings: dict[str, list[bytes]] = {name: [] for name in ("service_template", "object_path")}
    nul = data.find(b"\0")
    while nul >= 0:
        for name in strings:
            spec = privacy[name]
            start = nul - spec["length"]
            if start >= 0:
                value = data[start:nul]
                if hashlib.sha256(value).hexdigest() == spec["sha256"]:
                    strings[name].append(value)
        nul = data.find(b"\0", nul + 1)
    if any(len(values) != 1 for values in strings.values()):
        raise ProvenanceError("privacy-sensitive string identity is absent or ambiguous")
    token_spec = privacy["service_token"]
    token_anchor = instructions.get(token_spec["anchor_instruction_va"])
    token_va = _target_va(token_anchor.operands) if token_anchor is not None else None
    if token_va is None:
        raise ProvenanceError("service-token anchor is absent")
    token = elf.bytes_at(token_va, token_spec["length"] + 1, "service token")
    if token[-1:] != b"\0":
        raise ProvenanceError("service token is not NUL terminated")
    token = token[:-1]
    if hashlib.sha256(token).hexdigest() != token_spec["sha256"]:
        raise ProvenanceError("service-token anchor identity does not match")
    template = strings["service_template"][0]
    if template.count(b"%1") != privacy["service_template"]["placeholder_count"]:
        raise ProvenanceError("service template placeholder count does not match")
    final = template.replace(b"%1", token)
    final_spec = privacy["final_service"]
    if len(final) != final_spec["length"] or hashlib.sha256(final).hexdigest() != final_spec["sha256"]:
        raise ProvenanceError("derived service identity does not match")
    return {
        "service_template": {"length": len(template), "sha256": privacy["service_template"]["sha256"]},
        "service_token": {"length": len(token), "sha256": privacy["service_token"]["sha256"]},
        "final_service": {"length": len(final), "sha256": final_spec["sha256"]},
        "object_path": {"length": len(strings["object_path"][0]), "sha256": privacy["object_path"]["sha256"]},
        "callable_coordinates_emitted": False,
    }


def analyze(elf_path: Path, objdump_path: Path, readelf_path: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    elf_data = _read_regular(elf_path, MAX_ELF_SIZE, "ELF")
    actual_sha = hashlib.sha256(elf_data).hexdigest()
    artifact = manifest["artifact"]
    if len(elf_data) != artifact["size"] or actual_sha != artifact["sha256"]:
        raise ProvenanceError("ELF identity does not match manifest")
    elf = ElfView(elf_data)
    _validate_tool(objdump_path, manifest["llvm"]["version"], manifest["llvm"]["objdump_size"], manifest["llvm"]["objdump_sha256"], "llvm-objdump")
    _validate_tool(readelf_path, manifest["llvm"]["version"], manifest["llvm"]["readelf_size"], manifest["llvm"]["readelf_sha256"], "llvm-readelf")
    disassembly_raw = _run_tool([str(objdump_path), "-d", "--no-show-raw-insn", str(elf_path)], "llvm-objdump")
    relocation_raw = _run_tool([str(readelf_path), "-r", str(elf_path)], "llvm-readelf relocations")
    notes_raw = _run_tool([str(readelf_path), "-n", str(elf_path)], "llvm-readelf notes")
    symbols_raw = _run_tool([str(readelf_path), "--dyn-syms", "--wide", str(elf_path)], "llvm-readelf dynamic symbols")
    _validate_tool(objdump_path, manifest["llvm"]["version"], manifest["llvm"]["objdump_size"], manifest["llvm"]["objdump_sha256"], "llvm-objdump")
    _validate_tool(readelf_path, manifest["llvm"]["version"], manifest["llvm"]["readelf_size"], manifest["llvm"]["readelf_sha256"], "llvm-readelf")
    if _read_regular(elf_path, MAX_ELF_SIZE, "ELF") != elf_data:
        raise ProvenanceError("ELF changed during analysis")
    if parse_build_id(notes_raw) != artifact["build_id"]:
        raise ProvenanceError("ELF Build ID does not match manifest")
    instructions = parse_disassembly(disassembly_raw)
    canonical = "".join(item.canonical + "\n" for item in instructions).encode("utf-8")
    if len(instructions) != manifest["llvm"]["instruction_count"] or hashlib.sha256(canonical).hexdigest() != manifest["llvm"]["instruction_sha256"]:
        raise ProvenanceError("normalized instruction stream does not match manifest")
    instruction_map = _instruction_map(instructions)
    relocations = parse_relocations(relocation_raw)
    expected = manifest["expected"]
    _validate_anchors(instruction_map, expected["machine_anchors"])

    bare_bytes = expected["bare_name"]["text"].encode("utf-8") + b"\0"
    actual_offsets = []
    cursor = 0
    while True:
        found = elf_data.find(bare_bytes, cursor)
        if found < 0:
            break
        actual_offsets.append(found)
        cursor = found + 1
    expected_offsets = [row["offset"] for row in expected["bare_name"]["occurrences"]]
    if actual_offsets != expected_offsets:
        raise ProvenanceError("bare target-name occurrence inventory does not match")
    for form in expected["absent_forms"]:
        if form.encode("utf-8") in elf_data:
            raise ProvenanceError("an expected-absent target signature is present")
    for row in expected["bare_name"]["occurrences"]:
        xrefs = sorted(item.address for item in instructions if _target_va(item.operands) == row["offset"])
        if xrefs != row["xref_vas"]:
            raise ProvenanceError("bare target-name xref inventory does not match")
        if row["classification"] != "selected metadata payload":
            for xref_va in xrefs:
                xref_index = next(index for index, item in enumerate(instructions) if item.address == xref_va)
                xref = instructions[xref_index]
                if xref.mnemonic != "leaq" or _split_operands(xref.operands)[-1] != "%rdx":
                    raise ProvenanceError("logging-name xref does not feed the logging argument")
                following_calls = [item for item in instructions[xref_index + 1:xref_index + 9] if item.mnemonic.startswith("call")]
                if not following_calls or _call_target(following_calls[0]) != 0x137430:
                    raise ProvenanceError("logging-name classification does not reach the bounded logger")

    target_va = 0x100B30
    direct_calls = sorted(item.address for item in instructions if _call_target(item) == target_va)
    expected_calls = [row["call_va"] for row in expected["direct_edges"]]
    other_target_refs = [item.address for item in instructions if item.address not in direct_calls and (_target_va(item.operands) == target_va or re.match(rf"0x{target_va:x}(?:\s|$)", item.operands))]
    if direct_calls != expected_calls or other_target_refs:
        raise ProvenanceError("direct target edge inventory does not match")

    old_connects = analyze_old_connects(instructions, elf)
    invokes = analyze_invokes(instructions, elf)
    timer_members = analyze_timer_members(instructions, elf)
    count_symbols = {
        "old_connect": OLD_CONNECT,
        "connect_impl": CONNECT_IMPL,
        "invoke_method": INVOKE_METHOD,
        "dbus_connect": DBUS_CONNECT,
        "timer_string": TIMER_STRING,
        "register_service": REGISTER_SERVICE,
        "register_object": REGISTER_OBJECT,
    }
    actual_counts = {key: sum(symbol in _call_symbol(item) for item in instructions) for key, symbol in count_symbols.items()}
    if actual_counts != expected["call_counts"] or len(old_connects) != actual_counts["old_connect"] or len(invokes) != actual_counts["invoke_method"] or len(timer_members) != actual_counts["timer_string"]:
        raise ProvenanceError("imported direct-call counts do not match manifest")
    try:
        dyn_symbols = symbols_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProvenanceError("dynamic-symbol output is not UTF-8") from exc
    zero_needles = {
        "connect_slots_by_name": "_ZN11QMetaObject18connectSlotsByNameEP7QObject",
        "post_event": "_ZN16QCoreApplication9postEvent",
        "send_event": "_ZN16QCoreApplication9sendEvent",
        "qobject_disconnect": "_ZN7QObject10disconnect",
    }
    actual_zeros = {key: sum(needle in _call_symbol(item) for item in instructions) for key, needle in zero_needles.items()}
    actual_zeros["qmeta_call_event_import"] = dyn_symbols.count("QMetaCallEvent")
    if actual_zeros != expected["bounded_zeros"]:
        raise ProvenanceError("bounded zero-call/import inventory does not match")

    old_values = [row["member"] + "\n" + row["signal"] + "\n" + str(row["connection_type"]) for row in old_connects]
    invoke_values = [row["member"] + "\n" + str(row["connection_type"]) for row in invokes]
    if _canonical_hash(old_values) != expected["ordered_hashes"]["old_connect_pairs"]:
        raise ProvenanceError("ordered old-style connect hash does not match")
    if _canonical_hash(invoke_values) != expected["ordered_hashes"]["invoke_members"]:
        raise ProvenanceError("ordered invokeMethod hash does not match")
    if _canonical_hash(row["member"] for row in timer_members) != expected["ordered_hashes"]["timer_members"]:
        raise ProvenanceError("ordered QTimer member hash does not match")
    target_name = expected["bare_name"]["text"]
    if any(target_name in row["signal"] or target_name in row["member"] for row in old_connects) or any(target_name in row["member"] for row in invokes) or any(target_name in row["member"] for row in timer_members):
        raise ProvenanceError("target unexpectedly appears in audited connect/invoke operands")

    metaobjects = [decode_metaobject(elf, spec, relocations) for spec in expected["metaobjects"]]
    roles = {row["role"]: row for row in metaobjects}
    selected = roles.get("selected_engine")
    parent = roles.get("parent_engine")
    if not selected or not parent or selected["method_count"] != 85 or parent["method_count"] != 11:
        raise ProvenanceError("selected qt_metacall chain does not resolve to 11/85 methods")
    row64 = selected["methods"][64]
    if row64["name"] != target_name or row64["argc"] != 2 or row64["parameter_words"][:3] != [10, 10, 10] or row64["flags"] != 0x0A:
        raise ProvenanceError("selected local row 64 does not match target slot")
    metadata_occurrence = next(row for row in expected["bare_name"]["occurrences"] if row["classification"] == "selected metadata payload")
    if elf.map(row64["name_va"], len(target_name) + 1, "row-64 name payload") != metadata_occurrence["offset"]:
        raise ProvenanceError("selected metadata payload classification does not bind row 64")

    ctor = expected["constructor"]
    ctor_old = [row for row in old_connects if ctor["start_va"] <= row["call_va"] < ctor["end_va_exclusive"]]
    ctor_impl = [item.address for item in instructions if ctor["start_va"] <= item.address < ctor["end_va_exclusive"] and _call_symbol(item) == CONNECT_IMPL]
    type_counts = {"AutoConnection": sum(row["connection_type"] == 0 for row in ctor_old), "DirectConnection": sum(row["connection_type"] == 1 for row in ctor_old)}
    ctor_hash = _canonical_hash(row["member"] + "\n" + row["signal"] + "\n" + str(row["connection_type"]) for row in ctor_old)
    if len(ctor_old) != ctor["old_connect_count"] or ctor_impl != ctor["connect_impl_calls"] or type_counts != ctor["connection_types"] or ctor_hash != expected["ordered_hashes"]["constructor_connect_pairs"]:
        raise ProvenanceError("selected constructor connection inventory does not match")
    callback_starts = [row["start_va"] for row in ctor["callbacks"]]
    connect_impl_bindings = analyze_connect_impl_bindings(
        instructions, ctor_impl, callback_starts
    )
    for callback in ctor["callbacks"]:
        body = [item for item in instructions if callback["start_va"] <= item.address < callback["end_va_exclusive"]]
        if not body or body[0].address != callback["start_va"]:
            raise ProvenanceError("selected callback body is truncated")
        if any(target_name in item.operands or f"0x{target_va:x}" in item.operands for item in body):
            raise ProvenanceError("selected callback directly references target")
    ctor_region = [item for item in instructions if ctor["start_va"] <= item.address < ctor["end_va_exclusive"]]
    for callback_va in callback_starts:
        refs = [item for item in ctor_region if _target_va(item.operands) == callback_va]
        if len(refs) != 1:
            raise ProvenanceError("selected callback constructor reference is absent or ambiguous")

    registration = expected["registration"]
    registration_binding = analyze_registration_binding(
        instructions,
        ctor["start_va"],
        ctor["end_va_exclusive"],
        REGISTER_OBJECT,
        registration["helper_va"],
        registration["option_value"],
    )
    for adaptor in registration["adaptor_calls"]:
        call = instruction_map.get(adaptor["call_va"])
        if call is None or _call_target(call) != adaptor["constructor_va"]:
            raise ProvenanceError("selected adaptor construction call does not match")
        index = instructions.index(call)
        parent_moves = [item for item in instructions[max(0, index - 8):index] if item.mnemonic == "movq" and _split_operands(item.operands) == ["%rbx", "%rsi"]]
        if len(parent_moves) != 1:
            raise ProvenanceError("selected adaptor parent is not uniquely the helper object")
        constructor_body = [item for item in instructions if adaptor["constructor_va"] <= item.address < adaptor["constructor_va"] + 0x60]
        vptr_refs = [item for item in constructor_body if _target_va(item.operands) == adaptor["vptr_va"]]
        if len(vptr_refs) != 1 or relocations.get(adaptor["vptr_va"]) != adaptor["metaobject_fn_va"]:
            raise ProvenanceError("selected adaptor constructor/vtable binding does not match")
        role = roles.get(adaptor["metaobject_role"])
        if role is None:
            raise ProvenanceError("selected adaptor metaobject role is absent")
        meta_fn = [item for item in instructions if adaptor["metaobject_fn_va"] <= item.address < adaptor["metaobject_fn_va"] + 0x80]
        static_refs = [item for item in meta_fn if _target_va(item.operands) == next(spec["static_object_va"] for spec in expected["metaobjects"] if spec["role"] == adaptor["metaobject_role"])]
        if len(static_refs) != 1:
            raise ProvenanceError("selected adaptor vtable/metaobject binding does not match")
    subscriptions = analyze_subscriptions(instructions, elf, registration["subscription_call_vas"])
    if _canonical_hash(row["member"] for row in subscriptions) != expected["ordered_hashes"]["dbus_subscriptions"]:
        raise ProvenanceError("ordered D-Bus subscription hash does not match")
    if any(target_name in row["member"] for row in subscriptions):
        raise ProvenanceError("target unexpectedly appears in D-Bus subscriptions")
    invoke_by_va = {row["call_va"]: row for row in invokes}
    adaptor_rows = [row for row in metaobjects if row["role"].startswith("adaptor_")]
    if len(adaptor_rows) != 6 or sum(row["slot_count"] for row in adaptor_rows) != 16 or sum(row["signal_count"] for row in adaptor_rows) != 14:
        raise ProvenanceError("selected adaptor metadata totals do not match")
    if any(method["name"] == target_name for row in adaptor_rows for method in row["methods"]):
        raise ProvenanceError("target unexpectedly appears in selected adaptor metadata")
    forwarders = bind_adaptor_forwarders(
        instructions, elf, adaptor_rows, invoke_by_va
    )
    if _canonical_hash(row["member"] for row in forwarders) != expected["ordered_hashes"]["adaptor_forwarders"]:
        raise ProvenanceError("ordered adaptor forwarder hash does not match")
    if any(target_name in row["member"] for row in forwarders):
        raise ProvenanceError("target unexpectedly appears in adaptor forwarders")
    privacy_report = _scan_privacy(elf_data, elf, instruction_map, registration["privacy"])

    old_types = {"AutoConnection": sum(row["connection_type"] == 0 for row in old_connects), "DirectConnection": sum(row["connection_type"] == 1 for row in old_connects)}
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "artifact": {"sha256": actual_sha, "size": len(elf_data), "build_id": artifact["build_id"]},
        "target_name_inventory": {
            "bare_name_count": len(actual_offsets),
            "occurrences": [{"offset": f"0x{row['offset']:x}", "classification": row["classification"], "xref_count": len(row["xref_vas"])} for row in expected["bare_name"]["occurrences"]],
            "absent_signature_form_count": len(expected["absent_forms"]),
        },
        "direct_target_edges": {"count": len(direct_calls), "edges": [{"call_va": f"0x{row['call_va']:x}", "classification": row["classification"]} for row in expected["direct_edges"]]},
        "meta_call_chain": {"parent_local_method_count": parent["method_count"], "selected_local_method_count": selected["method_count"], "target_local_index": 64, "index_scope": "local-to-selected-metaobject", "absolute_method_index": None, "generated_forwarding": {"case_va": "0x16dfc6", "call_va": "0x16e030", "argument_copy": "a[1]/a[2] to local QString values", "return": "QString to a[0] when non-null"}},
        "dispatch_inventory": {
            "direct_call_counts": actual_counts,
            "bounded_zero_counts": actual_zeros,
            "old_style_connect": {"count": len(old_connects), "target_matches": 0, "connection_types": old_types, "ordered_provenance_sha256": expected["ordered_hashes"]["old_connect_pairs"]},
            "named_invoke": {"count": len(invokes), "distinct_member_count": len({row["member"] for row in invokes}), "target_matches": 0, "connection_type": "AutoConnection", "ordered_provenance_sha256": expected["ordered_hashes"]["invoke_members"]},
            "string_timer": {"count": len(timer_members), "target_matches": 0, "ordered_member_sha256": expected["ordered_hashes"]["timer_members"]},
            "selected_constructor": {"old_style_connect_count": len(ctor_old), "connect_impl_count": len(connect_impl_bindings), "connect_impl_connection_type": "AutoConnection", "connect_impl_callback_binding": "resolved", "connection_types": type_counts, "ordered_provenance_sha256": ctor_hash, "connect_impl_call_vas": [f"0x{row['call_va']:x}" for row in connect_impl_bindings], "callback_ranges": [{"start_va": f"0x{row['start_va']:x}", "end_va_exclusive": f"0x{row['end_va_exclusive']:x}", "direct_target_references": 0} for row in ctor["callbacks"]]},
        },
        "dbus_registration": {
            "same_object_helper_chain": True,
            "helper_va": f"0x{registration_binding['helper_va']:x}",
            "helper_call_va": f"0x{registration_binding['helper_call_va']:x}",
            "register_option_definition_va": f"0x{registration_binding['option_definition_va']:x}",
            "register_option_value": registration_binding["option_value"],
            "register_option_name": registration_binding["option_name"],
            "selected_adaptor_count": len(adaptor_rows),
            "selected_adaptor_totals": {"public_slots": sum(row["slot_count"] for row in adaptor_rows), "signals": sum(row["signal_count"] for row in adaptor_rows), "target_rows": 0},
            "selected_forwarders": {"count": len(forwarders), "target_matches": 0, "ordered_member_sha256": expected["ordered_hashes"]["adaptor_forwarders"]},
            "same_object_subscriptions": {"count": len(subscriptions), "target_matches": 0, "ordered_member_sha256": expected["ordered_hashes"]["dbus_subscriptions"]},
            "privacy": privacy_report,
        },
        "scope": {"exact_static": True, "runtime_invocation_proven": False, "complete_dynamic_producer_absence_proven": False, "attacker_control_proven": False},
    }


def _write_json(value: Any) -> None:
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    sys.stdout.buffer.write(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--llvm-objdump", required=True, type=Path)
    parser.add_argument("--llvm-readelf", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = analyze(args.elf, args.llvm_objdump, args.llvm_readelf, args.manifest)
    except ProvenanceError as exc:
        sys.stderr.buffer.write((f"error: {exc}\n").encode("utf-8"))
        return 2
    _write_json(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
