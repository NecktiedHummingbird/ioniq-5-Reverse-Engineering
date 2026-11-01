#!/usr/bin/env python3
"""Audit the two exact AppUpgrade parameterized verifier operands.

This execution-free analyzer accepts one strict JSON manifest, one exact ELF,
and explicit Homebrew LLVM tools.  It emits only normalized identities,
classifications, addresses, and Boolean/null scope facts: never target bytes,
recovered command text, callable coordinates, or supplied filesystem paths.
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
TOOL_NAME = "appfumo-parameterized-verifier-provenance"
TOOL_VERSION = "1.0.0"
MAX_ELF_SIZE = 64 << 20
MAX_MANIFEST_SIZE = 1 << 20
MAX_TOOL_SIZE = 16 << 20
MAX_TOOL_OUTPUT = 192 << 20
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
PT_LOAD = 1

REQUIRED_FDE_ROLES = {
    "verifier": (0x45820, 0x45D75),
    "resource-route": (0x9CBC0, 0x9E260),
    "resource-route-caller": (0xF28E0, 0xF3DDF),
    "navigation-transform": (0x140030, 0x1405DA),
    "command-helper": (0x1397C0, 0x1398FB),
}
REQUIRED_DIRECT_TARGETS = {
    0x45820: (0x7BE3A, 0x80095, 0x802F0, 0x9D1D2, 0x100BB0, 0x140092),
    0x9CBC0: (0xF359E,),
    0x140030: (0x9D4FE,),
    0xF28E0: (),
}
REQUIRED_LITERAL_VAS = {
    "selector-mkbd": 0x2155AD, "selector-amp": 0x2155B8,
    "selector-adp": 0x2155C3, "selector-vess": 0x2155CE,
    "source-tree-mkbd": 0x214A30, "source-tree-amp": 0x214A58,
    "source-tree-adp": 0x214A78, "source-tree-vess": 0x214A98,
    "destination-tree-mkbd": 0x214EA0, "destination-tree-amp": 0x214EC8,
    "destination-tree-adp": 0x214EF0, "destination-tree-vess": 0x214F18,
    "encrypted-suffix": 0x220B31,
    "news-basename": 0x215840, "software-basename": 0x215873,
    "news-destination-template": 0x21584C,
    "news-fallback-destination-template": 0x215861,
    "software-destination-template": 0x21587E,
    "decrypt-command-template": 0x212297,
    "destination-command-template": 0x2122A5,
    "decrypt-helper": 0x20B4D8,
}
REQUIRED_PRODUCER_CLASSES = (
    ("mkbd-resource", "selector-mkbd", "source-tree-mkbd", "destination-tree-mkbd"),
    ("amp-resource", "selector-amp", "source-tree-amp", "destination-tree-amp"),
    ("adp-resource", "selector-adp", "source-tree-adp", "destination-tree-adp"),
    ("vess-resource", "selector-vess", "source-tree-vess", "destination-tree-vess"),
)
REQUIRED_ANCHOR_VAS = {
    0x9CBC0, 0x9CBCA, 0x9CC0B, 0x9CC29, 0x9CC3B, 0x9CC51,
    0x9CE9E, 0x9CEBF, 0x9CEEF, 0x9CF70, 0x9CF97, 0x9D08D, 0x9D0EE, 0x9D0F8,
    0x9D12A, 0x9D14F, 0x9D19E, 0x9D1A8, 0x9D1CF, 0x9D1D2,
    0x9D22E, 0x9D4B4, 0x9D4BE, 0x9D4D5, 0x9D4EA, 0x9D4FB, 0x9D4FE,
    0x9D526, 0x9D543, 0x9D57C, 0x9D634, 0x9D7F9, 0x9D83C,
    0x9D841, 0x9D873, 0x9D896, 0x9D8FE, 0x9DAAB, 0x9DABC, 0x9DADD,
    0x9DB1A, 0x9DDBF, 0x9DDD9, 0x9DDEA, 0x9DE29, 0x9DE43,
    0x9DE54, 0x9DE91, 0x9DEAF, 0x9DEC0,
    0xF28E0, 0xF2B62, 0xF2E04, 0xF2E11, 0xF2E1E, 0xF2F6E,
    0xF2FA5, 0xF2FD2, 0xF3028, 0xF32BC, 0xF32E4, 0xF3597,
    0xF359B, 0xF359E,
    0x140030, 0x140032, 0x14005F, 0x14006F, 0x14007A, 0x14008F,
    0x140092, 0x1400A5, 0x14016C, 0x140189, 0x1401CA, 0x1401EC,
    0x140201, 0x14020F, 0x14023B, 0x14027C, 0x1402DF, 0x1402E4,
    0x1402EC, 0x1402F4, 0x140301, 0x140306, 0x14030E, 0x140311,
    0x1397C0, 0x139867, 0x1398B0,
}


class ProvenanceError(ValueError):
    """The input or evidence falls outside this exact bounded contract."""


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
        if not 0 < phnum <= 256 or phoff + phnum * phentsize > len(data):
            raise ProvenanceError("ELF program-header table is malformed or truncated")
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
        if end > 1 << 64:
            raise ProvenanceError(f"{what} range overflows")
        candidates = [
            item.offset + va - item.vaddr
            for item in self.segments
            if item.vaddr <= va and end <= item.vaddr + item.filesz
        ]
        if len(candidates) != 1:
            raise ProvenanceError(f"{what} range is {'ambiguous' if candidates else 'unmapped'}")
        return candidates[0]

    def bytes_at(self, va: int, size: int, what: str) -> bytes:
        offset = self.map(va, size, what)
        return self.data[offset : offset + size]


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
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if (
        len(raw) != before.st_size
        or any(getattr(before, name) != getattr(after, name) for name in identity)
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


def _load_manifest(path: Path) -> dict[str, Any]:
    raw = _read_regular(path, MAX_MANIFEST_SIZE, "manifest")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError("manifest is not valid UTF-8 JSON") from exc
    top = _object(value, {"schema_version", "artifact", "llvm", "expected"}, "manifest")
    if _integer(top["schema_version"], "schema_version") != SCHEMA_VERSION:
        raise ProvenanceError("unsupported manifest schema version")
    artifact = _object(top["artifact"], {"sha256", "size", "build_id"}, "artifact")
    artifact_out = {
        "sha256": _digest(artifact["sha256"], "artifact.sha256"),
        "size": _integer(artifact["size"], "artifact.size", MAX_ELF_SIZE),
        "build_id": _string(artifact["build_id"], "artifact.build_id", 128),
    }
    if not re.fullmatch(r"[0-9a-f]+", artifact_out["build_id"]):
        raise ProvenanceError("artifact.build_id must be lowercase hexadecimal")
    llvm = _object(top["llvm"], {
        "version", "objdump_size", "objdump_sha256", "readelf_size", "readelf_sha256",
        "instruction_count", "instruction_sha256", "fde_count", "fde_sha256",
    }, "llvm")
    llvm_out = {
        "version": _string(llvm["version"], "llvm.version", 128),
        "objdump_size": _integer(llvm["objdump_size"], "llvm.objdump_size", MAX_TOOL_SIZE),
        "objdump_sha256": _digest(llvm["objdump_sha256"], "llvm.objdump_sha256"),
        "readelf_size": _integer(llvm["readelf_size"], "llvm.readelf_size", MAX_TOOL_SIZE),
        "readelf_sha256": _digest(llvm["readelf_sha256"], "llvm.readelf_sha256"),
        "instruction_count": _integer(llvm["instruction_count"], "llvm.instruction_count", 2_000_000),
        "instruction_sha256": _digest(llvm["instruction_sha256"], "llvm.instruction_sha256"),
        "fde_count": _integer(llvm["fde_count"], "llvm.fde_count", 100_000),
        "fde_sha256": _digest(llvm["fde_sha256"], "llvm.fde_sha256"),
    }
    expected = _load_expected(top["expected"])
    return {
        "artifact": artifact_out,
        "llvm": llvm_out,
        "expected": expected,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _load_expected(value: Any) -> dict[str, Any]:
    obj = _object(value, {"fdes", "direct_calls", "anchors", "literals", "producer_classes"}, "expected")
    fdes = []
    for index, item in enumerate(_array(obj["fdes"], "fdes", 32)):
        row = _object(item, {"role", "start", "end_exclusive"}, f"fde {index}")
        fdes.append({
            "role": _string(row["role"], "fde.role", 64),
            "start": _integer(row["start"], "fde.start"),
            "end_exclusive": _integer(row["end_exclusive"], "fde.end_exclusive"),
        })
    if len(fdes) != len(REQUIRED_FDE_ROLES) or {row["role"]: (row["start"], row["end_exclusive"]) for row in fdes} != REQUIRED_FDE_ROLES:
        raise ProvenanceError("selected FDE role/range set does not match the supported audit")
    direct = []
    for index, item in enumerate(_array(obj["direct_calls"], "direct_calls", 32)):
        row = _object(item, {"target", "call_vas"}, f"direct_calls {index}")
        direct.append({
            "target": _integer(row["target"], "direct target"),
            "call_vas": tuple(_integer(v, "direct call") for v in _array(row["call_vas"], "call_vas", 64)),
        })
    if len(direct) != len(REQUIRED_DIRECT_TARGETS) or {row["target"]: row["call_vas"] for row in direct} != REQUIRED_DIRECT_TARGETS:
        raise ProvenanceError("direct-call expectation set does not match the supported audit")
    anchors = []
    for index, item in enumerate(_array(obj["anchors"], "anchors", 256)):
        row = _object(item, {"va", "mnemonic", "operands"}, f"anchor {index}")
        anchors.append({
            "va": _integer(row["va"], "anchor.va"),
            "mnemonic": _string(row["mnemonic"], "anchor.mnemonic", 32),
            "operands": _string(row["operands"], "anchor.operands", 512),
        })
    if {row["va"] for row in anchors} != REQUIRED_ANCHOR_VAS or len(anchors) != len(REQUIRED_ANCHOR_VAS):
        raise ProvenanceError("machine-anchor address set does not match the supported audit")
    literals = []
    for index, item in enumerate(_array(obj["literals"], "literals", 64)):
        row = _object(item, {"role", "va", "length", "sha256"}, f"literal {index}")
        literals.append({
            "role": _string(row["role"], "literal.role", 64),
            "va": _integer(row["va"], "literal.va"),
            "length": _integer(row["length"], "literal.length", 4096),
            "sha256": _digest(row["sha256"], "literal.sha256"),
        })
    if len(literals) != len(REQUIRED_LITERAL_VAS) or {row["role"]: row["va"] for row in literals} != REQUIRED_LITERAL_VAS:
        raise ProvenanceError("literal role/address set does not match the supported audit")
    classes = []
    for index, item in enumerate(_array(obj["producer_classes"], "producer_classes", 8)):
        row = _object(item, {"name", "selector_role", "source_tree_role", "destination_tree_role"}, f"producer class {index}")
        classes.append({key: _string(row[key], f"producer class {key}", 64) for key in row})
    actual_classes = tuple(
        (row["name"], row["selector_role"], row["source_tree_role"], row["destination_tree_role"])
        for row in classes
    )
    if actual_classes != REQUIRED_PRODUCER_CLASSES:
        raise ProvenanceError("producer class mapping does not match the supported audit")
    return {"fdes": fdes, "direct_calls": direct, "anchors": anchors, "literals": literals, "producer_classes": classes}


def _run_tool(command: list[str], what: str, maximum: int = MAX_TOOL_OUTPUT) -> bytes:
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        raise ProvenanceError(f"cannot run {what}: {exc.strerror}") from exc
    if completed.returncode != 0:
        raise ProvenanceError(f"{what} failed with status {completed.returncode}")
    if len(completed.stdout) > maximum or len(completed.stderr) > 1 << 20:
        raise ProvenanceError(f"{what} output exceeds bound")
    if completed.stderr:
        raise ProvenanceError(f"{what} produced unexpected stderr")
    return completed.stdout


def _validate_tool(path: Path, version: str, size: int, digest: str, what: str) -> None:
    try:
        st = path.stat()
    except OSError as exc:
        raise ProvenanceError(f"cannot stat {what}: {exc.strerror}") from exc
    if not stat.S_ISREG(st.st_mode) or not os.access(path, os.X_OK):
        raise ProvenanceError(f"{what} is not a regular executable")
    raw = _read_regular(path, MAX_TOOL_SIZE, what)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ProvenanceError(f"{what} file identity does not match manifest")
    output = _run_tool([str(path), "--version"], f"{what} version", 1 << 20)
    lines = output.decode("utf-8", "strict").splitlines()
    if not lines or lines[0] != version:
        raise ProvenanceError(f"{what} version identity does not match manifest")


def parse_disassembly(raw: bytes) -> list[Instruction]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProvenanceError("objdump output is not UTF-8") from exc
    result: list[Instruction] = []
    seen: set[int] = set()
    active = False
    line_re = re.compile(r"^\s*([0-9a-f]+):\s+([^\s]+)(?:\s+(.*?))?\s*$")
    malformed_re = re.compile(r"^\s*[0-9a-f]+:")
    for line in text.splitlines():
        if line.startswith("Disassembly of section "):
            active = True
            continue
        match = line_re.match(line)
        if match:
            address = int(match.group(1), 16)
            mnemonic = match.group(2)
            operands = (match.group(3) or "").strip()
            if not re.fullmatch(r"[a-z][a-z0-9.]*", mnemonic):
                raise ProvenanceError("objdump instruction mnemonic is malformed")
            if address in seen:
                raise ProvenanceError("objdump contains a duplicate instruction address")
            seen.add(address)
            result.append(Instruction(address, mnemonic, operands))
        elif active and malformed_re.match(line):
            raise ProvenanceError("objdump contains a malformed or truncated instruction line")
    if not result:
        raise ProvenanceError("objdump contains no decoded instructions")
    if any(a.address >= b.address for a, b in zip(result, result[1:])):
        raise ProvenanceError("objdump instruction addresses are not strictly increasing")
    return result


def parse_fdes(raw: bytes) -> list[tuple[int, int]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProvenanceError("readelf unwind output is not UTF-8") from exc
    pattern = re.compile(
        r"^\s*\[0x[0-9a-f]+\] FDE length=[0-9]+ cie=\[0x[0-9a-f]+\]\n"
        r"\s+initial_location: 0x([0-9a-f]+)\n"
        r"\s+address_range: 0x([0-9a-f]+) \(end : 0x([0-9a-f]+)\)$",
        re.MULTILINE,
    )
    rows: list[tuple[int, int]] = []
    for match in pattern.finditer(text):
        start, size, end = (int(match.group(i), 16) for i in (1, 2, 3))
        if start + size != end or size == 0:
            raise ProvenanceError("readelf contains a malformed FDE range")
        rows.append((start, end))
    if not rows:
        raise ProvenanceError("readelf contains no FDE ranges")
    if len({start for start, _end in rows}) != len(rows):
        raise ProvenanceError("readelf contains duplicate FDE starts")
    rows.sort()
    return rows


def parse_build_id(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProvenanceError("readelf note output is not UTF-8") from exc
    values = re.findall(r"Build ID: ([0-9a-f]+)", text)
    if len(values) != 1:
        raise ProvenanceError("readelf Build ID is absent or ambiguous")
    return values[0]


def _canonical_hash(lines: Iterable[str]) -> str:
    return hashlib.sha256("".join(line + "\n" for line in lines).encode("utf-8")).hexdigest()


def _branch_target(item: Instruction) -> int | None:
    if not item.mnemonic.startswith(("call", "j")):
        return None
    match = re.match(r"0x([0-9a-f]+)(?:\s|$)", item.operands)
    return int(match.group(1), 16) if match else None


def _direct_calls(instructions: list[Instruction], target: int) -> tuple[int, ...]:
    return tuple(item.address for item in instructions if item.mnemonic.startswith("call") and _branch_target(item) == target)


def _writes_rbx(item: Instruction) -> bool:
    operands = item.operands.split("#", 1)[0].strip()
    parts = [part.strip() for part in operands.split(",")] if operands else []
    if not parts:
        return False
    return parts[-1] in ("%rbx", "%ebx", "%bx", "%bl") and item.mnemonic.startswith(("mov", "lea", "pop", "xor", "add", "sub"))


def _validate_semantics(instructions: list[Instruction], expected: dict[str, Any]) -> None:
    by_va = {item.address: item for item in instructions}
    for row in expected["anchors"]:
        actual = by_va.get(row["va"])
        if actual is None or actual.mnemonic != row["mnemonic"] or actual.operands != row["operands"]:
            raise ProvenanceError(f"machine anchor at 0x{row['va']:x} does not match")
    for target, calls in REQUIRED_DIRECT_TARGETS.items():
        if _direct_calls(instructions, target) != calls:
            raise ProvenanceError(f"direct-call inventory drift for target 0x{target:x}")
    ordered = sorted(instructions, key=lambda item: item.address)
    windows = (
        (0x9CE9E, 0x9D1D2, "resource verifier operand"),
        (0x9CE9E, 0x9D4FE, "navigation destination operand"),
    )
    for start, end, what in windows:
        writes = [item.address for item in ordered if start < item.address < end and _writes_rbx(item)]
        if writes:
            raise ProvenanceError(f"{what} RBX provenance is overwritten")
    # These exact stack copies are the pathname-value bindings at the two calls.
    required_pairs = {
        0x9D19E: "0xd0(%rsp), %rax",
        0x9D1A8: "%rax, 0x240(%rsp)",
        0x9D1CF: "%rbx, %rsi",
        0x9D4B4: "0xd0(%rsp), %rax",
        0x9D4BE: "%rax, 0x230(%rsp)",
        0x9D4FB: "%rbp, %rdx",
        0x140032: "%rdx, %rsi",
        0x14006F: "0x55bf0 <.text+0x313c0>",
        0x14008F: "%rbx, %rsi",
        0x140201: "%rbp, %rdx",
    }
    for va, operands in required_pairs.items():
        if by_va[va].operands != operands:
            raise ProvenanceError(f"operand provenance drift at 0x{va:x}")


def analyze(elf_path: Path, objdump_path: Path, readelf_path: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)
    artifact = manifest["artifact"]
    llvm = manifest["llvm"]
    expected = manifest["expected"]
    _validate_tool(objdump_path, llvm["version"], llvm["objdump_size"], llvm["objdump_sha256"], "llvm-objdump")
    _validate_tool(readelf_path, llvm["version"], llvm["readelf_size"], llvm["readelf_sha256"], "llvm-readelf")
    elf_data = _read_regular(elf_path, MAX_ELF_SIZE, "ELF")
    actual_sha = hashlib.sha256(elf_data).hexdigest()
    if len(elf_data) != artifact["size"] or actual_sha != artifact["sha256"]:
        raise ProvenanceError("ELF identity does not match manifest")
    elf = ElfView(elf_data)
    dis_raw = _run_tool([str(objdump_path), "-d", "--no-show-raw-insn", str(elf_path)], "llvm-objdump disassembly")
    instructions = parse_disassembly(dis_raw)
    if len(instructions) != llvm["instruction_count"] or _canonical_hash(item.canonical for item in instructions) != llvm["instruction_sha256"]:
        raise ProvenanceError("complete instruction identity/count does not match manifest")
    unwind_raw = _run_tool([str(readelf_path), "--unwind", str(elf_path)], "llvm-readelf unwind")
    fdes = parse_fdes(unwind_raw)
    if len(fdes) != llvm["fde_count"] or _canonical_hash(f"{start:x}-{end:x}" for start, end in fdes) != llvm["fde_sha256"]:
        raise ProvenanceError("complete FDE identity/count does not match manifest")
    fde_map = dict(fdes)
    for role, (start, end) in REQUIRED_FDE_ROLES.items():
        if fde_map.get(start) != end:
            raise ProvenanceError(f"selected {role} FDE range drift")
    notes_raw = _run_tool([str(readelf_path), "--notes", str(elf_path)], "llvm-readelf notes", 8 << 20)
    if parse_build_id(notes_raw) != artifact["build_id"]:
        raise ProvenanceError("ELF Build ID does not match manifest")
    for row in expected["literals"]:
        raw = elf.bytes_at(row["va"], row["length"] + 1, f"{row['role']} literal")
        if raw[-1:] != b"\0" or b"\0" in raw[:-1] or hashlib.sha256(raw[:-1]).hexdigest() != row["sha256"]:
            raise ProvenanceError(f"{row['role']} literal identity does not match")
    _validate_semantics(instructions, expected)
    classes = [row["name"] for row in expected["producer_classes"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "artifact": {"sha256": actual_sha, "size": len(elf_data), "build_id": artifact["build_id"]},
        "evidence": {
            "llvm_version": llvm["version"],
            "instruction_count": len(instructions),
            "instruction_sha256": llvm["instruction_sha256"],
            "fde_count": len(fdes),
            "fde_sha256": llvm["fde_sha256"],
            "manifest_sha256": manifest["manifest_sha256"],
            "selected_fdes": {role: {"start": f"0x{start:x}", "end_exclusive": f"0x{end:x}"} for role, (start, end) in REQUIRED_FDE_ROLES.items()},
        },
        "call_0x9d1d2": {
            "immediate_function": "0x9cbc0",
            "immediate_direct_callers": ["0xf359e"],
            "caller_direct_callers": [],
            "operand": "absolute pathname of an enumerated encrypted controller-resource member",
            "bounded_producer_classes": classes,
            "can_be_running_or_staged_updater": False,
            "can_be_descriptor": False,
            "can_be_general_firmware_member": False,
            "can_be_controller_resource_member": True,
            "classification": "controller-resource encrypted member",
            "classification_is_pathname_role_only": True,
            "content_type_or_runtime_object_identity": None,
        },
        "call_0x140092": {
            "immediate_function": "0x140030",
            "immediate_direct_callers": ["0x9d4fe"],
            "operand": "QString copy of the source-pathname value supplied at 0x9d1d2",
            "bounded_producer_classes": classes,
            "source_roles": ["encrypted controller resource"],
            "destination_roles": ["derived JSON resource", "derived binary resource"],
            "post_success_transformation": "pathname-based decrypt-helper pipeline to the derived destination",
        },
        "binding": {
            "same_pathname_value_reaches_both_verifiers_and_decrypt_source": True,
            "retained_descriptor_or_open_object": False,
            "pathname_reopened_by_verifier_and_transform": True,
            "destination_exists_or_size_checked": False,
            "transform_status_propagated": False,
            "caller_accepts_nonempty_returned_destination_only": True,
            "authenticated_bytes_bound_to_transformed_bytes": None,
            "transformed_bytes_bound_to_final_consumed_image": None,
        },
        "scope": {
            "exact_static_direct_coverage": True,
            "unbounded_virtual_indirect_cross_process_producers": None,
            "runtime_path_mutation_or_object_substitution": None,
            "authentication_acceptance_proven": False,
            "command_success_proven": False,
            "partition_write_or_boot_acceptance_proven": False,
            "root_or_persistence_proven": False,
            "operator_paths_emitted": False,
            "proprietary_binary_bytes_emitted": False,
        },
    }


def _write_json(value: Any) -> None:
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
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
