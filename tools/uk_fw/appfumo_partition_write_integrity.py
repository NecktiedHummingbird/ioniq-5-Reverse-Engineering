#!/usr/bin/env python3
"""Audit exact-static AppFUMO PartitionUpdater integrity and target selection.

The analyzer is execution-free: it accepts one strict manifest, one exact ELF,
and explicit Homebrew LLVM tools.  Output is normalized JSON and never includes
supplied paths, recovered command text, target pathnames, or proprietary bytes.
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
TOOL_NAME = "appfumo-partition-write-integrity"
TOOL_VERSION = "1.0.0"
MAX_ELF_SIZE = 64 << 20
MAX_MANIFEST_SIZE = 1 << 20
MAX_TOOL_SIZE = 16 << 20
MAX_TOOL_OUTPUT = 192 << 20
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
PT_LOAD = 1

REQUIRED_FDE_ROLES = {
    "active-partition-name": (0xA0E10, 0xA14B2),
    "inactive-partition-name": (0xA14C0, 0xA1B64),
    "partition-map-population": (0xA1B70, 0xA247E),
    "primary-image-selector": (0xA2480, 0xA2C17),
    "partition-record-lookup": (0xBFB20, 0xBFE67),
    "partition-updater-constructor": (0xC0130, 0xC0518),
    "source-integrity-gate": (0xC1FF0, 0xC255D),
    "partition-write-starter": (0xC53D0, 0xCC479),
    "process-counter": (0xCC480, 0xCC6B4),
    "post-hash-write-starter": (0xCD560, 0xCD637),
    "slot-hash-check": (0xCD640, 0xCE067),
    "mode-orchestrator": (0xCE070, 0xCE217),
    "process-completion-handler": (0xCF9B0, 0xD0C79),
    "fstab-state-update": (0xD0C80, 0xD1E6C),
    "finalization": (0xD1E70, 0xD327F),
    "public-key-source-verifier": (0x45D80, 0x461E8),
    "signed-trailer-parser": (0x18E520, 0x18E9EE),
    "record-key-verification": (0x18F5A0, 0x18F6FC),
    "process-thread-starter": (0x145250, 0x1458BD),
    "partition-updater-meta-dispatch": (0x16B910, 0x16BAC6),
}

# Calls and tail/direct jumps are deliberately separate.  This is a complete
# whole-instruction inventory for each target, not just a selected-FDE scan.
REQUIRED_DIRECT_TRANSFERS = {
    0x45820: ((0x7BE3A, 0x80095, 0x802F0, 0x9D1D2, 0x100BB0, 0x140092), ()),
    0x45D80: ((0x5C21B, 0xC22EB), ()),
    0x18F700: ((0x45F68, 0x4B4EE, 0x18F797), ()),
    0x140F50: ((0x1432F6, 0x15170C), ()),
    0xA0E10: ((0xB1A4E, 0xD0DBF, 0xD0F0C), ()),
    0xA14C0: ((0xA1C2A, 0xA1D07, 0xA1DE3, 0xA1EE6, 0xA1FDA, 0xA20CE,
               0xB2971, 0xD0DFB, 0xD0F48, 0xD1F47), ()),
    0xA1B70: ((0xA075B,), ()),
    0xA2480: ((0xA30B5, 0xA9951, 0xCD692, 0x148FA2), ()),
    0xBFB20: ((0xC54CA,), ()),
    0xC1FF0: ((0xCD6FA, 0xCDBAE), ()),
    0xC53D0: ((0xCC646,), (0xCD5DB, 0xCE110)),
    0xCC480: ((0xCFA2E,), (0x16B9E0,)),
    0xCD560: ((0xCDEA7,), ()),
    0xCD640: ((), (0x16BA9C,)),
    0xCE070: ((), ()),
    0xCF9B0: ((), (0x16BA28,)),
    0xD0C80: ((0xD2400,), ()),
    0xD1E70: ((), ()),
}

REQUIRED_ANCHOR_VAS = {
    0x45D82, 0x45DB7, 0x45EA4, 0x45F68,
    0xA1509, 0xA1518, 0xA1C2A, 0xA1C7C, 0xA1D07, 0xA1D57,
    0xA1DE3, 0xA1E39, 0xA1EE6, 0xA1F44, 0xA1FDA, 0xA2038,
    0xA20CE, 0xA212C, 0xA24AF, 0xA2593,
    0xBFB73, 0xBFBE3, 0xBFD27, 0xBFD90,
    0xC0155, 0xC018E, 0xC01B5, 0xC01D3, 0xC0339, 0xC036D,
    0xC20A7, 0xC20B2, 0xC2150, 0xC22EB, 0xC2307,
    0xC5421, 0xC543A, 0xC54CA, 0xC5637, 0xC564B, 0xC57AF, 0xC57BC,
    0xC67CC, 0xC683B, 0xC684F, 0xC6C69, 0xC7400, 0xC7423,
    0xCD5DB, 0xCD692, 0xCD6FA, 0xCD709, 0xCDB76, 0xCDB7E,
    0xCDBA8, 0xCDBAE, 0xCDBD7, 0xCDBDA, 0xCDEA7,
    0xCE09B, 0xCE110, 0xCE134, 0xCFA2E,
    0xD2400, 0xD2514, 0xD2541, 0xD2920, 0x16BA9C,
    0x18E5A5, 0x18E5AD, 0x18E5FD, 0x18E610, 0x18E680, 0x18E686,
    0x18E68A, 0x18E68C, 0x18E69A, 0x18F610, 0x18F66E,
}

REQUIRED_LITERAL_VAS = {
    "public-key-directory": 0x209D43,
    "public-key-basename": 0x209D5A,
    "mode-marker": 0x2119F0,
    "integrity-slot-signature": 0x21A9E0,
    "integrity-signal-signature": 0x21AA20,
    "primary-selector-0": 0x2163A0,
    "primary-selector-1": 0x2163A9,
    "primary-selector-2": 0x2163B7,
    "primary-selector-3": 0x2163C8,
    "primary-selector-4": 0x2163D4,
    "primary-selector-5": 0x2163E5,
    "primary-selector-6": 0x2163F9,
    "primary-selector-7": 0x216405,
    "primary-selector-8": 0x216416,
}
REQUIRED_BLOB_VAS = {
    "static-partition-map": (0x6C51A0, 0xA0),
    "mode-byte-initializer": (0x6D20B4, 1),
}
POST_WRITE_RANGES = (
    (0xCF9B0, 0xD0C79),
    (0xD0C80, 0xD1E6C),
    (0xD1E70, 0xD327F),
)
KNOWN_CRYPTO_FILE_TARGETS = {0x45820, 0x45D80, 0x18F700, 0x140F50, 0xC1FF0}


class IntegrityError(ValueError):
    """Input or evidence is outside the exact bounded contract."""


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
            raise IntegrityError("ELF header is truncated")
        fields = ELF_HEADER.unpack_from(data)
        ident = fields[0]
        if ident[:4] != b"\x7fELF" or ident[4:7] != bytes((2, 1, 1)):
            raise IntegrityError("unsupported ELF identity")
        if fields[1] not in (2, 3) or fields[2] != 62 or fields[3] != 1:
            raise IntegrityError("unsupported ELF ABI")
        phoff, ehsize, phentsize, phnum = fields[5], fields[8], fields[9], fields[10]
        if ehsize != ELF_HEADER.size or phentsize != PROGRAM_HEADER.size:
            raise IntegrityError("unsupported ELF header layout")
        if not 0 < phnum <= 256 or phoff + phnum * phentsize > len(data):
            raise IntegrityError("ELF program-header table is malformed or truncated")
        segments: list[Segment] = []
        for index in range(phnum):
            row = PROGRAM_HEADER.unpack_from(data, phoff + index * phentsize)
            if row[0] != PT_LOAD:
                continue
            offset, vaddr, filesz, memsz = row[2], row[3], row[5], row[6]
            if filesz > memsz or offset + filesz > len(data):
                raise IntegrityError("ELF PT_LOAD range is malformed")
            segments.append(Segment(offset, vaddr, filesz))
        if not segments:
            raise IntegrityError("ELF has no file-backed PT_LOAD segment")
        self.segments = segments

    def map(self, va: int, size: int, what: str) -> int:
        if type(va) is not int or type(size) is not int or va < 0 or size < 0:
            raise IntegrityError(f"{what} range is invalid")
        end = va + size
        if end > 1 << 64:
            raise IntegrityError(f"{what} range overflows")
        candidates = [
            item.offset + va - item.vaddr
            for item in self.segments
            if item.vaddr <= va and end <= item.vaddr + item.filesz
        ]
        if len(candidates) != 1:
            raise IntegrityError(f"{what} range is {'ambiguous' if candidates else 'unmapped'}")
        return candidates[0]

    def bytes_at(self, va: int, size: int, what: str) -> bytes:
        offset = self.map(va, size, what)
        return self.data[offset:offset + size]


def _read_regular(path: Path, maximum: int, what: str) -> bytes:
    try:
        before = path.stat()
    except OSError as exc:
        raise IntegrityError(f"cannot stat {what}: {exc.strerror}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise IntegrityError(f"{what} is not a regular file")
    if before.st_size > maximum:
        raise IntegrityError(f"{what} exceeds the size limit")
    try:
        with path.open("rb") as handle:
            raw = handle.read(before.st_size + 1)
    except OSError as exc:
        raise IntegrityError(f"cannot read {what}: {exc.strerror}") from exc
    try:
        after = path.stat()
    except OSError as exc:
        raise IntegrityError(f"cannot restat {what}: {exc.strerror}") from exc
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if (len(raw) != before.st_size
            or any(getattr(before, key) != getattr(after, key) for key in identity)
            or not stat.S_ISREG(after.st_mode)):
        raise IntegrityError(f"{what} changed while being read")
    return raw


def _object(value: Any, keys: Iterable[str], what: str) -> dict[str, Any]:
    expected = set(keys)
    if type(value) is not dict:
        raise IntegrityError(f"{what} must be an object")
    actual = set(value)
    if actual != expected:
        raise IntegrityError(
            f"{what} keys mismatch: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}"
        )
    return value


def _array(value: Any, what: str, maximum: int = 4096) -> list[Any]:
    if type(value) is not list or len(value) > maximum:
        raise IntegrityError(f"{what} must be a bounded array")
    return value


def _integer(value: Any, what: str, maximum: int = (1 << 64) - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise IntegrityError(f"{what} must be a bounded non-Boolean integer")
    return value


def _string(value: Any, what: str, maximum: int = 4096) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise IntegrityError(f"{what} must be a bounded non-empty string")
    return value


def _digest(value: Any, what: str) -> str:
    text = _string(value, what, 64)
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise IntegrityError(f"{what} must be lowercase SHA-256")
    return text


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IntegrityError(f"manifest contains duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_manifest(path: Path) -> dict[str, Any]:
    raw = _read_regular(path, MAX_MANIFEST_SIZE, "manifest")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("manifest is not valid UTF-8 JSON") from exc
    top = _object(value, {"schema_version", "artifact", "llvm", "expected"}, "manifest")
    if _integer(top["schema_version"], "schema_version") != SCHEMA_VERSION:
        raise IntegrityError("unsupported manifest schema version")
    artifact = _object(top["artifact"], {"sha256", "size", "build_id"}, "artifact")
    artifact_out = {
        "sha256": _digest(artifact["sha256"], "artifact.sha256"),
        "size": _integer(artifact["size"], "artifact.size", MAX_ELF_SIZE),
        "build_id": _string(artifact["build_id"], "artifact.build_id", 128),
    }
    if not re.fullmatch(r"[0-9a-f]+", artifact_out["build_id"]):
        raise IntegrityError("artifact.build_id must be lowercase hexadecimal")
    llvm_obj = _object(top["llvm"], {
        "version", "objdump_size", "objdump_sha256", "readelf_size", "readelf_sha256",
        "instruction_count", "instruction_sha256", "fde_count", "fde_sha256",
    }, "llvm")
    llvm = {
        "version": _string(llvm_obj["version"], "llvm.version", 128),
        "objdump_size": _integer(llvm_obj["objdump_size"], "llvm.objdump_size", MAX_TOOL_SIZE),
        "objdump_sha256": _digest(llvm_obj["objdump_sha256"], "llvm.objdump_sha256"),
        "readelf_size": _integer(llvm_obj["readelf_size"], "llvm.readelf_size", MAX_TOOL_SIZE),
        "readelf_sha256": _digest(llvm_obj["readelf_sha256"], "llvm.readelf_sha256"),
        "instruction_count": _integer(llvm_obj["instruction_count"], "llvm.instruction_count", 2_000_000),
        "instruction_sha256": _digest(llvm_obj["instruction_sha256"], "llvm.instruction_sha256"),
        "fde_count": _integer(llvm_obj["fde_count"], "llvm.fde_count", 100_000),
        "fde_sha256": _digest(llvm_obj["fde_sha256"], "llvm.fde_sha256"),
    }
    expected = _load_expected(top["expected"])
    return {"artifact": artifact_out, "llvm": llvm, "expected": expected,
            "manifest_sha256": hashlib.sha256(raw).hexdigest()}


def _load_expected(value: Any) -> dict[str, Any]:
    obj = _object(value, {"fdes", "direct_transfers", "anchors", "literals", "blobs"}, "expected")
    fdes = []
    for index, item in enumerate(_array(obj["fdes"], "fdes", 64)):
        row = _object(item, {"role", "start", "end_exclusive"}, f"fde {index}")
        fdes.append({"role": _string(row["role"], "fde.role", 80),
                     "start": _integer(row["start"], "fde.start"),
                     "end_exclusive": _integer(row["end_exclusive"], "fde.end_exclusive")})
    if len(fdes) != len(REQUIRED_FDE_ROLES) or {
        row["role"]: (row["start"], row["end_exclusive"]) for row in fdes
    } != REQUIRED_FDE_ROLES:
        raise IntegrityError("selected FDE role/range set does not match the supported audit")
    transfers = []
    for index, item in enumerate(_array(obj["direct_transfers"], "direct_transfers", 64)):
        row = _object(item, {"target", "call_vas", "jump_vas"}, f"direct transfer {index}")
        transfers.append({
            "target": _integer(row["target"], "direct target"),
            "call_vas": tuple(_integer(v, "call VA") for v in _array(row["call_vas"], "call_vas", 128)),
            "jump_vas": tuple(_integer(v, "jump VA") for v in _array(row["jump_vas"], "jump_vas", 128)),
        })
    actual_transfers = {row["target"]: (row["call_vas"], row["jump_vas"]) for row in transfers}
    if len(transfers) != len(REQUIRED_DIRECT_TRANSFERS) or actual_transfers != REQUIRED_DIRECT_TRANSFERS:
        raise IntegrityError("direct-transfer expectation set does not match the supported audit")
    anchors = []
    for index, item in enumerate(_array(obj["anchors"], "anchors", 256)):
        row = _object(item, {"va", "mnemonic", "operands"}, f"anchor {index}")
        anchors.append({"va": _integer(row["va"], "anchor.va"),
                        "mnemonic": _string(row["mnemonic"], "anchor.mnemonic", 32),
                        "operands": _string(row["operands"], "anchor.operands", 512)})
    if len(anchors) != len(REQUIRED_ANCHOR_VAS) or {row["va"] for row in anchors} != REQUIRED_ANCHOR_VAS:
        raise IntegrityError("machine-anchor address set does not match the supported audit")
    literals = []
    for index, item in enumerate(_array(obj["literals"], "literals", 64)):
        row = _object(item, {"role", "va", "length", "sha256"}, f"literal {index}")
        literals.append({"role": _string(row["role"], "literal.role", 80),
                         "va": _integer(row["va"], "literal.va"),
                         "length": _integer(row["length"], "literal.length", 4096),
                         "sha256": _digest(row["sha256"], "literal.sha256")})
    if len(literals) != len(REQUIRED_LITERAL_VAS) or {row["role"]: row["va"] for row in literals} != REQUIRED_LITERAL_VAS:
        raise IntegrityError("literal role/address set does not match the supported audit")
    blobs = []
    for index, item in enumerate(_array(obj["blobs"], "blobs", 16)):
        row = _object(item, {"role", "va", "length", "sha256"}, f"blob {index}")
        blobs.append({"role": _string(row["role"], "blob.role", 80),
                      "va": _integer(row["va"], "blob.va"),
                      "length": _integer(row["length"], "blob.length", 4096),
                      "sha256": _digest(row["sha256"], "blob.sha256")})
    if len(blobs) != len(REQUIRED_BLOB_VAS) or {
        row["role"]: (row["va"], row["length"]) for row in blobs
    } != REQUIRED_BLOB_VAS:
        raise IntegrityError("blob role/range set does not match the supported audit")
    return {"fdes": fdes, "direct_transfers": transfers, "anchors": anchors,
            "literals": literals, "blobs": blobs}


def _run_tool(command: list[str], what: str, maximum: int = MAX_TOOL_OUTPUT) -> bytes:
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        raise IntegrityError(f"cannot run {what}: {exc.strerror}") from exc
    if completed.returncode != 0:
        raise IntegrityError(f"{what} failed with status {completed.returncode}")
    if len(completed.stdout) > maximum or len(completed.stderr) > 1 << 20:
        raise IntegrityError(f"{what} output exceeds bound")
    if completed.stderr:
        raise IntegrityError(f"{what} produced unexpected stderr")
    return completed.stdout


def _validate_tool(path: Path, version: str, size: int, digest: str, what: str) -> None:
    try:
        st = path.stat()
    except OSError as exc:
        raise IntegrityError(f"cannot stat {what}: {exc.strerror}") from exc
    if not stat.S_ISREG(st.st_mode) or not os.access(path, os.X_OK):
        raise IntegrityError(f"{what} is not a regular executable")
    raw = _read_regular(path, MAX_TOOL_SIZE, what)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise IntegrityError(f"{what} file identity does not match manifest")
    lines = _run_tool([str(path), "--version"], f"{what} version", 1 << 20).decode("utf-8", "strict").splitlines()
    if not lines or lines[0] != version:
        raise IntegrityError(f"{what} version identity does not match manifest")


def parse_disassembly(raw: bytes) -> list[Instruction]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrityError("objdump output is not UTF-8") from exc
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
                raise IntegrityError("objdump instruction mnemonic is malformed")
            if address in seen:
                raise IntegrityError("objdump contains a duplicate instruction address")
            seen.add(address)
            result.append(Instruction(address, mnemonic, operands))
        elif active and malformed_re.match(line):
            raise IntegrityError("objdump contains a malformed or truncated instruction line")
    if not result:
        raise IntegrityError("objdump contains no decoded instructions")
    if any(left.address >= right.address for left, right in zip(result, result[1:])):
        raise IntegrityError("objdump instruction addresses are not strictly increasing")
    return result


def parse_fdes(raw: bytes) -> list[tuple[int, int]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrityError("readelf unwind output is not UTF-8") from exc
    pattern = re.compile(
        r"^\s*\[0x[0-9a-f]+\] FDE length=[0-9]+ cie=\[0x[0-9a-f]+\]\n"
        r"\s+initial_location: 0x([0-9a-f]+)\n"
        r"\s+address_range: 0x([0-9a-f]+) \(end : 0x([0-9a-f]+)\)$", re.MULTILINE)
    matches = list(pattern.finditer(text))
    fde_headers = re.findall(r"^\s*\[0x[0-9a-f]+\] FDE length=", text, re.MULTILINE)
    if len(fde_headers) != len(matches):
        raise IntegrityError("readelf contains a malformed or truncated FDE record")
    rows: list[tuple[int, int]] = []
    for match in matches:
        start, size, end = (int(match.group(i), 16) for i in (1, 2, 3))
        if size == 0 or start + size != end:
            raise IntegrityError("readelf contains a malformed FDE range")
        rows.append((start, end))
    if not rows:
        raise IntegrityError("readelf contains no FDE ranges")
    if len({start for start, _ in rows}) != len(rows):
        raise IntegrityError("readelf contains duplicate FDE starts")
    rows.sort()
    return rows


def parse_build_id(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrityError("readelf note output is not UTF-8") from exc
    values = re.findall(r"Build ID: ([0-9a-f]+)", text)
    if len(values) != 1:
        raise IntegrityError("readelf Build ID is absent or ambiguous")
    return values[0]


def _canonical_hash(lines: Iterable[str]) -> str:
    return hashlib.sha256("".join(line + "\n" for line in lines).encode("utf-8")).hexdigest()


def _branch_target(item: Instruction) -> int | None:
    if not item.mnemonic.startswith(("call", "j")):
        return None
    match = re.match(r"0x([0-9a-f]+)(?:\s|$)", item.operands)
    return int(match.group(1), 16) if match else None


def _transfers(instructions: list[Instruction], target: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    calls = tuple(item.address for item in instructions
                  if item.mnemonic.startswith("call") and _branch_target(item) == target)
    jumps = tuple(item.address for item in instructions
                  if item.mnemonic.startswith("j") and _branch_target(item) == target)
    return calls, jumps


def _validate_semantics(instructions: list[Instruction], expected: dict[str, Any]) -> None:
    by_va = {item.address: item for item in instructions}
    for row in expected["anchors"]:
        actual = by_va.get(row["va"])
        if actual is None or actual.mnemonic != row["mnemonic"] or actual.operands != row["operands"]:
            raise IntegrityError(f"machine anchor at 0x{row['va']:x} does not match")
    for target, transfers in REQUIRED_DIRECT_TRANSFERS.items():
        if _transfers(instructions, target) != transfers:
            raise IntegrityError(f"direct-transfer inventory drift for target 0x{target:x}")
    # The process-completion/fstab/finalization FDEs contain no direct edge to
    # the reviewed signature/hash helpers.  This negative is bounded to these
    # exact ranges and these complete direct target inventories.
    for item in instructions:
        if any(start <= item.address < end for start, end in POST_WRITE_RANGES):
            if item.mnemonic.startswith(("call", "j")) and _branch_target(item) in KNOWN_CRYPTO_FILE_TARGETS:
                raise IntegrityError("post-write reviewed route gained a direct cryptographic-file edge")
    # Exact mismatch gates: both verifier calls must return zero before their
    # respective continuation blocks; nonzero takes the failure paths.
    required = {
        0xCD709: ("testl", "%ebp, %ebp"),
        0xCD70B: ("jne", "0xcda20 <.text+0xa91f0>"),
        0xCDBD7: ("testl", "%r13d, %r13d"),
        0xCDBDA: ("je", "0xcd788 <.text+0xa8f58>"),
        0xCE09B: ("cmpb", "$0x0, 0x604012(%rip)    # 0x6d20b4"),
        0xCE110: ("jmp", "0xc53d0 <.text+0xa0ba0>"),
        0xCE134: ("jmp", "0x16b850 <.text+0x147020>"),
        0x16BA9C: ("jmp", "0xcd640 <.text+0xa8e10>"),
    }
    for va, pair in required.items():
        item = by_va.get(va)
        if item is None or (item.mnemonic, item.operands) != pair:
            raise IntegrityError(f"control-flow provenance drift at 0x{va:x}")


def analyze(elf_path: Path, objdump_path: Path, readelf_path: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)
    artifact, llvm, expected = manifest["artifact"], manifest["llvm"], manifest["expected"]
    _validate_tool(objdump_path, llvm["version"], llvm["objdump_size"], llvm["objdump_sha256"], "llvm-objdump")
    _validate_tool(readelf_path, llvm["version"], llvm["readelf_size"], llvm["readelf_sha256"], "llvm-readelf")
    elf_data = _read_regular(elf_path, MAX_ELF_SIZE, "ELF")
    actual_sha = hashlib.sha256(elf_data).hexdigest()
    if len(elf_data) != artifact["size"] or actual_sha != artifact["sha256"]:
        raise IntegrityError("ELF identity does not match manifest")
    elf = ElfView(elf_data)
    dis_raw = _run_tool([str(objdump_path), "-d", "--no-show-raw-insn", str(elf_path)], "llvm-objdump disassembly")
    instructions = parse_disassembly(dis_raw)
    if (len(instructions) != llvm["instruction_count"]
            or _canonical_hash(item.canonical for item in instructions) != llvm["instruction_sha256"]):
        raise IntegrityError("complete instruction identity/count does not match manifest")
    unwind_raw = _run_tool([str(readelf_path), "--unwind", str(elf_path)], "llvm-readelf unwind")
    fdes = parse_fdes(unwind_raw)
    if (len(fdes) != llvm["fde_count"]
            or _canonical_hash(f"{start:x}-{end:x}" for start, end in fdes) != llvm["fde_sha256"]):
        raise IntegrityError("complete FDE identity/count does not match manifest")
    fde_map = dict(fdes)
    for role, (start, end) in REQUIRED_FDE_ROLES.items():
        if fde_map.get(start) != end:
            raise IntegrityError(f"selected {role} FDE range drift")
    notes_raw = _run_tool([str(readelf_path), "--notes", str(elf_path)], "llvm-readelf notes", 8 << 20)
    if parse_build_id(notes_raw) != artifact["build_id"]:
        raise IntegrityError("ELF Build ID does not match manifest")
    for row in expected["literals"]:
        raw = elf.bytes_at(row["va"], row["length"] + 1, f"{row['role']} literal")
        if raw[-1:] != b"\0" or b"\0" in raw[:-1] or hashlib.sha256(raw[:-1]).hexdigest() != row["sha256"]:
            raise IntegrityError(f"{row['role']} literal identity does not match")
    for row in expected["blobs"]:
        raw = elf.bytes_at(row["va"], row["length"], f"{row['role']} blob")
        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise IntegrityError(f"{row['role']} blob identity does not match")
    _validate_semantics(instructions, expected)
    # Re-read every supplied input after all tool runs so persistent identity
    # changes cannot be hidden behind the identities validated at entry.
    if _read_regular(elf_path, MAX_ELF_SIZE, "ELF") != elf_data:
        raise IntegrityError("ELF changed during analysis")
    if hashlib.sha256(_read_regular(manifest_path, MAX_MANIFEST_SIZE, "manifest")).hexdigest() != manifest["manifest_sha256"]:
        raise IntegrityError("manifest changed during analysis")
    for path, size, digest, what in (
        (objdump_path, llvm["objdump_size"], llvm["objdump_sha256"], "llvm-objdump"),
        (readelf_path, llvm["readelf_size"], llvm["readelf_sha256"], "llvm-readelf"),
    ):
        raw = _read_regular(path, MAX_TOOL_SIZE, what)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise IntegrityError(f"{what} changed during analysis")
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
            "selected_fdes": {role: {"start": f"0x{start:x}", "end_exclusive": f"0x{end:x}"}
                               for role, (start, end) in REQUIRED_FDE_ROLES.items()},
            "direct_transfers": {f"0x{target:x}": {
                "calls": [f"0x{va:x}" for va in calls],
                "jumps": [f"0x{va:x}" for va in jumps],
            } for target, (calls, jumps) in REQUIRED_DIRECT_TRANSFERS.items()},
        },
        "pre_write_integrity": {
            "hash_gated_mode": "nonzero mode byte dispatches the asynchronous source-integrity route",
            "non_hash_mode": "zero mode byte reaches the write starter directly",
            "selected_primary_source_verified_when_primary_candidate_is_present": True,
            "eligible_nonexcluded_entry_source_paths_verified": True,
            "both_source_verifier_results_must_equal_zero": True,
            "mismatch_reaches_write_starter": False,
            "fixed_public_key_identity_bound_by_literal_hashes": True,
            "signed_trailer_size": 0x4024,
            "accepted_three_byte_trailer_families": ["family-1", "family-2"],
            "exact_signed_byte_ranges": None,
            "digest_algorithm_for_this_route": None,
            "rsa_padding_or_signature_encoding": None,
        },
        "source_binding": {
            "record_source_path_field_offset": "0x10",
            "same_stored_qstring_pathname_value_reaches_verifier_and_writer": True,
            "retained_file_descriptor_or_open_object": False,
            "verifier_and_writer_reopen_pathname_independently": True,
            "same_source_object_identity": None,
            "same_source_byte_identity": None,
            "source_package_integrity_bound_to_transformed_final_partition_bytes": None,
        },
        "target_selection": {
            "static_partition_map_bound": True,
            "active_and_inactive_name_helpers_bound": True,
            "selected_record_name_field_offset": "0x20",
            "writer_target_field_offset": "0x28",
            "record_lookup_precedes_writer_start": True,
            "inactive_helper_output_to_exact_runtime_record_instance": None,
            "normalized_inactive_target_selection": "present",
            "bootloader_slot_activation": None,
            "bootloader_mark_good": None,
        },
        "write_and_completion": {
            "image_backed_and_clone_branches_are_distinct": True,
            "process_completion_handler_bound": True,
            "process_completion_is_cryptographic_readback": False,
            "same_source_verifier_directly_reinvoked_post_write": False,
            "known_file_signature_or_hash_helpers_directly_called_in_reviewed_post_write_fdes": False,
            "bounded_post_write_fdes": ["process-completion-handler", "fstab-state-update", "finalization"],
            "all_indirect_external_or_inlined_destination_verification_absent": None,
            "final_partition_byte_identity": None,
        },
        "scope": {
            "exact_static_direct_coverage": True,
            "dynamic_signal_invocation_complete": False,
            "installed_runtime_identity_or_reachability": None,
            "update_acceptance": None,
            "partition_write_success": None,
            "slot_change": None,
            "boot_acceptance": None,
            "root": None,
            "persistence": None,
            "operator_paths_emitted": False,
            "target_pathnames_or_commands_emitted": False,
            "proprietary_binary_bytes_emitted": False,
        },
    }


def _write_json(value: Any) -> None:
    sys.stdout.buffer.write((json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--llvm-objdump", required=True, type=Path)
    parser.add_argument("--llvm-readelf", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = analyze(args.elf, args.llvm_objdump, args.llvm_readelf, args.manifest)
    except IntegrityError as exc:
        sys.stderr.buffer.write((f"error: {exc}\n").encode("utf-8"))
        return 2
    _write_json(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
