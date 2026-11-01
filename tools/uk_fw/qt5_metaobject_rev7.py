#!/usr/bin/env python3
"""Decode one explicitly selected Qt 5 revision-7 local meta-method.

This is a bounded, read-only ELF decoder.  It never searches for meta-objects,
loads target code, or invokes a recovered method.  Machine-code forwarding may
only be reported from a separately supplied, schema-checked evidence manifest;
the metadata decoder itself does not establish forwarding or producer provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2
TOOL_VERSION = "1.1.0"
TOOL_NAME = "qt5-metaobject-rev7"

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
QBYTEARRAYDATA = struct.Struct("<iiIIq")
UINT32 = struct.Struct("<I")
PT_LOAD = 1
EM_X86_64 = 62
ET_EXEC = 2
ET_DYN = 3
MAX_FILE_SIZE = 1 << 30
MAX_MANIFEST_SIZE = 1 << 16
MAX_EVIDENCE_EXCERPT_SIZE = 1 << 20
MAX_PROGRAM_HEADERS = 256
MAX_METHODS = 16384
MAX_AUX_COUNT = 1 << 20
MAX_ARGUMENTS = 1024
MAX_STRING_RECORDS = 1 << 20
MAX_STRING_BYTES = 1 << 20
U64_MAX = (1 << 64) - 1
UNRESOLVED_TYPE = 0x80000000

# Qt 5 QMetaType::Type values needed by revision-7 moc data. Unknown numeric
# values fail closed rather than being presented as a decoded type.
BUILTIN_TYPES = {
    0: "UnknownType",
    1: "bool",
    2: "int",
    3: "uint",
    4: "qlonglong",
    5: "qulonglong",
    6: "double",
    7: "QChar",
    8: "QVariantMap",
    9: "QVariantList",
    10: "QString",
    11: "QStringList",
    12: "QByteArray",
    13: "QBitArray",
    14: "QDate",
    15: "QTime",
    16: "QDateTime",
    17: "QUrl",
    18: "QLocale",
    19: "QRect",
    20: "QRectF",
    21: "QSize",
    22: "QSizeF",
    23: "QLine",
    24: "QLineF",
    25: "QPoint",
    26: "QPointF",
    27: "QRegExp",
    28: "QVariantHash",
    29: "QEasingCurve",
    30: "QUuid",
    31: "void*",
    32: "long",
    33: "short",
    34: "char",
    35: "ulong",
    36: "ushort",
    37: "uchar",
    38: "float",
    39: "QObject*",
    40: "signed char",
    41: "QVariant",
    42: "QModelIndex",
    43: "void",
    44: "QRegularExpression",
    45: "QJsonValue",
    46: "QJsonObject",
    47: "QJsonArray",
    48: "QJsonDocument",
}

HEADER_NAMES = (
    "revision",
    "class_name_string_index",
    "classinfo_count",
    "classinfo_word_offset",
    "method_count",
    "method_table_word_offset",
    "property_count",
    "property_word_offset",
    "enum_count",
    "enum_word_offset",
    "constructor_count",
    "constructor_word_offset",
    "flags",
    "signal_count",
)


class DecodeError(ValueError):
    """The selected input cannot be decoded under the supported contract."""


@dataclass(frozen=True)
class LoadSegment:
    offset: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass(frozen=True)
class MetadataInterval:
    label: str
    start: int
    end: int

    def overlaps(self, other: "MetadataInterval") -> bool:
        return self.start < other.end and other.start < self.end


class ElfView:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < ELF_HEADER.size:
            raise DecodeError("ELF header is truncated")
        fields = ELF_HEADER.unpack_from(data)
        ident = fields[0]
        if ident[:4] != b"\x7fELF":
            raise DecodeError("input is not ELF")
        if ident[4] != 2:
            raise DecodeError("unsupported ELF class (expected ELF64)")
        if ident[5] != 1:
            raise DecodeError("unsupported ELF endianness (expected little-endian)")
        if ident[6] != 1 or fields[3] != 1:
            raise DecodeError("unsupported ELF version")
        elf_type, machine = fields[1], fields[2]
        if elf_type not in (ET_EXEC, ET_DYN):
            raise DecodeError("unsupported ELF type")
        if machine != EM_X86_64:
            raise DecodeError("unsupported ELF machine (expected x86-64)")
        phoff, ehsize, phentsize, phnum = fields[5], fields[8], fields[9], fields[10]
        if ehsize != ELF_HEADER.size:
            raise DecodeError("unsupported ELF64 header size")
        if phentsize != PROGRAM_HEADER.size:
            raise DecodeError("unsupported program-header ABI")
        if phnum == 0 or phnum > MAX_PROGRAM_HEADERS:
            raise DecodeError("program-header count is unsupported or unbounded")
        ph_end = _checked_add(phoff, phnum * phentsize, "program-header table")
        if ph_end > len(data):
            raise DecodeError("program-header table is outside the file")

        loads: list[LoadSegment] = []
        for index in range(phnum):
            row = PROGRAM_HEADER.unpack_from(data, phoff + index * phentsize)
            p_type, p_offset, p_vaddr, p_filesz, p_memsz = row[0], row[2], row[3], row[5], row[6]
            if p_type != PT_LOAD:
                continue
            if p_filesz > p_memsz:
                raise DecodeError("PT_LOAD file size exceeds memory size")
            file_end = _checked_add(p_offset, p_filesz, "PT_LOAD file range")
            _checked_add(p_vaddr, p_memsz, "PT_LOAD virtual range")
            if file_end > len(data):
                raise DecodeError("PT_LOAD file range is outside the file")
            loads.append(LoadSegment(p_offset, p_vaddr, p_filesz, p_memsz))
        if not loads:
            raise DecodeError("ELF has no PT_LOAD segment")
        self.loads = loads

    def map_range(self, va: int, size: int, what: str) -> int:
        end = _checked_add(va, size, what)
        candidates: list[int] = []
        for segment in self.loads:
            seg_end = segment.vaddr + segment.filesz
            if va >= segment.vaddr and end <= seg_end:
                candidates.append(segment.offset + (va - segment.vaddr))
        if not candidates:
            raise DecodeError(f"{what} is not in a file-backed PT_LOAD range")
        if len(candidates) != 1:
            raise DecodeError(f"{what} has ambiguous PT_LOAD mappings")
        offset = candidates[0]
        if offset + size > len(self.data):
            raise DecodeError(f"{what} exceeds the input file")
        return offset

    def read(self, va: int, size: int, what: str) -> tuple[int, bytes]:
        offset = self.map_range(va, size, what)
        return offset, self.data[offset : offset + size]


def _checked_add(start: int, size: int, what: str) -> int:
    if not isinstance(start, int) or isinstance(start, bool) or start < 0 or start > U64_MAX:
        raise DecodeError(f"{what} start is outside uint64")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > U64_MAX - start:
        raise DecodeError(f"{what} overflows uint64")
    return start + size


def _hex(value: int, width: int = 0) -> str:
    return f"0x{value:0{width}x}" if width else f"0x{value:x}"


def _read_regular_file(path: Path, maximum: int, what: str) -> bytes:
    """Bound a regular file before reading and reject observable replacement/change."""
    try:
        before = path.stat()
    except OSError as exc:
        raise DecodeError(f"cannot stat {what}: {exc.strerror}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise DecodeError(f"{what} is not a regular file")
    if before.st_size < 0 or before.st_size > maximum:
        raise DecodeError(f"{what} exceeds the bounded size limit")
    try:
        with path.open("rb") as handle:
            raw = handle.read(before.st_size + 1)
    except OSError as exc:
        raise DecodeError(f"cannot read {what}: {exc.strerror}") from exc
    if len(raw) > maximum:
        raise DecodeError(f"{what} exceeds the bounded size limit")
    try:
        after = path.stat()
    except OSError as exc:
        raise DecodeError(f"cannot restat {what}: {exc.strerror}") from exc
    identity_before = (before.st_dev, before.st_ino)
    identity_after = (after.st_dev, after.st_ino)
    if (
        not stat.S_ISREG(after.st_mode)
        or identity_before != identity_after
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(raw) != before.st_size
    ):
        raise DecodeError(f"{what} changed while being read")
    return raw


def _word_interval(label: str, start: int, count: int) -> MetadataInterval:
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or start < 0
        or start > 0xFFFFFFFF
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
    ):
        raise DecodeError(f"{label} metadata word interval is invalid")
    end = start + count
    if end > 1 << 32:
        raise DecodeError(f"{label} metadata word interval overflows")
    return MetadataInterval(label, start, end)


def _reject_interval_overlaps(intervals: list[MetadataInterval], what: str) -> None:
    ordered = sorted(intervals, key=lambda item: (item.start, item.end, item.label))
    for previous, current in zip(ordered, ordered[1:]):
        if previous.overlaps(current):
            raise DecodeError(
                f"{what} overlap: {previous.label} [{previous.start},{previous.end}) "
                f"and {current.label} [{current.start},{current.end})"
            )


def _require_exact_keys(value: Any, expected: set[str], what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DecodeError(f"{what} must be an object")
    actual = set(value)
    if actual != expected:
        raise DecodeError(
            f"{what} keys mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def _manifest_int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= U64_MAX:
        raise DecodeError(f"{what} must be a uint64 integer")
    return value


def _manifest_int_list(value: Any, what: str) -> list[int]:
    if not isinstance(value, list) or len(value) > 64:
        raise DecodeError(f"{what} must be a bounded array")
    result = [_manifest_int(item, f"{what} item") for item in value]
    if len(set(result)) != len(result):
        raise DecodeError(f"{what} contains duplicates")
    return result


def _manifest_string(value: Any, what: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise DecodeError(f"{what} must be a bounded non-empty string")
    return value


def _manifest_digest(value: Any, what: str) -> str:
    digest = _manifest_string(value, what, 64)
    if len(digest) != 64 or digest != digest.lower():
        raise DecodeError(f"{what} must be lowercase hexadecimal SHA-256")
    try:
        decoded = bytes.fromhex(digest)
    except ValueError as exc:
        raise DecodeError(f"{what} must be lowercase hexadecimal SHA-256") from exc
    if len(decoded) != 32:
        raise DecodeError(f"{what} must be lowercase hexadecimal SHA-256")
    return digest


def _load_manifest(
    path: Path,
    excerpt_path: Path,
    *,
    artifact_sha256: str,
    local_method_index: int,
    elf: ElfView,
) -> dict[str, Any]:
    raw = _read_regular_file(path, MAX_MANIFEST_SIZE, "evidence manifest")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("evidence manifest is not valid UTF-8 JSON") from exc
    top = _require_exact_keys(
        value,
        {
            "schema_version",
            "artifact_sha256",
            "local_method_index",
            "evidence_excerpt_sha256",
            "forwarding",
            "producer_provenance",
        },
        "evidence manifest",
    )
    schema_version = _manifest_int(top["schema_version"], "evidence manifest schema_version")
    if schema_version != 1:
        raise DecodeError("unsupported evidence-manifest schema version")
    manifest_artifact_sha256 = _manifest_digest(
        top["artifact_sha256"], "evidence manifest artifact_sha256"
    )
    if manifest_artifact_sha256 != artifact_sha256:
        raise DecodeError("evidence manifest artifact identity does not match")
    manifest_method_index = _manifest_int(
        top["local_method_index"], "evidence manifest local_method_index"
    )
    if manifest_method_index != local_method_index:
        raise DecodeError("evidence manifest method index does not match")
    excerpt_digest = _manifest_digest(
        top["evidence_excerpt_sha256"], "evidence excerpt SHA-256"
    )
    excerpt_raw = _read_regular_file(
        excerpt_path, MAX_EVIDENCE_EXCERPT_SIZE, "evidence excerpt"
    )
    actual_excerpt_digest = hashlib.sha256(excerpt_raw).hexdigest()
    if actual_excerpt_digest != excerpt_digest:
        raise DecodeError("evidence excerpt SHA-256 does not match current bytes")

    forwarding = _require_exact_keys(
        top["forwarding"],
        {
            "status",
            "static_metacall_va",
            "dispatcher_end_va_exclusive",
            "jump_table_base_va",
            "jump_table_entry_size_bytes",
            "jump_table_entry_va",
            "jump_table_entry_raw_u32",
            "case_target_va",
            "callee_va",
            "verifier_call_va",
            "argument_semantics",
        },
        "forwarding",
    )
    if _manifest_string(forwarding["status"], "forwarding.status") != "resolved":
        raise DecodeError("manifest forwarding status must be resolved")
    numeric_names = (
        "static_metacall_va",
        "dispatcher_end_va_exclusive",
        "jump_table_base_va",
        "jump_table_entry_size_bytes",
        "jump_table_entry_va",
        "jump_table_entry_raw_u32",
        "case_target_va",
        "callee_va",
        "verifier_call_va",
    )
    numbers = {name: _manifest_int(forwarding[name], f"forwarding.{name}") for name in numeric_names}
    if numbers["jump_table_entry_size_bytes"] != 4:
        raise DecodeError("manifest jump-table entry size must be four bytes")
    expected_entry = _checked_add(
        numbers["jump_table_base_va"], local_method_index * 4, "jump-table entry"
    )
    if numbers["jump_table_entry_va"] != expected_entry:
        raise DecodeError("manifest jump-table entry does not match local method index")
    if numbers["jump_table_entry_raw_u32"] > 0xFFFFFFFF:
        raise DecodeError("manifest jump-table word exceeds uint32")
    _entry_offset, entry_bytes = elf.read(expected_entry, 4, "manifest jump-table entry")
    raw_word = UINT32.unpack(entry_bytes)[0]
    if raw_word != numbers["jump_table_entry_raw_u32"]:
        raise DecodeError("manifest jump-table word does not match ELF bytes")
    displacement = struct.unpack("<i", entry_bytes)[0]
    target = numbers["jump_table_base_va"] + displacement
    if not 0 <= target <= U64_MAX or target != numbers["case_target_va"]:
        raise DecodeError("manifest jump-table displacement does not match case target")
    if not (
        numbers["static_metacall_va"] <= numbers["case_target_va"]
        < numbers["dispatcher_end_va_exclusive"]
    ):
        raise DecodeError("manifest case target is outside dispatcher range")

    semantics = _require_exact_keys(
        forwarding["argument_semantics"],
        {"a_2", "a_1", "call_rdx", "call_rcx", "return"},
        "forwarding.argument_semantics",
    )
    expected_semantics = {
        "a_2": "destPath",
        "a_1": "encFile",
        "call_rdx": "encFile",
        "call_rcx": "destPath",
        "return": "QString -> a[0]",
    }
    typed_semantics = {
        name: _manifest_string(semantics[name], f"forwarding.argument_semantics.{name}")
        for name in expected_semantics
    }
    if typed_semantics != expected_semantics:
        raise DecodeError("manifest argument semantics are unsupported")

    producer = _require_exact_keys(
        top["producer_provenance"],
        {"status", "direct_reference_search", "remaining_unknowns"},
        "producer_provenance",
    )
    if _manifest_string(producer["status"], "producer_provenance.status") != "unresolved":
        raise DecodeError("producer provenance must remain unresolved")
    search = _require_exact_keys(
        producer["direct_reference_search"],
        {
            "kind",
            "target_va",
            "observed_internal_call_vas",
            "generated_metacall_call_va",
            "complete_producer_absence_proven",
        },
        "producer_provenance.direct_reference_search",
    )
    search_kind = _manifest_string(
        search["kind"], "producer_provenance.direct_reference_search.kind"
    )
    if (
        search_kind != "x86-64 direct call/lea"
        or search["complete_producer_absence_proven"] is not False
    ):
        raise DecodeError("manifest direct-reference scope is unsupported")
    search_target = _manifest_int(search["target_va"], "direct-reference target")
    calls = _manifest_int_list(search["observed_internal_call_vas"], "observed internal calls")
    metacall = _manifest_int(search["generated_metacall_call_va"], "generated metacall call")
    if search_target != numbers["callee_va"] or metacall not in calls:
        raise DecodeError("manifest direct-reference facts are inconsistent")
    expected_unknowns = [
        "dynamic meta-invocation",
        "indirect calls",
        "external paths",
        "runtime invocation",
        "external reachability",
        "attacker control",
    ]
    unknown_values = producer["remaining_unknowns"]
    if not isinstance(unknown_values, list) or len(unknown_values) != len(expected_unknowns):
        raise DecodeError("manifest producer unknowns are unsupported")
    typed_unknowns = [
        _manifest_string(item, "producer_provenance.remaining_unknowns item")
        for item in unknown_values
    ]
    if typed_unknowns != expected_unknowns:
        raise DecodeError("manifest producer unknowns are unsupported")

    return {
        "manifest_schema_version": 1,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "evidence_excerpt_sha256": actual_excerpt_digest,
        "evidence_excerpt_size_bytes": len(excerpt_raw),
        "forwarding": {
            "status": "resolved",
            "basis": "explicit bounded instruction-evidence manifest; not metadata decoding",
            "static_metacall_va": _hex(numbers["static_metacall_va"]),
            "dispatcher_range": {
                "start_va": _hex(numbers["static_metacall_va"]),
                "end_va_exclusive": _hex(numbers["dispatcher_end_va_exclusive"]),
            },
            "jump_table_base_va": _hex(numbers["jump_table_base_va"]),
            "jump_table_entry_va": _hex(numbers["jump_table_entry_va"]),
            "jump_table_entry_file_offset": _entry_offset,
            "jump_table_entry_raw_u32": _hex(raw_word, 8),
            "jump_table_signed_displacement": displacement,
            "case_target_va": _hex(numbers["case_target_va"]),
            "callee_va": _hex(numbers["callee_va"]),
            "verifier_call_va": _hex(numbers["verifier_call_va"]),
            "argument_semantics": typed_semantics,
        },
        "producer_provenance": {
            "status": "unresolved",
            "bounded_direct_reference_observation": {
                "kind": search_kind,
                "target_va": _hex(search_target),
                "observed_internal_call_vas": [_hex(item) for item in calls],
                "generated_metacall_call_va": _hex(metacall),
                "complete_producer_absence_proven": False,
            },
            "remaining_unknowns": expected_unknowns,
        },
    }


def _read_words(elf: ElfView, va: int, count: int, what: str) -> tuple[int, list[int]]:
    if count < 0 or count > MAX_AUX_COUNT:
        raise DecodeError(f"{what} word count is unsupported or unbounded")
    size = count * 4
    offset, raw = elf.read(va, size, what)
    return offset, list(struct.unpack(f"<{count}I", raw)) if count else []


def _decode_string(elf: ElfView, stringdata_va: int, index: int) -> dict[str, Any]:
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < MAX_STRING_RECORDS:
        raise DecodeError("string index is unsupported or unbounded")
    descriptor_va = _checked_add(stringdata_va, index * QBYTEARRAYDATA.size, "string descriptor")
    descriptor_offset, raw = elf.read(descriptor_va, QBYTEARRAYDATA.size, "string descriptor")
    refcount, size, alloc_word, reserved_word, relative_offset = QBYTEARRAYDATA.unpack(raw)
    if size < 0 or size > MAX_STRING_BYTES:
        raise DecodeError("string length is unsupported or unbounded")
    if refcount != -1 or alloc_word != 0 or reserved_word != 0:
        raise DecodeError("unsupported static QByteArrayData flags/padding/layout")
    data_va = descriptor_va + relative_offset
    if not 0 <= data_va <= U64_MAX:
        raise DecodeError("signed descriptor-relative string offset is outside uint64")
    data_offset, payload = elf.read(data_va, size + 1, "string data and terminator")
    if payload[-1:] != b"\0":
        raise DecodeError("meta-object string is not NUL terminated at its declared size")
    content = payload[:-1]
    if b"\0" in content:
        raise DecodeError("meta-object string contains an embedded NUL")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("meta-object string is not valid UTF-8") from exc
    return {
        "string_index": index,
        "text": text,
        "descriptor_va": _hex(descriptor_va),
        "descriptor_file_offset": descriptor_offset,
        "descriptor_raw_hex": raw.hex(),
        "descriptor_fields": {
            "refcount": refcount,
            "size_bytes": size,
            "allocation_word": _hex(alloc_word, 8),
            "reserved_padding_word": reserved_word,
            "signed_data_offset": relative_offset,
        },
        "data_va": _hex(data_va),
        "data_file_offset": data_offset,
    }


def _decode_type(elf: ElfView, stringdata_va: int, raw_type: int) -> dict[str, Any]:
    if raw_type & UNRESOLVED_TYPE:
        index = raw_type & ~UNRESOLVED_TYPE
        string = _decode_string(elf, stringdata_va, index)
        if not string["text"]:
            raise DecodeError("string-referenced type name is empty")
        return {
            "raw_word": raw_type,
            "encoding": "string-reference",
            "name": string["text"],
            "string": string,
        }
    if raw_type not in BUILTIN_TYPES:
        raise DecodeError(f"unsupported Qt 5 built-in metatype ID {raw_type}")
    return {
        "raw_word": raw_type,
        "encoding": "built-in",
        "metatype_id": raw_type,
        "name": BUILTIN_TYPES[raw_type],
    }


def _decode_flags(raw: int) -> dict[str, Any]:
    if raw & ~0x1FF:
        raise DecodeError("method flags contain unsupported bits")
    method_type = raw & 0x0C
    if method_type != 0x08:
        raise DecodeError("selected method is not a Qt slot")
    access = {0: "private", 1: "protected", 2: "public"}.get(raw & 0x03)
    if access is None:
        raise DecodeError("method flags contain invalid access bits")
    return {
        "raw": raw,
        "raw_hex": _hex(raw, 8),
        "access": access,
        "method_type": "slot",
        "compatibility": bool(raw & 0x10),
        "cloned": bool(raw & 0x20),
        "scriptable": bool(raw & 0x40),
        "revisioned": bool(raw & 0x80),
        "const": bool(raw & 0x100),
    }


def decode(
    data: bytes,
    *,
    metadata_va: int,
    stringdata_va: int,
    local_method_index: int,
    evidence_manifest: Path | None = None,
    evidence_excerpt: Path | None = None,
) -> dict[str, Any]:
    if len(data) > MAX_FILE_SIZE:
        raise DecodeError("input file exceeds the bounded size limit")
    if not isinstance(local_method_index, int) or isinstance(local_method_index, bool) or local_method_index < 0:
        raise DecodeError("local method index must be a non-negative integer")
    elf = ElfView(data)
    digest = hashlib.sha256(data).hexdigest()

    header_offset, header_words = _read_words(elf, metadata_va, 14, "revision-7 metadata header")
    header = dict(zip(HEADER_NAMES, header_words))
    if header["revision"] != 7:
        raise DecodeError("unsupported Qt meta-object revision (expected 7)")
    header_interval = _word_interval("metadata header", 0, 14)
    reserved_intervals = [header_interval]
    auxiliary_tables = (
        ("classinfo", "classinfo_count", "classinfo_word_offset", 2),
        ("property", "property_count", "property_word_offset", 3),
        ("enum", "enum_count", "enum_word_offset", 4),
        ("constructor", "constructor_count", "constructor_word_offset", 5),
    )
    for label, count_name, offset_name, row_words in auxiliary_tables:
        count = header[count_name]
        if count > MAX_AUX_COUNT:
            raise DecodeError(f"{count_name} is unsupported or unbounded")
        if count:
            interval = _word_interval(
                f"{label} table", header[offset_name], count * row_words
            )
            table_va = _checked_add(
                metadata_va, interval.start * 4, f"{label} table"
            )
            elf.map_range(
                table_va, (interval.end - interval.start) * 4, f"{label} table"
            )
            reserved_intervals.append(interval)

    method_count = header["method_count"]
    if method_count > MAX_METHODS:
        raise DecodeError("method count is unsupported or unbounded")
    if header["signal_count"] > method_count:
        raise DecodeError("signal count exceeds method count")
    if local_method_index >= method_count:
        raise DecodeError("local method index is outside the method table")
    method_interval = _word_interval(
        "method table", header["method_table_word_offset"], method_count * 5
    )
    method_table_va = _checked_add(
        metadata_va, method_interval.start * 4, "method table"
    )
    method_table_word_count = method_interval.end - method_interval.start
    method_table_file_offset, method_table_words = _read_words(
        elf, method_table_va, method_table_word_count, "method table"
    )
    reserved_intervals.append(method_interval)
    _reject_interval_overlaps(reserved_intervals, "metadata table")

    rows = [
        method_table_words[index * 5 : (index + 1) * 5]
        for index in range(method_count)
    ]
    parameter_intervals: list[MetadataInterval] = []
    for index, method_row in enumerate(rows):
        if len(method_row) != 5:
            raise DecodeError("method table is truncated")
        argument_count = method_row[1]
        if argument_count > MAX_ARGUMENTS:
            raise DecodeError(
                f"local method {index} argument count is unsupported or unbounded"
            )
        interval = _word_interval(
            f"local method {index} parameter record",
            method_row[2],
            1 + 2 * argument_count,
        )
        parameter_va_for_row = _checked_add(
            metadata_va,
            interval.start * 4,
            f"local method {index} parameter record",
        )
        elf.map_range(
            parameter_va_for_row,
            (interval.end - interval.start) * 4,
            f"local method {index} parameter record",
        )
        for reserved in reserved_intervals:
            if interval.overlaps(reserved):
                raise DecodeError(
                    f"local method {index} parameter record overlaps {reserved.label}"
                )
        parameter_intervals.append(interval)
    _reject_interval_overlaps(parameter_intervals, "method parameter record")

    row = rows[local_method_index]
    name_index, argument_count, parameter_word_offset, tag_index, raw_flags = row
    row_va = _checked_add(
        method_table_va, local_method_index * 20, "selected method row"
    )
    row_offset = method_table_file_offset + local_method_index * 20
    parameter_interval = parameter_intervals[local_method_index]
    parameter_word_count = parameter_interval.end - parameter_interval.start
    parameter_va = _checked_add(
        metadata_va, parameter_interval.start * 4, "selected parameter record"
    )
    parameter_offset, parameter_words = _read_words(
        elf, parameter_va, parameter_word_count, "selected parameter record"
    )

    class_name = _decode_string(elf, stringdata_va, header["class_name_string_index"])
    method_name = _decode_string(elf, stringdata_va, name_index)
    tag = _decode_string(elf, stringdata_va, tag_index)
    if not method_name["text"]:
        raise DecodeError("method name is empty")
    flags = _decode_flags(raw_flags)
    if local_method_index < header["signal_count"]:
        raise DecodeError("selected slot overlaps the metadata signal prefix")
    return_type = _decode_type(elf, stringdata_va, parameter_words[0])
    argument_types = [
        _decode_type(elf, stringdata_va, value)
        for value in parameter_words[1 : 1 + argument_count]
    ]
    argument_names = [
        _decode_string(elf, stringdata_va, value)
        for value in parameter_words[1 + argument_count :]
    ]
    parameters = []
    signature_parts = []
    for position, (type_record, name_record) in enumerate(zip(argument_types, argument_names)):
        parameters.append(
            {
                "position": position,
                "type": type_record,
                "name": name_record,
            }
        )
        suffix = f" {name_record['text']}" if name_record["text"] else ""
        signature_parts.append(type_record["name"] + suffix)
    signature = f"{method_name['text']}({', '.join(signature_parts)})"

    status: dict[str, Any] = {
        "metadata_binding": {
            "status": "resolved",
            "basis": "bounded Qt 5 revision-7 metadata decoding",
        },
        "forwarding": {
            "status": "unresolved",
            "basis": "machine code is outside metadata-only decoding",
        },
        "producer_provenance": {
            "status": "unresolved",
            "basis": "metadata does not identify runtime invokers or argument producers",
        },
    }
    manifest_binding = None
    if (evidence_manifest is None) != (evidence_excerpt is None):
        raise DecodeError(
            "evidence manifest and evidence excerpt must be supplied together"
        )
    if evidence_manifest is not None and evidence_excerpt is not None:
        manifest_binding = _load_manifest(
            evidence_manifest,
            evidence_excerpt,
            artifact_sha256=digest,
            local_method_index=local_method_index,
            elf=elf,
        )
        status["forwarding"] = manifest_binding.pop("forwarding")
        status["producer_provenance"] = manifest_binding.pop("producer_provenance")

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "input": {
            "sha256": digest,
            "size_bytes": len(data),
            "elf": {
                "class": "ELF64",
                "endianness": "little-endian",
                "machine": "x86-64",
            },
        },
        "request": {
            "metadata_va": _hex(metadata_va),
            "stringdata_va": _hex(stringdata_va),
            "local_method_index": local_method_index,
        },
        "metaobject": {
            "revision": 7,
            "header_word_count": 14,
            "header_va": _hex(metadata_va),
            "header_file_offset": header_offset,
            "header_raw_words": header_words,
            "class_name": class_name,
            "method_count": method_count,
            "method_table_word_offset": method_interval.start,
            "method_table_va": _hex(method_table_va),
            "method_table_file_offset": method_table_file_offset,
            "method_row_word_count": 5,
            "signal_count": header["signal_count"],
            "method": {
                "index_scope": "local-to-declaring-metaobject",
                "index_scope_basis": (
                    "selected revision-7 row; QMetaObject::methodOffset and "
                    "inheritance context are required for an absolute method index"
                ),
                "local_index": local_method_index,
                "declared_in_selected_metaobject": True,
                "absolute_method_index": None,
                "signal_number": None,
                "row_va": _hex(row_va),
                "row_file_offset": row_offset,
                "raw_words": row,
                "name": method_name,
                "tag": tag,
                "argument_count": argument_count,
                "parameter_record": {
                    "word_offset": parameter_word_offset,
                    "word_interval": {
                        "start": parameter_interval.start,
                        "end_exclusive": parameter_interval.end,
                    },
                    "va": _hex(parameter_va),
                    "file_offset": parameter_offset,
                    "word_count": parameter_word_count,
                    "raw_words": parameter_words,
                },
                "return_type": return_type,
                "parameters": parameters,
                "signature": signature,
                "declaration": f"{return_type['name']} {signature}",
                "flags": flags,
            },
        },
        "analysis_status": status,
        "claim_boundary": {
            "metadata_decoder_establishes_machine_code_forwarding": False,
            "complete_producer_provenance_established": False,
            "runtime_invocation_established": False,
            "external_reachability_established": False,
            "attacker_control_established": False,
            "update_acceptance_established": False,
            "root_established": False,
            "persistence_established": False,
        },
    }
    if manifest_binding is not None:
        report["evidence_manifest"] = manifest_binding
    return report


def parse_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an integer (decimal or 0x-prefixed)") from exc
    if not 0 <= parsed <= U64_MAX:
        raise argparse.ArgumentTypeError("integer is outside uint64")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--elf", required=True, type=Path, help="explicit ELF input path")
    parser.add_argument("--metadata-va", required=True, type=parse_int)
    parser.add_argument("--stringdata-va", required=True, type=parse_int)
    parser.add_argument("--local-method-index", required=True, type=parse_int)
    parser.add_argument("--evidence-manifest", type=Path)
    parser.add_argument("--evidence-excerpt", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        data = _read_regular_file(args.elf, MAX_FILE_SIZE, "ELF input")
        report = decode(
            data,
            metadata_va=args.metadata_va,
            stringdata_va=args.stringdata_va,
            local_method_index=args.local_method_index,
            evidence_manifest=args.evidence_manifest,
            evidence_excerpt=args.evidence_excerpt,
        )
    except DecodeError as exc:
        raise SystemExit(f"error: {exc}") from exc
    payload = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
