#!/usr/bin/env python3
"""Build and audit bounded ASF stream-count probes.

The generated file duplicates an existing, valid ASF Stream Properties object.
It is intended to test whether an ASF parser rejects more than 32 streams, as
required by the CVE-2026-2920 fix. It does not contain shellcode or a command
payload. Run generated files only in an isolated VM or disposable test target.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

ASF_HEADER_GUID = uuid.UUID("75b22630-668e-11cf-a6d9-00aa0062ce6c").bytes_le
ASF_FILE_PROPERTIES_GUID = uuid.UUID("8cabdca1-a947-11cf-8ee4-00c00c205365").bytes_le
ASF_STREAM_PROPERTIES_GUID = uuid.UUID("b7dc0791-a9b7-11cf-8ee6-00c00c205365").bytes_le
ASF_HEADER_FIXED_SIZE = 30
ASF_OBJECT_FIXED_SIZE = 24
ASF_STREAM_FLAGS_OFFSET = ASF_OBJECT_FIXED_SIZE + 16 + 16 + 8 + 4 + 4
PATCH_MARKER = b"File has too many streams"


class AsfProbeError(ValueError):
    """The input is not a safe, supported ASF template."""


@dataclass(frozen=True)
class AsfObject:
    guid: bytes
    data: bytes


@dataclass(frozen=True)
class AsfHeader:
    reserved: bytes
    objects: tuple[AsfObject, ...]
    tail: bytes


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def parse_asf(data: bytes) -> AsfHeader:
    if len(data) < ASF_HEADER_FIXED_SIZE or data[:16] != ASF_HEADER_GUID:
        raise AsfProbeError("input is not an ASF Header Object")

    header_size = _u64(data, 16)
    object_count = struct.unpack_from("<I", data, 24)[0]
    if header_size < ASF_HEADER_FIXED_SIZE or header_size > len(data):
        raise AsfProbeError("ASF header size is outside the input")
    if object_count > 4096:
        raise AsfProbeError("refusing implausible ASF object count")

    objects: list[AsfObject] = []
    offset = ASF_HEADER_FIXED_SIZE
    for index in range(object_count):
        if offset + ASF_OBJECT_FIXED_SIZE > header_size:
            raise AsfProbeError(f"object {index} header exceeds ASF header")
        size = _u64(data, offset + 16)
        if size < ASF_OBJECT_FIXED_SIZE or offset + size > header_size:
            raise AsfProbeError(f"object {index} size exceeds ASF header")
        raw = data[offset : offset + size]
        objects.append(AsfObject(raw[:16], raw))
        offset += size

    if offset != header_size:
        raise AsfProbeError("ASF object sizes do not exactly fill the header")
    return AsfHeader(data[28:30], tuple(objects), data[header_size:])


def _set_stream_id(raw: bytes, stream_id: int) -> bytes:
    if len(raw) < ASF_STREAM_FLAGS_OFFSET + 2:
        raise AsfProbeError("Stream Properties object is truncated before flags")
    result = bytearray(raw)
    flags = struct.unpack_from("<H", result, ASF_STREAM_FLAGS_OFFSET)[0]
    struct.pack_into("<H", result, ASF_STREAM_FLAGS_OFFSET, (flags & ~0x7F) | stream_id)
    return bytes(result)


def build_stream_count_probe(template: bytes, streams: int = 33) -> bytes:
    if not 1 <= streams <= 127:
        raise AsfProbeError("stream count must be in 1..127")
    parsed = parse_asf(template)
    stream_objects = [obj for obj in parsed.objects if obj.guid == ASF_STREAM_PROPERTIES_GUID]
    if len(stream_objects) != 1:
        raise AsfProbeError("template must contain exactly one Stream Properties object")

    expanded: list[bytes] = []
    for obj in parsed.objects:
        if obj.guid != ASF_STREAM_PROPERTIES_GUID:
            expanded.append(obj.data)
            continue
        expanded.extend(_set_stream_id(obj.data, stream_id) for stream_id in range(1, streams + 1))

    body = b"".join(expanded)
    header = (
        ASF_HEADER_GUID
        + struct.pack("<QI", ASF_HEADER_FIXED_SIZE + len(body), len(expanded))
        + parsed.reserved
        + body
    )
    output = bytearray(header + parsed.tail)

    # Keep the File Properties Object's declared file size coherent when it is
    # present. Its file-size field follows the 24-byte object header and 16-byte
    # file-ID GUID.
    offset = ASF_HEADER_FIXED_SIZE
    for raw in expanded:
        if raw[:16] == ASF_FILE_PROPERTIES_GUID and len(raw) >= 48:
            struct.pack_into("<Q", output, offset + 40, len(output))
        offset += len(raw)
    return bytes(output)


def describe(data: bytes) -> dict[str, object]:
    parsed = parse_asf(data)
    stream_ids: list[int] = []
    for obj in parsed.objects:
        if obj.guid == ASF_STREAM_PROPERTIES_GUID:
            if len(obj.data) < ASF_STREAM_FLAGS_OFFSET + 2:
                raise AsfProbeError("Stream Properties object is truncated before flags")
            flags = struct.unpack_from("<H", obj.data, ASF_STREAM_FLAGS_OFFSET)[0]
            stream_ids.append(flags & 0x7F)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "header_objects": len(parsed.objects),
        "stream_objects": len(stream_ids),
        "stream_ids": stream_ids,
    }


def cmd_build(args: argparse.Namespace) -> int:
    source = args.template.resolve()
    destination = args.output.resolve()
    if source == destination:
        raise AsfProbeError("refusing to overwrite the template")
    if destination.exists() and not args.force:
        raise AsfProbeError(f"output exists (use --force): {destination}")

    original = source.read_bytes()
    output = build_stream_count_probe(original, args.streams)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(output)
    print(json.dumps({"template": describe(original), "output": describe(output)}, indent=2))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    data = args.plugin.read_bytes()
    result = {
        "path": str(args.plugin),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "cve_2026_2920_rejection_marker_present": PATCH_MARKER in data,
        "note": (
            "marker presence supports the upstream >32-stream rejection; marker absence alone "
            "does not prove vulnerability and requires control-flow or dynamic validation"
        ),
    }
    print(json.dumps(result, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="duplicate one valid ASF stream object")
    build.add_argument("--template", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--streams", type=int, default=33)
    build.add_argument("--force", action="store_true")
    build.set_defaults(func=cmd_build)

    audit = sub.add_parser("audit", help="check an ASF plugin for the upstream rejection marker")
    audit.add_argument("plugin", type=Path)
    audit.set_defaults(func=cmd_audit)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (AsfProbeError, OSError) as exc:
        raise SystemExit(f"asf_stream_probe: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
