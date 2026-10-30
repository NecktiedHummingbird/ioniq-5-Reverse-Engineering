#!/usr/bin/env python3
"""Parse an RPM Berkeley DB ``db_dump -p`` Nvra index read-only.

The recovered target database uses a Berkeley DB format that host RPM bindings
may not support.  This tool consumes the printable output of a compatible
``db_dump``; it does not load the target database, execute target files, or infer
vulnerability from package versions.  Record values are retained only as opaque
hex identifiers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Iterable

SCHEMA_VERSION = 1
MAX_DUMP_SIZE = 64 * 1024 * 1024
SUPPORTED_HEADERS = {
    "VERSION": "3",
    "format": "print",
    "type": "btree",
}


class InventoryError(ValueError):
    """The input or requested output is unsafe or malformed."""


def validate_input(path: Path) -> Path:
    if path.is_symlink():
        raise InventoryError("dump input must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise InventoryError("dump input does not exist") from exc
    if not resolved.is_file():
        raise InventoryError("dump input must be a regular file")
    if resolved.stat().st_size > MAX_DUMP_SIZE:
        raise InventoryError(f"dump input exceeds {MAX_DUMP_SIZE} bytes")
    return resolved


def validate_output(path: Path | None, source: Path) -> Path | None:
    if path is None:
        return None
    if path.exists() and path.is_symlink():
        raise InventoryError("output must not be a symlink")
    try:
        parent = path.parent.resolve(strict=True)
    except FileNotFoundError as exc:
        raise InventoryError("output parent does not exist") from exc
    candidate = parent / path.name
    if candidate == source:
        raise InventoryError("output must differ from dump input")
    if path.exists() and not path.is_file():
        raise InventoryError("output must be a regular file")
    return candidate


def decode_print_field(line: bytes) -> bytes:
    """Decode one leading-space-prefixed Berkeley DB print field."""
    if not line.startswith(b" "):
        raise InventoryError("data record does not begin with one space")
    source = line[1:]
    result = bytearray()
    index = 0
    while index < len(source):
        value = source[index]
        if value != 0x5C:  # backslash
            result.append(value)
            index += 1
            continue
        if index + 1 < len(source) and source[index + 1] == 0x5C:
            result.append(0x5C)
            index += 2
            continue
        if index + 2 >= len(source):
            raise InventoryError("truncated print escape")
        escape = source[index + 1:index + 3]
        try:
            result.append(int(escape, 16))
        except ValueError as exc:
            raise InventoryError("invalid print escape") from exc
        index += 3
    return bytes(result)


def parse_nvra(value: str) -> dict[str, str]:
    if "\x00" in value or not value:
        raise InventoryError("NVRA key is empty or contains NUL")
    try:
        name, version, release_arch = value.rsplit("-", 2)
        release, arch = release_arch.rsplit(".", 1)
    except ValueError as exc:
        raise InventoryError(f"malformed NVRA key: {value!r}") from exc
    if not all((name, version, release, arch)):
        raise InventoryError(f"malformed NVRA key: {value!r}")
    return {
        "nvra": value,
        "name": name,
        "version": version,
        "release": release,
        "arch": arch,
    }


def parse_dump(data: bytes) -> tuple[dict[str, str], list[dict[str, str]]]:
    lines = data.splitlines()
    if lines.count(b"HEADER=END") != 1:
        raise InventoryError("dump must contain exactly one HEADER=END")
    header_end = lines.index(b"HEADER=END")
    headers: dict[str, str] = {}
    for raw in lines[:header_end]:
        try:
            line = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise InventoryError("dump header is not ASCII") from exc
        if "=" not in line:
            raise InventoryError("malformed dump header")
        key, value = line.split("=", 1)
        if not key or key in headers:
            raise InventoryError("empty or duplicate dump header")
        headers[key] = value
    for key, expected in SUPPORTED_HEADERS.items():
        if headers.get(key) != expected:
            raise InventoryError(f"unsupported {key}: {headers.get(key)!r}")

    records = lines[header_end + 1:]
    if records.count(b"DATA=END") != 1 or not records or records[-1] != b"DATA=END":
        raise InventoryError("dump must end with exactly one DATA=END")
    fields = records[:-1]
    if len(fields) % 2:
        raise InventoryError("dump contains an unmatched key/value field")

    packages: list[dict[str, str]] = []
    for offset in range(0, len(fields), 2):
        key_bytes = decode_print_field(fields[offset])
        record_bytes = decode_print_field(fields[offset + 1])
        try:
            key = key_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("NVRA key is not UTF-8") from exc
        package = parse_nvra(key)
        package["record_id_hex"] = record_bytes.hex()
        packages.append(package)

    packages.sort(key=lambda item: (item["name"], item["nvra"], item["record_id_hex"]))
    return headers, packages


def build_report(
    data: bytes,
    source_name: str,
    selectors: Iterable[str] = (),
    include_all: bool = False,
) -> dict[str, Any]:
    headers, packages = parse_dump(data)
    selected_names = sorted(set(selectors))
    by_name: dict[str, list[dict[str, str]]] = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)

    duplicate_nvras: list[str] = []
    seen: set[str] = set()
    for package in packages:
        nvra = package["nvra"]
        if nvra in seen:
            duplicate_nvras.append(nvra)
        seen.add(nvra)

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "name": source_name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "headers": dict(sorted(headers.items())),
        },
        "package_count": len(packages),
        "unique_name_count": len(by_name),
        "selected": [
            package
            for name in selected_names
            for package in by_name.get(name, [])
        ],
        "missing_selectors": [name for name in selected_names if name not in by_name],
        "duplicate_nvras": sorted(set(duplicate_nvras)),
        "interpretation": (
            "Package-index metadata identifies installed records but does not prove "
            "that a component is reachable, vulnerable, or identical to upstream."
        ),
    }
    if include_all:
        report["packages"] = packages
    return report


def write_output_atomic(path: Path, text: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path, help="printable output from db_dump -p")
    parser.add_argument(
        "--select",
        action="append",
        default=[],
        metavar="NAME",
        help="include records with this exact package name (repeatable)",
    )
    parser.add_argument("--all", action="store_true", help="include all package records")
    parser.add_argument("--output", type=Path, help="write JSON atomically instead of stdout")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        source = validate_input(args.dump)
        output = validate_output(args.output, source)
        data = source.read_bytes()
        report = build_report(data, source.name, args.select, args.all)
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if output is None:
            print(text, end="")
        else:
            write_output_atomic(output, text)
    except (InventoryError, OSError) as exc:
        raise SystemExit(f"error: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
