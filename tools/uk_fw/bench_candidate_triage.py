#!/usr/bin/env python3
"""Triage passive bench-state JSON for V-024 through V-026 runtime gates.

This host-only tool consumes a completed report produced by
``bench_state_bundle.py parse``. It never executes capture contents, contacts a
target, opens a device, loads a module, creates a socket/timer/PTY, or emits a
trigger, race schedule, payload, command, or firmware bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "ioniq-bench-state/v1"
MAX_INPUT_BYTES = 64 * 1024 * 1024
UNIX_MODULE_PATH = "/lib/modules/4.1.27-abl/kernel/net/unix/unix.ko"
UNIX_MODULE_SHA256 = "e1841632fee9f70eb8f97204cf629a2b34c9e21136fda9236a971ca2d8758ecb"
KERNEL_BANNER = "4.1.27-abl"
EXPECTED_SECTIONS = (
    "meta",
    "identity",
    "processes",
    "smack",
    "units",
    "interfaces",
    "cellular",
    "bluetooth",
    "dropbear",
    "storage",
    "hashes",
    "complete",
)
HEX64_RE = re.compile(r"[0-9a-f]{64}")
MODE_RE = re.compile(r"[0-7]{3,4}")


class TriageError(ValueError):
    """Raised when a report cannot support fail-closed triage."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TriageError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _is_plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _read_regular_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise TriageError("input must resolve to a regular file")
            raw = source.read(MAX_INPUT_BYTES + 1)
    except TriageError:
        raise
    except OSError as exc:
        raise TriageError(f"cannot read input: {exc}") from exc
    if len(raw) > MAX_INPUT_BYTES:
        raise TriageError("input exceeds 64 MiB")
    return raw


def load_report(path: Path) -> dict[str, Any]:
    raw = _read_regular_bounded(path)
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except UnicodeDecodeError as exc:
        raise TriageError("input is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise TriageError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(report, dict):
        raise TriageError("report root must be an object")

    expected_top = {
        "schema",
        "capture_sha256",
        "capture_bytes",
        "complete",
        "section_order",
        "sections",
        "facts",
        "warnings",
        "canonical_sha256",
    }
    if set(report) != expected_top:
        raise TriageError("report top-level fields do not match producer schema")
    if report.get("schema") != SCHEMA:
        raise TriageError("unexpected or missing report schema")
    if report.get("complete") is not True:
        raise TriageError("report is not complete")
    if report.get("warnings") != []:
        raise TriageError("complete report must have no warnings")
    if not _is_plain_int(report.get("capture_bytes")) or report["capture_bytes"] < 0:
        raise TriageError("invalid capture byte count")
    if not isinstance(report.get("capture_sha256"), str) or not HEX64_RE.fullmatch(
        report["capture_sha256"]
    ):
        raise TriageError("invalid capture SHA-256")
    supplied_canonical = report.get("canonical_sha256")
    if not isinstance(supplied_canonical, str) or not HEX64_RE.fullmatch(supplied_canonical):
        raise TriageError("invalid canonical SHA-256")
    without_canonical = dict(report)
    del without_canonical["canonical_sha256"]
    if _sha256_json(without_canonical) != supplied_canonical:
        raise TriageError("canonical report SHA-256 mismatch")

    sections = report.get("sections")
    if not isinstance(sections, list):
        raise TriageError("report sections must be a list")
    if report.get("section_order") != list(EXPECTED_SECTIONS):
        raise TriageError("unexpected section order")
    if len(sections) != len(EXPECTED_SECTIONS):
        raise TriageError("unexpected section count")
    for expected_name, section in zip(EXPECTED_SECTIONS, sections):
        if not isinstance(section, dict):
            raise TriageError("section must be an object")
        expected_section_fields = {
            "name",
            "complete",
            "end_status",
            "records",
            "raw",
            "captured_bytes",
            "sha256",
        }
        if set(section) != expected_section_fields:
            raise TriageError(f"section fields are malformed: {expected_name}")
        name = section.get("name")
        records = section.get("records")
        if name != expected_name or not isinstance(records, list):
            raise TriageError("section name/records are malformed")
        if section.get("complete") is not True:
            raise TriageError(f"section is not complete: {name}")
        if not _is_plain_int(section.get("end_status")) or section["end_status"] != 0:
            raise TriageError(f"section has nonzero or invalid status: {name}")
        if not _is_plain_int(section.get("captured_bytes")) or section["captured_bytes"] < 0:
            raise TriageError(f"section has invalid byte count: {name}")
        if not isinstance(section.get("raw"), list) or any(
            not isinstance(item, str) for item in section["raw"]
        ):
            raise TriageError(f"section raw records are malformed: {name}")
        supplied_section_hash = section.get("sha256")
        if not isinstance(supplied_section_hash, str) or not HEX64_RE.fullmatch(
            supplied_section_hash
        ):
            raise TriageError(f"section SHA-256 is malformed: {name}")
        section_without_hash = dict(section)
        del section_without_hash["sha256"]
        if _sha256_json(section_without_hash) != supplied_section_hash:
            raise TriageError(f"section SHA-256 mismatch: {name}")
        for record in records:
            if (
                not isinstance(record, dict)
                or set(record) != {"key", "value"}
                or not isinstance(record.get("key"), str)
                or not isinstance(record.get("value"), str)
            ):
                raise TriageError(f"malformed record in section: {name}")

    if sections[0]["records"] != [{"key": "schema", "value": SCHEMA}]:
        raise TriageError("meta schema record is missing or invalid")
    if sections[-1]["records"] != [{"key": "result", "value": "complete"}]:
        raise TriageError("terminal complete record is missing or invalid")
    if not isinstance(report.get("facts"), dict):
        raise TriageError("report facts must be an object")
    return report


def _records(report: dict[str, Any], key: str) -> list[str]:
    return [
        record["value"]
        for section in report["sections"]
        for record in section["records"]
        if record["key"] == key
    ]


def _single_path_record(values: Iterable[str], path: str, kind: str) -> str | None:
    matches = [value for value in values if value == path or value.startswith(path + "|")]
    if len(matches) > 1:
        raise TriageError(f"conflicting {kind} records for {path}")
    return matches[0] if matches else None


def _file_state(report: dict[str, Any], path: str) -> dict[str, Any]:
    value = _single_path_record(_records(report, "file"), path, "file")
    empty = {
        "observed": False,
        "present": None,
        "metadata_structured": False,
        "mode": None,
        "type": None,
        "link_target": None,
        "link_target_observed": False,
        "device_major": None,
        "device_minor": None,
        "device_identity_observed": False,
    }
    if value is None:
        return empty
    parts = value.split("|", 9)
    if len(parts) == 2 and parts == [path, "absent"]:
        return {**empty, "observed": True, "present": False}
    if len(parts) in (3, 4) and parts[0] == path and parts[1] == "present":
        # Producer fallback when only `ls` is available. The final field is a
        # possible link target, but without structured type metadata it cannot
        # safely establish that this is a symlink, so infer no metadata.
        return {**empty, "observed": True, "present": True}
    if len(parts) not in (8, 10) or parts[0] != path or parts[1] != "present":
        raise TriageError(f"malformed file record for {path}")
    mode = parts[2]
    if not MODE_RE.fullmatch(mode):
        raise TriageError(f"malformed mode for {path}")
    if len(parts) == 10:
        kind, major_text, minor_text, link_text = parts[6:10]
        if not re.fullmatch(r"[0-9a-fA-F]+", major_text) or not re.fullmatch(
            r"[0-9a-fA-F]+", minor_text
        ):
            raise TriageError(f"malformed device identity for {path}")
        device_major = int(major_text, 16)
        device_minor = int(minor_text, 16)
        device_identity_observed = True
    else:
        # Reports from the prior producer revision have no device identity.
        kind, link_text = parts[6:8]
        device_major = None
        device_minor = None
        device_identity_observed = False
    link_target = link_text or None
    link_observed = kind != "symbolic link" or link_target not in (None, "unavailable")
    return {
        "observed": True,
        "present": True,
        "metadata_structured": True,
        "mode": mode,
        "type": kind,
        "link_target": None if link_target == "unavailable" else link_target,
        "link_target_observed": link_observed,
        "device_major": device_major,
        "device_minor": device_minor,
        "device_identity_observed": device_identity_observed,
    }


def _hash_state(report: dict[str, Any], path: str) -> dict[str, Any]:
    value = _single_path_record(_records(report, "hash"), path, "hash")
    if value is None:
        return {"observed": False, "state": "missing-record", "sha256": None}
    parts = value.split("|", 1)
    if len(parts) != 2 or parts[0] != path:
        raise TriageError(f"malformed hash record for {path}")
    token = parts[1]
    if token in ("absent", "unavailable"):
        return {"observed": True, "state": token, "sha256": None}
    if not re.fullmatch(r"[0-9a-fA-F]{64}", token):
        raise TriageError(f"malformed hash digest for {path}")
    return {"observed": True, "state": "digest", "sha256": token.lower()}


def _kernel_banner_state(report: dict[str, Any]) -> bool | None:
    values = _records(report, "uname")
    if not values:
        return None
    if len(values) != 1:
        raise TriageError("conflicting uname records")
    fields = values[0].split()
    if len(fields) < 3 or fields[0] != "Linux":
        raise TriageError("malformed uname record")
    return fields[2] == KERNEL_BANNER


def _devpts_mounted(report: dict[str, Any]) -> bool | None:
    values = _records(report, "mounts")
    if not values:
        return None
    for value in values:
        fields = value.split()
        if len(fields) >= 3 and fields[1] == "/dev/pts" and fields[2] == "devpts":
            return True
    return False


def _unix_module_loaded(report: dict[str, Any]) -> bool | None:
    values = _records(report, "modules")
    if not values:
        return None
    return any(value.split(maxsplit=1)[0] == "unix" for value in values if value.split())


def _world_read_write(mode: str | None) -> bool | None:
    if mode is None:
        return None
    if not MODE_RE.fullmatch(mode):
        raise TriageError("invalid mode supplied to permission classifier")
    permissions = int(mode[-3:], 8)
    return permissions & 0o006 == 0o006


def _tri_and(*values: bool | None) -> bool | None:
    if any(value is False for value in values):
        return False
    if all(value is True for value in values):
        return True
    return None


def _character_device_valid(state: dict[str, Any]) -> bool | None:
    if state["present"] is False:
        return False
    if state["present"] is not True or not state["metadata_structured"]:
        return None
    if state["type"] != "character special file":
        return False
    if not state["device_identity_observed"]:
        return None
    return state["device_major"] == 5 and state["device_minor"] == 2


def _ptmx_endpoint_valid(
    state: dict[str, Any], target_state: dict[str, Any]
) -> bool | None:
    if state["present"] is False:
        return False
    if state["present"] is not True or not state["metadata_structured"]:
        return None
    if state["type"] == "character special file":
        return _character_device_valid(state)
    if state["type"] != "symbolic link":
        return False
    if not state["link_target_observed"]:
        return None
    if state["link_target"] not in ("pts/ptmx", "/dev/pts/ptmx"):
        return False
    return _character_device_valid(target_state)


def _ptmx_effective_world_read_write(
    state: dict[str, Any], target_state: dict[str, Any]
) -> bool | None:
    endpoint_valid = _ptmx_endpoint_valid(state, target_state)
    if endpoint_valid is False:
        return False
    if endpoint_valid is None:
        return None
    if state["type"] == "character special file":
        return _world_read_write(state["mode"])
    return _world_read_write(target_state["mode"])


def _directory_valid(state: dict[str, Any]) -> bool | None:
    if state["present"] is False:
        return False
    if state["present"] is not True or not state["metadata_structured"]:
        return None
    return state["type"] == "directory"


def build_triage(report: dict[str, Any]) -> dict[str, Any]:
    ptmx = _file_state(report, "/dev/ptmx")
    pts = _file_state(report, "/dev/pts")
    ptmx_target = _file_state(report, "/dev/pts/ptmx")
    unix_hash = _hash_state(report, UNIX_MODULE_PATH)
    unix_loaded = _unix_module_loaded(report)
    hash_matches = (
        unix_hash["sha256"] == UNIX_MODULE_SHA256
        if unix_hash["state"] == "digest"
        else (False if unix_hash["state"] == "absent" else None)
    )
    ptmx_record_world_rw = _world_read_write(ptmx["mode"])
    ptmx_endpoint_valid = _ptmx_endpoint_valid(ptmx, ptmx_target)
    ptmx_effective_world_rw = _ptmx_effective_world_read_write(ptmx, ptmx_target)
    pts_directory_valid = _directory_valid(pts)
    devpts_mounted = _devpts_mounted(report)
    kernel_banner_match = _kernel_banner_state(report)

    v024_surface = _tri_and(
        ptmx["present"],
        ptmx_effective_world_rw,
        ptmx_endpoint_valid,
        pts_directory_valid,
        devpts_mounted,
    )
    v025_name_and_file = _tri_and(unix_loaded, hash_matches)

    return {
        "schema_version": 1,
        "source_schema": SCHEMA,
        "observations": {
            "kernel_banner_match": kernel_banner_match,
            "ptmx": ptmx,
            "ptmx_record_world_read_write": ptmx_record_world_rw,
            "ptmx_effective_world_read_write": ptmx_effective_world_rw,
            "ptmx_endpoint_valid": ptmx_endpoint_valid,
            "ptmx_target": ptmx_target,
            "devpts_directory": pts,
            "devpts_directory_valid": pts_directory_valid,
            "devpts_mounted": devpts_mounted,
            "unix_module_name_loaded": unix_loaded,
            "unix_module_file_hash": unix_hash,
            "unix_module_file_hash_matches_recovered": hash_matches,
        },
        "candidate_runtime_gates": {
            "V-024": {
                "name": "TTY pgrp wrong-object lock",
                "static_premise": "exact-recovered",
                "pty_surface_observed": v024_surface,
                "installed_kernel_exact_identity": None,
                "race_or_uaf_observed": None,
            },
            "V-025": {
                "name": "AF_UNIX MSG_PEEK/GC gap",
                "static_premise": "exact-recovered-module",
                "module_name_loaded_and_current_file_matches": v025_name_and_file,
                "loaded_module_bound_to_current_file": None,
                "gc_overlap_or_uaf_observed": None,
            },
            "V-026": {
                "name": "timerfd cancellation context-lock gap",
                "static_premise": "exact-recovered",
                "kernel_banner_match": kernel_banner_match,
                "installed_kernel_exact_identity": None,
                "race_or_corruption_observed": None,
            },
        },
        "claim_boundary": {
            "establishes": [
                "classification of completed passive capture records",
                "runtime PTY metadata and AF_UNIX module-name/current-file gates when providers succeeded",
            ],
            "does_not_establish": [
                "installed vmlinux byte identity from a version banner",
                "that a loaded module came from the currently hashed file",
                "capture authenticity or provenance beyond producer-format integrity",
                "syscall/ioctl/policy reachability beyond captured metadata",
                "a race, use-after-free, corruption, code execution, root, or persistence",
            ],
            "executes_capture_contents": False,
            "performs_target_operations": False,
            "emits_trigger_or_payload_material": False,
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("report", type=Path, help="completed parsed bench-state JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        triage = build_triage(load_report(args.report))
    except TriageError as exc:
        raise SystemExit(f"error: {exc}") from exc
    sys.stdout.buffer.write(
        json.dumps(triage, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
