#!/usr/bin/env python3
"""Parse bounded AppFUMO decryption/copy provenance from an explicit log.

The parser is read-only.  It recognizes only the two log-record families needed
for this evidence package, never executes target material, and never emits the
logged command or its transient token.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
TOOL_NAME = "appfumo-decryption-log-model"
TOOL_VERSION = "1.0.0"
EXPECTED_LOG_SHA256 = "84d5bb69270dd610b132c8950c31dd98adad844c5a2c108b4df617381685de86"
EXACT_ELF_SHA256 = "464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7"
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_LINES = 100_000
MAX_LINE_BYTES = 4096
MAX_RELEVANT_RECORDS = 512
MAX_INVOCATIONS = 64
CONTEXT_BEFORE_LINES = 32
CONTEXT_AFTER_LINES = 8

_TIMESTAMP = r"(?P<timestamp>\d{2}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}:\d{3})"
_USB_ROOT = r"(?P<root>/media/usb/(?P<slot>[1-9][0-9]*)/(?P<volume>[A-Za-z0-9][A-Za-z0-9_-]{0,63}))"
_SOURCE = _USB_ROOT + r"/\.whatsnew\.tar\.gz"
_DESTINATION = r"/update/whatsnew/temp/\.whatsnew\.tar\.gz"

DECRYPTION_RE = re.compile(
    rf"^\[{_TIMESTAMP}\] \[decryptionFile\] command "
    rf"/app/share/AppUpgrade/DecryptToPIPE -d "
    rf"(?P<token>/tmp/[0-9a-f]{{32}}) (?P<source>{_SOURCE}) 0 "
    rf"\| dd of=(?P<destination>{_DESTINATION}) bs=512$"
)
COPY_PREFIX_RE = re.compile(rf"^\[{_TIMESTAMP}\] \[copyWhatsNewFiles\] (?P<body>.+?)[ ]*$")
COPY_CONFIG_RE = re.compile(
    rf"^(?P<label>s_package_systemdir|s_package_controlsdir) "
    rf"(?P<root>/media/usb/(?P<slot>[1-9][0-9]*)/(?P<volume>[A-Za-z0-9][A-Za-z0-9_-]{{0,63}}))"
    rf"(?P<suffix>/whatsnew/whatsnew(?:_controls)?)$"
)
COPY_DEST_CONFIG_RE = re.compile(
    r"^(?P<label>s_whatsnew_systemdir|s_whatsnew_controlsdir) "
    r"(?P<path>/update/whatsnew/whatsnew(?:_controls)?_new)$"
)
COPY_TRANSFER_RE = re.compile(
    rf"^(?P<source>{_SOURCE}) --> (?P<destination>{_DESTINATION})$"
)
COPY_COUNT_RE = re.compile(r"^(?P<label>system|control) countdirs   (?P<count>0|[1-9][0-9]*)$")
PATH_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class ParseError(ValueError):
    """Input is outside the parser's bounded evidence contract."""


@dataclass(frozen=True)
class RelevantRecord:
    line: int
    timestamp: str
    kind: str
    fields: dict[str, Any]


def _validate_timestamp(value: str) -> None:
    try:
        dt.datetime.strptime(value, "%m-%d-%y %H:%M:%S:%f")
    except ValueError as exc:
        raise ParseError("relevant record has an invalid timestamp") from exc


def _validate_path(path: str, what: str) -> None:
    if not path.startswith("/"):
        raise ParseError(f"{what} is not absolute")
    if PATH_CONTROL_RE.search(path):
        raise ParseError(f"{what} contains a control character")
    if "//" in path:
        raise ParseError(f"{what} contains an empty component")
    parts = path.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ParseError(f"{what} contains traversal or an empty component")


def _read_stable_regular_file(path: Path) -> bytes:
    """Read one non-symlink regular file with before/after identity checks."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise ParseError(f"cannot stat log: {exc.strerror}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ParseError("log is not a regular non-symlink file")
    if before.st_size < 0 or before.st_size > MAX_LOG_BYTES:
        raise ParseError("log exceeds the pre-read size bound")

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ParseError(f"cannot open log: {exc.strerror}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ParseError("opened log is not a regular file")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ParseError("log identity changed before read")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_LOG_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_LOG_BYTES:
                raise ParseError("log exceeds the read size bound")
        after_fd = os.fstat(fd)
    finally:
        os.close(fd)
    try:
        after_path = path.lstat()
    except OSError as exc:
        raise ParseError(f"cannot restat log: {exc.strerror}") from exc

    stable_fields_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    stable_fields_opened = (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    )
    stable_fields_after_fd = (
        after_fd.st_dev,
        after_fd.st_ino,
        after_fd.st_size,
        after_fd.st_mtime_ns,
        after_fd.st_ctime_ns,
    )
    stable_fields_after_path = (
        after_path.st_dev,
        after_path.st_ino,
        after_path.st_size,
        after_path.st_mtime_ns,
        after_path.st_ctime_ns,
    )
    raw = b"".join(chunks)
    if not stat.S_ISREG(after_path.st_mode) or not (
        stable_fields_before
        == stable_fields_opened
        == stable_fields_after_fd
        == stable_fields_after_path
    ):
        raise ParseError("log changed while being read")
    if len(raw) != before.st_size:
        raise ParseError("log length changed while being read")
    return raw


def _normalized_usb_archive() -> dict[str, str]:
    return {
        "class": "removable_usb_whatsnew_archive",
        "normalized": "/media/usb/{slot}/{volume}/.whatsnew.tar.gz",
    }


def _normalized_destination_archive() -> dict[str, str]:
    return {
        "class": "update_whatsnew_temp_archive",
        "normalized": "/update/whatsnew/temp/.whatsnew.tar.gz",
    }


def _record_ref(record: RelevantRecord) -> dict[str, Any]:
    result: dict[str, Any] = {"line": record.line, "timestamp": record.timestamp}
    if record.kind.startswith("config:"):
        result["record"] = record.kind.split(":", 1)[1]
        result["path_class"] = record.fields["path_class"]
        result["normalized_path"] = record.fields["normalized_path"]
    elif record.kind == "transfer":
        result["record"] = "archive_transfer"
        result["source"] = _normalized_usb_archive()
        result["destination"] = _normalized_destination_archive()
    elif record.kind.startswith("count:"):
        result["record"] = record.kind.replace(":", "_")
        result["count"] = record.fields["count"]
    else:
        raise ParseError("internal unsupported context record")
    return result


def _parse_copy(line_number: int, match: re.Match[str]) -> RelevantRecord:
    timestamp = match.group("timestamp")
    _validate_timestamp(timestamp)
    body = match.group("body")
    config = COPY_CONFIG_RE.fullmatch(body)
    if config:
        path = config.group("root") + config.group("suffix")
        _validate_path(path, "copy source configuration path")
        label = config.group("label")
        expected_suffix = {
            "s_package_systemdir": "/whatsnew/whatsnew",
            "s_package_controlsdir": "/whatsnew/whatsnew_controls",
        }[label]
        if config.group("suffix") != expected_suffix:
            raise ParseError(f"line {line_number}: copy configuration label/path mismatch")
        return RelevantRecord(
            line_number,
            timestamp,
            f"config:{label}",
            {
                "root_key": (config.group("slot"), config.group("volume")),
                "path_class": "removable_usb_whatsnew_tree",
                "normalized_path": "/media/usb/{slot}/{volume}" + expected_suffix,
            },
        )
    destination_config = COPY_DEST_CONFIG_RE.fullmatch(body)
    if destination_config:
        path = destination_config.group("path")
        _validate_path(path, "copy destination configuration path")
        label = destination_config.group("label")
        expected_path = {
            "s_whatsnew_systemdir": "/update/whatsnew/whatsnew_new",
            "s_whatsnew_controlsdir": "/update/whatsnew/whatsnew_controls_new",
        }[label]
        if path != expected_path:
            raise ParseError(f"line {line_number}: copy destination label/path mismatch")
        return RelevantRecord(
            line_number,
            timestamp,
            f"config:{label}",
            {"path_class": "update_whatsnew_destination_tree", "normalized_path": path},
        )
    transfer = COPY_TRANSFER_RE.fullmatch(body)
    if transfer:
        source = transfer.group("source")
        destination = transfer.group("destination")
        _validate_path(source, "copy transfer source")
        _validate_path(destination, "copy transfer destination")
        return RelevantRecord(
            line_number,
            timestamp,
            "transfer",
            {
                "root_key": (transfer.group("slot"), transfer.group("volume")),
                "source": source,
                "destination": destination,
            },
        )
    count = COPY_COUNT_RE.fullmatch(body)
    if count:
        value = int(count.group("count"), 10)
        if isinstance(value, bool) or value > 1_000_000:
            raise ParseError(f"line {line_number}: copy count is outside bounds")
        return RelevantRecord(
            line_number,
            timestamp,
            f"count:{count.group('label')}",
            {"count": value},
        )
    raise ParseError(f"line {line_number}: unexpected copyWhatsNewFiles record shape")


def _parse_records(text: str) -> tuple[list[RelevantRecord], list[RelevantRecord]]:
    # The authentic log uses horizontal tabs in unrelated records. Preserve that
    # one structural character, but reject every other non-LF control globally;
    # relevant record grammar permits spaces only and path validation rejects all.
    if "\r" in text:
        raise ParseError("log must use LF rather than CR/CRLF")
    if any((ord(char) < 0x20 and char not in ("\n", "\t")) or 0x7F <= ord(char) <= 0x9F for char in text):
        raise ParseError("log contains an unsupported control character")
    if not text.endswith("\n"):
        raise ParseError("log must end with LF")
    lines = text.split("\n")[:-1]
    if len(lines) > MAX_LINES:
        raise ParseError("log has too many lines")

    decryptions: list[RelevantRecord] = []
    copies: list[RelevantRecord] = []
    seen_relevant: set[tuple[str, str, str]] = set()
    seen_tokens: set[str] = set()
    seen_invocations: set[tuple[str, str, str]] = set()
    for line_number, line in enumerate(lines, start=1):
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise ParseError(f"line {line_number} exceeds the line-size bound")
        relevant: RelevantRecord | None = None
        if "[decryptionFile]" in line:
            match = DECRYPTION_RE.fullmatch(line)
            if match is None:
                raise ParseError(f"line {line_number}: unexpected decryptionFile command shape")
            timestamp = match.group("timestamp")
            _validate_timestamp(timestamp)
            source = match.group("source")
            destination = match.group("destination")
            token = match.group("token")
            _validate_path(token, "transient token path")
            _validate_path(source, "decryption source")
            _validate_path(destination, "decryption destination")
            if token in seen_tokens:
                raise ParseError(f"line {line_number}: duplicate transient token")
            seen_tokens.add(token)
            invocation_key = (timestamp, source, destination)
            if invocation_key in seen_invocations:
                raise ParseError(f"line {line_number}: duplicate decryption invocation")
            seen_invocations.add(invocation_key)
            relevant = RelevantRecord(
                line_number,
                timestamp,
                "decryption",
                {
                    "root_key": (match.group("slot"), match.group("volume")),
                    "source": source,
                    "destination": destination,
                },
            )
            decryptions.append(relevant)
            if len(decryptions) > MAX_INVOCATIONS:
                raise ParseError("too many decryption invocations")
        elif "[copyWhatsNewFiles]" in line:
            match = COPY_PREFIX_RE.fullmatch(line)
            if match is None:
                raise ParseError(f"line {line_number}: unexpected copyWhatsNewFiles record shape")
            relevant = _parse_copy(line_number, match)
            copies.append(relevant)

        if relevant is not None:
            duplicate_key = (relevant.kind, relevant.timestamp, repr(sorted(relevant.fields.items())))
            if duplicate_key in seen_relevant:
                raise ParseError(f"line {line_number}: duplicate relevant record")
            seen_relevant.add(duplicate_key)
            if len(seen_relevant) > MAX_RELEVANT_RECORDS:
                raise ParseError("too many relevant records")
    if not decryptions:
        raise ParseError("no decryptionFile records found")
    return decryptions, copies


def _select_unique(records: list[RelevantRecord], kind: str, event_line: int, scope: str) -> RelevantRecord | None:
    matches = [record for record in records if record.kind == kind]
    if len(matches) > 1:
        raise ParseError(f"line {event_line}: ambiguous {scope} {kind} context")
    return matches[0] if matches else None


def _context_for(event: RelevantRecord, copies: list[RelevantRecord]) -> dict[str, Any]:
    before = [
        record
        for record in copies
        if event.line - CONTEXT_BEFORE_LINES <= record.line < event.line
    ]
    after = [
        record
        for record in copies
        if event.line < record.line <= event.line + CONTEXT_AFTER_LINES
    ]
    before_kinds = (
        "config:s_package_systemdir",
        "config:s_package_controlsdir",
        "config:s_whatsnew_systemdir",
        "config:s_whatsnew_controlsdir",
    )
    after_kinds = ("transfer", "count:system", "count:control")
    selected_before = [_select_unique(before, kind, event.line, "preceding") for kind in before_kinds]
    selected_after = [_select_unique(after, kind, event.line, "following") for kind in after_kinds]
    selected = selected_before + selected_after
    if any(record is None for record in selected):
        return {
            "status": "incomplete_copyWhatsNewFiles_context",
            "records": [_record_ref(record) for record in selected if record is not None],
        }

    complete = [record for record in selected if record is not None]
    package_system, package_controls, whatsnew_system, whatsnew_controls, transfer, _, _ = complete
    consistent = (
        package_system.fields["root_key"] == event.fields["root_key"]
        and package_controls.fields["root_key"] == event.fields["root_key"]
        and transfer.fields["root_key"] == event.fields["root_key"]
        and transfer.fields["source"] == event.fields["source"]
        and transfer.fields["destination"] == event.fields["destination"]
        and whatsnew_system.fields["normalized_path"] == "/update/whatsnew/whatsnew_new"
        and whatsnew_controls.fields["normalized_path"] == "/update/whatsnew/whatsnew_controls_new"
    )
    if not consistent:
        raise ParseError(f"line {event.line}: copyWhatsNewFiles context conflicts with invocation")
    return {
        "status": "matched_copyWhatsNewFiles_context",
        "records": [_record_ref(record) for record in complete],
    }


def build_report(raw: bytes, *, synthetic_test: bool) -> dict[str, Any]:
    digest = hashlib.sha256(raw).hexdigest()
    if not synthetic_test and digest != EXPECTED_LOG_SHA256:
        raise ParseError("log SHA-256 does not match the required public-log identity")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ParseError("log is not valid UTF-8") from exc
    decryptions, copies = _parse_records(text)

    events: list[dict[str, Any]] = []
    context_counts: dict[str, int] = {}
    for event in decryptions:
        context = _context_for(event, copies)
        status = context["status"]
        context_counts[status] = context_counts.get(status, 0) + 1
        events.append(
            {
                "line": event.line,
                "timestamp": event.timestamp,
                "source": _normalized_usb_archive(),
                "destination": _normalized_destination_archive(),
                "context": context,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "input": {
            "mode": "synthetic-test" if synthetic_test else "expected-public-log",
            "sha256": digest,
            "size_bytes": len(raw),
            "expected_sha256_status": "not_required_synthetic_test" if synthetic_test else "matched",
        },
        "observation": {
            "decryption_file_record_count": len(decryptions),
            "copy_whats_new_files_record_count": len(copies),
            "runtime_invocation_status": "observed_in_supplied_log",
            "source_path_classes": [_normalized_usb_archive()],
            "destination_path_classes": [_normalized_destination_archive()],
            "copy_context_status_counts": dict(sorted(context_counts.items())),
            "events": events,
        },
        "identity_and_mechanism": {
            "logged_build_identity_status": "unknown_no_binary_identity_in_log",
            "logged_build_equals_exact_elf_status": "unknown",
            "exact_elf_sha256_for_separate_static_evidence": EXACT_ELF_SHA256,
            "invocation_mechanism_status": "unknown_log_does_not_distinguish_direct_meta_or_indirect_dispatch",
        },
        "unknowns": [
            "binary identity of the AppUpgrade build that wrote the log",
            "whether the logged build equals the separately recovered exact ELF",
            "whether any logged invocation used a direct call, generated Qt meta-call, or another mechanism",
            "external or D-Bus reachability",
            "attacker control of either pathname or invocation timing",
            "update acceptance, effective privilege, root, and persistence",
        ],
    }


def _emit_json(report: dict[str, Any]) -> None:
    encoded = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    sys.stdout.buffer.write(encoded)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        allow_abbrev=False,
    )
    parser.add_argument("--log", required=True, help="explicit AppUpgrade regular log file")
    parser.add_argument(
        "--synthetic-test",
        action="store_true",
        help="explicitly permit a non-public-log hash for bounded synthetic tests",
    )
    args = parser.parse_args(argv)
    try:
        raw = _read_stable_regular_file(Path(args.log))
        report = build_report(raw, synthetic_test=args.synthetic_test)
    except ParseError as exc:
        sys.stderr.buffer.write((f"error: {exc}\n").encode("utf-8"))
        return 2
    _emit_json(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
