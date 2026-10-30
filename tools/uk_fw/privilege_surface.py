#!/usr/bin/env python3
"""Deterministic, read-only privilege-surface inventory for extracted Linux trees.

The analyzer never executes target files, follows no symlink while walking, and
makes no exploitability claim. Host-visible ownership, modes, and xattrs may not
faithfully reproduce the source filesystem; the JSON records that limitation.
"""
from __future__ import annotations

import argparse
import errno
import glob
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import tempfile
from typing import Any, Iterable

SCHEMA_VERSION = 1
SERVICE_DIRS = ("etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system")
UDEV_DIRS = ("etc/udev/rules.d", "lib/udev/rules.d", "usr/lib/udev/rules.d")
DEFAULT_LIBRARY_DIRS = ("lib", "lib64", "usr/lib", "usr/lib64")
CAP_XATTR = "security.capability"
MODE_RE = re.compile(r'\bMODE\s*(?::=|=)\s*"?([0-7]{3,4})"?')
OWNER_RE = re.compile(r'\bOWNER\s*(?::=|=)\s*"?([^",\s]+)')
GROUP_RE = re.compile(r'\bGROUP\s*(?::=|=)\s*"?([^",\s]+)')
INCLUDE_RE = re.compile(r"^include\s+(.+)$", re.I)


class AuditError(ValueError):
    """Unsafe or unsupported audit request."""


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_root(root: Path) -> Path:
    if root.is_symlink():
        raise AuditError("rootfs directory must not be a symlink")
    try:
        resolved = root.resolve(strict=True)
    except FileNotFoundError as exc:
        raise AuditError("rootfs directory does not exist") from exc
    if not resolved.is_dir():
        raise AuditError("rootfs path must be a directory")
    return resolved


def validate_output(output: Path | None, root: Path) -> Path | None:
    if output is None:
        return None
    if output.exists() and output.is_symlink():
        raise AuditError("output must not be a symlink")
    parent = output.parent.resolve(strict=True)
    candidate = parent / output.name
    if _inside(candidate, root):
        raise AuditError("output must be outside the analyzed rootfs")
    if output.exists() and not output.is_file():
        raise AuditError("output must be a regular file")
    return candidate


def rel_name(path: Path, root: Path) -> str:
    return "/" + path.relative_to(root).as_posix()


def walk_no_symlinks(root: Path) -> tuple[list[Path], list[str]]:
    """Return sorted non-symlink descendants without traversing links."""
    found: list[Path] = []
    warnings: list[str] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            warnings.append(f"walk-error:{rel_name(directory, root)}:{exc.errno}")
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                if entry.is_symlink():
                    continue
                found.append(path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
            except OSError as exc:
                warnings.append(f"stat-error:{rel_name(path, root)}:{exc.errno}")
    found.sort(key=lambda path: rel_name(path, root))
    return found, sorted(set(warnings))


def mode_record(path: Path, root: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"path": rel_name(path, root)}
    try:
        st = path.lstat()
    except OSError as exc:
        info.update({"exists": False, "error": exc.errno})
        return info
    info.update({
        "exists": True,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": f"{stat.S_IMODE(st.st_mode):04o}",
        "kind": (
            "symlink" if stat.S_ISLNK(st.st_mode) else
            "directory" if stat.S_ISDIR(st.st_mode) else
            "regular" if stat.S_ISREG(st.st_mode) else "other"
        ),
        "group_writable": bool(st.st_mode & stat.S_IWGRP),
        "world_writable": bool(st.st_mode & stat.S_IWOTH),
    })
    if stat.S_ISLNK(st.st_mode):
        try:
            info["link_target"] = os.readlink(path)
        except OSError as exc:
            info["link_error"] = exc.errno
    return info


def root_path(root: Path, value: str) -> Path | None:
    """Map an absolute target path without crossing an intermediate symlink."""
    if not value.startswith("/"):
        return None
    pure = PurePosixPath(value)
    if ".." in pure.parts:
        return None
    parts = pure.parts[1:]
    current = root
    for part in parts[:-1]:
        if glob.has_magic(part):
            return None
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            break
        except OSError:
            return None
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            return None
    return root.joinpath(*parts)


def read_text(path: Path, limit: int = 2 * 1024 * 1024) -> tuple[str | None, str | None]:
    try:
        if path.is_symlink() or not path.is_file():
            return None, "not-regular-or-symlink"
        if path.stat().st_size > limit:
            return None, "size-limit"
        return path.read_text(encoding="utf-8", errors="replace"), None
    except OSError as exc:
        return None, f"read-error:{exc.errno}"


def joined_lines_with_numbers(text: str) -> list[tuple[int, str]]:
    """Join continuations while retaining the first physical source line."""
    result: list[tuple[int, str]] = []
    current = ""
    start = 1
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not current:
            start = number
        if line.endswith("\\"):
            current += line[:-1] + " "
            continue
        result.append((start, current + line))
        current = ""
    if current:
        result.append((start, current))
    return result


def joined_lines(text: str) -> list[str]:
    return [line for _, line in joined_lines_with_numbers(text)]


def parse_unit(text: str) -> dict[str, list[str]]:
    section = ""
    directives: dict[str, list[str]] = {}
    for raw in joined_lines(text):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section != "service" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        directives.setdefault(key.strip().lower(), []).append(value.strip())
    return directives


def split_words(value: str) -> list[str]:
    try:
        return shlex.split(value, posix=True)
    except ValueError:
        return value.split()


def command_path(value: str) -> str | None:
    words = split_words(value)
    if not words:
        return None
    token = words[0]
    while token and token[0] in "-+!@:":
        token = token[1:]
    return token if token.startswith("/") else None


def env_assignments(values: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if not value:
            result.clear()
            continue
        for word in split_words(value):
            if "=" in word:
                key, val = word.split("=", 1)
                result[key] = val
    return result


def service_inventory(root: Path, paths: list[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    allowed = {root / item for item in SERVICE_DIRS}
    services: list[dict[str, Any]] = []
    warnings: list[str] = []
    for path in paths:
        if path.suffix != ".service" or path.parent not in allowed:
            continue
        text, error = read_text(path)
        if error:
            warnings.append(f"service-{error}:{rel_name(path, root)}")
            continue
        assert text is not None
        directives = parse_unit(text)
        users = directives.get("user", [])
        groups = directives.get("group", [])
        exec_values = [
            value
            for key in ("execstart", "execstartpre", "execstartpost", "execreload", "execstop")
            for value in directives.get(key, [])
        ]
        exec_paths = sorted({item for item in (command_path(v) for v in exec_values) if item})
        env_files: list[dict[str, Any]] = []
        env_file_values: list[str] = []
        for value in directives.get("environmentfile", []):
            if not value:
                env_file_values.clear()
                env_files.clear()
                continue
            for word in split_words(value):
                optional = word.startswith("-")
                target = word[1:] if optional else word
                env_file_values.append(target)
                mapped = root_path(root, target)
                record: dict[str, Any] = {"value": target, "optional": optional}
                if mapped is not None:
                    record["path_info"] = mode_record(mapped, root)
                env_files.append(record)
        environment = env_assignments(directives.get("environment", []))
        for target in env_file_values:
            mapped = root_path(root, target)
            if mapped is None:
                continue
            env_text, _ = read_text(mapped, limit=256 * 1024)
            if env_text:
                for line in env_text.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#") and "=" in stripped:
                        key, val = stripped.split("=", 1)
                        environment[key.strip()] = val.strip().strip('"\'')
        library_components: list[str] = []
        for key in ("LD_LIBRARY_PATH", "LD_PRELOAD"):
            value = environment.get(key, "")
            separator = r":" if key == "LD_LIBRARY_PATH" else r"[:\s]+"
            library_components.extend(re.split(separator, value))
        library_paths = sorted({item for item in library_components if item.startswith("/")})
        services.append({
            "path": rel_name(path, root),
            "user": users[-1] if users else None,
            "group": groups[-1] if groups else None,
            "effective_default_root": not users or users[-1] in ("", "root", "0"),
            "exec": [
                {"value": item, "path_info": mode_record(root_path(root, item), root)}
                for item in exec_paths
                if root_path(root, item) is not None
            ],
            "environment_files": env_files,
            "absolute_loader_environment": [
                {"value": item, "path_info": mode_record(root_path(root, item), root)}
                for item in library_paths
                if root_path(root, item) is not None
            ],
        })
    services.sort(key=lambda item: item["path"])
    return services, sorted(set(warnings))


def parse_loader_file(root: Path, path: Path, seen: set[Path], warnings: list[str]) -> list[str]:
    if path in seen:
        return []
    seen.add(path)
    text, error = read_text(path, limit=256 * 1024)
    if error:
        warnings.append(f"loader-{error}:{rel_name(path, root)}")
        return []
    assert text is not None
    values: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = INCLUDE_RE.match(line)
        if match:
            pattern = match.group(1).strip()
            mapped = root_path(root, pattern)
            if mapped is None:
                warnings.append(f"loader-relative-include:{line}")
                continue
            for name in sorted(glob.glob(str(mapped))):
                child = Path(name)
                if not _inside(child, root):
                    continue
                relative = "/" + child.relative_to(root).as_posix()
                safe_child = root_path(root, relative)
                if safe_child is not None:
                    values.extend(parse_loader_file(root, safe_child, seen, warnings))
            continue
        if line.startswith("/"):
            values.append(line)
    return values


def loader_inventory(root: Path) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    config = root_path(root, "/etc/ld.so.conf")
    search = (
        parse_loader_file(root, config, set(), warnings)
        if config is not None and config.exists() else []
    )
    for item in DEFAULT_LIBRARY_DIRS:
        mapped = root_path(root, "/" + item)
        if mapped is not None and mapped.exists():
            search.append("/" + item)
    search = sorted(set(search))
    search_info = []
    for item in search:
        mapped = root_path(root, item)
        if mapped is not None:
            search_info.append({"value": item, "path_info": mode_record(mapped, root)})
    preload = root_path(root, "/etc/ld.so.preload")
    preload_entries: list[dict[str, Any]] = []
    if preload is not None and preload.exists():
        text, error = read_text(preload, limit=256 * 1024)
        if error:
            warnings.append(f"preload-{error}:/etc/ld.so.preload")
        elif text is not None:
            for word in split_words(" ".join(line.split("#", 1)[0] for line in text.splitlines())):
                record: dict[str, Any] = {"value": word}
                mapped = root_path(root, word)
                if mapped is not None:
                    record["path_info"] = mode_record(mapped, root)
                preload_entries.append(record)
    return {
        "search_paths": search_info,
        "preload_file": mode_record(preload, root) if preload is not None and preload.exists() else None,
        "preload_entries": sorted(preload_entries, key=lambda item: item["value"]),
    }, sorted(set(warnings))


def udev_inventory(root: Path, paths: list[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    allowed = {root / item for item in UDEV_DIRS}
    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    for path in paths:
        if path.suffix != ".rules" or path.parent not in allowed:
            continue
        text, error = read_text(path, limit=512 * 1024)
        if error:
            warnings.append(f"udev-{error}:{rel_name(path, root)}")
            continue
        assert text is not None
        for number, raw in joined_lines_with_numbers(text):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            mode_match = MODE_RE.search(line)
            owner_match = OWNER_RE.search(line)
            group_match = GROUP_RE.search(line)
            mode = int(mode_match.group(1), 8) if mode_match else None
            permissive_mode = mode is not None and bool(mode & 0o077)
            non_root_owner = owner_match is not None and owner_match.group(1) not in ("root", "0")
            non_root_group = group_match is not None and group_match.group(1) not in ("root", "0")
            if permissive_mode or non_root_owner or non_root_group:
                findings.append({
                    "path": rel_name(path, root),
                    "line": number,
                    "mode": f"{mode:04o}" if mode is not None else None,
                    "owner": owner_match.group(1) if owner_match else None,
                    "group": group_match.group(1) if group_match else None,
                    "text": line,
                })
    findings.sort(key=lambda item: (item["path"], item["line"], item["text"]))
    return findings, sorted(set(warnings))


def get_xattr(path: Path, name: str) -> bytes:
    getter = getattr(os, "getxattr", None)
    if getter is None:
        raise AttributeError("os.getxattr is unavailable on this host")
    return getter(path, name, follow_symlinks=False)


def capability_inventory(root: Path, paths: list[Path]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    errors: dict[str, int] = {}
    checked = 0
    absent = 0
    for path in paths:
        try:
            st = path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            continue
        checked += 1
        try:
            raw = get_xattr(path, CAP_XATTR)
        except AttributeError:
            errors["api-unavailable"] = errors.get("api-unavailable", 0) + 1
            break
        except OSError as exc:
            if exc.errno in (getattr(errno, "ENODATA", -1), getattr(errno, "ENOATTR", -1)):
                absent += 1
            else:
                key = errno.errorcode.get(exc.errno, str(exc.errno))
                errors[key] = errors.get(key, 0) + 1
            continue
        revision = int.from_bytes(raw[:4], "little") if len(raw) >= 4 else None
        entries.append({
            "path": rel_name(path, root),
            "raw_hex": raw.hex(),
            "decode_status": "header-only" if revision is not None else "truncated",
            "revision_flags": revision,
        })
    entries.sort(key=lambda item: item["path"])
    return {
        "checked_host_executables": checked,
        "host_xattr_absent": absent,
        "errors": [{"kind": key, "count": errors[key]} for key in sorted(errors)],
        "entries": entries,
        "interpretation": (
            "Host-visible extraction xattrs only; absent or unavailable xattrs do not prove "
            "the source filesystem lacked file capabilities."
        ),
    }


def audit(root_arg: Path) -> dict[str, Any]:
    root = validate_root(root_arg)
    paths, walk_warnings = walk_no_symlinks(root)
    setid: list[dict[str, Any]] = []
    writable_exec: list[dict[str, Any]] = []
    writable_dirs: list[dict[str, Any]] = []
    for path in paths:
        try:
            st = path.lstat()
        except OSError:
            continue
        mode = st.st_mode
        if stat.S_ISREG(mode) and mode & (stat.S_ISUID | stat.S_ISGID):
            record = mode_record(path, root)
            record["setuid"] = bool(mode & stat.S_ISUID)
            record["setgid"] = bool(mode & stat.S_ISGID)
            setid.append(record)
        if stat.S_ISREG(mode) and mode & 0o111 and mode & (stat.S_IWGRP | stat.S_IWOTH):
            writable_exec.append(mode_record(path, root))
        if stat.S_ISDIR(mode) and mode & (stat.S_IWGRP | stat.S_IWOTH):
            writable_dirs.append(mode_record(path, root))
    services, service_warnings = service_inventory(root, paths)
    loader, loader_warnings = loader_inventory(root)
    udev, udev_warnings = udev_inventory(root, paths)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "root": str(root),
        "limitations": [
            "Read-only static inventory; no target executable was run.",
            "Host-visible uid/gid/mode/xattr metadata may differ from the source image.",
            "A listed condition is a review candidate, not proof of exploitability or root access.",
            "Symlinks are skipped and never traversed.",
        ],
        "counts": {
            "walked_non_symlink_entries": len(paths),
            "setid_files": len(setid),
            "writable_executables": len(writable_exec),
            "writable_directories": len(writable_dirs),
            "services": len(services),
            "udev_rules": len(udev),
        },
        "findings": {
            "setid_files": sorted(setid, key=lambda item: item["path"]),
            "group_or_world_writable_executables": sorted(writable_exec, key=lambda item: item["path"]),
            "group_or_world_writable_directories": sorted(writable_dirs, key=lambda item: item["path"]),
            "services": services,
            "loader": loader,
            "udev_rules": udev,
            "file_capabilities": capability_inventory(root, paths),
        },
        "warnings": sorted(set(walk_warnings + service_warnings + loader_warnings + udev_warnings)),
    }
    return report


def write_output_atomic(output: Path, rendered: str) -> None:
    """Replace output without following an existing symlink or hard link."""
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path, help="extracted Linux root directory")
    parser.add_argument("--output", type=Path, help="JSON path outside the analyzed tree")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = validate_root(args.rootfs)
        output = validate_output(args.output, root)
        report = audit(root)
    except (AuditError, OSError) as exc:
        raise SystemExit(f"error: {exc}") from exc
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output is None:
        print(rendered, end="")
    else:
        write_output_atomic(output, rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
