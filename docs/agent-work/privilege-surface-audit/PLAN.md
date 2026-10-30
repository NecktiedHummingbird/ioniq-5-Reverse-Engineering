# Privilege-surface audit plan

## Objective

Build a deterministic, read-only analyzer for an extracted embedded-Linux root
filesystem. It should identify defensible local privilege-boundary candidates
without inferring exploitability from version strings or unsafe-looking text
alone.

## Non-goals

- No payloads, races, shellcode, privilege changes, device access, or execution
  of recovered target binaries.
- No writes to the analyzed rootfs or ignored firmware inputs.
- No claim that a candidate yields root without exact caller, permissions, and
  runtime reachability evidence.
- No bulk inclusion of proprietary binaries or full extracted metadata in Git.

## Phase 1 — deterministic analyzer

Add `tools/uk_fw/privilege_surface.py` and focused tests. The tool accepts one
rootfs directory and writes JSON to stdout or `--output`. It must:

1. reject non-directories, symlink roots, and output paths inside the analyzed
   tree;
2. never follow symlinks while walking;
3. inventory setuid/setgid regular files and executable world/group-writable
   regular files/directories;
4. inspect Linux file-capability xattrs when available, recording raw bytes and
   decode status without silently treating unavailable host xattrs as absence on
   the source filesystem;
5. parse systemd service files sufficiently to record effective default-root
   execution, `User=`, `Group=`, `ExecStart*`, `EnvironmentFile=`, and path
   existence/mode/ownership beneath the rootfs;
6. inventory `ld.so.preload`, `ld.so.conf`/included files, writable loader search
   paths, and absolute library paths referenced by service environment;
7. inventory udev rules that assign permissive modes or non-root ownership to
   device nodes, retaining the exact rule location and text;
8. emit deterministic sorted JSON with schema version, root identity, counts,
   findings, warnings, and explicit evidence limitations.

The scanner may use Python's standard library only. It must not invoke target
executables, mount images, or require root.

## Acceptance

- Unit tests cover symlink-root rejection, no symlink traversal, deterministic
  ordering, service default-root semantics, `User=` override, writable service
  executable/config paths, loader configuration, permissive udev rules, and xattr
  unavailable/error reporting.
- `python -m pytest -q tests/test_privilege_surface.py` passes.
- `python -m py_compile tools/uk_fw/privilege_surface.py` passes.
- A bounded run against the recovered directory completes and writes its full
  report only under ignored `work/`; tracked documentation may retain only
  reviewed summary facts.

## Phase 2 — evidence-led follow-up

After Phase 1 acceptance, run the analyzer against the recovered userspace,
review high-confidence results against exact files/binaries, and select one or
more bounded static or VM confirmations. Online CVE research must be tied to exact
component identity and shipped-code checks; version matches remain candidates.
