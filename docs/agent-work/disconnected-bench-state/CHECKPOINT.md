# Disconnected bench state bundle checkpoint

Status: implemented, extended for FUMO relaunch state, independently
re-reviewed, and locally accepted on 2026-11-01.

## Completed

- `tools/uk_fw/bench_state_bundle.py`
  - emits and statically audits a fixed, read-only POSIX-shell probe;
  - hex-frames every command/file record and suppresses unframed diagnostics;
  - limits process command lines to named daemons under review and filters the
    kernel command line to boot/trust fields plus a full-line SHA-256;
  - does not mount, start/stop services, alter radios, query modem control
    planes, contact network peers, signal processes, or write target files;
  - parses serial timestamps offline with exact section/schema/status/completion
    validation, 64 MiB capture and 8 MiB line/section bounds, and capture,
    section, and canonical-report hashes;
  - passively records FUMO mode and local-relaunch state
    (`disableEncryptionUpdate`, `disableNaviMapSignatureCheck_20230207`,
    `force_launch`, completion markers, update-directory metadata, staged
    AppUpgrade/XML hashes, and `/tmp/AppUpgrade`) without creating or changing
    any marker;
  - distinguishes absent from unreadable/read-error state and fails the terminal
    completion verdict on failed reads, metadata/link queries, passive commands,
    or malformed/empty hash output.
- `tools/uk_fw/rootfs_patch.py`
  - rejects absolute/traversal/drive/backslash paths, normalized duplicates,
    links, FIFOs and device nodes;
  - confines injection destinations and refuses existing, in-place, symlink and
    hard-link-alias package/manifest outputs, including cross-aliases to the
    rebuilt package;
  - emits USTAR directly while preserving numeric uid/gid/mode/mtime and
    top-level dotfile names, independent of host ownership;
  - stages read-only directory modes without blocking descendant extraction.
- Updated the bench runbook, custom-firmware build note, handover, changelog and
  append-only history.

## Review corrections

The first review found incomplete-verdict, unframed-stderr, size-accounting,
hard-link, duplicate-directory, and read-only-directory defects. The second
found raw-line/conflicting-schema acceptance, `command -v` stdout, whole-capture
line splitting, top-level dotfile renaming, and a manifest/rebuilt cross-alias.
All are covered by regression tests. The final root review also changed package
and manifest outputs to exclusive new-file creation. The FUMO-state extension
received separate correction rounds for writer coverage, scoped relaunch claims,
provider failures, and terminal fail-closed semantics; the corrected diff was
independently accepted.

## Validation

```text
346 passed, 109 subtests passed
public harness: PASS (pass=3, info=4, no pending/blocked/fail)
probe audit: safe=true, syntax_ok=true, violations=[]
probe SHA-256: e5759a8410ffe4fcb1d37e2d55ecdc981e2be9794fee42bdf670897a8c78fb05
git diff --check: PASS
py_compile: PASS
```

No physical unit, target network, radio, modem, firmware update, recovered
executable, or active exploit input was used.

## Delegation/routing

- Fable route check failed because `openrouter/claude-fable-5.1` is not
  advertised for native subagents (`multi_agent_version != v2`). No router
  configuration was changed and no private target data was sent to Fable.
- DeepSeek Flash remained static-ready only and was not substituted.
- Generic read-only child reports:
  - `2f0cbd80-0a7d-4050-adc5-6c76bdaed852`: public update-system trust and
    offline acceptance model;
  - `1cc317d2-2adf-48c4-a384-06c9963cd44a`: passive collector design.
- Independent implementation review ran on the current selected model and
  returned two correction rounds; acceptance is based on the corrected diff and
  local regression evidence, not on route self-report.

## Next exact actions

1. On return of an owner-controlled disconnected bench, emit/audit the probe,
   run it through an already-available console without copying it to storage,
   and parse the retained stdout before any active test.
2. Compare installed hashes/state with V-015 through V-020 and the recovered
   Dropbear conclusion; do not promote absence/denial/truncation to a negative.
   V-020-specific passive fields now cover BusyBox/unzip providers,
   AppLauncher/AppDMClient/AppScomoDM/AppUpgrade, `CarOption.csv`,
   `DecryptToPIPE`, the public key, effective arguments, uid, SMACK labels,
   relaunch/completion markers, and staged `/update/usb/bin` identities.
3. Use the captured A/B flags and current root only after a full partition dump
   and restore rehearsal to plan any update acceptance experiment.
4. Offline, continue exact `AppUpgrade` child analysis of descriptor semantics,
   TE2 metadata use, manifest-to-payload binding, version comparison, payload
   targets, inactive-slot writes, boot selection, and mark-good. AppScomoDM USB
   staging and its pre-auth BusyBox boundary are now separately documented.
