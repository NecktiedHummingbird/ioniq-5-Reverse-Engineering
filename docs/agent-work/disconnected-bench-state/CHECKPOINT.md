# Disconnected bench state bundle checkpoint

Status: implemented, corrected after two independent read-only review passes,
and locally accepted on 2026-11-01.

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
    section, and canonical-report hashes.
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
and manifest outputs to exclusive new-file creation.

## Validation

```text
295 passed, 72 subtests passed
public harness: PASS
probe audit: safe=true
probe SHA-256: dca6a219dd54a52ecd0bde6ee2d15b3cfed91e0e1e635fdb25e1d609f54af200
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
2. Compare installed hashes/state with V-015 through V-019 and the recovered
   Dropbear conclusion; do not promote absence/denial/truncation to a negative.
3. Use the captured A/B flags and current root only after a full partition dump
   and restore rehearsal to plan any update acceptance experiment.
4. Offline, continue exact `AppSetup`/`AppUpgrade` analysis of verification order,
   TE2 metadata use, manifest-to-payload binding, and version comparison. Keep
   parsing, eligibility, authentication, inactive-slot write, boot selection,
   boot trust, and mark-good as separate verdicts.
