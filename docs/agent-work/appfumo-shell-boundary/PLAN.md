# AppFUMO shell boundary exact-static plan

## Objective

Bind the exact shell-command boundary reached by `AppUpgradeEngine::decryptionFile`
in the hash-identified embedded AppUpgrade ELF, while keeping exact static structure
separate from every runtime, authentication, privilege, root, and persistence
prerequisite.

## Fixed evidence contract

- exact ELF SHA-256: `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`
- Build ID: `863a8730e66a1c5245a1bf458fe2554adee0351a`
- `decryptionFile` FDE: `[0x100b30,0x10110c)`
- direct sink-helper call: `0x100e0c -> 0x1397c0`
- sink-helper FDE: `[0x1397c0,0x1398fb)`
- shell-library call: `popen` at `0x139867`, mode pointer `0x211c8b`
- fixed helper append: `0x20b81c`
- separately bounded neighboring output-returning helper FDE:
  `[0x139900,0x139b46)`
- preserve direct producer calls `0x10281c`, `0x102de9`, and `0x103398`; keep
  generated meta-call `0x16e030` separate.

## Required distinctions

1. Trace the exact split command construction in `[0x100b30,0x10110c)` and all
   QString substitutions. Do not import similar literals from another function.
2. Bind literals `0x20b4d8`, `0x20b500`, and `0x20b530` accurately. The full
   templates at `0x20b500`/`0x20b530` are referenced by the separate FDE
   `[0x60ac0,0x6178f)`, not by the `decryptionFile` FDE.
3. Show that `[0x1397c0,0x1398fb)` drains output with `fgets`, discards it, calls
   `pclose`, and ignores its return. Do not confuse it with the next FDE at
   `0x139900`, which accumulates output into a returned QString.
4. Describe `decryptionFile`'s QString return paths: verifier/key failure yields
   the fixed failure string; after the shell helper it removes the transient key,
   calls `sync`, and returns `destPath` without consuming helper status or checking
   destination existence/size in this FDE.
5. State shell semantics as the contextual contract of `popen`, then limit the
   target-specific conclusion to unquoted/unescaped pathname substitution observed
   in the exact QString chain.
6. Keep pathname control, shell-character survival, invocation reachability,
   authentication/acceptance, process uid/capabilities/SMACK domain, command
   success, privilege/domain amplification, root, and persistence independently
   unknown unless separately evidenced.

## Deliverables

- bounded retained exact-static artifact under
  `evidence/artifacts/update-candidates/`;
- focused assessment under `evidence/`;
- strict Boolean-only non-operational tri-state model under `tools/uk_fw/`;
- focused tests under `tests/`;
- narrow integrations in `HANDOVER.md`, the IONIQ changelog when not already
  absorbed by concurrent work, `evidence/appfumo-authentication-coverage.md`,
  `evidence/appfumo-decryption-runtime-provenance.md`, and
  `evidence/exploit-inventory.md`;
- resumable `CHECKPOINT.md`.

## Safety/non-goals

Static analysis and host-side tests only. Do not execute recovered code, contact a
target/device/network, create an archive/update package, craft a payload or trigger,
bypass a signature, claim root/persistence, stage, commit, or push. Model/report
output must contain no command, target pathname, payload, or trigger instructions.

## Acceptance

Focused tests, full tests-scoped suite, public/privacy harness, `py_compile`,
deterministic report comparison/hash checks, retained artifact hash/anchor checks,
and `git diff --check` pass using the project-approved
`<platformio-env>/bin/python3` without a project-local `TMPDIR`.
