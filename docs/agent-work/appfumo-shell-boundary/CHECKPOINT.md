# AppFUMO shell-boundary checkpoint

Date: 2026-11-08
Original clean bundle baseline: `70467e83cbc26deee907e4029d7aaa3d43463293`
Reviewed integration base: `32baeae8ba009577e2e77239bbfc738c894bb021`
Actual delivery commit: `3f6bd7e60cba92cae364a228c6cb44706d947554`

The reviewed 11-path bundle was staged on the integration base, then absorbed by
concurrent commit `3f6bd7e` before the parent could create its planned dedicated
commit. That commit was pushed to `ioniq/main`. Published history is preserved.

## Bounded result

- Exact ELF identity: SHA-256
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`,
  size `5,066,264`, Build ID `863a8730e66a1c5245a1bf458fe2554adee0351a`.
- `decryptionFile` FDE `[0x100b30,0x10110c)` constructs a command from a
  fixed helper, UUID-derived transient key pathname, incoming `encFile`, and
  incoming `destPath`. The two incoming pathnames occupy unquoted/unescaped
  command fields.
- Direct call `0x100e0c` reaches shared helper FDE
  `[0x1397c0,0x1398fb)`. The helper appends fixed stderr redirection, converts
  to bytes, and calls `popen` at `0x139867` with read mode at `0x211c8b`. It
  drains/discards output, calls `pclose` at `0x1398b0`, and ignores status.
- Neighboring output-accumulating helper `[0x139900,0x139b46)` is a distinct
  FDE, not an alternate entry.
- After the sink, `decryptionFile` removes the transient key, calls `sync`, and
  returns `destPath` without helper-status or destination existence/size checks.
- Full literals at `0x20b500` and `0x20b530` belong to separate FDE
  `[0x60ac0,0x6178f)`, selected by object byte `+0x22`; that function performs
  later destination checks. They are not the split templates used by
  `decryptionFile`.
- Prior producer-family calls `0x10281c`, `0x102de9`, and `0x103398` remain in
  `copyWhatsNewFiles()` FDE `[0x101110,0x104c1b)`; generated meta-call
  `0x16e030` remains separate.
- The supported conclusion is exact unquoted shell-sink structure only.
  Pathname influence, shell-sensitive-character survival, runtime reachability,
  authentication acceptance, process uid/capabilities/SMACK domain, command
  success, privilege/domain amplification, root, and persistence remain
  independent unknowns.

## Deliverables and current hashes

- `tools/uk_fw/appfumo_shell_boundary_model.py`
  - SHA-256 `8ed5e7b78e229d874eee5ded8340f341227bb623280e29076da999760da23116`
- `tests/test_appfumo_shell_boundary_model.py`
  - SHA-256 `87a324274bd1bed454c66611e7c69fae4790ee50b781ab8206a57d70d82b5741`
- `evidence/appfumo-shell-command-boundary.md`
  - SHA-256 `f7e150c3da6ce5b0b2f85bed5c1c02b6981360705535e11e6f6164b393539116`
- `evidence/artifacts/update-candidates/appfumo-shell-boundary-exact-static.asm`
  - SHA-256 `a6bbe8e74630e7a64001a8bad2b5f67846f465473612a14e8bccf3aad47c5510`
- `docs/agent-work/appfumo-shell-boundary/PLAN.md`
  - SHA-256 `51bd1bc725b50a3ba836dea2594daa0b3994047d55b3e7c6893feb66ee1314ee`
- narrow integrations: `HANDOVER.md`,
  `evidence/appfumo-authentication-coverage.md`,
  `evidence/appfumo-decryption-runtime-provenance.md`,
  `evidence/exploit-inventory.md`, and
  `evidence/artifacts/update-candidates/README.md`.

`Ioniq5-CHANGELOG.md` is context-only for this bundle. Concurrent commit
`32baeae8ba009577e2e77239bbfc738c894bb021` had already absorbed the intended
changelog paragraph together with unrelated V-036 work. Delivery commit
`3f6bd7e` contains the 11 reviewed paths listed here plus concurrent changes to
`Ioniq5-CHANGELOG.md`, `Ioniq5-HISTORY.md`, and `Ioniq5-VULNERABILITIES.md`.
Those three paths and the commit title belong to the concurrent VM investigation
and are not attributed to this AppFUMO package.

Deterministic default report SHA-256:
`7702f40e87033dfb9bbb271b3615c0ec5212d17c16c3965b151306e62b38bfc3`.
The report contains no command, target pathname, payload, trigger, archive, or
update material.

## Model semantics

The model consumes strict Boolean evidence only. The exact sink conclusion uses
only the eight facts required to bind the sink. Ignored `pclose` status and
post-sink return handling remain separate static outcome facts. Runtime
shell-syntax delivery depends on sink structure, pathname influence, character
survival, and invocation. Authentication, process context, command success,
amplification, root, and persistence remain distinct outputs.

Causally contradictory inputs are rejected: influenced-character survival
without pathname influence, command success without invocation, amplification
without command success, and root impact without amplification. False means
“not established,” not “disproved.” Exhaustive tests cover all `524,288`
Boolean assignments against an independently stated policy.

## Validation after review corrections

All commands used the project-approved `<platformio-env>/bin/python3`; no
project-local `TMPDIR` was set.

- focused model tests: `12 passed, 168 subtests passed`; optional exact-ELF
  checks ran and all `121` retained instruction-byte rows matched;
- full tests-scoped suite: `694 passed, 351445 subtests passed`;
- `py_compile`: passed for model and focused test;
- deterministic report comparison under ASCII, Latin-1, and UTF-16
  `PYTHONIOENCODING`: byte-identical, one LF, expected hash;
- public harness: `pass=3 info=4 pending=0 blocked=0 fail=0`;
- privacy: `375` files, zero blocking findings, three informational
  public/reserved identifiers;
- tracked and untracked whitespace checks: passed after correcting the initial
  checkpoint trailing whitespace.

## Review and routing record

Daybreak implementation thread `859ac3ca-1e98-4066-9ea5-ea931128779d`
produced the initial bundle. It attempted a prohibited nested delegation; the
route failed before a child ran. No nested worker output or configuration
change resulted.

Independent read-only reviewer
`c5a2e513-8850-4f3f-abe2-4baff6f3a548` returned **CHANGES_REQUIRED** on the
initial bytes while accepting the exact-static analysis. It required separate
sink/delivery/success semantics, a contradiction policy, accurate concurrent
integration provenance, complete whitespace checking, and precise
“no target pathname” wording. The same reviewer then independently checked the
corrected current bytes, all `524,288` Boolean states, exact instruction rows,
deterministic output, hashes, and whitespace, and returned **ACCEPT** with no
remaining blocking or advisory findings.

## Safety

Static analysis and host tests only. No recovered executable/helper or target
code ran. No device, radio, target network, archive/update package, operational
payload/trigger, signature bypass, partition/slot/boot action, privilege action,
root action, or persistence mechanism was created or exercised.
