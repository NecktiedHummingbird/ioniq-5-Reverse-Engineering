# AppFUMO `decryptionFile` producer-provenance checkpoint

Date: 2026-11-08
Requested/start baseline: `c886e103c9378cbc6f3884e738f4870bab7a3826`
Final integration-check HEAD: `1d5da8111b26a64d7efaff4c69e368f93bc7ec2c`
Status: **ACCEPT**; staged delivery validation passed.

Five external non-overlapping commits advanced HEAD from the requested baseline
through `4dd644e`, `332fc60`, `bb3fe7b`, and `f2f4bd2` to `1d5da81` and changed only
`Ioniq5-CHANGELOG.md`, `Ioniq5-HISTORY.md`, and `Ioniq5-VULNERABILITIES.md`.
This audit did not create, stage, amend, reset, or push those commits and
preserved them without rewriting shared history.

## Independent review remediation

Independent review and the subsequent re-review both returned
**CHANGES_REQUIRED**. The initial package used the wrong interpreter/validation
record and lacked durable deterministic regeneration. Re-review then identified
unconsumed registration fields, optional proximity-only callback claims,
unresolved `connectImpl` callback operands, and manifest-selected adaptor
forwarders. The remediated package now machine-binds those required claims and
removes the optional claim. Neither independent decision is relabeled as a pass;
the final machine-bound correction passed independent re-review: **ACCEPT**.

## Bounded result

- Four bare target-name occurrences and four absent signature forms are checked.
  Three occurrences are logging labels; one is the selected row-64 metadata
  payload.
- The target inventory is exactly three row-60 `copyWhatsNewFiles()` calls at
  `0x10281c`, `0x102de9`, and `0x103398`, plus generated row-64 forwarding at
  `0x16e030`.
- Targeted metadata/relocations and machine anchors establish the parent/selected
  11/85 local-method chain, local row 64, generated `a[1]`/`a[2]` copying,
  call, and return assignment. No absolute method index is asserted.
- Exact imported direct-call counts are 90 old-style connects, 18
  `connectImpl`, 105 named invokes, 32 D-Bus connects, four string timers, one
  service registration, and one object registration. Bounded auto-connect,
  post/send-event, explicit-disconnect, and QMetaCallEvent-import counts are zero.
- Every old-style connect and named invoke has bounded static operand/type
  provenance and a deterministic ordered hash; none selects the target.
- The selected constructor contains 29 string connects (28 Auto, one Direct).
  Per-call slot-object/callback-field def-use binds two Auto `connectImpl` sites
  to their respective callback bodies; those bounded bodies contain no direct
  target body/name reference.
- Constructor target and register-origin tracking binds helper `0xb8b40` and the
  same object at registerObject. Exact dominating `%ecx` definition
  `movl $0x1,%ecx` must match the manifest; only actual value one derives
  `ExportAdaptors`.
- Six constructor/vtable/metaobject adaptor bindings, 16 public-slot/14-signal
  totals, 16 row-dispatch/body/invoke-bound non-target forwarders, and 12
  same-object non-target subscriptions are checked. Option one remains
  `ExportAdaptors`, not export of ordinary parent slots.
- Service template/token/final-service/object-path identities are checked by
  length/hash and selected instruction provenance. Retained output contains no
  exact callable service/path/token bytes or coordinates.
- Synthesized/indexed, indirect, Qt-library-internal, cross-library/external and
  runtime-created producers, registration success/policy, exact-ELF runtime
  invocation, arguments, queued transport, and attacker control remain unknown.

## Deliverables and SHA-256

- analyzer, `tools/uk_fw/appfumo_decryption_dispatch_provenance.py`:
  `dabc7366c2795ca86ff6cca93822f65ab6e2da240978e149536e2a5a75e880ba`;
- tests, `tests/test_appfumo_decryption_dispatch_provenance.py`:
  `6a3d7f95ed7b13782e4013238b09a2a9deec9aad58d2e0f42b701d7a1fcff036`;
- strict manifest:
  `d20cefb6941d7c344fcd2c65d659c44a1b30e1a2df63d8694ad1354dec96b53a`;
- deterministic compact report:
  `01c26edeaa241f6577ac26f27a5d8c8b71a8ed2866954783752adc997d33814a`;
- compact exact-static excerpt:
  `c712ff7592022f243c17739242e7e73345f0b91007d4acadced2a89ac2032baf`;
- assessment, `evidence/appfumo-decryption-producer-provenance.md`:
  `7b3d1c0dea63aff9021077d7f44063c86eeef920d40a11d561b22d6ccd44ff2a`;
- plan:
  `a95604bcdd616178fabdc74df2d47d84fbc47b6946ca1faf8e24299f75a926ff`;
- review-remediation record:
  `dd601bed8239bfce980143942a1a720d2d9eb4c8641fb7bd0697bc4c35f13bd0`.

Narrow integration updates cover authentication, Qt metadata, runtime
provenance, artifact README, exploit inventory, and HANDOVER.

## Validation

All Python commands use the project-approved `<platformio-env>/bin/python3`.

Old focused command:

```text
<platformio-env>/bin/python3 -m pytest -q -p no:cacheprovider tests/test_qt5_metaobject_rev7.py
```

Result: `19 passed, 25 subtests passed`.

Final combined focused command:

```text
<platformio-env>/bin/python3 -m pytest -q -p no:cacheprovider tests/test_qt5_metaobject_rev7.py tests/test_appfumo_decryption_dispatch_provenance.py
```

Result: `37 passed, 31 subtests passed`.

Also passed:

- `py_compile` for both analyzers and both focused tests;
- deterministic UTF-8/LF output under ASCII, Latin-1, and UTF-16
  `PYTHONIOENCODING` settings;
- retained-report byte regeneration;
- strict schema/key/type, Boolean-as-int, file safety, mapping,
  instruction/relocation, tool/ELF identity, count-drift and operand-provenance
  failure tests;
- callable-coordinate/operator-path privacy exclusion;
- final retained hashes and `git diff --check`;
- tests-scoped full suite: `736 passed, 351451 subtests passed`;
- post-stage public harness:
  `pass=3 info=4 pending=0 blocked=0 fail=0`;
- post-stage privacy: 388 files, zero blockers, three informational
  public/reserved identifiers.

The requested baseline remains five non-overlapping commits behind the preserved
integration HEAD. Exactly 15 reviewed package paths are staged for delivery. The
unrelated dirty MICOM source remains unstaged and untouched.

## Safety

Only read-only exact-static analysis and host-side parsing/tests were performed.
No recovered target/helper ran. No D-Bus request, target/device/radio/network
interaction, payload, malformed input, update/archive action, target staging,
signature bypass, partition/slot/boot action, privilege action, root action, or
persistence action was created or performed. During implementation and review,
no delegation/orchestration, repository staging, commit, push, reset, or stash
was used. Parent integration later staged exactly the 15 reviewed package paths.
The unrelated dirty MICOM source was preserved untouched and unstaged.
