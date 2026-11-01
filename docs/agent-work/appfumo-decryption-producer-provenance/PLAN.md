# AppFUMO `decryptionFile` producer-provenance plan

## Objective

Bound the exact-static in-binary producer and Qt/D-Bus dispatch provenance for
`QString AppUpgradeEngine::decryptionFile(QString,QString)` in the exact
AppUpgrade ELF while failing closed on dynamic invocation, runtime registration,
argument control, and external reachability.

## Fixed identity

- requested/start baseline: `c886e103c9378cbc6f3884e738f4870bab7a3826`;
- final integration-check HEAD:
  `1d5da8111b26a64d7efaff4c69e368f93bc7ec2c` (the requested baseline is five
  non-overlapping commits behind, including `f2f4bd2`; the intervening external
  commits change only three unrelated IONIQ ledger documents);
- ELF SHA-256:
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`;
- Build ID: `863a8730e66a1c5245a1bf458fe2554adee0351a`;
- target body: `0x100b30`;
- selected metadata: stringdata `0x445260`, metadata `0x444760`, static metacall
  `0x16df80`;
- selected constructor: `0x125800`;
- selected `qt_metacall`: `0x16f080`.

## Work

1. Enumerate exact bare-name, normalized/declarative signature, old-style Qt
   encoding, selected metadata-row, and instruction-xref occurrences.
2. Reconfirm the generated row-64 case and distinguish it from row 60
   `copyWhatsNewFiles()` and its three implementation-internal direct calls.
3. Resolve the inherited `qt_metacall` residual-index and local-count
   subtraction chain without asserting an unavailable absolute method index.
4. Audit direct callsites for old/new `QObject::connect`, named
   `QMetaObject::invokeMethod`, timer string dispatch, auto-connect, event
   posting/sending, explicit disconnect, and selected constructor connections.
5. Trace the selected constructor into session-bus service/object registration;
   decode option `1 = ExportAdaptors`, attached adaptor metadata/forwarding, and
   independent incoming D-Bus signal subscriptions. Do not treat ordinary parent
   slots as exported.
6. Discuss Direct/Auto/Queued/Blocking and QString copying only where a row-64
   candidate exists. Keep Qt-internal event creation and dynamic/indexed or
   cross-library calls unresolved.
7. After independent review and re-review returned `CHANGES_REQUIRED`, add a
   privacy-safe deterministic analyzer, strict exact-input manifest, compact
   report, and focused tests. Machine-bind helper/option fields, constructor
   slot-object/callback def-use, and selected adaptor public row dispatch to
   implementation invokes; remove optional proximity-only claims. Fail closed
   on malformed identity/schema/instructions, unsupported mapping/provenance,
   count drift, unsafe files, and Boolean-as-int.
8. Retain compact evidence and narrowly integrate the assessment into existing
   AppFUMO evidence, artifact README, exploit inventory, and HANDOVER.
9. During implementation, run only the requested focused pytest files with
   `<platformio-env>/bin/python3`, plus bytecode, encoding/privacy, hash, and
   whitespace checks. Parent integration subsequently runs the tests-scoped
   full suite and post-stage public/privacy harness.

## Safety and exclusions

Read-only host static analysis only. Do not delegate or orchestrate. Do not run
recovered target code, send D-Bus requests, contact a target/device/network,
create payloads or malformed input, stage, commit, push, reset, or stash. Keep
full disassembly under ignored `work/`. Do not inspect or modify unrelated
`tools/uk_fw/ias_backend_soft/micom_service.c`.

## Acceptance

- all exact identities and key instruction/metadata anchors rechecked;
- compact excerpt, strict manifest, deterministic report, analyzer, assessment,
  and review-document hashes recorded after final bytes;
- the old focused test reports `19 passed, 25 subtests passed` and the requested
  combined focused pytest command passes under exactly
  `<platformio-env>/bin/python3`;
- no stale claim that `ExportAdaptors` exports ordinary slots;
- no metadata/import/callsite negative promoted to global non-reachability;
- `git diff --check` passes for touched paths;
- the requested baseline remains an ancestor; any concurrent HEAD advance is
  recorded without reset, and unrelated dirty work is preserved.
