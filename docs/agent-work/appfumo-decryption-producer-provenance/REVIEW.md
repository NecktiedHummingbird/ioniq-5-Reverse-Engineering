# AppFUMO `decryptionFile` producer-provenance review remediation

Date: 2026-11-08

## Independent decision

The independent review returned **CHANGES_REQUIRED**. Its two binding findings
were:

1. validation used the wrong PlatformIO interpreter and documented the wrong
   fallback validation mode;
2. the package lacked a durable, deterministic, privacy-safe analyzer and tests
   capable of regenerating and checking the retained dispatch claims.

The subsequent independent re-review also returned **CHANGES_REQUIRED**. It
identified unconsumed registration manifest fields, proximity-only optional
callback claims, unresolved `connectImpl` callback operands, and a
manifest-selected rather than row-derived adaptor forwarder list.

No reviewer was delegated from the implementation task. A separate parent-owned
reviewer performed both correction rounds and then returned **ACCEPT** for the
machine-bound remediation.

## Remediation

- Validation uses the project-approved `<platformio-env>/bin/python3`.
- The old focused pytest invocation reports `19 passed, 25 subtests passed`;
  the final combined focused invocation reports `37 passed, 31 subtests passed`.
- Added `tools/uk_fw/appfumo_decryption_dispatch_provenance.py`.
- Added a strict exact-input manifest and compact deterministic JSON report under
  `evidence/artifacts/update-candidates/`.
- Added `tests/test_appfumo_decryption_dispatch_provenance.py`.
- Added exact Homebrew LLVM executable size/SHA-256/version checks and a hash of
  the complete normalized instruction stream.
- Added fail-closed checks for regular/bounded/unchanged inputs, exact ELF and
  Build ID, strict schema keys/types, Boolean-as-int, unsupported/ambiguous ELF
  mappings, malformed/duplicate/truncated instruction streams, relocation and
  count drift, and unsupported operand provenance.
- Added per-callsite signal/member/type provenance for all 90 old-style
  connects and literal-member/type provenance for all 105 named invokes.
- The registration helper manifest value is now compared to the constructor's
  actual call target and same-object register dataflow. The option manifest
  value is compared to the exact immediate `%ecx` definition dominating
  registerObject; only checked actual value one derives `ExportAdaptors`.
- Removed the optional `callWithCallback` claim, manifest field, and report key.
- Added overwrite/swap mutation tests for each constructor `connectImpl`
  slot-object/callback binding.
- Replaced the adaptor invoke-site list with selected metadata access decoding,
  static-metacall row dispatch, implementation-body resolution, and per-row
  invoke-member equality. Access, row/body swap, invoke substitution, and name
  mutation tests fail closed.
- Added durable timer-member, constructor functor slot-object/callback def-use,
  callback-body, selected metaobject/adaptor row-to-body-to-invoke binding,
  registration, subscription, and privacy checks.
- Retained D-Bus output contains lengths and hashes only. It emits neither exact
  service/path/token bytes nor callable coordinates, input/tool paths, or an
  operator home path.

## Claim-to-evidence checks

- Exact ELF hash, size, Build ID, four bare-name locations/classifications, four
  absent signature forms, and four direct target edges are deterministic.
- Targeted parent/selected metadata and machine anchors establish the 11/85
  local-count chain, local row 64, generated argument copying/call/return, and
  no absolute method index.
- Imported direct-call counts are 90/18/105/32/4/1/1 for the requested routes.
- The selected constructor contains 29 string connects (28 Auto, one Direct).
  Per-call slot-object def-use binds two Auto `connectImpl` sites to callback
  bodies at `0x1305c0` and
  `0x1309c0`; bounded bodies contain no direct target reference.
- The same-object registration chain, six constructor-to-vtable-to-metaobject
  adaptor bindings, 16-slot/14-signal totals, 16 non-target forwarders, and 12
  same-object non-target subscriptions are checked.
- `ExportAdaptors` remains distinct from exporting ordinary parent slots.

## Fail-closed boundary

The remediated package still does not infer invocation from metadata or
generated dispatch availability. It does not exclude synthesized/indexed,
indirect, Qt-library-internal, cross-library, external, or runtime-created
calls. It does not prove registration success, policy permission, exact-ELF
runtime identity, argument values, queued transport, or attacker control.

## Validation contract

Run only:

```text
<platformio-env>/bin/python3 -m pytest -q -p no:cacheprovider tests/test_qt5_metaobject_rev7.py tests/test_appfumo_decryption_dispatch_provenance.py
```

Also run `py_compile`, encoding determinism, privacy exclusion, retained-report
regeneration/hash checks, and `git diff --check`. Parent integration later ran
the tests-scoped full suite: `736 passed, 351451 subtests passed`.

Analysis started at requested baseline
`c886e103c9378cbc6f3884e738f4870bab7a3826`. Preserved concurrent external
commits advanced HEAD through `4dd644e37`, `332fc60cc`, `bb3fe7ba8`, and
`f2f4bd215` to `1d5da8111b26a64d7efaff4c69e368f93bc7ec2c` and changed only three unrelated
IONIQ ledger documents. The unrelated dirty MICOM source
must remain unstaged and untouched.
