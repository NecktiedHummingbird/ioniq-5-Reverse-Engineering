# AppFUMO parameterized verifier provenance checkpoint

Date: 2026-11-01

## Completed

- Revalidated exact embedded AppUpgrade identity:
  - size `5,066,264`;
  - SHA-256
    `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`;
  - Build ID `863a8730e66a1c5245a1bf458fe2554adee0351a`.
- Bound Homebrew LLVM 23.1.3 `llvm-objdump` and `llvm-readelf` executable
  identities, all `470,739` decoded instructions, and all `3,789` FDE ranges.
- Confirmed exact FDEs:
  - verifier `[0x45820,0x45d75)`;
  - target route `[0x9cbc0,0x9e260)`;
  - immediate caller `[0xf28e0,0xf3ddf)`;
  - nested target `[0x140030,0x1405da)`;
  - command helper `[0x1397c0,0x1398fb)`.
- Confirmed whole-instruction direct edges:
  - sole direct caller `0xf359e -> 0x9cbc0`;
  - sole direct caller `0x9d4fe -> 0x140030`;
  - no direct call to upstream FDE entry `0xf28e0`;
  - the complete six-site direct verifier inventory remains unchanged.
- Resolved `0x9d1d2` to the absolute pathname of an enumerated `.enc`
  controller-resource member under one of four fixed resource trees selected by
  the immediate caller's controller class.
- Classified the bounded pathname role as a controller resource, not a
  running/staged updater, descriptor, general firmware archive, or general
  firmware member. Kept content type, runtime object identity, and every
  unbounded producer class unknown.
- Proved exact-zero verifier status at `0x9d1d2` dominates call `0x9d4fe`.
- Proved `0x9d4fe` separates source and derived destination QStrings and that
  `0x140092` verifies a QString copy of the same source-pathname value.
- Proved exact-zero status at `0x140092` dominates a pathname-based helper
  transformation to a derived JSON or binary destination.
- Bound the source pathname to the later command field and destination pathname
  to the returned QString, but stopped same-byte claims at pathname reopen:
  there is no retained descriptor/object identity, command status propagation,
  destination existence/size check, or post-transform digest/signature check in
  the bounded route.
- Added fail-closed analyzer
  `tools/uk_fw/appfumo_parameterized_verifier_provenance.py`.
- Added focused tests
  `tests/test_appfumo_parameterized_verifier_provenance.py`.
- Retained exact-static assembly, strict manifest, and normalized report under
  `evidence/artifacts/update-candidates/`.
- Added public assessment
  `evidence/appfumo-parameterized-verifier-provenance.md` and narrowly updated
  authentication/update-trust summaries and the retained-artifact index.
- Preserved unrelated concurrent modification
  `tools/uk_fw/ias_backend_soft/micom_service.c` without editing it.

## Fail-closed and privacy properties

The analyzer rejects:

- unknown/missing JSON keys, wrong types, and Boolean-as-integer values;
- nonregular, oversized, or changing inputs;
- unsupported or malformed ELF structure and ambiguous/unmapped ranges;
- exact ELF size/hash/Build-ID drift;
- exact LLVM file/version drift;
- malformed, duplicate, unordered, truncated, count-drifted, or hash-drifted
  instruction evidence;
- malformed, duplicate, count/hash-drifted, or selected-range-drifted FDEs;
- complete direct-call inventory drift;
- selected machine instruction/operand and literal hash drift;
- an overwrite of the retained RBX operand provenance.

Output is deterministic UTF-8/LF JSON. It contains normalized identities,
classifications, VAs, Booleans, and nulls, but no proprietary instruction bytes,
recovered command text, callable coordinates, or supplied filesystem path.

## Validation

Completed from the repository root:

```text
focused pytest: 12 passed, 6 subtests passed
full pytest: 748 passed, 351457 subtests passed
repository harness: overall pass; 0 fail, 0 blocked, 0 pending
privacy-only harness: pass; 0 blocking findings
git diff --check: pass
```

The three informational privacy findings are unchanged public noreply-email
records outside this work. Independent exact-binary/package review rechecked the
ELF identity, FDEs, direct-call inventories, operand flow, exact-zero gates,
pathname-reopen boundary, analyzer, focused tests, and privacy, and returned
**ACCEPT**. No implementation or review worker staged, committed, or pushed.

## Remaining unknowns

- Invocation of FDE `[0xf28e0,0xf3ddf)` through virtual, indirect,
  synthesized/indexed Qt, cross-library, external-service, or cross-process
  mechanisms.
- Installed-runtime identity and runtime reachability.
- Path mutation, rename/symlink/hardlink/mount substitution, and same-object or
  same-byte continuity between verifier and helper opens.
- Actual signature acceptance and helper/command success.
- Destination existence, size, hash, signature, and final consumer.
- Partition writes, boot selection/acceptance, privilege, root, and persistence.
- The separate metadata-forwarded `0x100bb0` producer boundary and all remaining
  indirect/external/loader verification routes.

## Safety record

No recovered target binary or helper was executed. No payload, package, image,
operational update input, signature bypass, mount, flash, partition write, or
persistence action was created or attempted.
