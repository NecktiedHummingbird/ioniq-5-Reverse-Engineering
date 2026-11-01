# AppFUMO PartitionUpdater integrity/slot-selection checkpoint

Date: 2026-11-03

## Completed

- Confirmed baseline commit `12c61a266cb9e34992bae2cac9283792eec37cf3`
  is an ancestor of current HEAD.
- Preserved the pre-existing modification to
  `tools/uk_fw/ias_backend_soft/micom_service.c` without editing it.
- Revalidated exact ELF size, SHA-256, and Build ID.
- Bound Homebrew LLVM 23.1.3 executable identities, all `470,739` decoded
  instructions, and all `3,789` FDE ranges.
- Independently confirmed every supplied candidate FDE exactly, plus support
  FDEs for the fixed-key verifier, trailer parser, record/key verifier,
  process-thread starter, and generated metadata dispatcher.
- Confirmed complete whole-instruction direct-transfer inventories, including:
  - source gate `0xc1ff0`: two calls, both in `slotHashCheck`;
  - write starter `0xc53d0`: one call and two tail jumps;
  - generated tail `0x16ba9c -> 0xcd640`;
  - completion tail `0x16ba28 -> 0xcf9b0`;
  - no direct entry transfer to finalization `0xd1e70`.
- Bound global mode byte `0x6d20b4`: zero routes directly to the writer, while
  nonzero emits the constructor-bound integrity signal. Hash-bound signal/slot
  literals and generated metadata bind that asynchronous route to
  `slotHashCheck`.
- Bound exact-zero gates for selected-primary and non-excluded per-entry source
  verification. Nonzero results take failure paths; only completed verification
  reaches post-hash starter `0xcd560` and its tail jump to the writer.
- Bound the fixed-key verifier, final `0x4024`-byte trailer read, and accepted
  three-byte `TER`/`TE2` families. Did not infer a four-byte `TER2` marker,
  signed byte ranges, digest choice for this route, or RSA padding.
- Bound source pathname field `+0x10` into verifier and writer while retaining
  the independent-reopen boundary: pathname value is continuous, descriptor,
  object, and byte identity are not.
- Bound static map/helper identities, selected-name field `+0x20`, record lookup,
  writer target field `+0x28`, and distinct image/clone branches. Kept the exact
  inactive-helper-return-to-runtime-record-instance assignment unknown.
- Bound the process-completion, fstab-state, and finalization FDEs. Complete
  direct inventories find no edge from those FDEs to the five selected
  file-signature/hash helpers. Broader absence remains unknown.
- Added analyzer, strict manifest, deterministic JSON report, selected
  exact-static assembly without raw bytes, focused tests, public assessment,
  and narrow documentation/index updates.

## Fail-closed properties

The analyzer rejects unknown/missing keys, wrong types, Boolean-as-integer,
nonregular/oversized/changing inputs, malformed/ambiguous ELF mappings, exact
ELF/Build-ID/LLVM drift, malformed/duplicate/unordered/truncated instruction
output, complete instruction/FDE count or hash drift, selected-FDE drift,
direct-transfer drift, machine-anchor drift, literal/blob drift, mismatch-gate
drift, mode-flow drift, and a new reviewed post-write direct cryptographic-file
edge.

Output is deterministic UTF-8/LF through `sys.stdout.buffer` independent of
`PYTHONIOENCODING`. It emits no supplied paths, target pathnames, commands,
proprietary bytes, operational device mapping, or exploit material.

## Artifacts

- manifest SHA-256:
  `5d3ca7bf8261805ca10d02d61d75ec1ee54c1205c66cb15be03a3e009dd0c5c5`;
- exact-static selected text SHA-256:
  `e3acf80fdc76df6f1defd29d74fedcd1a62a90ef74ebe170f4a48591b20ec61c`;
- normalized report SHA-256:
  `e84e0771dea6aabe8f76fbe5a495084d0d6ef42650d7c39bec54fe68ab55c612`.

## Remaining unknowns

- Exact end-to-end inactive-helper output assignment to the selected runtime
  record instance.
- Runtime pathname mutation or source object/byte substitution between opens.
- Exact signed byte ranges, digest algorithm for this route, and RSA
  padding/signature encoding.
- Indirect, virtual, external, inlined, dynamic, loader, and boot-stage
  destination verification.
- Dynamic invoker and universal reachability of finalization FDE `0xd1e70`.
- Final partition byte identity and cryptographic readback.
- Installed runtime identity/reachability, update acceptance, write success,
  slot activation, mark-good, rollback, boot acceptance, health, root, and
  persistence.

## Validation

Completed from the repository root:

- focused analyzer tests: `14 passed, 7 subtests passed`;
- full required suite: `762 passed, 351464 subtests passed`;
- `git diff --check`: pass;
- public harness: overall pass, `pass=3 info=4 pending=0 blocked=0 fail=0`;
- public privacy check: no blocking finding (three unchanged public no-reply
  informational findings);
- supplemental public-mode privacy scan including the five new untracked
  evidence/tool files: no blocking finding;
- independent exact-binary/package review rechecked the ELF identity, FDEs,
  direct-transfer inventories, mode/mismatch gates, source and target field
  provenance, post-write bounded negative, trailer wording, analyzer/tests, and
  privacy, and returned **ACCEPT**.

## Safety record

No recovered updater, helper, or target executable was run. No payload, malformed
input, package, pathname/command test input, image, mount, flash/write operation,
slot change, target command, root action, or persistence action was created or
attempted.
