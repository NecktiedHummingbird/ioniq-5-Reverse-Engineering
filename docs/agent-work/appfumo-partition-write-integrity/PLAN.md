# AppFUMO PartitionUpdater integrity/slot-selection plan

Date: 2026-11-03

## Objective

Build a deterministic fail-closed exact-static package for the embedded FUMO
`PartitionUpdater` route. Bind pre-write source authentication, mode selection,
pathname continuity, normalized inactive-target selection, process completion,
and the bounded post-write re-verification negative without claiming slot
activation, boot acceptance, root, or persistence.

## Safety and repository boundaries

- Work only in this repository and do not delegate.
- Do not execute recovered target code or helpers.
- Do not create payloads, malformed update inputs, packages, images, pathname or
  command test inputs, mounts, writes, slot operations, target commands, or
  persistence.
- Use only host-side parsing, hashing, Homebrew LLVM disassembly, exact ELF
  inspection, and Python tests.
- Preserve all concurrent work, especially the modified
  `tools/uk_fw/ias_backend_soft/micom_service.c`; do not edit, stage, reset,
  stash, commit, or push it.
- Retained output must omit proprietary bytes, target commands/pathnames,
  operator paths, and operational device mappings.

## Exact input

- embedded ELF size: `5,066,264` bytes;
- SHA-256:
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`;
- Build ID: `863a8730e66a1c5245a1bf458fe2554adee0351a`;
- instruction authority: exact Homebrew LLVM `llvm-objdump` with raw bytes
  suppressed;
- unwind authority: exact Homebrew LLVM `llvm-readelf --unwind`.

## Phases

1. Revalidate baseline ancestry, exact ELF identity, Build ID, and LLVM tool
   identities without changing concurrent work.
2. Recover every selected FDE from `.eh_frame`; independently validate, rather
   than trust, the supplied candidate ranges.
3. Build whole-instruction call/jump inventories for source verifier, write
   starter, post-hash starter, generated metadata slots, completion handler,
   fstab updater, and finalization.
4. Bind the mode-byte branch, constructor signal/slot identities, generated
   `slotHashCheck` tail jump, selected-primary and per-entry source checks,
   exact-zero mismatch gates, and transition to the write starter.
5. Bind source-record pathname flow separately from file-object/byte identity.
   Trace source field `+0x10`, selected-name field `+0x20`, writer target field
   `+0x28`, static partition map, active/inactive helpers, and record lookup.
   Mark an incomplete helper-output-to-record-instance chain unknown.
6. Bound the trailer parser and fixed-key verifier. State only instruction-backed
   trailer size/header facts; leave signed ranges, digest choice, and RSA
   encoding unknown where not closed.
7. Bound the no-post-write-reverification claim to complete direct inventories
   for named helper targets and named FDEs. Keep indirect, virtual, external,
   inlined, dynamic, loader, and boot-stage behavior unknown.
8. Add strict manifest, analyzer, deterministic report, byte-free selected
   assembly, focused tests, public evidence, and narrow umbrella updates.
9. Run focused/full tests, `git diff --check`, public harness, and privacy scan.
   Do not stage, commit, or push.

## Acceptance boundaries

The final model must distinguish:

- pre-write source authentication from final-partition integrity;
- pathname value from object and byte identity;
- hash-gated mode from non-hash mode;
- image-backed writes from clone branches;
- process completion from cryptographic readback;
- inactive target selection from bootloader activation and mark-good;
- unknown update success, slot change, boot acceptance, root, and persistence.
