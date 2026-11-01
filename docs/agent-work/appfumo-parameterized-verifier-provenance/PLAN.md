# AppFUMO parameterized verifier provenance plan

Date: 2026-11-01

## Objective

Resolve exact static operand and bounded direct/static producer provenance for
verifier calls `0x9d1d2` and `0x140092` in the exact embedded AppUpgrade ELF.
Classify the pathname roles and, only where instruction evidence supports it,
bind verified pathname values to later transformation and consumption.

## Safety and scope

- Never execute recovered updater/helper/target code.
- Never create payloads, packages, images, operational update inputs, or
  signature bypasses; never mount, flash, or alter a target filesystem.
- Preserve unrelated concurrent work, especially
  `tools/uk_fw/ias_backend_soft/micom_service.c`.
- Treat indirect, virtual, synthesized/indexed Qt, cross-library,
  cross-process, and external-service producers as unknown unless bounded.
- Distinguish pathname-value continuity from same-object/same-byte continuity.
- Do not claim runtime acceptance, command success, final-image consumption,
  partition writing, boot acceptance, root, or persistence.

## Exact input

- ELF:
  `work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf`
- size: `5,066,264`
- SHA-256:
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`
- Build ID: `863a8730e66a1c5245a1bf458fe2554adee0351a`
- instruction authority: exact Homebrew LLVM 23.1.3 `llvm-objdump`
- unwind authority: exact Homebrew LLVM 23.1.3 `llvm-readelf --unwind`

## Phases

1. **Identity and unwind**
   - Revalidate ELF size/hash/Build ID.
   - Bind exact LLVM executable files and version line.
   - Recover exact FDEs for verifier, each target, immediate caller, and command
     helper.
2. **Whole-instruction call inventory**
   - Confirm the complete six-edge direct-call inventory for verifier `0x45820`.
   - Find all direct callers of `0x9cbc0`, `0x140030`, and upstream `0xf28e0`.
   - Keep direct-call negatives explicitly bounded.
3. **`0x9d1d2` operand provenance**
   - Trace the immediate caller into the resource route.
   - Bind fixed selectors, source/destination tree roles, suffix filtering,
     absolute-path construction, stack ownership, and verifier status branch.
   - Classify updater/descriptor/firmware/resource pathname roles.
4. **`0x140092` operand and transformation provenance**
   - Prove source/destination argument separation at `0x9d4fe`.
   - Trace the source QString copy to verifier `0x140092` and later command
     substitution.
   - Trace destination construction/return and command-helper status handling.
   - Stop byte-binding claims at pathname reopen.
5. **Fail-closed package**
   - Add strict manifest, analyzer, focused tests, selected exact-static
     assembly, normalized JSON report, and public evidence.
   - Reject schema/type/Boolean drift, malformed or duplicate instruction data,
     changing/nonregular/oversized inputs, ELF/tool/Build-ID drift, complete
     instruction/FDE identity drift, selected FDE drift, call drift, machine
     anchor drift, mapping ambiguity, literal drift, and provenance overwrite.
   - Emit UTF-8/LF deterministic JSON without proprietary bytes or supplied
     operator paths.
6. **Validation and documentation**
   - Run focused and full tests, `git diff --check`, repository harness, and
     privacy validation.
   - Update only the relevant authentication/update-trust summaries and retained
     artifact index.

## Deliverables

- `tools/uk_fw/appfumo_parameterized_verifier_provenance.py`
- `tests/test_appfumo_parameterized_verifier_provenance.py`
- `evidence/appfumo-parameterized-verifier-provenance.md`
- three retained files under `evidence/artifacts/update-candidates/`
- this plan and `CHECKPOINT.md`
- narrowly necessary umbrella-document corrections
