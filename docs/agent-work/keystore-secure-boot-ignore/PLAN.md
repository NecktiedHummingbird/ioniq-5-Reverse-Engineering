# Keystore secure-boot-ignore and manifest-bounds plan

## Objective

Determine the exact machine-code effect of
`CONFIG_KEYSTORE_SECURE_BOOT_IGNORE=y`, whether it removes OEM signature
verification, and whether `manifest_init` binds all parser reads to the copied
physical-memory allocation.

## Boundaries

- Static analysis only; do not execute the recovered kernel.
- Do not construct a manifest, key, signature, boot parameter, physical-memory
  input, update, payload, or firmware image.
- Preserve exact kernel identity, linked virtual addresses, half-open symbol
  ranges, field operands, predicates, initcall separation, and return routing.
- Treat configuration names and strings as leads, not conclusions.
- Distinguish status-gate removal, signature verification, parser read bounds,
  runtime input control, memory corruption, root, boot acceptance, and
  persistence.
- Models consume Boolean or bounded numeric state only and emit no target
  material.

## Work

1. Retain complete `keystore_init`, `manifest_init`, `verify_oem_signature`,
   `manifest_key_verify_digest`, and parameter-parser disassembly.
2. Trace exact IGNORE-option control flow through seed/device setup and kernel-client registration.
3. Confirm whether manifest and signature-verifier paths remain compiled and
   called independently.
4. Audit outer copied-size and internal declared-length arithmetic, fixed header
   reads, extension entry reads, loop cap, pointer ownership, and cleanup frees.
5. Locate matching authoritative public source for configuration and command-line registration context without replacing exact-binary review.
6. Add fail-closed deterministic models and boundary tests.
7. Correct earlier size wording, update evidence, obtain independent review,
   run focused/full validation, then commit and push reviewed paths.

## Acceptance

- No broad signature-bypass conclusion is inferred from the config name.
- The exact skipped prerequisite and surviving failure paths are identified.
- The accepted outer size range is arithmetically correct.
- Any parser defect is classified no stronger than exact instructions support.
- Runtime control, controlled write, code execution, root, update acceptance,
  boot acceptance, and persistence remain separate unknowns.
- CLI models fail closed and emit deterministic explicit UTF-8/LF.
