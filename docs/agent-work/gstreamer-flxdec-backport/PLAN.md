# GStreamer FLIC write-bounds backport plan

## Objective

Determine from exact recovered `libgstflxdec.so` machine code whether the FLIC
write-bounds mechanisms associated with CVE-2016-9634/9635/9636/9808 remain,
despite embedded GStreamer `1.8.3-r0` metadata.

## Boundaries

- Static analysis only; do not execute the recovered plugin.
- Do not create a FLIC/media input, malformed file, trigger, heap layout,
  overwrite, shellcode, or payload.
- Preserve exact hash, Build ID, PIE addresses, half-open FDE ranges, operands,
  return routing, and source-line bindings.
- Treat imports and version strings as leads only.
- Keep CVE-2016-9807 separate unless its distinct mechanism is exactly audited.
- Any model accepts Boolean state only and emits no target material.

## Work

1. Recover the complete upstream remediation history.
2. Bind the exact plugin and affected FDEs.
3. Trace chunk sub-reader creation, frame-writer initialization, FLI/FLC line
   and cumulative-position checks, read/write failure handling, and caller
   propagation.
4. Retain reviewed patch and machine-code evidence.
5. Add a fail-closed Boolean classifier and exhaustive tests.
6. Obtain independent review, run focused/full validation, then commit only
   reviewed paths.

## Acceptance

- The conclusion distinguishes the early partial checks from the comprehensive
  ByteReader/ByteWriter rewrite.
- Every relevant reader/writer failure and helper failure is shown to terminate
  the affected decode route before output publication.
- The evidence binds writer storage and size to exact object fields.
- Tests exhaust every Boolean state and verify deterministic UTF-8/LF output.
- No parser execution or trigger occurs.
