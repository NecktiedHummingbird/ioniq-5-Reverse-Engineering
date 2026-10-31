# GStreamer VMNC CVE-2016-9445 / CVE-2016-9446 plan

## Objective

Determine from exact recovered `libgstvmnc.so` machine code whether the width /
height allocation-overflow mechanism fixed by upstream commit
`4cb1bcf1422bbcd79c0f683edb7ee85e3f7a31fe`, and its related uninitialised
canvas disclosure, remain present despite embedded GStreamer `1.8.3-r0`
metadata.

## Boundaries

- Static analysis only; do not execute the recovered plugin.
- Do not create a VMNC/FLIC/media trigger, malformed file, packet, heap layout,
  overwrite, shellcode, or payload.
- Preserve exact artifact hash, Build ID, ELF addresses, FDE half-open ranges,
  and source-to-machine-code field binding.
- A version match is only a lead; accept or reject by equivalent machine-code
  effects and dominance.
- Any model consumes bounded numeric state only and emits no target material.

## Work

1. Acquire the authoritative upstream patch and public impact descriptions.
2. Bind the exact plugin identity and relevant FDEs.
3. Trace WMVi type, width and height parsing, both dimension branches, handler
   dispatch, allocation arithmetic, and allocator binding.
4. Retain a small reviewed instruction excerpt and patch under tracked evidence.
5. Add a deterministic bounded arithmetic/control-flow model and tests.
6. Update inventories and handover without claiming general decoder safety.
7. Obtain independent semantic/model review, run focused and full validation,
   then commit and push only reviewed paths.

## Acceptance

- The conclusion states whether both upstream fix effects are present.
- Every feasible oversized WMVi path is proven to terminate before handler
  dispatch, with any predicate-infeasible CFG bypass documented, or the
  candidate remains open.
- The exact allocation call is bound to `g_malloc` or `g_malloc0`.
- Tests cover 16384/16385 boundaries, maximum accepted arithmetic, invalid
  input, and deterministic explicit UTF-8/LF output.
- No runtime parser or exploit action occurs.
