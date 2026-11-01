# AppFUMO decryption producer/runtime provenance plan

## Scope

Advance the bounded producer provenance for exact ELF calls `0x10281c`,
`0x102de9`, and `0x103398`, then correlate only pathname classes and temporal
context with the already-tracked public AppUpgrade log.

## Evidence questions

1. Which exact `.eh_frame` FDE contains the three direct calls?
2. Does exact Qt metadata and generated forwarding bind that FDE entry to
   `copyWhatsNewFiles()`?
3. Which branch and QString producers supply `%rdx` (`encFile`) and `%rcx`
   (`destPath`) at each call?
4. How many exact-shape runtime records are actually present in the hash-bound
   public log, and what bounded `copyWhatsNewFiles` context surrounds them?
5. Which identity, dispatch, reachability, control, acceptance, privilege, and
   persistence facts remain unknown?

## Constraints

- static and read-only only; never execute the recovered ELF or helper;
- Homebrew LLVM output for instruction claims;
- keep generated row-64 call `0x16e030` separate from implementation-internal
  direct calls;
- do not claim dynamic/indirect producer completeness;
- do not identify the logged installed build with the exact ELF without binary
  identity;
- do not infer invocation mechanism or attacker control from log text;
- retain bounded normalized evidence only, without transient tokens or a copy of
  the full public log.

## Deliverables

- exact bounded FDE/instruction excerpts and row-60 metadata report;
- fail-closed deterministic public-log parser and tests;
- normalized hash-bound public-log JSON;
- evidence assessment plus narrow handover/changelog/inventory updates;
- focused/full tests, public/privacy harness, encoding determinism,
  `py_compile`, and `git diff --check`.
