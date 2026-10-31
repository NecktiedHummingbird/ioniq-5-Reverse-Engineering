# CVE-2016-2384 exact-module backport plan

## Goal

Determine whether exact recovered USB-MIDI code retains CVE-2016-2384's
post-registration double-free without creating a USB descriptor or running the
target module.

## Acceptance criteria

1. Bind analysis to exact module SHA-256, Build ID, configuration, ELF section,
   section-relative address, and file offset.
2. Compare the authoritative fix and vulnerable parent source.
3. Identify raw-MIDI ownership/private-free installation.
4. Trace every endpoint-creation failure after ownership transfer.
5. Distinguish legitimate pre-registration cleanup and owner teardown from the
   removed second free.
6. Keep physical reachability, crash, corruption, root, and owner-build
   applicability as separate claims.

## Exclusions

No USB descriptor, peripheral emulation, module load, endpoint failure, double
free, heap shaping, payload, target execution, or physical-unit action.
