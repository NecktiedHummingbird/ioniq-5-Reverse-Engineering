# vmacache CVE-2018-17182 exact-candidate plan

## Goal

Determine whether the exact recovered kernel carries the CVE-2018-17182
semantic fix or the vulnerable finite-generation design, without executing a
mapping/thread cycle or stale-pointer path.

## Acceptance criteria

1. Bind conclusions to exact `vmlinux` SHA-256, Build ID, virtual addresses,
   file offsets, and authoritative upstream patch.
2. Trace every direct zero-wrap caller of `vmacache_flush_all`.
3. Prove generation operand widths in invalidation and lookup.
4. Prove single-user flush cleanup behavior and independently bind its user
   count field.
5. Separate static generation aliasing from actual wrap, stale pointer,
   dereference, corruption, root, and persistence.
6. Add a Boolean-only model with complete matrix and deterministic output.

## Exclusions

No mapping loop, thread lifecycle, counter wrap, race schedule, memory pressure,
stale-pointer dereference, allocation shaping, corruption attempt, payload,
privilege transition, or persistence.
