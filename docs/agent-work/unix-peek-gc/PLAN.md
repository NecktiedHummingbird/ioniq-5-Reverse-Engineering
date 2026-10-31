# AF_UNIX CVE-2021-0920 exact-GC-barrier plan

## Goal

Determine whether exact shipped AF_UNIX stream/datagram MSG_PEEK paths contain
the garbage-collector serialization added for CVE-2021-0920, without loading a
module, creating sockets, passing descriptors, or invoking GC.

## Acceptance criteria

1. Bind the exact module identity, sections, configuration, and upstream patch.
2. Prove MSG_PEEK dominance and attached-file duplication on both receive paths.
3. Trace duplicate return values into the exact SCM cookie consumed by delivery.
4. Bind exact `unix_gc_lock` and exclude direct and indirect equivalent barriers
   between duplication and delivery.
5. Separate static missing serialization from module load, GC overlap, UAF,
   controlled reuse, corruption, privilege gain, and persistence.
6. Add a Boolean-only deterministic model and passive module load/hash capture.

## Exclusions

No socket, SCM_RIGHTS transfer, MSG_PEEK call, descriptor graph, GC invocation,
concurrency, resource pressure, race schedule, allocation shaping, corruption
attempt, payload, privilege transition, or persistence.
