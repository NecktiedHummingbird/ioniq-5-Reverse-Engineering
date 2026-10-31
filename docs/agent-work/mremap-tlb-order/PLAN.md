# mremap CVE-2018-18281 exact-ordering plan

## Goal

Determine whether the exact recovered kernel retains the ordinary-PTE
page-table-lock/TLB-flush ordering fixed for CVE-2018-18281, without executing a
mapping lifecycle, concurrency, page release/reuse, or stale access.

## Acceptance criteria

1. Bind conclusions to exact kernel identity, addresses, file offsets,
   configuration, and authoritative upstream patch.
2. Trace source/destination PTE transfer.
3. Bind source and destination PTL acquisition and release, including aliasing.
4. Identify every TLB-flush call in the complete containing function and bind
   the old-range arguments.
5. Separate static lifetime-window semantics from concurrent invalidation,
   stale access, corruption, privilege gain, and persistence.
6. Add a Boolean-only deterministic model with complete matrix tests.

## Exclusions

No mapping/remapping sequence, backing-file mutation, race schedule, page
release/reuse, memory pressure, allocation shaping, stale-pointer or stale-TLB
access, corruption attempt, payload, privilege transition, or persistence.
