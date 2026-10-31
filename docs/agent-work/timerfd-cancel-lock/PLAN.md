# timerfd CVE-2017-10661 exact-lock plan

## Goal

Determine whether exact recovered timerfd cancellation membership/list updates
contain the per-context serialization added for CVE-2017-10661, without creating
a timer, sharing a descriptor, changing a clock, or creating concurrency.

## Acceptance criteria

1. Bind exact context membership/list fields and global-list lock.
2. Trace complete setup, removal, release, creation, and same-file lookup paths.
3. Determine whether one context-derived lock continuously covers membership
   decisions and associated global-list operations.
4. Exclude later or unrelated locks as equivalent serialization using dominance
   and object identity.
5. Separate static race premises from harmful interleaving, list corruption,
   UAF, crash, privilege gain, and persistence.
6. Add a Boolean-only deterministic model with complete matrix tests.

## Exclusions

No timerfd, timer configuration, clock change, shared descriptor, concurrency,
race schedule, resource pressure, allocation shaping, corruption attempt,
payload, privilege transition, or persistence.
