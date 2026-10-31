# Plan — exact CVE-2016-7910 block seq-iterator lifetime audit

## Objective

Determine whether recovered `vmlinux` retains the stale private-pointer cleanup
fixed by upstream CVE-2016-7910, without opening proc entries, forcing an
allocation failure, creating memory pressure, or executing target code.

## Method

1. Bind exact kernel/configuration identity and authoritative embedded-kallsyms
   ranges for `disk_seqf_next`, `disk_seqf_start`, and `disk_seqf_stop`.
2. Preserve authoritative upstream fix
   `77da160530dd1dc94f6ae15a981f24e5f0021e84` and stable lineage.
3. Bind the successful allocation/store, allocation-failure return, owner-field
   load, iterator exit, free, and owner-field invalidation in exact machine
   code.
4. Check operation-table registration for both block proc iterators and
   distinguish the outer `seq_file.private` slot from nested iterator fields.
5. Add a Boolean-only deterministic classifier and exhaustive tests. A complete
   private-pointer clear may reject the CVE premise, but absent clear evidence
   must not prove a retained stale pointer without an explicit retention fact.
6. Keep installed identity, runtime proc policy, allocation failure, stale use,
   repeated free, crash, corruption, privilege and persistence separate.
7. Obtain independent semantic/model review and run focused/full validation
   before committing.

## Non-goals

- No proc open/read/seek, allocation pressure, target execution, stale-pointer
  attempt, crash, heap manipulation, privilege action, or persistence.
- No conclusion from a kernel version alone.
- No claim that rejecting this CVE proves block/proc/seq-file code safe.

## Acceptance

- Complete exact iterator functions retained with provenance and hashes.
- Every upstream fix effect bound to exact fields, registers, calls, and branch
  ordering.
- Focused/full tests, public harness, and `git diff --check` pass.
- Independent review returns ACCEPT.
