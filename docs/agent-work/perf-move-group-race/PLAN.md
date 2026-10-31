# Plan — exact CVE-2017-6001 perf move-group audit

## Objective

Determine whether recovered `vmlinux` retains the exact context-lifetime and
identity-validation omission fixed by upstream CVE-2017-6001, without invoking
`perf_event_open`, constructing events, scheduling a race, or executing target
code.

## Method

1. Bind exact kernel/configuration identity and complete kallsyms-derived
   function extents.
2. Preserve authoritative upstream fix `321027c1fe77f892f4ea07846aeae08cefbbb290`.
3. Compare exact `SYSC_perf_event_open` move-group object identity, ownership,
   lock, retry, and cleanup effects with exact `perf_event_ctx_lock_nested` and
   the upstream two-context fix.
4. Keep initialized policy, mutable runtime policy, PMU availability, syscall
   acceptance, race success, stale use, corruption, privilege and persistence
   as separate gates.
5. Add a Boolean-only deterministic model and exhaustive tests. The model must
   emit no syscall arguments, event attributes, thread/race schedule, command,
   payload, or target material.
6. Obtain independent semantic/model review, run focused/full validation, and
   commit only if accepted.

## Non-goals

- No event creation, syscall probe, thread, race, heap grooming, crash attempt,
  target execution, credential modification, root action, or persistence.
- No claim that package/kernel version alone proves applicability.
- No claim that public local-privilege impact proves root on this platform.

## Acceptance

- Complete exact affected and comparison-helper FDEs retained with hashes.
- Every fix effect classified by exact field/object/control-flow binding.
- Runtime and impact outcomes remain explicitly null/unobserved.
- Focused and complete tests, public harness, and `git diff --check` pass.
- Independent review returns ACCEPT.
