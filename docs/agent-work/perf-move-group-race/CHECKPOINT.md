# Checkpoint — exact CVE-2017-6001 perf move-group audit

## Completed

- Bound recovered `vmlinux` SHA-256
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`,
  Build ID `273378887b4cf563c10862fdf18b2292765df781`, and
  `CONFIG_PERF_EVENTS=y`.
- Retained complete exact FDEs:
  - `perf_event_ctx_lock_nested.isra.60`
    `[0xffffffff810c7996,0xffffffff810c7a14)`;
  - `SYSC_perf_event_open`
    `[0xffffffff810cd747,0xffffffff810ce12f)`.
- Confirmed exact initialized `sysctl_perf_event_paranoid` value 1 at
  `0xffffffff81ae0570`; runtime value remains unknown.
- Confirmed the move-group path loads `group_leader->ctx` before the double
  mutex wait and lacks live-reference, identity-revalidation/retry, and
  post-lock move-state checks.
- Confirmed the same binary's single-context helper implements the reference,
  lock, identity-check, unlock/drop, and retry discipline.
- Added V-030 evidence, upstream fix, deterministic Boolean-only model, and
  exhaustive tests.

## Hashes

- Exact retained assembly:
  `6f171c2c89ed13f641f4a5084fd40a90d23f7deeb644a00de8c5eed1a1ef6863`
- Upstream fix patch:
  `3349b60feb8808444a3905369e4d4d7660690f2223c6b8e3cbabb9b0e7c6be99`
- Deterministic model report:
  `7d12b7cd0cf1ae0a7b64336a823d96c633255e48106eb1079b1f6936ef2e2eca`

## Current classification

Exact static CVE-2017-6001 local privilege-escalation candidate. Installed
identity, runtime perf policy, hardware PMU/event behavior, unprivileged event
acceptance, race realization, stale/dead-context use, controlled corruption,
credential/SMACK transition, unrestricted root and persistence are unobserved.

## Validation/review

- Focused integration: `27 passed, 521 subtests passed`.
- Full suite: `491 passed, 134967 subtests passed`.
- Public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- `git diff --check`: **PASS**.
- Independent review found and corrected a passive-collector success-value
  omission, a model counterexample, and imprecise old-context reference-drop
  wording, then required emitter-to-parser coverage and unique changelog
  versioning. Final re-review returned **ACCEPT**.
- No syscall, event, thread, race, target execution, crash, root or persistence
  action was performed.
