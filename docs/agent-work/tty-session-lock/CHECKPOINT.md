# TTY session-lock audit checkpoint

## Result

V-027 records the exact CVE-2020-29660 locking defect and stale-session read premise, with the upstream-documented exploitation condition constrained by recovered configuration.

## Exact result

- `TIOCGSID` (`0x5429`) reaches an unlocked real-TTY session null test, `might_fault`, a second session load, and `pid_vnr`.
- `pid_vnr` reaches exact PID-object field dereferences.
- `__proc_set_tty` releases the old session reference under the control lock, unlocks, and only afterward obtains/stores the replacement.
- `disassociate_ctty` independently releases and clears the same field under the control lock; the reader does not take it.
- The equivalent effects introduced by upstream fix `c8bcd9c5be24fb9e6132e97da5a35e55a83e36b9` are absent.
- `CONFIG_SMP=y` and `CONFIG_PREEMPT_VOLUNTARY=y`, but `CONFIG_PREEMPT` is unset. The upstream commit specifically describes its theoretical unprivileged four-byte read for `PREEMPT=y`.

The result is a conditional local information-disclosure candidate, not a root finding. Runtime PTY exposure, a realizable harmful overlap, stale dereference, returned disclosure, controlled write, code execution, root, and persistence remain unproved.

## Artifacts

- Assessment: `evidence/vendor-kernel-tty-session-cve-2020-29660.md`
- Assembly SHA-256: `59c57c33c242e31a0aba484fd096ff735cf6364009f6de598d16feb8c17d05dd`
- Fix patch SHA-256: `87040827df8edc1a7923db1eb71ee85eea03cdab37a0f2ff9ae9462023b4b2f0`
- Model: `tools/uk_fw/tty_session_lock_model.py`
- Tests: `tests/test_tty_session_lock_model.py`
- Deterministic model-report SHA-256: `453e0fee85ba1c3bc675d4322bf14e240ef4d659beb4cffb7a892cf04c015b46`

## Review and safety

- Semantic review: `ACCEPT` after correcting namespace-level-dependent PID offsets.
- Model review: `ACCEPT` after separating independent configuration facts from conjunctions, removing operational addresses from model output, and adding the complete 64-state Boolean matrix and CLI invariants.
- No target operation or active race material was created.
