# timerfd CVE-2017-10661 exact-lock checkpoint

Status: complete — exact missing-context-serialization premise accepted as V-026.

## Result

- Same-file operations obtain references and resolve one live timerfd context.
- Setup decides/sets membership before the static global-list lock.
- Removal clears membership before that same global lock.
- No common context-derived cancel lock spans either transition.
- The waitqueue lock is acquired only after setup/removal and is not equivalent.
- Creation contains no corresponding per-context cancel-lock initialization.
- Two frozen semantic reviews and model code review returned `ACCEPT`.

## Deliverables

- `evidence/vendor-kernel-timerfd-cve-2017-10661.md`
- `evidence/artifacts/kernel-candidates/kernel-timerfd-cve-2017-10661.asm`
- `evidence/artifacts/kernel-candidates/cve-2017-10661-fix.patch`
- `tools/uk_fw/timerfd_cancel_lock_model.py`
- `tests/test_timerfd_cancel_lock_model.py`

## Boundary

No timerfd, harmful interleaving, list invariant violation, list corruption,
UAF, controlled reuse, crash, disclosure, code execution, root, policy escape,
or persistence was executed or established.
