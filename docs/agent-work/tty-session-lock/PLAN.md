# TTY session-lock audit plan

## Objective

Determine whether the exact recovered kernel retains CVE-2020-29660 machine-code effects and classify the result without running a TTY race or inferring root from a source-version match.

## Acceptance criteria

1. Bind `TIOCGSID` dispatch to the exact reader branch and linked/real TTY object.
2. Bind the session field, control lock, PID reference release/replacement, and downstream object dereference.
3. Compare equivalent machine-code effects against authoritative upstream commit `c8bcd9c5be24fb9e6132e97da5a35e55a83e36b9`.
4. Record exact `CONFIG_PREEMPT`, voluntary-preemption, SMP, TTY, and UNIX98 PTY state.
5. Separate locking defect, documented full-preemption condition, runtime concurrency, freed-memory read, and privilege escalation.
6. Add a Boolean-only deterministic model and complete truth-table tests; emit no target instructions, addresses, trigger, race schedule, payload, or firmware bytes from the model.
7. Obtain independent semantic and model reviews.

## Safety boundary

No PTY, ioctl, thread, race, PID lifetime manipulation, stale access, disclosure, corruption, privilege transition, or recovered-kernel execution.
