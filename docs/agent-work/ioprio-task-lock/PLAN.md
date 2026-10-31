# Plan — exact CVE-2016-7911 ioprio task-lock audit

## Objective

Determine whether recovered `vmlinux` retains the unlocked `task->io_context`
read fixed by CVE-2016-7911, without invoking an ioprio syscall, creating tasks
or concurrency, inducing allocation pressure, or executing target code.

## Method

1. Bind exact kernel identity, configuration, authoritative embedded-kallsyms
   ranges, and upstream fix `8ba8682107ee2ca3347354e018865d8e1967c5f4`.
2. Bind the getter's security gate, task lock, `io_context` pointer load,
   priority load, and unlock ordering.
3. Bind `exit_io_context` to the same task lock and pointer field through
   detachment and object release.
4. Retain complete syscall caller coverage without constructing an invocation.
5. Add a deterministic Boolean-only tri-state model and exhaustive tests.
6. Keep installed identity, runtime policy, concurrency, stale use, crash,
   corruption, privilege and persistence separate.
7. Require independent review and focused/full validation before commit.

## Non-goals

No target or ioprio syscall, process, thread, race, allocation pressure, crash
attempt, target execution, privilege action, or persistence. Rejecting this CVE
does not prove block/task/I/O-context safety generally.
