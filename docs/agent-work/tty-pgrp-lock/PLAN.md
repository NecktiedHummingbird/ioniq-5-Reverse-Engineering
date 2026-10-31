# TTY CVE-2020-29661 exact-lock plan

## Goal

Determine whether exact recovered UNIX98 PTY process-group setters contain the
wrong-object locking fixed for CVE-2020-29661, without opening a PTY, issuing an
ioctl, creating concurrency, or manipulating PID lifetimes.

## Acceptance criteria

1. Bind target and real TTY identities on master and slave ioctl routes.
2. Bind `ctrl_lock`, pgrp, and peer-link offsets in exact machine code.
3. Prove whether two setters can modify the same referenced field under distinct
   locks, including distinct peer-object construction.
4. Record exact kernel/configuration and intended `/dev/ptmx` exposure while
   separating configured intent from runtime state.
5. Separate the race premise from successful concurrency, UAF, controlled reuse,
   corruption, privilege gain, and persistence.
6. Add a Boolean-only deterministic model and passive PTY metadata collection.

## Exclusions

No PTY open, controlling-terminal setup, ioctl, process-group transition,
concurrency, PID lifetime manipulation, race schedule, allocation shaping,
corruption attempt, payload, privilege transition, or persistence.
