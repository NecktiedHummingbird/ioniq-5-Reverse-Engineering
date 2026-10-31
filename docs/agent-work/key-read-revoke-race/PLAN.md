# Plan — exact CVE-2015-7550 key read/revoke race audit

## Objective

Determine whether recovered `vmlinux` retains the unlocked validation-to-read
window fixed by CVE-2015-7550, without invoking keyctl, creating a key or
thread, inducing a race or allocation pressure, or executing target code.

## Method

1. Bind exact kernel identity, configuration, authoritative embedded-kallsyms
   ranges, and upstream fix `b4a1b4f5047e4f54e194681125c74c0aa64d637d`.
2. Bind the reader's key pointer, `key + 0x20` rwsem, validation, optional read
   callback, unlock, and release ordering.
3. Bind revoke's state mutation and optional callback to write ownership of the
   same key/rwsem object.
4. Corroborate that validation reads the revoked-state field and bit changed by
   revoke.
5. Retain exact complete functions and real instruction boundaries.
6. Add a deterministic Boolean-only tri-state model with exhaustive tests.
7. Keep installed identity, runtime policy, concurrency, stale access, crash,
   corruption, privilege and persistence separate.
8. Require independent exact-binary review and focused/full validation before
   commit.

## Non-goals

No target or keyctl syscall, key, process, thread, race, allocation pressure,
crash attempt, recovered-target execution, privilege action, or persistence.
Rejecting this CVE does not establish general key-subsystem or callback safety.
