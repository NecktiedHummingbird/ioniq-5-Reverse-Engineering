# Plan — exact CVE-2016-7914 associative-array leaf-guard audit

## Objective

Determine whether recovered `vmlinux` can call `compare_object()` on a
metadata-tagged terminal-node slot as in CVE-2016-7914, without issuing a target
or key syscall, creating keys/keyrings, constructing associative-array state, or
executing target code.

## Method

1. Bind exact kernel identity, configuration, authoritative embedded-kallsyms
   ranges, and upstream fix `8d4a2ec1e0b41b0cf9a0c5cd4511da7f8e4f3de2`.
2. Bind the inlined terminal-node loop's slot load, null branch, tag test,
   callback arguments, callback target offset, branch polarity, and loop bound.
3. Distinguish structural CFG dominance from feasible-path exclusion of nonleaf
   slots.
4. Bind static keyring use and one direct caller without invoking a syscall.
5. Add a deterministic Boolean-only tri-state model and exhaustive tests.
6. Keep installed identity, runtime policy, tree construction, callback outcome,
   disclosure, crash, corruption, privilege and persistence separate.
7. Require independent review and focused/full validation before commit.

## Non-goals

No target/key syscall, key descriptor, keyring, associative-array mutation,
malformed state, allocation pressure, target execution, crash attempt, privilege
action, or persistence. Rejecting this CVE does not prove keyring or
associative-array safety generally.
