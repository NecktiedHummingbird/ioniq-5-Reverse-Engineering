# Plan — exact CVE-2018-14634 preventive argument-stack-cap audit

## Objective

Determine whether recovered `vmlinux` contains the six-MiB argument-space cap
that prevents CVE-2018-14634's oversized initial-stack state, without invoking
target-side exec, constructing oversized target argument/environment vectors,
inspecting or running a privileged target executable, or executing target code.

## Method

1. Bind exact kernel identity, configuration, authoritative embedded-kallsyms
   range, and upstream preventive commit
   `da029c11e6b12f321f36dac8771e833b65cec962`.
2. Bind complete `copy_strings`, candidate-size calculation, cumulative-size
   addition-overflow routing, `ARG_MAX`, stack-rlimit load/division, six-MiB constant,
   minimum selection, final comparison, and page-release/failure path.
3. Prove feasible large-argument acceptance routing rather than relying on a
   constant or source-version match.
4. Keep static exec support, privileged-binary presence and runtime policy
   separate.
5. Add a deterministic Boolean-only tri-state model and exhaustive tests.
6. Keep argument construction, execution, corruption, privilege and persistence
   unobserved.
7. Require independent review and focused/full validation before commit.

## Non-goals

No recovered-kernel exec syscall, target process, oversized target
argument/environment vector, privileged-target-binary execution, malformed target
stack, allocation pressure, target execution, crash attempt, privilege action, or
persistence. Ordinary host validation may create host subprocesses. Rejecting
this CVE does not prove ELF-loader or exec safety generally.
