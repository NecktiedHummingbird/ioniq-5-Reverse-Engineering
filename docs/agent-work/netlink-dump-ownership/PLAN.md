# Plan — exact CVE-2016-9806 netlink dump ownership audit

## Objective

Determine whether recovered `vmlinux` retains the callback-field race fixed by
upstream CVE-2016-9806, without opening a netlink socket, sending a message,
starting a dump, creating concurrency, or executing target code.

## Method

1. Bind exact kernel/configuration identity and the complete embedded-kallsyms
   `netlink_dump` extent.
2. Preserve authoritative upstream fix
   `92964c79b357efd980812c4de5c1fd2ec8bb5520`.
3. Bind callback mutex ownership, `cb_running`, `cb->module`, `cb->skb`,
   `module_put`, and `consume_skb` in exact machine code.
4. Determine whether post-unlock cleanup reloads mutable callback fields or uses
   object identities captured before unlock.
5. Add a Boolean-only deterministic classifier and exhaustive tests. Complete
   saved-object effects may reject the CVE premise, but missing fix facts must
   not affirmatively prove a vulnerable callback-field reload. The classifier
   must emit no socket address, message, dump request, race schedule, command,
   payload, target instructions, or firmware bytes.
6. Keep installed identity, runtime reachability, concurrency, double free,
   crash, corruption, privilege and persistence as separate unknowns.
7. Obtain independent semantic/model review and run focused/full validation
   before committing.

## Non-goals

- No socket, message, request, thread, race, crash attempt, target execution,
  heap manipulation, privilege action, or persistence.
- No conclusion from a kernel version alone.
- No claim that rejecting this CVE proves all netlink code safe.

## Acceptance

- Complete exact `netlink_dump` range retained with provenance and hashes.
- Every upstream fix effect bound to exact fields, registers, calls, and mutex
  ordering.
- Focused/full tests, public harness, and `git diff --check` pass.
- Independent review returns ACCEPT.
