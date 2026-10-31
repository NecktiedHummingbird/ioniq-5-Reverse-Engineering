# Plan — CVE-2016-4997 compat netfilter path audit

## Objective

Determine whether the recovered 64-bit kernel compiles and dispatches the
compat iptables replace path affected by CVE-2016-4997, without invoking a
target syscall, creating a namespace/socket/filter table, or constructing an
input.

## Method

1. Bind exact kernel, configuration and authoritative map identities.
2. Establish the CVE's public compat-path prerequisite from authoritative
   records and fixes.
3. Check IA32/compat configuration, compat syscall dispatch, and compat
   translation/check symbols.
4. Retain native iptables symbols to prevent overbroad subsystem-absence claims.
5. Add a deterministic tri-state Boolean model with exhaustive tests.
6. Keep installed identity, runtime policy, native-netfilter safety, request
   delivery, corruption, privilege and persistence separate.
7. Require independent review and focused/full validation before commit.

## Non-goals

No target syscall, socket, namespace, packet, filter/table input, crash attempt,
target execution, privilege action, or persistence. An absent compat path does
not establish general native netfilter safety.
