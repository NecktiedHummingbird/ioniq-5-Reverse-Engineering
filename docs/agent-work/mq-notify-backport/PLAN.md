# CVE-2017-11176 exact-kernel backport plan

## Goal

Determine whether recovered `vmlinux` retains CVE-2017-11176's stale-socket
reference over-release without executing a race or target syscall.

## Acceptance criteria

1. Bind analysis to exact SHA-256, Build ID, architecture, symbol ranges, and
   ELF address/file-offset mapping.
2. Compare authoritative vulnerable/fixed source and upstream fix metadata.
3. Trace the exact return-one edge through every retry failure successor to
   socket-detach or skb-only cleanup.
4. Confirm the callee's socket-reference release before return value one.
5. Retain minimal reviewable instructions and a deterministic boolean-only
   ownership model.
6. Keep root, runtime reachability, policy escape, and owner-build applicability
   as separate claims.

## Exclusions

No message-queue race, netlink trigger, heap manipulation, payload, target
executable, privilege transition, persistence, or physical-unit action.
