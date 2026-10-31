# Checkpoint — CVE-2016-4997 compat netfilter path audit

## Result

CVE-2016-4997 is rejected for exact recovered `vmlinux` by an absent compiled
prerequisite. IA32 emulation is disabled, `CONFIG_COMPAT=y` is absent,
`compat_sys_setsockopt` aliases `sys_ni_syscall` and returns `-ENOSYS`, and no
compat iptables translation/check symbol occurs in the authoritative map.
Native IPv4/IPv6 iptables remains compiled; this is not a general netfilter
safety claim.

## Evidence

- `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- config SHA-256:
  `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`
- authoritative map SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`
- exact stub range:
  `sys_ni_syscall [0xffffffff810722cb,0xffffffff810722d8)`
- exact artifact SHA-256:
  `3f548b2cdac454999d919b8f1d88a696810ee1bbbfa94693fc6060f8214a75f9`
- primary patch SHA-256:
  `4a30140d96c857a4cebf0ccdfd6e7a4b80d1d0aed01c002af8a490d33f7afec0`
- related patch SHA-256:
  `b42c9a22f04883903c3a8b9f86efe22dc4b790c95e8f1a1d83ab8053fabaadd7`
- model-report SHA-256:
  `e5d16ebcb6e7d4841e8c6f741a92dd91889dd002645d59c7699d416c8d933cd5`

## Boundary and safety

Installed identity, runtime filtering, native-netfilter safety, request
delivery, corruption, root and persistence remain unobserved. No target syscall,
socket, namespace, packet, filter table, target execution, crash, privilege
transition, or persistence action occurred.

## Validation/review

- Focused model validation: `6 passed, 36 subtests passed`.
- Complete suite: `570 passed, 148606 subtests passed`.
- Public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Corrected independent exact-binary/package review: **ACCEPT**.
