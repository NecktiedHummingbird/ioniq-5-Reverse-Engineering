# Checkpoint — exact CVE-2016-7914 associative-array leaf-guard audit

## Result

CVE-2016-7914 is rejected for exact recovered `vmlinux` by leaf-guard effects
matching upstream `8d4a2ec1e0b41b0cf9a0c5cd4511da7f8e4f3de2`. In the inlined
terminal-node loop, null slots record a free position, metadata-tagged slots
branch past `compare_object`, and only leaf-tag fallthrough reaches the callback.
The stripped binary does not establish source-commit provenance.

## Evidence

- `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- `CONFIG_KEYS=y`
- authoritative map SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`
- ranges:
  - `assoc_array_insert [0xffffffff8121379b,0xffffffff812140ee)`
  - `__key_link_begin [0xffffffff811b428f,0xffffffff811b437a)`
- assembly SHA-256:
  `382b2a7b6083ebfabfd65cc3fd0c3da11999d190708df69156e7bb6f4ec0386c`
- patch SHA-256:
  `6ad914e07cb0cab1d3e6826119287553b5e96356f2b4a4366d8e73b7cc18c481`
- model-report SHA-256:
  `8e05d9116d95742d33ec070ab880ade4c1a72a0d4690bd411fafdff30fd40c01`

## Boundary and safety

Installed identity, runtime key syscall/SMACK policy, attacker-controlled tree
shape, nonleaf callback, out-of-bounds read, disclosure, crash, corruption, root
and persistence remain unobserved. No target or key syscall, key/keyring,
associative-array state, target execution, crash, privilege transition, or
persistence action occurred.

## Validation/review

- Focused model validation: `8 passed, 524 subtests passed`.
- Complete suite: `526 passed, 136161 subtests passed`.
- Public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Independent exact-binary review: **REJECTED-BY-FIX-EFFECTS**.
- Independent package review: **ACCEPT**.
