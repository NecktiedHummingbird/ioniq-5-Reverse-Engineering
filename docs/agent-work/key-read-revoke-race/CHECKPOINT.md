# Checkpoint — exact CVE-2015-7550 key read/revoke race audit

## Result

CVE-2015-7550 is rejected for the exact recovered kernel by same-rwsem effects
matching upstream fix `b4a1b4f5047e4f54e194681125c74c0aa64d637d`.
`keyctl_read_key` takes `key + 0x20` for reading before validation and retains
it through the read callback. `key_revoke` takes that same rwsem for writing
across revoked-state mutation and the revoke callback. Commit provenance is not
inferable from the stripped binary.

## Evidence

- `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- `CONFIG_KEYS=y`, `CONFIG_SMP=y`, `CONFIG_PREEMPT_VOLUNTARY=y`
- authoritative map SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`
- ranges:
  - `key_revoke [0xffffffff811b239c,0xffffffff811b2401)`;
  - `keyctl_revoke_key [0xffffffff811b4af2,0xffffffff811b4b6b)`;
  - `keyctl_read_key [0xffffffff811b509a,0xffffffff811b516e)`;
  - `key_validate [0xffffffff811b5dce,0xffffffff811b5e10)`.
- assembly SHA-256:
  `8dfaf1486bf070d154ac02d1f818ef9193f8a0f16ff9fdc4c72af39f1434ba6e`
- patch SHA-256:
  `e2576be983a765c1a462fe9d90bcfcedf9fc076def125ffa94937513e264d7cc`
- model-report SHA-256:
  `2c1a56f8d3ceec3dfb1d6fbfc63ec62593f56281f87cdd3c99add0b63ec8246c`

## Boundary and safety

Installed identity, runtime keyctl policy, concurrency, stale access, crash,
corruption, root and persistence remain unobserved. No target or keyctl syscall,
key, process, thread, race, allocation pressure, target execution, crash,
privilege transition, or persistence action occurred.

## Validation/review

- Focused model validation: `8 passed, 73 subtests passed`.
- Complete suite: `564 passed, 148570 subtests passed`.
- Public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Independent exact-binary/package review: **ACCEPT**.
