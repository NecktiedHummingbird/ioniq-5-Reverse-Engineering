# Checkpoint — exact CVE-2016-7911 ioprio task-lock audit

## Result

CVE-2016-7911 is rejected for the exact recovered kernel by same-lock effects
matching upstream fix `8ba8682107ee2ca3347354e018865d8e1967c5f4`.
`get_task_ioprio` locks `task + 0x630` before reading `task->io_context +0x678`
and `io_context->ioprio +0x12`; exact `exit_io_context` uses the same lock while
loading and clearing that pointer, then unlocks before releasing the object.
Commit provenance is not inferable from the stripped binary.

## Evidence

- `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- `CONFIG_BLOCK=y`
- authoritative map SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`
- ranges:
  - `get_task_ioprio [0xffffffff811f5e7b,0xffffffff811f5ec0)`
  - `SyS_ioprio_get [0xffffffff811f616a,0xffffffff811f6371)`
  - `exit_io_context [0xffffffff811eab51,0xffffffff811eab95)`
- assembly SHA-256:
  `c2ad1649793759124b1f65553194727cc39082a09c4d7c1f2ca82b41a76641d7`
- patch SHA-256:
  `35c7a6a530095ed0424987d820e46db341a250820ed88ce1b1a89ec30acabd67`
- model-report SHA-256:
  `b1ddc09f0f555188b85ab5f1cab1fa23a3f790844a81967e72bfcc9aeca612c8`

## Boundary and safety

Installed identity, runtime syscall/task policy, concurrent exit, stale read,
crash, disclosure, corruption, root and persistence remain unobserved. No
target or ioprio syscall, process, thread, race, allocation pressure, target
execution, crash, privilege transition, or persistence action occurred.

## Validation/review

- Focused model validation: `8 passed, 267 subtests passed`.
- Complete suite: `518 passed, 135637 subtests passed`.
- Public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Independent review: **ACCEPT** after correcting validation-status wording,
  exhaustive output-field assertions, and target-syscall claim scope.
