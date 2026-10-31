# Checkpoint — exact CVE-2016-0723 retained line-discipline reference audit

## Result

CVE-2016-0723 is rejected for the exact recovered kernel by retained-reference
effects matching upstream fix `5c17c861a357e9458001f021a7afa7aab9937439`.
Exact command dispatch reaches a path that waits for the line-discipline
reference, loads `ldisc->ops->num` only afterward, performs the four-byte user
copy, and dereferences the same retained object before return. There is no
branch around dereference after successful wait, including on user-copy error.
This proves fixed effects, not historical patch provenance or general TTY
safety.

## Evidence

- `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- configuration SHA-256:
  `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`
- authoritative map SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`
- ranges:
  - `tty_ioctl [0xffffffff812871f8,0xffffffff81287d46)`;
  - `tty_ldisc_ref_wait [0xffffffff8128d207,0xffffffff8128d243)`;
  - `tty_ldisc_ref [0xffffffff8128d243,0xffffffff8128d27e)`;
  - `tty_ldisc_deref [0xffffffff8128d27e,0xffffffff8128d291)`;
  - `__put_user_4 [0xffffffff812094a0,0xffffffff812094d0)`;
  - `bad_put_user [0xffffffff812094f9,0xffffffff81209510)`.
- assembly SHA-256:
  `358b8e8b4402841fcfc834a2ad23535274b0cd2804114fd78d6c70d5bac903cb`
- patch SHA-256:
  `b99eb5238c54e8d49834ef225761ded17ebf0d130ea11ea3e4206bad619586c1`
- deterministic model-report SHA-256:
  `26ada294eb83e8d7986a00fadf0b2a458dc5332ae331fa95d8adb174bf47e3c7`

## Model contract

Schema v2; twelve Boolean inputs; deterministic explicit UTF-8/LF; all-or-none
fail-closed CLI; tri-state unknown for incomplete fixed-effect facts; explicit
contrary unlocked-dereference fact; null runtime and impact observations; and
exhaustive assertions for every emitted classification field. The report emits
no addresses, target operation, terminal/race schedule, command, payload,
target instructions, or firmware bytes.

## Boundary and safety

Installed identity, runtime TTY/device policy, concurrency, stale access,
disclosure, crash, corruption, root, and persistence remain unobserved. No
recovered target was run; no target operation, terminal, process, thread, race,
trigger material, crash, privilege transition, or persistence action occurred.

## Validation and review status

- Focused model validation: **PASS**, `8 tests, 4111 subtests`.
- Bytecode compilation: **PASS** for the model and focused test.
- `git diff --check`: **PASS**.
- Complete suite: **PASS**, `578 passed, 152717 subtests passed`.
- Public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Independent exact-binary and package review: **ACCEPT**.
