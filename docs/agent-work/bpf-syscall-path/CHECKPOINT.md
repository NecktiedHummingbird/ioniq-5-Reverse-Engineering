# Checkpoint — exact CVE-2017-16995 syscall-path applicability audit

## Result

CVE-2017-16995 is rejected for the exact recovered kernel only for the named
syscall-based eBPF verifier path. `CONFIG_BPF_SYSCALL` is not set, weak
`sys_bpf` aliases the complete `sys_ni_syscall` range returning `-ENOSYS`, and
native x86-64 syscall-table slot 321 contains the exact pointer to that stub.
The conclusion does not rely on the vendor 4.1-derived banner and does not audit
verifier internals.

`CONFIG_BPF=y`, while classic BPF validation, creation, attachment, interpreter,
and runtime-selection symbols remain compiled. This is not general BPF absence,
classic-BPF safety, or proof that every alternate eBPF entry is absent.

## Evidence hashes

- `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- configuration SHA-256:
  `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`
- authoritative map SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`
- exact retained assembly SHA-256:
  `e36aa175a3ea5cc7083d30d2e2970d90613409cad2177249e6eeed1a05eaf98f`
- upstream fix commit: `95a762e2c8c942780948091f8f2a4f32fce1ac6f`
- retained patch SHA-256:
  `d09d5733423b14add9cb9d9a25487a088cba449d1ca5c614b55dad307f73f557`
- deterministic model-report SHA-256:
  `48e9d32f190d56c1b0a0b8a3ee5240a2964d15e45a75d18d2d9f1a7ca531295b`

## Model contract

Schema v2; nine Boolean inputs; deterministic explicit UTF-8/LF; all-or-none
fail-closed CLI; tri-state unknown for incomplete absence and unproved alternate
entry facts; explicit contrary functional syscall and alternate-entry facts;
classic-BPF compilation preserved as an explicit input and output; null
verifier-internal, installed-device, runtime, and impact outcomes; exhaustive
assertions for every classification field. The report emits no address,
invocation, verifier input, communication endpoint, command, trigger, target
bytes, race, or payload.

## Boundary and safety

Installed-device identity, live dispatch behavior, all alternate eBPF entry
routes, verifier internals, classic-BPF safety, corruption, privilege gain,
unrestricted root, and persistence remain unobserved or unaudited. No recovered
target was run; no target operation, code load, communication endpoint, verifier
input, verifier trigger, race, payload, crash attempt, privilege transition, or
persistence action occurred.

## Validation and review status

- Focused model validation: **PASS**, `8 tests, 529 subtests`.
- Bytecode compilation: **PASS** for the model and focused test.
- `git diff --check`: **PASS**.
- Complete suite: **PASS**, `586 passed, 153246 subtests passed`.
- Public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Independent exact-binary and package review: **ACCEPT**.
