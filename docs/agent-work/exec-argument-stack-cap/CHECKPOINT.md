# Checkpoint — exact CVE-2018-14634 preventive argument-stack-cap audit

## Result

CVE-2018-14634's oversized argument-space prerequisite is rejected for exact
recovered `vmlinux`. Complete `copy_strings` preserves `ARG_MAX`, then caps larger
space at `min(rlimit(RLIMIT_STACK)/4, 0x600000)` and routes oversize state through
exact page release to `-E2BIG`. These effects match preventive upstream commit
`da029c11e6b12f321f36dac8771e833b65cec962`; stripped code does not establish
commit provenance.

## Evidence

- `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- `CONFIG_MMU=y`, `CONFIG_BINFMT_ELF=y`
- authoritative map SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`
- range: `copy_strings [0xffffffff811161be,0xffffffff811164b0)`
- assembly SHA-256:
  `b240d2a93833c9e000ffa19edb5ddf52bbc523af6645ea57f7c9dd208a86e4c4`
- patch SHA-256:
  `b2bd9af42ba1ada88463ecd5f19c70e9b1b6a789c3a0912f9baf54106c49d724`
- model-report SHA-256:
  `1ddc6b05339544212e9439fc523543d71301bf42f02c83edfa13fbb313b8f156`

## Boundary and safety

Installed identity, privileged-executable presence, runtime exec/uid/SMACK policy,
large argument construction, execution success, stack corruption, root and
persistence remain unobserved. No recovered-kernel exec syscall, target process,
oversized target argument vector, privileged target executable execution, target
code, crash, privilege transition, or persistence action occurred. Ordinary host
validation created host Python subprocesses outside these target claims.

## Validation/review

- Focused model validation: `8 passed, 2062 subtests passed`.
- Complete suite: `534 passed, 138223 subtests passed`.
- Public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Independent exact-binary review: **REJECTED-BY-FIX-EFFECTS**.
- Independent package review: **ACCEPT** after correcting cumulative-overflow
  wording, adding construction/overflow model facts, inclusive-threshold wording,
  and target-versus-host process claim scope.
