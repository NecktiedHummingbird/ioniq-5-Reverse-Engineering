# Checkpoint — exact CVE-2016-7910 block seq-iterator lifetime audit

## Result

CVE-2016-7910 is rejected for the exact recovered kernel by the same
cleanup-side, post-free field-clear effect as the upstream fix. The stripped
binary does not establish whether that source change came from the upstream
commit, its stable backport, or independent vendor work. Complete exact
`disk_seqf_stop` machine code loads the iterator
from `seq_file.private`, passes it to exact `class_dev_iter_exit` and `kfree`,
then stores pointer-width zero to the same owner field before returning. A later
allocation failure therefore cannot expose the freed iterator to another stop
through that field.

## Exact evidence

- Recovered `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- `CONFIG_BLOCK=y`; `CONFIG_PROC_FS=y`
- Authoritative embedded-kallsyms map:
  `work/eu-260128/kallsyms.tsv`
- Embedded-kallsyms map SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`
- Exact ranges:
  - `disk_seqf_next [0xffffffff811f2c92,0xffffffff811f2cb4)`
  - `disk_seqf_start [0xffffffff811f2cb4,0xffffffff811f2d26)`
  - `disk_seqf_stop [0xffffffff811f2d26,0xffffffff811f2d56)`
- Exact assembly SHA-256:
  `466a6c195ec3bfad9367da414716633be9e5fb7ef524a25a5555ebd56094f7d4`
- Upstream patch SHA-256:
  `701c7be0854836b8c7f2f4ff21e8e3d4a932809c2d32fe572215bdd5b03bcff0`
- Deterministic schema-v2 model report SHA-256:
  `e32657eeb22a870d596956c9f4fb2450dd8d3539c95fff646f6534491aee443b`

## Claim boundary

The exact stale `seq_file.private` cleanup premise is absent. In the bounded
model, incomplete fix facts leave the vulnerable retained-pointer premise
unknown rather than claiming it present. Installed-kernel identity, runtime proc
visibility, allocation failure, stale use, repeated free, crash, unrelated
corruption, privilege gain, root and persistence remain unobserved. This
rejection does not generalize to unrelated block, proc, seq-file, allocator, or
lifetime defects.

## Safety

No proc entry was opened, no allocation pressure or repeated read/seek sequence
was created, and no target execution, stale dereference, repeated free, crash,
corruption, privilege transition, or persistence action occurred.

## Validation/review

- Focused model validation: `10 passed, 267 subtests passed`.
- Complete suite: `510 passed, 135370 subtests passed`.
- Public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Python compilation, deterministic/artifact hash checks, and `git diff --check`:
  passed.
- Independent instruction/model/provenance review: **ACCEPT** after correction
  of an allocator-cache description and explicit stripped-binary provenance
  boundary; no remaining issue.
