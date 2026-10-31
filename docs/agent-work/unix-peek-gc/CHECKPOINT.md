# AF_UNIX CVE-2021-0920 exact-GC-barrier checkpoint

Status: complete — exact missing-GC-serialization premise accepted as V-025.

## Result

- Exact shipped `unix.ko` contains both affected receive paths.
- Datagram and stream paths derive MSG_PEEK from flag bit `0x2`.
- Both duplicate non-null attached file lists through exact `scm_fp_dup`.
- Duplicate returns are stored in the exact SCM cookies passed to `scm_recv`.
- Exact `unix_gc_lock` is `.bss+0x102e`; neither interval directly or
  indirectly acquires it.
- The stream's only intervening lock operation is a per-socket receive-mutex
  unlock, not a GC barrier.
- Two frozen semantic reviews and model code review returned `ACCEPT`.

## Deliverables

- `evidence/vendor-kernel-unix-peek-cve-2021-0920.md`
- `evidence/artifacts/kernel-candidates/kernel-unix-peek-cve-2021-0920.asm`
- `evidence/artifacts/kernel-candidates/cve-2021-0920-fix.patch`
- `tools/uk_fw/unix_peek_gc_model.py`
- `tests/test_unix_peek_gc_model.py`
- passive `/proc/modules` capture and exact module hash in the bench bundle

## Boundary

No runtime module load, socket/descriptor graph, overlapping GC pass, candidate
selection, premature free, stale use, UAF, controlled reuse, corruption, code
execution, root, policy escape, or persistence was executed or established.
