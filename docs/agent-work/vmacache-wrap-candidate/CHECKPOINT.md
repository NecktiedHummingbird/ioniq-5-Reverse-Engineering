# vmacache CVE-2018-17182 exact-candidate checkpoint

Status: complete — exact pre-fix semantic premise accepted as V-022.

## Result

- Two live VMA invalidation paths increment the same 32-bit mm generation and
  call exact `vmacache_flush_all` on zero.
- Its single-user route returns without clearing task cache pointers.
- Exact `mmput` independently binds the tested field to the mm user count.
- Lookup compares and updates only 32-bit mm/task generations.
- No upstream 64-bit/removal fix effect is present.
- Independent frozen semantic review returned `ACCEPT` after field binding.
- Boolean model review returned `ACCEPT`.

## Deliverables

- `evidence/vendor-kernel-vmacache-cve-2018-17182.md`
- `evidence/artifacts/kernel-candidates/kernel-vmacache-cve-2018-17182.asm`
- `evidence/artifacts/kernel-candidates/cve-2018-17182-fix.patch`
- `tools/uk_fw/vmacache_wrap_model.py`
- `tests/test_vmacache_wrap_model.py`

## Boundary

A complete generation cycle has 2^32 states. No target wrap, stale pointer,
UAF dereference, controlled reuse, corruption, code execution, root, or
persistence was executed or established.
