# mremap CVE-2018-18281 exact-ordering checkpoint

Status: complete — exact pre-fix lifetime-window premise accepted as V-023.

## Result

- Ordinary source PTEs are atomically cleared and installed at destination.
- Exact source and distinct destination PTLs are acquired and later released;
  the alias case releases the shared lock once.
- No TLB flush occurs before those releases.
- A deferred flag is set only afterward and reaches exact old-range
  `flush_tlb_mm_range` at outer exit.
- Upstream fix moves that flush before both PTL releases and removes the
  deferred outer flush.
- Two independent frozen semantic reviews returned `ACCEPT` after explicit
  lock/call/range binding.
- Boolean model review returned `ACCEPT`.

## Deliverables

- `evidence/vendor-kernel-mremap-cve-2018-18281.md`
- `evidence/artifacts/kernel-candidates/kernel-mremap-cve-2018-18281.asm`
- `evidence/artifacts/kernel-candidates/cve-2018-18281-fix.patch`
- `tools/uk_fw/mremap_tlb_order_model.py`
- `tests/test_mremap_tlb_order_model.py`

## Boundary

No concurrent invalidation, physical-page release/reuse, stale translation,
stale access, controlled data, corruption, code execution, root, policy escape,
or persistence was executed or established.
