# AF_PACKET frame-count residual checkpoint

Status: complete; independent semantic/model review **ACCEPT**.

## Result

- The exact module accepts a wrapped 32-bit `frames_per_block * tp_block_nr`
  equality because the later upstream non-overflow guard is absent.
- Successful allocation is based on the full block count, not wrapped frame
  count.
- All exact V1/V2 receive, transmit, poll, readiness, progression, and lookup
  consumers remain in bounds. The proof includes wrapped `tp_frame_nr == 0` and
  `frame_max == UINT_MAX`.
- `packet_mmap` separately multiplies block count by pages per block in 32 bits.
  A wrapped expected size can make the mapping too short, but exact
  `vm_insert_page` rejects addresses at or beyond `vm_end`; no out-of-VMA insert
  is established.
- Three syntactic signed vector-index edges begin at block count `0x80000001`.
  The minimum vector is `0x400000008` bytes and produces allocation order 23.
  Exact `__rmqueue` and `__alloc_pages_nodemask` reject every order above 10, so
  `__kmalloc` returns null and `packet_set_ring` exits before block allocation,
  cleanup, publication, or mmap. The opcodes are present but predicate-infeasible.
- Classification: the missing guard is a correctness/early-rejection gap, not a
  defensible V1/V2 frame-lookup corruption or local-root primitive.

## Tracked artifacts

- `evidence/vendor-kernel-af-packet-frame-count.md`
- `evidence/artifacts/kernel-candidates/kernel-af-packet-frame-count.asm`
  - SHA-256 `f7097d97fc2e29671673aa67c0cd34df7241e60e0fb49d6d782376fca37d9994`
- `tools/uk_fw/af_packet_frame_geometry_model.py`
- `tests/test_af_packet_frame_geometry_model.py`
- deterministic default report SHA-256:
  `b8d42156434be6ff8aaecc2a1b67650e124cd68f90d0eaf3991a7920bd3611b0`

## Validation

- Focused: `11 passed, 23 subtests passed`.
- Complete suite: `483 passed, 134451 subtests passed`.
- Public research harness: **PASS**.
- Independent review found missing `free_pg_vec` evidence/overbroad cleanup
  wording, argparse abbreviation aliasing, an off-by-one signed-index threshold,
  and two additional signed index sites in setup/mmap. All were corrected. A
  final exact allocator trace made those three edges predicate-infeasible; its
  independent semantic/model/cross-document review returned **ACCEPT**.

## Delegation/routing

- Generic public-only Astra planning child:
  `6c49c736-1356-475d-8773-8cfd1e1fd4f0`; completed and corroborated the
  allocation/index proof and required mmap separation.
- Fable doctor check failed closed because its catalog route is not advertised
  for native subagents (`multi_agent_version != v2`). No inference probe was
  made.
- DeepSeek Flash was static-ready according to the local doctor, but native
  dispatch rejected `deepseek/deepseek-v4.1-flash` as unknown. No provider was
  silently substituted for implementation.

## Safety

No packet socket, ring request, mmap, packet, namespace, capability, allocation
pressure, race, target execution, crash, corruption, privilege transition, root,
or persistence action was created or performed.
