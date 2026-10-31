# AF_PACKET wrapped frame-count residual: exact V1/V2 consumer audit

Date: 2026-11-03

Target module: `/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko`

Module SHA-256: `c810265b3c22f95d2b90494cc206abd6b4e67b7710bff2adcb177ee4867f467b`

## Result

The exact module lacks the later upstream guard
`frames_per_block > UINT_MAX / tp_block_nr`. Its equality check can therefore
accept `tp_frame_nr == (frames_per_block * tp_block_nr) mod 2^32` even when the
mathematical frame product exceeds `UINT_MAX`.

That accepted wrap does **not** create an allocation/index mismatch in the
reviewed TPACKET_V1/V2 frame lookup. Allocation uses the requested block count,
whereas every logical position is bounded by the wrapped `frame_max`. For every
accepted position, the quotient used as the `pg_vec` index remains below the
allocated block count and the remainder-derived byte offset remains inside the
allocated block. This includes the edge case in which wrapped `tp_frame_nr` is
zero and stored `frame_max` becomes `UINT_MAX`.

`packet_mmap` has a separate 32-bit `pg_vec_len * pg_vec_pages` multiplication.
If that page-count product wraps, its expected VMA size can be smaller than the
actual allocated page sequence. The exact `vm_insert_page` rejects an address
below `vm_start` or at/above `vm_end` before insertion, so the mapping loop
returns an error when it reaches the declared VMA boundary rather than inserting
outside it. Successful cleanup of every possible partially inserted mapping was
not independently reconstructed, but no out-of-VMA insertion follows from this
mapping path. Three syntactic signed vector-index sites are bounded below and
then rejected as predicate-infeasible by the exact allocator path.

Classification: the absent guard admits an invalid wrapped frame-count geometry
and can permit allocation work that a later kernel rejects earlier. It is **not a
defensible memory-corruption or local-root primitive** on the reviewed exact
V1/V2 address paths. The three signed vector-index edges require a vector size
that the exact allocator rejects before publication or cleanup. Actual allocation success, resource exhaustion, mapping
success, crash, corruption, code execution, privilege transition, root, and
persistence were not observed. The published CVE-2017-7308 private-area primitive
remains separately rejected by the existing exact 64-bit arithmetic evidence.

## Exact producer and allocation

`packet_set_ring` is the module-relative FDE `[0x1f5d,0x25aa)`.
The request layout is bound by the exact loads:

- `+0x00`: `tp_block_size`;
- `+0x04`: `tp_block_nr`;
- `+0x08`: `tp_frame_size`;
- `+0x0c`: `tp_frame_nr`.

The ring-buffer fields used below are:

- `+0x00`: `pg_vec`;
- `+0x08`: `head`;
- `+0x0c`: `frames_per_block`;
- `+0x10`: `frame_size`;
- `+0x14`: `frame_max`;
- `+0x18`: allocation order;
- `+0x1c`: pages per block;
- `+0x20`: block/vector length.

The exact sequence is:

1. `0x2065–0x207d` rejects a non-positive or non-page-aligned block size.
2. `0x209c–0x20b4` checks the minimum and alignment of frame size.
3. `0x20b6–0x20c0` performs unsigned 32-bit
   `tp_block_size / tp_frame_size`, stores `frames_per_block` at ring `+0x0c`,
   and rejects zero.
4. `0x20c2–0x20d0` loads `tp_block_nr`, performs 32-bit `imull`, and compares
   only the wrapped result with `tp_frame_nr`. There is no division guard from
   upstream `8f8d28e4...` or its final `fc62814d...` form.
5. `0x20d9–0x20fb` widens the block count before multiplying it by the eight-byte
   vector-entry size and calls `__kmalloc`.
6. `0x2122–0x218b` attempts one block allocation for every requested block.
   A failed block routes through `free_pg_vec`; ordinary in-range cleanup returns
   `-ENOMEM`, while the greater-than-`0x80000000` cleanup residual below prevents a
   universal return claim over the full `u32` domain.
7. Only after complete allocation does `0x2252–0x22b5` install the vector and
   store `tp_frame_nr - 1` as `frame_max`, frame size, block count, pages per
   block, and allocation order.

An allocation attempt is not allocation success. The missing frame-count guard
does not shrink the vector or per-block allocation to the wrapped frame count.

## V1/V2 lookup and progression

`packet_lookup_frame` is the complete FDE `[0x19bb,0x19f7)`. Given logical
position `p`, it:

- divides `p` by ring `+0x0c` at `0x19bb–0x19c2`;
- uses the quotient as the eight-byte `pg_vec` index at `0x19c9–0x19cb`;
- multiplies the remainder by ring `+0x10` in 32 bits at `0x19c5`;
- adds that offset to the selected block pointer at `0x19cb`.

All exact V1/V2 callers use a position bounded by `frame_max`:

- receive-room check: `0x1a3a–0x1a4c` uses RX `head`;
- poll previous RX frame: `0x1cba–0x1cda` uses `head-1`, or `frame_max` when
  `head` is zero;
- poll current TX frame: `0x1d32–0x1d44` uses TX `head`;
- receive: `0x315b–0x316e` looks up RX `head`, then `0x32d1–0x32ea` increments it
  or resets it to zero when it equals `frame_max`;
- transmit: `0x42e2–0x42f8` looks up TX `head`; both progression sites
  `0x4db4–0x4dd1` and `0x4df4–0x4e10` increment or reset at `frame_max`.

TPACKET_V3 takes its separate block-queue path at the receive and poll version
branches. It does not justify or weaken the V1/V2 proof.

## Arithmetic proof, including wrapped zero

Let all request/ring fields be unsigned 32-bit values, and let:

- `F = floor(block_size / frame_size)`, with `F > 0`;
- `N = block_count`, with `N > 0`;
- `M = 2^32`;
- `P = F*N` as a mathematical integer;
- `R = P mod M`, the accepted `tp_frame_nr`;
- accepted positions be `0 <= p <= R-1` when `R>0`, or
  `0 <= p <= M-1` when `R=0` because `frame_max` wraps.

For `R>0`, `p < R <= P`, so `floor(p/F) < P/F = N`.
For `R=0`, `P=kM` for some `k>=1`; therefore
`floor((M-1)/F) < M/F <= kM/F = N`.
Thus the quotient index is below the allocated `N`-entry vector in both cases.

For the in-block offset, `p mod F <= F-1`. Because
`F=floor(block_size/frame_size)`,
`(F-1)*frame_size < F*frame_size <= block_size`. The 32-bit multiply at
`0x19c5` cannot wrap before this bound: the product is strictly below the
accepted positive block size, which `0x2065–0x206b` bounds below `2^31`.

The wrap can make the logical ring a subset of its allocated capacity; it cannot
make the lookup quotient exceed the allocation established from `N`.

## Separate mmap arithmetic

`packet_mmap` is the complete module-relative FDE `[0x596,0x6ef)`.
At `0x5f2–0x5fd`, it loads pages per block and block count as 32-bit values,
performs `imull`, then widens and shifts the wrapped page count by 12. It compares
the resulting expected size with the VMA size at `0x617–0x625`.

The mapping loops are driven by the actual stored block count and pages per
block (`0x63d–0x6ac`), not by wrapped `tp_frame_nr`. Each page is passed to
`vm_insert_page` at `0x67e`. The exact vmlinux function
`vm_insert_page`, absolute VA FDE
`[0xffffffff810ee3bd,0xffffffff810ee50e)`, compares the address against
`vm_start` at `0xffffffff810ee3db–0xffffffff810ee3de` and against `vm_end` at
`0xffffffff810ee3e4–0xffffffff810ee3eb`; an out-of-range address routes to
`-EFAULT` at `0xffffffff810ee4e1`. `packet_mmap` tests that return at
`0x683–0x688` and exits on failure.

Three exact loops compare a full `u32` block count/length but sign-extend the
low 32-bit index before using it as a vector subscript. The first bad iteration
requires `block_count >= 0x80000001` (strictly greater than `0x80000000`), because
length `0x80000000` exits when the loop counter first reaches that value:

- allocation in `packet_set_ring` compares at `0x2122`, sign-extends at `0x212f`,
  and indexes at `0x2137`; reaching the bad index requires successful vector
  allocation and successful allocation of the preceding `0x80000000` blocks;
- cleanup in complete `free_pg_vec` `[0x4b7,0x53c)` preserves the zero-extended
  length at `0x4dc`, compares at `0x4e0–0x4e4`, sign-extends at `0x4e6`, and
  indexes at `0x4e9`; after the strictly-greater-than-16-GiB zeroed vector
  allocation succeeds, failure of even an early block allocation can pass the
  full requested length to this loop, so this is the weakest of the three
  allocation prerequisites;
- mapping in `packet_mmap` compares stored length at `0x63d–0x641`, sign-extends
  at `0x646`, and indexes at `0x64c`; reaching the bad index requires publication
  after successful vector and all-block allocation, followed by mapping.

### Exact allocator rejection

The exact allocator makes all three signed-index edges predicate-infeasible:

1. At the first bad count, `block_count * 8` is at least `0x400000008` bytes.
   `packet_set_ring` widens before its shift at `0x20d9–0x20dc`, so that size is
   passed without truncation to `__kmalloc`.
2. Exact `__kmalloc` `[0xffffffff8110665a,0xffffffff81106746)` sends every size
   above `0x2000` to `__get_order` and `kmalloc_order` at
   `0xffffffff8110665b–0xffffffff8110667e`.
3. Exact `__get_order` `[0xffffffff81103c70,0xffffffff81103c86)` decrements the
   byte size, shifts by 12, applies `bsr`, and increments. The minimum bad vector
   therefore produces order 23; larger bad vectors produce order at least 23.
4. `kmalloc_order` `[0xffffffff810e78ba,0xffffffff810e78fb)` calls
   `alloc_kmem_pages`, which forwards that order to
   `__alloc_pages_nodemask` `[0xffffffff810d674c,0xffffffff810d6e3d)`.
5. Its fast path reaches exact `get_page_from_freelist`
   `[0xffffffff810d6114,0xffffffff810d6663)`, whose buddy removal reaches exact
   `__rmqueue` `[0xffffffff810d5f25,0xffffffff810d6114)`. `__rmqueue` compares
   requested order with 10 at `0xffffffff810d5f5b`; an order above 10 follows
   the fallback where `0xffffffff810d5fdb–0xffffffff810d60d8` produces a null
   page, retries only the fallback migratetype, and returns null at
   `0xffffffff810d60eb–0xffffffff810d60fe`.
6. After fast-path failure, `__alloc_pages_nodemask` compares the same order with
   10 at `0xffffffff810d6919–0xffffffff810d6923`. An order above 10 bypasses the
   slow allocation path and converges on its null return.
7. `__kmalloc` returns null, and `packet_set_ring` tests that result at
   `0x20fb–0x2102` and exits through `-ENOMEM` before any block-allocation,
   cleanup, publication, or mmap signed-index loop.

Thus the signed-extension opcodes are real but unreachable for every count that
could make them negative. The final upstream frame-product guard would not by
itself reject every `F=1` geometry in this count range; exact allocator rejection,
not that guard, closes these edges. This does not weaken the V1/V2 frame-lookup
proof.

## Upstream comparison

- `8f8d28e4d6d815a391285e121c3a53a0b6cb9e7b` added
  `tp_block_size > UINT_MAX / tp_block_nr` as a sufficient but over-broad guard.
- `fc62814d690cf62189854464f4bd07457d5e9e50` replaced it with the direct
  `frames_per_block > UINT_MAX / tp_block_nr` test so valid rings larger than
  4 GiB were not rejected solely by byte size.

These commits establish the intended non-wrapping validation invariant. Their
messages do not assign a standalone memory-corruption or privilege-escalation
impact to the omitted guard, and exact consumer tracing above does not produce
one.

## Retained evidence and model

- `evidence/artifacts/kernel-candidates/kernel-af-packet-frame-count.asm`
  contains complete `free_pg_vec`, all affected producer/consumer FDEs, exact
  `vm_insert_page`, and the complete exact allocator chain through `__rmqueue`;
  SHA-256
  `f7097d97fc2e29671673aa67c0cd34df7241e60e0fb49d6d782376fca37d9994`.
- `tools/uk_fw/af_packet_frame_geometry_model.py` is a bounded, non-operational
  Boolean/reduced-width classifier. It does not verify the binary or create a
  ring. Default deterministic report SHA-256:
  `b8d42156434be6ff8aaecc2a1b67650e124cd68f90d0eaf3991a7920bd3611b0`.
- `tests/test_af_packet_frame_geometry_model.py` covers wrapped zero, nonzero
  wrap, rejected equality, exhaustive toy geometries, all Boolean evidence
  states, deterministic UTF-8/LF output, and fail-closed CLI parsing.

## Sources

- <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8f8d28e4d6d815a391285e121c3a53a0b6cb9e7b>
- <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fc62814d690cf62189854464f4bd07457d5e9e50>
- <https://github.com/torvalds/linux/blob/v4.1/net/packet/af_packet.c>
- <https://docs.kernel.org/networking/packet_mmap.html>

## Safety boundary

No packet socket, ring request, mmap, packet, namespace, capability, allocation
pressure, race, crash, target execution, corruption, privilege transition, root,
or persistence action was created or performed.
