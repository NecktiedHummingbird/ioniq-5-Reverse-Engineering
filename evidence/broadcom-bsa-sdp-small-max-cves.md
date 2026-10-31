# Broadcom BSA SDP small-maximum assessment — CVE-2017-13255 / CVE-2017-13256

## Executive conclusion

For the two exact recovered Broadcom BSA binaries below, static analysis
**conditionally rejects only the public small-maximum physical out-of-bounds-
write mechanism** associated with CVE-2017-13255 and CVE-2017-13256 on the
feasible-response-path prerequisites specified below.

Both exact handlers lack the public fix's source-like `max_list_len < 4` early
rejection. On a feasible ordinary response-building path, initial effective
internal maxima 0, 1, or 2 retain a logical effective-limit exceedance: outer
sequence-header construction can reach scratch offset 2. Error exits can occur
before that path. The write matrix therefore requires syntactically valid
handler input, successful scratch allocation/reuse, and, for continuation,
accepted valid internal continuation state. That fact does not become the
public physical write beyond an object sized to the small maximum in these
binaries. Both handlers allocate scratch using remote MTU; GKI selects a
capacity-sufficient public pool whose minimum exact user capacity is 64 bytes.
On the stated path, initial writes reach no higher than offset 2 and
continuation writes are bounded by the effective internal maximum 0..3.

This is not a general SDP safety finding. Runtime reachability, installed
identity, adapter policy, channel security, other SDP behavior, controlled
execution, impact, and owner-device applicability remain unknown.

## Exact scope and identity

The exact analysis started from repository baseline
`0a9a7f2fd1cb3b25d928fe9f32fe65cac055d121`. Final integration review used
pre-delivery HEAD `30f6cace8d2c776b2501c88791b7e54dd4da9055`; the recovered binaries and
ignored machine-code inputs were unchanged across that interval. Concurrent
commit `30f6cac` accidentally absorbed a preliminary version of this package's
changelog entry, while the model, tests, assessment, patch, and static artifact
remained untracked. The present delivery corrects that preliminary wording and
records the complete package. Analysis is bound to these recovered ET_DYN
x86-64 images (addresses below are image virtual addresses before runtime
relocation):

| Image | SHA-256 | Build ID | Embedded BSA version | Exact relevant ranges |
|---|---|---|---|---|
| `/app/bin/vbtd-51` | `55e21d077082e97f56fb113a1d3b216c0f2e63aa02fc4cd754a6593bc6cec9e0` | `12175aa88ccff70cc56498e0208c9a51aac0c9e9` | `BSA0107_00.51.00` | search-attribute FDE `[0x841dc0,0x842628)`; service-attribute dispatcher FDE `[0x842630,0x842e0b)`; `GKI_getbuf_r [0x7ad2e0,0x7ad690)`; `gki_buffer_init [0x7ac590,0x7ad284)`; `sdpu_build_partial_attrib_entry [0x8445f0,0x8448bf)` |
| `/app/bin/vbtd-63` | `c56b68fdd35b16b95688ab54a48ffb9f18034d925c057e86f8b9fe304f8b26b9` | `04141ed222ee8f150c0eb0e46fdb73624d168920` | `BSA0107_00.63.00` | search-attribute FDE `[0x8425b0,0x842e00)`; service-attribute dispatcher FDE `[0x842e00,0x8435c3)`; `GKI_getbuf [0x7af2f0,0x7af633)`; `gki_buffer_init [0x7ae5a0,0x7af294)`; `sdpu_build_partial_attrib_entry [0x844d90,0x84504f)` |

Firmware routing selects `vbtd-63` for PCB versions 11/12 and `vbtd-51` for
other PCB values, as separately documented in
[`broadcom-bsa-bluetooth-cves.md`](broadcom-bsa-bluetooth-cves.md). That routing
fact does not establish which binary was installed or active on any particular
owner device.

## Public baseline

The public records map:

- **CVE-2017-13255 / Android bug 68776054** to
  `process_service_attr_req`;
- **CVE-2017-13256 / Android bug 68817966** to
  `process_service_search_attr_req`.

The shared public fix is commit
`f0edf6571d2d58e66ee0b100ebe49c585d31489f` (parent
`ec16f7d8c7e359a68ffe6b76e88add2210bf2cbd`). It adds the same
`max_list_len < 4` error path before a `max_list_len`-sized scratch allocation
in both handlers. The byte-for-byte retained patch is:

- [`artifacts/network-candidates/f0edf6571d2d58e66ee0b100ebe49c585d31489f.patch`](artifacts/network-candidates/f0edf6571d2d58e66ee0b100ebe49c585d31489f.patch)
- SHA-256
  `a0470c20592473144f8114cf41ab4cb2479fe2c108a4aa73fa4864eabd02ca34`

The public descriptions and patch identify the mechanism to test; they do not
by themselves transfer Android source behavior or affected-version status to
these Broadcom BSA binaries.

## Static method

The review used only static host tooling. The complete handler, allocator,
initializer, and partial-attribute-helper ranges were regenerated with
`/opt/homebrew/opt/llvm/bin/llvm-objdump`; FDE boundaries and ET_DYN identity
were checked with `/opt/homebrew/opt/llvm/bin/llvm-readelf`. Neither recovered
binary was executed.

The retained exact-static excerpt, commands, instruction bytes, ranges, and
semantic derivation are in:

- [`artifacts/network-candidates/broadcom-bsa-sdp-small-max-exact-static.txt`](artifacts/network-candidates/broadcom-bsa-sdp-small-max-exact-static.txt)
- SHA-256
  `414d7bc0687960762c15b8e270eac9aaa2a5ae660b15c00feff9a5a5d9a1d2f2`

A pure deterministic finite model records the result without interacting with
the target:

- [`../tools/uk_fw/bluetooth_sdp_small_max_model.py`](../tools/uk_fw/bluetooth_sdp_small_max_model.py)
- exhaustive test:
  [`../tests/test_bluetooth_sdp_small_max_model.py`](../tests/test_bluetooth_sdp_small_max_model.py)

## Matrix quantity and path prerequisites

The finite `0..3` input is the **effective internal maximum after the recovered
remote-MTU cap**, not unconditionally the peer-requested value. For a small
peer-requested maximum under an ordinary protocol-valid remote MTU, the cap
selects that peer value, so the quantities coincide. The separate low/invalid
remote-MTU subtraction and possible wrap edge remains unknown and is not
covered by the matrix.

The matrix applies only after:

1. syntactically valid handler input passes earlier parsing and validation;
2. control reaches ordinary response-list construction;
3. scratch allocation or reuse succeeds; and
4. for continuation, valid internal continuation state is accepted, including
   a feasible state-derived attribute offset when the partial builder is used.

Earlier error exits are not classified as if they reach header construction.
Corrupted or impossible internal attribute offsets remain unknown.

## Independent handler traces

### CVE-2017-13255 — service-attribute handler

In both binaries this logic is inlined in `sdp_server_handle_client_req`.

1. **Maximum derivation.** The two-byte peer-requested maximum is assembled and
   converted to the effective internal maximum by the remote-MTU cap (`vbtd-51`
   `0x8427ae-0x8427e8`; `vbtd-63` `0x842f7e-0x842fb8`). Complete review through
   each enclosing FDE found no equivalent of the public less-than-four guard.
2. **State split.** Initial state allocates/reuses scratch, sets the write cursor
   to scratch base + 3, and marks initial-header state. Continuation validates
   state, uses the existing scratch base as its cursor, and does not re-enter
   outer initial-header construction.
3. **Body bound.** Before whole or partial attribute construction, remaining
   space is calculated as capped maximum minus cursor displacement and tested
   for positive space (`vbtd-51` `0x842a04-0x842a1d`; `vbtd-63`
   `0x8431d4-0x8431ed`). Whole entries are selected only when their computed
   length fits. Complete `sdpu_build_partial_attrib_entry` review (`vbtd-51`
   `[0x8445f0,0x8448bf)`, clamp/copy `0x8446ec-0x84472a`; `vbtd-63`
   `[0x844d90,0x84504f)`, clamp/copy `0x844e84-0x844eb6`) proves that, for a
   valid feasible state-derived offset, copy length and destination advancement
   are both `min(remaining, total_serialized_length - attr_offset)`. Corrupted
   or impossible offsets and general helper safety remain unknown.
4. **Initial header.** The state gates (`vbtd-51` `0x842b01`; `vbtd-63`
   `0x8432d1`) restrict outer header construction to initial state. Long and
   short encodings can reach scratch offset 2 on the feasible path and neither
   writes past it.
5. **Allocation and copy.** Scratch allocation uses CCB remote MTU, not the
   effective internal maximum (`vbtd-51` request/call `0x842d32/0x842d43`; `vbtd-63`
   `0x8434f6/0x8434fb`). Response-copy calls are `0x842b97` and `0x84335b`;
   copy length is at most three for initial effective maxima 0..3 and at most
   the effective maximum for accepted valid continuation state. Successor
   routing does not add scratch writes.

### CVE-2017-13256 — service-search-attribute handler

1. **Maximum derivation.** The peer-requested maximum is assembled and converted
   to the effective internal maximum by the remote-MTU cap at `vbtd-51`
   `0x841e60-0x841e9a` and `vbtd-63` `0x842650-0x84268a`. Complete review again
   found no less-than-four branch.
2. **State split.** Initial state sets the cursor to scratch base + 3;
   continuation restores the existing scratch base and marks continuation so
   outer initial-header construction is skipped (`vbtd-51` state gate
   `0x8421a1`; `vbtd-63` `0x842991`).
3. **Nested/body bound.** Before reserving a three-byte inner sequence header,
   the handler requires more than two remaining bytes (`vbtd-51`
   `0x841fcf-0x841fea`; `vbtd-63` `0x8427bf-0x8427da`). Attribute builders use
   the same checked remaining-space pattern and complete valid-state partial-
   helper clamp described above. For initial effective maxima 0..3 on the
   feasible path, base + 3 leaves no space and no body construction occurs. In
   accepted valid continuation, effective maxima 0..2 cannot reserve the inner
   header; effective maximum 3 can reach only offsets 0..2.
4. **Initial header.** Long and short outer encodings can reach offset 2 on the
   feasible path and stop there. Continuation does not rewrite this outer
   header.
5. **Allocation and copy.** Scratch requests again use remote MTU (`vbtd-51`
   `0x84254b/0x84255d`; `vbtd-63` `0x842d2b/0x842d31`). Response-copy calls are
   `0x84223c` and `0x842a20`; the same conditional initial-three/effective-
   continuation-maximum copy bound applies, with no later scratch write in
   successor routing.

## Exact GKI capacity and caller effect

The allocator proof was checked independently in each binary:

- `vbtd-51` `GKI_getbuf_r` rejects a zero request, compares its request against
  each candidate pool's capacity (`0x7ad32b`, capacity-greater-or-equal branch),
  and returns the user pointer at `0x7ad581`. `gki_buffer_init` stores pool 0's
  exact user capacity `0x40` at `0x7acbc4`. The separate `0xd4` value is its
  debug-build stride, not user capacity.
- `vbtd-63` `GKI_getbuf` has the corresponding zero rejection and
  capacity-greater-or-equal selection at `0x7af332`, returning the user pointer
  at `0x7af56b`. `gki_buffer_init` stores pool 0's exact user capacity `0x40` at
  `0x7aebd4`. The separate `0x54` value is its non-debug stride.

Therefore every successful scratch allocation has at least **64 user bytes**
and is capacity-sufficient for the remote-MTU request. Allocation failure is
checked before scratch writes. The largest effective-small-maximum write extent
proven on the stated feasible path is three bytes.

## Exhaustive bounded matrix

This conditional matrix applies to both exact binaries and both named handlers
after the prerequisites above. “Extent” is highest possibly written offset plus
one; continuation values are upper bounds.

| Request state | Effective internal maximum after cap | Scratch write extent | Logical effective limit exceeded on feasible path | Successful 64-byte GKI capacity exceeded | Public small-maximum physical mechanism on stated prerequisites |
|---|---:|---:|---|---|---|
| initial | 0 | 3 | yes | no | rejected |
| initial | 1 | 3 | yes | no | rejected |
| initial | 2 | 3 | yes | no | rejected |
| initial | 3 | 3 | no | no | rejected |
| continuation | 0 | 0 | no | no | rejected |
| continuation | 1 | ≤1 | no | no | rejected |
| continuation | 2 | ≤2 | no | no | rejected |
| continuation | 3 | ≤3 | no | no | rejected |

The logical and physical columns are intentionally separate. On the feasible
initial path, absence of a physical overflow in the exact scratch object does
not make effective maxima 0..2 protocol-conformant. Under the ordinary valid-
remote-MTU precondition, those effective values equal small peer requests.

## Bounded verdict

| CVE | Exact-static result for `vbtd-51` and `vbtd-63` |
|---|---|
| CVE-2017-13255 | The source-like guard is absent and the feasible initial path can reach beyond an effective logical limit below three. The service-attribute scratch allocation uses remote MTU, every successful GKI user object has at least 64 bytes, and the complete valid-state partial helper clamps copy length and destination advancement. **Public small-maximum physical OOB-write mechanism rejected on the stated prerequisites.** |
| CVE-2017-13256 | The source-like guard is absent and the feasible initial path can reach beyond an effective logical limit below three. The independently traced service-search-attribute allocator, nested bounds, and complete valid-state partial helper have the same 64-byte minimum-capacity effect. **Public small-maximum physical OOB-write mechanism rejected on the stated prerequisites.** |

No broader acceptance or rejection follows from this result.

## Claim limits

Established only for the two hash-bound recovered images:

- exact absence of the public source-like less-than-four branch in the reviewed
  complete ranges;
- remote-MTU scratch allocation at both named handlers;
- capacity-sufficient GKI selection and exact 64-byte minimum user capacity;
- complete partial-attribute helper ranges and valid-state clamp of copy length
  and destination advancement to remaining space;
- conditional initial and continuation write extents for effective internal
  maxima 0..3;
- logical effective-limit exceedance on the feasible initial path for effective
  maxima 0..2;
- small peer/effective-value equivalence only under an ordinary protocol-valid
  remote-MTU precondition;
- rejection of only the public small-maximum physical OOB-write mechanism on
  the stated prerequisites.

Not established:

- installed or running binary identity on an owner device;
- runtime reachability of either named handler;
- adapter state or policy, channel exposure, pairing/authentication conditions,
  or any other security boundary;
- classification of early syntax, allocation/reuse, or continuation-state
  error exits as if they reached ordinary response construction;
- corrupted or impossible internal attribute-offset safety or general partial-
  helper safety;
- behavior or safety of other SDP handlers or other malformed-input paths;
- low/invalid negotiated-MTU subtraction behavior, allocator-corruption
  absence, or absence of every vendor-equivalent unnamed path;
- controlled runtime behavior, crash, memory corruption, code execution,
  unrestricted root, persistence, or any impact outcome;
- applicability to every Broadcom BSA build, Android build, vehicle, or owner
  device;
- general Bluetooth or SDP safety.
