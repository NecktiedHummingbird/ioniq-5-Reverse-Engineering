# Checkpoint — Broadcom BSA SDP small-maximum review

## State — final root-review checkpoint

- Analysis baseline: `0a9a7f2fd1cb3b25d928fe9f32fe65cac055d121`.
- Pre-delivery integration HEAD:
  `30f6cace8d2c776b2501c88791b7e54dd4da9055`. The recovered binaries and
  ignored static inputs did not change between those references.
- Concurrent commit `30f6cac` accidentally absorbed the preliminary SDP
  changelog entry while the package model, tests, assessment, retained patch,
  and exact-static artifact remained untracked. Final delivery corrects the
  preliminary wording, validation counts, and changelog order without
  rewriting shared history.
- Public candidate source: Astra child
  `e0ed907e-7e23-42f2-a8cd-fe46ef6b975c` identified CVE-2017-13255 and
  CVE-2017-13256 as the highest-priority unaudited exact targets.
- Public shared fix retained in ignored work:
  `f0edf6571d2d58e66ee0b100ebe49c585d31489f`, patch SHA-256
  `a0470c20592473144f8114cf41ab4cb2479fe2c108a4aa73fa4864eabd02ca34`.
- Both exact binaries lack the source-like `max_list_len < 4` error branch, but
  complete path and allocator review found materially different effects from
  the patched AOSP implementation: each scratch allocation uses remote MTU,
  exact GKI pool 0 user capacity is 64 bytes, and successful allocations are
  capacity-sufficient for the request.
- The finite matrix is the effective internal maximum after the remote-MTU cap.
  On the stated valid response-building prerequisites, initial maxima `0..3`
  reach at most the three-byte sequence header; continuation writes are bounded
  by the effective maximum. Complete partial-attribute helpers clamp valid-state
  copy length and destination advancement. Low/invalid remote-MTU arithmetic,
  corrupted/impossible internal offsets, and general helper safety remain
  unknown.
- Root technical review and an independent read-only reviewer found no blocker
  in the bounded technical conclusion. The first independent verdict was
  `CHANGES_REQUIRED` only for moving-base/provenance, stale checkpoint, and
  changelog-order defects; those bookkeeping defects were corrected and the
  final narrow re-review returned **ACCEPT**.

## Exact ranges identified

- `vbtd-51`:
  - service-search-attribute handler FDE
    `[0x841dc0,0x842628)`;
  - SDP request dispatcher containing the inlined service-attribute handler
    `[0x842630,0x842e0b)`;
  - `GKI_getbuf_r [0x7ad2e0,0x7ad690)`;
  - `gki_buffer_init [0x7ac590,0x7ad284)`.
- `vbtd-63`:
  - service-search-attribute handler FDE
    `[0x8425b0,0x842e00)`;
  - SDP request dispatcher containing the inlined service-attribute handler
    `[0x842e00,0x8435c3)`;
  - `GKI_getbuf [0x7af2f0,0x7af633)`;
  - `gki_buffer_init [0x7ae5a0,0x7af294)`.

## Preservation

Unrelated residue remains untouched:

- modified `tools/uk_fw/ias_backend_soft/micom_service.c`;
- untracked `tools/uk_fw/ias_backend_soft/micom-service`.

No recovered target, Bluetooth endpoint, radio, packet/PDU, pairing, connection,
malformed input, or exploit material has been exercised.

## Validation and acceptance state

- Focused validation: `9 passed, 52 subtests passed`.
- Required tests-scoped suite: `626 passed, 318256 subtests passed`.
- Public harness: `pass=3 info=4 pending=0 blocked=0 fail=0`.
- After the final provenance and changelog correction, root independently reran
  focused and required full tests, the public harness, `py_compile`, all eight
  complete LLVM disassembly hash checks, all ten exact FDE checks, both ELF
  identities/hashes/Build IDs, helper clamp/copy/advance instructions, retained-
  patch byte comparison, deterministic report hashing, and `git diff --check`;
  all passed.
- Independent final review sampled the same evidence and found no technical
  blocker. Its only follow-up was to replace the now-obsolete pre-correction
  resume wording in this checkpoint; a final narrow recheck returned **ACCEPT**.
- No recovered target, Bluetooth endpoint, radio, packet/PDU, malformed input,
  controlled execution, or exploit material was used.

## Resume action

Stage only the reviewed SDP package paths and explicitly exclude the unrelated
MICOM/IAS residue. Commit and push only after verifying the staged diff.
