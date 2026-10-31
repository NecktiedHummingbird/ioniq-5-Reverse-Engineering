# GStreamer FLIC write-bounds backport checkpoint

Status: complete; independent semantic/model review **ACCEPT**.

## Exact artifact

- path: `/usr/lib/gstreamer-1.0/libgstflxdec.so`
- SHA-256: `46886e9a31e21efca01b68c56c8e879d06902b9b7343530cf518ee908fb96b16`
- GNU Build ID: `67b88ba2c35738081fe1397cf7d10a1375d0525b`
- decode-helper FDE: `[0x2540,0x3cbf)`
- chain/dispatch FDE: `[0x3cc0,0x53b0)`

## Result

- Embedded metadata says GStreamer `1.8.3-r0`, but exact source-line values and
  instructions match the later comprehensive rewrite at upstream commit
  `153a8ae752c90d07190ef45803422a4f71ea8bff`.
- Chunk payloads use a checked sub-reader.
- The writer is initialized over exact `frame_data` and frame-size fields.
- FLI and FLC line counts, cumulative destination positions, reader operations,
  writer operations, helper return, and chain return are checked.
- A decode failure branches to the chain error path before output publication.
- The CVE-2016-9634/9635/9636/9808 write-bounds family is rejected for this
  exact plugin. This is not general decoder safety, and CVE-2016-9807 remains
  outside this conclusion.

## Tracked evidence

- `evidence/gstreamer-flxdec-cve-2016-9634-9636-9808.md`
- `evidence/artifacts/media-candidates/gstreamer-flxdec-cve-2016-9634-9636-9808.asm`
  - SHA-256 `4bb62e092fd4acce79f432fc4a322ace164367ce86cdb5cad06b34cef9585400`
- `evidence/artifacts/media-candidates/gstreamer-flxdec-bytewriter-rewrite.patch`
  - SHA-256 `b24b1d95ee7ec6205ae688380a969197cd32bb29f7acef1f0897600283b1166a`
- `tools/uk_fw/flic_writer_bounds_model.py`
- `tests/test_flic_writer_bounds_model.py`
- deterministic model report SHA-256:
  `be93a960d834d793808148785525c3fa73f8c6b87e2f168ce69d8c0c3fba888a`
- focused validation: `6 passed, 526 subtests passed`
- complete validation: `459 passed, 132344 subtests passed`
- public research harness: **PASS**

## Review correction

The first independent review found that the report mislabeled the chain-level
frame-payload sub-reader as the individual chunk sub-reader, truncated the
helper FDE at `0x3c5b` instead of `0x3cbf`, and stopped the chain error excerpt
before its final `GST_FLOW_ERROR` return. The report now distinguishes both
reader layers and the tracked artifact retains both complete affected FDEs,
including all three previously missing regions. Final independent review returned **ACCEPT** and
confirmed the CVE scope, instruction semantics, complete FDEs, error routing,
model, hashes, and claim boundaries.

## Safety

No media input, parser execution, trigger, heap manipulation, overwrite, crash,
code execution, privilege transition, or persistence action was created or
performed.
