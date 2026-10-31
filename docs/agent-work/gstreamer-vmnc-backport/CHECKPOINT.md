# GStreamer VMNC backport checkpoint

Status: complete; independent semantic/model review **ACCEPT**.

## Exact artifact

- path: `/usr/lib/gstreamer-1.0/libgstvmnc.so`
- SHA-256: `12aef863358f39d522fed29659184dac785f048ed01135c1c6ba5602bf4c9b52`
- GNU Build ID: `ca57536fdc452aa6e73f0e457a75a398e9f16b0c`
- packet-parser FDE: `[0x2890,0x2dd4)`
- WMVi-handler FDE: `[0x3460,0x3b72)`

## Result

- Embedded recipe metadata says GStreamer `1.8.3-r0`.
- Exact WMVi dispatch checks unsigned height and width against `0x4000`; either
  larger value reaches the `Width or height too high` error and `-1` return.
- Every feasible WMVi path passes those checks before loading/calling the
  handler. This is predicate-sensitive, not structural CFG dominance: a
  syntactic bypass edge requires the earlier WMVi comparison to have been false
  and `%edi` is unchanged.
- The handler accepts only 8/16/32-bit depth, stores bytes-per-pixel as 1/2/4,
  copies the guarded rectangle width/height into the exact allocation fields,
  multiplies those fields, and calls `g_malloc0@plt`.
- Maximum accepted product at four bytes per pixel is `0x40000000`, which fits
  signed 32-bit arithmetic.
- Both effects of upstream commit
  `4cb1bcf1422bbcd79c0f683edb7ee85e3f7a31fe` are present. The exact
  CVE-2016-9445 allocation-overflow and CVE-2016-9446 uninitialised-canvas
  mechanisms are rejected for this plugin. This is not general decoder safety.

## Tracked evidence

- `evidence/gstreamer-vmnc-cve-2016-9445-9446.md`
- `evidence/artifacts/media-candidates/gstreamer-vmnc-cve-2016-9445.asm`
  - SHA-256 `fc9be376a057f9672a2b8139fa5eb29e14f73a220bbe20050c3130fd35fa1f91`
- `evidence/artifacts/media-candidates/cve-2016-9445-fix.patch`
  - SHA-256 `c6b23d9d499715b1dbb5525901a1216de1a2e48e54078df7ad82efddf0c2840e`
- `tools/uk_fw/vmnc_dimension_guard_model.py`
- `tests/test_vmnc_dimension_guard_model.py`
- focused validation: `7 passed, 59 subtests passed`
- deterministic model-report SHA-256:
  `d022d6d25e6d439281ffe442fac7c468bc5fcd1d4c0d273f847a5a23b2fc49f0`
- complete validation: `453 passed, 131818 subtests passed`
- public research harness: **PASS**

The first independent review requested exact operand/depth binding and corrected
structural-dominance wording. The retained handler excerpt now includes the
8/16/32-bit validation and assignments to `+0x308`, `+0x30c`, and `+0x314`.
The evidence and model now distinguish every feasible WMVi path passing the
guard from strict CFG dominance and document the predicate-infeasible bypass.
Follow-up review caught that the numeric model admitted bpp 3 even though the
handler derives only 1/2/4; the model now rejects 3 and tests that boundary.
Final independent review returned **ACCEPT** with no remaining blocking finding.

## Safety

No media input, malformed file, parser execution, packet, heap manipulation,
overwrite, crash, code execution, privilege transition, or persistence action
was created or performed.
