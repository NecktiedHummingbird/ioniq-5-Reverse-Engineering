# Keystore secure-boot-ignore and manifest-bounds checkpoint

Status: complete; independent semantic/model review **ACCEPT**.

## Exact artifact

- kernel SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- config: `CONFIG_KEYSTORE_SECURE_BOOT_IGNORE=y`
- `keystore_init`: `[0xffffffff81b1dc66,0xffffffff81b1ddd2)`
- `keystore_register`: `[0xffffffff811c17ab,0xffffffff811c18fb)`
- `manifest_init`: `[0xffffffff81b1ddd2,0xffffffff81b1e03e)`
- `verify_oem_signature`: `[0xffffffff811c5a36,0xffffffff811c5bad)`
- `manifest_key_verify_digest`: `[0xffffffff811cca0f,0xffffffff811ccc84)`

## Result

- Matching Intel-authored public source was located in vendor commit
  `0c9640bba6a841f524f5947d0741386792674577`. It confirms the full command-line
  spelling is `ABL.oemkm=...`; `oemkm` alone is the internal ABL-list name.
- The option compiles an explicit `Not checking secure boot status` init path
  which directly calls `keystore_fill_seeds`, and the complete registration
  path similarly proceeds to client derivation without a status query. Seed,
  device-number, and cdev failures
  can still prevent init. Class/device creation has a separate defect: normal
  `ERR_PTR` failures pass NULL-only checks and can lead to a false success return.
- `manifest_init` remains a separate initcall.
- `verify_oem_signature` still hashes through SHA-256 and calls
  `manifest_key_verify_digest`; the config is not a general signature bypass.
- The manifest outer guard accepts `1..0x4000000`, correcting the earlier
  off-by-one documentation.
- Declared-length and type reads lack copied-size checks; later fixed header
  reads can conditionally reach `+0x1b` when earlier equality predicates pass.
  The internal declared length is not bounded by copied size. Extension stride
  reads are bounded only by the internal end plus a 101-entry cap.
- The 101-entry cap bounds the furthest possible stride read to exclusive offset
  `0x640df4`; the model accounts for this and does not treat every declared
  extent mismatch as an OOB candidate.
- `manifest_init` overwrites the allocation-pointer global with `base + 0x24`
  before header validation and passes that interior cursor to `kfree` after a
  feasible header rejection. This is an invalid-free/crash-or-corruption
  candidate.
- Neither parser defect establishes a controlled write, execution primitive,
  root route, update bypass, boot bypass, or persistence path. Boot parameter
  and physical-memory control remain unproved.

## Tracked evidence

- `evidence/eu-keystore-secure-boot-ignore.md`
- `evidence/eu-keystore-manifest-root-of-trust.md`
- `evidence/artifacts/kernel-candidates/kernel-keystore-secure-boot-ignore.asm`
  - SHA-256 `54be9f05a4969be0bcc350ddbd35da2fa2fdf9e3abb397d44393f06289b0b3a3`
- `tools/uk_fw/keystore_boot_gate_model.py`
- `tests/test_keystore_boot_gate_model.py`
  - report SHA-256 `e5d935fe17a05d2304ced562a515e3dd964b1bae993e300985a0c9aaf3f20926`
- `tools/uk_fw/manifest_initial_bounds_model.py`
- `tests/test_manifest_initial_bounds_model.py`
  - report SHA-256 `495ef9bdd20e9bd52da8c92cf52a657d3f5d0d2c37722218ac7a51a7fd0a3c3d`
- focused validation: `13 passed, 2084 subtests passed`
- complete validation: `472 passed, 134428 subtests passed`
- public research harness: **PASS**

## Review corrections

Independent review caught and resolved four classes of overstatement or missing
evidence: class/device `ERR_PTR` results had been treated as fatal despite
NULL-only checks; later fixed-header reads had been called unconditional; the
first bounds model ignored no-loop and 101-entry-cap counterexamples; and the
retained device wrapper chain was incomplete. Review also identified the
previously unclassified interior-pointer `kfree` path. The artifact, evidence,
models, duplicate-argument handling, and tests were corrected. A later public-
source/provenance pass added the exact registration-gate scope and full
`ABL.oemkm=` prefix while preserving known source/target differences; review
also removed stale trust-coverage and memory-safety wording. Final review
returned **ACCEPT**.

## Safety

No manifest, physical-memory input, boot parameter, signature, update, target
execution, crash, overwrite, code execution, privilege transition, flashing, or
persistence action was created or performed.
