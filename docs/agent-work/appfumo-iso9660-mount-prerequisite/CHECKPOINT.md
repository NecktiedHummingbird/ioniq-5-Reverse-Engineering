# AppFUMO ISO9660 mount-prerequisite follow-up checkpoint

Date: 2026-11-08
Status: **ACCEPT**; staged validation passed.

## Baselines and scope

- Worker baseline:
  `ec93aed4aec4f14a4620f4152abe9746f83f523f`.
- Initial independent-review integration HEAD:
  `fe3d363431041249e295650ea63ab9677e81b7b1`.
- Non-overlapping integration commits advanced through `a1f1351` to current
  final-check HEAD `750cfcfbd88937576fde9ee61e83fd6c1980f28d`; those commits did not
  overlap the 16 package paths.
- Only the 16 package paths listed below were staged for this package.
- The unrelated pre-existing modification at
  `tools/uk_fw/ias_backend_soft/micom_service.c` was not inspected, modified,
  or staged.
- The implementation worker did not delegate, stage, commit, push, reset, or
  stash. Parent delivery staged exactly the reviewed 16 paths after acceptance.
- Static/read-only target analysis only. No target/helper execution, mount,
  media/image/archive construction, malformed target input, pathname/command/
  payload, D-Bus request, target syscall, privilege/root action, or persistence
  action occurred. Temporary generated reports remained under ignored `work/`.

## Retained cryptographic identity chain

The focused test continues to require exactly one regular
`./boot/bzImage-4.1.27-abl` member in canonical archive SHA-256
`423491fd8b86bd815d4e12f47054e08a589a5159f87213f08980fcc3a0e47c84`.
It binds:

- bzImage SHA-256
  `2fec21219b4e52c90d287687f3cfd4fbdc55ad00f71117b02c32134487277582`;
- boot-header-derived legacy-LZ4 payload offset `0x406e` and length
  `0x50ebf7`;
- 16,398,376-byte vmlinux SHA-256
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`;
- vmlinux GNU Build ID
  `273378887b4cf563c10862fdf18b2292765df781`;
- unique `IKCFG_ST`/`IKCFG_ED` offsets `0x809860`/`0x80fab2`;
- unique embedded gzip IKCONFIG, byte-identical to the 113,598-byte recovered
  config SHA-256
  `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`.

The outer bzImage kernel payload is legacy LZ4; the gzip stream is the embedded
IKCONFIG. No target code or decompressed ELF was executed.

## Fail-closed LZ4 correction

The in-memory LZ4 block helper now:

1. validates the configured output bound;
2. parses a literal length, verifies its compressed-input bounds, and preflights
   it against remaining per-block output capacity **before** `extend`;
3. parses a complete match length and preflights it against remaining per-block
   capacity **before** any overlap copy;
4. performs overlap expansion in chunks of at most 64 KiB, with each chunk
   checked against remaining capacity and without `(pattern * repeats)` or any
   equivalent repeated-pattern allocation.

The aggregate legacy-LZ4 decoder stores each bounded block result separately,
checks `len(block_output) <= max_output_size - len(output)`, and only then
extends aggregate output.

Dedicated unit cases force and validate:

- oversized literal rejection with
  `LZ4 literal output exceeds bound before extend`;
- oversized overlap-match rejection with
  `LZ4 match output exceeds bound before copy`;
- second-block aggregate rejection with
  `decompressed vmlinux aggregate exceeds bound before extend`.

The exact canonical two-block decode and all prior magic/header/footer/ELF/
IKCONFIG identity checks still pass.

## Corrected claim boundary and schema-v5 outputs

Embedded config rows remain:

- byte `0x861a`, line 1292: `# CONFIG_BLK_DEV_SR is not set`;
- byte `0x17e34`, line 3666: `# CONFIG_ISO9660_FS is not set`;
- byte `0x17e53`, line 3667: `# CONFIG_UDF_FS is not set`.

The canonical 163-member inventory and 11 hash-bound metadata members lack only
the tested stock isofs/ISO9660, UDF, sr/sr_mod basenames/paths, bounded module
identifiers, and SCSI type-5/block-major-11 aliases. These facts reject the
**named canonical** ISO9660/UDF and SCSI CD-ROM implementations. They do not
exclude inline, renamed, or vendor-equivalent implementations.

Accordingly, the pre-recorded model emits:

- `recovered_kernel_named_iso9660_mount_prerequisite_absence = true`;
- `recovered_kernel_iso9660_mount_prerequisite_absence = null`;
- `exact_recovered_stack_named_iso9660_mount_route = false`;
- `exact_recovered_stack_iso9660_mount_route = null`;
- `exact_recovered_stack_named_physical_optical_sr_route = false`;
- `exact_recovered_stack_physical_optical_sr_route = null`.

Exact userland ISO9660 recognition, the pre-mount UUID-byte route, generic direct
`mount(2)`, read-only retry, and post-success `UsbMount` gating remain
established. Unidentified installed-unit mount success remains `null`; explicit
true still requires a materially different runtime identity. Physical source
control, broad exact-stack completion, installed identity/extra modules,
mixed-case/dot naming extensions, successful callback, and the AppDMClient-to-
inner-AppUpgrade bridge remain unknown.

## Review and validation

- Independent review first returned **CHANGES_REQUIRED** for missing bzImage to
  config provenance and overbroad module-equivalent claims.
- First correction review returned **CHANGES_REQUIRED** for post-allocation LZ4
  bounds and a remaining broad exact-stack negative.
- The bounded LZ4 and named-versus-broad corrections then returned **ACCEPT**.
- `py_compile`: passed for model and focused test.
- `tests/test_appfumo_usb_pathname_model.py`: **24 passed**.
- Exact archive/member, bounded legacy-LZ4, vmlinux/Build-ID, unique bounded
  gzip IKCONFIG, byte-identical config, config-row/offset, module identity/
  alias, userland instruction/literal, every-output, causality, named-versus-
  broad claim, and runtime-state checks passed.
- ASCII, Latin-1, and UTF-16 `PYTHONIOENCODING` reports were byte-identical,
  ASCII-only UTF-8 JSON with one LF and no CR.
- Deterministic schema-v5 report SHA-256:
  `56b7a941a4180472292af59e60b5b1bdf5b3e369205b75519a3d3c4f073f1804`.
- Tests-scoped full suite: **718 passed, 351445 subtests passed**.
- Post-stage public harness:
  `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Post-stage privacy coverage: 383 files, zero blockers, three informational
  public/reserved identifiers.
- `git diff --check` passed for the package; exactly 16 reviewed paths were
  staged.

## Package paths and hashes

| Path | SHA-256 |
|---|---|
| `HANDOVER.md` | `709c47b68602db46a6e2616c20088a917a62d86703a7f3c9647e506733abd6db` |
| `docs/agent-work/appfumo-usb-pathname-provenance/CHECKPOINT.md` | `761c0f10fb00d53fb64dfb236a73d69da8cd917d96891ba2ee3e6ed69c033a85` |
| `docs/agent-work/appfumo-iso9660-mount-prerequisite/PLAN.md` | `0c1e9c3b4a1345009ce22a00ecc9ed3cdb10fe5f1ab51e0226e28902847d3e64` |
| `docs/agent-work/appfumo-iso9660-mount-prerequisite/CHECKPOINT.md` | self-referential; final hash reported externally |
| `evidence/appdmclient-fumo-usb-eligibility.md` | `f2f1194cecc5d6e20749aad94a00d1f8c77506e195195cf022487dd5bba703c8` |
| `evidence/appfumo-authentication-coverage.md` | `9080a811c3d530e6e2c95d7d7e4907aae62cd71110060959f53fba72511ce113` |
| `evidence/appfumo-decryption-runtime-provenance.md` | `527b66273435f9f09b6c679f895f5f979be086a999bf2cac4563ac23612adb58` |
| `evidence/appfumo-shell-command-boundary.md` | `16dba6dea758aa10b6898dca85818b081dca9898bbd518f7d8d9e49511b5e5c4` |
| `evidence/appfumo-usb-pathname-provenance.md` | `b562562f16aa6c115ffb0670a34cf261d36b4e4f2de93a8514ff6a8682e74636` |
| `evidence/appfumo-iso9660-mount-prerequisite.md` | `b8eff7ef5f83c918fd792ff6f047106e5a1d235cfa275ecb378056bdcc45422b` |
| `evidence/artifacts/update-candidates/README.md` | `a95ff349b4855aa28e0593f980d10d9c7fb77a7a6faa037921c3a98d940ef4fc` |
| `evidence/artifacts/update-candidates/appfumo-iso9660-mount-prerequisite-exact-static.txt` | `7935f331841eed2374a8318ce5f4d9c287cc76225ebefbfd9dd4e5a94b62cc0e` |
| `evidence/exploit-inventory.md` | `fc73268ef8766656e36faffa3245e0e3436bc05132572a7fdfb6a93035d0d3d4` |
| `evidence/vm-bringup/usb-root-vector-map.md` | `97eb0ce32317d6b4709e07998262d3ac976020ff921f8c9e6a69664b6a66678b` |
| `tests/test_appfumo_usb_pathname_model.py` | `e09531fc821d61ca5f9c3c1c260f5ff87762abc8c7eae813c5faecc0800a9d7d` |
| `tools/uk_fw/appfumo_usb_pathname_model.py` | `9326cedb04c048d57a6a5297ff7aec1c3a4c7dbb2310fff476f1b2d25bdfbf8a` |
