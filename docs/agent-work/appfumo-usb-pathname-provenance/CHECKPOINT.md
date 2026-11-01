# AppFUMO USB pathname-provenance checkpoint

Date: 2026-11-01; fourth-review preparation after bounded sink-causality correction

## Repository and coordination provenance

- Original planning baseline: `394e76a`.
- Actual worker-open base: `9955460`.
- Concurrent heads observed across review cycles: `1c43670`, `72fd667`,
  `4bb85f5`, and current preserved
  `e74d96cce9dfba83d1a3028a17e5220b2dcbe6f1`.
- Coordinator-owned `PLAN.md` remains immutable.
- In the first cycle, two prohibited `spawn_worker` attempts failed before any
  nested worker ran (`Unknown model deepseek:deepseek-v4.1-flash` and
  `Ambiguous model "deepseek-v4.1-flash"`). No nested result or edit existed.
- In the first cycle, paths were staged despite instruction; the coordinator
  unstaged those exact paths without changing bytes.
- This review cycle used no delegation, spawning, orchestration, staging,
  commit, push, reset, history rewrite, or unrelated-path modification.

## Review cycle 1: corrected AppUpgrade call mapping

The package corrected the three direct-call roles and retained immediate bytes:

- `0x102de9`: top-level `<package base>/.whatsnew.tar.gz`;
- `0x10281c`: enumerated system-tree file;
- `0x103398`: enumerated controls-tree file.

It also narrowed the missing AppDMClient launch-argument/inner-AppUpgrade
constructor bridge rather than claiming direct end-to-end static dataflow.

## Review cycle 2: P0 dispatcher reversal

The first independent review returned **CHANGES_REQUIRED** because event-caller
`r8/r9` had been carried directly into mount FDE `0x4c00`. The correction
followed dispatcher `0x3a50..0x3b49`:

| Address | Transfer | Value |
|---|---|---|
| `0x3a59` | original `r9 -> r13` | UUID/alternate |
| `0x3a5e` | original `r8 -> r12` | label |
| `0x3a8d` | seventh argument -> `r14` | model |
| `0x3b28` | saved `rcx -> rdx` | FS type |
| `0x3b31` | `r14 -> r9` | model |
| `0x3b34` | `r13 -> r8` | UUID/alternate |
| `0x3b37` | `r12 -> rcx` | label |
| `0x3b49` | tail jump | `0x4c00` |

At mount entry, UUID/alternate becomes `r13` and `0x4d16` pushes it as the
final `%s` in `%s/%d/%s`. Label and model are separate D-Bus fields. This
matches `evidence/vm-bringup/usb-root-vector-map.md`.

## Review cycle 3: P0 ISO9660 producer exception

The second independent review returned **CHANGES_REQUIRED** because the blanket
ordinary-supported UUID rejection omitted stock libblkid's ISO9660 producer.

Exact archive-bound libblkid:

- member: `./lib/libblkid.so.1.1.0`;
- SHA-256: `56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701`;
- Build ID: `c6f98d98cb2cbc2ff864167f37048233d90a8fef`.

Exact ISO9660 findings:

1. FDE `[0x1c4c0,0x1c654)` loads all 16 bytes from the modified/created-date
   input without per-field digit or range validation.
2. `0x1c5a8..0x1c5c2` checks only whether all 16 copied bytes equal ASCII
   `'0'`; offset byte `+0x10` is separately tested only in that all-zero case.
3. `0x1c5c6` binds format `0x35368`:
   `%c%c%c%c-%c%c-%c%c-%c%c-%c%c-%c%c-%c%c`.
4. `0x1c60c` calls the UUID formatter with those raw byte values.
5. The ISO9660 probe first supplies modified date at `0x1c7eb..0x1c7f5`, then
   created date at `0x1ca10..0x1ca1a` if the helper returns zero.
6. Systemd builtin-blkid applies UUID `blkid_safe_string`, which preserves
   allowed shell/path-sensitive byte classes including `$`, `?`, and `/`.
7. The corrected automounter dispatcher places resulting `ID_FS_UUID` in the
   final mount-path component.

Version-matched source provenance:

- util-linux v2.27.1
  `libblkid/src/superblocks/iso9660.c`;
- `probe_iso9660_set_uuid()` lines 110-151;
- SHA-256: `601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b`;
- retained only under ignored `work/`.

No media/input example was created.

## Review cycle 4: bounded sink-delivery causality correction

The third independent review returned **CHANGES_REQUIRED** only because generic
AppUpgrade process invocation had been treated as sufficient path invocation,
and pre-auth delivery to a `decryptionFile` input had been equated with actual
shell-sink delivery.

The corrected runtime gate is
`relevant_decryptionfile_invocation_established`: invocation of the relevant
`decryptionFile` call with this delivered path. The formulas now separate:

1. `physical_iso9660_path_delivery_to_decryption_input_established`: exact
   static route + physical source + accepted/mounted media + cross-process path
   bridge + relevant `decryptionFile` invocation, without authentication;
2. `overall_physical_shell_sensitive_sink_delivery_established`: that pre-auth
   decryption-input delivery plus authentication acceptance, because verifier
   `0x45820` at `0x100bb0` rejects nonzero at `0x100bc3` before command
   construction and `popen`.

The duplicate ambiguously named authenticated-sink output was removed. Command
success still requires cross-process delivery, relevant `decryptionFile`
invocation, and authentication. Command success and amplification remain
route-generic observations, not ISO9660-specific outcomes.

## Corrected bounded conclusion

- Label-as-mount-component remains **false**; label byte preservation remains a
  separate non-path D-Bus fact.
- The no-UUID sanitized serial/partition word still has no useful shell-active
  effect in its already-prefixed command-word context.
- Constrained VFAT/exFAT/NTFS/ext/UDF UUID-family negatives remain bounded to
  their exact producer forms.
- The combined filesystem-metadata rejection is withdrawn.
- ISO9660 static parser/transform/UUID/mount-component shell/path-sensitive byte
  route is **established**.
- Physical ISO9660 source control, installed source acceptance, successful
  mount, cross-process delivery, AppDMClient-to-AppUpgrade bridge, invocation of
  the relevant `decryptionFile` call with that path, verifier acceptance,
  command success, process context, privilege/root and persistence remain
  **unknown**.
- Pre-auth physical delivery to the decryption input is distinct from actual
  shell-sink delivery; the latter requires authentication acceptance.
- Static byte-route existence is not physical sink delivery and is not arbitrary
  command execution.

## Schema v4

The strict Boolean/tri-state model now emits separate findings:

- constrained UUID-family shell-active route: `false`;
- ISO9660 static shell/path-sensitive UUID byte route: `true`;
- physical ISO9660 source control: `null`;
- accepted/mounted ISO9660 media delivery: `null`;
- relevant `decryptionFile` invocation with this path: `null`;
- pre-auth physical ISO9660 path delivery to the decryption input: `null`;
- overall physical shell-sensitive sink delivery after authentication: `null`;
- label-path and no-UUID shell-active routes: `false`.

`command_success_observed=true` still requires installed delivery, relevant
`decryptionFile` invocation, and authentication acceptance. Command success and
amplification are route-generic observations. Amplification requires success,
root requires amplification, and persistence remains independent.

## Package paths

Changed package paths:

- `HANDOVER.md`
- `docs/agent-work/appfumo-usb-pathname-provenance/CHECKPOINT.md`
- `evidence/appfumo-authentication-coverage.md`
- `evidence/appfumo-decryption-runtime-provenance.md`
- `evidence/appfumo-shell-command-boundary.md`
- `evidence/appfumo-usb-pathname-provenance.md`
- `evidence/artifacts/update-candidates/README.md`
- `evidence/artifacts/update-candidates/appfumo-usb-pathname-provenance-exact-static.asm`
- `evidence/exploit-inventory.md`
- `tests/test_appfumo_usb_pathname_model.py`
- `tools/uk_fw/appfumo_usb_pathname_model.py`

Coordinator-owned twelfth package path, unchanged:

- `docs/agent-work/appfumo-usb-pathname-provenance/PLAN.md`

## Validation

Focused validation passed:

- `tests/test_appfumo_usb_pathname_model.py`: `18 passed`;
- retained artifact SHA-256:
  `932510a860b40cce280f217670cbf2c213e31b0a90008ac5c011c933cd584e8f`;
- frozen schema-v4 report SHA-256:
  `026b421772bd708c7f6ccec9200ed8fb47fee3307b1821415c3b9db516854aa3`;
- canonical archive/member, extracted libblkid, Build ID, and ISO9660 source
  hashes passed;
- all retained ISO9660 producer rows matched exact ignored libblkid bytes, and
  exact rodata `0x35368` matched the complete NUL-terminated format;
- all retained dispatcher/mount rows matched exact ignored automounter bytes;
- every output/pre-recorded formula and all runtime Boolean states were asserted,
  including the explicit pre-auth-delivery-without-authentication case,
  success-without-authentication rejection, and independent persistence;
- reports were byte-identical under ASCII, Latin-1, and UTF-16
  `PYTHONIOENCODING`, ASCII-only UTF-8 JSON with one LF and no CR;
- deterministic hash checks, `py_compile`, UTF-8/LF round-trip,
  `git diff --check`, `git diff --cached --check`, HEAD/PLAN preservation, and
  no-staged-path checks passed.

After the focused review freeze, the required tests-scoped full suite passed
`712 tests, 351445 subtests`. The post-stage public harness passed with
`pass=3 info=4 pending=0 blocked=0 fail=0`. Its index-scoped privacy check
scanned `381` files and reported zero blockers plus three informational public
identifiers.

The fourth independent review returned **ACCEPT** for the frozen corrected
package. Accepted hashes include model
`4a630519fcbeeffc023cbfcf3366d80cded47b430856c7af667694ffe77f52b1`, tests
`5e736307dd2b562efaf823b801f4b131f0d59085f8efbd70771f7780550e3451`,
assessment
`54008018b2b9c357c976c8749df000cb57908db34cf358a80d4f242bd8483515`,
retained artifact
`932510a860b40cce280f217670cbf2c213e31b0a90008ac5c011c933cd584e8f`,
and deterministic report
`026b421772bd708c7f6ccec9200ed8fb47fee3307b1821415c3b9db516854aa3`.

No recovered target/helper code, payload, media/input example, update, trigger,
mount, D-Bus request, target syscall, privilege action, root action, or
persistence action was created or executed.

Status: **ACCEPT**; staged validation passed and the final documentation-only
validation delta awaits bounded review.

## Post-delivery follow-up (2026-11-08; prior acceptance unchanged)

A separate bounded package now resolves the named canonical recovered EU 260128
kernel mount prerequisites without rewriting the acceptance above. Userspace ISO9660
recognition, ordinary `sd*` builtin-blkid routing, generic direct `mount(2)`,
read-only retry, and success-signal dominance are present. Canonical archive
SHA-256 `423491fd8b86bd815d4e12f47054e08a589a5159f87213f08980fcc3a0e47c84`
now binds bzImage -> bounded legacy-LZ4 vmlinux SHA-256
`f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
-> unique gzip IKCONFIG/config SHA-256
`987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`.
That config disables `BLK_DEV_SR`, `ISO9660_FS`, and `UDF_FS`; the 163-member
inventory/metadata lack the tested isofs/ISO9660, UDF, sr/sr_mod identities and
SCSI CD-ROM aliases. This does not exclude every renamed, inline, or vendor-
equivalent implementation. Named canonical ISO9660 and SCSI CD-ROM routes are
therefore false, while broad exact-stack ISO9660 and physical-optical routes
remain unknown despite the accepted pre-mount UUID byte route.

Schema v5 emits named prerequisite absence `true`, named exact routes `false`,
and broad exact route outputs `null`. It keeps unidentified installed-unit
acceptance/mount tri-state `null` and permits an
explicit true installed mount only with a materially different runtime identity.
Exact mixed-case/dot ISO naming extensions, successful port-1 callback on such a
different runtime, and the AppDMClient-to-inner-AppUpgrade bridge remain
unknown. See `evidence/appfumo-iso9660-mount-prerequisite.md` and
`docs/agent-work/appfumo-iso9660-mount-prerequisite/CHECKPOINT.md`. The original
fourth-review **ACCEPT** and its recorded hashes remain historical facts.
