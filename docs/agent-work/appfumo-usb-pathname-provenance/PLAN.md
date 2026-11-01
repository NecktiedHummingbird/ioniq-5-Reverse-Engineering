# AppFUMO USB pathname provenance plan

## Objective

Determine, for the hash-identified recovered EU `260128` userspace, whether a
physical removable-media principal can influence shell-sensitive bytes in the
`encFile` pathname that reaches the already-proven unquoted
`AppUpgradeEngine::decryptionFile(QString, QString)` `popen` boundary.

The primary hypothesis is the top-level What's New route:

```text
USB filesystem identity -> usb-automount mount directory
    -> AppDMClient mounted-source path -> AppUpgrade package base
    -> <package base>/.whatsnew.tar.gz
    -> verifier success -> decryptionFile shell boundary
```

Treat the enumerated post-extraction system/control names as a separate route.

## Required evidence phases

1. Bind the exact `usb-automount` ELF identity and mass-storage mount-directory
   construction. Resolve the roles of `ID_FS_TYPE`, `ID_FS_LABEL`, `ID_FS_UUID`,
   `ID_MODEL`, `ID_SERIAL_SHORT`, port index, and configured mount root.
2. Determine the no-UUID fallback construction and the exact udev producer or
   sanitization contracts for every component used in the mount-directory name.
   Use version-matched public systemd/udev and libblkid source only as supporting
   evidence; shipped instructions and configuration control target claims.
3. Bind the mount path into AppDMClient's mounted callback and the AppUpgrade
   package-base class using existing exact-static evidence and hash-bound public
   field logs. Do not claim complete external/D-Bus producer coverage unless
   proven.
4. Reconfirm that the top-level `.whatsnew.tar.gz` source reaches verifier
   `0x100bb0` and only reaches the `popen` boundary after verifier success.
   Authentication acceptance and pathname sanitization remain separate.
5. Separately trace the decrypted archive extraction and enumerated file-name
   route far enough to classify whether member names can reach calls
   `0x10281c`/`0x103398`, and whether archive authenticity binds those names.
6. Produce a fail-closed deterministic model that separates:
   pathname provenance, physical influence, shell-character survival,
   authentication acceptance, invocation, command success, process context,
   privilege/domain amplification, root, and persistence.

## Safety and non-goals

- Static/offline only: do not execute recovered targets or helpers.
- Do not create a filesystem image, archive, malformed input, shell command,
  pathname example, payload, trigger, D-Bus request, mount, target syscall,
  flash action, privilege action, or persistence mechanism.
- Do not infer installed-device identity or runtime state from recovered files.
- Do not treat an authenticated archive as proof of shell-safe source pathname,
  or an unquoted sink as proof of attacker-controlled shell syntax.
- Do not expose operator-specific paths in tracked artifacts.

## Deliverables

- `evidence/appfumo-usb-pathname-provenance.md`
- bounded exact-static artifact(s) under
  `evidence/artifacts/update-candidates/`
- `tools/uk_fw/appfumo_usb_pathname_model.py`
- `tests/test_appfumo_usb_pathname_model.py`
- `docs/agent-work/appfumo-usb-pathname-provenance/CHECKPOINT.md`
- narrow integrations in the existing AppFUMO shell/provenance/authentication
  evidence, artifact README, exploit inventory, and `HANDOVER.md` only where
  required.

Public-source captures and complete disassemblies remain under ignored `work/`.

## Acceptance criteria

- Exact hashes, Build IDs, addresses, instruction bytes, argument/register
  bindings, FDE/function boundaries, and literal identities are preserved.
- Mount-directory construction distinguishes UUID, label, model, serial, and
  port roles; absence/fallback branches are not conflated.
- Any character-survival conclusion is bounded by both filesystem-format
  identity and the actual udev/libblkid property producer.
- The verified-object subject and the pathname containing that object remain
  separate trust subjects.
- The model rejects unknown keys/types, Boolean-as-integer confusion,
  contradictory causal states, unsupported route combinations, and ambiguous
  evidence.
- Output is deterministic UTF-8 with one LF through `sys.stdout.buffer`,
  independent of `PYTHONIOENCODING`, and emits no operational target material.
- Focused tests cover every conclusion and exhaustive feasible Boolean states;
  exact evidence bytes and hashes are pinned.
- Full tests-scoped pytest, public harness, privacy validation after staging,
  `py_compile`, and diff/whitespace checks pass before delivery.
- Independent review returns `ACCEPT` for the final bytes.
