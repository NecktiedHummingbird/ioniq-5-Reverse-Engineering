# Recovered AppUpgrade trust-path analysis

## Objective

Reconstruct the exact offline update route in recovered EU `260128` userspace:
`AppSetup` / `AppScomoDM` / the outer `AppUpgrade` wrapper / its embedded SCOMO
and FUMO executables. Determine what `/update/disableEncryptionUpdate` changes,
which build- and route-selection gates precede it, and which eligibility,
authentication, integrity, write, boot-selection, boot-trust, and health gates
remain independent.

## Non-goals and safety boundaries

- do not execute a recovered updater or helper;
- do not install a package, write an image, switch a slot, or change the VM;
- do not create a signature-bypass patch, malicious package, or flash procedure;
- do not infer an installed owner build from recovered `260128` artifacts;
- do not equate plaintext/decryption mode with package authentication;
- do not treat raw outer-file offsets as virtual addresses in an embedded ELF.

## Phases

1. **Deterministic container map.** Add a read-only tool that validates every
   ELF header embedded in the outer file, distinguishes structural ELF extent
   from container padding/span, maps embedded virtual/file/outer offsets, and
   optionally extracts exact non-overlapping ELF files without executing them.
2. **Outer-wrapper selection.** Reconstruct the wrapper entry point, embedded
   boundaries, temporary paths, selection predicates, arguments, execution
   mechanism, cleanup, and errors.
3. **AppScomoDM route selection.** Reconstruct the USB method selector around
   `0xbf260`, its build-mode source, existing/new-method branches, copied paths,
   command lines, return handling, and marker/menu cleanup around `0xc1860`.
4. **SCOMO marker semantics.** Trace build-mode checks,
   `/test_keep_encryption_disable`, decryption selection, completion, and marker
   deletion in the first embedded executable.
5. **FUMO marker semantics.** Trace global `0x6d20b4` through decryption,
   signature/integrity, archive, version, and write decisions in the second
   embedded executable.
6. **AppSetup and trust synthesis.** Bind `.lge.upgrade.xml` handling and version
   eligibility to the selected updater route, then write a reviewed report that
   keeps parsing, eligibility, payload authentication, inactive-slot writing,
   slot selection, boot-time trust, health, and mark-good as separate verdicts.

## Acceptance criteria

- extraction boundaries and hashes are reproducible from the original outer
  SHA-256 `5295c6e4c41fb9c03760cf006c58b66fcd11aeb4e6e889af6e31b062549b6df0`;
- malformed/truncated/overlapping synthetic ELFs fail closed in tests;
- every address claim names its binary and address namespace;
- control-flow claims are confirmed from exact instructions, with decompiler
  output used only as supporting evidence;
- documentation explicitly retracts the broad claim that marker existence alone
  selects an unchecked production plaintext path;
- no recovered executable is run and no original firmware artifact is modified.

## Verification

```sh
PY="${PYTHON:-/opt/homebrew/bin/python3.13}"
"$PY" -m pytest -q tests/test_embedded_elf.py
"$PY" -m pytest -q tests
git diff --check
```
