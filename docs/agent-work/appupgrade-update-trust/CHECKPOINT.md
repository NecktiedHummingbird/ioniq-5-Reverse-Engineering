# AppUpgrade update-trust checkpoint

Date: 2026-11-01

## Completed

- Added strict read-only embedded-ELF inspection/extraction in
  `tools/uk_fw/embedded_elf.py` with synthetic tests.
- Replaced broad updater carvings with exact SCOMO and FUMO structural extents.
- Reconstructed the outer wrapper:
  - exact case-sensitive `-un:1` selects SCOMO;
  - all other sets, including `-un:0`, select FUMO;
  - all application arguments except item zero are forwarded to the child;
  - copy/chmod/XML-copy and child status results are not propagated;
  - the wrapper exits `1` on its normal path.
- Reconstructed AppLauncher argument flow:
  - dynamic app processes call the global/model option builder at `0x34510`;
  - the resulting list is stored at `AppProcess+0x60` and passed to
    `QProcess::start`;
  - the embedded NE/EUR row contains `-un:0`;
  - exact `-un:1` plus app ID 311 conditionally substitutes AppScomoDM for
    AppDMClient.
- Reconstructed marker startup semantics:
  - FUMO byte VA `0x6d20b4` starts at `1`; marker existence writes `0`;
  - SCOMO MASS_PRODUCT/PENETRATION startup explicitly ignores the marker.
- Excluded AppSetup as the descriptor parser; it initiates the app-ID-300
  transition.
- Wrote `evidence/appupgrade-update-trust.md` and corrected the broad
  marker-equals-unchecked-path documentation.

## Safety record

No recovered updater, helper, or target executable was run. No package was
installed. No image, partition, marker, slot, or VM filesystem was modified.
All exact binaries, disassemblies, maps, and extracted ELFs remain ignored under
`work/`.

## Remaining

1. Finish AppScomoDM `launchAppUpgrade` at `0xbf260`, including exact build-mode
   source, legacy/new archive branches, command lines, return handling, and
   cleanup at `0xc1860`.
2. Locate the exact owner of `.lge.upgrade.xml` discovery, TE2/decryption,
   version compare, model/region checks, and package authentication.
3. Trace FUMO mode-byte uses into named decryption, signature, digest, archive,
   and write functions without inferring that one skipped branch removes all
   trust controls.
4. Reconstruct payload target selection, inactive-slot writing, boot selection,
   userspace health, and mark-good independently.
5. Compare installed hashes and effective arguments only on an owner-controlled,
   disconnected bench using the passive state bundle.

## Validation

Run from the repository root:

```sh
/Users/leo/.platformio/penv/bin/python3 -m pytest -q tests
git diff --check
```
