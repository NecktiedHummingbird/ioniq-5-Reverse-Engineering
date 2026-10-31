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
- Reconstructed AppScomoDM `launchAppUpgrade` and its direct helpers:
  - one first `S5W_SYSTEM_*_*_*.zip` iterator result and stricter filename-shape validation;
  - pre-verification extraction of `AppUpgrade` and `.lge.upgrade.xml`;
  - exact-zero public-key-backed verification of both extracted files;
  - CryptoService versus old `DecryptToPIPE` AppUpgrade decryption;
  - plain XML copy, ELF/executable check, final copy/chmod, and app-ID-300 launch;
  - legacy layout rejection and weak subprocess/error propagation.
- Identified V-020 in the stock BusyBox `unzip` provider after correcting a VM-
  helper provenance error: exact method 8 reaches CVE-2015-9261's unfixed
  `huft_build` `v+n` bound before member authentication; method 12 is rejected.
  Added a data-free bound model and focused tests.
- Wrote `evidence/appupgrade-update-trust.md` and corrected the broad
  marker-equals-unchecked-path documentation.

## Safety record

No recovered updater, helper, or target executable was run. No package was
installed. No image, partition, marker, slot, or VM filesystem was modified.
All exact binaries, disassemblies, maps, and extracted ELFs remain ignored under
`work/`.

## Remaining

1. Finish the broader caller-state and cleanup reconstruction around AppScomoDM
   `0xc1860`; the `0xbf260` staging function and direct trust helpers are now
   complete enough for the current route verdict.
2. Parse `.lge.upgrade.xml` fields and locate the exact installed-version,
   model/region, and eligibility comparisons after AppScomoDM's authenticated
   copy. Keep the unresolved FUMO/AppDMClient route separate.
3. Trace FUMO mode-byte uses into named decryption, signature, digest, archive,
   and write functions without inferring that one skipped branch removes all
   trust controls.
4. Reconstruct payload target selection, inactive-slot writing, boot selection,
   userspace health, and mark-good independently.
5. On a disconnected bench, passively capture installed BusyBox/AppScomoDM/
   AppUpgrade hashes, effective `PATH`, runtime uid/SMACK label, selected `-un`
   arguments, and updater state before any active test.

## Validation

Run from the repository root:

```sh
/Users/leo/.platformio/penv/bin/python3 -m pytest -q tests
git diff --check
```
