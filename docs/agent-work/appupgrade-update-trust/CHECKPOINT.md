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
- Reconstructed AppDMClient's separate FUMO USB descriptor path:
  - `<source>/.lge.upgrade.xml`, accepted `lhavn`/`wideavn` roots, and
    consecutive-element traversal for a first-child-text `version` value;
  - encrypted XML versus direct-plaintext parser branches and separate verifier
    opens without a proved immutable snapshot;
  - two normalized lexicographic version comparisons;
  - on unequal source/destination, marker-absent retained-result contract `0/0`
    and marker-present explicit non-encrypted contract `-404/-404`; exact linked
    verifier code now identifies `-404` as no recognized fixed-size `TER`/`TE2`
    trailer, not successful signature verification;
  - equal pre-staged AppUpgrade path skips both contracts; caller reconstruction
    proves intended local `/update/usb/bin` relaunch reachability;
  - `slotUsbMounted` stores the mount-path `QString` at `this+0x128`, while
    standby-status and exact `force_launch=run` workflows provide fixed local
    relaunch paths;
  - inner FUMO progress-zero branches write `force_launch=run` and completion
    cleanup overwrites it with `none`; the additional scheduled branch requires
    both local completion strings plus `isScheduledUpdating`, but the provenance
    of that state, the preceding named authentication state, and source
    immutability remain unresolved;
  - explicit section-zero vehicle equality disabled at the reviewed USB call
    sites, while P5-family and later target checks remain;
  - added a numeric/boolean-only model for exact trailer classification and
    retained-result pair gates; it emits no update material and never equates
    gate progression with update acceptance.
- Wrote `evidence/appupgrade-update-trust.md`,
  `evidence/appdmclient-fumo-usb-eligibility.md`, and corrected the broad
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
2. Name the second stored AppDMClient version reference and numeric boot-state
   values from exact code; trace the XML destination helper.
3. Trace source stability across initial staging, repeated verifier/parser opens,
   and the now-proven local relaunch; trace the provenance of the two local
   completion strings and name any authentication state preceding the FUMO
   progress-callback `force_launch=run` writes.
4. Trace FUMO mode-byte uses into named decryption, signature, digest, archive,
   and write functions, and map inner AppUpgrade `car-variant`/system-version
   decisions without inferring that one skipped branch removes all trust
   controls.
5. Reconstruct payload target selection, inactive-slot writing, boot selection,
   userspace health, and mark-good independently.
6. On a disconnected bench, passively capture installed BusyBox/AppScomoDM/
   AppUpgrade hashes, effective `PATH`, runtime uid/SMACK label, selected `-un`
   arguments, relaunch/completion markers, staged `/update/usb/bin` identities,
   and updater state before any active test.

## Validation

Run from the repository root:

```sh
/Users/leo/.platformio/penv/bin/python3 -m pytest -q tests
git diff --check
```
