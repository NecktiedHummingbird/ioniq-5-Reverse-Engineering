# Update-candidate retained evidence

This directory contains bounded, reviewable static excerpts and deterministic
reports supporting update-path assessments. Original firmware and recovered
executables remain ignored under `work/`; retained files must not contain target
payloads, bypasses, private operator paths, or executable target material.

## AppFUMO decryption direct producers and public-log observation

- [`appfumo-decryption-producer-exact-static.asm`](appfumo-decryption-producer-exact-static.asm):
  bounded Homebrew LLVM 23.1.3 FDE and instruction excerpts (SHA-256
  `d8783cbdc41f5aae6663f339ff2debe2c3e425c8a243845e823b53f087099eb1`);
- [`appfumo-copywhatsnew-index-60.json`](appfumo-copywhatsnew-index-60.json):
  deterministic metadata report binding local public slot
  `void copyWhatsNewFiles()` (SHA-256
  `8f9adf55fbb3f0f65ef565175901a92144d33cf0ebc28bb57bffe39bbb386ee1`);
- [`appfumo-decryption-public-log.json`](appfumo-decryption-public-log.json):
  normalized, token/volume-label-free report over the hash-bound tracked public
  log (SHA-256
  `0dc7fb9c2775b2b201ca3b7e38438f75f1db3aa9ddac4298f315ad2e6f35bb66`).

The exact ELF's three selected direct sites are in the `copyWhatsNewFiles()`
FDE and classify archive/system/control producer families. The expected public
log contains seven matching records, including line 21713 beyond the previously
listed six. Its installed binary identity and invocation mechanism remain
unknown; dynamic/indirect/external producer completeness and attacker control
are not established. Assessment:
[`../../appfumo-decryption-runtime-provenance.md`](../../appfumo-decryption-runtime-provenance.md).

## AppFUMO exact shell boundary

- [`appfumo-shell-boundary-exact-static.asm`](appfumo-shell-boundary-exact-static.asm):
  bounded Homebrew LLVM FDE, literal, substitution, direct-call, `popen`, read,
  close, return-path, and separate-function excerpts (SHA-256
  `a6bbe8e74630e7a64001a8bad2b5f67846f465473612a14e8bccf3aad47c5510`).

The exact `decryptionFile` FDE substitutes `encFile` and `destPath` into command
fields without an observed quoting/escaping operation, then directly reaches a
shared `popen` helper. Similar full templates and destination checks are retained
as a separate-FDE correction, and the adjacent output-returning helper has its
own FDE. This establishes static shell-sink structure, not pathname influence,
character survival, runtime reachability, command success, privilege, root, or
persistence. Assessment:
[`../../appfumo-shell-command-boundary.md`](../../appfumo-shell-command-boundary.md).

## AppFUMO Qt 5 local meta-method 64

- [`appfumo-qt-metaobject-exact-static.txt`](appfumo-qt-metaobject-exact-static.txt):
  bounded relocation, metadata, string, jump-table, dispatcher, and verifier-call
  excerpts with addresses and range hashes;
- [`appfumo-qt-metaobject-forwarding-manifest.json`](appfumo-qt-metaobject-forwarding-manifest.json):
  strict machine-code forwarding facts, accepted only when the current bytes of
  the preceding evidence excerpt match its bound digest, with producer
  provenance explicitly unresolved. Excerpt SHA-256 is
  `31a90d0d633d22823fe1e4e61aa1c7df159c1a1acef379fe4e7aa38c7195c1ee`;
  manifest SHA-256 is
  `ecf48b2ec0d5f5c6014e2ef7c4efbfdd25899a3b79da2f4cf808dda062bf16bb`;
- [`appfumo-qt-metaobject-index-64.json`](appfumo-qt-metaobject-index-64.json):
  deterministic decoder report (SHA-256
  `330799c5215a0d3fda7c8870820240cb023c9b3a6c9673100778a038fe1d14a3`).

Assessment:
[`../../appfumo-qt-metaobject-provenance.md`](../../appfumo-qt-metaobject-provenance.md).
The package resolves local `AppUpgradeEngine` metadata row 64 as public slot
`QString decryptionFile(QString encFile, QString destPath)` and its generated
argument forwarding. Row 64 is not asserted as the absolute method index;
`methodOffset()` and inheritance context would be required. Complete producers,
runtime invocation, external/D-Bus
reachability, attacker control, update acceptance, root, and persistence remain
unknown.

Reproduce the exact report only with both bounded evidence inputs:

```sh
<platformio-env>/bin/python3 tools/uk_fw/qt5_metaobject_rev7.py \
  --elf work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf \
  --metadata-va 0x444760 --stringdata-va 0x445260 \
  --local-method-index 64 \
  --evidence-manifest evidence/artifacts/update-candidates/appfumo-qt-metaobject-forwarding-manifest.json \
  --evidence-excerpt evidence/artifacts/update-candidates/appfumo-qt-metaobject-exact-static.txt
```

Other files retain earlier bounded update-route evidence and keep the claim
boundaries stated in their corresponding assessments.
