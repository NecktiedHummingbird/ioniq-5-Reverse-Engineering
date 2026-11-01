# Update-candidate retained evidence

This directory contains bounded, reviewable static excerpts and deterministic
reports supporting update-path assessments. Original firmware and recovered
executables remain ignored under `work/`; retained files must not contain target
payloads, bypasses, private operator paths, or executable target material.

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
