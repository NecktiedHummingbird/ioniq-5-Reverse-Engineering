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

## AppFUMO USB pathname provenance

- [`appfumo-usb-pathname-provenance-exact-static.asm`](appfumo-usb-pathname-provenance-exact-static.asm):
  archive-member identities plus complete dispatcher, mount, shipped
  systemd-udevd/libblkid, AppDMClient, and AppUpgrade excerpts (SHA-256
  `932510a860b40cce280f217670cbf2c213e31b0a90008ac5c011c933cd584e8f`);
- [`appfumo-iso9660-mount-prerequisite-exact-static.txt`](appfumo-iso9660-mount-prerequisite-exact-static.txt):
  compact post-delivery binding of canonical bzImage -> vmlinux -> IKCONFIG,
  config offsets, bounded 163-member module identities/aliases, generic type
  dispatch, direct mount calls, read-only retry, and success-signal dominance.
  LZ4 literal/match and aggregate growth are preflighted before extension;
  overlap copying is chunk-bounded and uses no repeated-pattern multiplication
  (SHA-256
  `7935f331841eed2374a8318ce5f4d9c287cc76225ebefbfd9dd4e5a94b62cc0e`).

The complete dispatcher proves that exact `usb-automount` uses `ID_FS_UUID` or
the serial/partition no-UUID alternate—not `ID_FS_LABEL`—as the final
`/media/usb/<port>/<component>`. Label and model are separate D-Bus fields.
Exact stock `./lib/libblkid.so.1.1.0` is SHA-256
`56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701`,
Build ID `c6f98d98cb2cbc2ff864167f37048233d90a8fef`. Constrained
VFAT/exFAT/NTFS/ext/UDF UUID-family negatives remain, but ISO9660 exact code
`[0x1c4c0,0x1c654)` copies 16 raw date bytes, checks only the all-ASCII-`'0'`
case, formats raw `%c` values at `0x35368`, and passes through UUID
`blkid_safe_string`. The matching util-linux v2.27.1 `iso9660.c` lines 110-151
has SHA-256
`601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b`.
Allowed shell/path-sensitive byte classes can therefore reach the UUID mount
component statically. Label preservation remains non-path, and the no-UUID
sanitizer/context negative remains.

Separate exact AppDMClient and AppUpgrade edges do not bind the AppDMClient
launch argument to inner AppUpgrade's package-base constructor. The follow-up
cryptographically binds canonical archive bzImage to bounded legacy-LZ4
vmlinux SHA-256 `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
and unique gzip IKCONFIG/config SHA-256
`987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`.
`CONFIG_ISO9660_FS`, `CONFIG_UDF_FS`, and `CONFIG_BLK_DEV_SR` are unset. The
canonical 163-member inventory/metadata lack the tested isofs/ISO9660, UDF,
sr/sr_mod identities and SCSI CD-ROM aliases, without excluding every renamed,
inline, or vendor-equivalent implementation. The named canonical routes are
false, while broad exact-stack ISO9660 and physical-optical routes remain
unknown. Userspace recognition, generic direct `mount(2)`, and read-only retry
remain, and the success signal is post-mount only.

Physical ISO9660 source control, accepted/mounted media on an unidentified or
materially different installed runtime, end-to-end installed delivery, and
invocation of the relevant `decryptionFile` call with that path remain unknown.
Those gates would establish only pre-auth decryption-input delivery;
actual shell-sink delivery additionally requires authentication because the
verifier dominates command construction and `popen`. Command success and
amplification remain route-generic observations. Authentication acceptance,
command success, privilege/domain, root, and persistence remain unknown;
arbitrary command execution is not claimed. The
post-extraction route remains structural: `0x10281c` is system-tree,
`0x103398` controls-tree, and `0x102de9` top-level archive; decrypted-member-name
signature binding remains unknown.
Assessments:
[`../../appfumo-usb-pathname-provenance.md`](../../appfumo-usb-pathname-provenance.md)
and
[`../../appfumo-iso9660-mount-prerequisite.md`](../../appfumo-iso9660-mount-prerequisite.md).

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
