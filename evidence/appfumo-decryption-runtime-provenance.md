# AppFUMO `decryptionFile` direct producers and public-log runtime boundary

## Result

Two evidence sets advance different parts of the provenance boundary and must
not be conflated:

1. **Exact recovered ELF, static:** all three selected direct calls to
   `0x100b30`—`0x10281c`, `0x102de9`, and `0x103398`—are inside the one exact
   FDE `[0x101110,0x104c1b)`. Exact Qt metadata identifies local
   `AppUpgradeEngine` row 60 as public slot `void copyWhatsNewFiles()`, and its
   generated static-metacall case at `0x16e59f` calls entry `0x101110`.
   Therefore all three selected sites belong to the exact ELF's
   `copyWhatsNewFiles()` implementation. Their branch and argument-producer
   families are resolved below.
2. **Already-tracked public field log, runtime observation:** the hash-bound log
   records runtime `decryptionFile` activity in `copyWhatsNewFiles` temporal
   context, with removable-USB `.whatsnew.tar.gz` sources and the fixed
   `/update/whatsnew/temp/.whatsnew.tar.gz` destination class. The log does not
   identify its installed AppUpgrade binary or its invocation mechanism.

The supplied six-line expectation is not complete for the current bytes. The
log with expected SHA-256
`84d5bb69270dd610b132c8950c31dd98adad844c5a2c108b4df617381685de86`
contains **seven**, not six, exact-shape `[decryptionFile]` records: the six
listed lines plus line **21713**. The parser and retained report fail closed on
identity and preserve all seven rather than silently dropping the additional
record.

This establishes observed invocation on the logged system(s), not binary
identity, attacker control, external/D-Bus reachability, update acceptance,
effective privilege, root, or persistence.

## Status ledger

| Boundary | Status | Basis |
|---|---|---|
| public-log observation | **observed** | seven hash-bound log records |
| exact recovered static semantics | **resolved for the three selected direct sites** | exact FDE and Homebrew LLVM instruction output |
| metadata binding | **resolved** | local row 64 is `decryptionFile(QString,QString)`; local row 60 is `copyWhatsNewFiles()` |
| generated `decryptionFile` forwarding | **resolved, separate** | row-64 generated call `0x16e030`, documented previously |
| selected direct producer family | **resolved** | three sites are in exact `copyWhatsNewFiles()` FDE/function |
| complete producer provenance | **unresolved** | no complete dynamic/indirect/external dispatch proof |
| logged-build identity | **unknown** | log contains no binary hash/Build ID |
| logged invocation mechanism | **unknown** | text does not distinguish direct call, Qt meta-call, or another dispatch route |
| attacker control | **unknown** | neither evidence set proves control of paths or timing |

## Exact-static identity and function binding

- exact ELF:
  `work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf`
- size: `5,066,264` bytes
- SHA-256:
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`
- Build ID: `863a8730e66a1c5245a1bf458fe2554adee0351a`
- instruction tool: Homebrew LLVM `23.1.3`
- exact containing FDE: `[0x101110,0x104c1b)`
- bounded instruction/FDE excerpts:
  [`artifacts/update-candidates/appfumo-decryption-producer-exact-static.asm`](artifacts/update-candidates/appfumo-decryption-producer-exact-static.asm)
- excerpt SHA-256:
  `d8783cbdc41f5aae6663f339ff2debe2c3e425c8a243845e823b53f087099eb1`
- deterministic row-60 metadata report:
  [`artifacts/update-candidates/appfumo-copywhatsnew-index-60.json`](artifacts/update-candidates/appfumo-copywhatsnew-index-60.json)
- row-60 report SHA-256:
  `8f9adf55fbb3f0f65ef565175901a92144d33cf0ebc28bb57bffe39bbb386ee1`

Local metadata row 60 at `0x444c48` is `(93,0,623,2,10)` and decodes to
public slot `void copyWhatsNewFiles()`. Jump-table entry 60 is at `0x4446f0`:
raw word `0xffd29f9f`, signed displacement `-2973793`, target `0x16e59f`.
At `0x16e59f`, the generated static metacall directly calls `0x101110`.
`.eh_frame` places all three requested direct calls in the FDE beginning at that
entry. This combined metadata/dispatcher/FDE evidence is the function-name
binding; the FDE by itself would not provide a source-level name.

The generated row-64 call at `0x16e030` remains a separate producer edge. It is
not one of these three implementation-internal sites.

## Exact direct-call argument producers

The x86-64 QString-return convention at the three sites places hidden return
storage in `%rdi`, `this` in `%rsi`, `encFile` in `%rdx`, and `destPath` in
`%rcx`. The retained LLVM excerpts show these exact assignments before each
call.

### `0x102de9`: top-level What's New archive

- `0x10155b..0x1015cd` combines the branch-selected package-base QString with
  fixed `.whatsnew.tar.gz` (`0x20bb63`) through `%1/%2` (`0x209cd4`). The result
  is retained at stack slot `+0x80`.
- `0x1017c0..0x10185c` constructs `/update/whatsnew/temp` from fixed
  `/update/whatsnew` (`0x20bdad`) and `temp` (`0x20be21`).
- `0x101b50..0x101bbd` appends fixed `.whatsnew.tar.gz`, producing
  `/update/whatsnew/temp/.whatsnew.tar.gz`.
- `0x101bda` tests byte `0x6d20b4`; nonzero branches to `0x102da0`. The zero
  branch uses the non-decryption copy/extract route.
- `0x102dbb..0x102dc9` copies the package archive into the QString passed in
  `%rdx`; `0x102da8..0x102db6` copies the fixed temp archive destination into
  the QString passed in `%rcx`; `0x102de9` calls `0x100b30`.

Thus this site's static path classes are:

```text
encFile  = <branch-selected package base>/.whatsnew.tar.gz
destPath = /update/whatsnew/temp/.whatsnew.tar.gz
```

The package base is not a static literal. At `0x101134..0x101173`, one mode
copies a QString from the object graph (`this -> +0x40 -> +0x30`); the alternate
mode reached at `0x102c90` copies a global QString. Static analysis therefore
establishes suffix and destination constants, not a universal source mount.

### `0x10281c`: enumerated system-tree files

- Normal destination root construction uses fixed
  `/update/whatsnew` + `/whatsnew_new`; the alternate mode selected by the
  `0x6d4fb8 == 1` branch uses fixed `/whatsnew_new_usb_in_ota`.
- The package system root is branch-selected package base plus fixed
  `/whatsnew/whatsnew`.
- `0x1022b6` tests the same byte `0x6d20b4`; zero branches to the non-decryption
  copy route at `0x102eba`, while nonzero enters directory/file enumeration.
- `0x10237b..0x1023f5` pairs corresponding top-level source and destination
  names. `0x102536..0x1025b9` pairs the next directory level.
- `0x102a84..0x102b12` obtains each `QFileInfo::fileName()` and appends it to
  the destination directory. `0x1027f5` obtains the enumerated source
  `QFileInfo::absoluteFilePath()`.
- Immediately before `0x10281c`, `%rdx` receives that absolute source path and
  `%rcx` receives the constructed destination path.

Static path classes:

```text
encFile  = <package base>/whatsnew/whatsnew/<enumerated relative file>
destPath = /update/whatsnew/{whatsnew_new|whatsnew_new_usb_in_ota}/<same paired names>
```

### `0x103398`: enumerated controls-tree files

This is the controls-tree analogue:

- package root suffix: fixed `/whatsnew/whatsnew_controls`;
- normal destination: fixed `/update/whatsnew/whatsnew_controls_new`;
- alternate destination suffix: fixed `/whatsnew_controls_new_usb_in_ota`;
- `0x103075` tests `0x6d20b4`; zero branches to non-decryption copy logic at
  `0x103a1f`, while nonzero performs enumeration;
- `0x103134..0x1031ad` pairs source and destination top-level names;
- `0x1032bf..0x103352` finalizes the paired destination filename;
- `0x10337b` obtains the source `absoluteFilePath()`; immediately before
  `0x103398`, `%rdx` is that source and `%rcx` is the constructed destination.

Static path classes:

```text
encFile  = <package base>/whatsnew/whatsnew_controls/<enumerated relative file>
destPath = /update/whatsnew/{whatsnew_controls_new|whatsnew_controls_new_usb_in_ota}/<same paired names>
```

These conclusions classify the three selected direct producers. They do not
make the prior bounded textual direct-reference scan complete for dynamic,
indirect, reflective, queued, virtual, external-process, or cross-library
invocation.

## Exact downstream shell boundary

A separate bounded review now follows the selected inputs through
`decryptionFile` FDE `[0x100b30,0x10110c)`. The exact split QString construction
substitutes the fixed helper, UUID-derived transient key pathname, incoming
`encFile`, and incoming `destPath`; `encFile` and `destPath` occupy shell-command
fields without an observed quoting or escaping operation. Direct call
`0x100e0c` reaches shared helper FDE `[0x1397c0,0x1398fb)`, which appends fixed
stderr redirection, converts to bytes, and calls `popen` at `0x139867` with read
mode. Under the libc interface contract this is shell interpretation. The helper
drains and discards output, calls `pclose`, and ignores its status. The adjacent
output-accumulating code at `0x139900` has a distinct FDE and is not an alternate
entry.

After the helper, `decryptionFile` removes its transient key, calls `sync`, and
returns `destPath` without using process status or checking destination
existence/size. Similar full command templates at `0x20b500` and `0x20b530`,
plus later destination checks, are referenced by separate FDE
`[0x60ac0,0x6178f)` and must not be attributed to `decryptionFile`. See
[`appfumo-shell-command-boundary.md`](appfumo-shell-command-boundary.md).

This advances the consumer boundary only. The corrected USB dispatcher proves
that exact `usb-automount` places `ID_FS_UUID` or the serial/partition alternate,
not label, in the mount pathname. Exact stock `./lib/libblkid.so.1.1.0` is
SHA-256 `56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701`,
Build ID `c6f98d98cb2cbc2ff864167f37048233d90a8fef`.

Constrained VFAT/exFAT/NTFS/ext/UDF producer negatives remain. They cannot be
generalized to ISO9660: exact `[0x1c4c0,0x1c654)` copies 16 raw date bytes,
checks only the all-ASCII-`'0'` case, and uses raw `%c` format `0x35368`.
Version-matched util-linux v2.27.1 `iso9660.c` lines 110-151 is SHA-256
`601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b`.
`blkid_safe_string` preserves allowed shell/path-sensitive byte classes, and the
dispatcher puts the resulting UUID in the mount component. The static ISO9660
parser-to-mount-path byte route is therefore established. Label remains a
separate non-path field, and the no-UUID sanitizer/context negative remains.

Exact AppDMClient and AppUpgrade producer edges remain compatible with the
hash-bound log class below, but physical ISO9660 control, media acceptance/mount,
installed signal delivery, the AppDMClient launch-argument/inner-AppUpgrade
constructor bridge, and invocation of the relevant `decryptionFile` call with
that path remain unknown. Even if those pre-auth delivery gates were later
established, verifier acceptance would still be required for command
construction and `popen`; actual shell-sink delivery therefore includes that
authentication gate. The observations do not establish end-to-end exact-ELF
invocation, verifier acceptance, process uid/capabilities/SMACK domain, command
success, arbitrary command execution, amplification, root, or persistence.
Command success and amplification remain route-generic observations, not
ISO9660-specific outcomes.

## Public-log observation

Source:
`evidence/upstream/Ioniq5_Gen5W_Log_Dump/2024-10-13T14_08_30/AppUpgrade/upgrade_log`

- size: `2,106,504` bytes
- SHA-256:
  `84d5bb69270dd610b132c8950c31dd98adad844c5a2c108b4df617381685de86`
- retained normalized report:
  [`artifacts/update-candidates/appfumo-decryption-public-log.json`](artifacts/update-candidates/appfumo-decryption-public-log.json)
- normalized report SHA-256:
  `0dc7fb9c2775b2b201ca3b7e38438f75f1db3aa9ddac4298f315ad2e6f35bb66`

The normalized source class is
`/media/usb/{slot}/{volume}/.whatsnew.tar.gz`; the normalized destination is
`/update/whatsnew/temp/.whatsnew.tar.gz`. Volume labels and transient `/tmp`
tokens are not retained.

| Decryption line | Timestamp | Preceding copy context lines | Following transfer/count lines | Context |
|---:|---|---|---|---|
| 1414 | `05-31-24 13:53:48:659` | 1410–1413 | 1415–1417 | matched |
| 1710 | `05-31-24 13:54:12:657` | 1694, 1696, 1698, 1701 | 1711–1713 | matched |
| 7279 | `06-02-24 17:24:55:243` | 7264, 7266, 7269, 7272 | 7280–7282 | matched |
| 11714 | `08-12-24 16:24:43:310` | 11710–11713 | 11715–11717 | matched |
| 11975 | `08-12-24 16:25:37:403` | 11960, 11962, 11965, 11967 | 11976–11978 | matched |
| 17205 | `08-13-24 16:49:52:234` | 17189, 17191, 17193, 17195 | 17206–17208 | matched |
| 21713 | `09-12-24 16:45:08:601` | 21698, 21700, 21703, 21706 | 21714–21716 | matched |

For every event, the preceding records name package system/control directories
under the same normalized removable-media root and fixed
`/update/whatsnew/whatsnew_new` and
`/update/whatsnew/whatsnew_controls_new` destinations. The following record
reports the same normalized archive source/destination pair, followed by system
and control directory counts. This is temporal and pathname-class context only;
it does not prove that a particular static call site or Qt mechanism generated
any log line.

## Defensive parser/model

[`../tools/uk_fw/appfumo_decryption_log_model.py`](../tools/uk_fw/appfumo_decryption_log_model.py)
requires `--log` naming an explicit regular, non-symlink file. It:

- applies a 4 MiB pre-read/read bound, 100,000-line bound, 4,096-byte line
  bound, 512 relevant-record bound, and 64-invocation bound;
- checks path identity, size, mtime, and ctime before/opened/after read;
- requires strict UTF-8, LF endings, the exact public-log SHA-256, and exact
  decryption/copy record grammar;
- permits a hash mismatch only with the explicit `--synthetic-test` mode;
- rejects malformed or unexpected command shapes, duplicate or ambiguous
  records/context, duplicate transient tokens, excessive input, traversal,
  controls, non-absolute paths, and conflicting context;
- emits normalized deterministic UTF-8/LF JSON through `sys.stdout.buffer`;
- never executes or emits the logged command, and omits transient tokens and
  volume labels.

Reproduction:

```text
<platformio-env>/bin/python3 tools/uk_fw/appfumo_decryption_log_model.py --log <tracked-public-log>
```

The placeholder is intentional: this evidence document does not reproduce a
shell-ready target command.

## Remaining unknowns

- binary identity and Build ID of the AppUpgrade instance that wrote the log;
- equality between that installed/logged build and the exact recovered ELF;
- direct-call versus generated Qt meta-call versus another runtime mechanism;
- complete dynamic, indirect, external-process, and cross-library producers;
- external, IPC, D-Bus, UI, or service reachability;
- attacker influence over package base, enumerated files, destinations, or
  timing;
- result acceptance, final payload binding, partition writes, slot/boot
  acceptance, effective privilege, root, and persistence.

## Safety record

Only read-only hashing, metadata decoding, `.eh_frame` inspection, Homebrew LLVM
static disassembly, bounded public-log parsing, and host tests were performed.
No recovered target/helper was executed. No device, radio, target network path,
malformed target artifact, update package, payload, bypass, partition, slot,
boot state, root action, or persistence material was created or exercised.
