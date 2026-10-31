# AppDMClient FUMO USB descriptor eligibility and encryption-mode gate

## Scope and claim boundary

This note reconstructs the recovered `AppDMClient` FUMO USB path that reads
`.lge.upgrade.xml`, compares its version, and stages `AppUpgrade`. It is separate
from AppScomoDM's SCOMO ZIP path.

The work is static and read-only. No recovered executable was run, no update
input was made, and no firmware, VM partition, or owner unit was modified.
Decompiler output was used for navigation; the cited branches and calls were
checked against exact `llvm-objdump` instructions.

This establishes descriptor parsing and mode-gate semantics. It does **not**
establish acceptance of a modified update, model/region bypass, payload
authentication bypass, partition writes, slot selection, boot acceptance,
health, mark-good, root, or persistence.

## Exact artifact

| Property | Value |
|---|---|
| path in stock rootfs | `/app/bin/AppDMClient` |
| reviewed copy | `work/decrypted-eu-260128/extracted-partial-bsdtar/mango-rootfs/app/bin/AppDMClient` |
| SHA-256 | `9a1fb796d7ac24fcce71c16e3dbee9306c888f43e705ee081f41b7d473978bd0` |
| GNU Build ID | `b2dbcc5231f444d8f1dd68eb7a2376323ce805df` |
| format | x86-64 PIE ELF |

Function boundaries from exact unwind metadata:

- USB launch/staging owner: `0x7ff60..0x830e4`;
- `checkVersionUSBUpdate`: `0x67e30..0x69144`;
- first-line file reader: `0x76160..0x7640b`;
- `slotUsbMounted(QString, int, QString, QString)`: `0x84700..0x84e2d`;
- force-relaunch helper: `0x87150..0x873fb`;
- `slotOnStandbyStatus(int)`: `0x87400..0x886e7`;
- version comparator: `0xcab90..0xcbd4d`;
- XML reader: `0xe1e90..0xe3166`;
- USB-version wrapper: `0xe3170..0xe33ae`;
- public-key verifier wrapper: `0x34870..0x34d43`;
- marker helper: `0x696f0..0x697be`.

## FUMO and SCOMO are different paths

The string `bool AppDMClientEngine::checkVersionUSBUpdate(QString)` is present at
VA `0x17bd40`, and this binary carries FUMO and `/update/fota` state. AppScomoDM
is a separate executable and owns the SCOMO `S5W_SYSTEM_*_*_*.zip` extraction
path. Findings below must not be transferred to AppScomoDM.

## AppUpgrade and XML verification results are computed first

The FUMO staging function constructs `<source>/AppUpgrade` and
`<source>/.lge.upgrade.xml`. It calls verifier wrapper `0x34870` for AppUpgrade
at `0x802db` and for XML at `0x80320`. The wrapper:

1. constructs `/app/share/AppUpgrade/teruten5_pub.key`;
2. requires and reads that key;
3. passes the candidate path and key bytes to the linked verifier;
4. returns its integer result.

The pair is first ORed at `0x805a0..0x805a8`. A nonzero pair can enter an
optional `VarUpgrade` branch if that file exists; that branch has its own
verification and processing. Otherwise execution can continue toward USB
eligibility. The retained results are interpreted again later, but not on every
control-flow path.

## Descriptor path and XML semantics

The wrapper at `0xe3170` formats `%1/.lge.upgrade.xml` at
`0xe31a4..0xe31ce`, tests existence, and calls the XML reader at `0xe320c`.
Missing or unusable input leaves an empty `QString`.

After successful parsing, `0xe1e90`:

- lowercases the document root and accepts only `lhavn` or `wideavn`;
- starts with the root's first child and walks consecutive siblings only while
  each converts to a `QDomElement`; a comment or other non-element sibling ends
  the loop rather than being skipped;
- lowercases each element tag;
- converts only that element's first child to text and trims its data;
- returns the first such element whose tag is `version` and whose first child
  converts to a non-null text node. The trimmed string itself may be empty.

The root comparisons occur at `0xe245b..0xe246c` and
`0xe2b90..0xe2bc7`. Direct-child traversal starts at `0xe2482`; tag/text
handling is at `0xe24e8..0xe2564`; assignment of the matching version is at
`0xe2cb1..0xe2d8d`. Nested elements and attributes are not selected. A later
`version` sibling can still win if an earlier one lacks a qualifying first text
child; siblings after the first qualifying `version` are not examined.

The recovered official outer descriptor uses `<wideavn>` and a direct
`<version>` element, but that observation alone does not prove which owner
build or removable-media route will be selected.

## Encrypted and plain XML reader branches

The XML reader calls verifier wrapper `0x34870` at `0xe1ff7`.

- Return `0` selects the encrypted-container branch.
- A nonzero return selects direct plaintext XML parsing at
  `0xe22b8..0xe2407`.

For the encrypted branch, the executable and shell syntax are fixed:

```text
/app/share/AppUpgrade/DecryptToPIPE -d <generated-key-temp> <source-xml> 0 |
  dd of=<generated-output-temp> bs=512
```

The exact templates are `%1 -d %2 %3 0` and ` | dd of=%1 bs=512`. Temporary
paths are generated beneath `/tmp`; the key temp is populated by the local key
service/helper. `system()` is called at `0xe27b7..0xe27c3`, and its status is
not tested. The output file still has to open and parse as XML.

The source path is the caller-provided directory plus the fixed XML basename.
It is substituted into shell text without visible quoting. The executable,
options, pipe, `dd`, and temp-path base are fixed. The provenance and character
constraints of the runtime source-directory string have not been proved here,
and the earlier verifier call is not shown to hold an immutable snapshot across
this second open. These are shell/TOCTOU boundary observations, not a command-
injection or verifier-bypass finding.

## Conditional marker semantics and the equal-path gate-skipping branch

The staging function constructs source `<source>/AppUpgrade` at
`0x80165..0x80196` and destination `/update/usb/bin/AppUpgrade` at
`0x801ab..0x801ef`. It compares those paths at `0x80ba2..0x80bb2`.

If they are equal, `0x80bb2` jumps to `0x80ea7`, skipping both the marker helper
and the verifier-result pair checks below. This pre-staged/equal-path branch
continues through later existence/staging/launch logic. The result-pair
contracts are therefore **conditional on unequal source and destination**, not
universal FUMO gates.

### Caller and source provenance is now resolved

The equal path is an intended local relaunch route, not merely a hypothetical
comparison outcome:

- the constructor initializes the `QString` at `this+0x128` to Qt shared-null
  at `0x67431` and clears byte `this+0x11c` at `0x674b0`;
- exact string metadata names function `0x84700` as
  `AppDMClientEngine::slotUsbMounted(QString, int, QString, QString)`;
- when its integer index equals `1`, `0x848d8..0x848ee` copies the callback's
  mount-path argument into `this+0x128` and sets `this+0x11c=1`;
- the same callback directly passes that mount path to staging at `0x849a7`;
- later callers, including `0x850de`, `0x8680c`, `0x86f8c`, and `0x87858`, load
  the same member when mounted;
- exact string metadata names function `0x87400` as
  `AppDMClientEngine::slotOnStandbyStatus(int)`. Its status-12 workflow also has
  a fixed `/update/usb/bin` staging call at `0x882f3` when local state selects
  the pre-staged route.

The separate helper at `0x87150` implements a second fixed local route. It asks
`0x76160` to read the first line of `/update/force_launch`, compares that line
case-sensitively with exact text `run` at `0x87233..0x87256`, and returns on any
mismatch. Equality reaches `0x87379..0x87395`, constructs exact directory
`/update/usb/bin`, and calls staging. Because staging appends `/AppUpgrade` to
its source directory, this makes source and destination both
`/update/usb/bin/AppUpgrade` and reaches the `0x80bb2 → 0x80ea7` jump.
`slotOnStandbyStatus` calls this helper at `0x87ee9`.

The exact embedded FUMO child supplies the other half of this relaunch contract.
Its file writer at `0x140a50` opens the caller-provided path for write/truncate,
writes the provided UTF-8 value, flushes, and calls `fsync`. In its progress
handler:

- firmware-mode progress zero writes `processing` to
  `/update/firmware_update_complete` at `0x11ff11..0x11ff36`, then, unless
  global mode `0x6d4f94` equals `1`, writes `run` to
  `/update/force_launch` at `0x11ff4c..0x11ff71`;
- system-mode progress zero performs the corresponding writes at
  `0x120571..0x120593` and `0x1205a9..0x1205cb`;
- an additional branch in the same progress handler writes the same force
  path/value at `0x120371..0x1203a7`, again guarded by global
  `0x6d4f94 != 1`;
- another exact writer site for the same force path/value is present at
  `0x1151c3..0x1151fa`.

Completion cleanup at `0xfd3d0..0xfd9bb` first removes
`/update/system_update_completed` through helper `0x13feb0`. For each remaining
existing status path, including `/update/force_launch`, it writes exact text
`none`; the force-path overwrite is at `0xfd67b..0xfd6e9`. The force-relaunch
helper therefore calls staging only while the marker's first line is exactly
`run`, not merely while the file exists; AppDMClient's other staging callers do
not all consult this marker.

This proves normal software reachability and provenance of the equal local
source. It does **not** prove that removable media directly controls
`/update/usb/bin`, that an unauthenticated package creates `force_launch`, or
that files remain immutable between initial staging and relaunch. Entry into
the inner progress callback has not yet been bound to a named completed
signature/payload-authentication state. The equal branch is best described as
an intended pre-staged relaunch that omits repeated AppDMClient pair checks, not
as a first-entry authentication bypass.

On the unequal-path branch, helper `0x696f0` tests
`/update/disableEncryptionUpdate` and returns the inverse of `QFile::exists()`.
The staging function calls it at `0x80bbb`:

### Unequal path, marker absent: encrypted mode

The helper returns `1`, taking the branch to `0x815e0`. Exact instructions OR
the AppUpgrade and XML verifier results and reject unless **both are zero**:

```text
0x815e0  mov  AppUpgradeResult,%eax
0x815e4  or   XmlResult,%eax
0x815e8  jne  failure
```

Only then does the function obtain decryption key material and assemble the
fixed `DecryptToPIPE` pipeline for AppUpgrade. These checks use results retained
from the earlier calls at `0x802db`/`0x80320`, not the XML reader's later call at
`0xe1ff7`. With a stable file and deterministic verifier they should agree, but
no immutable snapshot is held across the opens. The equal-path branch skips
these checks entirely. Therefore plaintext fallback is not itself proof of a
bypass, but neither is it unconditionally bound by this pair check.

### Unequal path, marker present: explicit non-encrypted mode

The helper returns `0`. Exact comparisons require **both** verifier results to
equal `-404` (`0xfffffe6c`) at `0x80bc8` and `0x80bd6`. Any other result reaches
the `Error unencrypted update. (Unknown image type.)` failure path at
`0x824b0`.

The marker is a local `/update` state file, not a USB member. Its existence must
therefore be observed or established through a separate privileged path. This
unequal-path code proves an intentional plaintext-mode contract; the separate
equal path is now proven normally reachable only as the local relaunch described
above. Neither fact proves that removable media can create the mode marker or
that arbitrary plaintext payloads are accepted end to end.

## Eligibility comparison

`checkVersionUSBUpdate` calls the USB-version wrapper at `0x68207` and on a
duplicated state path at `0x6867e`. Empty XML versions fail.

It then requires two comparator results:

1. installed/current reference versus USB candidate with arguments
   `(vehicleCheck=false, allowEqual=false)` at `0x68271` / `0x686e8`;
2. a second stored reference versus USB candidate with
   `(vehicleCheck=false, allowEqual=true)` at `0x682d8` / `0x68745`.

The first is strict (`base < candidate`); the second allows equality
(`base <= candidate`). The exact `setle` for the equality-allowed result is at
`0xcb78b`. Both results must pass before the routine sets its accepted-state
byte or takes its next-stage path.

The comparator uses case-sensitive `QString::compare` over normalized string
sections, not component-wise integer arithmetic. Its explicit section-zero
vehicle-type equality check is disabled by all four reviewed USB call sites.
It still enforces a `P5` versus non-`P5` version-family match and applies
platform/CUV-dependent section normalization. Product meanings for every
numbered section are not present in this binary and are not assigned here.

This means the descriptor syntax helper in AppScomoDM and the FUMO version
checks here answer different questions. It also means “vehicle check disabled”
is not “all model/region gates removed”: later AppUpgrade code contains
`car-variant`, system-version, partition, and firmware filtering that remains to
be reconstructed end to end.

## Ordering and trust boundary

The FUMO function computes verifier results before calling the eligibility
routine. The pair is first used for preliminary zero/nonzero routing, then is
interpreted conditionally later. Consequently:

- the XML parser can inspect plaintext after a nonzero result from its own,
  second verifier call;
- the unequal source/destination branch requires retained outer results `0/0`
  when the marker is absent or `-404/-404` when it is present;
- the equal source/destination branch skips both pair contracts and is reached
  by the intended `/update/usb/bin` local-relaunch workflows described above;
- the outer and XML-reader verifier calls are separate opens without a proved
  immutable snapshot;
- eligibility success is not payload acceptance;
- the inner AppUpgrade process remains responsible for substantial target,
  partition, firmware, and write decisions.

No verifier bypass or accepted modified update is established.

## Remaining work

1. Name verifier return `-404` from exact linked verifier semantics rather than
   only its control-flow role and adjacent log text.
2. Analyze source-file stability from the initial unequal staging operation,
   through the separate XML verifier/open sequences, into the now-proven local
   relaunch; name the authentication state that precedes the progress-zero
   `force_launch=run` writes.
3. Recover the second stored version reference and boot-state enum names.
4. Trace the XML destination helper and prove whether encrypted XML is copied or
   transformed at each branch.
5. Map inner AppUpgrade's `version`, `car-variant`, current-system, force-update,
   and partition checks to exact accept/reject paths.
6. Reconstruct payload digests/binding, inactive-slot writing, boot selection,
   boot-time trust, health, and mark-good.
7. On a disconnected owner bench, capture hashes, route arguments, marker state,
   uid/SMACK label, effective `PATH`, staged `/update/usb/bin` identities, and
   updater state before any active test.
