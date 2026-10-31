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
continues through later existence/staging/launch logic. Exact callers and state
transitions have not yet proved whether the recovered normal FUMO USB route can
supply `/update/usb/bin` as its source. Therefore the result-pair contracts are
**conditional on unequal source and destination**, not universal FUMO gates.

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
unequal-path code proves an intentional plaintext-mode contract; it does not
prove that a removable device can create the marker, that the equal-path branch
is normally reachable, or that arbitrary plaintext payloads are accepted end to
end.

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
- the equal source/destination branch skips both pair contracts;
- the outer and XML-reader verifier calls are separate opens without a proved
  immutable snapshot;
- eligibility success is not payload acceptance;
- the inner AppUpgrade process remains responsible for substantial target,
  partition, firmware, and write decisions.

No verifier bypass or accepted modified update is established.

## Remaining work

1. Name verifier return `-404` from exact linked verifier semantics rather than
   only its control-flow role and adjacent log text.
2. Trace callers/source state to determine whether the equal
   `/update/usb/bin/AppUpgrade` path is reachable on normal FUMO USB entry, and
   analyze source-file stability across the two XML verifier/open sequences.
3. Recover the second stored version reference and boot-state enum names.
4. Trace the XML destination helper and prove whether encrypted XML is copied or
   transformed at each branch.
5. Map inner AppUpgrade's `version`, `car-variant`, current-system, force-update,
   and partition checks to exact accept/reject paths.
6. Reconstruct payload digests/binding, inactive-slot writing, boot selection,
   boot-time trust, health, and mark-good.
7. On a disconnected owner bench, capture hashes, route arguments, marker state,
   uid/SMACK label, effective `PATH`, and updater state before any active test.
