# Inner FUMO authentication coverage leaves parameterized executable reauthentication unresolved

## Result

The exact embedded EU `260128` FUMO updater contains real public-key, digest,
and component checks. A whole-`.text` scan inventories every direct call to its
file-signature verifier and file-MD5 helper. Fixed and enumerated operands prove
checks over the descriptor, firmware archive, firmware entries, and navigation
files, but several verifier paths accept caller-provided QStrings whose complete
producer provenance has not been bounded. No explicit running/staged
`AppUpgrade` verifier operand was identified, but its absence is not proved.

Separately, startup reduces `argv[0]` to an application base directory used to
find resources, and the reviewed worker `execv` wrapper does not verify its
executable inside that FDE before the call.

Classification: **complete direct-call instruction inventory; parameterized
verifier-target provenance incomplete, so inner executable reauthentication
remains unknown**.

This maps a major part of V-031's later-authentication question without closing
it. The reviewed startup, file-MD5, and relaunch paths do not establish
outer-executable reauthentication; parameterized signature-verifier routes,
indirect/external checks, loader checks, and boot-stage verification remain
unresolved. The result does not establish source mutability, an actual
executable substitution, successful process creation, package acceptance,
partition writes, slot selection, boot acceptance, root, or persistence.

## Exact identity and retained evidence

- exact embedded ELF:
  `work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf`
- size: `5,066,264` bytes
- SHA-256:
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`
- GNU Build ID: `863a8730e66a1c5245a1bf458fe2554adee0351a`
- ELF type: x86-64 PIE/shared object, stripped
- entry point: `0x43140`
- retained assembly:
  `evidence/artifacts/update-candidates/appfumo-authentication-coverage.asm`
- retained assembly SHA-256:
  `44d9192098bb6384a793ffe204727d0f7c409479caf2f46463793ba5c658f068`

Addresses are link-time virtual addresses in the embedded ELF's image-base-zero
namespace. FDE ranges came from the exact `.eh_frame`. Instruction claims were
confirmed with Homebrew LLVM `llvm-objdump`; advisory decompiler
records were used only to assist naming. Every retained excerpt begins at a real
instruction boundary.

## Startup uses the executable name to derive a resource directory

Startup/argument initialization is FDE `[0x125800,0x126fe4)`. The exact path
flow is:

1. `0x1259e3` calls `QCoreApplication::arguments()`.
2. `0x1259f4` obtains argument zero from that list.
3. `0x125a28` obtains `QCoreApplication::applicationName()`.
4. `0x125a45..0x125a4e` subtracts that name's length, subtracts one more
   character, and calls `QString::left()`.
5. `0x126d09` passes the resulting QString to application-object constructor
   `[0x9c2f0,0x9c851)`.
6. `0x9c6e7` forwards it to initializer `[0x8dc60,0x8dd51)`.
7. `0x8dcaa` stores it at object offset `+0x30`; `0x8dcf4` passes that value to
   descriptor reader `[0x7bc50,0x7f82a)`.

The descriptor reader appends the fixed suffix `/.lge.upgrade.xml`. Thus the
reviewed `argv[0]` use is a base-directory derivation for configuration and
resources, not a file-open, signature, or digest operation over the executable.
No full updater-executable pathname or executable bytes are handed from this
startup flow to the recovered verifier or file-hash helper.

## Exact public-key verifier contract

Verifier wrapper FDE `[0x45820,0x45d75)` constructs the fixed key pathname under
the AppUpgrade resource directory, constructs a `QFile` at `0x45944`, checks it
at `0x4594c`, opens it at `0x45975`, and reads its bytes at `0x45988`. It converts
the supplied target-file QString to local bytes and calls signed-container
driver `0x18f740` at `0x45a76`.

The internal code layout is:

- record/key verification: `[0x18f5a0,0x18f6fc)`;
- thin wrapper: `[0x18f700,0x18f732)`;
- signed-file/container driver: `[0x18f740,0x18f7df)`.

At `0x45a76`, the target pathname derived from the wrapper's target-file
argument is in `%rdi`; public-key bytes are in `%rsi`. This is a genuine
signed-file/container check. The coverage question is therefore which target
pathnames reach wrapper `0x45820`, not whether the verifier exists.

## Complete direct-call inventory for the file verifier

A whole-`.text` direct-call scan of the exact ELF found six calls to `0x45820`:

| Call | Containing FDE | Recovered operand class |
|---|---|---|
| `0x7be3a` | `[0x7bc50,0x7f82a)` | application-base-directory `/.lge.upgrade.xml` descriptor |
| `0x80095` | `[0x7fe40,0x80595)` | `%1/HU/firmware/update.tar.gz` firmware archive |
| `0x802f0` | `[0x7fe40,0x80595)` | `QFileInfo::absoluteFilePath()` from firmware-directory enumeration |
| `0x9d1d2` | `[0x9cbc0,0x9e260)` | caller-assembled input; complete producer set not bounded here |
| `0x100bb0` | `[0x100b30,0x10110c)` | `AppUpgradeEngine::decryptionFile(QString encFile, QString destPath)` verifier input; generated local row 64 forwards `a[1]`/`a[2]`, and three direct calls in row-60 `copyWhatsNewFiles()` FDE `[0x101110,0x104c1b)` resolve archive/system/control producer families; a bounded literal Qt/D-Bus audit finds no additional row-64 candidate, while synthesized/indexed, indirect, cross-library, external, and runtime producers remain unresolved |
| `0x140092` | `[0x140030,0x1405da)` | parameterized navigation verify/decryption input; immediate caller traced, complete upstream producer set not bounded here |

The descriptor path is itself conditional: one branch calls the verifier at
`0x7be3a`, while the alternate path constructs a `QFile` at `0x7c2ee` and opens
it at `0x7c31d` without that direct verifier call. This report does not infer
which mode is selected on an installed unit.

The first three rows have bounded descriptor/archive/enumeration provenance.
The latter parameterized routes do not contain an explicit fixed updater path,
but that negative observation is insufficient. The Qt 5 revision-7 metadata and
generated dispatcher now resolve `0x16e030` as local `AppUpgradeEngine` metadata
row 64, `QString decryptionFile(QString encFile, QString destPath)`: `a[1]` is copied
to the `%rdx` `encFile` local, `a[2]` to the `%rcx` `destPath` local, and the
QString result is assigned to `a[0]`. This names one forwarding edge but does not
by itself prove an invoker or argument producer. Follow-up exact-static analysis
binds local row 60 `void copyWhatsNewFiles()` through generated call `0x16e59f`
to FDE entry
`0x101110`; all three direct calls at `0x10281c`, `0x102de9`, and `0x103398`
are in that FDE. They receive, respectively, enumerated system-tree paths, the
branch-selected package-base `.whatsnew.tar.gz` and fixed update-temp archive,
and enumerated controls-tree paths. The common nonzero mode branch selects
`decryptionFile`; normal and USB-in-OTA destination suffix constants are
resolved. Generated row-64 call `0x16e030` remains separate.

A targeted follow-up classifies all 90 old-style QObject connects, all 105
imported literal named invokes, selected constructor connections/timers, and the
selected object's session-bus registration. Option `1` is `ExportAdaptors`; six
attached adaptors have 30 non-target rows and 16 non-target forwarders, and 12
separate D-Bus signal subscriptions select other ordinary slots. This rejects
row-64 selection only through those reviewed literal paths.

A hash-bound public log separately records seven runtime invocations in
`copyWhatsNewFiles` temporal context, but contains no installed-binary identity
and cannot identify direct versus meta-call dispatch. The retained artifacts
therefore keep complete target-producer classification incomplete. Virtual and
indirect calls, synthesized/indexed Qt meta-invocation, cross-library and
external-service behavior are not silently treated as absent. The direct parent
and local-count subtractions are resolved, but row 64 is not asserted as an
absolute method index because the QObject-derived runtime offset is unavailable.

Follow-up exact-static analysis bounds the command consumer inside
`decryptionFile`: its split QString templates substitute the fixed helper,
UUID-derived transient key pathname, `encFile`, and `destPath`; the two pathname
arguments are inserted without an observed quoting/escaping step; and direct
call `0x100e0c` reaches shared helper FDE `[0x1397c0,0x1398fb)`. That helper
appends fixed stderr redirection and calls `popen` at `0x139867` in read mode,
which supplies shell interpretation under the libc contract. It drains and
discards output, ignores `pclose` status, and returns no result. The neighboring
output-accumulating helper at `0x139900` has a separate FDE. After the sink,
`decryptionFile` removes the transient key, syncs, and returns `destPath` without
checking helper status or destination existence/size. Similar full templates at
`0x20b500`/`0x20b530` and subsequent file checks belong to separate FDE
`[0x60ac0,0x6178f)`, not `decryptionFile`. This proves exact unquoted shell-sink
structure, not pathname influence, character survival, reachability,
authentication acceptance, command success, privilege, root, or persistence.
See `evidence/appfumo-qt-metaobject-provenance.md`,
`evidence/appfumo-decryption-runtime-provenance.md`,
`evidence/appfumo-decryption-producer-provenance.md`, and
`evidence/appfumo-shell-command-boundary.md`.

The USB pathname-provenance result does not alter this authentication boundary.
Complete dispatcher flow proves UUID/no-UUID alternate is the path component;
label/model remain separate D-Bus fields. Exact stock
`./lib/libblkid.so.1.1.0` is SHA-256
`56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701`,
Build ID `c6f98d98cb2cbc2ff864167f37048233d90a8fef`.

The constrained UUID-family negatives remain, but ISO9660 exact code
`[0x1c4c0,0x1c654)` formats 16 raw date bytes after only an all-ASCII-`'0'`
test. util-linux v2.27.1 `iso9660.c` lines 110-151 is SHA-256
`601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b`.
Subsequent safe-string handling preserves allowed shell/path-sensitive byte
classes before dispatcher mount-path use. This establishes static byte
provenance. A post-delivery exact-kernel follow-up binds canonical bzImage
through bounded legacy-LZ4 vmlinux and unique embedded gzip IKCONFIG to config
SHA-256 `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`;
its named canonical ISO9660/UDF and SCSI CD-ROM paths are not configured. The
canonical 163-member inventory/metadata lack the tested stock identities and
aliases. Those named routes are false; broad exact-stack completion remains
unknown because renamed, inline, or vendor-equivalent implementation absence is
not established.
Physical source control and accepted/mounted media on an unidentified or
materially different installed runtime, installed end-to-end delivery, and the
AppDMClient launch-argument/inner-AppUpgrade bridge remain unknown. Label-path
and no-UUID shell-active routes remain rejected.

Even if the physical source, successful mount, cross-process pathname bridge,
and invocation of the relevant `decryptionFile` call with that path were later
observed, that would establish only pre-auth delivery to the decryption input.
`decryptionFile` calls verifier `0x45820` at `0x100bb0`, rejects nonzero at
`0x100bc3`, and only then constructs the command and reaches `popen`. Actual
shell-sink delivery therefore additionally requires authentication acceptance.
Static byte provenance establishes neither candidate acceptance, arbitrary
command execution, a successful child command, process context, root, nor
persistence. Command success and amplification remain route-generic
observations rather than ISO9660-specific outcomes.

## Complete direct-call inventory for file MD5

File-hash helper FDE `[0x140f50,0x1413e4)` receives a pathname in `%rdx`,
constructs `QFile` at `0x140f94`, constructs `QCryptographicHash` with algorithm
value `1` at `0x140fa8`, hashes the `QIODevice` at `0x14104a`, and obtains the
result at `0x14117d`. Under the linked Qt API, algorithm value `1` is MD5.

A whole-`.text` direct-call scan found two callers:

- `0x1432f6`, after `QFileInfo::absoluteFilePath()` at `0x1432da`;
- `0x15170c`, after `QFileInfo::absoluteFilePath()` at `0x1516e9`.

Both sit in the navigation-checksum code region identified by `getMD5`,
`naviChecksum`, `currentFileChecksum`, and `NaviChecksumThread` metadata. Neither
direct caller supplies an updater-executable pathname.

The ELF also contains SHA-1-like `QCryptographicHash` operations over parsed
QString/configuration fields. Those routines hash in-memory descriptor fields;
they do not open or hash the updater executable and therefore are not counted as
outer-executable authentication.

## Worker relaunch is not a reviewed self-verification path

Relaunch wrapper FDE `[0x6c9a0,0x6cab5)` calls `vfork` at `0x6c9bf`, constructs
an argument vector whose executable is `/navi/tmp/sysroot/AppUpgrade`, and calls
`execv` at `0x6caa8`. The following fixed arguments include
`handle_run_process` and `/navi/tmp/sysroot/hkmc_avn5_tot_d.up`, followed by
caller-provided arguments.

The wrapper does not call the file verifier, MD5 helper, or another recovered
file hash before `execv`. The whole-ELF direct-call inventories above likewise
do not identify that worker executable as a verifier/hash operand. This proves
only that the reviewed direct relaunch path lacks a pre-`execv` executable
reauthentication step; it does not exclude an indirect check in a caller,
external service, loader, or boot stage.

## Later payload trust remains real and distinct where operands are resolved

The unresolved outer-executable result does not mean that FUMO accepts arbitrary
update content. Resolved direct operands prove verification or hashing of the
descriptor, firmware archive, enumerated firmware files, and navigation content.
Other verifier calls occur in component/resource/navigation processing but keep
parameterized target provenance. The ELF also invokes external helper and
partition-writing machinery whose full behavior is not established here.

These are different trust subjects:

```text
outer updater executable identity
    != descriptor authenticity
    != archive/component authenticity
    != transformed final bytes
    != partition-write authorization
    != slot/boot acceptance
```

The TUF specification requires a desired target's downloaded length and hashes
to match its targets metadata before the target is returned for use. Uptane
2.1.0 similarly states that ECU images are verified against image hashes before
installation. These public specifications are comparative design guidance only;
they do not establish that this proprietary updater implements TUF/Uptane or
prove any target behavior. They support the narrower analytical rule that an
authentication result must be bound to the exact object or image later used.

Public references:

- TUF specification, section 5.7, “Download Target”:
  <https://theupdateframework.github.io/specification/latest/>
- Uptane Standard 2.1.0, sections 5.4.2.4 and 5.4.3.4:
  <https://uptane.org/docs/2.1.0/standard/uptane-standard>

Read-only copies and hashes remain under ignored
`work/online-update-binding-20261103/`. No target-specific information was sent
to either source.

## Security classification and remaining gates

This finding establishes the direct verifier/hash call inventory and several
resolved trust subjects. It does **not** decide whether all reviewed direct inner
FUMO paths close V-031's outer-executable identity boundary, because some direct
verifier targets remain parameterized and incompletely traced. These also remain
unresolved:

- complete producer provenance for the parameterized signature-verifier targets;
  local `AppUpgradeEngine` rows 60 and 64 now bind the selected direct
  `copyWhatsNewFiles()` producers and generated `decryptionFile` forwarding;
  reviewed literal Qt/D-Bus routes contain no additional candidate, but
  synthesized/indexed, indirect/cross-library/external paths and complete
  runtime upstream producers remain unbounded;
- indirect and virtual call targets not statically resolved by the direct-call
  inventory;
- all consumers of the four additional
  `QCoreApplication::arguments()` call sites;
- external helper and credential-service internals;
- runtime mount, ownership, uid, SMACK, directory-replacement, content-write,
  and update-serialization policy;
- whether the verified and consumed outer executables ever differ;
- whether the owner unit has this exact installed artifact;
- successful process creation and resulting uid/SMACK label;
- exact final-payload binding after decryption/extraction;
- partition-write eligibility, inactive-slot selection, loader verification,
  rollback policy, boot acceptance, health, and mark-good.

Consequently this is not proof of a signature bypass, accepted modified update,
root, flashing, or persistence. Even if an outer executable identity mismatch
were later demonstrated, FUMO's payload/component checks could still reject
unauthenticated update data.

## Bounded model

`tools/uk_fw/fumo_auth_coverage_model.py` consumes thirteen Boolean facts. It
requires complete direct call inventories and operand classification before a
negative direct-reauthentication result is emitted. Incomplete negative facts
remain `null`; any explicit positive direct executable-authentication path takes
precedence. Absolute absence remains `null` unless indirect and external
reauthentication are separately excluded.

For the pre-recorded exact-binary state the model reports:

- complete reviewed direct coverage: `false`;
- reviewed direct executable reauthentication found: `null`;
- reviewed direct executable reauthentication absent: `null`;
- reviewed direct paths close the outer executable identity gap: `null`;
- later descriptor/payload verification present: `true`;
- all inner/external executable reauthentication absence proven: `null`;
- every runtime, update, partition, slot, boot, privilege, and persistence
  outcome: `null`.

Deterministic schema-v2 report SHA-256:
`1192767f643c2cb075cb6f8f80e6fe7ce4555e7104daa7cf63a3735f7460c39f`.
The model emits no firmware, update, archive, command, target pathname, payload,
launch message, or race schedule.

## Validation and review

- focused model: `10 passed, 8203 subtests passed`;
- complete suite: `553 passed, 148482 subtests passed`;
- public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`;
- corrected independent exact-binary/package review: **ACCEPT**.

The corrected review independently confirmed the exact ELF identity, direct-call
sets, parameter-forwarding callers, retained instruction boundaries and bytes,
FDE ranges, model truth table, deterministic hashes, and fail-closed unknown
classification.

## Safety record

No updater, verifier, helper, target pathname, recovered executable, launch
request, update package, archive, partition, slot, boot state, or target syscall
was exercised. No replacement, race, payload, command, flash operation, root
action, or persistence mechanism was created. Host-side hashing, disassembly,
Boolean classification, and Python tests used ordinary host operations outside
those target claims.
