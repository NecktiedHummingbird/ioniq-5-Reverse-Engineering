# Recovered `AppUpgrade` routing and update-trust boundaries

Status: read-only exact-binary reconstruction of recovered EU `260128`. No
updater, helper, payload, or recovered target executable was run. No package was
installed, no partition was written, and no slot was changed.

## Result in one paragraph

Recovered `AppUpgrade` is an outer Qt wrapper containing two complete updater
ELFs. An exact, case-sensitive `-un:1` application argument selects the embedded
SCOMO updater; any other argument set, including `-un:0`, selects the embedded
FUMO updater. AppLauncher does not give a dynamically requested `AppUpgrade` an
empty argument list: it builds the normal vehicle/model option list and stores
it in the new process object. The recovered embedded fallback row for the
IONIQ 5 `NE`/EUR combination contains `-un:0`, so that row routes app ID 300 to
FUMO. AppDMClient's FUMO USB path computes verifier results for `AppUpgrade`
and `.lge.upgrade.xml`, parses a direct `<version>` child, and applies two version
comparisons before staging. On its unequal source/destination branch,
`/update/disableEncryptionUpdate` selects a result contract: absent requires
retained verifier returns `0/0`; present requires `-404/-404`. An equal
pre-staged AppUpgrade path skips both contracts. Caller reconstruction now shows
that the equal source is intentionally reached for local `/update/usb/bin`
relaunch, including an exact `force_launch=run` state contract; it is not an
unresolved hypothetical branch. In SCOMO, the recovered
MASS_PRODUCT/PENETRATION startup path explicitly ignores that marker. This reconciles the apparently conflicting code, but it does
**not** prove that a marker-bearing plaintext package passes later model/region,
payload binding, write, slot, boot, or health checks.

## Artifact identities

| Artifact | SHA-256 | Build ID |
|---|---|---|
| outer `/app/bin/AppUpgrade` | `5295c6e4c41fb9c03760cf006c58b66fcd11aeb4e6e889af6e31b062549b6df0` | `167190fb42e2c0eda6e2a3f2c2130759d4484145` |
| exact embedded SCOMO ELF | `dc11f293e4e8465fe3c23a55c6c6878925104576a719f9bba44cabd24e0d9d39` | `707355ce2c47bc7a9212b94c4a5b1831cc3b4933` |
| exact embedded FUMO ELF | `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7` | `863a8730e66a1c5245a1bf458fe2554adee0351a` |
| `/app/bin/AppLauncher` | `c8d6d56bc254ad0731e81f40bd83aa9b3be6b49bcbd8efb291157a06c4a84268` | not used for this conclusion |
| `/app/bin/AppScomoDM` | `c44da21eb39987e88d71c648f625338722b8458f0ff8ecfe29e3321cf6d62046` | `496a47fae4cca227723b1f4037be918cae18473c` |
| `/app/bin/AppDMClient` | `9a1fb796d7ac24fcce71c16e3dbee9306c888f43e705ee081f41b7d473978bd0` | `b2dbcc5231f444d8f1dd68eb7a2376323ce805df` |
| stock `/bin/busybox` | `95bab633630fb158344497af52dc112e9e777458b810860068d4daa257bd9ebc` | two notes: `42e0a4c7631667cf9106ca36a4f2e7886f6f72b0`, `dc25533aa5ad984ec9a7ed388925f24d328c1836` |
| `/app/bin/AppSetup` | `5221ed11a7945eee448c39f8c0a6b52ee2e3130ff8df5fb8b0a9d1c2343200b3` | `c30aaa3c2e3fd536beeb2fafc774e4339550fdf4` |

The canonical extracted files are ignored research artifacts under:

- `work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-7c64.elf`;
- `work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf`.

Older broad carvings named `AppUpgrade-embedded-*.elf` contain trailing bytes
and must not be cited for whole-file size or hash.

## Address namespaces

Three namespaces are kept separate throughout:

1. **outer-file offset** in the 10,787,256-byte wrapper;
2. **embedded-file offset** beginning at byte zero of the selected child ELF;
3. **embedded virtual address** interpreted through that child ELF's own
   program headers.

Outer code and resource data relevant here are in the first outer `PT_LOAD`, so
outer link-time VAs happen to equal outer-file offsets there. That numerical
equality does not merge the two concepts and does not apply to every segment.
For SCOMO, code/rodata VAs in the first load segment happen to equal embedded
file offsets, while writable data has a `0x200000` VA/file-offset delta.

## Deterministic embedded layout

`tools/uk_fw/embedded_elf.py` validates the ELF header, program table, section
table, load segments, file-backed extents, executable entry point, and overlap
before reporting or extracting an image.

| Resource | Outer start | Exact extent | Outer structural end | Gap to next image/section boundary |
|---|---:|---:|---:|---:|
| `:/AppScomoUpgrade` | `0x7c64` | `0x56a560` | `0x5721c4` | 4 bytes |
| `:/AppFumoUpgrade` | `0x5721c8` | `0x4d4e18` | `0xa46fe0` | `0x1e8` bytes |

The magic at outer `0x4fc8d2` is rejected because it is not ELF64. The four
bytes immediately before each Qt resource payload encode resource length and
are not part of the embedded ELF. In particular, the four-byte gap after SCOMO
is the FUMO resource's big-endian length field, not SCOMO padding. The final
`0x1e8` is only the gap to the containing outer `.rodata` boundary; the tool
does not assign those bytes to FUMO.

## Outer-wrapper control flow

The recovered outer `main` begins at outer VA/file offset `0x3780`.

### Selection predicate

- `QCoreApplication::arguments()` is called at `0x3978`.
- The exact literal `-un:1` is at outer `0x7924`.
- `QStringList::contains(..., Qt::CaseSensitive)` is called at `0x3988`.
- The result is tested at `0x39a0`.
- True selects `:/AppScomoUpgrade` at `0x39ae`.
- False selects `:/AppFumoUpgrade` at `0x3ae6`.

There is no `-un:0` test in the wrapper. Therefore:

| Application argument list | Selected child |
|---|---|
| contains exact `-un:1` | SCOMO |
| contains `-un:0` but not `-un:1` | FUMO |
| contains neither | FUMO |
| contains both | SCOMO |

### Copy, start, and completion

The wrapper:

1. attempts to find and kill orphaned `AppUpgrade` processes;
2. executes `rm -f /tmp/AppUpgrade` at `0x394a`;
3. copies the selected Qt resource to `/tmp/AppUpgrade`;
4. executes `chmod 755 /tmp/AppUpgrade`;
5. executes `cp /update/usb/bin/.lge.upgrade.xml /tmp/`;
6. starts `/tmp/AppUpgrade` asynchronously;
7. enters the Qt event loop until the child-finished signal calls
   `QCoreApplication::quit()`.

The child-launch helper begins at outer `0x5ee0`. It calls
`QCoreApplication::arguments()`, removes element zero, and passes every remaining
argument to `QProcess::start` at `0x5f65`. Thus the child receives `-un:0` or
`-un:1` and all other model/runtime options unchanged.

The wrapper does not block with `waitForFinished()` for the selected child. The
separate one-second wait at `0x61b2` belongs to the pre-launch orphan scan.

The return values from removal, resource copy, chmod, XML copy, and the
child-finished status are not used to determine wrapper success. Normal `main`
returns `1` at `0x3ab4` regardless of child exit code or exit status. No
post-run removal of `/tmp/AppUpgrade` was found. No `errorOccurred` signal
handler was identified, so a failed child start could leave the event loop
without its expected finished signal; that possible hang is a Qt-runtime
inference, not an observed result. Similarly, if removal failed and Qt refused
to overwrite an existing destination, proceeding toward a stale file is an API-
level possibility whose permissions and runtime reachability are unproven.
These are wrapper error-handling properties, not a bypass of checks inside the
selected child.

## How AppLauncher supplies `-un`

The D-Bus launch contract carries app ID, name, and executable location; it does
not carry an arbitrary argument array. That does not leave dynamic processes
argumentless.

### Dynamic app ID 300

The dynamic-process helper at AppLauncher VA `0x1fd30`:

- validates the requested ID and executable;
- allocates an `AppProcess` at `0x1fe28..0x1fe3a`;
- stores the ID at `AppProcess+0x20` and executable at `+0x58`;
- calls the option builder at `0x34510` from `0x1febe..0x1fec8`;
- installs the returned `QStringList` at `AppProcess+0x60`.

The launch routine at `0x163f0` passes that same `+0x60` list to
`QProcess::start` at `0x1745d`. The initial Qt shared-null value is only
construction state before the builder call, not the final launch list.

### Option builder and model table

The builder at `0x34510` first synthesizes common options such as `-cv`, `-vv`,
`-sv`, `-dt`, `-et`, `-pf`, and others. It then merges model-specific options
from the loader object at `+0x28` around `0x35ca8..0x35cd0` and returns the
assembled list around `0x36068..0x36072`.

The parser at `0x380a0` can replace its embedded table with
`/app/bin/CarOption.csv` if that file exists and is readable. No such external
file is present in the recovered extracted rootfs used here, so the embedded
fallback is the applicable recovered source. Its `NE`/EUR row contains:

```text
NE,...,0x26,...,EUR,...,-et:8,...,-pf:0,...,-un:0,...,END
```

For runtime vehicle fields that select this row, `-un:0` is retained in the
model option list. The `/tmp/no_unece` side effect around
`0x38ca8..0x394a0` does not remove or replace the argument.

This is stronger than merely finding a `-un:0` string: it establishes the
parser, storage, dynamic-process transfer, and eventual `QProcess::start` use.
It remains conditional on the runtime fields actually selecting the NE row and
on the installed owner unit matching this recovered binary and data.

## App ID 311 and AppScomoDM

The static AppLauncher table associates ID `0x137`/311 with `AppDMClient` and
`/app/bin/AppDMClient`. In the AppProcess launch routine:

- exact `-un:1` membership is tested at `0x16660..0x16695`;
- app ID 311 is required at `0x1669d..0x166a8`;
- `/app/bin/AppScomoDM` existence is checked at `0x18178..0x181a1`;
- if all conditions hold, the executable is replaced at
  `0x17990..0x179b8`.

The option remains attached to the process and is passed at launch. The
recovered NE `-un:0` row does not satisfy this substitution predicate.

`AppScomoDM::launchAppUpgrade` begins at VA `0xbf260`. Its recovered launch
request is app ID 300, name `AppUpgrade`, location
`/update/usb/bin/AppUpgrade`. When AppLauncher must create that process, the
normal option builder above supplies its arguments; the outer wrapper then sees
`-un:1` on a SCOMO/UNECE route and selects its SCOMO child.

## AppScomoDM USB staging and pre-launch trust

The function at `0xbf260` is guarded by byte `this+0x68`. All five direct
callers pass a true third argument. The ordinary new-method path is:

1. recreate `/update/usb/temp`;
2. examine the first traversal result returned by `QDirIterator` for
   `S5W_SYSTEM_*_*_*.zip` (there is no iterator loop);
3. require that one result to satisfy `QRegExpValidator::Acceptable` for the eight-group
   `S5W_SYSTEM_...zip` filename pattern;
4. extract only `AppUpgrade` and `.lge.upgrade.xml`;
5. authenticate both extracted files through wrapper `0x28580` and
   `/app/share/AppUpgrade/teruten5_pub.key`;
6. decrypt `AppUpgrade` to `/update/usb/bin/AppUpgrade.temp` through either the
   CryptoService `fileDecryption` method or the old `DecryptToPIPE | dd` route;
7. copy `.lge.upgrade.xml` without decrypting it on this path;
8. require the decrypted temporary application to begin with ELF magic and be
   executable;
9. copy it to `/update/usb/bin/AppUpgrade`, apply mode 755, and request the
   app-ID-300 launch.

Helper `0xb8a10` validates only filename syntax. It does not extract regex
captures or compare them with a device model, region, or installed version.
The normal ZIP command executed at `0xbfaf2` is:

```text
unzip -o <archive> -d /update/usb/temp AppUpgrade .lge.upgrade.xml
```

In the original recovered provider arrangement, `/usr/bin/unzip` points to
stock `/bin/busybox`, SHA-256 `95bab633...bd9ebc`, which identifies itself as
1.23.2. The current `extracted-safe/.../bin/busybox` was later replaced by a
VM-only static helper and must not be used for stock conclusions. Exact stock
`unzip` rejects method 12, accepts method 8, and retains CVE-2015-9261's pre-fix
`huft_build` bound. Consequently, USB-controlled DEFLATE table data is parsed
before AppScomoDM authenticates either member. This is V-020, documented in
`evidence/busybox-unzip-cve-2015-9261.md`; it supports a likely unzip-child
crash/update denial of service, not a demonstrated memory write, signature
bypass, RCE, root, or accepted update.

Authentication wrapper `0x28580` requires the fixed public-key path, reads the
key, and returns verifier `0xe3470`'s result. Linked code contains concrete
SHA-256 and mbedTLS key operations, but the exact signed-file format, covered
byte range, parser mode, and RSA/padding behavior remain incomplete. Both
verifier returns must be zero. This resolves the immediate SCOMO USB owner and
ordering without claiming that every later payload is authenticated.

The legacy layout detector requires exact entries `AppUpgrade`, `HU`,
`.lge.upgrade.xml`, and `.whatsnew.tar.gz`, but this MASS_PRODUCT/PENETRATION
function logs that it will not run the legacy method and returns `-2`. The new
method has weak error handling: several removal/copy/chmod results are ignored.
Exact Qt returns a normal child exit code, `-1` for abnormal/crashed termination,
and `-2` for start/wait failure; AppScomoDM tests only bits 8–15, so every normal
exit code 0..255 passes this gate while `-1`/`-2` fail. The old `DecryptToPIPE`
branch ignores `system()` status, and exhausting three final-copy retries still
continues toward launch. These properties can select stale/partial state only if
permissions and prior files allow it; they do not remove the two preceding
member-verifier calls or prove a first-entry path.

The exact launch is an asynchronous session-bus request to service
`com.lge.avn.applauncher`, path `/Request`, interface
`com.lge.avn.applauncher.request`, method `launch`, with arguments 300,
`AppUpgrade`, and `/update/usb/bin/AppUpgrade`. A separate polling helper uses
`pgrep -x AppUpgrade`; the D-Bus reply itself is not awaited.

## AppDMClient FUMO USB descriptor and mode gate

The FUMO staging function at AppDMClient `0x7ff60..0x830e4` constructs
`<source>/AppUpgrade` and `<source>/.lge.upgrade.xml`. It calls the same style of
fixed-public-key verifier wrapper at `0x802db` and `0x80320`. It first ORs the
results for preliminary routing; a nonzero pair can enter optional `VarUpgrade`
processing. It retains the pair for later conditional checks.

The USB-version wrapper at `0xe3170` reads `%1/.lge.upgrade.xml`. Its reader
accepts lowercased roots `lhavn` or `wideavn`, then walks consecutive siblings
that convert to elements starting at the root's first child; a non-element ends
the loop. It returns trimmed data from the first `version` element whose first
child converts to a non-null text node, although the trimmed string may be
empty. A verifier return of zero selects the `DecryptToPIPE` XML-container
branch; nonzero selects direct XML parsing. The encrypted branch uses generated
`/tmp` paths and fixed executable/options, but substitutes the source path into
shell text without visible quoting and ignores `system()` status. Runtime
source-directory character constraints and source stability across repeated
opens remain unproved, so no command-injection or verifier-bypass finding is
assigned.

`checkVersionUSBUpdate` calls the comparator twice. Reviewed call sites disable
its explicit section-zero vehicle comparison. The first comparison requires the
candidate to be strictly newer than the current reference; the second allows
equality against another stored reference. The comparator is lexicographic over
normalized dot-separated string sections and still enforces `P5` versus non-`P5`
family compatibility.

Later result interpretation is path- and mode-specific:

- source `<source>/AppUpgrade` is compared with destination
  `/update/usb/bin/AppUpgrade` at `0x80ba2..0x80bb2`; equality jumps to
  `0x80ea7` and skips the marker and pair checks;
- on the unequal path with marker absent, `0x815e0..0x815e8` requires retained
  outer results `0/0` before encrypted staging;
- on the unequal path with marker present, `0x80bc8`/`0x80bd6` require retained
  outer results `-404/-404`; any mismatch reaches the unencrypted-image failure
  path.

Exact linked-verifier semantics resolve `-404`. Wrapper `0x34870` calls verifier
`0x121040`, whose parser at `0x11fe20` seeks to `file_size - 0x4024`, reads a
fixed `0x4024`-byte suffix, and recognizes only suffixes beginning `TER` or
`TE2`. A positive-size file no larger than that suffix or one with different
magic reaches the `-404` store at `0x11ff26`; a non-positive size instead
returns `-401` at `0x120288`, and a short read returns `-402` at `0x11ff70`.
Therefore the marker-present contract requires both files to lack a
recognized fixed-size encrypted/authentication trailer. It does not treat
`-404` as successful cryptographic verification. The later 32-byte comparison
uses distinct error `-403` at `0x120f73..0x120f7a`.

The XML parser performs a separate later verifier/open sequence. Exact caller
review now proves that only integer status survives and that no retained open
description or object-identity revalidation binds the later consumer to the
earlier verified object. Runtime source mutability and an actual object mismatch
remain unproved. Numeric-only tool
`tools/uk_fw/appdmclient_fumo_gate_model.py` models these trailer and pair-gate
conditions without reading or creating update material and keeps parser
continuation distinct from cryptographic success or update acceptance.

Caller and state reconstruction resolves the equal path's role:

- `slotUsbMounted(QString, int, QString, QString)` at `0x84700` stores its mount
  path in the `QString` at `this+0x128` when index `1` is reported and directly
  passes that path to staging at `0x849a7`;
- `slotOnStandbyStatus(int)` at `0x87400` can pass the stored mount path, and its
  status-12 workflow also contains a fixed `/update/usb/bin` call at `0x882f3`;
- helper `0x87150` reads the first line of `/update/force_launch`, requires exact
  case-sensitive text `run`, and calls staging with `/update/usb/bin` at
  `0x87395`; the standby workflow calls the helper at `0x87ee9`;
- the exact FUMO child calls its generic writer with `processing` and then
  `force_launch=run` on progress-zero branches at `0x11ff4c..0x11ff71` or
  `0x1205a9..0x1205cb`. At progress 100 the branch-local call sequence is
  `complete` then force value `none` at `0x120754..0x120779` or
  `0x1206e4..0x120709`; later callback flow can still attempt scheduled `run` at
  `0x120371..0x1203a7`. All three run attempts are conditional on global
  `0x6d4f94 != 1`, and the weak writer/callers do not prove full or atomic
  status transitions;
- that additional branch first requires separately read, trimmed system- and
  firmware-completion strings to compare case-sensitively equal to `complete`
  at `0x11fb27..0x11fb62` and `0x120228..0x12029c`, then requires
  `isScheduledUpdating` predicate `0xe8ad0` at `0x1202a2..0x1202ac`. The
  predicate returns true for `this+0x201 != 0` or `this+0x1a0 == 0x19`; the
  accepted branch attempts both scheduled-completion markers before
  `force_launch=run`, without conditioning the force attempt on verified success
  of the preceding writes;
- completion-cleanup FDE `[0xfd3d0,0xfd9bb)` attempts to overwrite an existing
  force marker with `none`; the weak writer result is ignored. Force-relaunch
  helper `0x87150` does not call staging if the first line actually reads
  `none`.

Thus the equal branch is an intended pre-staged local relaunch and omits
repeating the two AppDMClient result-pair contracts. This does not prove direct
removable-media control of `/update/usb/bin`, unauthenticated creation of the
force marker, immutable staging across the relaunch interval, or removal of
inner payload/target checks. The marker has multiple origins, and the direct
call sites show that `force_launch=run` alone does not establish completion:
they follow a `processing` attempt, while the scheduled site has stronger local
completion and schedule-state preconditions. Those conditions are not named
cryptographic results. `DeltaUpdateProgressHandler` routes some events into
callback FDE `[0x11f1b0,0x120a9e)`, but the traced write-site evidence does not
itself establish authentication and valid upstream event authentication remains
unresolved. The static pathname-reopen/TOCTOU structure is now proven. V-032
inventories every direct inner FUMO signature/hash call and resolves the startup
and relaunch paths. Follow-up exact-static work resolves `0x9d1d2` and
`0x140092` as one fixed controller-resource route, not updater pathname roles;
the separate metadata-forwarded `0x100bb0` route and indirect, external, loader,
and boot-stage checks still leave executable reauthentication unknown. Runtime
source mutability and object substitution likewise remain unproved. Normal equal-path
software reachability is also proven. Marker
presence is still an explicit local non-encrypted-mode
contract on the unequal path, not proof that USB media can create it or that
later payloads are accepted. See
`evidence/appdmclient-fumo-usb-eligibility.md`.

## Marker semantics differ by child

### FUMO child

The FUMO mode byte is at embedded VA `0x6d20b4`, embedded-file offset
`0x4d20b4`, outer-file offset `0xa4427c`. Its static file value is `1`.

At startup:

- the marker path `/update/disableEncryptionUpdate` is at embedded
  `0x2119f0`;
- marker existence is tested before the update object/event loop is created;
- if it exists, `0x27ae9` writes zero to VA `0x6d20b4` and logs
  `### Unencryption Update. ####`;
- if absent, the byte remains one and `0x27f14` logs
  `### Encryption Update. ####`.

The byte is subsequently consulted by many decryption/archive/update branches,
including regions around `0x5a654`, `0x5aecc`, `0x6230f`, `0x6296f`,
`0x63287`, `0x7bd6c`, `0x863fc`, `0x864a5`, and `0x878fe`. This proves a
pervasive encryption/decryption-mode selector. It does not, by itself, prove
that all cryptographic authentication, digest, version, model, target, write,
or boot checks disappear.

The marker must exist at process startup. Creating it after the startup test
does not retroactively change the already loaded byte.

#### Navigation-map signature sub-gate

Exact follow-on tracing resolves one downstream use that earlier work left
separate. Function FDE `0x128070..0x128c52` owns a navigation-map signature gate,
with completion byte `this+0xd5`. Before starting its asynchronous NUA-backed
check, it has four skip routes that set the completion byte:

- existence of `/update/disableNaviMapSignatureCheck_20230207` at
  `0x128128..0x12816a`, followed by skip branch `0x128720..0x128745`;
- absence of `/app/bin/NaviUpdateApp`, logged as unavailable NUA, at
  `0x128790..0x1287b5`;
- FUMO encryption-mode byte `0x6d20b4` equal to zero at test
  `0x128940..0x128947`, targeting non-encrypted skip block
  `0x128330..0x128364`;
- no selected navigation-map item after the `navi_` plus `.zip`/`.enc` scan,
  reaching separate skip block `0x128a32..0x128a54`.

Thus `/update/disableEncryptionUpdate` does indirectly select the
non-encrypted skip branch when it was present at startup and changed the shared
mode byte to zero. This is a correction to the earlier statement that its data
flow into the NUA path had not been shown.

When none of those skip conditions applies, the updater starts a signature
worker and two timer-polled stages. Start failure/timeout in function FDE
`0x128c60..0x128e37` and verification failure/timeout in function FDE
`0x128e40..0x129037` call failure handler `0x127e80` with zero. A zero
verification result logs success, sets `this+0xd5`, and tail-calls the gate again
at `0x128f40..0x128f75`.

This is a real, named navigation-map signature skip, but it is not a universal
package-signature bypass. The dedicated marker literal has one static reference
in the exact binary: this existence check. No additional literal reference or
writer was found, but dynamic construction and other processes remain
unexcluded. Neither marker is proved
removable-media-creatable, and descriptor, version/model/region, non-map digest,
payload, write, slot, boot, and persistence gates remain separate. Numeric-only
`tools/uk_fw/fumo_navi_signature_gate_model.py` records the exact skip/wait/fail
states without ingesting or emitting update material.

### SCOMO child

In the exact SCOMO ELF, startup reaches embedded `0x82ba6` and logs:

```text
MASS_PRODUCT or PENETRATION Build mode -> Ignore disableEncryptionUpdate
```

The marker is therefore not the recovered SCOMO production/penetration startup
mode selector. It appears later in common completion cleanup around
`0x150dc7..0x151295`. Generalized test logic also references
`/test_keep_encryption_disable`; test mode 4 can retain the marker during
cleanup. Neither use establishes a startup package-trust bypass.

The navigation-map NUA gate belongs to the FUMO child described above. SCOMO's
startup decision to ignore `/update/disableEncryptionUpdate` remains separate.

## AppSetup is an initiator, not the parser

Exact AppSetup review found its upgrade slot sending the AppManager transition
corresponding to app ID 300. It does not itself discover or decrypt
`.lge.upgrade.xml`, compare package versions, validate model/region, authenticate
payloads, choose SCOMO/FUMO, inspect the marker, or pass `-un`. Statements that
assign those jobs to AppSetup are public operating-model summaries, not exact
recovered-code findings.

The SCOMO USB staging owner is exact: AppScomoDM discovers the archive,
extracts and authenticates `.lge.upgrade.xml`, then copies that file to
`/update/usb/bin` without decrypting it in this route. AppDMClient's separate
FUMO path now resolves direct `<version>` parsing, two version comparisons, and
conditional marker/path verifier contracts. Later model/region eligibility,
payload binding, and every authentication decision inside the selected embedded
updater remain incomplete.

## Route synthesis

The recovered architecture now supports this conditional model:

| Model option | ID 311 executable | Outer app-300 child | Marker at child startup |
|---|---|---|---|
| `-un:0` | `AppDMClient` remains selected | FUMO | changes FUMO mode `1 → 0` |
| `-un:1` | `AppScomoDM` substituted if present | SCOMO | ignored for recovered production/penetration startup mode |
| no exact `-un:1` | no UNECE substitution | FUMO | changes FUMO mode `1 → 0` |

For the recovered embedded NE/EUR row, the first row is the expected static
route. This does not establish the owner's installed hash, selected runtime row,
or active service state.

## Trust matrix

The verdicts below are deliberately separate.

| Boundary | Recovered `260128` verdict |
|---|---|
| outer parsing/extraction | Proven wrapper resource boundaries and selection; no package-parser verdict |
| route selection | Proven: exact `-un:1` selects SCOMO, otherwise FUMO |
| NE model argument | Proven in embedded fallback row and launch data flow; runtime/owner applicability conditional |
| descriptor discovery | SCOMO selected ZIP member and FUMO `<source>/.lge.upgrade.xml` paths proven |
| descriptor decryption | SCOMO copies authenticated XML without decrypting it there; FUMO XML-reader zero selects `DecryptToPIPE`, while nonzero enters direct parsing; its verifier call is separate from earlier retained staging results and no immutable snapshot is proved |
| version eligibility | FUMO exact two-comparison gate proven: strict current-reference upgrade plus equality-allowed second reference; SCOMO child semantics remain separate |
| model/region eligibility | Filename syntax only in AppScomoDM; FUMO explicit section-zero vehicle check is disabled at reviewed USB calls, but P5-family and later AppUpgrade `car-variant`/target checks remain |
| FUMO encryption mode | Proven marker-controlled startup byte; on AppDMClient's unequal source/destination branch, marker absent requires retained `0/0` and marker present requires `-404/-404`; equal pre-staged path skips both checks and is proven reachable through intended local `/update/usb/bin` relaunch state |
| SCOMO encryption mode | Proven marker ignored in recovered MASS_PRODUCT/PENETRATION startup path |
| package signature/authentication | AppScomoDM requires exact-zero verification of extracted AppUpgrade/XML; AppDMClient's unequal path conditionally requires retained `0/0` or `-404/-404`, where exact linked code identifies `-404` as no recognized fixed-size `TER`/`TE2` trailer rather than verification success; its intended local-relaunch equal path skips those repeated pair checks. Exact caller review proves a pathname-reopen boundary with no retained open description or identity revalidation, but runtime source mutability and object substitution remain unproved. V-032 inventories every direct inner FUMO signature/file-hash call. Fixed/enumerated operands authenticate descriptors, archives, firmware entries/resources, and navigation files. Follow-up resolves formerly parameterized calls `0x9d1d2` and `0x140092` as one nested fixed controller-resource path, not running/staged updater pathname roles; both verifier and transform reopen the path, so byte binding remains unknown. The separate metadata-forwarded `0x100bb0` producer boundary, indirect/external/loader checks, and outer-executable reauthentication remain unresolved. Startup and worker relaunch contain no direct self-verification step in the reviewed FDEs. Inner FUMO has a distinct navigation-map signature gate that skips for an explicit marker, absent provider, non-encrypted mode, or no map candidate; this is not a universal package-signature bypass. Authentication state before `force_launch=run` and exact final child payload binding remain incomplete |
| payload hashes/CRC binding | AppScomoDM linked verifier contains SHA-256, but exact covered bytes and all payload bindings remain unresolved |
| archive extraction safety | Exact V-020 pre-auth stock BusyBox method-8 CVE-2015-9261 uninitialized/invalid-read defect; likely child crash, dynamic target impact unproven |
| inactive-slot write | Publicly reported; exact recovered write/target reconstruction incomplete |
| slot selection | Unresolved exact mechanism |
| boot-time image trust | Separate from userspace package acceptance; existing boot-container evidence still applies |
| userspace health/mark-good | Unresolved |

## Correct security interpretation

`/update/disableEncryptionUpdate` is neither a universal production bypass nor
irrelevant:

- on the recovered NE-style FUMO route it is an exact startup mode selector;
- on the recovered SCOMO production/penetration route it is explicitly ignored
  for startup mode;
- it requires pre-existing privileged ability to create the marker and therefore
  is not a first-entry mechanism;
- marker existence alone does not prove acceptance of a modified package;
- no recovered updater was executed and no custom package was accepted.

The offline rootfs repacker remains useful as a deterministic archive builder.
It does not create a signed package, select the applicable route on a unit, or
satisfy the unresolved trust boundaries above.
