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
FUMO. In FUMO, `/update/disableEncryptionUpdate` changes a startup mode byte
from its initial value `1` to `0`. In SCOMO, the recovered MASS_PRODUCT/
PENETRATION startup path explicitly ignores that marker. This reconciles the
apparently conflicting code, but it does **not** prove that a marker-bearing
plaintext package passes version, model/region, signature, digest, extraction,
write, slot, boot, or health checks.

## Artifact identities

| Artifact | SHA-256 | Build ID |
|---|---|---|
| outer `/app/bin/AppUpgrade` | `5295c6e4c41fb9c03760cf006c58b66fcd11aeb4e6e889af6e31b062549b6df0` | `167190fb42e2c0eda6e2a3f2c2130759d4484145` |
| exact embedded SCOMO ELF | `dc11f293e4e8465fe3c23a55c6c6878925104576a719f9bba44cabd24e0d9d39` | `707355ce2c47bc7a9212b94c4a5b1831cc3b4933` |
| exact embedded FUMO ELF | `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7` | `863a8730e66a1c5245a1bf458fe2554adee0351a` |
| `/app/bin/AppLauncher` | `c8d6d56bc254ad0731e81f40bd83aa9b3be6b49bcbd8efb291157a06c4a84268` | not used for this conclusion |
| `/app/bin/AppScomoDM` | `c44da21eb39987e88d71c648f625338722b8458f0ff8ecfe29e3321cf6d62046` | `496a47fae4cca227723b1f4037be918cae18473c` |
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

A separate mode affects a Navi NUA signature path, but the reviewed data flow
does not make `/update/disableEncryptionUpdate` its controller.

## AppSetup is an initiator, not the parser

Exact AppSetup review found its upgrade slot sending the AppManager transition
corresponding to app ID 300. It does not itself discover or decrypt
`.lge.upgrade.xml`, compare package versions, validate model/region, authenticate
payloads, choose SCOMO/FUMO, inspect the marker, or pass `-un`. Statements that
assign those jobs to AppSetup are public operating-model summaries, not exact
recovered-code findings.

The owner of the descriptor discovery/decryption/version/authentication pipeline
is still being reconstructed. Candidates include AppScomoDM, ApplicationManager,
`DecryptToPIPE`, and the selected embedded updater.

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
| descriptor discovery | Unresolved owner/function |
| descriptor decryption | Unresolved end-to-end; `DecryptToPIPE` exists |
| version eligibility | Publicly reported, but exact recovered compare/owner still unresolved |
| model/region eligibility | Unresolved |
| FUMO encryption mode | Proven marker-controlled startup byte and broad downstream use |
| SCOMO encryption mode | Proven marker ignored in recovered MASS_PRODUCT/PENETRATION startup path |
| package signature/authentication | Unresolved; marker is not evidence that all checks are skipped |
| payload hashes/CRC binding | Unresolved |
| archive extraction safety | Unresolved |
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
