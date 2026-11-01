# AppFUMO `decryptionFile` bounded producer provenance

## Result

For the exact embedded AppUpgrade ELF, a targeted static audit resolves the
in-binary producer boundary more tightly without turning metadata availability
into a reachability claim:

- local `AppUpgradeEngine` metadata row 64 remains public slot
  `QString decryptionFile(QString encFile, QString destPath)`;
- its generated static-metacall case remains one forwarding edge to body
  `0x100b30`, but that case is a dispatch mechanism, not evidence that anything
  invokes it;
- the only three non-generated direct calls remain `0x10281c`, `0x102de9`, and
  `0x103398`, all in row-60 `copyWhatsNewFiles()` FDE
  `[0x101110,0x104c1b)` with their previously resolved archive/system/control
  argument origins;
- all 90 old-style `QObject::connect` calls, all 105 imported named
  `QMetaObject::invokeMethod` calls, the selected constructor's 29 string
  connects and two `connectImpl` functors, four string-form timer calls, and the
  selected object's D-Bus registrations/subscriptions yield no row-64 producer;
- the constructor calls a machine-bound helper with the same object; that helper
  attaches six concrete adaptors and attempts session-bus registration. The
  exact dominating option definition has actual value `1`, matching the
  manifest and deriving Qt 5 `ExportAdaptors`. Those adaptor interfaces contain
  30 local methods—16 public slots and 14 signals—and no `decryptionFile` row.
  All 16 public rows are bound through static dispatch and implementation bodies
  to other literal names. `ExportAdaptors` does **not** export every ordinary
  public slot on the parent object;
- 12 independent `QDBusConnection::connect` subscriptions deliver named D-Bus
  signals to 12 ordinary `AppUpgradeEngine` slots, but none names row 64.

This is a bounded negative for the audited exact-ELF dispatch sites, not a proof
of global non-reachability. Dynamically synthesized or index-based meta-calls,
linked-library/cross-process behavior outside the reviewed registration
contract, and runtime objects or connections not recoverable from these bytes
remain unresolved. Registration success, exact-ELF runtime invocation, caller
policy, argument values, and attacker control remain unknown.

## Identity and retained evidence

- exact ELF size: `5,066,264` bytes;
- SHA-256:
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`;
- Build ID: `863a8730e66a1c5245a1bf458fe2554adee0351a`;
- machine-code tool: Homebrew LLVM `23.1.3`;
- compact exact-static excerpt:
  [`artifacts/update-candidates/appfumo-decryption-dispatch-provenance-exact-static.txt`](artifacts/update-candidates/appfumo-decryption-dispatch-provenance-exact-static.txt);
- compact excerpt, strict manifest, and deterministic compact JSON report:
  [`artifacts/update-candidates/appfumo-decryption-dispatch-provenance-exact-static.txt`](artifacts/update-candidates/appfumo-decryption-dispatch-provenance-exact-static.txt),
  [`artifacts/update-candidates/appfumo-decryption-dispatch-provenance-manifest.json`](artifacts/update-candidates/appfumo-decryption-dispatch-provenance-manifest.json), and
  [`artifacts/update-candidates/appfumo-decryption-dispatch-provenance.json`](artifacts/update-candidates/appfumo-decryption-dispatch-provenance.json);
- deterministic analyzer:
  [`../tools/uk_fw/appfumo_decryption_dispatch_provenance.py`](../tools/uk_fw/appfumo_decryption_dispatch_provenance.py);
- analyzer tests:
  [`../tests/test_appfumo_decryption_dispatch_provenance.py`](../tests/test_appfumo_decryption_dispatch_provenance.py).

Retained SHA-256 values:

- compact excerpt: `c712ff7592022f243c17739242e7e73345f0b91007d4acadced2a89ac2032baf`;
- strict manifest: `d20cefb6941d7c344fcd2c65d659c44a1b30e1a2df63d8694ad1354dec96b53a`;
- deterministic report: `01c26edeaa241f6577ac26f27a5d8c8b71a8ed2866954783752adc997d33814a`;
- analyzer: `dabc7366c2795ca86ff6cca93822f65ab6e2da240978e149536e2a5a75e880ba`;
- analyzer tests: `6a3d7f95ed7b13782e4013238b09a2a9deec9aad58d2e0f42b701d7a1fcff036`.

Full generated disassembly remains ignored under `work/`. The compact artifact
retains addresses, key instruction bytes, exact counts, ordered-list hashes, and
service/path byte hashes without retaining callable D-Bus coordinates.

## Exact name and signature inventory

An exact byte scan found four NUL-terminated bare `decryptionFile` occurrences:

| VA/file offset | Classification | Direct instruction use |
|---:|---|---|
| `0x20c058` | function-label/logging pool | four uses passed to a logging helper |
| `0x2293f8` | logging label in target body FDE `[0x100b30,0x10110c)` | two logging uses |
| `0x22d208` | separate function-label/logging pool | two logging uses |
| `0x446479` | selected row-64 metadata string-record payload | descriptor-mediated; no direct `.text` RIP xref |

The exact normalized/declarative signature, the short
`decryptionFile(QString,QString)` form, and old-style Qt encodings
`1decryptionFile(QString,QString)` and `2decryptionFile(QString,QString)` do not
occur. The three non-metadata bare strings flow to logging, not to
`QObject::connect`, `QMetaObject::invokeMethod`, or D-Bus registration.

This absence is corroboration for the audited literal-name paths only. It does
not exclude a name assembled at runtime or an index-based meta-call.

## Local row, inheritance, and meta-call dispatch

The selected static `QMetaObject` at `0x6ce9c0` binds:

- superdata `0x6ce280`, decoded as `AppEngineBase`;
- stringdata `0x445260`;
- revision-7 metadata `0x444760`;
- static metacall `0x16df80`.

`AppEngineBase` has 11 local methods and QObject superdata.
`AppUpgradeEngine` has 85 local methods. The exact `AppUpgradeEngine::qt_metacall`
at `0x16f080`:

1. calls `AppEngineBase::qt_metacall` at `0x16b780`;
2. returns immediately for a negative inherited result;
3. for method invocation, dispatches residual IDs `0..84` through `0x16df80`;
4. subtracts 85 before returning the residual ID to its caller.

The parent performs the analogous sequence around QObject, dispatching residual
IDs `0..10` and subtracting 11. This proves that 60 and 64 are local residual
indexes and prevents conflating row 64 with an absolute method index. The exact
QObject runtime method count is not supplied by these bytes, so the package
still does not assign an absolute index.

For row 64, the generated case copies `a[1]` and `a[2]` QStrings into locals,
passes them as `encFile` and `destPath`, calls `0x100b30` at `0x16e030`, and
conditionally assigns the QString return to `a[0]`. For row 60, the generated
case calls `0x101110`, which begins `copyWhatsNewFiles()`.

A callable generated branch is not a producer observation. A caller must still
select the method and supply the argument array.

## Direct calls and argument origins

The reconfirmed bounded whole-`.text` direct target inventory is:

| Call | Kind | Origin |
|---:|---|---|
| `0x10281c` | implementation-internal direct call | enumerated system-tree file in `copyWhatsNewFiles()` |
| `0x102de9` | implementation-internal direct call | top-level What's New archive in `copyWhatsNewFiles()` |
| `0x103398` | implementation-internal direct call | enumerated controls-tree file in `copyWhatsNewFiles()` |
| `0x16e030` | generated forwarding | row-64 `qt_static_metacall` case |

No additional direct call, jump, or address-materializing textual reference to
`0x100b30` was observed. The first three sites and their branch-selected package
base, fixed/enumerated suffixes, destination classes, and encryption-mode gate
remain documented in
[`appfumo-decryption-runtime-provenance.md`](appfumo-decryption-runtime-provenance.md).
The generated edge is kept separate because its upstream selector and argument
producer are not identified by the case itself.

## Constructor and connection audit

The process entry path allocates one `0x2d0`-byte object, directly calls
constructor `0x125800`, and then enters `QApplication::exec`. Within that
constructor:

- 29 old-style string connects use 58 static `qFlagLocation` literals;
- 28 request `Qt::AutoConnection` and one requests `Qt::DirectConnection`;
- none of the signal or method strings contains `decryptionFile`;
- per-call slot-object def-use for `QObject::connectImpl` calls `0x126787` and
  `0x12681c` binds callback fields to `0x1305c0` and `0x1309c0`, respectively,
  and binds both connection-type operands to `Qt::AutoConnection`; neither
  bounded callback body references body `0x100b30` or the target name.

Across the exact ELF, all 90 old-style `QObject::connect` sites resolve to two
static old-style signal/member literals, and none contains the target name. The
binary has 18 direct `connectImpl` calls in total. A functor could in principle
perform further dynamic work, so absence of a direct body reference is not
promoted to a global dynamic-call absence claim.

The import/call audit also found no direct `QMetaObject::connectSlotsByName`
call. Thus no auto-connect producer is identified in the exact binary. This is
not a claim about hypothetical linked-library behavior or names assembled at
runtime.

## Named `invokeMethod`, timers, and queued semantics

The exact ELF directly calls one imported named `QMetaObject::invokeMethod`
overload at 105 sites. At every site:

- the member operand resolves to a literal string;
- all 105 names are distinct;
- none is `decryptionFile`;
- connection type is `0`, `Qt::AutoConnection`.

The four string-form `QTimer::singleShot` calls all have bounded
`qFlagLocation`-to-member operand provenance for `updateFailTimeoutSlot()`. No
string timer selects row 64.

No direct `QCoreApplication::postEvent`, `sendEvent`, or explicit
`QObject::disconnect` call was observed, and `QMetaCallEvent` is not imported.
These are deliberately narrow observations: queued signal delivery and queued
`invokeMethod` are normally implemented inside Qt and may create internal
meta-call events without a target-binary import. Import/call absence therefore
cannot prove that no queued event ever exists.

No audited connect, invoke, timer, or D-Bus candidate targets row 64. It would be
misleading to assign Direct, Queued, BlockingQueued, or Auto runtime semantics
to a nonexistent row-64 candidate. The selected constructor's one explicit
Direct connection and its Auto connections target other methods. Auto may
resolve direct or queued according to thread affinity at emission time, but
that fact does not create a row-64 edge.

Likewise, no queued producer exists here for which `QString` transport copying
should be attributed. Independently, row 64's generated static metacall makes
local QString copies from `a[]`; metadata identifies `QString` as built-in
metatype 10. That local forwarding behavior does not establish prior queued
marshalling, registration by a candidate producer, or attacker-controlled
arguments.

## Exact D-Bus registration and adaptor boundary

Constructor `0x125800` has one call whose actual target is manifest helper
`0xb8b40`; register-origin tracking binds its `%rdi` to the constructor `this`.
Inside the helper, callee-saved `%rbx` preserves that object and the
registerObject `%rdx` operand resolves to the same object. The helper:

1. obtains the session bus;
2. constructs six `QDBusAbstractAdaptor` subclasses with the
   `AppUpgradeEngine` object as parent;
3. enables adaptor auto-relay;
4. formats and attempts one fixed service registration;
5. calls `registerObject` with the same `AppUpgradeEngine` pointer, a fixed
   object path, and option value `1`.

The final `%ecx` definition dominating registerObject is `movl $0x1,%ecx` at
`0xb8e41`. Actual value 1 must match the manifest; only that checked value derives
Qt 5 `QDBusConnection::ExportAdaptors`. It exports interfaces provided by
attached adaptors. It is not `ExportAllSlots`, and ordinary public
slots in the parent metadata are not exported merely because they are public.

The six constructed adaptor classes are:

| Adaptor | Signals | Public slots |
|---|---:|---:|
| `AppInterfaceAdaptor` | 13 | 4 |
| `AppbaseAdaptor` | 0 | 9 |
| `AudiotransitionAdaptor` | 0 | 1 |
| `NotificationAdaptor` | 1 | 0 |
| `RegistrationAdaptor` | 0 | 1 |
| `ScreentransitionAdaptor` | 0 | 1 |

Their 30 local metadata rows contain no `decryptionFile`. Access bits classify
all 16 slot rows as public. For each selected row, the analyzer resolves the
static-metacall row dispatch/jump-table case, implementation body, and exact
literal named `invokeMethod` call. Every bound member equals its metadata row
name, requests `AutoConnection`, and is not row 64. Therefore
the reviewed `ExportAdaptors` registration does not expose
`AppUpgradeEngine::decryptionFile` through these adaptors.

The same helper separately makes 12 `QDBusConnection::connect` subscriptions
with the `AppUpgradeEngine` as receiver. Their old-style slot literals identify
12 notification/update callbacks, none row 64. This is an incoming D-Bus signal
subscription mechanism, not method export, and it does not alter the adaptor
conclusion.

The service and object-path bytes are fixed and resolved, but the retained
artifact records only their lengths and SHA-256 hashes rather than callable
coordinates. Static calls do not prove that service/object registration
succeeded at runtime, that a policy permits any caller, or that this exact ELF
is installed and running.

## Runtime observation and attacker-control boundary

The separate hash-bound public field log contains seven normalized
`decryptionFile` records in `copyWhatsNewFiles` temporal context. It does not
contain the installed binary hash or Build ID and does not distinguish one of
the three direct calls from generated/meta-call or another implementation.
Nothing in the log upgrades the selected registration call into observed
registration or identifies a dynamic producer for this exact object.

The static direct producers constrain pathname families, but neither this audit
nor the log proves attacker control of the package base, enumerated filenames,
destination, invocation timing, D-Bus caller, object thread, or argument array.
Authentication acceptance, command success, effective uid/capabilities/SMACK
domain, privilege amplification, root, and persistence remain separate unknowns.

## Status ledger

| Boundary | Status |
|---|---|
| selected row-64 name/signature/types/flags | resolved |
| generated row-64 argument/return forwarding | resolved |
| row-60 versus row-64 dispatch | resolved |
| three direct call sites and origins | resolved |
| selected constructor and registration object identity | resolved statically |
| option `1 = ExportAdaptors` and six adaptor metadata sets | resolved statically |
| row 64 exported by those adaptors | rejected for the reviewed registration |
| row 64 selected by audited connects/invokes/timers/D-Bus subscriptions | no candidate observed |
| exact registration success and runtime bus policy | unknown |
| dynamically synthesized/index-based/cross-library producer completeness | unknown |
| exact-ELF runtime invocation | unknown |
| attacker control | unknown |

## Method, validation, and safety record

Independent review and first re-review returned **CHANGES_REQUIRED**: the first
revision lacked a durable deterministic analyzer/test path and used the wrong
validation environment; the next revision left four provenance bindings
insufficiently fail-closed. After strict machine-bound remediation, corrected
independent re-review returned **ACCEPT**.

The audit used exact byte scans, targeted relocation and metadata decoding,
`.eh_frame` context already retained for the direct producers, and exact
Homebrew LLVM `23.1.3` executable identities and machine instructions. Bounded
host parsing and pytest use the project-approved
`<platformio-env>/bin/python3`. The focused command is:

```text
<platformio-env>/bin/python3 -m pytest -q -p no:cacheprovider tests/test_qt5_metaobject_rev7.py tests/test_appfumo_decryption_dispatch_provenance.py
```

The old focused test independently reports `19 passed, 25 subtests passed`.
The final combined focused command reports `37 passed, 31 subtests passed`.
`py_compile`, deterministic-encoding/report regeneration, privacy exclusion,
and exact identity/count/schema failure tests also pass. The final tests-scoped
full suite passed `736 tests, 351451 subtests`. Full generated output was kept
under ignored `work/`.

No recovered executable or helper ran. No D-Bus request, target, device, radio,
network path, payload, malformed input, package, archive, staging action,
signature bypass, partition/slot/boot action, privilege action, root action, or
persistence mechanism was created or exercised.
