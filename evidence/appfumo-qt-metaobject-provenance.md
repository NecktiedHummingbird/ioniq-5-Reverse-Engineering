# AppUpgradeEngine local meta-method 64: declaration resolved, producer provenance unresolved

## Result

For the authorized exact embedded FUMO ELF, Qt 5 revision-7 metadata and the
relocation-bound generated dispatcher resolve **local metadata row index 64** as:

```text
QString AppUpgradeEngine::decryptionFile(QString encFile, QString destPath)
```

The metadata binding and machine-code forwarding are separately established:

- **metadata binding — resolved:** method row 64 names `decryptionFile`, has two
  `QString` arguments named `encFile` and `destPath`, returns `QString`, and has
  flags `0x0a`, a **public slot**;
- **forwarding — resolved from bounded instruction evidence, not by metadata
  decoding alone:** jump-table entry 64 reaches `0x16dfc6`; the generated case
  copies `a[1]` to the `encFile` local passed in `%rdx`, copies `a[2]` to the
  `destPath` local passed in `%rcx`, calls `0x100b30`, and writes the returned
  `QString` to `a[0]` when non-null;
- **complete producer provenance — unresolved:** a bounded direct-reference scan
  does not enumerate dynamic Qt meta-invocation, indirect calls, or external
  paths and therefore cannot prove complete producer absence.

Index 64 is the **local row index in the selected `AppUpgradeEngine`
meta-object**, so the method is declared in that selected meta-object. It is not
asserted to be the absolute `QMetaObject` method index: that requires
`QMetaObject::methodOffset()` and the inheritance context, neither of which is
an input to this package. It is not signal number 64. The metadata header's
signal count is **7**; the selected row's slot flags independently classify it
as a slot rather than a signal.

This result narrows the parameterized verifier call at `0x100bb0`. It does not
establish runtime invocation, external or D-Bus reachability, attacker control,
update acceptance, root, or persistence.

## Exact identity and retained package

- ignored read-only ELF:
  `work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf`
- size: `5,066,264` bytes
- SHA-256:
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`
- GNU Build ID: `863a8730e66a1c5245a1bf458fe2554adee0351a`
- format: ELF64, little-endian, x86-64, ET_DYN
- exact bounded excerpts:
  [`artifacts/update-candidates/appfumo-qt-metaobject-exact-static.txt`](artifacts/update-candidates/appfumo-qt-metaobject-exact-static.txt)
- exact bounded-excerpt SHA-256:
  `31a90d0d633d22823fe1e4e61aa1c7df159c1a1acef379fe4e7aa38c7195c1ee`
- strict forwarding manifest:
  [`artifacts/update-candidates/appfumo-qt-metaobject-forwarding-manifest.json`](artifacts/update-candidates/appfumo-qt-metaobject-forwarding-manifest.json)
- forwarding-manifest SHA-256:
  `ecf48b2ec0d5f5c6014e2ef7c4efbfdd25899a3b79da2f4cf808dda062bf16bb`
- deterministic exact report:
  [`artifacts/update-candidates/appfumo-qt-metaobject-index-64.json`](artifacts/update-candidates/appfumo-qt-metaobject-index-64.json)
- exact report SHA-256:
  `330799c5215a0d3fda7c8870820240cb023c9b3a6c9673100778a038fe1d14a3`

The selected metadata, strings, jump table, and dispatcher are in a file-backed
segment where VAs equal file offsets. The static `QMetaObject` is in the second
load segment; its relocation locations therefore retain separate VAs and file
offsets in the exact-static artifact.

## Static-object and metadata binding

Three `R_X86_64_RELATIVE` fields in the same static object bind:

| Static-object field VA | Addend / target | Role |
|---|---:|---|
| `0x6ce9c8` | `0x445260` | Qt stringdata |
| `0x6ce9d0` | `0x444760` | revision-7 metadata |
| `0x6ce9d8` | `0x16df80` | generated static metacall |

The 14-word metadata header at `0x444760` is:

```text
(7, 0, 0, 0, 85, 14, 0, 0, 0, 0, 0, 0, 0, 7)
```

Thus revision is 7, local method count is 85, the method table begins at word
offset 14, and signal count is 7. Five-word local row 64 at `0x444c98` is:

```text
(98, 2, 631, 2, 10)
```

Under Qt 5's revision-7 method layout those fields are method-name string index,
argument count, parameter-record word offset, tag string index, and method
flags. The parameter record at metadata word offset 631 (`0x44513c`) is:

```text
(10, 10, 10, 99, 100)
```

The first word is return type, the next two are argument types, and the final
two are argument-name string indices. Built-in metatype ID 10 is `QString`.

Qt 5 x86-64 `QByteArrayData` descriptors are 24 bytes. Their final field is a
signed descriptor-relative offset. Records 98, 99, and 100 resolve to:

| Record | Declared size | Data VA | UTF-8 text |
|---:|---:|---:|---|
| 98 | 14 | `0x446479` | `decryptionFile` |
| 99 | 7 | `0x446488` | `encFile` |
| 100 | 8 | `0x446490` | `destPath` |

Flags `0x0a` combine public access (`0x02`) and slot type (`0x08`). The metadata
therefore resolves the declaration without using a decompiler or executing the
target.

## Generated dispatcher forwarding

The static metacall checks local IDs through 84 and dispatches through a signed
32-bit table rooted at `0x444600`. Entry 64 is at `0x444700`:

```text
raw uint32             0xffd299c6
signed displacement    -2975290
base + displacement    0x16dfc6
```

At the selected case:

1. `0x16dfc6` loads `a[2]` from argument-array offset `+0x10` and copies its
   `QString` into a local later placed in `%rcx` (`destPath`).
2. `0x16dff1` loads `a[1]` from offset `+0x08` and copies its `QString` into a
   local later placed in `%rdx` (`encFile`).
3. `0x16e024..0x16e030` passes the object in `%rsi`, the hidden `QString` return
   storage in `%rdi`, `encFile` in `%rdx`, and `destPath` in `%rcx`, then calls
   `0x100b30`.
4. `0x16e071..0x16e07c` tests `a[0]` and assigns the local `QString` return value
   there when non-null.

The target function's call at `0x100bb0` reaches verifier wrapper `0x45820`.
This machine-code evidence supplies forwarding semantics. The decoder does not
pretend that metadata itself proves these instructions: absent a strict evidence
manifest its output leaves forwarding `unresolved`; with the retained manifest
it reports the externally reviewed bounded forwarding facts and binds their
jump-table word back to the ELF bytes.

## Bounded direct-reference observation and producer boundary

A whole-`.text` textual scan of exact Homebrew LLVM disassembly observed direct
calls to `0x100b30` at:

```text
0x10281c  0x102de9  0x103398  0x16e030
```

No other direct x86-64 call/LEA textual reference to `0x100b30` was observed in
that bounded scan. This is not complete producer provenance. In particular, the
negative observation does not exclude:

- string-based or index-based `QMetaObject::invokeMethod` and related dynamic
  Qt meta-invocation;
- indirect, virtual, callback, signal/slot, queued, or reflective paths;
- invocations originating in another executable, library, process, or service;
- runtime argument producers and controls not recoverable from the selected
  direct-reference inventory;
- object registration, adaptor behavior, policy, and runtime reachability.

Accordingly producer provenance remains `unresolved`; runtime invocation,
external reachability, and attacker control remain unknown.

## D-Bus claim boundary

A `QDBusConnection::registerObject` option value of 1 observed elsewhere in the
program means `ExportAdaptors` under Qt 5. That general fact does not identify
this `AppUpgradeEngine` object, an adaptor exposing this slot, an object path, a
service registration, or a permitted caller. This package therefore makes no
claim that local method 64 is D-Bus reachable, and does not claim D-Bus absence.
Complete object/adaptor and runtime registration proof would be required in
either direction.

## Defensive decoder

[`tools/uk_fw/qt5_metaobject_rev7.py`](../tools/uk_fw/qt5_metaobject_rev7.py)
requires four explicit selections: ELF path, metadata VA, stringdata VA, and
local method index. It performs no broad scan and never executes target code.
It fails closed unless the input is ELF64 little-endian x86-64 with an
unambiguous file-backed `PT_LOAD` mapping and a bounded revision-7 structure.
It validates:

- ELF and program-header ABI, range arithmetic, and file-backed mappings;
- the 14-word header, every five-word method row, counts, local index, and
  checked metadata-word intervals for the header and complete method/auxiliary
  tables;
- every method parameter-record interval, rejecting truncation and overlap with
  the header, method/auxiliary tables, or another parameter record, plus
  supported built-in or string-referenced type words and selected slot flags;
- 24-byte Qt 5 x86-64 `QByteArrayData`, signed relative offsets, string bounds,
  terminators, and UTF-8;
- exact keys and scalar types in the optional bounded evidence manifest,
  artifact identity, method index, jump-table location, raw word, signed target,
  and conservative unresolved producer status;
- an explicitly supplied regular evidence-excerpt file: its size is bounded and
  its current bytes must hash to the manifest digest before forwarding can
  become `resolved`.

Stable UTF-8/LF JSON is written through `sys.stdout.buffer`; no timestamp or host
path enters the report. The default result is metadata `resolved`, forwarding
`unresolved`, and producer provenance `unresolved`. Supplying both the retained
manifest and retained evidence excerpt changes only forwarding to `resolved`;
a missing or mismatched excerpt fails closed, and producer provenance remains
`unresolved`.

Reproduction uses the environment's Python rather than an operator-specific
tracked path:

```sh
<platformio-env>/bin/python3 tools/uk_fw/qt5_metaobject_rev7.py \
  --elf work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf \
  --metadata-va 0x444760 --stringdata-va 0x445260 \
  --local-method-index 64 \
  --evidence-manifest evidence/artifacts/update-candidates/appfumo-qt-metaobject-forwarding-manifest.json \
  --evidence-excerpt evidence/artifacts/update-candidates/appfumo-qt-metaobject-exact-static.txt
```

## Authoritative Qt 5 references

The interpretation uses Qt's public source and documentation, not reverse-
engineered field names alone. In particular, the local row index is not treated
as an absolute method index without `methodOffset()` and inheritance context:

- Qt 5.6.3 `QMetaObjectPrivate` and method-data layout, including revision 7,
  header fields, method-row width, parameter data, flags, and signal count:
  <https://code.qt.io/cgit/qt/qtbase.git/tree/src/corelib/kernel/qmetaobject_p.h?h=5.6.3>
- Qt 5.6.3 public meta-object enums and `QMetaObject::Call` definitions:
  <https://code.qt.io/cgit/qt/qtbase.git/tree/src/corelib/kernel/qobjectdefs.h?h=5.6.3>
- Qt 5.6.3 moc generator, including generated metadata/string tables and
  `qt_static_metacall` argument-array conventions:
  <https://code.qt.io/cgit/qt/qtbase.git/tree/src/tools/moc/generator.cpp?h=5.6.3>
- Qt 5.6.3 `QArrayData`/`QByteArrayData` public-source ABI fields:
  <https://code.qt.io/cgit/qt/qtbase.git/tree/src/corelib/tools/qarraydata.h?h=5.6.3>
- Qt 5.6.3 `QMetaType::Type`, including `QString = 10`:
  <https://code.qt.io/cgit/qt/qtbase.git/tree/src/corelib/kernel/qmetatype.h?h=5.6.3>
- Qt 5 `QMetaObject` documentation (`methodOffset()` distinguishes a class's
  own methods from inherited absolute indexes):
  <https://doc.qt.io/qt-5/qmetaobject.html>
- Qt 5 `QMetaMethod` access and method-type documentation:
  <https://doc.qt.io/qt-5/qmetamethod.html>
- Qt 5 `QDBusConnection::RegisterOption`, including `ExportAdaptors`:
  <https://doc.qt.io/qt-5/qdbusconnection.html#RegisterOption-enum>

These sources define Qt semantics; they do not establish this proprietary
object's runtime construction, registration, invocation, or exposure.

## Conservative conclusion and remaining unknowns

The former unnamed QString meta-call argument at `0x100bb0` is now defensibly
named and typed: local `AppUpgradeEngine` metadata row 64 forwards
`decryptionFile(QString encFile, QString destPath)` to `0x100b30`, whose verifier
call is at `0x100bb0`.

The package does **not** resolve complete producer provenance. It also leaves
unknown:

- actual runtime invocation and argument values;
- external, IPC, D-Bus, UI, update-state, or service reachability;
- attacker influence over `encFile`, `destPath`, object construction, or call
  timing;
- owner-device installed identity and runtime policy;
- outer-executable reauthentication as a whole, including indirect/external,
  loader, and boot-stage checks;
- final payload binding, update acceptance, partition writes, slot/boot
  acceptance, root, and persistence.

The existing V-032 Boolean model therefore remains fail-closed and unchanged:
complete direct signature-target classification is still false, so direct
outer-executable reauthentication and identity-gap closure remain `null`.

## Validation

- bytecode compilation passed;
- focused Qt/FUMO tests: `29 passed, 8228 subtests passed`;
- complete suite: `664 passed, 351250 subtests passed`;
- public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`;
- privacy-only public harness: **PASS**, no blocking finding;
- three exact report generations under `ascii`, `latin-1`, and `utf-16`
  `PYTHONIOENCODING` settings were byte-identical to the retained report;
- deterministic exact report SHA-256:
  `330799c5215a0d3fda7c8870820240cb023c9b3a6c9673100778a038fe1d14a3`;
- `git diff --check` passed.

## Safety record

Only read-only host hashing, bounded byte decoding, relocation inspection,
disassembly, and tests were performed. No recovered target, updater, verifier,
helper, method, device, radio, network path, package, archive, partition, slot,
or boot state was executed or exercised. No malformed target input, payload,
bypass, launch request, race schedule, root action, or persistence material was
created. Synthetic tests construct bounded byte arrays only; they are not target
inputs and are never executed.
