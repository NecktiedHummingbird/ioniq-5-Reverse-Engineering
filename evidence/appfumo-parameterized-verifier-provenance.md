# AppFUMO parameterized verifier targets resolve to controller resources, not updater pathnames

## Result

The two previously unresolved direct calls to the exact embedded AppUpgrade
file-signature verifier are one nested resource-processing route:

```text
sole direct call 0xf359e
    -> resource route 0x9cbc0
       -> verify encrypted resource pathname at 0x9d1d2
       -> on exact-zero verifier result
          -> call navigation transform at 0x9d4fe
             -> verify a QString copy of the same source pathname at 0x140092
             -> on exact-zero verifier result
                -> pathname-based decrypt-helper pipeline to a derived destination
```

Within this bounded direct/static route, the source is an absolute pathname for
an enumerated `.enc` member under one of four fixed controller-resource trees:
`mkbdupdate`, `ampupdate`, `adpupdate`, or `vessupdate`. Base-name tests select
news-pattern, software-pattern, and unmatched news-fallback destination logic.
The resulting destination roles are JSON resources and binary resources.

The verified pathname is therefore **not the running AppUpgrade pathname, a
staged AppUpgrade pathname, the update descriptor, or a general firmware
archive/member pathname** in this route. It is a controller-resource encrypted
member pathname. This classifies path roles, not file contents: static code does
not prove that a pathname was not replaced, that bytes at the path have a
particular object type, or that the same object was reopened.

Classification: **both parameterized direct callsites resolved for bounded
immediate/direct-static provenance; authenticated-byte binding remains
unknown because verification and transformation reopen a pathname**.

No direct instruction calls FDE entry `0xf28e0`; virtual, indirect,
synthesized/indexed Qt, cross-library, external-service, and cross-process
producers of that caller therefore remain unknown. Runtime invocation,
pathname/object substitution, signature acceptance, transformation success,
final consumption, partition writing, boot acceptance, root, and persistence
are not established.

## Exact identity and retained package

Exact embedded ELF:

- size: `5,066,264` bytes;
- SHA-256:
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`;
- GNU Build ID: `863a8730e66a1c5245a1bf458fe2554adee0351a`;
- x86-64 image-base-zero ELF virtual addresses are used throughout.

Homebrew LLVM identities:

- first version line: `Homebrew LLVM version 23.1.3`;
- `llvm-objdump` size `813,808`, SHA-256
  `7b04d723638c0793efbd31b99b2389f36ceb8c803bdc1008e43ea7525958376f`;
- `llvm-readelf`/`llvm-readobj` size `1,805,104`, SHA-256
  `80a1f8ffc44c5a1e4dbeaa5c409cd98a01cb2fa73e1ccc2eeb22a3b7ee2e1cb0`.

Retained artifacts:

- `evidence/artifacts/update-candidates/appfumo-parameterized-verifier-provenance-exact-static.asm`:
  selected exact Homebrew LLVM disassembly without raw instruction bytes,
  SHA-256 `6c0abdf94c0cec730d890cdacb0d87b44bc49410a7815007e0159a28ff22e187`;
- `evidence/artifacts/update-candidates/appfumo-parameterized-verifier-provenance-manifest.json`:
  strict machine evidence and identity manifest;
- `evidence/artifacts/update-candidates/appfumo-parameterized-verifier-provenance.json`:
  deterministic normalized report;
- `tools/uk_fw/appfumo_parameterized_verifier_provenance.py`:
  execution-free fail-closed analyzer;
- `tests/test_appfumo_parameterized_verifier_provenance.py`:
  parser, schema, identity, provenance, determinism, scope, and privacy tests.

The manifest binds all `470,739` decoded instructions by count and canonical
SHA-256
`693dce0d89faabeea30512fe0a696a733e9bdd64fd7be7379dba98a44d2dc0c8`.
It also binds all `3,789` decoded FDE ranges by count and canonical SHA-256
`2c71813a3f098f8f949c6acee1080c0147df182e589f8b8b576798ce4807eb07`.
The analyzer rejects unknown/missing schema keys, wrong types, Boolean values in
integer fields, non-regular/oversized/changing inputs, tool/ELF/Build-ID drift,
malformed/duplicate/truncated instruction evidence, instruction count/hash
drift, FDE count/hash/range drift, direct-call drift, machine-anchor drift,
literal hash drift, ambiguous ELF mappings, and overwritten register
provenance.

## Exact `.eh_frame` authority

`llvm-readelf --unwind` reports these exact FDEs:

| Role | Exact FDE |
|---|---|
| signature verifier | `[0x45820,0x45d75)` |
| encrypted-resource route containing `0x9d1d2` | `[0x9cbc0,0x9e260)` |
| route's sole direct caller | `[0xf28e0,0xf3ddf)` |
| nested navigation transform containing `0x140092` | `[0x140030,0x1405da)` |
| shared command helper | `[0x1397c0,0x1398fb)` |

A whole decoded-instruction direct-call scan finds exactly six direct calls to
verifier entry `0x45820`:

```text
0x7be3a, 0x80095, 0x802f0, 0x9d1d2, 0x100bb0, 0x140092
```

For the route under review, it finds exactly:

```text
0xf359e -> 0x9cbc0
0x9d4fe -> 0x140030
```

No decoded direct call targets entry `0xf28e0`. This is a bounded direct-call
negative, not global absence of an invoker.

## Immediate caller and fixed producer classes

Caller FDE `[0xf28e0,0xf3ddf)` enumerates file information at `0xf2b62`, obtains
`QFileInfo::baseName()` at `0xf2e04`, `filePath()` at `0xf2e11`, and
`absoluteFilePath()` at `0xf2e1e`. It compares `completeSuffix()` at `0xf2f6e`
with fixed `zip` text and derives the first ten characters at `0xf2fd2` before
fixed selector comparisons. It copies the selected base-name QString at
`0xf32bc`, calls the four-class selector logic at `0xf32e4`, and eventually
passes that QString in `%rsi` at `0xf359b` to direct call `0xf359e`.

At route entry `0x9cbc0`, `0x9cbca` preserves that selector in `%rbx`.
`0x9cc0b` passes it into helper call `0x9cc29`. Its four outcomes select these
fixed source and destination classes:

| Class | Fixed source tree role | Fixed destination tree role |
|---|---|---|
| `mkbd-resource` | `/update/extInfoUpdate/mkbdupdate` | `/update/exfirmware_mkbdupdate_file` |
| `amp-resource` | `/update/extInfoUpdate/ampupdate` | `/update/exfirmware_ampupdate_file` |
| `adp-resource` | `/update/extInfoUpdate/adpupdate` | `/update/exfirmware_adpupdate_file` |
| `vess-resource` | `/update/extInfoUpdate/vessupdate` | `/update/exfirmware_vessupdate_file` |

The first class is loaded at `0x9cc3b`/`0x9cc51`; corresponding fixed branches
are retained at `0x9ddbf..0x9dec0`. Literal values and addresses are independently
length/hash-bound in the strict manifest.

The route constructs a `QDir`, calls `entryInfoList()` at `0x9ce06`, constructs
`QFileInfo` objects, obtains each suffix at `0x9cebf`, and compares it to fixed
`enc` text at `0x9ceef`. Only the equal branch reaches
`QFileInfo::absoluteFilePath()` at `0x9cf70`.

The subsequent base-name tests recognize fixed `l_whatsnews` and `l_updatesw`
text. The news-pattern branch derives `whatsnews_<token>.json`; the software-
pattern branch derives `<base-name>.bin`; the unmatched branch derives fallback
`whatsnews.json`. Thus the `.enc` suffix and fixed source tree classify the
verifier operand, while these tests select destination naming. They do not prove
that generated output exists or is valid.

This direct/static provenance excludes these pathname roles at `0x9d1d2`:

- current/running updater executable;
- staged updater executable;
- `/.lge.upgrade.xml` descriptor;
- top-level or HU firmware archive;
- general enumerated HU firmware member.

It positively classifies the operand as an enumerated encrypted
controller-resource member. Dynamic placement, symlink/hardlink replacement,
rename races, mount changes, and byte content remain outside static proof.

## `0x9d1d2`: exact operand ownership and dominance

`0x9cf70` writes the selected member's absolute pathname into local QString
storage at stack offset `0xd0`. All news/software destination-construction paths
converge at `0x9d19e` (`0x9d8fe` and `0x9db1a` are retained convergence jumps).
At the convergence:

1. `0x9d19e` loads the QString data pointer from `0xd0(%rsp)`;
2. `0x9d1a8` copies it to `0x240(%rsp)` and preserves reference ownership;
3. `%rbx`, established as `&0x240(%rsp)` at `0x9ce9e`, has no intervening
   overwrite;
4. `0x9d1cf` moves `%rbx` to `%rsi`;
5. `0x9d1d2` directly calls verifier `0x45820`.

The return is stored in `%r12d`; `0x9d22b..0x9d22e` tests it and branches away
on nonzero. The nested transform is reachable only from the exact-zero branch.
This proves static control-flow dominance, not that verification returns zero at
runtime.

## `0x140092`: same source pathname, derived destination

On the exact-zero branch, the route preserves two distinct QString roles:

- `0x9d49d` copies the already derived destination to local `0x240`, whose
  address remains in `%rbx`;
- `0x9d4b4..0x9d4be` copies source local `0xd0` to local `0x230`, and
  `0x9d4d5` forms its address in `%rbp`.

At `0x9d4ea`, `%rcx=%rbx` supplies the destination argument. At `0x9d4fb`,
`%rdx=%rbp` supplies the source argument. Direct call `0x9d4fe` enters FDE
`[0x140030,0x1405da)`.

At entry:

1. `0x140032` moves source `%rdx` to `%rsi`;
2. helper calls `0x14006f` and `0x14007a` make local QString copies at `%rbp`
   and `%rbx`;
3. `0x14008f` passes `%rbx` as verifier operand;
4. `0x140092` calls `0x45820`;
5. `0x1400a2..0x1400a5` branches away on nonzero verifier status.

Thus `0x140092` verifies a QString copy of the same source-pathname value already
verified at `0x9d1d2`. It is not a separate upstream producer family.

## What binds—and what does not—after verification

The transform receives source and destination as pathnames. On the verifier's
exact-zero branch:

- `0x14005f` retains incoming destination `%rcx`;
- `0x14016c` substitutes that destination into a fixed output command fragment;
- `0x140201` substitutes the original source copy at `%rbp` into a fixed decrypt
  command fragment;
- the fixed helper identity is inserted at `0x140196`;
- `0x1402df` calls shared command helper `0x1397c0`;
- the helper calls `popen` at `0x139867`, drains output, calls `pclose` at
  `0x1398b0`, and returns no command result;
- `0x1402e4..0x1402f4` removes the transient key file;
- `0x140301` calls `sync`;
- `0x140306..0x140311` returns the caller-provided destination QString.

The caller then compares the returned QString to empty at `0x9d543..0x9d57c`.
It does not thereby validate helper exit status, destination existence, size,
hash, or signature.

The defensible binding is therefore **pathname-value continuity**:

```text
absolute source pathname
  -> verifier at 0x9d1d2
  -> QString copy
  -> verifier at 0x140092
  -> source field of the decrypt command
```

It is not a retained-file-object binding. The verifier and helper independently
reopen the pathname; no retained descriptor, inode/device tuple, immutable
snapshot, or post-transform digest/signature check was found in this bounded
route. Consequently:

- whether verifier-read bytes equal helper-read bytes: **unknown**;
- whether returned destination names a successfully produced file: **unknown**;
- whether transformed bytes reach a final consumed image/resource: **unknown**;
- transformation success, partition write, boot acceptance, root, and
  persistence: **unknown**.

## Reproduction

The analyzer never executes recovered target code:

```sh
<python3> tools/uk_fw/appfumo_parameterized_verifier_provenance.py \
  --elf work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf \
  --llvm-objdump "$(brew --prefix llvm)/bin/llvm-objdump" \
  --llvm-readelf "$(brew --prefix llvm)/bin/llvm-readelf" \
  --manifest evidence/artifacts/update-candidates/appfumo-parameterized-verifier-provenance-manifest.json
```

It emits normalized JSON only: no proprietary binary bytes, recovered command
text, callable coordinates, or supplied host/operator path.

## Safety and claim boundary

No recovered updater, helper, or target executable was executed. No payload,
package, image, signature-bypass input, operational update input, filesystem
mount, flash operation, partition write, or persistence mechanism was created
or attempted. The work is exact-static analysis only.
