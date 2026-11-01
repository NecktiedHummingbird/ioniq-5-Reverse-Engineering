# AppFUMO `decryptionFile` exact shell-command boundary

## Result

The hash-identified embedded AppUpgrade ELF contains an exact, direct shell
boundary in the FDE bound to
`AppUpgradeEngine::decryptionFile(QString encFile, QString destPath)`:

```text
QString substitutions with pathname-derived fields
    -> direct call 0x100e0c to shared helper 0x1397c0
    -> fixed stderr-redirection append
    -> QString-to-byte conversion
    -> popen(command, read-mode) at 0x139867
```

The `popen` interface invokes a shell for its command string. In the exact
QString chain, `encFile` and `destPath` are inserted into command fields without
an observed quoting, escaping, validation, or shell-character filtering step.
This establishes an **exact unquoted shell-sink structure** for this ELF.

It does not establish who can influence either pathname, whether shell-sensitive
characters survive filesystem/archive/parser layers, whether the method is
reachable on an installed unit, whether an update is authenticated or accepted,
the process uid/capabilities/SMACK domain, successful command substitution,
privilege or domain amplification, root impact, or persistence. Those are
independent runtime prerequisites and remain unknown.

## Exact identity and retained evidence

- ELF:
  `work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf`
- size: `5,066,264` bytes
- SHA-256:
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`
- GNU Build ID: `863a8730e66a1c5245a1bf458fe2554adee0351a`
- type: ELF64 little-endian x86-64 PIE/shared object
- instruction/unwind tools: Homebrew LLVM `23.1.3`
- retained bounded evidence:
  [`artifacts/update-candidates/appfumo-shell-boundary-exact-static.asm`](artifacts/update-candidates/appfumo-shell-boundary-exact-static.asm)
- retained evidence SHA-256:
  `a6bbe8e74630e7a64001a8bad2b5f67846f465473612a14e8bccf3aad47c5510`

Addresses are image-base-zero link-time virtual addresses. `.eh_frame` gives the
exact `decryptionFile` range `[0x100b30,0x10110c)`. The function-name and
argument binding comes from the previously retained Qt metadata/dispatcher
analysis, not from unwind data alone.

## Exact `decryptionFile` inputs and early failures

At entry, the x86-64 QString-return convention places hidden return storage in
`%rdi`, `encFile` in `%rdx`, and `destPath` in `%rcx`. The prologue retains
`destPath` in `%r13` and copies the `encFile` QString data reference to a local.

The function has two pre-sink failure routes:

1. `0x100bb0` calls the previously mapped file verifier. A nonzero result branches
   at `0x100bc3` and returns the fixed QString `fail` from `0x211c17`.
2. After transient key-path construction, `0x100c4a` calls the key-file operation.
   A nonzero result branches at `0x100c5d`, logs, and returns the same fixed
   failure QString.

Neither failure route reaches `0x100e0c`.

## Transient key-path provenance

`decryptionFile` constructs fixed `/tmp` from `0x209da4` and passes it at
`0x100bfd` to helper FDE `[0x44010,0x4454c)`. That helper:

1. calls `QUuid::createUuid()` at `0x4403f`;
2. calls `QUuid::toString()` at `0x4405f`;
3. applies the fixed `%1/%2` template at `0x209cd4` to the supplied temporary
   directory and UUID text; and
4. performs three case-sensitive `QString::replace` calls that remove `{`, `}`
   and `-`.

The resulting transient key pathname is therefore a fixed temporary-directory
component plus UUID-derived text. It becomes the second substitution in the
command. This is provenance, not a claim that an external actor controls that
path.

## Exact command construction in `[0x100b30,0x10110c)`

The exact function uses two split literals, not either similar full template
elsewhere in the ELF:

- `0x212297`: `%1 -d %2 %3 0`
- `0x2122a5`: ` | dd of=%1 bs=512`

The substitution chain is:

| Instruction | Template field | Provenance |
|---|---:|---|
| `0x100cff` | first-template `%1` | fixed helper pathname from `0x20b4d8` |
| `0x100d2a` | first-template `%2` | UUID-derived transient key pathname from `[0x44010,0x4454c)` |
| `0x100d4f` | first-template `%3` | incoming `encFile` local |
| `0x100cb3` | second-template `%1` | incoming `destPath`, retained in `%r13` |
| `0x100d68` | concatenation | first substituted result followed by second substituted result |

No call in this chain quotes, escapes, validates, canonicalizes, or filters the
pathname strings for shell syntax. The QString `arg` calls perform textual
placeholder substitution. Thus the exact target-specific fact is that the two
pathname arguments occupy unquoted command fields; runtime character provenance
and survival are separate questions.

The fixed helper literal at `0x20b4d8` is
`/app/share/AppUpgrade/DecryptToPIPE`.

## Correction: `0x20b500` and `0x20b530` belong to another FDE

The following full four-placeholder literals exist in the exact ELF:

- `0x20b500`: `%1 -d %2 %3 0 | pv -q -L 8m | dd of=%4 bs=512`
- `0x20b530`: `%1 -d %2 %3 0 | dd of=%4 bs=512`

They are **not referenced by the `decryptionFile` FDE**. Both are referenced in
the separate FDE `[0x60ac0,0x6178f)`:

- `0x60ecc` tests object byte `+0x22`;
- zero falls through to the throughput-limited template reference at `0x60f08`;
- nonzero branches to the shorter template reference at `0x61351`;
- both routes substitute `%1` = fixed helper, `%2` = a transient key QString,
  `%3` = source QString, and `%4` = destination QString;
- both converge on a shared-helper call at `0x6103b`.

That separate function then checks destination existence and compares file sizes.
Those checks must not be imported into `decryptionFile`. This distinction corrects
the tempting but false inference that nearby identical helper/path concepts imply
one source-level function or one command-construction path.

## Direct call and exact helper behavior

At `0x100e0c`, `decryptionFile` directly calls `0x1397c0`. `.eh_frame` assigns
that helper its own FDE `[0x1397c0,0x1398fb)`. A whole-`.text` direct-call scan
found 26 callers, including `0x100e0c`, which is consistent with a shared utility
rather than an extension of `decryptionFile`.

The helper's bounded behavior is:

1. `0x1397e0..0x1397e8` tests the input QString length; empty input returns.
2. `0x139810` loads fixed bytes ` 2>&1` from `0x20b81c` and the helper appends
   them with `QString::append` at `0x13983e`.
3. Calls at `0x13984e` and `0x139858` produce byte storage and its data pointer.
4. `0x13985d` loads mode pointer `0x211c8b`, whose exact null-terminated bytes
   are `r\0`.
5. `0x139867` calls `popen@plt` with the byte command pointer and read mode.
6. A null stream returns immediately. Otherwise `0x139898..0x1398ab` repeatedly
   calls `fgets` with a `0x200`-byte stack buffer until it returns null. The read
   data is overwritten on the next iteration and is not appended or returned.
7. `0x1398b0` calls `pclose`; its integer result in `%eax` is not tested, stored,
   or returned. The helper returns `void` on all ordinary paths.

The target machine code proves the `popen` call and exact inputs. Shell invocation
is the documented libc/POSIX contract of `popen`, not an inference that the target
contains an inlined shell parser.

## Neighboring-helper / alternate-entry distinction

The next aligned code at `0x139900` is not an alternate entry into the helper
above. It has a separate unwind FDE `[0x139900,0x139b46)`, a separate prologue,
a separate `popen` call at `0x1399cc`, and a different ABI with hidden QString
return storage. Its read loop calls `QString::fromAscii_helper` and
`QString::append`, accumulating command output into the returned QString.

Confusing these adjacent functions would produce two wrong claims about the
`0x100e0c` path: that output is accumulated and that a QString result propagates
back to `decryptionFile`. Neither is true for the exact direct target
`0x1397c0`.

## Return and failure propagation after the sink

After `0x1397c0` returns, `decryptionFile`:

1. constructs a `QFile` for the transient key pathname;
2. calls `QFile::remove()`;
3. calls `sync()`; and
4. transfers the local `destPath` QString into its hidden return object.

It does not inspect helper success, `popen` success, `fgets` state, `pclose` exit
status, key-file removal success, destination existence, or destination size.
The function returns a QString, not a Boolean. Its exact ordinary outcomes are:

- fixed failure QString when either pre-sink verifier/key operation reports
  nonzero; or
- `destPath` after the sink path, independently of process exit status and
  without an in-FDE destination check.

This is return-propagation analysis, not evidence that the external command
succeeded or produced destination bytes.

## Preserved producer-family boundary

The prior exact producer result remains unchanged:

- `0x102de9`: branch-selected top-level package archive family;
- `0x10281c`: enumerated system-tree file family;
- `0x103398`: enumerated controls-tree file family.

All three direct calls are in `copyWhatsNewFiles()` FDE
`[0x101110,0x104c1b)`. Generated Qt row-64 forwarding call `0x16e030` remains a
separate producer edge. The exact shell-boundary result does not complete dynamic
Qt meta-invokers, indirect calls, external dispatch, or all upstream producers.

The USB provenance review follows dispatcher `0x3a50..0x3b49`: exact
`usb-automount` uses `/media/usb/<port>/<ID_FS_UUID-or-no-UUID-alternate>`, while
label and model are separate D-Bus fields. Exact stock
`./lib/libblkid.so.1.1.0` is SHA-256
`56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701`,
Build ID `c6f98d98cb2cbc2ff864167f37048233d90a8fef`.

The VFAT/exFAT/NTFS/ext/UDF UUID-family negatives remain bounded to those
constrained producers. ISO9660 is different: exact FDE
`[0x1c4c0,0x1c654)` copies 16 raw modified/created-date bytes, tests only the
all-ASCII-`'0'` case, and formats them through raw `%c` conversions at format
`0x35368`. Version-matched util-linux v2.27.1 `iso9660.c` lines 110-151 has
SHA-256 `601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b`.
Subsequent `blkid_safe_string` preserves allowed shell/path-sensitive byte
classes, and the dispatcher places that UUID in the mount component. This
establishes a static ISO9660 byte route to the automounter path.

Label `$`/`?`/`/` preservation remains a separate non-path D-Bus fact, and the
sanitized no-UUID word still has no useful shell-active effect. Exact
AppDMClient callback-to-staging and AppUpgrade suffix edge `0x102de9` remain
separate. A post-delivery follow-up binds canonical bzImage through bounded
legacy-LZ4 vmlinux and unique gzip IKCONFIG to exact recovered config SHA-256
`987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`:
ISO9660/UDF and SCSI CD-ROM paths are not configured. The canonical 163-member
inventory/metadata lack the tested stock isofs/ISO9660, UDF, sr/sr_mod
identities and SCSI CD-ROM aliases. The named canonical routes are false, while
broad exact-stack ISO9660 and physical-optical routes remain unknown because
renamed, inline, and vendor-equivalent implementations are not excluded.
Userspace recognition, generic direct `mount(2)`, and read-only retry remain.

Physical ISO9660 control and accepted/mounted media on an unidentified or
materially different installed runtime, installed delivery, the AppDMClient
launch-argument/inner-AppUpgrade constructor bridge, and invocation of the
relevant `decryptionFile` call with that path remain unknown. Those gates would
establish only pre-auth delivery to the decryption input.
Because verifier acceptance dominates command construction and `popen`, actual
physical shell-sink delivery additionally requires authentication acceptance.
Therefore this sink remains structurally unquoted without establishing physical
shell-syntax delivery, command success, or arbitrary command execution. Command
success and amplification remain route-generic observations rather than
ISO9660-specific outcomes.

## Non-operational Boolean/tri-state model

[`../tools/uk_fw/appfumo_shell_boundary_model.py`](../tools/uk_fw/appfumo_shell_boundary_model.py)
consumes only strict Boolean evidence facts. It rejects missing/extra keys,
non-Booleans, partial CLI groups, duplicate options, and abbreviations. False means
“not established”, not “disproved.”

For the pre-recorded exact-static state it reports:

- exact static fact set complete: `true`;
- exact unquoted shell-sink structure established: `true`;
- runtime shell-syntax delivery established: `null`;
- runtime command success established: `null`;
- pathname influence, shell-character survival, invocation, authentication,
  process security context, command success, privilege/domain amplification,
  root impact, and persistence: each independently `null`.

The sink-structure conclusion depends only on the eight facts necessary to bind
that structure; the separate static status/return facts do not suppress it.
Runtime shell-syntax delivery depends only on the sink structure, pathname
influence, character survival, and invocation. Authentication, process context,
command success, amplification, root, and persistence remain separate outputs.
Causally contradictory inputs are rejected rather than normalized into a
positive conclusion.

The deterministic report is sorted UTF-8 with one LF. It emits no command,
target pathname, payload, trigger, archive, or update material. Its SHA-256 is
recorded in the reviewed checkpoint after final bytes are frozen.

## Remaining independent questions

- installed/running binary identity and equality to this exact ELF;
- pathname influence over `encFile`, `destPath`, package base, or enumerated
  names;
- shell-sensitive-character survival through filesystem, archive, Qt, parser,
  and producer layers;
- direct, generated meta-call, dynamic meta-invocation, indirect, external,
  D-Bus, service, UI, or update-flow reachability;
- descriptor/package authentication, update eligibility, and acceptance;
- process uid/gid, capabilities, SMACK label/domain, loaded policy, and other
  confinement;
- actual child creation, command substitution, command exit status, and output;
- privilege/domain amplification, unrestricted root impact, partition writes,
  slot/boot acceptance, and persistence.

## Safety record

Only read-only hashing, `.eh_frame` inspection, Homebrew LLVM static
disassembly, byte inspection, documentation, and host Python tests were used. No
recovered executable or helper was run. No target, device, radio, network,
archive, update package, shell payload, trigger, signature bypass, partition,
slot, boot state, privilege action, root action, or persistence mechanism was
created or exercised.
