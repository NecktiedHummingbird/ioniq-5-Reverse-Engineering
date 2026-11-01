# AppFUMO USB pathname provenance: exact-static correction

## Result

The complete dispatcher reverses the package's earlier mount-component
conclusion. In exact stock `usb-automount`, the final component of
`%s/%d/%s` is **`ID_FS_UUID` or the no-UUID alternate**, not `ID_FS_LABEL`:

```text
/media/usb/<port>/<ID_FS_UUID-or-alternate>
```

`ID_FS_LABEL` and `ID_MODEL` are separate D-Bus fields. Label bytes can retain
characters such as `$`, `?`, and `/` after builtin-blkid normalization, but
those bytes do not enter the mount pathname in this binary.

The corrected bounded disposition is:

- filesystem-label mount-path route: **rejected**; label remains non-path;
- constrained UUID families (reviewed VFAT/exFAT/NTFS/ext/UDF forms):
  **rejected** as sources of shell-active UUID bytes;
- ISO9660 raw-date UUID static byte route: **established** from parser fields,
  through UUID formatting and `blkid_safe_string`, into the dispatcher-selected
  mount-path component;
- physical ISO9660 source control, media acceptance, and successful mount:
  **unknown**;
- no-UUID serial/partition route: **no shell-active effect established** after
  the exact stock USB serial precheck and sanitizer in the already-prefixed
  unquoted command word;
- hardware-descriptor control: **unknown** for an applicable installed
  no-UUID route;
- AppDMClient launch-argument/inner-AppUpgrade-constructor bridge and installed
  end-to-end delivery: **unknown**.

The previous combined filesystem-metadata rejection is withdrawn. The ISO9660
result establishes a static shell/path-sensitive byte route to the automounter
mount pathname, not physical delivery to an installed sink, a complete shell
expression, arbitrary command execution, authentication acceptance, command
success, privilege/domain amplification, root impact, or persistence.
Static/read-only analysis created no payload, update, trigger, mount, D-Bus
request, target syscall, privilege action, or persistence action.

## Exact stock binding

The analysis is directly bound to stock archive-member bytes:

| Object | SHA-256 | Additional identity |
|---|---|---|
| stock `mango-rootfs.tar.gz` | `423491fd8b86bd815d4e12f47054e08a589a5159f87213f08980fcc3a0e47c84` | canonical archive |
| `./app/bin/usb-automount` | `7db44d8e34fbece4d5b8ef4896a99239cb540a22d1d756335dde4bc219af3802` | Build ID `20748cf9928ba155ac4201a33bb1e29e64ae9139` |
| `./lib/systemd/systemd-udevd` | `f32f6296ea20d959ac046ae80724f39e317aaaf492a5c7eedd9270b5b2abab0d` | Build ID `91b0e9592a52274a97e185fed528d6af3557e49d` |
| `./lib/libblkid.so.1.1.0` | `56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701` | Build ID `c6f98d98cb2cbc2ff864167f37048233d90a8fef` |
| `./app/bin/AppDMClient` | `9a1fb796d7ac24fcce71c16e3dbee9306c888f43e705ee081f41b7d473978bd0` | stock member |
| `./etc/usb-automount.conf` | `559674d4469dc44611d77e175a27a238712b9f538d59a1864da0d321be3e2b51` | stock member |
| `./lib/systemd/system/usb-automount.service` | `563c077b61119a4ef7577732382fa245d87364a6068ac4304a94d073fc9c76fd` | stock member |
| exact AppUpgrade | `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7` | Build ID `863a8730e66a1c5245a1bf458fe2554adee0351a` |

A direct read from canonical `mango-rootfs.tar.gz` member
`./lib/libblkid.so.1.1.0` produced the stated libblkid SHA-256; it matched the
separately reviewed extracted copy. Its ELF note directly yielded the stated
Build ID. Package metadata identifies systemd `249.3-r0mango134` and
util-linux/libblkid `2.27.1-r0`.

Version-matched source provenance for the decisive producer is util-linux
v2.27.1 `libblkid/src/superblocks/iso9660.c`,
`probe_iso9660_set_uuid()` lines 110-151, SHA-256
`601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b`.
It remains under ignored `work/`; exact shipped machine code is retained below.

The bounded instruction record is
[`artifacts/update-candidates/appfumo-usb-pathname-provenance-exact-static.asm`](artifacts/update-candidates/appfumo-usb-pathname-provenance-exact-static.asm),
SHA-256
`932510a860b40cce280f217670cbf2c213e31b0a90008ac5c011c933cd584e8f`.
Full binaries, full disassemblies, and version-matched source remain under
ignored `work/`.

## 1. Property acquisition and caller state

The event/property FDE is `[0x3ef0,0x4836)`. It records:

1. `ID_FS_TYPE` at stack `+0x38`;
2. `ID_FS_LABEL` at `+0x58`;
3. `ID_FS_UUID` at `+0x48`;
4. `ID_MODEL` at `+0x50`;
5. `ID_SERIAL_SHORT` at `+0x60`;
6. `ID_ATA_SATA` at `+0x40`;
7. `ID_PART_ENTRY_NUMBER` at `+0x68`.

The event caller at `0x442d..0x4452` supplies dispatcher `0x3a50` with FS type
in `rcx`, label in `r8`, UUID/alternate in `r9`, and model as the seventh stack
argument. Those registers are only dispatcher inputs. Carrying them directly
into mount entry `0x4c00` was the prior P0 error.

## 2. Complete dispatcher and mount pathname

The decisive dispatcher transfers are:

| Address | Transfer | Meaning |
|---|---|---|
| `0x3a59` | original `r9 -> r13` | UUID/alternate |
| `0x3a5e` | original `r8 -> r12` | label |
| `0x3a8d` | seventh argument -> `r14` | model |
| `0x3b28` | saved `rcx -> rdx` | FS type |
| `0x3b31` | `r14 -> r9` | model |
| `0x3b34` | `r13 -> r8` | UUID/alternate |
| `0x3b37` | `r12 -> rcx` | label |
| `0x3b49` | tail jump `0x4c00` | mount entry |

Therefore mount FDE `[0x4c00,0x508d)` receives:

```text
rdx -> rbx      filesystem type
rcx -> r15      label
r8  -> r13      UUID/alternate
r9  -> stack+8  model
```

At `0x4d16`, `push %r13` supplies the final `%s` to format `%s/%d/%s` at
`0x78a6`. The stock root is `/media/usb`, and the port classifier emits `1..4`
(`front1`, `front2`, `rear1`, `rear2`; stock active entries are 1 and 3).
The exact path is consequently:

```text
/media/usb/<port>/<UUID-or-no-UUID-alternate>
```

This transfer matches the prior independent analysis in
`evidence/vm-bringup/usb-root-vector-map.md`.

## 3. D-Bus field roles

At `0x4e15..0x4e34`, the mount function invokes helper FDE
`[0x4870,0x4b7c)` with:

- `rsi`: constructed mount pathname;
- `edx`: port;
- `rcx`: label;
- `r8`: model;
- `r9`: filesystem type;
- stack argument: mount flag.

The helper stores and appends those as separate fields. Thus label and model are separate D-Bus fields. UUID/alternate is represented inside the mount
pathname, not as the label field. Shell-sensitive label preservation remains a
real but non-path D-Bus fact for this binary.

## 4. UUID producer split: constrained families and ISO9660

The exact stock libblkid identity is SHA-256
`56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701`,
Build ID `c6f98d98cb2cbc2ff864167f37048233d90a8fef`.

### Constrained reviewed families

| Filesystem class | UUID form | Shell-active byte in UUID? |
|---|---|---|
| VFAT/FAT | fixed hexadecimal serial with hyphen | no |
| exFAT | fixed hexadecimal serial with hyphen | no |
| NTFS | 16 uppercase hexadecimal digits | no |
| ext2/ext3/ext4 | canonical DCE UUID | no |
| UDF | constrained alphanumeric/hex/date-derived identifier | no established shell-active byte |

These exact-family negatives remain valid. They are not generalized to every
filesystem parser in stock libblkid.

### ISO9660 exception

Exact producer FDE `[0x1c4c0,0x1c654)` copies 16 bytes from the ISO9660 modified
or created date structure. Loads at `0x1c4d3..0x1c570` cover all 16 source
bytes. The loop at `0x1c5a8..0x1c5c2` checks only whether all 16 copied bytes are
ASCII `'0'`; it does not validate decimal ranges or restrict every copied byte
to a digit.

At `0x1c5c6`, exact rodata `0x35368` binds format
`%c%c%c%c-%c%c-%c%c-%c%c-%c%c-%c%c-%c%c`. Call `0x1c60c` formats the raw
copied bytes, with fixed hyphens, as the UUID. The ISO9660 probe first passes the
modified-date field at `0x1c7eb..0x1c7f5`; on the helper's zero result it passes
the created-date field at `0x1ca10..0x1ca1a`.

This machine code matches util-linux v2.27.1
`probe_iso9660_set_uuid()` lines 110-151, source SHA-256
`601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b`.
Systemd builtin-blkid subsequently applies exact `blkid_safe_string` to UUID.
Its allowed set preserves shell/path-sensitive byte classes including `$`, `?`,
and `/`. The corrected dispatcher then places that resulting `ID_FS_UUID` in
the final mount-path component.

Accordingly, this bounded static chain is established:

```text
ISO9660 modified/created date bytes
  -> raw-character UUID formatter
  -> ID_FS_UUID / blkid_safe_string-preserved byte class
  -> dispatcher UUID slot
  -> /media/usb/<port>/<UUID>
```

This is static parser/transform/path-component provenance. It does not establish
physical control of those bytes on an applicable source medium, installed media
acceptance, mount success, AppDMClient delivery, the AppDMClient-to-AppUpgrade
bridge, verifier acceptance, invocation, command success, process context,
privilege, root, or persistence.

## 5. Label preservation is separate and non-path

Shipped systemd builtin-blkid FDE `[0x3d210,0x3d69d)` maps LABEL separately from
UUID and calls exact stock `blkid_safe_string` FDE `[0xced0,0xd09c)`.
Whitespace is normalized, unsafe bytes are replaced, and the constrained
allowed set includes characters such as `$`, `?`, and `/`.

That establishes preservation in `ID_FS_LABEL`, including a shell-sensitive
byte class. It does **not** establish mount-path delivery, because the complete
dispatcher places label in `rcx/r15` and the D-Bus label field while
`UUID/alternate` occupies `r8/r13` and the final path component.

## 6. No-UUID alternate and shell context

When UUID is absent and the stock no-UUID support branch is selected, helper
FDE `[0x3e50,0x3eea)` constructs `%s_%s` from `ID_SERIAL_SHORT` and
`ID_PART_ENTRY_NUMBER`. If the partition number is absent while serial is
present, `0x3e7f..0x3e85` copies the bare serial. The result replaces the UUID
input before dispatcher `0x3a50`; neither label nor model becomes the path
component.

### Exact serial restrictions

Systemd 249.3 builtin `usb_id` obtains the raw USB serial attribute only after
an ASCII precheck: bytes must be `0x20..0x7f`, and comma is rejected. It then
runs whitespace normalization and `udev_replace_chars(..., NULL)`.
Exact machine code at `[0x22a00,0x22b20)` and its predicate at `0x29d80` retain
alphanumerics plus `# + - . : = @ _`; disallowed bytes become `_`. A narrow
literal backslash-`x` pair is skipped as a pair by the sanitizer. Decimal
partition text and the helper's `_` separator add no shell syntax.

Consequences in the actual unquoted source pathname:

```text
/media/usb/<port>/<sanitized-serial>[_<partition>]/.whatsnew.tar.gz
```

- whitespace, `;`, `|`, `&`, `$`, backticks, parentheses, quotes, `<`, `>`,
  slash, `*`, `?`, and brackets cannot survive the serial sanitizer;
- `#` is not a comment introducer because it occurs inside an already-started
  pathname word, not after a shell token boundary;
- `=` is not an assignment because the word begins with `/media/...`, not a
  shell name;
- `+`, `-`, `.`, `:`, `@`, and `_` are ordinary within this word;
- a retained `\x` pair makes the shell remove the backslash before ordinary
  `x`, which may make the command argument differ from the literal mounted
  pathname, but cannot create token splitting, an operator, substitution,
  redirection, globbing, or a comment.

A bare `..` serial can have pathname traversal semantics when no partition
suffix exists, as separately documented in the USB root vector map. It remains
one ordinary command word and is not shell-command injection. No useful
shell-active effect is established for this no-UUID pathname class.

The source principal is a hardware descriptor rather than filesystem-label
metadata. Whether a relevant physical principal controls the exact installed
`ID_SERIAL_SHORT`, reaches a supported no-UUID filesystem branch, and produces
an installed mount remains unknown; those gates are not inferred from the
sanitizer analysis.

## 7. Per-binary AppDMClient and AppUpgrade edges

The automounter emits its constructed pathname as the D-Bus mount-path field.
Exact AppDMClient separately receives a mounted-callback pathname at FDE
`0x84700`, assigns it to `this+0x128` at `0x848dd..0x848ee`, and forwards a
shared copy to staging at `0x84983..0x849a7`.

Exact AppUpgrade separately constructs `<package base>/.whatsnew.tar.gz` and
passes it as `encFile` at `0x102de9`. The fixed suffix at `0x20bb63`, `%1/%2`
template at `0x209cd4`, source slot `+0x80`, and argument setup
`0x102dbb..0x102de9` pin this role. `decryptionFile()` FDE
`[0x100b30,0x10110c)` inserts `encFile` and `destPath` without shell quoting and
reaches `popen(..., "r")` only after its verifier gate.

The package does not establish the AppDMClient launch-argument/inner-AppUpgrade-constructor bridge,
installed signal delivery, or exact installed binary pairing. The public field
log (SHA-256
`84d5bb69270dd610b132c8950c31dd98adad844c5a2c108b4df617381685de86`)
records a compatible `/media/usb/{slot}/{volume}/.whatsnew.tar.gz` runtime class
on an unidentified build, not the missing bridge.

## 8. Verifier and separate extraction route

`decryptionFile()` calls verifier `0x45820` at `0x100bb0`, retains and tests the
result, and rejects nonzero at `0x100bc3`. Command construction and the helper
call occur later. Authentication acceptance remains independent and unknown.

The corrected direct-call roles are:

- `0x102de9`: top-level `<package base>/.whatsnew.tar.gz`;
- `0x10281c`: enumerated system-tree file;
- `0x103398`: enumerated controls-tree file.

Extraction uses fixed temporary archive/root substitutions in
`tar xf %1 -C %2` and one-string `QProcess::execute` at `0x101d7c`. Archive
member names are not QProcess substitutions. QDir-enumerated member names later
reach `0x10281c` and `0x103398`, each through its own verifier-before-sink gate.

- member names as direct QProcess arguments: **false**;
- structural enumerated-member path route: **established**;
- top-level signature cryptographically binding decrypted tar member names:
  **unknown**;
- physically supplied authenticated member-name route: **unknown**.

## 9. Strict model and limits

`tools/uk_fw/appfumo_usb_pathname_model.py` accepts only a complete set of
literal Booleans, rejects missing/extra keys and causal contradictions, and
emits only `true`, `false`, or `null` findings. False input means “not
established,” not “disproved.” Explicit exact-static negative findings use
positive `*_bound` evidence facts.

The pre-recorded state reports:

- UUID/alternate as final mount-path component: `true`;
- label as mount-path component: `false`;
- ordinary label shell-active path route: `false`;
- constrained UUID-family shell-active path route: `false`;
- ISO9660 static shell/path-sensitive UUID byte route: `true`;
- no-UUID alternate shell-active effect: `false`;
- shell-sensitive label-byte preservation in the separate D-Bus field: `true`;
- physical ISO9660 source control and accepted/mounted delivery: `null`;
- cross-process package-base delivery and invocation of the relevant
  `decryptionFile` call with that path: `null`;
- pre-auth physical ISO9660 path delivery to that decryption input: `null`;
- overall physical shell-sensitive sink delivery, which additionally requires
  authentication acceptance because the verifier dominates construction and
  `popen`: `null`;
- hardware-descriptor control, authentication, command success, process
  context, privilege, root, and persistence: independently `null`.

`command_success_observed=true` is rejected unless cross-process delivery,
relevant `decryptionFile` invocation, and authentication acceptance are all
true. Command success and amplification remain route-generic observations; they
are not ISO9660-specific outcomes. Persistence remains an independent
observation, consistent with the accepted shell-boundary model. The model emits
no path, command, payload, trigger, update, archive, mount, D-Bus request, or
syscall material. Its frozen schema-v4 default report SHA-256 is
`026b421772bd708c7f6ccec9200ed8fb47fee3307b1821415c3b9db516854aa3`.

## Bottom line

Following the full dispatcher establishes that UUID/alternate—not label—is the
stock mount-path component. The constrained VFAT/exFAT/NTFS/ext/UDF UUID-family
negatives remain, label characters remain confined to a separate D-Bus field,
and the no-UUID serial/partition alternate has no useful shell-active effect in
the prefixed word. But exact ISO9660 code formats 16 raw date bytes after only an
all-`'0'` test, and `blkid_safe_string` preserves allowed shell/path-sensitive
bytes before the dispatcher uses the UUID as the path component. The combined
filesystem-metadata rejection is withdrawn and the ISO9660 static byte route is
established. Physical source control, media acceptance/mount, cross-process
package-base bridge, invocation of the relevant `decryptionFile` call with that
path, authentication, command success, process context, privilege, root, and
persistence remain unknown. Pre-auth delivery to the decryption input is
separate from actual shell-sink delivery, which requires authentication because
the verifier dominates command construction and `popen`.
