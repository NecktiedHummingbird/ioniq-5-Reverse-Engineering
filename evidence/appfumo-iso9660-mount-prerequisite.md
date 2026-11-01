# AppFUMO ISO9660 mount prerequisite: exact recovered EU 260128 follow-up

## Result

The previously accepted static UUID-byte provenance remains correct, but it
stops before a kernel mount prerequisite. The exact recovered userspace has all
of these edges:

1. stock libblkid recognizes ISO9660 and produces the established raw-date UUID;
2. the stock persistent-storage rule permits ordinary USB mass-storage `sd*`
   events to reach builtin blkid;
3. `usb-automount`'s generic non-NTFS/exFAT branch copies filesystem type
   `iso9660` and calls `mount(2)` directly;
4. initial failure reaches an explicit read-only retry; and
5. the `UsbMount` success signal is emitted only after either direct mount call
   succeeds.

The package rejects the named canonical ISO9660/UDF and SCSI CD-ROM routes,
but does not resolve the broad exact-stack ISO9660 mount route:

- canonical rootfs archive SHA-256
  `423491fd8b86bd815d4e12f47054e08a589a5159f87213f08980fcc3a0e47c84`
  contains the hash-bound bzImage; its bounded legacy-LZ4 payload decompresses
  to vmlinux SHA-256
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
  with Build ID `273378887b4cf563c10862fdf18b2292765df781`;
- the unique embedded gzip IKCONFIG is byte-identical to recovered config
  SHA-256
  `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`,
  which has `# CONFIG_BLK_DEV_SR is not set`,
  `# CONFIG_ISO9660_FS is not set`, and `# CONFIG_UDF_FS is not set`;
- the archive has 163 regular `.ko` members with none of the exact tested
  `isofs.ko`, `iso9660.ko`, `udf.ko`, `sr_mod.ko`, or `sr.ko` basenames/paths,
  and its 11 hash-bound `modules.*` payloads contain none of the tested bounded
  module identifiers or SCSI CD-ROM alias mappings.

Therefore
`exact_recovered_stack_named_iso9660_mount_route = false` when these exact
bindings are present, while broad
`exact_recovered_stack_iso9660_mount_route = null`. Likewise, the named
canonical physical-optical SCSI CD-ROM route is false while the broad physical-
optical route is unknown. This is a named static prerequisite rejection, not a
runtime mount attempt. It does not withdraw the pre-mount ISO9660 UUID byte
route or claim that every inline, renamed, or vendor-equivalent implementation
is absent. The success D-Bus signal remains gated on actual mount success.

The conclusion is not generalized to broad exact-stack completion, another
kernel, an installed unit with an unidentified runtime identity or extra
modules, or all filesystem types.

## Exact bindings

| Object | Exact canonical identity |
|---|---|
| rootfs archive | `423491fd8b86bd815d4e12f47054e08a589a5159f87213f08980fcc3a0e47c84` |
| recovered kernel config | `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56` |
| archive member `./boot/bzImage-4.1.27-abl` | SHA-256 `2fec21219b4e52c90d287687f3cfd4fbdc55ad00f71117b02c32134487277582`, size 5,327,072 |
| bzImage compressed kernel payload | boot-protocol-derived offset `0x406e`, length `0x50ebf7`, legacy-LZ4 magic; exact two-block bounded decode |
| decompressed vmlinux | SHA-256 `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`, size 16,398,376, Build ID `273378887b4cf563c10862fdf18b2292765df781` |
| embedded IKCONFIG | unique `IKCFG_ST` at `0x809860`, unique `IKCFG_ED` at `0x80fab2`, unique gzip stream, 113,598 decoded bytes, byte-identical to recovered config |
| archive member `./lib/udev/rules.d/60-persistent-storage.rules` | SHA-256 `5757bc1da0b3e07ee1769faa266af7720b8eef21006212051a8720c02eab5a8e`, size 4,903 |
| archive member `./lib/libblkid.so.1.1.0` | SHA-256 `56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701`, Build ID `c6f98d98cb2cbc2ff864167f37048233d90a8fef` |
| archive member `./lib/systemd/systemd-udevd` | SHA-256 `f32f6296ea20d959ac046ae80724f39e317aaaf492a5c7eedd9270b5b2abab0d`, Build ID `91b0e9592a52274a97e185fed528d6af3557e49d` |
| archive member `./app/bin/usb-automount` | SHA-256 `7db44d8e34fbece4d5b8ef4896a99239cb540a22d1d756335dde4bc219af3802`, Build ID `20748cf9928ba155ac4201a33bb1e29e64ae9139` |
| sorted 163-member `.ko` name manifest | SHA-256 `acfcc3ff781dfab5cfec2d7b9870aaf38d4d5882a73dbc65698c66162e671963` |

The compact retained record is
[`artifacts/update-candidates/appfumo-iso9660-mount-prerequisite-exact-static.txt`](artifacts/update-candidates/appfumo-iso9660-mount-prerequisite-exact-static.txt),
SHA-256
`7935f331841eed2374a8318ce5f4d9c287cc76225ebefbfd9dd4e5a94b62cc0e`.
It lists all 11 exact `modules.*` members, sizes, and SHA-256 values. Tests read
the canonical archive directly, independently reproduce the 163-member count
and sorted-name digest, and test exact member basenames/paths plus bounded
metadata identifiers `fs-iso9660`, `fs-isofs`, `fs-udf`, `isofs`, `iso9660`,
`udf`, and `sr_mod`, and textual SCSI type-5/block-major-11 alias mappings.
Identifier boundaries avoid incidental larger strings containing `udf`.

No exhaustive absence of renamed, inline, or vendor-equivalent implementation
is claimed. The exact embedded config's `n` rows decide the named built-in
ISO9660/UDF/SCSI-CD-ROM paths; the module result is limited to the identities
and aliases above. The retained file is evidence, not executable target
material.

## Bounded canonical kernel/config identity chain

The focused test extracts exactly one bzImage regular member from the canonical
archive and reads no more than 16 MiB. Boot protocol `0x020d` fields derive the
payload at `0x406e` with length `0x50ebf7`; all arithmetic and member bounds are
checked. The actual outer kernel payload is legacy LZ4, not gzip. Before any
extension/copy, decoded literal and match lengths are checked against remaining
per-block capacity; overlap copy uses at most 64 KiB chunks without repeated-
pattern multiplication. Each completed block is checked against remaining
aggregate capacity before extension. Mutation tests force literal, match, and
aggregate overflow rejections at those pre-extension checks. Block sizes,
tokens/offsets, final size footer, 32 MiB output limit, ELF magic, and the unique
valid candidate are also checked in memory. The result has the exact vmlinux
hash, size, and Build ID in the table.

The only gzip stream in that vmlinux is bounded by the unique IKCONFIG markers.
Bounded zlib decoding requires complete EOF and no unused/unconsumed bytes. The
result is byte-identical to `work/eu-260128/kernel.config`; malformed magic,
lengths, compressed data, duplicate markers, ELF notes, or over-limit output
fail closed. No target code is executed.

## Exact embedded config offsets and contrary mass-storage support

Offsets are zero-based byte offsets in the exact config; line numbers are
one-based:

| Byte offset | Line | Exact row |
|---:|---:|---|
| `0x861a` (34330) | 1292 | `# CONFIG_BLK_DEV_SR is not set` |
| `0x17e34` (97844) | 3666 | `# CONFIG_ISO9660_FS is not set` |
| `0x17e53` (97875) | 3667 | `# CONFIG_UDF_FS is not set` |

The same config has `CONFIG_BLOCK=y`, `CONFIG_SCSI=m`,
`CONFIG_BLK_DEV_SD=m`, and `CONFIG_USB_STORAGE=m`. The rootfs ships the normal
SCSI disk and USB-storage modules. Ordinary USB mass storage can consequently
appear as `sd*`; that positive route is preserved. Physical optical `sr*` is
additionally blocked because the named SCSI CD-ROM driver is not configured;
the tested canonical `sr_mod.ko`/`sr.ko` identities and SCSI type-5/
block-major-11 metadata aliases are also absent.

The ISO9660 and UDF rows are filesystem-specific. They do not establish an
absence of VFAT, exFAT, NTFS, ext, or every other filesystem implementation.

## Userspace route and direct mount semantics

### udev and libblkid

Exact `./lib/udev/rules.d/60-persistent-storage.rules` admits block names that
include `sd*`. Applicable USB SCSI disks reach builtin `usb_id`, and exact line
66 applies `IMPORT{builtin}="blkid"` when the kernel name is not `sr*`.
The accepted pathname assessment already binds exact libblkid ISO9660 producer
FDE `[0x1c4c0,0x1c654)`, its modified-date call at
`0x1c7eb..0x1c7fa`, created-date fallback at `0x1ca10..0x1ca1a`, UUID safe
string transformation, and dispatcher delivery into the mount component.
Recognition and UUID publication occur before the kernel mount call.

### Generic type copy and mount calls

In mount FDE `[0x4c00,0x508d)`, checks at `0x4c62` and `0x4c7a` special-case
NTFS/exFAT. The nonmatching edge at `0x4c81` reaches `0x4fd0`; `0x4fd8` supplies
the incoming type and exact format `0x794e` is `%s`. Thus ISO9660 takes the
generic direct-call branch rather than an absent filesystem-specific helper.

The initial flag slot receives either:

- `0xc0ed000a` at `0x4f20` for configured read-write
  (`MS_MGC_VAL | MS_NOSUID | MS_NOEXEC`); or
- `0xc0ed000b` at `0x4cd7`, adding `MS_RDONLY`.

The first direct `mount@plt` call is `0x4d70`; its success test is
`0x4d75..0x4d77`. Failure reaches `0x4dec`, which explicitly loads
`0xc0ed000b`, then the second direct call at `0x4df1` and failure test at
`0x4df6..0x4df8`. This is an actual read-only retry, but read-only does not
supply a missing kernel filesystem implementation.

Both success edges converge at `0x4dfe`. Retry failure branches elsewhere
before the `UsbMount` setup and helper call at `0x4e28..0x4e34`. The signal is
therefore a post-mount-success event, not evidence that userspace recognition
alone mounted the medium.

## AppDMClient boundary retained

Exact AppDMClient root-entry processing remains conditional on a successful
port-1 callback: only that callback condition stores the delivered mount path in
`this+0x128`, marks mounted state, and forwards the path into staging. Since the named canonical recovered-stack ISO9660 routes are rejected while
broad completion remains unknown, accepted static UUID byte provenance does not
by itself satisfy that callback prerequisite.

Two naming/dataflow questions remain unknown rather than inferred:

- exact mixed-case/dot ISO naming extensions and their installed acceptance;
- the AppDMClient-to-inner-AppUpgrade package-base/constructor bridge.

The established inner AppUpgrade suffix, verifier, and sink edges remain
separate per-binary facts.

## Schema-v5 semantics

`tools/uk_fw/appfumo_usb_pathname_model.py` now records positive exact-static
facts for:

- ordinary `sd*` builtin-blkid routing;
- generic ISO9660 direct mount dispatch;
- explicit read-only retry;
- post-success signal dominance; and
- `canonical_bzimage_vmlinux_identity_chain_bound`;
- `embedded_ikconfig_recovered_config_identity_chain_bound`; and
- `recovered_kernel_named_iso9660_mount_prerequisite_absence_bound` after the
  embedded exact config and named canonical module-identity/alias absence are
  bound.

The report exposes both positive identity-chain outputs. Module absence is
explicitly bounded to the tested basenames, identifiers, and aliases; no
renamed/inline/vendor-equivalent absence is modeled.

The named outputs are
`recovered_kernel_named_iso9660_mount_prerequisite_absence = true`,
`exact_recovered_stack_named_iso9660_mount_route = false`, and
`exact_recovered_stack_named_physical_optical_sr_route = false`. Broad
`recovered_kernel_iso9660_mount_prerequisite_absence`,
`exact_recovered_stack_iso9660_mount_route`, and
`exact_recovered_stack_physical_optical_sr_route` remain `null`. Likewise,
`installed_iso9660_media_accepted_and_mounted` remains tri-state and is `null`
in the pre-recorded state because no installed-unit identity was established.
An explicit true installed-mount input requires a
materially different runtime identity:
`materially_different_runtime_identity_established=true`. That generic
hypothetical classification can become true without changing the exact-stock
negative; the two meanings are deliberately independent.

The default schema-v5 report is deterministic sorted ASCII-only UTF-8 JSON with
one LF. Its SHA-256 is
`56b7a941a4180472292af59e60b5b1bdf5b3e369205b75519a3d3c4f073f1804`.

## Residual gates

- installed-unit kernel/config identity and any extra installed modules;
- physical ISO9660 source control on an applicable ordinary USB mass-storage
  device;
- materially different runtime ISO9660 acceptance and successful mount;
- exact mixed-case/dot ISO naming extensions;
- successful port-1 callback and AppDMClient root-entry handling;
- AppDMClient-to-inner-AppUpgrade package-base bridge;
- invocation of the relevant `decryptionFile` call with that path;
- authentication acceptance, command success, process context,
  privilege/domain amplification, root impact, and persistence.

Static/read-only analysis only: no target executable or helper was run; no
mount, media/image/archive, malformed input, path/command/payload, D-Bus request,
target syscall, privilege/root action, or persistence action was created or
performed.
