# Exact scope of `CONFIG_KEYSTORE_SECURE_BOOT_IGNORE` and boot-manifest bounds

Status: exact static audit of the recovered EU `260128` kernel. The configured
option removes a secure-boot-status prerequisite from **keystore device
initialization**; it does not remove the separately compiled OEM signature
verifier or manifest keyring. A separate boot-time manifest parser has
copy-size/internal-length mismatches and frees an interior cursor on parse
errors, creating conditional out-of-bounds-read and invalid-free candidates.
Control of its boot parameter and physical-memory input is not established.

No kernel, manifest, boot parameter, physical-memory region, signature, update,
or target was executed or modified.

## Exact artifact

| Field | Value |
|---|---|
| Kernel | `work/eu-260128/vmlinux` |
| SHA-256 | `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b` |
| GNU Build ID | `273378887b4cf563c10862fdf18b2292765df781` |
| Config SHA-256 | `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56` |
| Config option | `CONFIG_KEYSTORE_SECURE_BOOT_IGNORE=y` |
| `keystore_init` | `[0xffffffff81b1dc66, 0xffffffff81b1ddd2)` |
| `keystore_register` | `[0xffffffff811c17ab, 0xffffffff811c18fb)` |
| `manifest_init` | `[0xffffffff81b1ddd2, 0xffffffff81b1e03e)` |
| `verify_oem_signature` | `[0xffffffff811c5a36, 0xffffffff811c5bad)` |
| `manifest_key_verify_digest` | `[0xffffffff811cca0f, 0xffffffff811ccc84)` |

`evidence/artifacts/kernel-candidates/kernel-keystore-secure-boot-ignore.asm`
retains complete symbol ranges for those five functions and
`get_apl_manifest_offsets` and the class/device wrappers relevant to error
routing.

## Matching public source provenance

Astra's generic public-source research located the Intel-authored implementation
in the vendor-owned `teslamotors/linux` `intel-4.1` branch, pinned at commit
[`0c9640bba6a841f524f5947d0741386792674577`](https://github.com/teslamotors/linux/commit/0c9640bba6a841f524f5947d0741386792674577).
That tree identifies Linux `4.1.49-gvt`; it is comparison/provenance source,
not package-version or source-equivalence evidence for this kernel. It confirms
the Kconfig intent, ABL parameter registration, and shared core design, but the
target has source-level differences: its `keystore_register` lacks the public
snapshot's IGNORE warning call and calls a three-argument context helper rather
than that snapshot's four-argument form. Exact target conclusions therefore
come only from the recovered instructions reviewed here.

Authoritative source locations include:

- [`security/keystore/Kconfig`](https://github.com/teslamotors/linux/blob/0c9640bba6a841f524f5947d0741386792674577/security/keystore/Kconfig#L194-L219);
- [`security/keystore/keystore_kmod.c`](https://github.com/teslamotors/linux/blob/0c9640bba6a841f524f5947d0741386792674577/security/keystore/keystore_kmod.c#L217-L290);
- [`security/keystore/api_kernel.c`](https://github.com/teslamotors/linux/blob/0c9640bba6a841f524f5947d0741386792674577/security/keystore/api_kernel.c#L40-L112);
- [`security/keystore/operations.c`](https://github.com/teslamotors/linux/blob/0c9640bba6a841f524f5947d0741386792674577/security/keystore/operations.c#L631-L664);
- [`security/oemkey/manifest.c`](https://github.com/teslamotors/linux/blob/0c9640bba6a841f524f5947d0741386792674577/security/oemkey/manifest.c#L714-L817); and
- [`arch/x86/platform/bxt/abl_param.c`](https://github.com/teslamotors/linux/blob/0c9640bba6a841f524f5947d0741386792674577/arch/x86/platform/bxt/abl_param.c).

The public source resolves a naming ambiguity: `oemkm` is the internal ABL-list
entry, while `__setup("ABL.", setup_abl_params)` makes the full kernel command
line spelling `ABL.oemkm=<size>@<physical-address>`. The exact binary remains
the authority for every target-specific conclusion below.

## What the IGNORE option does in this build

`keystore_init` begins with two unconditional log calls. Their exact string
addresses resolve to:

```text
keystore: keystore_init
keystore: Not checking secure boot status!
```

Immediately after the second log, `0xffffffff81b1dc88` calls
`keystore_fill_seeds`. There is no intervening status query, predicate, or
alternate success path. A nonzero seed-fill result is tested at
`0xffffffff81b1dc8d` and returned through the error path; only success proceeds
to allocate the device number, class, and `/dev/keystore` device.
`alloc_chrdev_region` and `cdev_add` failures also reach error returns, so the
configured path is not unconditionally successful.

There is a separate error-handling defect: `__class_create` at
`0xffffffff81b1dced` and `device_create` at `0xffffffff81b1dd25` are checked
only against `NULL`, while their complete callee ranges return `ERR_PTR` on
ordinary failures. Such an error pointer can pass the tests at
`0xffffffff81b1dcf2` or `0xffffffff81b1dd2a`; if later `cdev_add` succeeds,
`keystore_init` can return zero despite class/device creation failure. This is
weak initialization-state handling, not a demonstrated signature bypass or
privilege primitive.

This establishes a narrow semantic effect: the configured build does not make
keystore initialization conditional on a secure-boot-status check. It does
**not** make keystore initialization unconditional in general, because seed,
device-number, and cdev setup can still fail.

The option has a second exact status-gate effect in `keystore_register`.
The complete range contains no secure-boot-status query: after argument checks,
`0xffffffff811c1809` proceeds to client-ID calculation and later client-key
and context setup. Matching public source places the omitted `get_sb_stat()` /
`-EPERM` branch under the inverse of the IGNORE option. Thus kernel clients can
register without that platform-status prerequisite, but ordinary client
identification, key derivation, allocation, and insertion failures remain.

## What the option does not remove

`manifest_init` is a distinct adjacent initcall, with separate initcall table
entries:

- `__initcall_keystore_init6` at `0xffffffff81b9a610`;
- `__initcall_manifest_init6` at `0xffffffff81b9a618`.

The manifest initcall still obtains the firmware-provided manifest location,
copies it, parses extension pointers, prepares root credentials, and calls
`keyring_alloc` for `.manifest_keyring`.

The ordinary OEM verification chain is also intact. In
`verify_oem_signature`:

1. null data/signature arguments are rejected;
2. `keystore_sha256_block` is called at `0xffffffff811c5acf`;
3. the digest and signature are optionally logged under dynamic debug; and
4. `manifest_key_verify_digest` is called at `0xffffffff811c5b5b`, with its
   return value preserved through the epilogue.

`manifest_key_verify_digest` still searches the manifest keyring for an
asymmetric key, checks key operations and usage bits, imports the supplied
signature, and reaches `verify_signature`. None of these paths consults the
IGNORE option.

Therefore, treating `CONFIG_KEYSTORE_SECURE_BOOT_IGNORE=y` as a general OEM
signature, update-signature, verified-boot, or package-acceptance bypass is
rejected for this exact kernel. It removes keystore initialization and client
registration **status gates**; it is not evidence that arbitrary firmware will
boot.

## Manifest parser length mismatch

The complete `manifest_init` range also corrects and sharpens the existing
bounds description.

At `0xffffffff81b1de18` through `0xffffffff81b1de29`, the outer size check uses
`size - 1 <= 0x03ffffff`. The accepted range is therefore:

```text
1 .. 0x04000000 bytes (inclusive)
```

—not `1 .. 0x03ffffff`.

The accepted size is passed to `__kmalloc` and to `memcpy_from_ph`, so allocation
and copy lengths match. Bounds are lost after that copy in two ways:

1. The parser reads the internal declared length at `+4` and type at `+0`
   without a copied-size check. If the type is `0xe`, later equality predicates
   conditionally reach fields at `+0x13`, `+0x14..+0x17`, and
   `+0x18..+0x1b`, again without a copied-size check. Accepted copied sizes
   `1..0x1b` can therefore cause a fixed-header out-of-bounds read when the
   corresponding earlier predicates permit that read; not every path reads
   through `+0x1b`.
2. At `0xffffffff81b1dead`, it loads an internal 32-bit declared length from
   `base + 4` and computes `declared_end = base + declared_length`. That value is
   never compared with the copied size. If the declared length exceeds `0x24`,
   the extension loop starts at `base + 0x24` and reads a 16-bit stride at
   `entry + 0x22`. The first such stride read ends at offset `0x48`; later entry
   pointers are advanced by `0x24 + stride` and compared only with the internal
   declared end. The loop has a 101-entry cap, but no copied-allocation bound.

The 101-entry cap limits the furthest possible stride read: with every 16-bit
stride at `0xffff`, the exclusive end of the 101st stride read is offset
`0x640df4`. The bounded arithmetic model accounts for this cap rather than
assuming that every declared-length/copy-size mismatch is reachable.

This establishes an exact conditional boot-time out-of-bounds **read**
candidate. It does not establish an out-of-bounds write, controlled corruption,
instruction-pointer control, code execution, root, or persistence.

## Invalid interior free on parse error

A separate defect appears in cleanup ownership. `__kmalloc`'s base pointer is
stored at global `0xffffffff81c2b2e8` at `0xffffffff81b1de55`. After a successful
physical copy, `0xffffffff81b1de9f` preserves the base in a different global,
but `0xffffffff81b1dea6` overwrites `0xffffffff81c2b2e8` with `base + 0x24`, the
first extension cursor. The loop can later overwrite that same global with an
even later interior cursor.

Header rejection after this overwrite reaches cleanup at
`0xffffffff81b1dffb`, which loads the shifted global and passes it to `kfree` at
`0xffffffff81b1e002`. The invalid-type path alone demonstrates a feasible
`kfree(base + 0x24)` route. This is an exact invalid-interior-free candidate and
may cause a boot-time allocator fault or memory corruption. The audit has not
established controlled allocator corruption, a write of chosen data,
instruction-pointer control, code execution, root, or persistence.

Runtime reachability for both parser candidates additionally requires control
or corruption of the bootloader's manifest size/address or the physical-memory
blob before this initcall. No such first-stage control is currently established.
If that control already exists, trust-anchor substitution is the more direct
concern and these parser defects do not by themselves add a first-root primitive.

## Security classification

| Question | Result |
|---|---|
| Is the IGNORE option enabled? | Yes |
| Is the status check present before seed filling? | **No** |
| Is the status check present before client registration? | **No** |
| Can seed, device-number, or cdev failures still prevent init? | Yes |
| Are class/device `ERR_PTR` results handled correctly? | **No; only NULL is checked** |
| Is `manifest_init` still a separate initcall? | Yes |
| Is SHA-256 plus manifest-key verification still compiled and called? | Yes |
| Does the IGNORE option establish general signature bypass? | **No** |
| Is the copied manifest size accepted up to `0x04000000`? | Yes |
| Is the fixed header safe for every accepted copied size? | **No** |
| Is internal declared length bounded by copied size? | **No** |
| Boot-time OOB read candidate | **Present, conditional on unproved input control** |
| Interior-pointer `kfree` candidate | **Present on feasible header-rejection paths** |
| Allocator crash or memory corruption | Candidate; not observed or controlled |
| Controlled write, code execution, root, or persistence | Not established |

## Deterministic models

`tools/uk_fw/keystore_boot_gate_model.py` accepts eleven Boolean facts only. It
keeps both status-gate removals, fatal seed failure, the separate manifest initcall,
the interior-pointer-free path, and the surviving verifier chain independent.
Class/device `ERR_PTR` handling is documented separately and is not represented
by that model. Its default report SHA-256 is
`e5d935fe17a05d2304ced562a515e3dd964b1bae993e300985a0c9aaf3f20926`.

`tools/uk_fw/manifest_initial_bounds_model.py` accepts only a copied size in
`[1, 0x04000000]` and an internal declared length in `[0, 0xffffffff]`. It
classifies fixed-header, first-extension, and declared-extent arithmetic while
explicitly refusing to claim complete later-walk safety. Its default report
SHA-256 is
`495ef9bdd20e9bd52da8c92cf52a657d3f5d0d2c37722218ac7a51a7fd0a3c3d`.

Neither model extracts instructions or emits a manifest, physical address, key,
signature, command, payload, or firmware image.

## Evidence identities

- selected complete-function disassembly SHA-256:
  `54be9f05a4969be0bcc350ddbd35da2fa2fdf9e3abb397d44393f06289b0b3a3`.

## Claim boundary

This work narrows one tempting configuration-based bypass theory and exposes a
conditional parser-bounds defect. It does not establish control of the external `ABL.oemkm=` handoff, the
firmware-provided physical region, bootloader command-line construction,
substituted admission policy plus a usable certificate path, update acceptance, partition writing, slot selection,
boot acceptance, or persistence. Those remain separate gates requiring stock
boot-chain or disconnected-bench evidence.
