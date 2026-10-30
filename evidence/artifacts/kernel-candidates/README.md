# Minimal retained kernel-candidate evidence

These are reviewable excerpts and authoritative upstream patches supporting the
2026-11-01 exact-binary assessments. Large firmware inputs and full disassembly
remain ignored under `work/`.

## Inputs and tools

- recovered `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`;
- recovered `snd-seq.ko` SHA-256:
  `ccc802452bb4ac4527d2def96ddef463211c03ae2c07d9003fdc7ebed9eb091d`;
- disassembler: Homebrew LLVM `llvm-objdump` 23.1.3, Intel syntax;
- source module path:
  `work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko`;
- source kernel path: `work/eu-260128/vmlinux`.

The sequencer files retain complete disassemblies of the two relevant module
functions. The kernel files retain only the branches needed to review the
claims. They were generated with commands equivalent to:

```sh
llvm-objdump -d --x86-asm-syntax=intel \
  --start-address=0xffffffff814cd140 --stop-address=0xffffffff814cd305 \
  work/eu-260128/vmlinux > kernel-ipv4-ufo-branch.asm
llvm-objdump -d --x86-asm-syntax=intel \
  --start-address=0xffffffff8151cd2a --stop-address=0xffffffff8151cf25 \
  work/eu-260128/vmlinux > kernel-ipv6-ufo-branch.asm
llvm-objdump -d --x86-asm-syntax=intel \
  --start-address=0xffffffff811b6496 --stop-address=0xffffffff811b64fb \
  work/eu-260128/vmlinux > kernel-join-session-keyring-branch.asm
```

The `cve-*.patch` files are GitHub patch representations of these upstream
commits:

- CVE-2016-0728: `23567fd052a9abb6d67fe8e7a9ccdd9800a540f2`;
- CVE-2017-1000112: `85f1bd9a7b5a79d5baa8bf44af19658f7bf77bfa`;
- CVE-2017-15265: `71105998845fb012937332fe2e806d443c09e026`.

`alsa-seq-probe-result.json` is the retained machine-readable benign reachability
result. It contains no firmware binary, proprietary module, credential, payload,
or personal identifier.
