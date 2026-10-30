# Minimal retained kernel-candidate evidence

These are reviewable excerpts and authoritative upstream patches supporting the
2026-11-01 exact-binary assessments. Large firmware inputs and full disassembly
remain ignored under `work/`.

## Inputs and tools

- recovered `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`;
- recovered `snd-seq.ko` SHA-256:
  `ccc802452bb4ac4527d2def96ddef463211c03ae2c07d9003fdc7ebed9eb091d`;
- recovered `snd-pcm.ko` SHA-256:
  `9a1f126d6919812d3e7c6d7c9def51a698564cdfb22b9ebc72022c6e87d19fb9`;
- disassembler: Homebrew LLVM `llvm-objdump` 23.1.3, Intel syntax;
- source module path:
  `work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko`;
- source PCM module path:
  `work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/snd-pcm.ko`;
- source kernel path: `work/eu-260128/vmlinux`.

The ALSA files retain complete disassemblies of the relevant module functions. The kernel files retain only the branches needed to review the
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
llvm-objdump -dr --x86-asm-syntax=intel \
  --start-address=0xc6c --stop-address=0xe7e \
  work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/snd-pcm.ko \
  > snd-pcm-control-ioctl.asm
llvm-objdump -dr --x86-asm-syntax=intel \
  --start-address=0x3e8f --stop-address=0x3f1f \
  work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/snd-pcm.ko \
  > snd-pcm-release.asm
llvm-objdump -dr --x86-asm-syntax=intel \
  --start-address=0x1621 --stop-address=0x174e \
  work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko \
  > snd-seq-do-ioctl.asm
llvm-objdump -dr --x86-asm-syntax=intel \
  --start-address=0x174e --stop-address=0x188d \
  work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko \
  > snd-seq-create-client.asm
llvm-objdump -dr --x86-asm-syntax=intel \
  --start-address=0x2293 --stop-address=0x23b8 \
  work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko \
  > snd-seq-set-client-pool.asm
```

The `cve-*.patch` files are GitHub patch representations of these upstream
commits:

- CVE-2016-0728: `23567fd052a9abb6d67fe8e7a9ccdd9800a540f2`;
- CVE-2017-1000112: `85f1bd9a7b5a79d5baa8bf44af19658f7bf77bfa`;
- CVE-2017-0861: `362bca57f5d78220f8b5907b875961af9436e229`;
- CVE-2017-15265: `71105998845fb012937332fe2e806d443c09e026`;
- CVE-2018-1000004 mainline: `b3defb791b26ea0683a93a4f49c77ec45ec96f10`;
- CVE-2018-1000004 Linux 4.1 stable equivalent:
  `f8a38ab4cd9624fc5ac8a7f965c7b20f5b62c03c`.

`alsa-seq-probe-result.json` is the retained machine-readable benign reachability
result. It contains no firmware binary, proprietary module, credential, payload,
or personal identifier.
