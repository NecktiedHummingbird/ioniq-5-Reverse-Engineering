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
- recovered `af_packet.ko` SHA-256:
  `c810265b3c22f95d2b90494cc206abd6b4e67b7710bff2adcb177ee4867f467b`;
- recovered `snd-usbmidi-lib.ko` SHA-256:
  `ad2180bab3d7433287288c9b8255c8f70cefb6d4ee3c6b7d95ea4826d4b434be`;
- disassembler: Homebrew LLVM `llvm-objdump` 23.1.3, Intel syntax;
- source module path:
  `work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko`;
- source PCM module path:
  `work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/snd-pcm.ko`;
- source packet module path:
  `work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko`;
- source USB-MIDI module path:
  `work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/usb/snd-usbmidi-lib.ko`;
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
llvm-objdump -d --x86-asm-syntax=intel \
  --start-address=0xffffffff811b1694 --stop-address=0xffffffff811b1709 \
  work/eu-260128/vmlinux
llvm-objdump -d --x86-asm-syntax=intel \
  --start-address=0xffffffff811b1892 --stop-address=0xffffffff811b18b1 \
  work/eu-260128/vmlinux
llvm-objdump -d --x86-asm-syntax=intel \
  --start-address=0xffffffff814a8d51 --stop-address=0xffffffff814a8d70 \
  work/eu-260128/vmlinux
llvm-objdump -d --x86-asm-syntax=intel \
  --start-address=0xffffffff81475c1d --stop-address=0xffffffff81475e13 \
  work/eu-260128/vmlinux
llvm-objdump -d --x86-asm-syntax=intel \
  --start-address=0xffffffff814d22f5 --stop-address=0xffffffff814d23ab \
  work/eu-260128/vmlinux
llvm-objdump -d --x86-asm-syntax=intel \
  --start-address=0xffffffff811aa199 --stop-address=0xffffffff811aa294 \
  work/eu-260128/vmlinux
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
llvm-objdump -dr --x86-asm-syntax=intel \
  --start-address=0x2084 --stop-address=0x20d2 \
  work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko \
  > af-packet-cve-2017-7308.asm
llvm-objdump -dr --x86-asm-syntax=intel \
  --start-address=0x2034 --stop-address=0x2893 \
  work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/usb/snd-usbmidi-lib.ko
```

The `cve-*.patch` files are GitHub patch representations of these upstream
commits:

- CVE-2015-7613: `b9a532277938798b53178d5a66af6e2915cb27cf`;
- CVE-2016-0728: `23567fd052a9abb6d67fe8e7a9ccdd9800a540f2`;
- CVE-2016-2544: `3567eb6af614dac436c4b16a8d426f9faed639b3`;
- CVE-2016-2545: `ee8413b01045c74340aa13ad5bdf905de32be736`;
- CVE-2016-2546: `af368027a49a751d6ff4ee9e3f9961f35bb4fede`;
- CVE-2016-2547/2548: `b5a663aa426f4884c71cd8580adae73f33570f0d`;
- CVE-2016-2549: `2ba1fe7a06d3624f9a7586d672b55f08f7c670f3`;
- CVE-2016-4569: `cec8f96e49d9be372fdb0c3836dcf31ec71e457e`;
- CVE-2016-4578: `9a47e9cff994f37f7f0dbd9ae23740d0f64f9fe6`,
  `e4ec8cc8039a7063e24204299b462bd1383184a5`, and completeness follow-up
  `a8c006aafead3c45ae5d5601e3717055bccf41bc`;
- CVE-2016-2384: `07d86ca93db7e5cdf4743564d98292042ec21af7`;
- CVE-2016-7117: `34b88a68f26a75e4fded796f1a49c40f82234b7d`;
- CVE-2017-8890: `657831ffc38e30092a2d5f03d385d710eb88b09a`;
- CVE-2017-9242: `232cd35d0804cc241eb887bb8d4d9b3b9881c64a`;
- CVE-2017-11176: `f991af3daabaecff34684fd51fac80319d1baad1`;
- CVE-2017-7533: `49d31c2f389acfe83417083e1208422b4091cd9e`;
- CVE-2017-10661: `1e38da300e1e395a15048b0af1e5305bd91402f6`;
- CVE-2018-17182: `7a9cdebdcc17e426fb5287e4a82db1dfe86339b2`;
- CVE-2018-18281: `eb66ae030829605d61fbef1909ce310e29f78821`;
- CVE-2020-29660: `c8bcd9c5be24fb9e6132e97da5a35e55a83e36b9`;
- CVE-2020-29661: `54ffccbf053b5b6ca4f6e45094b942fab92a25fc`;
- CVE-2021-0920: `cbcf01128d0a92e131bd09f1688fe032480b65ca`;
- CVE-2017-1000112: `85f1bd9a7b5a79d5baa8bf44af19658f7bf77bfa`;
- CVE-2017-0861: `362bca57f5d78220f8b5907b875961af9436e229`;
- CVE-2017-15265: `71105998845fb012937332fe2e806d443c09e026`;
- CVE-2018-1000004 mainline: `b3defb791b26ea0683a93a4f49c77ec45ec96f10`;
- CVE-2018-1000004 Linux 4.1 stable equivalent:
  `f8a38ab4cd9624fc5ac8a7f965c7b20f5b62c03c`.

The CVE-2017-7308 comparison additionally uses ignored GitHub patch captures
under `work/online-kernel-candidates-20261101/cve-2017-7308/`:

- primary private-area fix `2b6867c2ce76c596676bec7d2d525af525fdc6e2`,
  patch SHA-256
  `a2a31d146687d372bdbe3b40d3a04bf46d544a0d15901664b2ed2130b243a474`;
- companion frame-count fix `8f8d28e4d6d815a391285e121c3a53a0b6cb9e7b`,
  patch SHA-256
  `3e84b1acd9dd82dd0aedbb2ef301ce181993a2f68e106d1e3117d4608571b340`.

`kernel-inotify-cve-2017-7533.asm` binds snapshot dominance around exact parent
and rename notification paths, short-name copying under the dentry lock,
external-name reference retention/release, and the stable pointer passed to the
separate inotify length/copy operations. These exact effects reject the
CVE-2017-7533 mutable-name premise despite the old kernel version banner.

`kernel-ipv6-cve-2017-9242.asm` binds ordinary UDPv6 call flow, skb allocation,
the fraggap copy/trim, later signed copy calculation, and post-copy error
cleanup underlying V-029. The companion `-full.asm` and `-wrapper.asm` files
retain branch-complete evidence for absence of an equivalent early rejection
and exact wrapper-to-internal-function routing.

`kernel-timerfd-cve-2017-10661.asm` binds same-file context identity,
membership/list fields, narrow global locking, later waitqueue locking, and the
absent fixed per-context critical region underlying V-026.

`kernel-unix-peek-cve-2021-0920.asm` binds both MSG_PEEK branches, attached-file
`scm_fp_dup` calls, SCM-cookie continuity, exact global GC-lock identity, and
absence of a direct or indirect barrier underlying V-025.

`kernel-tty-pgrp-cve-2020-29661.asm` binds target/real TTY identities,
reciprocal UNIX98 PTY links, exact pgrp/lock offsets, and same-field updates
under distinct master/slave locks underlying V-024.

`kernel-tty-session-cve-2020-29660.asm` binds `TIOCGSID` dispatch, the unlocked
session null-test/reload/dereference sequence, two same-field writer lifetime
transitions, and exact `pid_vnr` object dereferences underlying V-027.

`kernel-mremap-cve-2018-18281.asm` binds ordinary PTE transfer, exact
source/destination PTL acquisition and release, deferred-flush state, and the
old-range `flush_tlb_mm_range` call underlying V-023.

`kernel-vmacache-cve-2018-17182.asm` retains both live 32-bit invalidation
edges, exact zero-wrap calls, the single-user no-clear flush route, independent
`mmput` user-count binding, and 32-bit lookup generation effects underlying
V-022.

`kernel-sysvipc-cve-2015-7613.asm`,
`kernel-recvmmsg-cve-2016-7117.asm`, and
`kernel-inet-csk-cve-2017-8890.asm` retain the initialization/publication,
socket-release, and multicast-child field effects needed to reject those three
version-derived local-kernel candidates.

`snd-timer-2016-backports.asm` retains the list initialization, per-user ioctl
mutex, slave-active singleton lock, timer lock, and complete ack/active unlink
effects needed to reject CVE-2016-2545 through CVE-2016-2548 for exact
`snd-timer.ko`.

`snd-seq-queue-cve-2016-2544.asm` retains the queue timer-mutex region around
stop and close. `snd-timer-padding-cve-2016-4569-4578.asm` retains the complete
32-byte queue/read copies, fixed params/general-callback initialization, and
unfixed timer-interrupt padding paths underlying V-021.

`snd-usbmidi-cve-2016-2384.asm` retains raw-MIDI ownership assignment,
post-registration endpoint-failure branches, direct error returns, and the
owner's legitimate private-free callback. The absence of the second cleanup
after ownership transfer matches the upstream fix.

`mq-notify-cve-2017-11176.asm` retains the return-one retry, failed-lookup
cleanup, detach cleanup, and callee reference-release branches needed to review
the semantic backport. The missing explicit register clear is not treated as a
missing fix: exact failed-retry branches bypass detach, which is equivalent to
the source-level `sock = NULL` assignment.

`alsa-seq-probe-result.json` is the retained machine-readable benign reachability
result. It contains no firmware binary, proprietary module, credential, payload,
or personal identifier.
