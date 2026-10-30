# Vendor kernel ALSA follow-up — CVE-2017-0861 and CVE-2018-1000004

Date: 2026-11-01
Target: recovered EU `260128` Linux `4.1.27-abl`

## Result

Two ALSA candidates adjacent to V-013 have different outcomes:

- **CVE-2017-0861 is fixed** in exact shipped `snd-pcm.ko`. The PCM control
  ioctl takes the per-PCM `open_mutex` around `snd_pcm_info_user`, matching the
  complete upstream fix.
- **CVE-2018-1000004 lacks the official serialization fix** in exact shipped
  `snd-seq.ko`. Its native sequencer ioctl dispatcher calls handlers without the
  per-client serialization added upstream and in Linux 4.1 stable. However, the
  published sequence requires a successful `write()` plus two overlapping
  pool-setting ioctls. Recovered intended udev policy is `root:root 0644`; the VM
  confirmed ioctl reachability through an `O_RDONLY` descriptor under that
  manually modeled mode, but an ordinary non-owner cannot open the node for
  writing. The published unprivileged sequence is therefore blocked by DAC
  under that recovered policy.

Neither result supplies a local-root path.

## CVE-2017-0861 — exact fix present

Component:

- `/lib/modules/4.1.27-abl/kernel/sound/core/snd-pcm.ko`;
- SHA-256:
  `9a1f126d6919812d3e7c6d7c9def51a698564cdfb22b9ebc72022c6e87d19fb9`.

Upstream commit `362bca57f5d78220f8b5907b875961af9436e229` prevents
`snd_pcm_info()` from racing a close that frees `substream->runtime`. Its entire
change is to lock `pcm->open_mutex` around `snd_pcm_info_user()` in
`snd_pcm_control_ioctl()`.

The shipped function begins at module `.text+0x0c6c`. It first takes the global
`register_mutex` at `+0x0d98`, finds the PCM/substream, and then executes:

```text
0x0e4b  lea  rbx,[rdi+0x6a8]   # per-PCM open mutex
0x0e52  mov  rdi,rbx
0x0e55  call mutex_lock
0x0e5a  mov  rdi,r13           # substream
0x0e5d  mov  rsi,r12           # user info
0x0e60  call snd_pcm_info_user
0x0e65  mov  rdi,rbx
0x0e6b  call mutex_unlock
```

It then reaches the existing global-register-mutex unlock. Shipped
`snd_pcm_release` independently computes the same `pcm+0x6a8` address, locks it
before releasing the substream, and unlocks it afterwards. This identifies the
field by both sides of the race and matches the upstream patch's placement and
scope. The CVE-2017-0861 missing-lock premise is rejected for recovered EU
`260128`.

Tracked review inputs:

- `evidence/artifacts/kernel-candidates/cve-2017-0861-fix.patch`;
- `evidence/artifacts/kernel-candidates/snd-pcm-control-ioctl.asm`;
- `evidence/artifacts/kernel-candidates/snd-pcm-release.asm`;
- `evidence/artifacts/kernel-candidates/README.md`.

## CVE-2018-1000004 — official serialization absent, unprivileged write blocked

Component:

- `/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko`;
- SHA-256:
  `ccc802452bb4ac4527d2def96ddef463211c03ae2c07d9003fdc7ebed9eb091d`.

Upstream commit `b3defb791b26ea0683a93a4f49c77ec45ec96f10` adds an
`ioctl_mutex` to each sequencer client and serializes ioctl handler calls. Its
Linux 4.1 stable equivalent,
`f8a38ab4cd9624fc5ac8a7f965c7b20f5b62c03c`, applies the lock directly in
`snd_seq_do_ioctl()`, matching the target's source generation. The mutex breaks
the published sequence by preventing two `SET_CLIENT_POOL` ioctl handlers from
overlapping; a concurrent `write()` is also part of that sequence but is not
itself serialized by this mutex.

The shipped `snd_seq_do_ioctl` begins at module `.text+0x1621`. For ordinary
commands it searches the handler table and dispatches directly:

```text
0x167c  mov  edx,[r8]
...
0x1687  mov  rsi,r12
0x168a  call qword ptr [r8+0x8]
0x168e  mov  ebx,eax
```

There is no `mutex_lock` or `mutex_unlock` anywhere in the shipped dispatcher.
The outer native `snd_seq_ioctl` at `+0x172d` also calls it directly without
locking. `seq_create_client1` initializes only the existing mutex at client
`+0x98`; there is no second ioctl-mutex initialization before the output pool
pointer at `+0xc8`. `snd_seq_ioctl_set_client_pool` itself contains no mutex
operation. Together these establish that the official Linux 4.1 per-client
ioctl serialization is absent from the native user path. They do not assert
that every imaginable vendor-specific alternative mitigation is absent.

The public mechanism is not just a single ioctl: a `write()` exhausts the pool
and sleeps while two `SET_CLIENT_POOL` ioctl executions overlap and replace pool
state. The recovered intended udev rule assigns `/dev/snd/seq`
`root:root 0644`. Consequently:

- the VM confirmed that uid/gid 65534 can open it `O_RDONLY` and issue
  create/delete ioctls under a manually modeled `root:root 0644` node;
- mode `0644` does not grant uid/gid 65534 write permission or an `O_RDWR` open;
- a read-only descriptor cannot drive the required `write()` half of the race.

This DAC boundary is stronger than a mere absence of dynamic reproduction. It
blocks the published unprivileged trigger under the recovered mode. It does not
repair the code and does not protect a process that already has root, a granted
write-capable descriptor, altered node permissions, or an unexpectedly
permissive production policy. Application-specific SMACK behavior and the
owner's installed firmware remain unknown.

Tracked review inputs:

- mainline fix:
  `evidence/artifacts/kernel-candidates/cve-2018-1000004-fix.patch`;
- Linux 4.1 stable fix:
  `evidence/artifacts/kernel-candidates/cve-2018-1000004-stable-4.1-fix.patch`;
- `evidence/artifacts/kernel-candidates/snd-seq-do-ioctl.asm`;
- `evidence/artifacts/kernel-candidates/snd-seq-create-client.asm`;
- `evidence/artifacts/kernel-candidates/snd-seq-set-client-pool.asm`;
- `evidence/artifacts/kernel-candidates/README.md`.

## Classification

| Candidate | Exact code | Ordinary uid under recovered mode | Current disposition |
|---|---|---|---|
| CVE-2017-0861 | fixed | hardware-dependent PCM control path not dynamically modeled | rejected for recovered EU `260128` |
| CVE-2018-1000004 | official Linux 4.1 serialization absent from native ioctl path | ioctls work through `O_RDONLY`; required sequencer write denied by `0644` | conditional privileged/permission-regression DoS/UAF surface, not local root |

## Remediation

Retain the CVE-2017-0861 open-mutex fix. Backport the target-appropriate
stable equivalent of `b3defb791b26ea0683a93a4f49c77ec45ec96f10` (Linux 4.1
commit `f8a38ab4cd9624fc5ac8a7f965c7b20f5b62c03c`) even though current DAC policy
blocks the ordinary-user write path; DAC and SMACK policy should be defense in
depth, not the memory-lifetime fix. Add a regression that denies write access to
untrusted application domains and stress-tests concurrent sequencer writes and
pool-setting ioctls under a privileged test identity.
