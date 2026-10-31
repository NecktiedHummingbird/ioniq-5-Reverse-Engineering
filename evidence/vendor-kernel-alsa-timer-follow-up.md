# Vendor ALSA timer and sequencer follow-up

Date: 2026-11-01
Target: recovered EU `260128` Linux `4.1.27-abl` sound modules

## Result

This follow-up extends the exact ALSA review:

- **CVE-2016-2544 is rejected** for exact `snd-seq.ko`: queue deletion holds the
  queue's timer mutex across exact timer stop and close.
- **CVE-2016-2548 is rejected** for exact `snd-timer.ko`: this is the second CVE
  covered by the already-verified `b5a663aa...` slave lock/list backport, whose
  stop and master-close paths reinitialize both ack and active links.
- **CVE-2016-2549 is unavailable** in this build: `CONFIG_SND_HRTIMER` is not
  set, no `snd-hrtimer.ko` exists, and no shipped module defines the affected
  `snd_hrtimer_start`/`snd_hrtimer_stop` functions.
- **CVE-2016-4569 is rejected** for exact `snd-timer.ko`: the early-event record
  is fully zeroed before named fields and queue insertion.
- **CVE-2016-4578 remains present in one exact callback path**: the general
  callback is fixed, but `snd_timer_user_tinterrupt` does not initialize either
  four-byte padding region in its 32-byte event record before the complete
  record is queued and later copied to userspace.

The supported impact of CVE-2016-4578 is a conditional local kernel-stack
information disclosure, not corruption, code execution, root, SMACK escape, or
persistence. Runtime module load, `/dev/snd/timer` metadata, effective SMACK
labels, provider availability, event generation, and an observed disclosure
remain unverified.

## Exact identities and address spaces

### `snd-timer.ko`

- SHA-256:
  `3b2fa4e722ff210c2643089b2035a4ba93134ad1624e0c520bafa6debac46a91`;
- GNU Build ID: `42457bdb4c6cd4911a707afac6912e23d735b68a`;
- x86-64 `ET_REL`;
- `.text` file offset `0x64`, size `0x2d44`.

### `snd-seq.ko`

- SHA-256:
  `ccc802452bb4ac4527d2def96ddef463211c03ae2c07d9003fdc7ebed9eb091d`;
- GNU Build ID: `596b9160ed31d8fe76da5eb8017e82d990ba2aa6`;
- x86-64 `ET_REL`;
- `.text` file offset `0x64`, size `0x7032`.

All module addresses below are ELF section-relative. File offset is `.text`
address plus `0x64`; no loaded runtime VA is claimed.

## CVE-2016-2544 — sequencer queue timer setup/delete race

Upstream fix `3567eb6af614dac436c4b16a8d426f9faed639b3` takes
`q->timer_mutex` across both timer stop and close during `queue_delete`.

Exact `snd-seq.ko` effects:

- `queue_delete` is `[0x3e61,0x3ed3)`;
- `0x3e67` derives the mutex at `q+0x98`;
- `0x3e75` calls exact `mutex_lock`;
- while holding it, `0x3e7e` calls exact `snd_seq_timer_stop(q->timer)` and
  `0x3e86` calls exact `snd_seq_timer_close(q)`;
- `0x3e8e` calls exact `mutex_unlock` only after both operations;
- queue-resource synchronization/deletion and `kfree` follow the unlock.

This is machine-code-equivalent to the upstream repair. The named unprotected
stop/close premise is absent.

Authoritative fix:
<https://git.kernel.org/linus/3567eb6af614dac436c4b16a8d426f9faed639b3>.

## CVE-2016-2548 — retained slave list nodes

CVE-2016-2547 and CVE-2016-2548 share upstream commit
`b5a663aa426f4884c71cd8580adae73f33570f0d`. The prior review established all
lock changes. It also established both CVE-2016-2548 cleanup effects:

- `_snd_timer_stop` invokes exact `list_del_init` for ack (`timeri+0x90`) and
  active (`timeri+0x80`) links at `0xf6e` and `0xf7a` on the slave branch, with
  the ordinary stop pair at `0xfea` and `0xff6`;
- `snd_timer_close` moves each slave, clears its master/timer pointers, and
  invokes exact `list_del_init` on both links at `0x173e` and `0x174a` while
  holding the global slave-active and timer locks.

The retained-linked-node premise is absent. See
`evidence/vendor-kernel-alsa-timer-backports.md` for the complete lock proof.

Authoritative fix:
<https://git.kernel.org/linus/b5a663aa426f4884c71cd8580adae73f33570f0d>.

## CVE-2016-2549 — hrtimer self-cancellation stall

Upstream fix `2ba1fe7a06d3624f9a7586d672b55f08f7c670f3` replaces synchronous
`hrtimer_cancel` with `hrtimer_try_to_cancel` in ALSA hrtimer start and adds a
non-waiting cancellation in stop.

The exact recovered configuration says `# CONFIG_SND_HRTIMER is not set`. No
`snd-hrtimer.ko` is shipped, and static symbol scans of shipped modules found no
`snd_hrtimer_start` or `snd_hrtimer_stop`. Therefore the affected provider route
is absent in this recovered build. This does not assess unrelated hrtimer users
or the owner's unknown installed build.

Authoritative fix:
<https://git.kernel.org/linus/2ba1fe7a06d3624f9a7586d672b55f08f7c670f3>.

## CVE-2016-4569 — early-event padding

Upstream fix `cec8f96e49d9be372fdb0c3836dcf31ec71e457e` zeroes the complete
stack-local `snd_timer_tread` record before setting its early-event type and
queueing it.

Exact `snd_timer_user_params` is `[0x2153,0x236d)`. On the early-event path:

- `0x22dc` derives the record start at `[rbp-0x98]`;
- `0x22e3..0x22ed` clears eight dwords, exactly 32 bytes;
- `0x22f2` then writes event `6`; and
- `0x22fc` calls the exact queue helper.

Both ABI padding regions are initialized, so the named CVE-2016-4569 disclosure
premise is absent.

Authoritative fix:
<https://git.kernel.org/linus/cec8f96e49d9be372fdb0c3836dcf31ec71e457e>.

## CVE-2016-4578 — partial callback fix and residual disclosure

A native 64-bit `snd_timer_tread` queue record is 32 bytes. Named fields occupy:

- event at bytes `0..3`;
- timestamp at bytes `8..23`;
- value at bytes `24..27`.

Bytes `4..7` and `28..31` are ABI padding. Exact
`snd_timer_user_append_to_tqueue` `[0xb9b,0xbdf)` sets `ecx=8` and uses
`rep movsd`, copying all 32 bytes—including padding—into the queue.

### Fixed general callback

Exact `snd_timer_user_ccallback` `[0xbdf,0xcc3)` derives its record at
`[rbp-0x48]`, sets `ecx=8`, and clears all 32 bytes with `rep stosd` at `0xc40`
before overwriting named fields and queueing the record at `0xc69`. This matches
upstream `9a47e9cff994f37f7f0dbd9ae23740d0f64f9fe6`.

### Unfixed timer-interrupt callback

Exact `snd_timer_user_tinterrupt` `[0xcc3,0xe43)` has two distinct stack
objects:

- a 16-byte timestamp starts at `[rbp-0x68]` and is cleared with four dwords at
  `0xcc4..0xcf9`;
- the emitted 32-byte `snd_timer_tread` starts at `[rbp-0x58]`.

No instruction initializes the complete record or its padding. The resolution
path writes only event, timestamp, and value at `0xd5b`, `0xd6c..0xd70`, and
`0xd62`, then queues `[rbp-0x58]` at `0xd74`. The tick path likewise writes only
named fields at `0xdc6..0xddc` and queues the same record at `0xde0`.

Exact `snd_timer_user_read` later multiplies the queue index by `0x20` and calls
`_copy_to_user` with length `0x20` at `0x19b4..0x19c7`. Thus both untouched
four-byte padding regions are carried through the complete queue and read copy.

Neither the original timer-interrupt fix
`e4ec8cc8039a7063e24204299b462bd1383184a5` nor the complete dominating
initialization from follow-up `a8c006aafead3c45ae5d5601e3717055bccf41bc` is
present in equivalent machine-code form.

Authoritative fixes:

- <https://git.kernel.org/linus/9a47e9cff994f37f7f0dbd9ae23740d0f64f9fe6>;
- <https://git.kernel.org/linus/e4ec8cc8039a7063e24204299b462bd1383184a5>;
- <https://git.kernel.org/linus/a8c006aafead3c45ae5d5601e3717055bccf41bc>.

## Static accessibility and runtime gates

Recovered configuration has `CONFIG_SND_TIMER=m`. Recovered udev policy requests
static `snd/timer`, and `55-audio-perms.rules` expresses intended owner/group
`root:root` and mode `0644` for sound nodes. Exact timer file operations include
open, read, unlocked ioctl, and release; `snd_timer_user_open` and the ioctl
dispatcher contain no `FMODE_WRITE` gate. An `O_RDONLY` descriptor is therefore
sufficient at the generic file-operation layer if policy permits opening it.

That is static intended reachability, not observed owner-device reachability.
Module load, node existence and metadata, effective SMACK access, event provider,
filter setup, timer operation, and successful read all remain runtime gates.

## Model and retained evidence

- `evidence/artifacts/kernel-candidates/snd-timer-padding-cve-2016-4569-4578.asm`;
- `evidence/artifacts/kernel-candidates/snd-seq-queue-cve-2016-2544.asm`;
- authoritative patches under `evidence/artifacts/kernel-candidates/`;
- Boolean-only `tools/uk_fw/alsa_tread_padding_model.py`.

The model records four initialization paths plus complete queue/read copy facts.
It labels the target state as pre-recorded and unverified by model execution and
leaves observed disclosure and privilege escalation `null`. Deterministic
no-argument report SHA-256:
`88cfaa36ede1b3ed4d013bbbb64d8cb4525508a8a23b87f60743d966a122033f`.

## Claim boundary

The exact static evidence supports a conditional CVE-2016-4578 kernel-stack
padding disclosure path. It does not establish actual target bytes, repeated
entropy value, pointer disclosure, KASLR defeat, corruption, controlled write,
code execution, root, SMACK escape, update acceptance, or persistence.

No sound module was loaded; no device was opened; and no ioctl, filter, timer,
event, queue, read, malformed input, race, payload, or privilege transition was
created or run.
