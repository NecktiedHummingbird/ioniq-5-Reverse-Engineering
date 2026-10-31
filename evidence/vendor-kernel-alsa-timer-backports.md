# Vendor ALSA timer 2016 backport assessment

Date: 2026-11-01
Target: recovered EU `260128` Linux `4.1.27-abl` ALSA timer module

## Result

CVE-2016-2545, CVE-2016-2546, and CVE-2016-2547 are **rejected for the exact
recovered `snd-timer.ko`**. The module contains the upstream list-state,
ioctl/release serialization, and slave/timer lock-and-unlink effects.

This is not a version conclusion. `CONFIG_SND_TIMER=m`, the module is shipped,
and installed udev policy requests static `/dev/snd/timer` state with intended
root ownership and mode `0644`; those facts made exact review worthwhile.
Runtime module load, node metadata, effective labels, and caller access remain
unobserved.

## Provenance and address space

- path:
  `lib/modules/4.1.27-abl/kernel/sound/core/snd-timer.ko`;
- SHA-256:
  `3b2fa4e722ff210c2643089b2035a4ba93134ad1624e0c520bafa6debac46a91`;
- GNU Build ID: `42457bdb4c6cd4911a707afac6912e23d735b68a`;
- x86-64 `ET_REL`;
- `.text` file offset `0x64`, size `0x2d44`;
- all addresses below are `.text` section-relative, not loaded runtime VAs;
- a cited instruction's ELF file offset is its section address plus `0x64`.

## CVE-2016-2545 — expired active-list state

Upstream commit `ee8413b01045c74340aa13ad5bdf905de32be736` replaces `list_del()`
with `list_del_init()` when a non-auto timer instance expires, so a later stop
cannot delete an already unlinked active-list node through stale linkage.

Exact `snd_timer_interrupt` is `[0x111e,0x1414)`. On the non-auto expiry path:

1. `[rbp-0x38]` is the current `timeri` derived from the timer's active list;
2. `0x11a8..0x11ac` derives `rdi=timeri+0x80` from that same object, with no
   intervening call or object substitution before deletion;
3. `0x122c..0x122f` clears the running flag and `0x1232` decrements
   `timer->running`; and
4. `0x1238` calls the module's exact `list_del_init` helper. This is the only
   active-list deletion on the reviewed non-auto-expiry branch and dominates
   continuation from that state transition.

The named stale-list-state premise is absent.

Authoritative fix:
<https://git.kernel.org/linus/ee8413b01045c74340aa13ad5bdf905de32be736>.

## CVE-2016-2546 — concurrent timer ioctls and release

Upstream commit `af368027a49a751d6ff4ee9e3f9961f35bb4fede` serializes the entire
ioctl dispatcher with a per-user `ioctl_lock`, and takes the same lock around
timer close during file release. This prevents parallel state-changing ioctls
and release from racing timer-instance selection/freeing.

Exact target effects:

- `snd_timer_user_open` initializes exact `__mutex_init(user+0x90)` at `0x1ab3`
  before storing that same user pointer at `file+0xd0` at `0x1af0`;
- `snd_timer_user_ioctl` is `[0x236d,0x2d44)`;
- `0x2398..0x23a9` reloads the user object from `file+0xd0`, derives the same
  `user+0x90` mutex, and calls exact `mutex_lock` before command dispatch;
- the function has one returning block. Every returning ioctl route passes
  `0x2cda..0x2cdd`, which calls exact `mutex_unlock`; the stack-check failure is
  non-returning;
- the file-operations relocation table has one ioctl target, `.text+0x236d`,
  and no alternate compat-ioctl target;
- `snd_timer_user_release` is `[0x17cc,0x182f)`;
- it reloads that same per-file object from `file+0xd0`, clears the file field,
  derives the initialized `user+0x90` mutex, locks at `0x17f4`, calls exact
  `snd_timer_close` at `0x1801` while still holding it, unlocks at `0x1809`, and
  only then frees user buffers and the user object. The close callee does not
  access or release the enclosing user-object mutex.

The published missing-ioctl-serialization premise is absent.

Authoritative fix:
<https://git.kernel.org/linus/af368027a49a751d6ff4ee9e3f9961f35bb4fede>.

## CVE-2016-2547 — slave/master timer list races

Upstream commit `b5a663aa426f4884c71cd8580adae73f33570f0d` adds four coordinated
effects: timer locking while attaching a slave, lock coverage and explicit
ack/active unlinking while closing a master, timer locking around delayed slave
start, and explicit list reinitialization during slave stop.

All four are present. Every cited global lock relocation names the same
`.bss+0x290` singleton. Each nested timer lock is derived as `timer+0x130` from
the exact timer associated with the affected master, and the attach, close,
delayed-start, and slave-stop routes consistently acquire the global lock
before a nested timer lock:

1. **Attach in `snd_timer_open` `[0x1da9,0x2153)`:** the exact global
   slave-active lock at `0x20a9` is followed by the master timer lock at
   `0x20b8`; slave `master`/`timer` assignment and optional active-list insertion
   occur before the nested unlocks at `0x210e` and `0x211a`.
2. **Master close in `snd_timer_close` `[0x15ad,0x17cc)`:** the global
   slave-active lock and timer lock are acquired at `0x16ea` and `0x16f2`.
   Within both locks, each slave is moved, its master/timer pointers are nulled,
   and its ack and active links are passed to exact `list_del_init` at `0x173e`
   and `0x174a`; locks are released at `0x175f` and `0x176b`.
3. **Delayed start in `snd_timer_start_slave` `[0xd0,0x190)`:** it takes the
   global slave-active lock at `0xe3` *before* checking both master (`+0xc0`) and
   timer (`+0`). Those pointers therefore remain protected while it derives and
   locks `timer+0x130` at `0x12c`, inserts the same instance's active link, then
   unlocks in reverse order.
4. **Stop in `_snd_timer_stop` `[0xf03,0x10b0)`:** the slave branch holds the
   global slave-active lock, conditionally holds the timer lock, clears running
   state, and invokes exact `list_del_init` on ack (`+0x90`) and active
   (`+0x80`) links at `0xf6e` and `0xf7a`. The ordinary stop branch contains the
   same pair at `0xfea` and `0xff6`.

The exact missing-lock/missing-unlink premise addressed by CVE-2016-2547 is
absent.

Authoritative fix:
<https://git.kernel.org/linus/b5a663aa426f4884c71cd8580adae73f33570f0d>.

## Retained evidence

- `evidence/artifacts/kernel-candidates/snd-timer-2016-backports.asm`;
- `evidence/artifacts/kernel-candidates/cve-2016-2545-fix.patch`;
- `evidence/artifacts/kernel-candidates/cve-2016-2546-fix.patch`;
- `evidence/artifacts/kernel-candidates/cve-2016-2547-fix.patch`.

The excerpts retain relocations identifying external lock and close calls.
Exact LLVM disassembly is authoritative; no source-version inference is used.

## Claim boundary

The result rejects only the three named primitives for this module identity. It
does not establish the owner's installed module, runtime load, device-node
mode, uid/group membership, SMACK label, or absence of unrelated ALSA timer
bugs. No module was loaded; no timer node was opened; and no ioctl, parallel
thread, race, target execution, corruption attempt, payload, root transition,
policy escape, or persistence mechanism was created or run.
