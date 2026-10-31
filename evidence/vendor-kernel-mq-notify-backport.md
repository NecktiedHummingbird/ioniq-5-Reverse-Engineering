# Vendor kernel POSIX message-queue assessment — CVE-2017-11176

Date: 2026-11-01
Target: recovered EU `260128` Linux `4.1.27-abl`

## Result

CVE-2017-11176 is **rejected for the exact recovered kernel**. The affected
POSIX message-queue and netlink code is compiled in, but exact x86-64 control
flow contains the semantic effect of upstream fix
`f991af3daabaecff34684fd51fac80319d1baad1`.

The important result is not the absence or presence of one zeroing opcode. The
return-one edge does not explicitly clear the socket register before looping,
but every failed retry lookup routes directly to notification-skb cleanup. The
stale pre-retry socket value cannot reach `netlink_detachskb`. This is a
compiler representation of `sock = NULL`, so the published reference
over-release premise is absent.

## Provenance and configuration

- recovered `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`;
- GNU Build ID: `273378887b4cf563c10862fdf18b2292765df781`;
- recovered kernel configuration SHA-256:
  `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`;
- `CONFIG_POSIX_MQUEUE=y` and `CONFIG_POSIX_MQUEUE_SYSCTL=y`;
- recovered kallsyms table SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`;
- `sys_mq_notify` half-open VA range:
  `[0xffffffff811b1580,0xffffffff811b18da)`;
- `netlink_attachskb` half-open VA range:
  `[0xffffffff814a8c37,0xffffffff814a8dc5)`;
- ELF `.text` mapping: VA `0xffffffff81000000`, file offset `0x200000`.

The old kernel banner and reachable configuration made this a valid candidate
to check. They did not establish that the downstream binary lacked the fix.

## Upstream ownership defect

The authoritative one-hunk fix adds `sock = NULL` when
`netlink_attachskb()` returns one before retrying the descriptor lookup. The
callee has already dropped the old socket reference on that edge. In vulnerable
source, a failed `fdget()` on the retry can therefore leave the old non-null
pointer for common cleanup, which calls `netlink_detachskb()` and releases the
socket again.

Authoritative sources:

- mainline fix and metadata:
  <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f991af3daabaecff34684fd51fac80319d1baad1>;
- mainline one-hunk diff:
  <https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/f991af3daabaecff34684fd51fac80319d1baad1%5E%21/>;
- stable pre-fix Linux 4.1.42 source:
  <https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux/+/refs/tags/v4.1.42/ipc/mqueue.c>;
- stable fixed Linux 4.1.43 source:
  <https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux/+/refs/tags/v4.1.43/ipc/mqueue.c>;
- CVE record:
  <https://nvd.nist.gov/vuln/detail/CVE-2017-11176>.

The tracked patch is
`evidence/artifacts/kernel-candidates/cve-2017-11176-fix.patch`.

## Exact target data flow

Recovered symbol mapping identifies:

- `r12` as the local `sock` value around the relevant branch;
- `rbx` as notification skb `nc`;
- `0xffffffff814a8bf8` as `netlink_getsockbyfilp`;
- `0xffffffff814a8c37` as `netlink_attachskb`;
- `0xffffffff814a94c4` as `netlink_detachskb`;
- `0xffffffff814a61eb` as `sock_put`.

At `0xffffffff811b16f2`, `sys_mq_notify` calls `netlink_attachskb`. It compares
the result with one at `0xffffffff811b16f7` and loops to
`0xffffffff811b1694` at `0xffffffff811b16fd`. There is no explicit `xor r12d,
r12d` or equivalent zero store on that edge.

That absence is not a vulnerability signature. The retry failure successors
matter:

1. `fdget` failure branches at `0xffffffff811b16a9` to
   `0xffffffff811b1709`, which records `-EBADF` and jumps directly to
   `0xffffffff811b18a4`.
2. An error from `netlink_getsockbyfilp` is detected at
   `0xffffffff811b16c7..0xffffffff811b16d3` and also jumps directly to
   `0xffffffff811b18a4`.
3. `0xffffffff811b18a4` tests/frees only `rbx` (`nc`). It does not call
   `netlink_detachskb`.
4. The socket-detach block is separately rooted at `0xffffffff811b1892`; neither
   failed retry edge reaches it with the old `r12` value.
5. In exact `netlink_attachskb`, `0xffffffff814a8d59` calls `sock_put` before
   setting return value one at `0xffffffff814a8d66`, confirming the ownership
   transition whose stale cleanup the CVE requires.

Corresponding file offsets are obtained from the `.text` mapping. The attach
call/test/retry instructions are at `0x3b16f2`, `0x3b16f7`, and `0x3b16fd`;
the detach cleanup starts at `0x3b1892`; skb-only cleanup starts at
`0x3b18a4`; and the callee's release/return-one block begins at `0x6a8d56`.

Reviewed bytes and reproduction ranges are retained in
`evidence/artifacts/kernel-candidates/mq-notify-cve-2017-11176.asm`.

## Bounded model

`tools/uk_fw/mq_notify_retry_model.py` records both valid fix
representations:

- explicit pointer clearing before retry; and
- equivalent cleanup routing that prevents the old pointer from reaching
  detach.

For the pre-recorded exact-target state `(attach drops reference=true,
explicit clear=false, retry fdget failure reaches socket-detach cleanup=false)`,
it reports `fixed-equivalent-cleanup-routing`. The report explicitly says that
this state comes from separate instruction review and is not verified by model
execution. The tool accepts booleans only and does not
invoke message queues, netlink, races, target executables, or target syscalls.
It cannot extract data flow from an arbitrary binary; the exact LLVM review is
the evidence for its supplied state. The deterministic no-argument report
SHA-256 is
`06d6a4354c2a6c4e1eeda1f7ff653a79a90b1ffdaca7029b62dc221a1ec8c3c4`.

## Claim boundary

This rejects only CVE-2017-11176's stale-socket reference over-release in the
recovered `vmlinux`. It does not prove that POSIX message queues or netlink are
free of other defects, that the owner's unknown installed kernel is identical,
or that every local kernel-escalation candidate is fixed.

No message-queue race, heap manipulation, corruption attempt, exploit payload,
root transition, SMACK escape, persistence mechanism, or recovered target
executable was run or created.
