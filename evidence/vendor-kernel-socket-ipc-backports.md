# Vendor kernel socket and SysV IPC backport assessment

Date: 2026-11-01
Target: recovered EU `260128` Linux `4.1.27-abl`

## Result

Three additional unprivileged local-kernel candidates are **rejected for the
exact recovered `vmlinux`**:

- CVE-2015-7613, SysV IPC object publication before initialization;
- CVE-2016-7117, `recvmmsg` socket use after `fput_light`;
- CVE-2017-8890, inherited IPv4 multicast-list double free in accepted sockets.

All three affected facilities are compiled in and ordinary callers do not need
user namespaces or a special device, so version-only triage made them credible
local-escalation candidates. Exact ordering and initialization effects show the
vendor kernel contains each upstream fix semantics.

## Common provenance

- recovered `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`;
- GNU Build ID: `273378887b4cf563c10862fdf18b2292765df781`;
- x86-64 `ET_EXEC`;
- `.text`: VA `0xffffffff81000000`, file offset `0x200000`;
- recovered kernel configuration SHA-256:
  `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`;
- `CONFIG_SYSVIPC=y`, networking and IPv4 are built in.

## CVE-2015-7613 — SysV IPC publication order

### Upstream defect

The vulnerable ordering made new message-queue/shared-memory objects visible
through the IPC ID registry before all security and object fields were
initialized. Upstream fix `b9a532277938798b53178d5a66af6e2915cb27cf` moved:

1. effective uid/gid assignment before `idr_alloc()` in `ipc_addid()`;
2. message-queue times, counters and list-head initialization before
   `ipc_addid()` in `newque()`; and
3. shared-memory creator, time, attachment, file and owner initialization before
   `ipc_addid()` in `newseg()`.

Authoritative fix:
<https://git.kernel.org/linus/b9a532277938798b53178d5a66af6e2915cb27cf>.

### Exact target effect

- `ipc_addid` is `[0xffffffff811aa199,0xffffffff811aa294)`.
- Exact effective uid/gid loads and all four `uid/cuid/gid/cgid` stores at
  `0xffffffff811aa1e5..0xffffffff811aa214` dominate the function's sole
  `idr_alloc` call at `0xffffffff811aa22c`.
- `newque` is `[0xffffffff811aaa0c,0xffffffff811aab37)`. On the successful
  security-allocation path, one straight-line block initializes `q_stime`,
  `q_rtime`, `q_ctime`, `q_cbytes`, `q_qnum`, `q_qbytes`, `q_lspid`, `q_lrpid`,
  and all three list heads at `0xffffffff811aaa79..0xffffffff811aaaed`. It then
  passes that same object in `rsi=rbx` to the function's sole `ipc_addid` call
  at `0xffffffff811aaafc`.
- `newseg` is `[0xffffffff811ae626,0xffffffff811ae919)`. On the successful file
  creation path, one straight-line block initializes `shm_cprid`, `shm_lprid`,
  `shm_atim`, `shm_dtim`, `shm_ctim`, `shm_segsz`, `shm_nattch`, `shm_file`,
  and `shm_creator` at `0xffffffff811ae7fe..0xffffffff811ae83f`. It passes the
  same object in `rsi=rbx` to the function's sole `ipc_addid` call at
  `0xffffffff811ae84a`.

The exact publication-before-initialization premise is absent.

## CVE-2016-7117 — `recvmmsg` release ordering

### Upstream defect

When `recvmmsg` had already received at least one datagram and later encountered
a non-`EAGAIN` error, vulnerable code called `fput_light(sock->file, ...)` before
writing the delayed error into `sock->sk->sk_err`. Another thread could close
the last reference, leaving the subsequent socket dereference stale. Upstream
fix `34b88a68f26a75e4fded796f1a49c40f82234b7d` moves all result handling and the
`sk_err` store before `fput_light`.

Authoritative fix:
<https://git.kernel.org/linus/34b88a68f26a75e4fded796f1a49c40f82234b7d>.

### Exact target effect

- `__sys_recvmmsg` is
  `[0xffffffff81475c1d,0xffffffff81475e13)`.
- `sockfd_lookup_light` returns the retained socket in `r15` at
  `0xffffffff81475c6a..0xffffffff81475c72`.
- The delayed `sk_err` store occurs at `0xffffffff81475dca..0xffffffff81475dd0`.
- All reference-owning result branches join at `0xffffffff81475ddb`; only
  afterward does `0xffffffff81475de5` make the function's sole exact
  `fput_light` call. There is no earlier equivalent release on the delayed
  error-store path.
- The store file offset is `0x675dd0`; the release call file offset is
  `0x675de5`.

The exact post-release socket-dereference premise is absent.

## CVE-2017-8890 — inherited IPv4 multicast state

### Upstream defect

A cloned accepted socket inherited its listening socket's `inet_sock.mc_list`.
Both sockets could later tear down the same multicast membership list. Upstream
fix `657831ffc38e30092a2d5f03d385d710eb88b09a` explicitly clears the child
`mc_list` in `inet_csk_clone_lock()`.

Authoritative fix:
<https://git.kernel.org/linus/657831ffc38e30092a2d5f03d385d710eb88b09a>.

### Exact target effect

- `inet_csk_clone_lock` is
  `[0xffffffff814d22f5,0xffffffff814d23ab)`.
- The clone call produces the child in `rbx`. Its non-null successful path
  unconditionally executes `0xffffffff814d2357`, storing zero to child offset
  `+0x2e8`. No later instruction in the function writes that field, and this
  clear dominates the sole child-return block at `0xffffffff814d23a3`.
- Exact `ip_mc_drop_socket` independently checks, loads, and updates
  `inet_sock+0x2e8` at `0xffffffff814fbe45`, `0xffffffff814fbe75`, and
  `0xffffffff814fbe88`, binding that offset to the multicast-list field rather
  than relying only on source structure layout.
- The clear file offset is `0x6d2357`.

The child does not inherit the listener's multicast-list pointer, so the named
double-free premise is absent.

## Retained evidence and model

Reviewed instruction excerpts:

- `evidence/artifacts/kernel-candidates/kernel-sysvipc-cve-2015-7613.asm`;
- `evidence/artifacts/kernel-candidates/kernel-recvmmsg-cve-2016-7117.asm`;
- `evidence/artifacts/kernel-candidates/kernel-inet-csk-cve-2017-8890.asm`.

Authoritative one-hunk patches are retained alongside them. Numeric/boolean-only
`tools/uk_fw/kernel_backport_matrix.py` records the five required semantic facts
and rejects a SysV fix classification unless all three publication orders are
fixed. It labels the target state as pre-recorded and unverified by model
execution. Deterministic no-argument report SHA-256:
`01a8084d9c9f00885777163a895e9d7aae86629897509c01a4a4253b69df2905`.

## Claim boundary

These conclusions reject only the three named primitives for this exact
`vmlinux`. They do not prove the socket, multicast or SysV IPC subsystems free
of other defects; establish the owner's installed kernel; or prove runtime
SMACK, seccomp, namespace, interface or service state.

No socket traffic, multicast membership, SysV IPC object, race, target syscall,
kernel execution, corruption attempt, payload, root transition, policy escape,
or persistence mechanism was created or run.
