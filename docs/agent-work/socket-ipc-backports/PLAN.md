# Socket and SysV IPC exact-backport plan

## Goal

Assess CVE-2015-7613, CVE-2016-7117, and CVE-2017-8890 against exact recovered
kernel instructions without executing target syscalls or races.

## Acceptance criteria

1. Bind every conclusion to exact kernel SHA-256, Build ID, half-open function
   ranges, virtual addresses, and file offsets.
2. Retain authoritative upstream fix patches.
3. Verify all three required SysV initialization/publication orderings.
4. Verify socket error state is written before `fput_light` in `recvmmsg`.
5. Bind the cloned child multicast clear to the field used by
   `ip_mc_drop_socket`.
6. Preserve a boolean-only model that cannot overstate runtime exploitation.

## Exclusions

No socket traffic, multicast membership, SysV IPC object, race, target syscall,
corruption attempt, payload, root transition, persistence, or physical action.
