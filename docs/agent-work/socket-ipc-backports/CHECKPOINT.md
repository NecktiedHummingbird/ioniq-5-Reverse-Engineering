# Socket and SysV IPC exact-backport checkpoint

Status: complete — all three candidates rejected for recovered `260128` kernel.

## Results

- CVE-2015-7613: effective credentials, message-queue state, and shared-memory
  state are all initialized before IDR/IPC publication.
- CVE-2016-7117: the delayed socket-error store precedes exact `fput_light`.
- CVE-2017-8890: the cloned child clears the exact `mc_list` field used by
  `ip_mc_drop_socket`.
- No version-only conclusion is used.

## Deliverables

- `evidence/vendor-kernel-socket-ipc-backports.md`
- three retained instruction excerpts and three authoritative patches under
  `evidence/artifacts/kernel-candidates/`
- `tools/uk_fw/kernel_backport_matrix.py`
- `tests/test_kernel_backport_matrix.py`

## Boundary

The result rejects only these named primitives for exact recovered `vmlinux`.
No target syscall, race, socket traffic, multicast operation, IPC object,
corruption attempt, or privilege transition was executed.
