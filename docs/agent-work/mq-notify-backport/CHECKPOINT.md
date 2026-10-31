# CVE-2017-11176 exact-kernel backport checkpoint

Status: complete — candidate rejected for recovered `260128` kernel.

## Result

- Exact `vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`.
- `CONFIG_POSIX_MQUEUE=y`; version/configuration made the candidate statically
  relevant.
- `netlink_attachskb` drops the old socket reference before returning one.
- `sys_mq_notify` loops on one without an explicit register clear.
- Both failed retry lookup paths bypass socket-detach cleanup and enter skb-only
  cleanup, giving the semantic effect of upstream `sock = NULL`.
- CVE-2017-11176's reference-overrelease primitive is therefore absent in this
  exact kernel.

## Deliverables

- `evidence/vendor-kernel-mq-notify-backport.md`
- `evidence/artifacts/kernel-candidates/mq-notify-cve-2017-11176.asm`
- `evidence/artifacts/kernel-candidates/cve-2017-11176-fix.patch`
- `tools/uk_fw/mq_notify_retry_model.py`
- `tests/test_mq_notify_retry_model.py`

## Boundary

This does not assess unrelated message-queue/netlink defects or the owner's
unknown installed build. No race, target syscall, corruption attempt, or
privilege transition was executed.
