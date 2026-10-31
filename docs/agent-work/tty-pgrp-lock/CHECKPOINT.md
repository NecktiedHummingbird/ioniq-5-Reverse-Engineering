# TTY CVE-2020-29661 exact-lock checkpoint

Status: complete — exact wrong-object-lock premise accepted as V-024.

## Result

- UNIX98 PTY installation creates distinct reciprocal peer objects.
- Master ioctl routing substitutes linked slave as `real_tty`; slave routing
  retains target and real object identity.
- TIOCSPGRP locks target `+0x128` while releasing/replacing real TTY pgrp PID at
  `+0x1d0`.
- `tty_get_pgrp` independently binds those lock and field offsets.
- Master and slave setters can therefore update one slave pgrp under different
  locks on an SMP kernel.
- Shipped boot scripts intend `/dev/ptmx` mode `0666` and devpts; runtime state
  remains unobserved.
- Two frozen semantic reviews and the model code review returned `ACCEPT`.

## Deliverables

- `evidence/vendor-kernel-tty-pgrp-cve-2020-29661.md`
- `evidence/artifacts/kernel-candidates/kernel-tty-pgrp-cve-2020-29661.asm`
- `evidence/artifacts/kernel-candidates/cve-2020-29661-fix.patch`
- `tools/uk_fw/tty_pgrp_lock_model.py`
- `tests/test_tty_pgrp_lock_model.py`
- passive `/dev/ptmx` and `/dev/pts` metadata in `bench_state_bundle.py`

## Boundary

No runtime PTY exposure, ioctl, successful interleaving, PID reference-count
imbalance, UAF, controlled reuse, corruption, code execution, root, policy
escape, or persistence was executed or established.
