# ALSA timer 2016 exact-backport checkpoint

Status: complete — three named primitives rejected for exact module.

## Results

- CVE-2016-2545: fixed `list_del_init` effect is present on non-auto expiry.
- CVE-2016-2546: one open-initialized user mutex serializes the sole ioctl
  dispatcher and release-through-close path.
- CVE-2016-2547: all four upstream changed routes carry matching lock identity,
  order, and link cleanup.
- Independent frozen semantic review returned `ACCEPT` after object, dominance,
  exit, file-operations, and lock-identity proof was made explicit.

## Deliverables

- `evidence/vendor-kernel-alsa-timer-backports.md`
- `evidence/artifacts/kernel-candidates/snd-timer-2016-backports.asm`
- three authoritative fixes under `evidence/artifacts/kernel-candidates/`

## Boundary

No runtime module/interface state was observed. No module, node, ioctl, thread,
race, target execution, or privilege transition was used.
