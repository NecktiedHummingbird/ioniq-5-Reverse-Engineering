# ALSA sequencer assessment checkpoint

Status: complete, 2026-11-01.

## Outcome

- Exact `snd-seq.ko` SHA-256:
  `ccc802452bb4ac4527d2def96ddef463211c03ae2c07d9003fdc7ebed9eb091d`.
- Shipped `snd_seq_create_port`/`snd_seq_ioctl_create_port` lack the use-lock
  acquisition and matching releases from CVE-2017-15265's upstream fix.
- Tracked benign runner: `tools/uk_fw/alsa_seq_probe.py`.
- Tracked guest source: `tools/uk_fw/guest/alsa_seq_reachability.S`.
- Probe SHA-256:
  `f12c99be0fd854d5ef7d1402c9ffd2292afe74a1a7b138d4c71d84735c42e5b1`.
- The guest verified the loaded module file against the exact expected module
  digest before `modprobe`; the machine report also records canonical rootfs and
  kernel digests.
- Numeric uid/gid 65534 completed open, client-ID, create-port, and delete-port
  under modeled recovered mode `root:root 0644`.
- Machine classification: `unprivileged-reachable`; tracked result:
  `evidence/artifacts/kernel-candidates/alsa-seq-probe-result.json`.
- A separate bounded crash-only race issued 200,000 create and 400,000 delete
  attempts without a detected kernel fault. This is a negative run, not evidence
  that the missing lifetime fix is harmless.

## Boundaries

V-013 establishes exact pre-fix code and local entry-point reachability. It does
not establish a dynamically observed UAF, controlled reuse, arbitrary read or
write, instruction-pointer control, or root. Production SMACK-domain access and
the owner's installed firmware remain unknown.

Primary report: `evidence/alsa-sequencer-cve-2017-15265.md`.
