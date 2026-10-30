# ALSA sequencer CVE-2017-15265 assessment plan

## Goal

Determine whether recovered EU `260128` contains the exact vulnerable ALSA
sequencer lifetime flow and whether an unprivileged VM process can reach the
relevant ioctls, without developing a privilege payload.

## Phases

1. Freeze authoritative NVD/advisory/fix inputs and hash the shipped module.
2. Compare `snd_seq_create_port` and `snd_seq_ioctl_create_port` against upstream
   commit `71105998845fb012937332fe2e806d443c09e026`.
3. Build a freestanding diagnostic that performs one read-only open, client-ID
   query, port creation, and port deletion.
4. Run it as numeric uid/gid 65534 in the offline snapshot-backed VM under the
   recovered `root:root 0644` DAC mode.
5. Optionally run a bounded crash-only create/delete stress control in a
   disposable VM; no heap grooming, payload, or privilege action.
6. Publish a conservative evidence report, tests, vulnerability-register entry,
   and correction/backport status.

## Acceptance

- exact module digest and instruction evidence;
- machine-readable benign-probe result;
- no network, host mount, canonical-rootfs write, or exploit payload;
- dynamic non-reproduction is not treated as proof that a fix is present;
- no root or RCE claim without a separately observed primitive.
