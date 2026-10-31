# ALSA timer 2016 exact-backport plan

## Goal

Assess CVE-2016-2545 through CVE-2016-2548 against exact recovered
`snd-timer.ko` without loading the module, opening a node, issuing an ioctl, or
running a race.

## Acceptance criteria

1. Bind evidence to module SHA-256, Build ID, ELF section, section-relative
   addresses, relocations, and file-offset conversion.
2. Confirm expiry uses `list_del_init` on the same current active-list object.
3. Confirm one initialized per-user mutex covers all ioctl returns and timer
   close during release.
4. Confirm all CVE-2016-2547/2548 global/timer lock-and-unlink effects with
   exact lock and object identity.
5. Retain authoritative upstream patches and reviewed instruction excerpts.

## Exclusions

No module load, timer node, ioctl, parallel thread, race, target execution,
corruption attempt, payload, privilege transition, or persistence.
