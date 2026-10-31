# ALSA timer and sequencer follow-up plan

## Goal

Assess CVE-2016-2544, CVE-2016-2548, CVE-2016-2549, CVE-2016-4569, and
CVE-2016-4578 against exact recovered sound modules without executing a target
module or interface.

## Acceptance criteria

1. Bind every conclusion to exact module hashes, Build IDs, ELF section
   addresses, file-offset conversion, and authoritative upstream fixes.
2. Verify sequencer queue-delete mutex coverage for CVE-2016-2544.
3. Verify both ack/active cleanup sites for CVE-2016-2548.
4. Establish whether the CVE-2016-2549 provider is compiled and shipped.
5. Perform byte-complete reaching-store analysis for every 32-byte extended
   timer record before full queue and userspace copies.
6. Keep observed disclosure, exploitation, root, and persistence distinct.
7. Add only a Boolean state-flow model; emit no target data or trigger material.

## Exclusions

No module load, device open, ioctl, timer setup, event generation, read, race,
target-byte collection, malformed input, payload, privilege transition, or
persistence.
