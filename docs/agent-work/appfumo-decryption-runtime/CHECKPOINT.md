# AppFUMO decryption producer/runtime provenance checkpoint

## Completed result

- Bound exact ELF SHA-256
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`.
- Homebrew LLVM 23.1.3 `.eh_frame` places `0x10281c`, `0x102de9`, and
  `0x103398` in exact FDE `[0x101110,0x104c1b)`.
- Exact local `AppUpgradeEngine` metadata row 60 resolves to public slot
  `void copyWhatsNewFiles()`; jump-table row 60 targets `0x16e59f`, whose
  generated case calls FDE entry `0x101110`. All three selected sites therefore
  belong to that implementation.
- Resolved the three direct producer families:
  - `0x102de9`: branch-selected package base + `.whatsnew.tar.gz` to fixed
    `/update/whatsnew/temp/.whatsnew.tar.gz`;
  - `0x10281c`: enumerated system-tree absolute source to the paired normal or
    USB-in-OTA destination tree;
  - `0x103398`: enumerated controls-tree absolute source to the paired normal or
    USB-in-OTA destination tree.
- Kept generated row-64 forwarding call `0x16e030` separate.
- Hash-bound public log inspection found seven exact-shape records, not the six
  stated in the task: lines `1414,1710,7279,11714,11975,17205,21713`. All seven
  have matched bounded `copyWhatsNewFiles` context and the same normalized
  removable-USB archive to update-temp archive classes.
- Added a read-only, fail-closed parser with stable-file checks, strict expected
  hash/default mode, explicit synthetic-test mode, exact grammar, normalization,
  deterministic UTF-8/LF JSON, and no command/token emission.

## Evidence identities

- exact static excerpt SHA-256:
  `d8783cbdc41f5aae6663f339ff2debe2c3e425c8a243845e823b53f087099eb1`;
- row-60 report SHA-256:
  `8f9adf55fbb3f0f65ef565175901a92144d33cf0ebc28bb57bffe39bbb386ee1`;
- public log SHA-256:
  `84d5bb69270dd610b132c8950c31dd98adad844c5a2c108b4df617381685de86`;
- normalized public-log report SHA-256:
  `0dc7fb9c2775b2b201ca3b7e38438f75f1db3aa9ddac4298f315ad2e6f35bb66`.

## Claim boundary

Public-log runtime observation, exact recovered static semantics, row-64
metadata binding, generated row-64 forwarding, the three selected direct
producer families, complete producer provenance, and attacker control remain
separate statuses. The logged build's identity and invocation mechanism are
unknown. Dynamic/indirect/external producer completeness, external/D-Bus
reachability, attacker control, acceptance, privilege, root, and persistence
are not established.

## Validation

- focused AppFUMO tests: `47 passed, 8255 subtests passed`;
- complete tests-scoped suite: `682 passed, 351277 subtests passed`;
- public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`;
- privacy-only harness: **PASS**, no blocking finding;
- explicit new-file privacy pattern scan: passed;
- exact public-log report under `ascii`, `latin-1`, and `utf-16`
  `PYTHONIOENCODING`: byte-identical to retained JSON;
- `py_compile`: passed;
- `git diff --check`: passed.

No project-local temporary-directory override was used.

## Safety

No recovered target/helper was executed. No device/radio/network path,
malformed target artifact, update package, payload, bypass, partition/slot/boot
state, root action, or persistence material was created or exercised. Synthetic
fixtures are bounded text logs only.
