# ConnMan DHCPv6 exact-build review plan

## Objective

Establish, conservatively and reproducibly, whether the recovered EU `260128`
userspace contains the code affected by CVE-2026-115863 and map the installed
activation and receive conditions without sending network traffic or developing
an exploitation payload.

## Scope and contracts

1. Recover the exact installed package identifier from the read-only RPM Berkeley
   DB `Nvra` index. Because the target DB uses Btree format version 10, preserve
   `db_dump` output under ignored `work/` and add a deterministic parser for its
   printable dump format.
2. Bind conclusions to hashes of the exact `connmand`, package DB, service unit,
   and reviewed static evidence.
3. Confirm in the shipped binary, rather than from a version label alone:
   - the DHCPv6 DOMAIN_LIST option-24 dispatch;
   - the fixed-size `strncpy(..., 0x401)` into the local stack buffer;
   - the unbounded label walk and `'.'` store;
   - the DHCPv6 receive path and RA Managed/Other flag dispatch.
4. Record installed service identity, excluded interfaces, intended Wi-Fi
   interface evidence, restart behavior, and ELF hardening.
5. Preserve the following claim boundary: exact vulnerable code and a static
   conditional on-link route may be established, but installed-device interface
   state, physical reachability, a crash, controlled execution, and root access
   remain unproven.

## Non-goals

- No crafted Router Advertisement or DHCPv6 packet generator.
- No network-enabled VM run, packet injection, exploit payload, shell, or
  privilege-changing action.
- No execution of recovered target binaries on the host.
- No claim based only on the `connman` package version.
- No claim that the recovered `260128` build matches the owner's installed unit.

## Implementation

- Add `tools/uk_fw/rpm_nvra_inventory.py` for strict, read-only parsing of
  Berkeley DB `db_dump -p` output and deterministic JSON selection.
- Add focused parser/CLI tests in `tests/test_rpm_nvra_inventory.py`.
- Add a sanitized exact-build evidence excerpt under
  `evidence/artifacts/network-candidates/` and a conservative report in
  `evidence/connman-cve-2026-115863.md`.
- Update the vulnerability inventory, attack-surface prioritisation, handover,
  history, and changelog only after review.

## Failure behavior

- Reject missing/duplicate `HEADER=END` or `DATA=END`, odd key/value records,
  unsupported dump versions/formats/types, malformed print escapes, invalid
  UTF-8 NVRA keys, malformed NVRA strings, symlink input, non-regular input, or
  the same pathname for input and output.
- Write JSON atomically so even an existing hard-link output is replaced without
  modifying the source inode.
- Report selectors with no match rather than silently treating them as absent.

## Acceptance criteria

- Focused tests and `py_compile` pass.
- Exact dump yields 1,679 package records and selects
  `connman-1.29+5w.master.38-r1.corei7_64`.
- Evidence names exact function offsets and separates upstream-source comparison
  from exact-binary observations.
- ELF mitigations and `Restart=on-failure` are recorded as constraints, not a
  safety or exploitability conclusion.
- Full `pytest -q tests`, `git diff --check`, rootfs SHA-256, and `e2fsck -fn`
  checks pass before commit.
- Only reviewed text, tests, and tooling are staged; downloads, full disassembly,
  decompiler JSON, binaries, DB dumps, and generated reports remain under
  ignored `work/`.
