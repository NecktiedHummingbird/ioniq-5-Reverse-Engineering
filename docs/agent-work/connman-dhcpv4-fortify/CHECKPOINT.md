# Checkpoint — ConnMan DHCPv4 CVE-2023-28488 fortified outcome

## Status

Complete for offline recovered-`260128` static analysis. No packet was generated,
no socket was opened by the analysis tool, target binaries were not executed,
and the NIC-free VM was not changed.

## Result

Recorded V-016 with a narrow conclusion:

- exact `connmand` retains CVE-2023-28488's pre-fix IP-total-length ordering;
- normal IPv4 client startup enters `INIT_SELECTING`, selects L2 mode, creates an
  `AF_PACKET` datagram listener, and registers the affected receive callback;
- the vulnerable subtraction feeds exact `__memcpy_chk(..., object_size=0x274)`;
- exact recovered libc rejects every underflowed request through
  `__chk_fail`/`__fortify_fail` before copying;
- recovered `260128` therefore supports a conditional adjacent-network ConnMan
  process-termination/availability claim, not stack overwrite, RCE, or root.

## Exact identities

- `connmand`:
  `d82d4018bfa9d8f8d67407453bd783a3c896f6764f147dcf23cf06b978024c28`
- `libc-2.25.so`:
  `04946077dfd7554a20438ee581367e3995931b26c9ee516ffeeecdc0ee9f331f`
- `connman.service`:
  `98cdbabd95d92ea66851ce0fc54cee572118a38d82edc854707e642cae52c4ba`
- package:
  `connman-1.29+5w.master.38-r1.corei7_64`

## Exact code anchors

- client start: file virtual `0x24c40`, Ghidra `0x124c40`;
- listening-mode switch: file virtual `0x220c0`, Ghidra `0x1220c0`;
- affected callback: file virtual `0x23390`, Ghidra `0x123390`;
- read cap: `0x2346e`, `0x290` bytes;
- original 28-byte minimum check: `0x23473..0x23476`;
- untrusted IP-total load/order: `0x23558..0x2356d`;
- zero-extension/subtraction/call: `0x23647..0x2365b`;
- libc `__memcpy_chk` IFUNC: `+0xf64b0`;
- libc `__chk_fail`: `+0xf7540`;
- libc `__fortify_fail`: `+0xf93b0`.

## Tracked deliverables

- `tools/uk_fw/connman_length_model.py`
- `tests/test_connman_length_model.py`
- `evidence/connman-cve-2023-28488.md`
- `evidence/artifacts/network-candidates/connman-cve-2023-28488-fortify-evidence.txt`
- `docs/agent-work/connman-dhcpv4-fortify/PLAN.md`
- this checkpoint

## Evidence hashes

- reviewed static excerpt:
  `63e18168be09496c730d44b13542418f894f20b5ce3246c4f6d5c09e5d303723`
- ignored generated arithmetic report:
  `d315a7467d54a344f22fdbed05f7eeaa5cd3841b6979792a93b60fbcbdef819a`
- decoded upstream fix:
  `effc148e5dd7c957deb260c05017d6eb0a3ac59928be18ae86eb46df9cca2805`

## Arithmetic acceptance

The model partitions all 43,057,152 combinations of read lengths `0..656` and
16-bit total lengths:

- short-read reject: 1,835,008;
- partial-read reject: 41,006,397;
- fortify abort: 17,612;
- bounded copy: 198,135.

This is a length-only partition. Protocol, header, UDP port/length, checksum,
DHCP state, interface, and physical delivery gates remain outside it.

## Validation

- focused pytest: `10 passed, 5 subtests passed`;
- full pytest: `255 passed, 48 subtests passed`;
- `py_compile`: passed;
- public harness: passed (`pass=3`, `info=4`, no pending/blocked/fail);
- `git diff --check`: passed;
- canonical rootfs SHA-256 remained
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`;
- `e2fsck -fn`: clean at `246790/2097152 files`,
  `6108674/8388608 blocks`.

## Remaining boundary

The owner's installed firmware and interface state are unknown. No dynamic abort,
restart loop, physical reachability, corruption, RCE, root access, persistence,
CAN access, or safety-system impact is established.

Any future dynamic check belongs on a disconnected owner-controlled bench and
must begin with installed hashes, interface ownership, IPv4 client state, and
benign DHCP controls. A malformed control, if separately approved, remains
crash-only with no exploit payload.

## Delegation note

No child/worker result was used. Fable was not advertised for native v2
subagents and the required direct DeepSeek route remains unavailable; project
policy forbids silent substitution.
