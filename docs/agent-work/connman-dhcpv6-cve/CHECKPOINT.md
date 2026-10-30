# ConnMan DHCPv6 exact-build review checkpoint

Status: implementation and local acceptance complete; ready for final diff review,
commit, and push.

## Accepted work

- Recovered the exact RPM `Nvra` package index read-only with Berkeley DB
  18.1.40. Preserved print dump under ignored `work/`:
  - source Btree SHA-256:
    `1c9694c13b4313c169d5a0e3fd716acbf18bcb1342a22ec6c17e34cdd2b8840e`
  - print dump SHA-256:
    `88b0f30f0684ddf719b13fd49ca6f702cbae47b5ec64b324188ec83221ef21b0`
  - 1,679 records / 1,679 unique names
  - selected record: `connman-1.29+5w.master.38-r1.corei7_64`
- Added `tools/uk_fw/rpm_nvra_inventory.py` with strict printable-dump
  validation, exact selectors, deterministic JSON, input/output safety, and
  atomic replacement.
- Added `tests/test_rpm_nvra_inventory.py` covering parsing, escapes,
  determinism, exact selection, malformed inputs, symlinks, hard-link safety,
  and CLI output.
- Confirmed exact `connmand` SHA-256
  `d82d4018bfa9d8f8d67407453bd783a3c896f6764f147dcf23cf06b978024c28`
  contains:
  - vulnerable `get_domains` at `+0x1f150`;
  - option-24 dispatch at `+0x1f211`;
  - higher DHCP receive/state function at `+0x23390`;
  - connected-network RA Managed/Other dispatch at `+0x574e0`;
  - stateful/info start functions at `+0x856f0` / `+0x855a0`;
  - information-request option-24 registration at `+0x84770`.
- Recorded uid-0 default service identity, `Restart=on-failure`, non-excluded
  intended `wlan0`, transaction/client/server/state gates, and PIE/NX/canary/full
  RELRO constraints.
- Added V-015 report and reviewed static excerpt. Excerpt SHA-256:
  `ffebd6f772e2676d865ff692c129f58c4cdcace7ab11608d94adacb432776c11`.
- Updated the vulnerability register, exploit inventory, network survey,
  prioritisation, handover, history, and changelog with the conservative claim
  boundary.

## Claim boundary

Established: exact affected code, option dispatch, static conditional
RA-to-DHCPv6 route, installed service configuration, intended Wi-Fi interface,
and ELF mitigations in recovered EU `260128`.

Not established: owner's installed build, production Wi-Fi/IPv6/interface state,
physical packet delivery, a dynamic crash, controlled memory primitive, RCE,
root access, persistence, CAN access, or safety-system impact.

No network packet, target binary execution, firmware write, root operation,
shellcode, persistence mechanism, or privilege payload was used.

## Acceptance evidence

- Focused tests: `7 passed, 5 subtests passed`.
- Full suite: `245 passed, 43 subtests passed`.
- `py_compile`: passed.
- `git diff --check`: passed.
- `tests/run_all.py`: passed (`pass=3`, `info=4`, no blocking finding).
  Its first run exposed one pre-existing operator-home path in the public V-012
  reproduction command; that path was replaced and the harness then passed.
- Canonical rootfs SHA-256 remained
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`.
- `/opt/homebrew/Cellar/e2fsprogs/1.47.4/sbin/e2fsck -fn`: passed at
  `246790/2097152 files`, `6108674/8388608 blocks`.

## Delegation/routing

Fable was not available for native v2 subagents. The previously checked
DeepSeek V4.1 Flash route was rejected by native dispatch as an unknown model.
No substitute model, failed worker output, or external disclosure was used.
Worker thread IDs: none.

## Tracked scope

- `tools/uk_fw/rpm_nvra_inventory.py`
- `tests/test_rpm_nvra_inventory.py`
- `docs/agent-work/connman-dhcpv6-cve/{PLAN,CHECKPOINT}.md`
- `evidence/connman-cve-2026-115863.md`
- `evidence/artifacts/network-candidates/{README.md,connman-cve-2026-115863-static-evidence.txt}`
- conservative updates to the root vulnerability/changelog/history/handover and
  network/exploit prioritisation documents;
- one unrelated public-snapshot privacy cleanup replacing an operator-specific
  Python home path in `evidence/gstreamer-cve-2026-2920.md` with an overridable
  host-independent interpreter path.

Full downloads, upstream source, package DB/dump, generated JSON, disassembly,
Ghidra snapshot/records, and exploratory AppMediaPlayer output remain ignored
under `work/`.

## Resume action

Review the complete tracked diff and repository status, rerun only any check
invalidated by review edits, then commit and push to both synchronized remotes.
Future dynamic V-015 work begins only on a disconnected bench with installed
build/hash capture and benign interface/IPv6/RA observations; keep the current VM
NIC-free.
