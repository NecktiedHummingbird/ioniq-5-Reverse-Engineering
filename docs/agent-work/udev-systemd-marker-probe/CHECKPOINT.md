# Offline udevd-to-systemd marker checkpoint

Status: implementation, matched VM controls, review corrections, full acceptance,
integrity checks, and tracked repository integration complete.

Baseline:

- branch `main`;
- starting HEAD `f9dcadc70236fb5ec6a0a8f76e4f413a3c4d218f`;
- workspace clean before plan/checkpoint creation;
- canonical rootfs SHA-256
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`.

Routing:

- Fable doctor remained blocked: `openrouter/claude-fable-5.1` existed but was
  not advertised for native subagents (`multi_agent_version` was not `v2`);
- DeepSeek Flash doctor reported static-ready for role
  `astra_terra_builder_deepseek_flash`, route
  `deepseek/deepseek-v4.1-flash`, but native dispatch failed with
  `Unknown model deepseek:deepseek-v4.1-flash`;
- no worker result or route substitution was used; root implementation proceeded
  directly. Independent read-only review used an available explicitly selected
  reviewer model, not a substitute implementation worker.

Implementation:

- added `tools/uk_fw/udev_systemd_probe.py`;
- added `tests/test_udev_systemd_probe.py`;
- extended `tools/uk_fw/vm_boot.py` with an optional exact, terminated serial
  completion line for PID-1 handoff diagnostics; default command completion is
  unchanged;
- added focused serial-marker tests to `tests/test_vm_boot.py`;
- fixed workspace and guest-binary hashes, new/disjoint project output, exact
  marker allowlists, and per-run cryptographic provenance;
- all generated helper/rule/unit files were transient under `/run`; root was
  remounted read-only before exact PID 1 systemd and rechecked read-only at end;
- exact vulnerable installed storage/V4L helper rules were shadowed by verified
  `/run/udev/rules.d/* -> /dev/null` masks before coldplug;
- the custom target disabled default dependencies but intentionally layered on
  installed `sysinit.target`, so ordinary sysinit/coldplug activity remained;
- the marker unit performed only fixed BusyBox `touch` and `echo` operations and
  contained no shell command.

Matched accepted controls:

- negative run `1793367045339706000`:
  `negative-marker-absent`, exact `ID_SCSI_SERIAL` present,
  `SYSTEMD_WANTS` absent, marker file absent, unit inactive;
- positive run `1793367069868535000`:
  `benign-unit-activation-confirmed`, exact `ID_SCSI_SERIAL` and
  `SYSTEMD_WANTS` present, PID 1 logged transient marker start, marker file
  present, unit active;
- both runs completed without timeout/error, retained root read-only, used
  `-nic none` and `snapshot=on`, and returned VM harness status zero.

Final ignored evidence:

- aggregate JSON SHA-256:
  `200bfa75e197ac5f95f698987a4388ecd1bedc8caa328452889eb3c3366c60b2`;
- host log SHA-256:
  `b79fda44ce306ee120b12ef706029255a145114ca02b379915f3552b4610834c`;
- negative serial SHA-256:
  `e4b942feb337f153d3a737f5887e7d79e4736cc6100edc889d2c6255372c078c`;
- positive serial SHA-256:
  `8c227ee56fe163008b5fcb7b6b426732cdc6f578cbc6f41aee5e8746f987ac3b`;
- reviewed tracked excerpt:
  `evidence/artifacts/udev-candidates/cve-2026-40225-systemd-marker-evidence.txt`,
  SHA-256 `fb9bfc1b01fbf2417713e8fa5ba10a8a956f31b8deda34852036d897f43de64d`.

Review outcome:

- initial read-only review found non-exact marker acceptance, unterminated serial
  completion, insufficient helper-rule isolation, broad default dependencies,
  weak provenance, missing installed-unit checks, and no final read-only check;
- corrections added exact sequence equality, malformed/opposite-state tests,
  terminated-line matching, transient rule masks, `DefaultDependencies=no`,
  artifact/QEMU/script hashes, installed-unit/drop-in checks, and final root
  verification;
- re-review found no blocking issue for the bounded synthetic activation claim;
- additional root hardening made rule-mask creation/readback fail closed and made
  offline classification independently recheck the terminated completion line.

Evidence boundary:

- established: exact recovered udevd stores the fixed synthetic property and exact
  PID 1 systemd starts the otherwise-unreferenced transient benign unit only in
  the positive matched control;
- not established: hardware bytes reaching shipped `scsi_id`/`v4l_id`, a physical
  device or port, a request for any installed shell unit, VT interaction, a root
  command, persistence, or owner-vehicle applicability.

Final verification:

- focused tests: `39 passed, 17 subtests passed`;
- full suite: `238 passed, 38 subtests passed`;
- `py_compile` passed;
- `git diff --check` passed;
- rootfs SHA-256 remained canonical;
- `e2fsck -fn` passed at `246790/2097152 files` and
  `6108674/8388608 blocks`.

Resume action:

- preserve the remaining hardware-helper, physical-port, production-tty, and
  display/input gates for a disconnected bench using a benign marker; do not
  start the installed shell unit.
