# Bounded udev import probe checkpoint

Status: implementation, bounded VM run, review corrections, final acceptance,
and repository integration complete.

Baseline:

- branch `main`;
- starting HEAD `7bed650`;
- workspace clean before plan/checkpoint creation;
- canonical rootfs SHA-256
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`.

Routing:

- DeepSeek Flash doctor result: `static-ready`, route
  `deepseek/deepseek-v4.1-flash`, native role
  `astra_terra_builder_deepseek_flash`;
- actual native dispatch was rejected as
  `Unknown model deepseek:deepseek-v4.1-flash`, so runtime routing remains
  unverified and no worker result exists;
- Fable doctor result: blocked because `openrouter/claude-fable-5.1` is not
  advertised for native subagents;
- no substitute model was silently used; root implementation proceeded against
  `PLAN.md`.

Implementation:

- added `tools/uk_fw/udev_import_probe.py`;
- added `tests/test_udev_import_probe.py`;
- fixed synthetic output only:
  `ID_SCSI_SERIAL=V014_BENIGN_CONTROL`, followed by a leading-space
  ` SYSTEMD_WANTS=v014-benign-nonexistent.service`;
- the unit is checked absent in `/etc`, `/run`, `/lib`, and `/usr/lib` systemd
  unit directories;
- the tool invokes only `udevadm test --action=change` against fixed
  `/sys/class/block/mmcblk0`; it starts no daemon/service and sends no uevent;
- temporary helper and rule are removed in the guest;
- deterministic classification and canonical sorted-key per-run JSON retain
  explicit evidence limits; run directory and elapsed time are intentionally
  variable provenance.

Bounded VM result:

- classification: `benign-second-property-retained`;
- exact `/bin/udevadm` SHA-256:
  `b3d0274757f9ded9260f22a629da22e1e06ef0f6c750293b317e09810c93692b`;
- exact `/lib/systemd/systemd-udevd` SHA-256:
  `f32f6296ea20d959ac046ae80724f39e317aaaf492a5c7eedd9270b5b2abab0d`;
- authentic output recorded the raw leading-space line and retained normalized
  `SYSTEMD_WANTS=v014-benign-nonexistent.service`;
- command exit `0`, userspace/root mounted, no timeout/error;
- ignored report SHA-256:
  `10b2f463f49f2bfa446e2a68acb95897cd2569db68c38d0a05019feb35242bf4`;
- ignored host log SHA-256:
  `93fa0523c1733c9bcb570deec2f5f25c58aadd44b416fa37fa3cc39d7166a9f6`;
- run directory:
  `work/vm/vendor-userspace-260128/runs/1793362696049646000`.

Tracked evidence:

- `evidence/artifacts/udev-candidates/cve-2026-40225-import-parser-evidence.txt`,
  SHA-256 `4fc1284dc3503e462ecb714886accc1efd52b79545fc376f9423e727d9de4515`;
- primary report: `evidence/systemd-udev-cve-2026-40225.md`.

Evidence boundary:

- proves exact recovered udevadm import-parser retention for fixed benign output;
- does not prove physical byte delivery, shipped helper execution, authentic
  udevd database persistence, systemd unit activation, root access, or owner-
  vehicle applicability.

Final verification:

- focused tests: `14 passed`, including exact-line retention, echoed-marker,
  missing/duplicate/out-of-order frame, contradictory/malformed marker,
  workspace pinning, and temp-path safety controls;
- full suite: `223 passed, 25 subtests passed`;
- `py_compile` passed;
- `git diff --check` passed;
- canonical rootfs SHA-256 remained
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`;
- `e2fsck -fn` passed at `246790/2097152 files` and
  `6108674/8388608 blocks`.

Review outcome:

- independent read-only review findings on exact-line validation, frame
  boundaries, workspace pinning, temporary-path safety, provenance wording, and
  static/dynamic claim separation were corrected;
- root acceptance reran adversarial focused tests, the full suite, rootfs hash,
  and read-only filesystem check.

Resume action:

- the next experimental step is a separate authentic udevd-to-systemd benign-
  marker control; do not extend this parser-only diagnostic into service
  activation.
