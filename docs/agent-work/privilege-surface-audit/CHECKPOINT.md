# Privilege-surface audit checkpoint

Status: Phases 1 and 2 complete; reviewed findings documented.

Baseline:

- branch `main`;
- starting HEAD `219c743`;
- workspace was clean before plan creation;
- recovered firmware and full reports remain under ignored `work/`.

Routing:

- Fable was not available for native subagent dispatch.
- DeepSeek Flash was statically configured as
  `deepseek/deepseek-v4.1-flash`, but native dispatch rejected it as an unknown
  model.
- No worker result exists, no substitute model was silently used, and all
  implementation/review below is native work.

Phase 1 result:

- added `tools/uk_fw/privilege_surface.py`;
- added `tests/test_privilege_surface.py`;
- scanner is standard-library-only, read-only, does not follow symlinks, rejects
  a symlink root and output paths inside the root, and never executes recovered
  target binaries;
- focused tests: `13 passed`, including hard-link output replacement,
  intermediate-symlink rejection, environment precedence, and physical udev
  line-number retention;
- `py_compile` and `git diff --check` passed.

Recovered-tree run:

- analyzed `work/decrypted-eu-260128/extracted-safe/mango-rootfs`;
- ignored full JSON:
  `work/public-vuln-research-20261101/privilege-surface-260128.json`;
- SHA-256:
  `cb58b49945fbf894191d79617665cf86351555b5c3afa2439510968bf7e6753f`;
- 236,552 non-symlink entries, 102 services, zero host-visible setuid/setgid
  files, 129 writable-executable-mode files, zero writable directories, and 46
  permissive/non-root udev rule findings;
- archive metadata independently confirmed notable `/navi` `0777` modes and no
  setuid/setgid entries in the reviewed rootfs/RW-data/GUI/AppNavi archives;
- normal fstab policy mounts `/navi` read-only, so permissive archive modes are
  not a demonstrated runtime overwrite path;
- host Python lacks `os.getxattr`; capability coverage is explicitly reported as
  unavailable rather than absent.

Phase 2 result:

- exact helper/rule review identified CVE-2026-40225 in shipped `v4l_id` and
  `scsi_id` instructions;
- installed rules invoke both helpers and expose the advisory's injected
  `REMOVE_CMD`/`SYSTEMD_WANTS` properties;
- installed `debug-shell.service` is configured to start `/bin/sh` as root on
  `/dev/tty9` when its path condition passes;
- recorded as V-014, a high-confidence static malicious-device-to-root-console
  path;
- a separate bounded offline VM control confirmed `/dev/tty9` exists as
  `root:root` mode `0600`, character device `4:9`, under the vendor
  kernel/userspace and research init; it did not inject a property, start the
  service, or change privilege;
- no physical event, observed root transition, or owner-vehicle applicability is
  claimed;
- PID 1/pkg-config report systemd `225`, while embedded build paths say
  `systemd/1_249.3-r0`; the finding rests on exact pre-fix instructions, not a
  version inference.

Tracked reports:

- `evidence/privilege-surface-static-audit.md`;
- `evidence/systemd-udev-cve-2026-40225.md`;
- `evidence/artifacts/udev-candidates/cve-2026-40225-static-evidence.txt`;
- `evidence/artifacts/udev-candidates/cve-2026-40225-tty9-vm-evidence.txt`.

Final validation:

- full suite: `209 passed, 25 subtests passed`;
- `py_compile` and `git diff --check` passed;
- independent read-only re-review found no remaining blocking issue after
  hard-link, intermediate-symlink, environment precedence, udev line-number,
  stale-report, and debug-shell-condition fixes;
- canonical rootfs SHA-256 remains
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`;
- `e2fsck -fn` passed: `246790/2097152 files`, `6108674/8388608 blocks`.

Next safe action:

- in a disconnected disposable environment, validate property import and unit
  request using a benign marker unit rather than `debug-shell.service`;
- do not treat such a VM result as proof of physical-port or VT9 behavior.
