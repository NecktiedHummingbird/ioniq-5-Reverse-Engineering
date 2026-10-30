# Recovered userspace privilege-surface static audit

## Scope

`tools/uk_fw/privilege_surface.py` is a standard-library-only, read-only scanner
for extracted Linux root filesystems. It does not execute recovered binaries,
follow symlinks, mount images, or write into the analyzed tree. Its purpose is
to turn broad privilege-escalation searches into reviewable candidate lists;
its output is not an exploitability verdict.

The bounded audit used:

- root: `work/decrypted-eu-260128/extracted-safe/mango-rootfs`;
- full ignored report:
  `work/public-vuln-research-20261101/privilege-surface-260128.json`;
- report SHA-256:
  `cb58b49945fbf894191d79617665cf86351555b5c3afa2439510968bf7e6753f`.

## Summary

The scanner walked 236,552 non-symlink entries and parsed 102 systemd service
files. It reported:

- zero host-visible setuid/setgid regular files;
- 129 executable files whose extracted host metadata is group- or
  world-writable;
- zero group- or world-writable directories;
- 46 permissive/non-root udev rule assignments;
- no traversal or parser warnings.

Archive metadata independently supports the most notable mode result: the
original `HU/images/navi_eu/appnavi.tar` records mode `0777` on files including
`Bin/AppNavi`, `Bin/CANService`, `Bin/CANService.sh`, and `Bin/AppNavi.sign`.
A direct archive-mode search found no setuid/setgid entries in the reviewed
rootfs, RW-data, GUI, or AppNavi archives.

## Interpretation

### No conventional setuid entry was found

This removes one common local-escalation route from the recovered archive set.
It is not proof that a running unit cannot create, install, or expose a setuid
file later.

### Navigation files have permissive modes but are normally mounted read-only

Most writable-executable findings are under `/navi`. `etc/fstab_emmc` mounts
`/navi` and `/navi2` with `ro,noatime,nouser,auto,exec,suid`. The `0777` archive
modes therefore do not by themselves provide a runtime overwrite path.

Recovery/setup code can temporarily remount these filesystems read-write, but a
useful finding would still require a reachable remount window, exact DAC/SMACK
write access, a caller able to alter a trusted file, and later execution of the
altered file. None of those steps was demonstrated by this audit.

The only writable-executable-mode result outside `/navi` was
`/rw_data/navi_data/certificates/TomTom_Root_CA.crt`; its executable mode does
not make certificate data an executable program.

### System services default to root

Of 102 parsed service files, 101 had no effective `User=` override and therefore
use the system-service default identity; the only non-root classification was
templated `user@.service` with `User=%i`. This is a broad privilege-separation
gap and an impact amplifier, not evidence that each service is enabled or
attacker-reachable.

The current static dependency check did not identify a group/world-writable
existing service executable or environment dependency. Several unit paths were
absent from the recovered tree, including `/usr/sbin/dropbear`, `/bin/plymouth`,
`/usr/sbin/halt.local`, `/usr/sbin/quotaon`, and `/etc/rc.local`. An absent path
is not automatically exploitable: parent-directory permissions, creation
rights, unit enablement, and SMACK remain required.

### File-capability coverage is explicitly incomplete

The macOS Python host does not expose `os.getxattr`. The JSON records the API as
unavailable instead of reporting that the target has no file capabilities.
Archive extraction can also lose Linux ownership, xattrs, ACLs, labels, or
special bits, so source archives and guest runtime remain the stronger evidence
where available.

## Follow-up outcome

Evidence-led review of the udev findings identified a separate, stronger result:
exact pre-fix CVE-2026-40225 helper code plus an installed root debug-shell unit.
That result is V-014 and is documented independently in
`evidence/systemd-udev-cve-2026-40225.md`. It is not inferred from permissive
udev mode rules or from version strings alone.

## Tool behavior and limitations

The scanner:

- rejects symlink roots and output paths beneath the analyzed tree;
- uses `lstat` and does not descend through symlinks;
- records extracted mode/uid/gid rather than presenting them as production
  runtime truth;
- parses a bounded subset of systemd syntax and does not determine enablement,
  generator output, runtime drop-ins outside the tree, or actual process state;
- identifies suspicious loader and service dependencies but does not load or
  execute them;
- emits deterministic sorted JSON suitable for diffing between releases.

Validation is covered by `tests/test_privilege_surface.py`.
