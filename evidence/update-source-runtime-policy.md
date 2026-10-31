# AppDMClient staged-source runtime policy boundary

## Result

Recovered EU `260128` configuration places `/update` on a writable ext4
partition and boot-time setup creates the intended `/update/usb/bin` staging
namespace when it is absent. This proves that the namespace is not inherently a
read-only filesystem. It does **not** prove that an untrusted runtime actor can
replace a verified source pathname or modify its bytes.

The missing facts are the mounted filesystem root and staging-directory
ownership/modes, the files' effective `SMACK64` labels, the executables'
`SMACK64EXEC` labels, the relevant processes' real/effective/saved/filesystem
uid/gid values, supplementary groups and labels, and the live policy rules. The
disconnected passive state bundle now records those
facts without reading staged content or issuing an update, launch, D-Bus, radio,
network, mount, or write request.

Classification: **writable staging filesystem and boot-time namespace
construction proven; attacker-writable pathname mapping or file content remains
runtime-conditional**.

This advances V-031's source-mutability gate but does not establish an object
substitution, authentication bypass, successful launch, update acceptance,
partition write, slot selection, boot acceptance, root, or persistence.

## Exact recovered configuration

The canonical rootfs archive is:

- `HU/images/mango-rootfs.tar.gz` size and provenance as recorded by the package
  evidence;
- SHA-256:
  `423491fd8b86bd815d4e12f47054e08a589a5159f87213f08980fcc3a0e47c84`.

Its GNU-tar metadata records:

- `/update/`: `root:root`, mode `0755` **for the rootfs mountpoint**;
- `/app/bin/AppDMClient`: `root:root`, mode `0755`;
- `/app/bin/AppUpgrade`: `root:root`, mode `0755`;
- `/etc/smack_setup.sh`: `root:root`, mode `0700`.

The mountpoint metadata is not the metadata of the root directory of the
filesystem mounted over it. It therefore cannot establish the installed
`/update` owner or mode.

### `/update` is configured read-write

Both selected eMMC tables contain:

```text
/dev/mmcblk0p9 /update ext4 defaults,noatime,journal_checksum 0 0
```

Neither entry includes `ro`. Under normal mount option semantics, `defaults`
includes read-write operation. The relevant hashes are:

- `/etc/fstab_emmc`:
  `93c4af1a0ffb0f36c9ff64c6252cfbd950e7615d2f32f85dcab0af17cf9af74e`;
- `/etc/fstab_emmc_fde`:
  `e716ad6b2f300ccc352f7737bb616d8e8fbba2169bee877e82c0f8fa83ec6cbb`.

`/etc/fstab` is a link to `/tmp/fstab`. `esinit` selects
`/etc/fstab_emmc_fde` when `endFde == 1` and `/etc/fstab_emmc` otherwise, by
creating `/tmp/fstab`. Thus both recovered eMMC branches configure the same
writable `/update` partition. Installed mount success and live flags still need
`/proc/mounts` evidence.

### Boot setup constructs the staging namespace

`/etc/smack_setup.sh` performs these conditional operations:

```text
mkdir -p /update/usb/bin

touch /update/usb/bin/AppUpgrade
chsmack -e "App::upgrade" /update/usb/bin/AppUpgrade

touch /update/usb/bin/AppScomoUpgrade
chsmack -e "App::upgrade" /update/usb/bin/AppScomoUpgrade
```

The `mkdir` and `touch` branches run when the path does not resolve to the
expected directory or regular-file type, respectively; this includes absence,
wrong-type objects, and dangling links. The script does not set an explicit
directory/file uid, gid, or mode and does not set a
`SMACK64` access label on these staged objects. `chsmack -e` sets the execution
transition label, which is a different attribute from the access label used for
write checks. The creator's uid, umask, current SMACK label, filesystem label
inheritance, pre-existing-object metadata, and successful completion therefore
remain relevant runtime facts.

The associated unit has no `User=` or `Group=` directive. That is configured
uid-zero intent under systemd defaults, not proof of observed runtime
credentials or successful setup.

Hashes:

- `/etc/smack_setup.sh`:
  `847af53be34d0e325c738a4ae26d11f7ed69b940cf2aa53d27e3b422e8a8ebb6`;
- `smack-setup.service`:
  `d41768e8f4372f4affc3804bbf7a45297782416a44fc384d7943932eba6048ea`.

## SMACK policy is permissive in one direction but not self-proving

The update-time relabel helper includes `AppDMClient` and `AppUpgrade` in the
set assigned `SMACK64EXEC=App::upgrade` when `app_labeling` is invoked. The
recovered policy also contains
write permission from the floor label `_` and 22 named `App::*` labels to an
object labelled `App::upgrade`.

That observation alone does not prove write access to `/update/usb/bin` or its
files:

1. SMACK rules are directional: a subject-label/object-label pair must match.
2. The setup script sets `SMACK64EXEC`, not `SMACK64`, on staged executables.
3. Parent-directory search/write permission and file-content write permission
   are separate checks.
4. DAC uid/gid/mode checks still apply.
5. Static policy files prove configured rules, not that they were loaded
   unchanged or remain effective.

Relevant hashes:

- `/etc/smack-relabel-ro.sh`:
  `8275625764c30b6e82d99e5fdf887038261f97e9f0ef5a36da8faa743a35a15f`;
- `/etc/smack/accesses.d/upgrade`:
  `c10c636ec92b91cadb6e867feeb36522d0861af6eb101be67f5a37848c20ad22`;
- `/etc/smack/accesses.d/floor`:
  `ed5df75dd1337984e5c454eed9614e8348e7064040fde46be03c53eb64f39353`.

## Passive runtime evidence extension

`tools/uk_fw/bench_state_bundle.py` remains a host-side emitter/parser. Its
emitted POSIX `/bin/sh` probe now:

- captures metadata for `/update`, `/update/usb`, `/update/usb/bin`, staged
  AppUpgrade/XML, installed AppDMClient/AppUpgrade, and the persistent public
  key;
- lists and reads `SMACK64` and `SMACK64EXEC` through read-only `getfattr`
  calls, with an exact security-namespace name match before value retrieval;
- distinguishes absent path, absent attribute, unavailable provider, query error,
  malformed result, and a successful label;
- preserves the raw records and derives `facts.smack_xattrs` in parsed JSON;
- rejects emitted xattr mutation commands and mutating `attr` options during
  host-side script audit.

Provider and attribute absence are retained separately rather than silently
treated as empty labels. Query and validation failures fail the collection
closed. The probe
does not read `/tmp/session_appmgr{,.env}` contents, connect to D-Bus, or send a
request.

## Required disconnected-bench observations

Before any active update test, collect:

1. live `/proc/mounts` entry and options for `/update`;
2. uid/gid/mode/type for `/update`, `/update/usb`, `/update/usb/bin`, staged
   AppUpgrade, and staged XML;
3. `SMACK64` and `SMACK64EXEC` for the same namespace plus installed
   AppDMClient/AppUpgrade and the public key;
4. AppDMClient/AppUpgrade process real/effective/saved/filesystem uid/gid,
   supplementary groups, effective label, executable, and arguments if running;
5. loaded SMACK rules, `onlycap`, and ambient label;
6. installed and staged hashes.

Only after identifying a concrete actor can DAC and SMACK write permission be
combined. A writable mount by itself is insufficient; conversely, restrictive
file mode alone is insufficient if the candidate actor is observed with uid 0
and the required SMACK relation.

## Validation and review

- focused collector: `23 passed, 20 subtests passed`;
- complete suite: `556 passed, 148497 subtests passed`;
- public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`;
- emitted probe: 22,464 bytes, SHA-256
  `c043f3ed5c1815897de8ee5faececd6c36a9cb36e24fabd83d43b7dab164fc56`;
- emitted-probe audit: `safe=true`, `syntax_ok=true`, no violations;
- corrected independent package review: **ACCEPT**.

## Safety record

Only recovered text configuration, archive metadata, hashes, host-side parsing,
and synthetic tests were used. No target file, xattr, mount, process, D-Bus
object, update state, package, partition, slot, boot state, radio, network, or
persistent object was changed. No recovered executable was run.
