# `/media` permission analysis — resolving V-011's weakest link

Static analysis of `NE_E.EUR.S5W_L.001.001.260128`. Claims tagged (V) verified in the tree,
(I) inferred from documented kernel/systemd defaults, (U) unestablished.

## What mounts and creates `/media`

- (V) `etc/fstab_emmc:8` — `tmpfs /media tmpfs defaults 0 0`. No mode, no `nodev`, no `nosuid`.
- (V) No `tmpfiles.d` entry mentions `/media`, and `lib/systemd/esinit` contains no `/media` reference,
  so nothing in the vendor tree sets a mode or owner on it. The tmpfs root mode is therefore whatever
  the kernel default gives.
- (I) The kernel's tmpfs root inode default is `01777` (directory, world-writable, sticky), the same
  default that makes `/tmp` behave as `/tmp`. Nothing in this image overrides it.
- (V) The automounter creates per-device directories beneath it with `mkdir(…, 0777)` under systemd's
  default `UMask=0022`, so those subdirectories land as `0755 root:root`.

**Conclusion:** `/media` itself is very likely world-writable and sticky, while the device
subdirectories beneath it are root-owned `0755`. An unprivileged local process can therefore create new
entries directly in `/media`, but cannot rename or delete entries owned by root (the sticky bit).

## Consequence for V-011 (mount without `MS_NODEV`)

The flag word is `0xC0ED000A` = `MS_NOSUID | MS_NOEXEC | MS_DEV` (verified earlier). Because the node is
interpreted by the kernel, the node's own recorded uid, gid and mode are what apply — an attacker
crafting a filesystem image chooses them. A node recorded as `0666` therefore opens the block device it
names to every user.

- (V) Device permissions the model assumes are protective: `0660 root:disk` on `/dev/mmcblk*`.
- (I) A crafted image containing a `mmcblk0` node with attacker-chosen ownership and mode defeats that
  boundary, giving unprivileged read and write access to internal storage rather than only to the
  attacker's own removable media.
- Impact boundary: this still requires physical USB access to insert the medium. What it changes is the
  *scope* — internal storage instead of removable media — not the precondition.

## Re-assessment of the `..` serial vector

With `/media` world-writable, the unchecked `umount2` → `mkdir` → `mount` sequence matters more than a
first reading suggested, because the attacker can create entries directly in the mount root without
needing write access to root-owned subdirectories. The vendor code performs no `openat`/`O_NOFOLLOW`
resolution and ignores `mkdir`'s return value.

- (I) A mount landing on `/media` itself, rather than under it, would shadow the mount point with
  attacker content for the period the automounter holds it.
- (U) Whether that is reachable in practice depends on the automounter's exact path construction for a
  `..`-bearing serial and on whether `mount(2)` accepts a target the caller does not own — as root it
  would. Not demonstrated, and it yields no root by itself.
- Verdict: remains an amplifier, now with a plausible writable root. Not a privilege escalation on its
  own.

## Falsification

- For V-011: mount any USB image through the service and check `/proc/mounts`; if the entry carries
  `nodev`, V-011 is wrong.
- For `/media` writability: as any non-root uid on the running system, attempt
  `mkdir /media/probe`. Success confirms `01777`; `EACCES` refutes it.
- For the `..` vector: drive the automounter with a `..` serial and observe the resolved mount target.
