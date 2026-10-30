#!/bin/sh
# Inject a host-built .so into the softbackend CoW clone and refresh prepare.json.
set -e
cd "$(dirname "$0")/../../../.."
# debugfs comes from e2fsprogs; override with DEBUGFS=... if it is not on PATH.
DBG=${DEBUGFS:-$(command -v debugfs 2>/dev/null || true)}
if [ -z "$DBG" ]; then
	echo "inject.sh: debugfs not found; set DEBUGFS=/path/to/debugfs" >&2
	exit 1
fi
IMG=work/vm/softbackend/rootfs.img
SO=${1:?usage: inject.sh path/to.so}
"$DBG" -w -R "rm /usr/lib/weston/ias-backend-soft.so" "$IMG" >/dev/null 2>&1 || true
"$DBG" -w -R "write $SO /usr/lib/weston/ias-backend-soft.so" "$IMG" 2>&1 | tail -1
INO=$("$DBG" -R "stat /usr/lib/weston/ias-backend-soft.so" "$IMG" 2>/dev/null | sed -n 's/^Inode: \([0-9]*\).*/\1/p')
[ -n "$INO" ] && "$DBG" -w -R "sif $INO mode 0100755" "$IMG" >/dev/null 2>&1 || true
"$DBG" -R "stat /usr/lib/weston/ias-backend-soft.so" "$IMG" 2>/dev/null | sed -n '2,4p'
python3.13 - "$IMG" <<'EOF'
import hashlib, json, sys, pathlib
img = pathlib.Path(sys.argv[1])
p = pathlib.Path('work/vm/softbackend/prepare.json')
meta = json.loads(p.read_text())
meta['sha256']['rootfs.img'] = hashlib.file_digest(img.open('rb'), 'sha256').hexdigest()
p.write_text(json.dumps(meta, indent=1) + "\n")
print('rootfs.img sha256', meta['sha256']['rootfs.img'])
EOF
