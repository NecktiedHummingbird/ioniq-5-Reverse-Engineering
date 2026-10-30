# First frame from the vendor HMI path (softbackend clone)

**Result: a frame was captured end-to-end through `weston_screenshooter` — and it is uniformly
black.** The capture path works; the vendor HMI is not yet putting pixels on the output. Both
statements are measured below, not inferred.

- Image: `evidence/vm-bringup/first-hmi-frame.png` — 1920x720, 4,099 bytes,
  sha256 `894ace9b746305c292202c0df0819ffc66792933f153917c6e40184dd685f7ac`.
- Source frame in the guest: `/tmp/shot.ppm`, binary PPM `P6`, 4,147,216 bytes
  (16-byte header `P6\n1920 720\n255\n` + 1920*720*3 = 4,147,200 pixel bytes),
  sha256 `3b5e233a731b938d0b2e9bb5e2234e0a2ac350c314eb0c26f943255eb73ec6ec`.
- Contents: **all 1,382,400 pixels are `(0,0,0)`**. A byte histogram of the RGB payload has a
  single bucket (value 0). This is the compositor's cleared output, i.e. a blank surface.

## Control: the capture path is not the reason it is black

`evidence/vm-bringup/screenshooter-control-simple-shm.png` (sha256
`4cfa611d13dc7d64d908ecf4948cde0fb5f01fec4dd8b6575d592b413393bef0`) was taken with the identical
`ias-shot` build and the identical compositor, with the vendor image's own
`/usr/bin/weston-simple-shm` as the only client. It shows weston's animated 250x250 test pattern
as a textured box occupying exactly `(0,0)-(249,249)`, right way up, with the full 0..255 RGB
range. So dimensions, stride, RGB order and row order are correct, and `ias-shell` does map and
composite client buffers in this backend.

## Why the HMI frame is blank (measured)

- **`--use-pixman` is required.** Without it `ias-backend-soft.so` installs weston's noop
  renderer, whose `read_pixels`/`repaint_output` are empty stubs
  (`work/weston-source-1.10/full/src/noop-renderer.c:33-45`); the shm buffer then stays zeroed no
  matter what the scene is. Every run below uses `--use-pixman`, and weston then reports
  `screen capture uses y-flip: yes` (pixman renderer).
- **`NaviUpdateApp` never submits a buffer.** With `WAYLAND_DEBUG=1` (run
  `work/vm/softbackend/runs/1793388401633468000`) it binds `wl_compositor@4`, creates
  `wl_surface@14` and binds `wl_shell@12`, but never calls `get_shell_surface`, `attach` or
  `commit`. It stays alive (pid 722) with only a `QDBusConnection` warning.
- **`AppHomeScreen` dies before drawing.** It creates one `wl_surface` and a `wl_shm_pool`
  (4096 -> 8832 bytes) and then segfaults:
  `AppHomeScreen[721]: segfault at 8 ... in libQt5Qml.so.5.4.1`. No attach, no commit.
- **`AppLauncher` launches managers, not UI.** `AppLauncher.sh` starts `/app/bin/AppLauncher`
  (pid 726), which starts `/app/bin/ApplicationManager` (pid 797); no application surface appears
  and `AppHomeScreen` is never spawned.
- **D-Bus is unavailable in this harness image.** `dbus-daemon --system` fails with
  `Could not get UID and GID for username "messagebus"`, and `--session` with
  `Memory allocation failure in message bus` (no user database in the projection). The D-Bus
  driven launch chain therefore cannot complete.

Since the control run proves the compositor renders client buffers, the blank frame is a
statement about HMI state: with this image and launch order, no vendor client ever commits a
surface.

## How it was taken

1. Guest-generated protocol headers, using the image's own `/usr/bin/wayland-scanner`:
   `client-header /usr/share/wayland/wayland.xml` (103,210 B), `client-header` and `code` for
   `work/weston-source-1.10/full/protocol/weston-screenshooter.xml` (1,958 B / 642 B).
   Extracted losslessly over a second serial port backed by a host file
   (`-chardev file,id=outhdr,... -device isa-serial,chardev=outhdr,index=2`): `busybox base64`
   to `/dev/ttyS2`, decoded host-side, byte counts identical to the in-guest `wc -c`
   (103,210 / 1,958 / 642).
2. `tools/uk_fw/ias_backend_soft/ias-shot.c` built host-side by
   `tools/uk_fw/ias_backend_soft/build-shot.sh` (bundled zig, `-target x86_64-linux-gnu.2.25`,
   guest headers, linked against the `libwayland-client.so.0.3.0` dumped from the image, so the
   ABI and the glibc 2.25 symbol versions are the guest's own).
3. Injected as `/usr/bin/ias-shot`, mode 0755, with `debugfs -w` into
   `work/vm/softbackend/rootfs.img`; `sha256` for `rootfs.img` in
   `work/vm/softbackend/prepare.json` recomputed (the `prepare` subcommand was not used).
4. Run (run `work/vm/softbackend/runs/1793387840777809000`):
   `weston --backend=ias-backend-soft.so --shell=/usr/lib/weston/ias-shell.so --use-pixman
   --idle-time=0` with `XDG_RUNTIME_DIR=/run/user/root`, `XDG_CONFIG_HOME=/tmp/ias`
   (vendor `ias.conf`), `HOME=/root`; then `/app/bin/NaviUpdateApp`; 30 s wait; then
   `/usr/bin/ias-shot /tmp/shot.ppm`.
5. PPM extracted over the same index=2 chardev in base64 (5,675,157 B with CRLF line breaks),
   decoded to 4,147,216 B — equal to the in-guest `wc -c` — and converted with
   `tools/uk_fw/ppm_to_png.py` (stdlib-only PPM->PNG).

## Next blocker for a non-blank HMI frame

The frame source is ready; what is missing is a vendor client that commits a surface. The two
candidates observed here need `AppHomeScreen`'s Qt QML start-up crash fixed (or the
ApplicationManager/AppHomeScreen chain plus a working session bus), after which the same
`/usr/bin/ias-shot /tmp/shot.ppm` call produces the frame. No further capture work is required.
