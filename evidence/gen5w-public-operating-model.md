# Gen5W operating model: update flow, A/B recovery and persistence

Status: synthesis of public "Gen5 Wide-Open" documentation, now separated from
exact recovered EU `260128` findings. Sources are public GitLab projects and the
public wiki (`g4933/wideopen`, `g4933/gen5w/*`). No device was used and no
exploit or updater was executed. Exact route corrections are in
`evidence/appupgrade-update-trust.md`.

## Why this matters

The userland is AES-encrypted, so the operating model could not be derived
offline. It is nevertheless **publicly documented**, and that documentation
answers most of the questions the ciphertext was hiding: how an update is
validated, how it is applied, where the version check lives, and how persistence
survives an official update.

## Publicly documented update flow

The following is the community operating model. Component attribution is not
promoted to an exact recovered-code finding unless stated separately below.

1. On USB insertion, the public documentation attributes scanning the USB root
   for `.lge.upgrade.xml` to **`AppSetup`**.
2. It invokes **`DecryptToPipe`** — a binary outside `AppUpgrade` — to decrypt
   that file.
3. It reads the version and proceeds only if it is **greater than or equal to**
   the installed version.
4. `AppUpgrade` copies the USB `AppUpgrade` into `/update/usb/` and hands control
   to that copy.
5. The new `AppUpgrade` performs three independent operations:
   - **filesystem**: for each file in `images/`, checksum → decrypt → extract →
     copy to the **inactive** partition;
   - **maps**: extract `appnavi.tar` (encrypted) and `naviX.tar` into `/navi/` or
     `/navi2/` according to `/update/activeNaviPath` and
     `/update/activeResourcePath`; the newly written directory is always the one
     **not** currently active;
   - **firmware**: take the unencrypted `frontkey` binary, decrypt and extract
     `modem_{REGION}.tar.gz` and `update.tar.gz`.
6. On completion it updates `activeNaviPath` / `activeResourcePath`, clears the
   `/update` flag files, **rewrites `/etc/fstab` to boot the new partitions**, and
   reboots.
7. The previous partition and previous navigation directory are left in place as
   a fallback.

Flag files in `/update` include `disableEncryptionUpdate`, `activeNaviPath`,
`activeResourcePath`, `updateVersionInfo`, `system_update_completed`,
`resumeBlockNumber`, `force_launch` and others.

## Publicly described A/B recovery

The public model says the filesystem is written to an **inactive** partition and
that `/etc/fstab` is changed at the end. This is useful recovery guidance, not a
proven property of the owner's installed build. Before relying on it, a
disconnected bench must establish current slot/mount state, boot selection,
console access, and an actual rollback procedure.

A bootloader or boot-image write remains a separate and higher-risk boundary.
Recovered boot-container signature evidence is documented in
`evidence/eu-boot-container-signature.md`; package acceptance and boot-time
image trust must not be conflated.

## `disableEncryptionUpdate`: public claim and recovered correction

Public tooling describes the marker as selecting an unencrypted update while
retaining a `.lge.upgrade.xml` version check. Exact recovered code makes that
statement route-specific:

- AppLauncher's model options are forwarded to a dynamically created app ID 300;
- exact `-un:1` makes the outer wrapper select its SCOMO child;
- `-un:0` or absence of `-un:1` selects FUMO;
- in FUMO, marker existence at process startup changes a mode byte from `1` to
  `0` and logs `Unencryption Update`;
- in the recovered SCOMO MASS_PRODUCT/PENETRATION startup path, the marker is
  explicitly ignored.

The recovered embedded NE/EUR row contains `-un:0`, so its static route is
FUMO, conditional on runtime row selection and installed identity. The FUMO
mode byte is used widely, but marker existence alone does not prove that
version, model/region, signature, hash, target, write, slot, boot, or health
checks are bypassed. The public patcher still requires prior privileged code
execution to create the marker.

## Entry mechanism (public)

`navi_extended` is a replacement for `AppNavi` placed in `/Bin`. It is installed
through **Engineering Mode → Dynamics → Navigation → Config → "Update AppNavi
from USB"**. It finds the USB and runs `main_loop.sh` from its root. The script
copies `DecryptToPIPE` and `decryption_key.der` off the unit.

Documented preconditions:

- an **unpatched/older** build; if the Config entry shows "This feature is
  currently unavailable", the unit must be **downgraded** first;
- an official update on the USB, because the navigation app is extracted from it;
- exFAT-formatted USB.

## Persistence

- Patch `AppNavi` to call `navi_extended` before its normal work, so future
  updates keep the entry point.
- Install `wideopen.service`.
- Every subsequent official update must be re-patched, or the unit loses the
  modification.
- Public SSH path as documented by community material: remount `/` read-write,
  add keys to `/etc/dropbear/authorized_keys` (the shipped key lacks a trailing
  newline), run `/etc/dropbear/dropbear_publickey_installer.sh`, and edit
  `dropbear@.service` to drop its `ConditionPathExists` guard. **This procedure
  is incomplete for recovered EU `260128`:** that image lacks `dropbear`/
  `dropbearmulti`, a socket unit, host-key service/key, and enable links. A
  public patch would have to independently supply and activate that missing
  chain; changing the key and condition alone cannot create a listener.

## Cross-reference with the static findings

| Public statement | Exact recovered status |
|---|---|
| AppSetup owns USB descriptor parsing | **Not confirmed:** exact AppSetup initiates the app-ID-300 transition but does not perform the reviewed discovery/decryption/version/authentication work |
| Version check happens in userspace updater flow | Plausible and consistent with kernel evidence, but the exact recovered compare and owner remain unresolved |
| `DecryptToPIPE` is a separate binary | Confirmed as an artifact; its end-to-end caller/acceptance role remains under reconstruction |
| Update writes to an inactive partition | Publicly described; exact recovered target/write and owner-build applicability remain incomplete |
| `frontkey` is unencrypted | Confirmed package observation: the `MKBD_*.bin` files are plaintext Renesas RL78 firmware |
| `.lge.upgrade.xml` is encrypted and handled through `DecryptToPIPE` | High entropy and helper presence are confirmed; exact caller and trust semantics are not |

Earlier interpretation of `mmcblk0p3` and `mmcblk0p5` as a proven A/B pair was
too strong: command-line/path presence is compatible with multiple hardware or
slot layouts. Effective target selection must be recovered from the selected
updater and observed passively on a disconnected bench.

## What this changes for the plan

1. **Downgrade is the first gate.** The public entry requires a build where the
   AppNavi USB install is still offered. A `260128` unit likely presents "This
   feature is currently unavailable", and the documented remedy is a downgrade —
   which the `>=` version check blocks on a stock unit.
2. **The reported version check is a userspace anti-rollback candidate.** No
   kernel rollback counter was found in the recovered configuration or symbols,
   but the exact compare and any other eligibility controls remain unresolved.
3. **A/B is a recovery hypothesis to verify, not permission to flash.** Slot,
   target, boot-selection, health, and mark-good behavior must be established
   before an active experiment.
4. **Key extraction remains a pivot.** Everything downstream — decryption, patching,
   custom firmware — depends on obtaining `DecryptToPIPE` and
   `decryption_key.der`, and the only documented route to those needs code
   execution first.

## Open questions

- Does a stock `260128` still offer "Update AppNavi from USB", or has it been
  removed? This decides whether downgrade is required at all.
- Is the version comparison `>=` on a normalized tuple, and is it per package or
  per file?
- Does the device enforce any rollback counter outside `AppUpgrade`?
- Is `.lge.upgrade.xml` itself signed, and if so, by the same key as the boot
  container?
- On the bench unit, which of `mmcblk0p3` / `mmcblk0p5` is active at capture time?

## Sources

- `gitlab.com/g4933/gen5w/navi_extended` (README, releases)
- `gitlab.com/g4933/gen5w/update-patcher` (README, `disable_encryption.sh`)
- `gitlab.com/g4933/gen5w/update_decryptor` (README)
- `gitlab.com/g4933/wideopen` wiki: `Software/Update_Process`, `Software/Network`,
  `Unit/Pinouts`, `Hardware/lowlevel`
- `g4933.gitlab.io/wideopen` landing page
