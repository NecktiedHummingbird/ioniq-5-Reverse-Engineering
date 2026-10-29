# IONIQ 5 research history

This file is append-only. It records the IONIQ 5 research programme only.
The root `HISTORY.md` and `CHANGELOG.md` belong to the parallel Kona programme
and are not modified by IONIQ work.

## 2026-10-19 — project-directory consolidation

- Moved the complete IONIQ-owned project tree into `ioniq research/`, including
  the dedicated plan, ledger, history, changelog, evidence, Council review
  packages, test harness and analysis tools.
- Kept the IONIQ directory internally self-contained: paths such as
  `evidence/**`, `council/**`, `tests/**` and `tools/**` remain relative to the
  IONIQ project root.
- Preserved the separate Kona workspace, root `README.md`, root `HISTORY.md`
  and root `CHANGELOG.md` without modification.

## 2026-10-18

- Established the confidential IONIQ 5 research scope for the owner's 2021
  Australian NE1 in Daybreak Blue.
- Recorded the rule that vehicle research covers architecture, interfaces,
  evidence, and risk, while operational theft or live-intrusion procedures are
  outside scope.
- Accepted T1: the published Australian family is Standard Gen5W, model
  `NEAE.S5BLN.AAU`, with software `NE_E.AUS.S5W_L.001.001.260319` and map
  `AUS.19.41.47.011.611.0`. The installed build on the car remains unread.
- Catalogued the public method landscape as T3, separating Android `S5W_M`
  from Linux `S5W_L` and recording that many public recovery claims are author
  statements rather than proven restores.
- Accepted T4: the passive-to-bench route map, including owner-visible
  readback, official media metadata, dealer documentation, spare-unit work, and
  the separation of physical restoration from persistent software state.
- Accepted T5: the NE1 trust-zone and subsystem map, including the smart key,
  immobilizer, body controller, gateway, diagnostics, telematics, ADAS, chassis,
  VCU, BMS/HV, HVAC, camera/audio, and network domains.

## 2026-10-19

- Repaired and ran the official Hyundai Navigation Updater on macOS, moved an
  off-screen updater window back onto the primary display, and downloaded the
  official Australian 2021-23 IONIQ 5 package for read-only inspection.
- Confirmed the package identity: 36 files, 9,514,830,930 bytes, 35 manifest
  payload records, all sizes and IEEE/zlib CRC-32 values matching, a verified
  Australian map, two verified voice-resource MD5 values, and both front-key
  CRC-32/MPEG-2 values matching. The sorted-tree SHA-256 is
  `bc3013e5fc1499612cec76777aa736e0973a0b8a337c6619aace9af5a4d9652a`.
- Recorded that nineteen package files are high-entropy opaque envelopes, that
  six `*_sub` files are plaintext x86-64 Linux 4.1.27 IPK containers, and that
  no decryption, USB write, or vehicle action occurred.
- Accepted T2 after an independent review reproduced the inventory, digest,
  manifest records, MD5 values, and archive format checks.
- Accepted T7: `hmg_nemesis` is a real Android/TCC803x root path but is not an
  applicable method for this Linux `S5W_L` family; its Gate 4 and recovery
  limitations are transferable, its operational mechanism is not.
- Accepted the Council generation 10 review of frozen batch 8, fingerprint
  `9c410e07d2a130c967ac567f5e32788731c909ca2e2c684fc856fc8c3080198b`, with
  Astra, a labelled DeepSeek V4.1 Flash Grok replacement, and a labelled
  DeepSeek V4 Flash Vision Fable replacement all returning COMPLETE.
- Completed the T6 integration draft: `Ioniq5-research-plan.md` traces R1-R11
  to accepted evidence, covers every named vehicle subsystem, defines Phases
  0-8 with exit criteria, closes the T6 portion of ASTRA-G7-S01 through a
  four-part Gate 4 conjunction, and separates physical restoration from
  persistent software-state coverage.
- Added dedicated IONIQ history and changelog documents plus a root
  `.gitignore` that excludes firmware, package and extraction trees, dumps,
  captures, credentials, identifiers, and personal-data workspaces while
  retaining text evidence.
- Recorded that no live vehicle entry, diagnostic session, USB write, firmware
  flash, or actuation was performed. T6 review, staged-content verification,
  commit, and push to the private `Ioniq-5` repository remain coordinator
  actions.
- Revised the private-repository retention policy at the owner's request:
  firmware, extracted analysis trees, captures, device-specific dumps, vehicle
  identifiers, and analysis workspaces may now be deliberately committed. The
  downloaded 9.5 GB official package tree and live credentials/private keys
  remain excluded, and Kona-owned paths remain outside Ioniq commits.
- Corrected the active vehicle scope to the owner's UK-origin 2021 IONIQ 5 and
  selected the official European Standard Gen5W package
  `NE_E.EUR.S5W_L.001.001.260128`; retained the Australian package as comparison
  evidence rather than rewriting the earlier accepted record.
- Verified all 17 completed European payloads against their manifest CRC-32
  values and recorded the interrupted map-download state without deleting the
  11 GB cache.
- Repaired, ad-hoc signed and registered an isolated Navigation Updater copy,
  resumed the existing European cache through LaunchServices, and observed it
  rewrite interrupted segments and advance through new parts beyond `.z964`.
- Recovered all 64,923 kallsyms entries from the exact European x86-64 Linux
  4.1.27 kernel. Applied 25,068 names in Ghidra and decompiled 48 priority
  security functions, including the LG keystore and OEM-signature chain.
- Assessed published Gen5W root/application-loading methods against build
  `260128`. No public stock-to-root path is presently confirmed; published
  persistence, decryption and SSH components require prior execution.
- Added the interim EU/AUS byte comparison and region-transition gates. The
  Australian package is not established as a safe cross-region install.
- Completed the official European package: all 35 payload sizes and signed
  CRC-32 values match, the map and both voice MD5 sidecars match, and the
  36-file SHA-256 inventory digest is
  `f06752ea7cbf296ef7d7d7482f5ba96a3349161fc7ad0d60b36b042f62ef5b51`.
- Completed the EU/AUS file matrix: six of 32 common paths are byte-identical,
  nineteen are equal-size but byte-different, seven differ in size and bytes,
  and four paths are region-specific to each package.
- Confirmed that corresponding EU and AUS boot targets use the same x86-64
  Linux 4.1.27 kernel configuration but different kernel and signed-container
  bytes and different January/March 2026 build dates.
- Added a defensive custom-firmware and privileged-access feasibility report.
  It documents prerequisites, trust boundaries, published-method applicability
  and candidate audit surfaces without implementing an exploit, bypass,
  modified image, flash procedure or live vehicle action.


## 2026-10-26 — retrospective backfill and continuation contract

This entry is appended on 2026-10-26. The existing history through 2026-10-19
is preserved byte-for-byte. Dates below describe recorded milestones, not new
runs performed during this backfill. Sources are the existing changelog,
HANDOVER.md, Git history and named evidence; historical errors remain in place
and are superseded by corrections rather than silently rewritten.

### Backfill: 2026-10-20–21 — vendor-kernel VM and bounded recovery

- Consolidated the project as its own Git root. Git commits through `852c168`
  record boot-parameter research, VM boot and graphics harness work.
- Recovered the `ABL.` parameter collection mechanism and synthetic manifest/
  seed initialization. Later evidence corrected the earlier anti-tamper-panic
  attribution: the observed fatal failure was root mounting, not proof of a
  security bypass. Synthetic inputs are not recovered device keys.
- Reached interactive userspace with an exact-build guest-RAM SDHCI PCI-table
  adaptation and compatible ext4 root. Kept boot-image files unchanged and
  classified this as a VM-adapted vendor kernel, not stock-device boot.
- Demonstrated keyboard/pixel-verified direct-QEMU-VGA diagnostics, explicitly
  not vendor HMI or a DRM/EGL backend.
- Retained bounded negative RSA/updater-constant recovery experiments without
  claiming that all offline recovery was impossible. Corrections C12–C14 and
  changelog 0.40.0 supersede the categorical older ceiling claims.
- Sources: `evidence/vendor-kernel-vm.md`, `evidence/vendor-kernel-graphics.md`,
  `evidence/local-ui-recovery.md`, `evidence/corrections-log.md`.

### Backfill: recorded 2026-10-22 continuation — module and envelope work

- Existing local notes record envelope-format refinements and unsigned module
  initialization in QEMU against the vendor kernel. This requires privileged
  module loading; it does not establish an unprivileged or remote entry path.
- Source: `work/ui-recovery/SUMMARY-and-runbook.md` and
  `work/ui-recovery/SECURITY-FINDING-module-load.md`. Their contemporaneous
  claims that userspace recovery was device-gated are superseded below.

### Backfill: 2026-10-25 — recovered authentic userspace and visible map

- Native TE2/xcrypt decryption recovered EU/AU payload userspaces. Existing
  review records 28 focused decryptor tests, 165 repository tests, and a real
  EU descriptor output matching independently preserved recovered bytes.
- Recovered Weston/IVI plus project-local Mesa rendered authentic Home; bounded
  EU map/core/skin resources allowed AppNavi engine initialization and genuine
  836×720 map-widget pixels. The IVI hierarchy helper and zero-MSAA adaptation
  remain explicitly VM infrastructure, not stock behavior.
- Source: changelog 0.41.0 and the visible-navigation milestone at
  `work/vm/vendor-userspace-260128/ivi-link-navi-widget-build/visible-navigation-milestone.json`.

### Backfill: 2026-10-26 — launcher, Confirm and Navigation integration

- Fixed the duplicated `ivi:ivi` environment and added isolated micom serial
  transport. Reconstructed an exact 35-byte `AskSysBootinfo` reply and a
  fail-closed simulator; data-bearing CAN simulation remains incomplete.
- Authentic Confirm dispatch succeeded with two-thread llvmpipe: standby
  status 12, agreement true, cleared filters, authentic Home show/response,
  current/drawing Home 11, and visible composition. A bounded manager pause
  avoids a slow-TCG false liveness kill; no successful reply or pixels are
  fabricated. Immediate transition value 255 alone is not a rejection verdict.
- AppLauncher-owned, signature-checked AppNavi reached engine/EGL success and
  surfaces 3000/4903 through a targeted preload. A guarded PIE-aware in-memory
  startup deadline adaptation ruled out the original 22,999 ms timeout as the
  sole cause of incomplete Navigation transition. The signed file stayed intact.
- Latest recorded launch notification remains status 5/window 0. Manager state
  is `11/11 → 35/11 → 11/11`; full Home↔Navigation is not demonstrated.
- Sources: changelog 0.42.0–0.45.0, current HANDOVER top sections, correction C15.
  Latest complete archive SHA-256:
  `a0e2100ca5a0eb72426db6179c88a27e34abe5928d8a364ce9f14d0e9bfd52b8`.
  Recorded rootfs SHA-256:
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`.
  These are inherited evidence identities, not newly rehashed VM artifacts.

### Current continuation setup

- Owner reaffirmed the goal: authentic full-system VM operation with simulated
  adapters, drivers and OS support, plus editable changelog, append-only history,
  and a separate vulnerability document for patching.
- Added `Ioniq5-VULNERABILITIES.md` from existing security research, with explicit
  verification levels, remediation and acceptance criteria. No new vulnerability
  experiment or live-device validation was performed.
- Added `PROJECT-OPERATIONS.md`, documenting current milestones, exact next
  Navigation contract investigation, same-chat-only continuation and proposed
  scheduled instruction. Interval and active-work behavior await confirmation;
  no scheduled task was created during this setup.
- Routing doctor using Python 3.13 reports the installed DeepSeek Flash role as
  statically ready, runtime unverified. Current tools provide child threads but
  no native role-selectable worker interface. No threads were created, no
  workers invoked, and no router/model settings changed. Security restrictions
  will not be evaded through model switching.
- Preserved all pre-existing dirty/untracked source and research work. No image
  mutations, VM runs, commits, pushes, physical-device actions or flashes.

### Continuation-setup validation

- All 168 repository unit tests pass using the documented test interpreter.
- `git diff --check` passes. The original 6,819-byte history prefix was verified
  unchanged (SHA-256 `f15420373116d5c314ea9e88c4fc6ac96a813652f75121ab21ca7b478d1e508a`).
- Test output: `work/test-tmp/continuation-setup-unittest.log`. No VM feature
  acceptance or Council acceptance is implied by these checks.

## 2026-10-26 - existing scheduled-task continuation request

- Owner requested retaining the existing recurring task and no new chat threads.
- Listing showed task `206efda3-54ed-456c-a4f5-07b272247cc9` (keep going) active;
  the named IONIQ check-in and heartbeat tasks were paused.
- Updates with explicit same-chat-only instructions were rejected by scheduler
  validation (workspace target, then interval-incompatible time/timezone fields).
  No successful update, replacement task, or thread creation is claimed.
- Original cadence was not exposed by listing. The attempted 30-minute setting
  was rejected and is not evidence of the original cadence. Stopped retries;
  scheduler API repair or UI editing is needed. No pause/delete was performed.

## 2026-10-26 - bounded Navigation notification review

- Reviewed existing saved SendToAppLauncherNaviLaunchedToExcute disassembly.
  The function constructs a QVariant from literal 5 at 0x2c08e31, appends it to
  a signal and sends it after an initial one-shot flag gate. It does not select
  this value from engine state in the reviewed normal flow. Enum semantics and
  exact message strings remain unresolved; this is not proof of success.
- Added evidence/navigation-launch-status-contract.md and updated handover and
  editable changelog. Next resolve message identities and manager receiver/window
  producer. No guest execution, image mutation, thread creation, or new security
  finding occurred. git diff --check passes; prior 168-test result is not a new run.

## 2026-10-26 - exact AppNavi notification identities

- Read-only ELF section mapping resolved seven strings from original AppNavi,
  SHA-256 62d6e0b3119b99b3fe322ec3bbe03366e9f71ed40dc18b0323d2a9da0e7fa1a3.
- Saved code first calls launcher /Inform launched(30), then emits
  /navigation_map com.lge.hkmc.avn.appnavi.naviboot.SendNaviBootFail(5).
  Process registration and boot notification are distinct messages. Enum meaning,
  selected caller path and manager window-state producer remain unresolved.
- Retained raw address/offset/string mapping in the project-local notification
  JSON and updated evidence/navigation-launch-status-contract.md, handover and
  changelog. Located original ApplicationManager for subsequent receiver analysis.
- Mapping JSON parsed and seven entries checked; git diff --check passes.
  No guest execution, image change, new threads or new vulnerability claims.

## 2026-10-26 - ApplicationManager receiver triage

- Mapped SendNaviBootFail, notifyNaviLaunched and the boot interface strings in
  original ApplicationManager (SHA-256
  5d71539f61a3982b8aac6132a2de14c083fa9ac129792bae750a526ebd771cbc).
  Six literal matches retained in manager-notification-string-locations.json;
  they are not function addresses or proof of receiver behavior.
- No matching handler names exposed by ordinary/dynamic symbol inspection.
  REA reports Ghidra unconfigured, Hopper absent and IDA unconfigured. No installs
  or configuration changes made. Existing LLVM/Qt metadata remains a viable path.
- Updated Navigation evidence note and changelog. No guest execution, VM mutation,
  new thread, scheduler change or new vulnerability claim. git diff --check passes.

## 2026-10-26 - recovered Navigation window notification gate

- Original ApplicationManager LLVM disassembly establishes a Qt subscription
  using slot string 1notifyNaviLaunched(int). Diagnostic routine at 0x287e70
  reads window from receiver byte +0x20, caches incoming status at +0x1c and
  gates downstream dispatch when the byte is zero.
- Adjacent routine at 0x288070 logs vendor naviWindoeCreate, stores the incoming
  byte at +0x20 and invokes status handling with the cached status. Direct caller
  0x19108d is the next producer to trace. This is static control-flow evidence,
  not proof of successful VM transition or complete enum recovery.
- Retained original-binary disassembly and bounded extracts, updated Navigation
  evidence, changelog and handover. No synthetic success, flag patch, guest run,
  image mutation, new thread or new vulnerability claim. diff whitespace check
  passes; no fresh full-suite execution was needed for these research notes.

## 2026-10-26 - window-create producer narrowed

- Traced caller 0x19108d into routine 0x190c70, identified by exact diagnostic
  slotNotifyBGInfo surface_id/display/app_id. Display/string helper success,
  nonzero global 0x5c5028 and case-sensitive AppNavi containment precede the
  window-created notification; the global is cleared after notification.
- Global initialization, matching helper semantics and upstream caller 0x2d6611
  remain to be traced. A host-log-only negative search does not establish absent
  guest callbacks. Updated bounded Navigation evidence and editable changelog.
- No target execution, image mutation, forced state, new threads or security
  findings. git diff --check passes.

## 2026-10-26 - correlated FG/BG notification mismatch

- Recovered display-record selection and exact QString app-list equality.
  Pending gate 0x5c5028 initializes to 0xffffffff, not zero; no claim that an
  initially zero gate explains the missing notification remains supported.
- Scanned all 123,763 lines of retained latest DLT log, SHA-256
  02fa2f7268f574184745739afaa8a3e5e4db61c3b7093f70991e9e93d7a0d972.
  AppNavi surface 3000 produces FG info and manager slotNotifyFGInfo before
  status 5/window 0. Zero BG-info/window-created-latch diagnostic matches in
  that file; lossless collection is not established by the search.
- Recorded parent dimensions 1926x753 without attributing causality; harness
  already disables Qt window decorations. Next trace compositor FG/BG decision.
- Retained hashed correlation JSON and matcher disassembly; updated evidence,
  handover and editable changelog. No VM run, mutation, new threads or new
  vulnerability. git diff --check passes.

## 2026-10-26 - compositor notification classification recovered

- Original recovered compositor module copies match SHA-256
  e1ce4d479f1fb84cc44d2faebad748206bdf3003b48a9ccf90e76da17a553bd0.
  Local callback 0xf8e0 selects FG for any positive width or height, BG only
  when both are non-positive. It does not test exact screen resolution.
- This refines the geometry hypothesis: correcting 1926x753 to 1920x720 would
  not alter this notification selection. Next inspect initial zero-size
  configure lifecycle and verify the guest loaded the same module bytes.
- Saved disassembly, updated Navigation evidence, handover and changelog.
  No fabricated BG event, property change, VM run, new thread or vulnerability
  claim. git diff --check passes.

## 2026-10-26 - current-image compositor provenance and host timeout

- Read-only debugfs extraction of both current-image compositor paths matches
  original SHA-256 e1ce4d479f1fb84cc44d2faebad748206bdf3003b48a9ccf90e76da17a553bd0.
  Latest retained Weston log records loading the /usr/lib/weston path. This is
  current-image/path corroboration, not a historical in-memory digest.
- Subsequent shell-module disassembly and a follow-up command each timed out
  at 15 seconds. Their completion is unverified; any output may be partial.
  Stop retries and check host/process responsiveness before more analysis or VM runs.
- Existing keep-going task again listed active; prompt update again rejected
  by interval/time-field validation. No successful schedule change is claimed.
- Updated Navigation evidence and history. No guest execution, image mutation,
  new threads or vulnerability discovery. No new test result is claimed.

## 2026-10-27 - host recovery and shell configure semantics

- Host shell responsive; process snapshot found no matching QEMU or LLVM worker.
  Fresh bounded shell disassembly completed, superseding the outstanding timeout
  blocker without claiming that the original timed-out commands completed.
- Current image IVI shell extracted read-only and matches original SHA-256
  8b57db4baa1f35a1a08cffc6de221101a92b37528123d7250c774db03a3b7697.
- Original create routine initializes size cache to 0/0; configure returns when
  both dimensions match. An initial zero-size surface does not itself produce
  a layout configure/BG event through this path. The previous initial-zero
  hypothesis is narrowed, not accepted as root cause.
- Next compare retained positive BG events against AppNavi hide/unmap/buffer
  lifecycle. Updated evidence, handover and editable changelog. No VM execution,
  image mutation, new threads or security findings. git diff --check passes.

## 2026-10-27 - revised orchestration ceiling and Fable route check

- Owner raised DeepSeek worker ceiling from 20 to 30 and requested Astra/Fable
  planning, decisions, guidance and review, with nonduplicated efficient tasks.
- Updated operations contract and prompt draft. Existing no-new-chat-thread rule
  remains; native role-selectable delegation is not exposed in this session.
- Read-only Fable doctor failed: exact openrouter/claude-fable-5.1 route exists
  but is not advertised as native-subagent v2. No config changes, paid tests,
  worker launches or substituted model claims. Actual requested orchestration
  remains blocked pending host/tool routing support.

## 2026-10-27 - positive retained BG controls

- Older retained Camera/Standby logs show initial 1926x753 FG configure followed
  by zero-size configure, BG emission and manager BG receipt. Thirteen selected
  events retained with log digest and line provenance in navigation-contract-audit/
  positive-bg-event-control.json. Different-run control, not an AppNavi fix.
- This demonstrates a working earlier VM BG path. Next focus on AppNavi's
  onVisibleChanged(0), buffer detach/commit and zero-size configure lifecycle.
- Latest repeated owner message specifies up to 20 workers; operations ceiling
  adjusted accordingly while preserving the earlier 30-worker request in history.
  No workers launched, VM mutations, new threads or vulnerability claims.

## 2026-10-27 - AppNavi visibility versus unmapping distinction

- Bounded original-binary analysis shows onVisibleChanged(false) updates the
  first-hide flag, may call the one-shot boot notifier and calls clearScreen.
  The inspected clearScreen path clears and swaps renderer buffers; it does
  not prove a null Wayland attach or parent Qt-window hide. Virtual downstream
  implementations remain unresolved, not asserted absent.
- Retained logs corroborate callback execution. Next identify its source and
  parent-window hide path separately from native-map rendering operations.
- Updated evidence and editable changelog; appended this history entry. No VM
  run, image change, new thread or new vulnerability. git diff --check passes.

## 2026-10-27 - authentic Qt hide path located

- Located QWindow::hide at 0x3362275 in AppNavi onForeground, gated by base
  foreground handling and screen-specific control flow. Retained symbols and
  bounded create/foreground/base listings. This is distinct from renderer clear.
- Latest PID-908 foreground log scan exposes widget screens 6/9/10, not a
  matching primary-screen hide diagnostic; coverage does not prove invocation
  absence. Next trace constructor signal connection and primary foreground
  requests/deduplication, then actual Wayland null-buffer evidence.
- Updated Navigation note and editable changelog; no VM run, image edits,
  new threads or vulnerability claim. git diff --check passes.

## 2026-10-27 - Qt signal wiring and conditional Wayland detach

- Constructor strings/control flow confirm same-object visibleChanged(bool)
  connection to onVisibleChanged(bool), refining earlier signal-source uncertainty.
- Recovered QtWayland setVisible(false) explicitly attaches null/commits only
  when virtual slot +0x60 returns zero. Recovered EGL plugin inherits the handler
  and its slot implementation returns one, skipping that branch. Retained exact
  library identity, disassembly and plugin relocations in Navigation evidence.
- Actual guest byte identity/backend/instance remains to verify; no sole-root-
  cause or runtime fix claim. Next observe the authentic hide path and explain
  older positive BG controls before implementing a scoped compatibility adapter.
- Updated evidence, handover and editable changelog. No VM run, image changes,
  new threads or vulnerability claims. git diff --check passes.

## 2026-10-27 - current-image QtWayland identities verified

- Read-only extraction confirms current QtWayland client/EGL plugin match the
  recovered originals analyzed in the hide-path investigation. Digests and
  retained copies recorded in Navigation evidence.
- Runtime selected backend remains unknown: saved launcher log lacks explicit
  load identity, no AppNavi process-map snapshot found in inspected evidence,
  and alternate library directories precede /usr/lib. Do not equate image file
  identity with actual loaded objects.
- Next bounded run should capture mapped identities and actual hide/Wayland
  behavior observationally before changing it. No VM execution, image mutation,
  new thread or vulnerability. Updated evidence/changelog; git diff --check passes.

## 2026-10-27 - completed observational backend VM experiment

- Ran observation-only wrapper (SHA-256
  4ddf1fee3a7fcb5b3fc8b0873ab0d5dac625ccfacf45a973bfab6947df279880)
  around unchanged baseline runner; QEMU no-NIC/snapshot, 1536 MiB, host bound
  900 seconds. Harness completed in 404.87 seconds, command exit 0, no timeout.
- Collected 26 AppNavi maps snapshots and strictly allowlisted environment.
  Actual mapped QtWayland client and EGL plugin match analyzed originals.
  AppNavi environment has QT_WAYLAND_DISABLE_WINDOWDECORATION=1:1 and decoration
  plugin is mapped; parser effect remains to verify.
- Inspected authentic visible Home before Navigation. Manager sequence again
  11/11 -> 35/11 -> 11/11 with FG delivery and status 5/window 0. Final return
  screenshot inspected black, not accepted as restored Home despite manager state.
- No raw Wayland request trace in inspected logs despite WAYLAND_DEBUG=1; actual
  null-attach path remains unobserved. Late Camera/Radio crash messages retained
  without unsupported cause or vulnerability attribution.
- Complete archive SHA-256
  6019ec6e42cacce8a41fdc79c7dd9705487efdc0a53b741313e6b5b7aad01d84;
  serial-announced digest matches decoded bytes; extracted with safe data filter.
  Host log SHA-256
  2e961f8277683f21d40172b9e6c34816c04c28893519c4f1ccb3a82417464085.
- Rehashed base rootfs unchanged at
  4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f.
  All 168 repository tests pass; shell syntax and git diff --check pass. Updated
  evidence, handover and editable changelog. No new threads, image writes,
  synthetic state/callbacks, commits or new vulnerability claims.

## 2026-10-27 - decoration-disable scalar parser identified

- QtWayland supportsWindowDecoration reads the decoration-disable variable via
  QByteArray::toInt(nullptr,10), caches nonzero as disabled. Retained bounded
  original-binary disassembly. The observed 1:1 is not a supported scalar form;
  expected invalid-to-zero result remains inference until exact-library execution.
- Proposed future control: avoid pre-setting a scalar AppLauncher appends, verify
  child value exactly 1 before first Qt initialization. No setting changed; do
  not equate decoration correction with solving the separate BG/hide contract.
- Updated evidence/changelog and appended history. No VM run, image mutation,
  new threads or vulnerability claims. git diff --check passes.

## 2026-10-27 - negative decoration-unset environment control

- Verified baseline runner digest, changed only the pre-set decoration export
  to unset, transferred control/observer into snapshot guest /tmp. Same prior
  compatibility behavior otherwise; no base image injection.
- Harness completed command exit 0/no timeout in 474.71 seconds, but feature
  result failed: repeated Camera/Standby crashes, no authentic agreement, no
  AppNavi snapshots, manager 0/0 and all screenshots splash. Do not adopt this
  change or call it a Navigation fix. Early-client environment/crash context was
  not captured by the AppNavi-specific observer.
- Complete archive SHA-256
  648b5d30c169b2e4adaa2e8cf069742fd5b3d779b0ef1d6d7e63fead7f6910e9;
  digest independently matches serial announcement; safe extraction completed.
  Host-log SHA-256
  9df711936074c3be7b129b8c80b55f1a8a9f102e910d35c4e1c15228499162dc.
- Exact source delta and semantic summary retained. Base image independently
  rehashed unchanged at
  4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f.
  Original working baseline preserved; no automatic retry. Next use an early-
  client-focused control, not the whole sequence, for the environment failure.
- Updated handover/evidence/changelog; no new threads, commits or vulnerability
  claim. Shell syntax and git diff --check pass; prior 168-test result retained,
  not presented as a fresh test run for this shell-only experiment.

## 2026-10-27 - bounded crash-site analysis

- Recovered libc offset 0x128dde decodes to vmovntdq ymm0,(r9), a vector store
  in bulk-copy-style code. Retained exact libc digest and bounded disassembly.
  Memory-write fault is not SIGILL; caller/length/register context unresolved.
  No unsupported-AVX, QEMU-defect or vendor-vulnerability conclusion follows.
- Canonical piefix and both new run command manifests share max/GenuineIntel
  CPU and 1536 MiB. Older no-AVX2 runs are separate controls, not this baseline.
- Updated evidence/changelog; no new VM run, image change or thread. Next use
  short early-client crash observation rather than repeat the failed full flow.
  git diff --check passes.

## Delegation correction - recorded after the 2026-10-27 checkpoint

- Earlier explanations that no inline model-selectable worker tool was exposed
  were wrong: spawn_worker is exposed and does not create a chat thread.
- Dispatched one bounded read-only early-crash investigation requesting exact
  configured deepseek/deepseek-v4.1-flash, high reasoning. Host tool returned
  store.runWorkerToolResult is not a function. No worker findings, completion
  or inference routing metadata were obtained; underlying execution is unknown.
- Stopped rather than duplicate the dispatch, switch routes or create a child
  thread. Actual blocker is host worker integration, not the no-new-thread rule.
- Corrected operations, handover and editable changelog while preserving this
  history's older entries. No new VM action, image edit or vulnerability claim.

## Crash-capture planning follow-up

- Recovered guest inventory has strace but no gdb/gdbserver found. Vendor kernel
  configuration enables ELF core dumping and procfs. Planned a short snapshot-
  only early-client core-note capture rather than writing/installing a debugger.
- Bounded/header-only core filtering can capture registers/signal/map notes but
  not a reliable stack backtrace; output completeness needs validation. No procfs
  setting changed and no new experiment launched. Updated evidence/changelog;
  no new threads, image mutation or vulnerability claim. git diff --check passes.

## Supplied community-chat evidence reconciliation

- Owner supplied a summary of #general-g5w-linux and #userful-resources-linux,
  including AppNavi replacement/menu removal, tentative CV_E 220721 recollection,
  unsuccessful updater attempt/signature checks, xcrypt and downloader reports.
  Recorded in evidence/community-chat-leads.md without claiming channel access,
  repository reinspection, raw-message provenance or hardware validation.
- Kept CV_E distinct from NE_E and decryption distinct from authenticated update
  acceptance. Historical downloads remain model/region/time dependent. No new
  current-build entry, downgrade or vulnerability was established.
- Added warnings to three older notes to prevent stale plaintext/device-key/API
  conclusions from being reused as VM blockers. Current native recovery already
  supplies userspace. Linked unvalidated updater-attempt provenance to V-005 and
  updated handover/changelog. No external fetch, VM execution, image change,
  new thread, firmware installation or disclosure occurred.

## Focused early-client core experiment completed

- Ran snapshot-only early startup with bounded core settings, no agreement or
  Navigation sequence. Harness elapsed 44.83 seconds, command exit 0/no timeout.
  Captured one 81,920-byte AppCamera core with eight thread status notes.
- ELF64 note/program-header bounds validated. Fault SIGSEGV/SEGV_MAPERR at libc
  offset 0x128dde, R9/fault address 64 bytes below writable mapping start RDI.
  Core stack segment has no stored bytes; caller/original copy length unresolved.
  Modified in-loop RDX is not claimed as an original negative argument.
- Verified early-client decoration value exactly 1. Requested filter 0x10 read
  back 00000000; report actual coverage rather than assume filter semantics.
- Complete archive SHA-256
  10fbb21b674ab1795c5e2b52d4e04ad47611f8674c4ac5ed43d283322c24987c;
  decoded digest matches serial announcement and safe extraction completed.
  Core summary/script/run manifest retained in navigation-contract-audit.
- Rehashed base image unchanged at
  4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f.
  Updated evidence, handover and editable changelog. Shell syntax and whitespace
  checks pass; no fresh unit-suite result asserted. No new thread, image mutation
  or vendor-vulnerability claim. Next bounded fault-time stack/caller capture.

## Resumed work - bounded stack capture and EGL caller

- Added VM-only ptrace_crash_observe.c, explicit early-client path allowlist,
  bounded SEIZE-based main-thread observation, 64 stack words, bounded maps,
  original fatal signal redelivered. Cross-compiled with project Zig/musl and
  warnings-as-errors; initial type-format errors fixed before guest execution.
- Short snapshot run completed in 43.7 seconds, command exit 0/no timeout.
  Guest invalid-PID and disallowed-executable tests pass; real Camera SIGSEGV
  captured with 64 readable stack words and original signal 11 re-delivered.
  Timeout/cancellation/group-stop paths not dynamically exercised.
- Top stack return location immediately follows real memcpy call at vendor EGL
  dri2_wl_swrast_put_image2. Width-derived stride cached before buffer update,
  which can replace width; captured stride/count registers -4. Original memcpy
  entry arguments and exact initialization remain to measure, not invented.
- Qualified mixed-stack investigation I-001 added to vulnerability register,
  with stock-hardware reachability/impact explicitly unproven. Updated evidence,
  handover, operations and editable changelog. No Navigation-success claim.
- Complete archive SHA-256
  e0884a3c11582ed2b986db28f2673b7fde9297a1871f2633ad13672b2dfdeaae;
  host-log SHA-256
  45b07d1dd3f87b00cb306e1d56f3253beccbb819eea239df105b7a887daab86a.
  Digest verification and safe extraction pass. All 168 repository tests pass.
  Base image independently rehashed unchanged at
  4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f.
- No new chat threads, image writes or commits. Delegated host tool remains
  blocked; no independent Astra/Fable/DeepSeek review is claimed. Next bounded
  update-time geometry and copy-entry observation before adapter changes.


## 2026-10-27 — Parallelism and Council plan review

- Activated the requested Parallelism and three-seat Council workflow without
  creating chat threads. Astra-high planned; Astra-high and two independent
  Sol-medium reviewers completed independent and reconciliation rounds against
  the same frozen package.
- Council checker rehashed the package and returned COMPLETE for the plan only.
  Fingerprint c59ac8a0d4ece96fd8fab5fe8a6795789697c95394d6e548a02dc8484052bbb5;
  packet SHA-256
  528649b5b337fb0b76bafd6cb9b020e572851ec33136c6d0927a5c38a12ef790.
- Corrected the interpretation boundary: captured -4 does not prove original
  width -1 or that width changed during that invocation. Accepted plan requires
  raw pre/post dimensions and update state, EGL call-site arguments, and actual
  resolved copy-entry arguments with PLT/IFUNC-aware attribution.
- Council retained nonblocking downstream requirements: record vendor EGL and
  project Mesa identities together; numerical capture caps; debugger-state
  restoration; and host-owned VM termination after timeout/restoration failure.
- Attempts to dispatch EC-01/EC-02 to the catalog-suggested
  opencode/deepseek-v4.1-flash route failed because no API key is configured.
  No DeepSeek work ran, no alternate model was substituted, and the ledger marks
  both tasks blocked. No observer implementation or authentic VM run occurred.
- Latest scheduler listing showed the retained keep-going task paused. Its prompt
  update again failed because the API requires time/timezone fields while also
  rejecting those fields for an interval schedule. No active heartbeat claimed.


## 2026-10-27 — direct DeepSeek provider policy correction

- Owner clarified that all DeepSeek workers must use the direct DeepSeek API
  provider, not OpenCode. Updated Parallelism and Council skills, protocols,
  README, installation guidance and invocation metadata to require provider-
  qualified `deepseek/...` routes and fail closed instead of using OpenCode,
  OpenRouter, Codex Router or another intermediary fallback.
- Corrected the current project checkpoint: the earlier OpenCode no-key result is
  historical route probing, not the authorized worker route. The live worker
  tool previously rejected `deepseek/deepseek-v4.1-flash` as unknown. EC-01 and
  EC-02 remain blocked pending an exposed/authenticated direct DeepSeek model.
- Parallelism unit tests: 148 pass. Council unit tests: 93 pass. Both packaging
  validators reached their external validation step but failed because PyYAML is
  absent from that validator environment; no package was installed to bypass it.


## 2026-10-28 — unverified physical-access vectors recorded

- Received a third-party advisor summary asserting three physical-access vectors:
  USB descriptor strings reaching a privileged mount script; media file parsing
  running as root; and a root serial console gated by a hashed password.
- No logs, script excerpts, device identity, process identity, console device or
  reproduction accompanied the claims. None was validated against the recovered
  image in this session. Recorded as V-006, V-007 and V-008 with explicit
  "unverified actor report" status so they are neither lost nor treated as
  established findings.
- Technical caveats recorded with each: USB string descriptors are UTF-16LE so
  ASCII metacharacters arrive NUL-interleaved, and udev sanitises ID_SERIAL /
  ID_MODEL, so a vulnerable path needs a custom consumer; the 126-code-unit
  descriptor limit would still admit a ~40 character payload, making encoding and
  quoting, not length, the binding constraint. A hashed root console password is
  ordinary practice and only becomes a finding if the hash is weak, reused,
  bypassable, or its material is extractable.
- All three require physical access and none is a remote vector. Validation is
  scoped to the isolated VM snapshot or offline analysis of the recovered rootfs.
  No experiment was run against hardware.


## 2026-10-28 — advisor claims validated offline against the recovered rootfs

- Tested the three third-party claims of 2026-10-28 against the recovered
  `260128` rootfs. None was accepted as originally stated; one was upgraded to a
  confirmed vulnerability on different mechanics.
- V-006 upgraded to a CONFIRMED static command injection (CWE-78) in
  `/app/bin/usb-automount`. `__sprintf_chk` at 0x5326 builds `"%s %s %s %s &"`
  from `ID_SERIAL_SHORT` and `system()` is called at 0x535f; `popen()` at 0x53b9
  runs `cat /proc/mounts | grep %s` with the same string. Reachable only on the
  PTP (`060101`) or vendor-specific (`ffff00`) branch; the mass-storage branch
  uses mount(2)/umount2/mkdir with no shell. The advisor's "mount script"
  mechanism was wrong.
- The usual udev mitigation does not apply: `usb_id` sanitises through
  `util_replace_whitespace` and tests only the `_ISspace` ctype bit at 0x22b72,
  so only whitespace is rewritten. The serial filter at 0x1c2df allows
  0x20-0x7f and rejects comma, which neutralises literal spaces and comma-list
  brace expansion but not parameter expansion. The advisor's literal payload
  would therefore have failed; a parameter-expansion variant would not.
- Aggravating: `/tmp` is tmpfs read-write from `esinit:10`; `/usr/bin/go-mtpfs`
  is absent but the shell expands the whole line before execution, so a missing
  helper does not block an injected command. Service has no `User=` so runs as
  uid 0.
- V-007 confirmed as configuration only: no media unit sets `User=`,
  lightmediascannerd/thumbnail_extractor/mediamanager/playerengine/MediaBrowser
  are configured uid 0, no seccomp or capability restrictions exist and the
  image has zero setuid binaries. Reclassified as informational hardening, not a
  demonstrated vulnerability; no parser defect was found and runtime uid was not
  observed.
- V-008 confirmed as shipped configuration, not as a vulnerability: agetty on
  ttyS2 115200 with autologin commented out, securetty permits ttyS2,
  passwd.legacy gives root /bin/sh, and shadow.Global root is a $6$ SHA-512-crypt
  verifier with a unique salt and no locked marker; the other 18 accounts are
  locked. esinit is fail-open because it creates the enable marker before testing
  it. Dropbear is absent and inert despite one static authorized_keys entry.
- Astra triaged the three findings and corrected several overstatements: a
  system-service default is not an observed uid; absence of seccomp directives is
  not proof of no filtering; comma rejection blocks only comma-list brace forms;
  and a password verifier is not evidence of password weakness. Astra also
  advised that head-unit root does not establish vehicle-bus, safety-system or
  key-material access, and recommended holding V-006/7/8 technical dossiers
  privately pending vendor contact. The public mirror was left unchanged at its
  conservative "unverified" text.
- Fable was requested twice for this triage and returned neither text nor the
  requested output file, so no Fable execution is claimed. Astra performed the
  triage instead and is attributed as such.
- No VM was booted and no device was touched; all evidence is static.


## 2026-10-29 — EC-02 blocked by over-specification

- Reviewed the EC-02 hardware-breakpoint mechanism four times. Round 3 took the
  instructed change of approach: a normative machine-readable state machine
  (17 states, 48 transitions, 21-row classify-only decision table, mechanically
  derived budget) became the single source of truth, with the prose report and
  facts reduced to citations.
- Round 4 still returned REQUEST_CHANGES. Defects found were structural rather
  than editorial: absent pre-arm and subsequent revalidation failure edges; no
  ST_SEIZE -> ST_STOP0 transition and no initial interrupt; already-forwarded
  signals left pending and therefore redeliverable; budget operation sums that
  disagree with their own declarations plus unreachable maxima; a detach-error
  terminal that falsely reports the tracee detached; classifier row 8 shadowing
  nested and protocol rows; and inconsistent single-step routing and activation
  counters.
- Recorded the root cause instead of running a fifth textual round: the spec is
  over-specified for its purpose. The mechanism report grew from 771 to 1,931
  lines and gained a 1,187-line state machine for what is a bounded diagnostic
  observer, and each correction surfaces a new edge because edge policy is being
  authored with no implementation feedback.
- Recommendation recorded: rescope EC-03 to a minimal verifiable core - SEIZE,
  the four hardware observation points, bounded capture, restoration and a
  host-owned timeout - then let EC-04 fixtures settle the remaining edge policy
  empirically. EC-03 stays gated pending the owner's decision.
- No VM was booted, no target executed, no fixture run and no EGL behaviour
  measured. Ledger validates; EC-02 artifacts re-hashed in the ledger.


## 2026-10-29 — guest hardware breakpoints proven under TCG

- Stopped specifying and measured instead. Wrote a VM-only capability probe,
  tools/uk_fw/guest/dr_breakpoint_probe.c, that forks a tracee, stops it before
  user code, arms DR0 to an execute address and sets DR7.L0, continues, and checks
  the resulting trap, RIP and DR6 before restoring and requiring a clean exit.
- Built static x86-64 with the project Zig toolchain under -Wall -Wextra -Werror,
  and ran it through tools/uk_fw/vm_boot.py in a synthetic busybox workspace using
  the measured EU 260128 kernel with the documented --sdhci-compat adaptation.
  The first attempt without that adaptation stalled waiting for /dev/mmcblk0.
- Result: SUPPORTED. DR7 baseline 0x0 became 0x401; the trap arrived as SIGTRAP
  with RIP equal to the armed address 0x1002eb0 and DR6=0x1 reporting B0; after
  restoring DR7 and clearing DR0 the tracee exited 0 with no further trap; and
  PTRACE_SINGLESTEP advanced RIP from 0x10040be to 0x10040c1. Command elapsed
  3.64 s with exit code 0 and no timeout.
- This resolves EC-02 finding C-07, the single load-bearing unknown for the
  hardware-breakpoint mechanism. EC-02 was never blocked on capability; the
  remaining blockers are specification defects. The EC-04 fixture that the
  question had been deferred to is cheap and needs no vendor userspace.
- Bounds recorded rather than glossed: the probe ran against a synthetic tracee at
  user addresses, not against vendor libEGL observation points. Per-thread four
  slot capacity and slot-replacement semantics were not independently exercised,
  DR6 semantics beyond B0 and detach-time teardown of ptrace_bps remain unverified.
  No vendor binary executed, no navigation state claimed, no hardware touched.
- One authoring self-correction is recorded: the first draft of the probe omitted
  stdarg.h and left its tracee parked after the trap, so it was rewritten as a
  single arm/trap/restore/clean-exit sequence before any VM run.


## 2026-10-29 — detach discipline measured; four-slot behaviour verified

- Extended the hardware-breakpoint capability probe to the behaviours round 1 had
  explicitly left unexercised, since the EC-02 observer depends on each: four-slot
  capacity, slot replacement, invalid debug-register rejection, detach behaviour,
  and the safe detach sequence. Nine checks now pass in 3.85 s with exit 0.
- Four slots armed together (DR7 0x455) fired in program order at the correct
  RIPs, but only because the fired slot was disarmed before each resume. An
  execute breakpoint retriggers while enabled, so disarm-before-resume is a
  measured requirement, not a preference.
- Slot replacement was demonstrated: slot 0 fired at one function, then at a
  different address after reprogramming.
- DR4 and DR5 were rejected with errno 5 EIO, so the valid ptrace index set is
  0-3,6,7. This invalidates EC-02 fixture V-03's assumption that a fifth slot
  could be exercised through DR4.
- Detach behaviour was the significant result. With a slot still armed,
  PTRACE_DETACH left the breakpoint live and the untraced process was killed by
  SIGTRAP. EC-02's C-09 concern about kernel teardown of ptrace_bps is therefore
  confirmed rather than merely defensive.
- The safe exit was then proven: clear the DR7 enables, clear the address
  register, verify the readback reads zero, then detach. The tracee completed with
  exit 0. Both the failure mode and the remedy are now measured.
- Bounds recorded: synthetic tracee at user addresses with no vendor observation
  point; per-TID scoping and DR6 semantics beyond B0 remain unexercised; no vendor
  binary executed and no hardware touched.


## 2026-10-29 — community chat transcribed and leads triaged

- Transcribed eight owner-supplied Discord screenshots into a single de-duplicated
  transcript at evidence/community-chat-transcript-261029.md. The images were
  overlapping scrolls of one channel rather than eight conversations, so they were
  merged by timestamp with attribution preserved and relative labels left as shown.
- Recorded the transcript as unverified participant reports. It is useful for
  provenance, not as evidence that any method works, and several of its claims are
  contradicted by our own measurements.
- The transcript is the origin of the three exploit bullets captured as V-006, V-007
  and V-008. Cross-referenced each: V-006 confirmed but through system() in
  usb-automount on the PTP branch rather than a mount script, with the literal
  payload in the chat failing because spaces become underscores; V-007 confirmed only
  as configuration; V-008 confirmed as shipped password-gated configuration with no
  bypass.
- Ran cheap offline checks on the remaining leads. AppEngineerMode exists at
  /app/bin/AppEngineerMode with QML under /app/share/AppEngineerMode/qml, but the
  reported PIN 19480717 and the tap sequence 3 2 8 9 6 5 are absent as text from that
  binary and from QML/JS/conf under app and usr/share, so the entry handler is most
  plausibly the Settings application behind System info -> Manual.
- /tool/velix_aes.key and /tool/public.crt do not exist in the rootfs; those paths sit
  inside the AppUpgrade payload and belong to its decrypted tree. The claim that the
  IV is derived from the SHA-256 of the encrypted file name and size remains
  untested and is the most directly checkable item, to be compared against
  tools/uk_fw/gen5w_decrypt.py.
- Publication caution recorded: the transcript contains an engineering-mode PIN, a
  claimed VM image digest and a partial key-like hex string, so PUBLIC-RELEASE.md
  applies before mirroring. No disclosure decision was taken.


## 2026-10-29 — DR6 attribution verified; transcript IV claim corroborated

- Completed the hardware-breakpoint capability matrix with a DR6 test. With slots
  0 and 1 armed at different addresses, the first trap reported DR6=0x1 identifying
  B0, a POKEUSER write of 0 to DR6 read back as 0x0, and the second trap reported
  DR6=0x2 identifying B1. Ten checks pass in 3.83 s with exit 0.
- This settles a point the EC-02 specification had disputed: the observer can
  attribute a trap to a specific slot from DR6 and can clear stale status between
  stages, instead of inferring the slot from RIP alone.
- Per-TID scoping remains the only unexercised capability item: one traced thread
  while a sibling executes the same code.
- Checked the community transcript's most concrete claim against our own tooling.
  The chat states the update IV is derived from the SHA-256 of the encrypted file
  name and size. tools/uk_fw/gen5w_decrypt.py, derived independently from the
  envelope evidence, computes the IV as the first 16 bytes of
  SHA256((basename + signed_int32(body_size))) with body size file_size - 0x4024,
  and produces working decryptions. The claim is consequently recorded as
  corroborated, with the precise semantics, rather than as an open lead.
- No disclosure decision was taken and no VM image was modified.


## 2026-10-29 — capability matrix complete: per-thread scoping verified

- Closed the last unexercised item in the hardware-breakpoint capability matrix.
  Debug registers were shown to be per thread: the traced main thread trapped at an
  armed execute address, was single-stepped past with the slot temporarily
  disabled, the slot was then deliberately re-armed, and an untraced sibling thread
  executed the same function with no effect. The process exited 0. Eleven checks
  pass in 3.94 s with exit 0.
- The test was sequenced rather than raced, with the sibling spinning on a flag set
  only after the traced thread had been stepped past, so the two possible outcomes
  are distinguishable: an unaffected sibling yields a clean exit, whereas a
  process-wide slot would kill the untraced sibling on SIGTRAP, the same signature
  T8 established for untraced breakpoint hits.
- Consequence for EC-02: observing a single main thread is sound and needs neither
  thread-group control nor PTRACE_O_TRACECLONE. That removes an open design
  question rather than adding one.
- One authoring correction: the edit that introduced the threading headers replaced
  stdarg.h rather than extending the include list, which -Werror caught at build
  time before any VM run.
- Bounds stated explicitly: only execute breakpoints were exercised, data
  read/write watchpoints were not, and behaviour with many threads or
  PTRACE_O_TRACECLONE was not examined.
- No disclosure decision taken; no VM image modified; no vendor binary executed by
  the probe.

## 2026-10-29 — null-buffer BG question narrowed, with a reversed inference

- Returned to the main navigation workstream, which is independent of the EC-02
  gate, to settle whether a Qt hide can ever produce the BG notification that
  ApplicationManager requires.
- Established by disassembly that the FG/BG predicate lives in ivi-window-manager.so
  at 0xf981 and tests the surface size fields 0x68 and 0x6c, reproducing the known
  rule that any positive dimension selects FG. ivi_layout_surface_configure in
  ivi-shell.so at 0x81a0 only fans out to listeners and performs no classification.
  The two size fields are written only by surface_set_size in usr/bin/weston at
  0x40d4a0, whose three call sites all lie inside weston_surface_commit_state.
- The first inference, that a null buffer leaves the size positive and therefore
  cannot produce BG, was contradicted by two additional checks and is recorded as
  reversed. surface_attach at 0x40df20 treats a NULL resource by setting buffer to
  NULL and still setting the pending buffer-attached flag at pending+0x00, and
  commit_state at 0x40f32c enters the size block whenever that flag is set. A
  null-buffer commit therefore does reach surface_set_size.
- Whether that call writes 0x0 depends on fields 0x104 and 0x108 of the surface
  struct, whose meaning after a null attach is not yet established. A hidden surface
  yielding 0x0 and hence BG is consequently plausible rather than excluded, which
  raises the value of pursuing AppNavi's authentic hide path instead of assuming a
  resize adapter is required.
- A delegated worker was interrupted mid-analysis by the pi-gui restart after
  writing six disassembly excerpts and no report. The excerpts were retained and the
  analysis was completed by the coordinator from them plus direct llvm-objdump
  checks. No rootfs file was modified and no VM was booted.

## 2026-10-29 — skills updated, public disclosure reduced, EC-03 minimal core built

- Installed the Sol 6.1 skill bundle supplied by the owner. It moves default
  reviewers to gpt-6.1-sol and replaces Astra throughout examples and fixtures. The
  bundle did not include the operator's requirement that DeepSeek workers use the
  direct API provider and still referenced the superseded router route
  deepseek/deepseek-v4.1-flash, so that policy was re-applied across SKILL.md,
  references/protocol.md, README.md, docs/INSTALLATION.md, agents/openai.yaml and
  The Council, using the verified direct route deepseek/deepseek-flash.
- Both skills re-validated after the edit: 148 and 93 unit tests pass, and the
  packaging validator reports each skill valid. The earlier validator failure was
  traced to a Python interpreter without PyYAML rather than to the skills.
- The owner authorised the two pending decisions. For disclosure, the public mirror
  now carries status-only entries for V-006, V-007 and V-008 with no component
  names, property names, code locations or payload detail; the public tree was
  checked to contain no occurrence of the affected service or property names. The
  full dossiers remain private. Pre-existing publication of the engineering-mode
  entry sequence and PIN in that tree was noted rather than silently removed,
  because deleting it would not undo the exposure.
- For the rescope, EC-02 was stopped rather than reviewed a fifth time, and the
  EC-03 minimal core was implemented instead: tools/uk_fw/guest/ec03_observer.c
  performs SEIZE on a single thread, arms up to four execute breakpoints addressed
  as module substring plus offset, captures registers at each hit, disarms a slot
  after it fires, tears down with the mandated disarm/verify/detach sequence, and
  enforces both a deadline and a stop bound.
- The observer was validated end to end in the VM against a synthetic target. Without
  --once the tracee outlives the observer and teardown is reported unverifiable
  because the tracee is gone; with --once the observer detaches while the tracee is
  stopped and reports teardown verified with detach ok. Both runs exit 0.
- Three defects were found and fixed during that validation: a missing stddef.h
  include for offsetof; module-base resolution that had wrongly required an
  offset-zero mapping, which static non-PIE text does not have; and teardown being
  attempted against an already-exited tracee. The guest image also lacks busybox
  applet symlinks, so the driver now invokes applets through /bin/busybox.
- EC-02 is recorded as blocked and superseded rather than accepted, and the ledger
  validator's refusal to accept an important task without independent verification
  was respected rather than worked around.

## 2026-10-29 — second skill bundle pulled; policy patcher added

- Pulled and installed the second Sol 6.1 skill bundle supplied by the owner. The
  substantive difference from the first is Council behaviour: three Sol 6.1
  reviewers at xhigh reasoning by default, Astra-medium supported as an explicit
  seat, and sol aliasing Sol 6.1.
- The bundle shipped once more without the operator's direct-DeepSeek-provider
  requirement and still referenced the superseded deepseek/deepseek-v4.1-flash
  route. Because this had now happened twice, the correction was automated as an
  idempotent patcher rather than repeated by hand: it enforces the policy across
  SKILL.md, both protocol references, README, the installation guide and the
  invocation metadata, tries several candidate anchors because the Council protocol
  wording changes between bundles, and exits non-zero if it cannot find an anchor
  rather than silently skipping.
- Re-validated afterwards: 148 and 93 unit tests pass and both skills report as
  valid.
- Nine occurrences of the stale route id were left in place because they are test
  fixtures and a ledger example rather than policy text, and changing them could
  break assertions bound to the literal.

## 2026-10-29 — observer gains field capture

- Implemented the increment the ledger recorded next for EC-03: int32 field capture
  at an observation hit. Two fields are read from a struct pointer supplied either as
  an absolute address or as a register name, defaulting to the EC-01 contract offsets
  0x2c for width and 0x30 for height, with overrides. This is the shape required to
  capture the vendor dri2_surf dimensions before and after the buffer update.
- Validated in the VM across three cases, all exiting 0 in 12.87 s: without --once the
  tracee outlives the observer so teardown is reported unverifiable because the
  tracee is gone; with --once teardown is verified with detach ok; and an unknown
  register name is reported as status unknown-register instead of being guessed.
- The measurement itself confirmed the instrument reads the intended fields: FIELDS
  status ok with a=1926 and b=753 at offsets 0x2c and 0x30.
- Bounded honestly: the register-held pointer mode was validated only on its error
  path, because a synthetic target cannot reliably place a chosen value in a
  callee-saved register at a breakpoint. Its real exercise is the authentic AppCamera
  stage, where r15 holds the surface pointer.
- One defect was found and fixed: an unused field_regs global that -Werror rejected,
  removed rather than suppressed.

## 2026-10-29 — authentic measurement of the EGL dimension ordering

- Ran the EC-03 observer against the authentic AppCamera inside the real launcher
  chain and captured both EC-01 stages on the same surface pointer. At
  libEGL+0x16f16, before the width cache, the surface fields at +0x2c and +0x30 read
  -1 and -1. At libEGL+0x16f1e, immediately after swrast_update_buffers returns, the
  same struct read 1920 and 720. Teardown reported verified with detach ok.
- This measures the ordering defect behind I-001 rather than inferring it. The copy
  path derived its stride from Width=-1, giving -4 bytes, while the update populated
  the real geometry during the same invocation. It supersedes the earlier position,
  including my own correction two turns ago, that a width change had not been
  observed on this path.
- I-001 in the defensive register was rewritten to match: mechanism measured, still
  not a demonstrated exploitable vulnerability, with stock-driver reachability,
  attacker influence over the values, and any link to navigation failure explicitly
  left unestablished.
- Method notes retained because they cost real time: the canonical vendor image must
  not be modified and a plain copy costs 23 GB, so the run used an APFS copy-on-write
  clone, made in 0.031 s, with two files injected through debugfs. An earlier attempt
  to stream the binary over the serial console failed because the whole command
  became a single 80 KB line that the line discipline truncated.
- Two genuine defects were found and fixed. The driver inherited an argument-guard
  block that still invoked the previous crash observer, and the observer resolved
  libEGL before the client had mapped it. The second is a real race, since AppCamera
  becomes visible before its graphics libraries load, and is now handled by a bounded
  wait for the module with the tracee left running.

## 2026-10-29 — null-buffer question resolved; hide does not produce BG

- Settled the remaining navigation question using DWARF instead of inference. The
  weston binary retains debug information for weston_surface (weston 1.10.0-r21,
  compositor.h:1066), which fixes the layout as width at 0x68, height at 0x6c,
  width_from_buffer at 0x104 and height_from_buffer at 0x108. This confirms that the
  FG/BG predicate tests the surface's own size fields and that the commit path feeds
  them from the _from_buffer pair.
- A null-buffer attach does zero both _from_buffer fields at 0x40f813, reached when
  the buffer pointer is null. An earlier correction stopped at that point and
  concluded that BG was reachable, which was incorrect: the size block at 0x40f470
  executes before that zeroing, so it stores the previous positive size and the
  surface remains positive.
- The conclusion is therefore that a bare hide does not produce BG, and a genuine
  transition to non-positive dimensions is required, which matches the earlier
  Camera/Standby control that drove 1926x753 to 0x0 and then BG. The integration
  route consequently needs a scoped resize adapter rather than the authentic hide
  path.
- The reversal is recorded rather than tidied away: the withdrawn reasoning remains in
  the analysis report with an explicit note that it is superseded.
- Method notes: the DWARF inspection required llvm-dwarfdump with a byte-window scan,
  and several earlier greps silently matched nothing because objdump separates its
  columns with tabs rather than spaces.

## 2026-10-29 — I-001 scoped to the swrast path

- Established that no Intel hardware is required to continue. The same check narrowed
  I-001: vendor libEGL defines four surface constructors, and the -1 sentinel belongs
  to the swrast-specific one, while put_image2, get_image and swap_buffers all belong
  to the dri2_wl_swrast family. The hardware constructors are separate and do not
  share that vtable.
- The honest consequence was recorded: the evidence does not implicate the i965/i915
  path, so I-001 is a defect of the vendor's Wayland software-rendering path, which is
  the path this VM necessarily uses. That reduces rather than increases its real-world
  severity, and the register was updated to say so rather than leaving an implied
  hardware claim.
- The vendor image ships its own DRI drivers for i965, i915 and iu3d9, so the earlier
  mixed-stack caveat concerns which module loads in emulation, not an absence of
  vendor graphics code.
- No Intel machine is needed for the remaining authorised work: the navigation 0x0
  adapter, service reconstruction, audio, CAN/MICOM and persistence all execute in the
  VM.

## 2026-10-29 — navigation 0x0 adapter built; timing still wrong

- Began the integration piece the BG analysis called for: a scoped adapter that drives
  AppNavi's parent surface to a genuine 0x0 configure so the compositor classifies it
  BG. The mechanism follows from the earlier ordering finding: one null attach is
  insufficient because the size block stores the previous width_from_buffer before the
  null branch zeroes it, so two consecutive null attaches are required.
- Implemented as an LD_PRELOAD interposer on wl_surface_attach that forces a NULL
  buffer on two consecutive attaches. It drives only the vendor compositor and never
  calls the manager, writes the window byte, or synthesises a notification.
- Two runs completed with exit 0 in about 412 seconds each, and both still reported
  manager 11/11. Two defects were found and fixed: the preload is inherited by every
  launcher child, so the first attempt collapsed the wrong application, now gated to
  AppNavi through /proc/self/cmdline; and the trigger fired before the client had
  painted, so AppNavi never foregrounded, now gated behind a minimum attach count.
- Status recorded honestly: the plumbing is proven end to end, since the interposer
  loads under the vendor glibc 2.25, is correctly scoped, the chain still completes and
  manager state is queryable at the chosen moment. BG was not reached and the
  Home-to-Navigation transition is unchanged. The paint-first variant is built but not
  yet exercised.
- Built against x86_64-linux-gnu.2.25 rather than musl, since a musl-linked shared
  object will not load into the vendor glibc process.

## 2026-10-29 — engineering mode research published; navi 0x0 still not reaching BG

- Recorded the engineering-mode entry and PIN research in
  evidence/engineering-mode-research.md and published the same document to the public
  repository after the owner authorised releasing the PINs and entry methods.
- The entry gesture is Settings, General settings, System info, Manual, then taps on the
  left panel carrying the QR code and text in the order 3-2-8-9-6-5, which opens an
  eight-digit keypad. The engineering-mode PIN recorded is 19480717, reported accepted
  on a UK-origin 2021 IONIQ 5 whose installed build was later identified as 250604, so
  acceptance there does not establish the 260128 package.
- Dealer mode and full engineering mode are distinct with different codes, and two
  public references disagree about rotating codes. The SOP-gate claim, previously
  single-source, is now corroborated at code level: the binary really does contain
  bool AppEngineerModeEngine::checkSOPVersion().
- The PIN check was located: AppEngineerMode_PinCodeKeypad.qml calls
  AppEngineerModeEngine.checkPassWord at line 391 and branches on the return value, where
  21 and 11 are menu selectors rather than entered PINs. Lockout machinery is present,
  so failures are rate-limited by design. The binary is stripped but retains 111 C++
  signature strings, which is how those methods were identified.
- A full scan of 408,412 files across all five extracted components, including 444
  expanded archives, found the PIN in none of five encodings. The most probable
  explanation is that the reported PIN belongs to the owner's 250604 build rather than
  the 260128 package being analysed.
- The entry gesture is not implemented in QML, since Screen_Manual.qml has no MouseArea
  or onClicked handler, and no binary contains the literal AppEngineerMode, so the
  gesture is handled natively and the application is launched through the launcher
  registry.
- AppNavi update feasibility remains undetermined. The older capability is recorded as
  Engineering Mode, Config, Update AppNavi from USB, and four decision gates were
  written down, with the launcher executable inspection identified as the cheapest
  decisive test.
- The paint-first navi 0x0 run was also recorded: it completed with exit 0 but the
  manager still reported 11/11, so BG was not reached and the Home-to-Navigation
  transition is unchanged. Triggering on an attach count rather than on an observed
  event is the likely remaining flaw.

## 2026-10-29 — navi 0x0 adapter never fired; diagnosis narrowed

- Replaced the attach-count trigger with a sustained hold: while the trigger file
  exists, every attach on AppNavi's target surface is replaced by a null-buffer attach,
  holding the surface at 0x0 rather than flipping it for one frame. The hold lasted six
  seconds, then was released and observed again.
- The manager reported 11/11 during the hold and 11/11 after release, so BG was again
  not reached.
- Because "no manager change" and "adapter never ran" were indistinguishable, the
  interposer was given an audit write on first hold. The run produced no audit file at
  all, which shows the interposer never executed a hold. The manager readings from both
  attempts therefore say nothing about whether BG is reachable by this route.
- Two candidate causes remain indistinguishable. Either the preload never reaches
  AppNavi, which could happen if AppLauncher execs child applications with a sanitised
  environment, or SMACK denies access to the trigger file and the audit path for
  AppNavi's label, failing silently in exactly the observed way.
- The next step was recorded: take the filesystem out of the probe, logging to stderr
  which the launcher captures, and deriving the trigger from a monotonic clock or a
  launch-time environment variable so neither SMACK policy nor exec environment handling
  can block it without leaving a trace.
- Build and injection remain clean, the chain completes with exit 0 in about 418
  seconds, and screenshots were captured both during the hold and after release.

## 2026-10-29 — navi 0x0 injection unblocked

- Found the root cause behind every earlier "adapter never ran" result. The launcher
  liveness interposer deliberately calls unsetenv on LD_PRELOAD when it runs as
  AppLauncher, so vendor children inherit a clean environment. Any LD_PRELOAD placed on
  the launcher command line therefore never reaches AppNavi, which explains four
  consecutive attempts that produced no effect and no trace.
- The fix uses that same interposer's execve hook, which rewrites envp for AppNavi only.
  A variant now injects the navi-bg library ahead of the existing EGL compatibility
  entry for AppNavi alone, and the source was added to tools/uk_fw/guest.
- Injection is verified: the kernel log records navi-bg loading inside AppNavi at
  pid 857 with the configured hold window. The adapter demonstrably executes.
- The probe was also made filesystem-free, with the hold window derived from a
  monotonic clock and launch-time environment variables and the timeline written to
  /dev/kmsg, so neither SMACK policy nor exec environment handling can block it
  silently.
- Remaining gap: no first-attach record followed, so AppNavi did not attach a buffer on
  the elected surface within the window, and the manager still reported 11/11. The next
  step is to log every attach plus a destructor summary so a zero-attach run cannot be
  confused with a timing miss, then to align the window with real rendering.
- A method correction is recorded: an earlier conclusion that the library never loaded
  was wrong, because it depended on AppNavi's stderr appearing in launcher.log, where it
  does not. The kernel log is the reliable channel and overturned that diagnosis.

## 2026-10-29 — BG experiment repositioned; AppNavi does not render in the full chain

- Moved the navi-bg experiment to after the chain's own navigation transition request,
  because its previous placement ran before AppNavi had been asked to come forward. The
  hold also changed from a wall-clock window, which is measured from process start and
  was long past at that point, to an attach-count window anchored there.
- The wait then ran its full 180 seconds without observing a first surface attach. No
  interposer timeline was produced and the navi-live screenshots hashed identically to
  the earlier Home frames.
- The conclusion recorded is that AppNavi never becomes a rendering Wayland client in
  this full-chain configuration, so no surface exists for the adapter to hold. That is
  the Home-to-Navigation blocker itself rather than a defect in the adapter.
- A strategic correction was written down: the full chain is the wrong vehicle for this
  experiment. The standalone AppNavi render probe already present in the image is
  documented to produce genuine map pixels and should host the adapter, reusing the
  execve-hook injection that is now proven to work.
- A measurement caveat was also recorded: dmesg is unreliable as a late-run probe
  because the kernel ring buffer can wrap during a run of several hundred seconds, so an
  absent line near the end is weak evidence. Process state or a log file should be
  preferred for near-real-time checks.

## 2026-10-29 — adapter moved to the render probe; AppNavi still never attaches

- Built a variant of the standalone AppNavi render probe, which runs a session bus,
  weston-headless with the IVI shell and a real ApplicationManager before execing AppNavi
  directly, so the adapter no longer depends on the launcher hook.
- The first attempt launched AppNavi through the busybox timeout applet and lost the
  preload across that extra exec hop. Launching AppNavi directly corrected it, and
  AppNavi's own log now records the adapter loading with the configured hold parameters.
- No surface attach followed. That single line is the whole AppNavi log, and the manager
  reported drawing application 0 both before and after, which is not the behaviour of a
  rendering Qt client.
- An important open question was recorded: whether the interposer itself now prevents
  AppNavi from rendering. The cheapest discriminator is a baseline run of the same probe
  without the preload, comparing AppNavi's log and behaviour, and that is the next step.
- A method note was added: in this probe stderr reaches appnavi.log reliably while
  /dev/kmsg produced nothing, so an absent dmesg entry here reflects the channel rather
  than proving absence.

## 2026-10-29 — navigation status published to both repositories

- Published docs/navigation-status.md in the public repository along with the research
  helpers behind it, and kept the same document here as evidence/navigation-status.md so
  the private record matches what was released.
- The document states the three measured results of this session and, plainly, the one
  remaining blocker: AppNavi never attaches a surface, so nothing reaches the compositor
  to be classified, and the open question is whether the interposer itself prevents
  rendering.
- The new files were checked before publication for personal paths, VIN-shaped tokens and
  credentials, and the public harness passed on the clone before the push. No
  vulnerability register, raw evidence, ledger or firmware was published.
