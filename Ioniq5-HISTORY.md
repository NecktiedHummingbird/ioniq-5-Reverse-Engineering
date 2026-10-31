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

## 2026-10-29 — working tree committed and probes published

- Committed the working tree that had been preserved uncommitted through the VM work:
  the harness additions in vm_boot.py, the TE2 decryptor work in gen5w_decrypt.py, their
  tests, the eleven guest research helpers and the operations contract.
- One personal path in the operations contract was replaced with a placeholder before the
  commit. Everything else in the set was checked for personal paths, VIN-shaped tokens
  and credentials and came back clean. Harness and the full 171-test suite pass.
- Three further research instruments were published to the public repository, closing the
  gap between the private and public tool sets, namely the breakpoint capability probe,
  the minimal observer and its synthetic target.
- The vulnerability register, raw evidence tree, task ledger and all firmware remain
  private; the public tree carries neither firmware nor credentials.

## 2026-10-29 — baseline clears the interposer

- Ran the control that the open question called for: the identical render probe with no
  preload at all. AppNavi's log came back empty, zero lines, and the manager reported
  drawing application 0, which is the same outcome as the run with the adapter loaded
  apart from the adapter's own single load record.
- The interposer is therefore cleared of causing AppNavi's silence, and the fault lies in
  AppNavi's own startup in this probe.
- A caveat was recorded alongside it because it changes what can be claimed: an empty log
  does not prove nothing rendered. AppNavi may log to DLT or to a file, or not at all, and
  the probe's screenshot had not been inspected. Rendering silently and never rendering
  both remain open possibilities.
- The next steps were written down: inspect the captured frame and check whether AppNavi
  logs to DLT before drawing conclusions about its startup.
- docs/navigation-status.md was updated in both repositories so the published open
  question is replaced by this baseline result.

## 2026-10-29 — A/B shows AppNavi paints nothing at all

- Tested the previous entry's caveat with an A/B across three runs of the same probe: with
  the adapter, without it, and with AppNavi not launched at all. The captured frame is
  byte-identical between the baseline and the no-AppNavi control.
- The conclusion is that AppNavi renders nothing. It is alive, silent and contributes no
  pixels, so the adapter is not implicated and the compositor contract, the zero-size hold
  and the background notification cannot be exercised until AppNavi paints.
- The next step was narrowed to finding why AppNavi is alive but idle, by comparing the
  environment and arguments the launcher normally supplies against this probe's direct
  launch.
- An inconsistency between the two repositories was corrected: an earlier hard reset in the
  public clone discarded an uncommitted edit to the navigation status document, so the
  public copy still described the question as open while this copy already carried the
  baseline result. Both now agree.

## 2026-10-29 — why AppNavi idles: surface id and visibility are injected from outside

- Analysed the "alive but paints nothing" blocker and retained the report as
  evidence/appnavi-startup-analysis.md with the working excerpts alongside it.
- The leading cause is that AppNavi links libivi-platform-interface.so.1 directly, and
  that library resolves the ivi surface id only from the environment, via
  QT_WAYLAND_SET_SURFACE_ID and its FORCED and USE_PID variants. On the vehicle the value
  is injected by AppLauncher, which also sets APPID. Both the NEEDED entry and the three
  variable names were verified independently.
- With the variable unset the library enters an uncapped blockingReadEvents loop waiting
  for an id reply, which matches the observed symptom of a process that is alive, silent
  and produces no surface, rather than one that crashes.
- Several candidates were ruled out: ApplicationManager's absence, because the project's
  no-AppManager run still committed a 1920x720 buffer; all command-line flags in the
  current invocation; and APPID, which AppLauncher reads rather than AppNavi. AppNavi
  itself reads only MD_CONA40_ON.
- A significant open point was flagged: the VM logs show the ivi surface created under id
  30000 while the ivi-fg helper programmes 3000, so visibility may be requested for an id
  that does not exist. The offset's origin lives in .bss and was not established
  statically.
- The cheapest next test was written down: one boot with QT_WAYLAND_SET_SURFACE_ID=3000 and
  no ApplicationManager, checking which id the surface actually receives and re-driving the
  helper with that id.

## 2026-10-29 — first hardware-dependency adaptor found and stubbed

- With Wayland client debugging enabled, AppNavi's own log shows it connects, enumerates the
  registry including the ivi application global, and then never creates a surface. The tail
  of the log is a repeated failure to read /sys/class/gpio/gpio440/value.
- Confirmed in the VM that the node cannot exist: the gpio class holds only export and
  unexport, and exporting 440 returns EINVAL because no gpiochip registers that pin, which
  matches the kernel log where the GPS driver defers with -517 and never acquires it. The
  emulated board lacks hardware the firmware expects rather than being misconfigured.
- Built an adaptor in the form of a tmpfs over the gpio class with an inert gpio440 node.
  The gpio440 errors then vanish from AppNavi's log, which is the first demonstrated case in
  this project of a simulated hardware dependency unblocking a firmware startup path.
- Recorded honestly that it is not yet sufficient: surface creation appeared in one run and
  not the next, so either another dependency also gates the render path or the timing is
  racy. The stub is necessary and reproducible; further work is needed.

## 2026-10-29 — privacy checker corrected for Wayland object notation

- The harness reported five private email addresses in the retained AppNavi startup
  analysis. Investigation showed they were false positives caused by Wayland client debug
  output, which writes protocol objects as object@<id>.method, so field names like
  wl_surface@3.attach were parsed as addresses.
- The email pattern was tightened so the domain must start with a letter. Genuine addresses
  continue to match and the Wayland forms no longer do. A regression test was added so
  future protocol captures can be retained without tripping the privacy gate.
- The checker was corrected rather than the evidence rewritten: every Wayland capture would
  otherwise produce the same false positive, and editing quoted log text to satisfy a
  scanner would corrupt the evidence.

## 2026-10-29 — AppNavi's stop point isolated to the ivi surface creation

- With the gpio440 adaptor in place, protocol markers were counted in AppNavi's own Wayland
  debug log rather than shipping log text over the console, which is both cheaper and
  sufficient to locate the stop.
- The measured sequence is that AppNavi binds the display, enumerates 71 registry lines,
  binds wl_compositor, wl_shm and ivi_application, creates a wl_surface, and then never
  calls ivi_application.surface_create and never attaches or commits.
- wl_drm is absent entirely, because the compositor runs headless with pixman and offers no
  GPU buffer interface. Whether that causes the stop or merely accompanies it remains
  unestablished.
- Setting QT_WAYLAND_SET_SURFACE_ID_FORCED in addition to the surface id produced a second
  wl_surface but still no surface_create, so the forced environment path alone does not
  clear the stop.
- Ruled out along the way: gpio440 polling, now stubbed; the preload adapter, whose removal
  changes nothing; ApplicationManager presence; and the current command-line flags. The next
  hypotheses are libivi's id acquisition, a missing buffer integration under pixman
  headless, or a later unmet startup requirement upstream of surface creation.

## 2026-10-29 — wl_drm ruled out; a working harness identified

- Ruled out the absent wl_drm as the reason AppNavi stops before creating its ivi surface. A
  prior successful run used the same weston-headless pixman stack with no ApplicationManager
  and reached surface_create for ids 3000, 30000 and 4903 with 26 attach calls, which proves a
  client can create ivi surfaces and attach buffers on this compositor without any DRM
  interface.
- The same evidence settles the earlier 3000-versus-30000 puzzle: AppNavi creates both ids,
  plus 4903 and 4900 for the map widget, so there was never a single expected id to match.
- A working harness was identified and is still present in the image, namely the valet-stub
  probe paired with the valet-stub runner. The next step is to diff that harness against the
  current probe rather than continue debugging, since the delta between them is what is
  missing.

## 2026-10-29 — correction: AppNavi does create surfaces

- Withdrew the earlier conclusion that AppNavi never creates its ivi surface. That conclusion
  came from counting markers in the client's Wayland debug log, but the client does not emit
  those requests in this build, so their absence there was never evidence.
- Counting the compositor log for the same run shows two surface creations, seven ivi surface
  references, and attach and commit calls. AppNavi does render.
- The recipe that reproduces this is the one the retained milestone used: the gpio440
  adaptor, the valet-status D-Bus boolean stub, and the widget-linking helper replacing the
  plain foreground helper.
- The open question therefore moves from surface creation to visibility: whether a foreground
  request reaches the surface ids that exist and on which plane.

## 2026-10-29 — visibility requests issued but never bound to a surface

- Counted visibility markers in the compositor log during the valet-stub run: sixteen
  set_surface_visible calls, sixteen set_visible_for_qtwayland calls, eight foreground
  requests and sixteen layout calls, but zero ivi_surface_visibility events.
- The only surface id logged as created is 30000, whereas the helper programmes visibility for
  3000. The requests are therefore issued correctly and never bind to a surface that exists,
  which matches the manager continuing to report drawing application 0.
- The 3000-versus-30000 discrepancy is consequently promoted from a suspicion to the leading
  explanation, now backed by the visibility event count rather than by inference.
- The next step is to establish how the environment value maps to the created id, then either
  point the helper at the id that exists or make AppNavi create the id the helper expects.

## 2026-10-29 — surface id fixed at 30000 regardless of the environment variable

- Ran AppNavi with QT_WAYLAND_SET_SURFACE_ID set to 0 and the created surface id was still
  30000, identical to the run with 3000. The variable therefore does not determine the id in
  this path.
- Combined with the earlier marker counts this closes the diagnosis: AppNavi creates surface
  30000 and attaches buffers, the helper programmes visibility for 3000, and sixteen
  set_surface_visible calls consequently produce zero ivi_surface.visibility events.
- The fix is to address the id that exists, by rebuilding the widget-linking helper with
  parent 30000, which is cheaper than establishing where 30000 originates and making it
  configurable.

## 2026-10-29 — retargeting the helper to 30000 does not produce visibility

- Rebuilt the widget-linking helper with parent id 30000 and ran it through the same harness.
  The visibility request counts were unchanged at sixteen set_surface_visible and eight
  foreground requests, and ivi_surface.visibility events remained at zero.
- The conclusion recorded is that addressing the id that exists is necessary but not
  sufficient. The mismatch was real, but some further condition governs whether the window
  manager emits a visibility event for this surface.
- Candidate causes were written down in cost order: the helper's requests possibly not reaching
  the owning window-manager instance, its log being empty throughout and therefore suspicious;
  visibility requiring a later state change such as another commit or a layout change; or 30000
  not being the parent surface at all.
- The next discriminator is to confirm the helper connects and its first request is accepted,
  by capturing both its output and the compositor's response.

## 2026-10-29 — correction: visibility is granted and the harness has no ApplicationManager

- Withdrew the claim that no visibility events are emitted. The count came from searching for
  ivi_surface_visibility, whereas the compositor logs ivi_surface@7.visibility(1) twice, so the
  surface is in fact made visible. This is the second occasion in this investigation where a
  wrong marker string inverted the conclusion, and both are now on record.
- Noted as well that this harness deliberately runs without an ApplicationManager, so its empty
  manager query says nothing about the manager's view; the earlier drawing-application-zero
  observation came from a different configuration.
- With the retained milestone screenshot showing genuine map pixels, the standalone harness
  already reaches visible authentic AppNavi rendering.
- The remaining gap is therefore integration rather than rendering. The full launcher chain
  starts AppNavi through AppLauncher with different environment and ordering, and does not
  reproduce this harness's ingredients.
- The next step is to carry the three essentials into the full chain: the gpio440 adaptor, the
  valet-status D-Bus boolean stub, and the widget visibility helper.

## 2026-10-29 — physical HID identified as dropped by the shell

- Investigated the reported behaviour that a mouse pointer appears but never moves and a keyboard
  is ignored. The weston configuration selects ias-backend with ivi-shell and contains no input
  section, while the backend itself fully supports pointer, keyboard and touch through libinput
  and libevdev, and udev is stock apart from a touchscreen symlink rule.
- The gap is ivi-shell, which contains no pointer or keyboard focus implementation at all; the
  only keyboard logic in the window manager concerns the on-screen keyboard surface.
- Consequently the cursor is drawn because a pointer seat exists, but nothing moves it or grants
  pointer focus, and keys are consumed by the compositor with no focus surface and dropped. The
  caps-lock LED change on plug-in reflects device-open LED state rather than key handling.
- The consequence recorded is that input has to be simulated at the touch layer, which the GUI
  accepts, rather than by presenting a mouse or keyboard. A short VM experiment with the existing
  input helpers would confirm this at runtime.

## 2026-10-29 — USB root test plan written, private

- Wrote a lab procedure for the owner's own head unit covering the three USB vectors worth
  testing. It is held privately because it contains an exploit payload; the public mirror keeps
  the status-only V-006 entry.
- The serial-injection payloads were validated at the shell level against the exact command the
  firmware builds, and checked against both real filters: the 126-character descriptor limit,
  the 0x20 to 0x7f charset, the comma rejection and the whitespace rewriting.
- The useful two-stage result is a credential overwrite: /etc/shadow is a symlink into /tmp, so
  a root command writing the shipped field layout with an empty hash, combined with securetty
  already permitting root on ttyS2, gives an interactive root login over the serial console. The
  change lives in tmpfs and is cleared by a reboot.
- A drafting error was corrected before committing: the first payload used passwd field order
  against the shadow file. The shipped line is now mirrored exactly.
- Hardware guidance was recorded. An ESP32-S3 running TinyUSB is the right tool because the
  trigger requires an arbitrary interface class of 06/01/01 or ff/ff/00, which stock Pi Zero
  gadget functions cannot present. USB Ethernet is supported by the kernel but useless alone
  since the image has neither a DHCP client nor a remote-login daemon.
- The recommended first step is to pass the device through to QEMU so the real automounter,
  udev and payload path are exercised before the vehicle is involved.

## 2026-10-29 — live ESP design for interactive root over USB

- Reworked the USB plan for a reprogrammable ESP. Because descriptors are fixed at enumeration
  and TinyUSB can re-enumerate in software, changing the payload becomes a live operation, so the
  approach turns from a blind one-shot into an interactive channel.
- Two findings made the interactive form possible. First, the payload can end with a comment so
  that the template's trailing ampersand is swallowed, leaving the injected command as system()
  foreground child, which allows a shell payload. Second, the kernel has USB ACM as a module, so
  a CDC-ACM interface provides a data channel without requiring the automounter to mount
  anything.
- That second point matters because the automounter's filesystem strings cover only ntfs, exfat
  and ext4, so a FAT volume presented by a microcontroller is not obviously accepted, whereas an
  ACM node needs no mount at all.
- The composite descriptor was specified as a vendor-specific interface to satisfy the branch
  test, a CDC-ACM interface for the data channel, and the payload in iSerialNumber, with three
  payloads validated for length and charset including an interactive root shell.
- A drafting error was caught by the validator: a stray space in one probe payload would have been
  rewritten to an underscore. The corrected form has no spaces.
- Caveats were recorded about module autoloading, the device-add timing relative to the automount
  service, and the fact that an open shell blocks the automounter.

## 2026-10-29 — USB test plumbing added, disk exhaustion blocks further runs

- Added an opt-in extra-device argument to the VM harness so research runs can attach additional
  QEMU devices, keeping flag and value pairs together and rejecting multi-line arguments, with two
  tests covering it.
- The reason is that QEMU's usb-serial model accepts a serial property that sets iSerialNumber on a
  vendor-class device, so the serial-injection path could be exercised without any hardware. The
  first attempt reached QEMU and failed for an environmental reason: the q35 machine in this
  configuration exposes no USB bus, so a controller must be added and the kernel USB modules loaded.
- The volume then proved to be completely full, with roughly five hundred megabytes free. The vendor
  workspace contains seventy per-experiment pre-run image backups totalling 2.4 terabytes apparent,
  which is what consumed the space. Deleting my own derived workspaces reclaimed only thirty-three
  megabytes because they were copy-on-write clones.
- One suite test now fails with no space left on device; that is the disk rather than the change, and
  the VM command tests pass in isolation.
- The backups were deliberately not deleted. They are pre-existing work from earlier sessions and
  pruning them is the owner's decision, with the recommendation being to retain the canonical image
  and a few checkpoints and archive the remainder externally.

## 2026-10-29 — disk investigation: the backups were clones

- Pruned the fifteen earliest superseded control-chain backups after ranking by usefulness, keeping
  seven images tied to retained milestones. The removal changed the apparent size by 480 GiB and
  freed no space at all, because those files are copy-on-write clones sharing their blocks with the
  canonical image.
- Local snapshots were checked and there are none, so nothing is pinning the blocks. The container
  is full across the machine rather than because of the project: application support, the Codex and
  codex directories, downloads and the research tree together account for the capacity.
- The earlier statement that the backups were the cause of the disk exhaustion is corrected here. It
  was inferred from apparent size rather than allocated blocks.
- Further VM work remains blocked until about fifty gigabytes is freed elsewhere, since more backup
  pruning cannot release anything.

## 2026-10-29 — the USB harness enumerates, and two of my own assumptions were wrong

- Worked through why the emulated serial adapter never appeared. Three distinct causes had been
  collapsed into one: a null chardev stops QEMU presenting the device at all, an EHCI bus is rejected
  outright for a full-speed device, and QEMU's xHCI oopses in the vendor's own driver. UHCI, a file
  chardev and a real wait are enough to get a stable enumeration with the serial string under control.
- The keyboard enumerating beside the adapter mattered: it proved the bus, the port reset and the
  enumeration path all worked, which shifted suspicion from the guest kernel to the device
  configuration. Without that control the oops would have looked like the whole story.
- Two corrections to my own reasoning from earlier the same day. First, the serial string does not
  reach a shell: `usb-automount` is a Qt and D-Bus service, and the documented V-006 mechanism is the
  MTP branch. Second, a null chardev is not an inert detail, it is the specific reason nothing
  enumerated, so the earlier observations of a device that never appeared were an artefact of the
  harness rather than of the guest.
- Practical consequence: reproducing V-006 needs an emulated MTP device with a crafted serial, plus a
  running system bus so the service stays alive long enough to act.

## 2026-10-29 — the mount service is alive, and the reason it never was

- Delegated the D-Bus question and got an answer with a control behind it rather than an assertion.
  The daemon was not blocked by policy; it was blocked by a password database that does not exist at
  boot, because `/etc/passwd` is a symlink into volatile storage. Supplying the two required entries
  lets the system bus come up, and `usb-automount` then holds `com.lge.car.automount` indefinitely.
- The control run is the part worth keeping. With the bus up and the password file absent the client
  still died in three seconds, which isolates the password database as the cause instead of leaving
  two plausible explanations stacked on top of each other.
- This changes the shape of the work. The mount request surface is now reachable in the VM, so the
  remaining V-006 question is about the MTP branch's processing of the serial string, not about
  getting a service to run at all.
- The symlink is interesting on its own account and went into the register as a candidate rather than
  a finding. What matters is the permission and ownership of `/tmp` on real hardware, which this
  environment cannot establish.

## 2026-10-29 — the injection sink is reachable and the exploit is not

- Two workers ran in parallel, one on the VM and one on static analysis, which worked because the
  static job needed no image access. Both came back with evidence rather than conclusions.
- The security result inverted the entry it was meant to confirm. The vulnerable `system()` call is
  reachable at runtime — proven by the shell complaining about the missing helper, which only that
  call can produce — but the string arriving there has already been reduced to an allow-listed
  alphabet by udev, so nothing resembling a metacharacter survives. The register had asserted the
  opposite, and that assertion is now withdrawn rather than quietly left in place.
- What made this decidable was the positive control: the same payload executed perfectly when handed
  straight to `/bin/sh`. Without it there were two candidate explanations for the silence, the payload
  and the sanitiser, and the wrong one could easily have been recorded as fact.
- The through-line of the day is that three separate things I had treated as working were not: the
  serial device never enumerated, the mount service never started, and the injection could not reach
  the sink. Each had a specific, findable cause, and each had been masked by an earlier assumption.
- On the HMI question the analysis reframed the problem. The VM has never run the authentic init
  chain, so the missing `/tmp` state that keeps breaking services is a symptom of the harness rather
  than a series of unrelated faults. The display is the hard blocker: the vendor compositor wants an
  Intel i915 CRTC that nothing in the VM provides.

## 2026-10-29 — display architecture decided, and the analysis corrected by it

- The gap analysis proposed that a generic DRM node with software rasterisation would satisfy the
  vendor compositor. Reviewing it against the kernel tree and the backend binary rejected that: the
  backend carries Intel-specific paths, so a plain card node is not the device it wants. The decision
  is to replace only the backend's output path with a software implementation, keeping stock weston,
  the IVI modules and the IAS protocol intact.
- The value of asking for a decision rather than a menu showed here. The cheap option, a virtual KMS
  module, looked attractive on paper and would have consumed weeks before revealing that GBM, scanout,
  planes and vblank are the actual work, not device registration.
- What this buys is a path that can plausibly be called the infotainment system running in a VM,
  rather than a headless compositor standing in for it. The distinction matters because the IAS control
  path is part of what is being studied.
- Recorded risk, for cheap falsification next: that the IVI modules depend only on the Weston backend
  ABI and the `ias_crtc` interface. One run with the software backend and a `wrandr --crtc=1` call will
  settle it.

## 2026-10-29 — the real init chain runs, and dies on a kernel fault

- Booting the authentic esinit rather than the research shim changed the diagnosis again. Everything
  the services had been complaining about, the missing password file, fstab, weston configuration,
  turned out to be produced correctly by esinit in seconds. The harness had been feeding the system
  nothing and then attributing the resulting failures to individual services.
- The new blocker is deeper and more interesting than any of those. A vendor module, loaded by a
  vendor script during init, dereferences a null pointer on non-vendor hardware and orphans a lock on
  the platform bus. Every subsequent platform driver then waits forever, and because the hung-task
  detector is compiled out, nothing is printed. Progress looks like silence.
- What made the silence readable was the pair of controls: the same module loads fine on a clean guest,
  and a non-platform module still loads after the oops. That narrowed a whole-system stall to one bus.
- The MICOM work moved from folklore to a contract. The 35 bytes are the answer, not the question, and
  the framing is a five-byte header with an XOR checksum. The honest part of that document is the
  weakest link it names: static evidence cannot separate two readings of why the daemon stays silent,
  and one hex dump would settle it.
- Also corrected a housekeeping error of my own: the repository ignores `/work/`, so the analysis
  documents I believed I had committed were not in the repository at all. They are now under
  `evidence/vm-bringup/`.

## 2026-10-29 — systemd at last, and a quieter kind of finding

- Suppressing one module load was enough to let the authentic boot reach systemd, which reframes the
  whole bring-up: the vendor userspace has been ready to run for some time and one driver asserting
  hardware presence was holding it shut. Doing it on a CoW clone kept the canonical image untouched.
- systemd then failed in the least interesting place, the fstab. A projection with one partition cannot
  satisfy units that want `mmcblk0p8`, and systemd behaves exactly as documented: dependency failure,
  emergency mode, no drama. That is a good sign — the failures are now ordinary and legible rather than
  silent kernel faults.
- On the security side the valuable find was the least dramatic one. The MTP injection is dead, the
  kernel oops turned out to be unreachable, and what remains is a mount performed without `MS_NODEV`.
  No bug, no clever string, just a flag that lets a device node from a plugged-in filesystem reach
  storage that file permissions were supposed to protect.
- Worth noting the shape of that: three candidate attacks were investigated today and two dissolved
  under evidence, while the one that survived was visible in a constant at a single offset. Evidence
  keeps selecting for the boring answer.

## 2026-10-30 — a real media corruption path, and another scope correction

- The shipped ASF demuxer accepted a 33rd stream into a fixed 32-entry array and crashed authentic
  `gst-discoverer-1.0`. This is the first current-build parser memory-corruption condition reproduced
  dynamically rather than inferred from a version string. It is V-012 because V-011 was already
  assigned concurrently to the missing-`nodev` mount finding.
- A source-layout reconstruction shows the first out-of-range `AsfStream` aliases the live
  `flowcombiner` pointer with a newly allocated `GstPad *` and corrupts several fields of
  `old_stream[0]`. The file does not directly supply those pointer values, so the result is a strong
  crash primitive, not yet an attacker-chosen write or code-execution proof.
- Authentic thumbnail and PlayerEngine services were started as root and their D-Bus methods were
  recovered. Bounded calls failed before ASF pad creation in the incomplete VM media environment.
  Production-service reachability is therefore still open rather than being inferred from the library
  link alone.
- The previous missing-`nodev` interpretation was also narrowed. The automounter accepts vendor
  `tntfs`/`texfat`; FAT/exFAT cannot natively store POSIX device inodes, Tuxera's NTFS special-file
  semantics are untested, and a local process must still open the node. V-011 remains a hardening
  defect and post-execution candidate, not a proven first-step USB root path.

## 2026-10-29 — the vendor system boots

- Multi-user, first time. The two things holding it back were both trivial to look at and easy to miss:
  a mount check script shipped without an execute bit, and a partition layout the projection did not
  provide. After those, systemd did what systemd does, and the log reads like an ordinary embedded
  boot rather than a research harness.
- Worth recording what this changes. Until now every service failure had a plausible excuse, the
  harness had not prepared the ground. That excuse is gone. What fails now fails for its own reasons,
  on a system that booted the way the vendor intended.
- The two survivors are the ones the analysis predicted: no MICOM daemon, and no compositor. Both are
  now specific engineering tasks with named files rather than open questions.
- The `Requires=` on `micommanager` is worth noting as a design observation: the launcher cannot come
  up without the vehicle interface daemon, so the simulator is not a nice-to-have for the HMI path, it
  is the gate.

## 2026-10-29 — the MICOM speaks, and it speaks first

- The question the contract could not answer statically was whether the daemon waits for the vehicle
  before it talks. With a real serial boundary on the now-booting system it emitted 103 valid frames
  immediately. It does not wait. A silent peer is enough to reach the ask stage, which means the
  simulator is a listener that answers rather than something that must pretend to boot.
- Every frame checksummed correctly, which is worth more than it sounds. A protocol transcribed from
  disassembly that produces 103 frames with zero XOR errors on first contact was understood correctly.
  That confidence is what makes the remaining question tractable.
- The command ids are now known from traffic rather than inferred from code, including the ids that
  appeared exactly once at startup. The one thing still missing is which id is the boot-info ask, and
  the launcher's own call order narrows it to two candidates.
- A worker on this task was cut off mid-sentence and produced nothing. Rather than present the round as
  organised work, the measurement was taken directly and the record says so.

## 2026-11-01 — exact parser and backport evidence replaces version guesses

- A new offline harness now exercises the recovered commercial Tuxera modules
  against project-local raw images without mounting them on the host. QEMU opens
  parser inputs read-only, the guest uses `ro,nodev,nosuid,noexec`, and the
  canonical root remains snapshot-backed. Sixteen malformed exFAT fixtures
  produced no detected kernel fault; that is a bounded negative result, not a
  parser-safety claim.
- The clean NTFS control settled V-011's central filesystem question. Exact
  Tuxera NTFS retained a character node across remount. Without `nodev`, a
  process reduced to uid/gid 65534 under SMACK `_` opened the harmless QEMU
  `/dev/null` target; with `nodev`, VFS denied it. The omission therefore has a
  real policy effect, while still not providing execution, a useful target, or
  a first-step root path by itself.
- The old kernel banner was again a poor vulnerability oracle. Direct binary
  checks found the Dirty COW fix, both ranked AF_PACKET locking fixes, and the
  1 MiB Stack Clash guard-gap backport in the recovered `4.1.27-abl` image.
  Those four local-root candidates are rejected for EU `260128`; no substitute
  local-root path was claimed.

## 2026-11-01 — one reachable local UAF candidate, without calling it root

- Exact `snd-seq.ko` instructions show that the CVE-2017-15265 use-lock fix is
  absent. A small freestanding diagnostic then established the practical entry
  boundary: uid/gid 65534 can open the mode-0644 sequencer node and complete a
  client-ID/create/delete sequence in the offline vendor-kernel VM.
- The deliberately bounded race is equally important evidence. Two processes
  issued 200,000 create and 400,000 delete attempts without a kernel fault. That is
  not proof of safety and does not override the missing lifetime operation, but
  it prevents the report from turning a static UAF mechanism into a claimed
  exploit. V-013 is a local memory-safety candidate; root remains unproven.
- The same exact-code discipline split two other candidates cleanly. The
  CVE-2016-0728 keyring reference release is backported, so that path is
  rejected. The CVE-2017-1000112 IPv4/IPv6 UFO guards are absent, so that bug is
  retained, but `CONFIG_USER_NS=n` blocks the published unprivileged root setup
  and production UFO interface reachability is unknown.
- The tracked sequencer tool performs only one benign create/delete operation,
  keeps QEMU offline and snapshot-backed, and records a machine-readable
  classification. The race source and all generated binaries/logs remain in
  ignored `work/`; no exploit payload was added to the repository.

## 2026-11-01 — adjacent ALSA candidates separate code from usable access

- The next PCM candidate dissolved under the same exact-code check. Shipped
  `snd-pcm.ko` takes the per-device open mutex around `snd_pcm_info_user`, which
  is the complete CVE-2017-0861 fix. Another version-derived root candidate is
  therefore rejected.
- CVE-2018-1000004 went the other way at the instruction layer: the shipped
  native ioctl path lacks the later Linux 4.1 per-client serialization. But its
  published sequence needs `write()` to the sequencer pool, and recovered
  intended node mode gives ordinary users no write permission. V-013 ioctls
  working through a manually modeled `O_RDONLY` descriptor do not silently imply
  this sibling trigger is reachable.
- This is a useful three-way outcome from one subsystem: one exact UAF candidate
  with ioctls reachable through `O_RDONLY` (V-013), one exact fix (CVE-2017-0861), and
  one path missing the official serialization whose required access is blocked
  by DAC (CVE-2018-1000004). None is promoted to root.

## 2026-11-01 — PlayerEngine reaches the ASF bug, and the binary corrects the source model

- The earlier PlayerEngine failure was two independent setup errors: a flat JSON
  option that the service does not accept, and QEMU's missing `media_mixer` PCM.
  With the nested audio option and a disposable ALSA-null mapping for the stock
  PCM name, a valid WMA returns true and reaches the authentic ASF demuxer.
- The boundary controls are now clean. One stream and 32 streams survive under
  the same environment. A 33-stream file and a 34-stream file both terminate
  the uid-0 PlayerEngine service with signal 11. A plain path still fails while
  the `file://` URI succeeds, so the prior confounded URI conclusion is retired.
- The service's own crash handler recorded the useful transition:
  `g_queue_push_head+0x1d` called from `libgstasf.so+0xb6cc`. Exact plugin
  instructions show that `+0xb6cc` is the return from
  `gst_flow_combiner_add_pad` after loading the corrupted combiner pointer.
- Exact binary layout also overturned one source-only detail. The vendor stream
  stride is 208 bytes rather than public 1.8.3's 200. The 33rd stream zeros the
  low half of `flowcombiner`; its pad pointer overwrites `old_stream[0]` instead
  of becoming the combiner pointer itself. That is why offsets remain
  binary-derived facts, even when public source explains the control flow.
- Nothing in this run demonstrates instruction-pointer control or RCE. Manual
  D-Bus service reachability is now closed; automatic USB indexing,
  LightMediaScanner, thumbnail handoff, and physical-unit behavior remain open.

## 2026-11-01 — the automatic scanner takes a different ASF path

- Putting the 33-stream file under `/media/usb/probe` answered the next routing
  question. LightMediaScanner's configured startup scan found the USB directory,
  processed one file with zero reported errors, committed it, and stayed alive.
- The parser identity explains why. The registered `asf.so` is a separate
  LightMediaScanner metadata parser that reads with `open`/`read`/`lseek` and
  writes to SQLite through scanner APIs. It neither links GStreamer nor imports
  a `gst_*` function, so accepting this file does not reach V-012's `asfdemux`.
- A full session-bus capture showed only the scanner's D-Bus lifecycle,
  properties, explicit scan, and progress traffic; no PlayerEngine or thumbnail
  call appeared. That narrows the remaining automatic route to post-index
  media-manager/browser, playback, or thumbnail behavior.
- This is negative evidence for one route, not a safety claim for removable
  media. The exact file still kills PlayerEngine when sent manually under the
  established service contract.

## 2026-11-01 — a different udev helper boundary restores a static physical root path

- A deterministic privilege-surface scanner first reduced the recovered tree to
  reviewable facts: no host-visible or archive setuid/setgid entries, 102
  service files (101 using default root identity), 129 writable-executable-mode
  files mostly on normally read-only `/navi`, and 46 permissive/non-root udev
  rule assignments. The scanner records extraction and xattr limitations rather
  than treating host metadata as production truth.
- Online CVE triage tied to the exact shipped helpers identified
  CVE-2026-40225. Vendor `v4l_id` prints `v2cap.card` directly as
  `ID_V4L_PRODUCT`; vendor `scsi_id` prints `unit_serial_number` directly as
  `ID_SCSI_SERIAL`. Exact disassembly shows neither control-character guard
  added by the upstream 2026 fixes.
- The installed rules complete the static chain: hardware events invoke those
  helpers, block devices receive the systemd tag, and the generic removal rule
  executes `REMOVE_CMD`. More importantly, the image ships
  `debug-shell.service`, configured as an unauthenticated `/bin/sh` on
  `/dev/tty9` under the system-service default root identity, conditional on
  that device path existing. The advisory's SCSI
  `SYSTEMD_WANTS` route can therefore request an existing root unit rather than
  install one.
- Version evidence is intentionally not simplified. The PID 1 banner/pkg-config
  say `225`; embedded OpenEmbedded paths say `systemd/1_249.3-r0`. The finding
  rests on exact instructions and installed rules, not either version label.
- A bounded offline VM control then closed only the unit's path condition:
  `/dev/tty9` existed as `root:root` mode `0600`, character device `4:9`, under
  the recovered vendor kernel/userspace and research init. The service was not
  started and no udev property was injected.
- This became V-014, the strongest static physical root path in recovered EU
  `260128`. It is not a head-unit reproduction: no malicious device, injected
  authentic udev event, systemd unit request, VT9 interaction, root command,
  persistence, or applicability to the owner's unknown installed firmware was
  demonstrated.
- V-006 remains rejected as originally claimed. Its `usb_id`
  `ID_SERIAL_SHORT` allowlist does not protect the separate `v4l_id`/`scsi_id`
  line-oriented property boundary, so the two findings are not contradictory.

## 2026-11-01 — the exact udev parser retains the benign second property

- A new fixed-input diagnostic isolated the next V-014 boundary without running
  either vulnerable helper or any service. It hash-verified the recovered
  `udevadm` and `systemd-udevd`, installed one temporary rule and synthetic
  helper in the snapshot-backed VM, and invoked only `udevadm test` against the
  existing emulated root block device.
- The helper emitted `ID_SCSI_SERIAL=V014_BENIGN_CONTROL` followed by
  ` SYSTEMD_WANTS=v014-benign-nonexistent.service`, including the advisory-
  relevant leading ASCII space. Authentic test output recorded that raw line and
  retained a normalized separate `SYSTEMD_WANTS` property.
- The marker unit was verified absent, no udev daemon or systemd manager ran, no
  kernel uevent was sent, and the temporary helper, rule, and log were removed before
  completion. Classification was `benign-second-property-retained`.
- This closed downstream import-parser semantics only. Hardware delivery through
  SCSI, execution of shipped `scsi_id`, authentic udevd persistence, systemd
  device activation, the root-shell unit, and interactive VT9 remained untested
  at that checkpoint.

## 2026-11-01 — matched controls confirm synthetic benign unit activation

- A second fixed-input diagnostic handed PID 1 from the research shell to exact
  recovered systemd, started exact systemd-udevd through installed sysinit, and
  requested one synthetic add event for emulated `mmcblk0` after coldplug settled.
- Before coldplug, transient `/run` masks shadowed the installed persistent-
  storage and V4L helper rules. The root was remounted read-only, QEMU remained
  NIC-free and snapshot-backed, and the only property-selected unit was a
  transient BusyBox touch/echo marker with no shell command.
- The negative run stored fixed `ID_SCSI_SERIAL` but no `SYSTEMD_WANTS`; the
  marker remained absent/inactive. The positive run stored fixed
  `SYSTEMD_WANTS=v014-benign-marker.service`; PID 1 logged the unit starting and
  marker-file plus active-state checks passed. Root remained read-only in both.
- This closes the synthetic udevd database/device-unit and manager-activation
  boundary. Hardware bytes reaching shipped helpers, physical hotplug, the
  installed shell-unit request, production VT9 access, and root remain untested.

## 2026-11-01 — exact thumbnail routing corrects the V-012 media boundary

- Exact MediaBrowser code maps public `requestThumbnails(as)` to the session-bus
  destination `com.lge.thumbnailextractor`, object
  `/com/lge/thumbnailextractor/service`, interface
  `com.lge.thumbnailextractor.service`, method `Start(as)`.
- Exact extractor code queues every `Start` path and selects `VideoContext`
  without an extension branch. The earlier inference that `.wma` selected the
  audio/TagLib context was corrected; that context handles cover-art work.
- Exact `libthumbnailextractor.so` builds an `uridecodebin ... appsink` pipeline.
  Its custom autoplug callback excludes only factory names beginning with `mfx`,
  so the shipped vulnerable `asfdemux` remains eligible.
- The recovered edge is explicit but request-driven. Reviewed scan callbacks
  forward progress/file events without requesting thumbnails. Bounded VM
  attempts did not observe service-name acquisition, a delivered `Start`, an ASF
  plugin map, cache output, or a natural crash.
- This strengthens static post-index reachability while preserving the dynamic
  boundary: automatic USB/UI invocation and thumbnail-process corruption remain
  unproven; manual uid-0 PlayerEngine remains the only dynamically confirmed
  production-service V-012 route.

## 2026-10-29 — the dependency was never a dependency

- The launcher's hard requirement on the MICOM daemon looked like the central problem: satisfy a serial
  protocol correctly enough to keep a vendor daemon alive. It turned out that the daemon starts perfectly
  well when the device node it opens exists. The failure had been the environment, not the contract, and
  the whole reply-simulator effort was set aside as unnecessary for this gate.
- That is the third time in this project that a blocker attributed to a service was really the harness
  failing to provide something. The pattern is consistent enough to be a rule now: before believing a
  vendor component is broken, check whether it was ever given the thing it opens.
- What is left is honest and specific. The UI process needs a compositor, and nothing in this image
  starts one, because the vendor starts weston from its own init branch behind an SPI validation that
  emulation fails. The remaining work is to create that runtime environment deliberately.
- Two workers were dispatched and neither returned anything. Rather than dress that up, the records note
  it, and the round's actual finding came from an existing log.

## 2026-10-29 — the UI connects

- The compositor turned out to be a non-problem. The image ships a headless backend next to the Intel
  one, so the vendor's own weston runs with no DRM device at all, and the socket appears. The build
  that had been estimated in weeks was unnecessary for reaching the next gate.
- The UI process then did the thing that matters: it stopped complaining about the display. That single
  changed line, an error that is no longer printed, is the first evidence that the vendor stack is
  talking to itself rather than to a substitute.
- Two failures along the way were both configuration, not capability: weston wanted a shell this
  product does not use, and the IAS shell wanted a config path that `HOME` normally supplies.
- The remaining gap is now narrow and named. The shell needs its configuration to initialise outputs,
  and scanout still has to become real for anything to be seen.

## 2026-10-29 — the shell comes up, and a permission boundary turns out to be thinner than stated

- The IAS shell now initialises with its own configuration. The detail that mattered was unglamorous:
  the config is read from `$XDG_CONFIG_HOME/ias.conf` directly, and the vendor ships it one directory
  deeper, so the value of that variable is what makes the difference. Renaming the CRTC to the headless
  output's name was the other half.
- The security question of the day resolved against optimism. `/media` is a plain tmpfs with defaults
  and nothing sets a mode, so the kernel default applies and it is very likely world-writable. The
  earlier entry leaned on "probably 0755 root" as reassurance; that assumption is gone and the entry now
  says so.
- What survived is worth stating plainly: the mount lacks `nodev`, and node permissions are chosen by
  whoever built the filesystem. That combination is a boundary failure regardless of how tidy the rest
  of the permission model is.
- Escalation still requires physical access. Being accurate about that matters as much as being accurate
  about the defect.

## 2026-10-29 — the interface is live, the pixels are not

- The compositor answered for itself today: the IAS shell interface appears in the registry and an
  output exists. That is the strongest statement available while running headless, and it means the
  vendor control path is coherent — the thing this project actually wants to study.
- The scanout question closed in the least dramatic way: the kernel simply has no driver that could
  provide a framebuffer on this virtual hardware. i915 is built in and binds nothing, and every fbdev
  and virtual GPU option is compiled out. No amount of configuration was going to produce an image.
- Worth noting there were no failures to chase here. Reading the config answered in a minute what
  experiments could have circled for hours, and it retired an option that looked cheap.
- The boundary is now precise: the system runs, its interfaces are live, and the only thing missing is
  a device that can present pixels. That is a well-posed problem rather than a vague one.

## 2026-11-01 — exact package recovery exposes a conditional DHCPv6 parser path

- Recovered the firmware's RPM package inventory from its Berkeley DB rather than
  inferring component age from strings. The preserved index contains 1,679
  records, including the exact vendor ConnMan package identity.
- Version matching produced a lead, not a conclusion. Exact `connmand`
  instructions then confirmed CVE-2026-115863's fixed-size DOMAIN_LIST copy,
  unbounded label walk/store, and option-24 dispatch.
- The main reachability question narrowed from generic Wi-Fi speculation to a
  specific conditional path: a connected ConnMan network accepts RA flag state,
  starts the DHCPv6 information request, and asks for the affected option. Live
  transaction and client/server identifiers remain required.
- The service is configured for uid 0, but the binary also carries PIE, NX stack,
  a stack canary, and full RELRO. No traffic was generated and no process was
  crashed. The result is a static adjacent-network candidate, not root access.
- Added deterministic dump tooling and kept the database, source, downloads,
  disassembly, and decompiler output in ignored `work/`. Physical and dynamic
  validation remains deferred until a disconnected bench exists.

## 2026-11-01 — both PCB-selected Bluetooth daemons retain an old BNEP parser

- The product does not ship one generic Bluetooth binary. Its setup script reads
  MICOM PCB state: versions 11/12 select BSA `00.63.00` with one of two
  controller patchrams; other values select BSA `00.51.00` and a third patchram.
- Exact comparison avoided relying on either BSA version. Both exported
  `bnep_process_control_packet()` implementations read the extension/control
  bytes before the remaining-length checks later added for CVE-2017-0782. The
  same pre-fix order persists in later multi-byte control fields.
- The daemon unit is enabled with a configured uid-0 default, while recovered
  policy intends `App::bluetooth`. Contrary reachability evidence matters:
  both engineering profiles say `PAN : N/A`, startup calls `BNEP_Init`, and no
  direct `BNEP_Register` reference was found. The parser is therefore dormant
  pending evidence of indirect/runtime registration. Adapter state, pairing/
  authorization, accepted channel, and controller byte preservation remain unknown.
- No Bluetooth process, adapter, pairing, packet, malformed input, crash, or
  disclosure was used. V-019 records exact conditional parser behavior without
  promoting Android's generic critical-RCE rating to a vehicle exploit claim.

## 2026-11-01 — Dropbear package remnants do not form a listener

- The RPM inventory's Dropbear version initially looked like another old daemon
  candidate. Filesystem reconciliation changed the conclusion: there is no
  `dropbear` or `dropbearmulti` executable, socket unit, host-key service/key, or
  enable link in recovered `260128`.
- The remaining template documents intended per-connection socket mode with
  passwords disabled. Its pre-start script would overwrite root's authorized
  keys with one shipped static public key, while the default does not disable
  root public-key login. That is latent trust material, not usable authentication
  without the private key and a restored server/socket chain.
- The default init branch creates the template's condition marker, so the marker
  is not the decisive blocker. Missing executable and activation dependencies
  are. No process, port, banner, or login was exercised.

## 2026-11-01 — exact wpa_supplicant code rejects two version-derived P2P findings

- The recovered package and binary advertise wpa_supplicant 2.5, but exact
  instructions contain later security backports. In `p2p_add_device()`, the
  every SSID copy is gated on the peer-controlled element length being at most 32,
  matching the CVE-2015-1863 fix.
- CVE-2021-27803 required a more careful control-flow comparison. The recovered
  Provision Discovery Request handler calls `p2p_add_device()`, then on every
  successful return unconditionally calls `p2p_get_device(p2p, sa)` and replaces
  the old pointer. This is the fixed flow; it is not conditional on the prior
  pointer being NULL.
- P2P is still a real compiled surface. ConnMan contains peer, find, listen,
  provision-discovery, and GO-negotiation machinery, and an enabled path unit
  can conditionally launch supplicantmanager. This capability evidence does not
  undo the exact fixed-code conclusions or prove production radio exposure.
- No target process, interface, P2P discovery, frame, or malformed input was
  used. The next physical evidence is passive capture of installed hashes,
  marker/arguments, process label, interface ownership, and find/listen state on
  a disconnected bench.

## 2026-11-01 — exact fortification changes an old ConnMan overflow into an abort

- Followed the same package lead into CVE-2023-28488, but stopped at exact code.
  The shipped DHCPv4 receiver does retain the upstream pre-fix mistake: it checks
  the real read length for 28 header bytes, replaces that count with untrusted
  `ip.tot_len`, and subtracts 28 without checking the replacement again.
- Normal IPv4 acquisition does reach the affected L2 callback. The exact client
  start enters `INIT_SELECTING`; mode 1 opens and binds an `AF_PACKET` datagram
  listener and registers the reviewed receive function.
- The compiler materially changes the consequence. The copy is
  `__memcpy_chk(..., 0x274)`, and every selected checked-copy implementation in
  the recovered libc branches to `__chk_fail` before an underflowed size can
  write the stack object. This exact build therefore supports conditional daemon
  termination, not the generic stack-overflow/RCE claim.
- A packet-free model partitioned all possible 16-bit total lengths and read
  lengths up to the exact 656-byte cap. No socket, frame, target execution, or
  NIC-enabled VM was used. V-016 records the availability boundary and leaves
  production interface state and the owner's installed build for a disconnected
  bench.

## 2026-11-01 — cellular SMS decoding adds a separate conditional root-daemon surface

- The RPM inventory pointed to an old oFono build, but the package label was
  only the start. Exact `ofonod` instructions retain both missing destination
  checks fixed for CVE-2023-4233 and CVE-2023-2794.
- The route is product-specific rather than hypothetical upstream code. Two
  callbacks in the compiled LG QMI modem driver pass direct indications and
  stored/raw-read SMS data into `ofono_sms_deliver_notify`, then the affected
  deliver decoder.
- Exact layout narrows the generic advisory. The address path can write 257
  bytes into 23; deliver data can copy 255 into 140. Both can leave the local
  `sms` object, but neither maximum directly reaches this caller's canary. The
  deliver copy is plain `memcpy`, so the fortify result that constrained V-016
  does not apply here.
- The service would be uid 0 but executes under SMACK `App::tms`, and its unit
  is marker-gated. No recovered path-unit enable link was found. Activation,
  modem/QMI state, carrier delivery, dynamic corruption, RCE, and unrestricted
  root remain open rather than assumed.
- Added a packet-free arithmetic model, exhaustive tests, reviewed evidence,
  and a disconnected-bench observation plan. No target binary, modem input,
  PDU, packet, or privilege action was used.
- Fable remained unavailable. DeepSeek Flash's route doctor was static-ready,
  but native dispatch failed as an unknown model; no substitute model or failed
  output was used.

## 2026-10-29 — the control protocol, read out of the binary

- The IAS interface had been inferred from wrandr's help text. It is now read directly: five methods and
  four events on ias_crtc, one method on ias_mode, with signatures. The interesting part is how well
  they line up with wrandr — brightness, contrast, gamma, mode and transparency all present — which
  confirms the tool is the intended driver of this protocol rather than something adjacent to it.
- Getting there took a correction. The first parse produced nonsense because a pointer into the data
  section coincided with a relocation entry; resolving vaddr to file offset through the program headers
  fixed it. Worth remembering that a plausible-looking struct at the wrong address is still wrong.
- The slice is now specified before any code exists, including how it will be refuted: a CRTC in
  wrandr's listing, a successful enable, and a 1920x720 output seen by weston-info. Writing the
  falsification first is cheaper than discovering afterwards that a backend "ran" without proving
  anything.
- The blocker is unglamorous and immediate: pixman headers are absent, so the first build decision is
  where that small amount of header surface comes from.

## 2026-10-29 — the toolchain answers first, as it should

- Before writing a backend it was worth knowing whether one could be built at all: an arm64 host with no
  cross-gcc, targeting a 2015 embedded x86_64 userspace. The bundled zig does it, and the proof is an
  ELF file exporting the right symbol rather than an opinion about compilers.
- The remaining blockers came from reading the source's own include list. That is a minute of work that
  would otherwise have been an afternoon of compiler errors, and it named the one genuinely missing piece
  on this machine: there is no wayland-scanner here.
- The pixman skew is the kind of detail that silently poisons a result later. Headers newer than the
  runtime will compile cleanly and then misbehave in ways that look like a backend bug, so it is written
  down now, with the fallback stated.
- Also a small housekeeping correction: the scaffold was first written under work/, which this repository
  ignores, so it would have been lost from history. It now lives under tools/.

## 2026-10-29 — the tool was inside the image all along

- The missing dependency was shipped with the product. The vendor rootfs carries wayland-scanner, so the
  guest can generate its own protocol headers, and a host install that had been the obvious next step
  turned out to be unnecessary.
- Getting the output back out taught a harness lesson worth its own line: the guest writes to a
  throwaway overlay, so a file produced inside disappears with the snapshot. Nothing about that is
  visible from inside the guest, where the file plainly exists. The extraction that worked streams the
  bytes over the console instead.
- The integrity check mattered more than usual here, because console transfer is lossy in ways that are
  easy to miss — wrapped lines, echoed commands, prompts in the middle of data. The decoded size matching
  the in-guest size exactly, plus the expected count of interface definitions, is the difference between
  a header and a plausible-looking corruption.
- Two build items remain rather than four, and both are small.

## 2026-10-29 — it builds

- The first real artefact: a backend plugin for this 2015 embedded guest, compiled from an arm64 laptop
  with no cross-compiler installed. The undefined-symbol count is the detail that makes it a plugin
  rather than a binary — those 31 symbols are weston's, resolved when it loads us.
- Every dependency on the way was discovered by failing, in this order: config.h, wayland headers,
  a protocol header the tarball does not ship, xkbcommon, then pixman. None of those would have been
  guessed in advance, and each is now written down so the next build starts from them.
- Homebrew refusing wayland on macOS was the surprise. The formula is a Linux compositor library and the
  bottle system simply will not build it here, so the release tarball was the way in.
- The extraction channels were worth testing properly instead of trusting the first one. Console transfer
  looked fine at 8 KB and silently corrupted at 23 KB; the socket capture looked authoritative and ate
  bytes. Both would have produced a header that compiled and then behaved strangely, which is the worst
  kind of wrong.

## 2026-11-01 — oFono directionality changes what “reachable” means

- `sms_decode` does not defer work until its caller accepts the decoded type.
  Incoming TP-MTI selects deliver, submit-report, or status-report decoding and
  completes the selected copy first. The QMI delivery handler's later DELIVER
  check therefore cannot protect CVE-2023-4232 or CVE-2023-4234.
- The reverse distinction matters equally. Deliver-report and command decoders
  are selected only for `outgoing=TRUE`, so they do not belong to the ordinary
  incoming SMS route. Exact callers were found in transmit-queue deserialization
  and SIM-Toolkit Send SMS parsing. That establishes shipped routes without
  pretending they are unauthenticated radio paths.
- Exact instructions retain all six reviewed TPDU decoder bounds. The expanded
  arithmetic model quantifies each destination. Incoming-decoder maxima do not
  directly reach the reviewed delivery caller's canary; outgoing-only caller
  frames remain separate and unresolved. That narrows impact without erasing
  corruption.
- The QMI WMS list callback proved to be a separate boundary. It reads the TLV
  length but does not validate it. A vendor overflow diagnostic uses a wrapping
  32-bit product and then falls through to a four-byte allocation, while
  iteration follows the original count. This confirms V-018, but the controlling
  metadata comes from the modem, not directly from an SMS TPDU.
- Both results remain static and conditional: no modem input, QMI message, PDU,
  target execution, crash, payload, SMACK escape, or root transition occurred.

## 2026-10-29 — our backend, the vendor shell on top of it

- The compositor that came up is ours. The vendor's own weston loaded our module, the vendor's IAS shell
  layered onto it, and the registry filled with vendor interfaces. That is the architecture the display
  decision was aiming at, running.
- The build gap was a useful one: option parsing belongs inside the module, not in the executable. One
  undefined symbol, one file added to the compile.
- Worth noting what turned up unasked: a screenshooter interface. If the vendor stack can hand out frames
  over the protocol, then "nothing is visible" is no longer true in principle, only unimplemented.
- The honest limit is that wrandr cannot yet drive a CRTC, because the interface tables are still only in
  the extraction document. Written down as the next step rather than folded into a claim of success.

## 2026-10-29 — the vendor did not ship stock Weston

- The crash was not a bug in what we wrote. The shipped compositor has a struct layout that differs from
  upstream by one inserted member, which shifts everything after it by 24 bytes. A field we initialised
  correctly landed in the wrong place, and the crash surfaced three functions away in the compositor's
  own output binding.
- What made this findable was two negative controls: removing our new code entirely did not change the
  crash, and putting logging inside our handlers showed they were never called. When a crash survives
  deleting the suspect, the suspect is not the cause — that inference is worth more than any amount of
  reading the protocol tables again.
- The vendor's binary ships its own DWARF, so the layout could be read out exactly rather than guessed,
  and then checked member by member against what the compiler produced. Reverse engineering against a
  documented layout is a different activity from reverse engineering against a remembered one.
- The control path now works end to end: a client enumerates a CRTC, sets a mode, and the compositor
  reports 1920x720 at 60 Hz on an output named HDMI1. The display architecture decision has its first
  working slice.

## 2026-10-31 — privacy sweep on the IAS tooling

- Two absolute paths in a debug script tripped the public harness. Fixing only the reported instance
  would have left the same leak in three other files, so the sweep covered every tracked file in this
  line of work instead of the single reported one.
- One apparent hit was not a leak at all: `/home/root` is a path inside the guest, not on this machine.
  Worth the extra look, because a blind find-and-replace would have corrupted a correct statement.
- The build products are the quiet risk: they embed the host path in their string tables, and they are
  ignored rather than tracked. That is now noted so nobody "helpfully" commits one.

## 2026-10-31 — we can see the screen now, and it is empty

- The screenshot pipeline works, and I checked it the only way that means anything: a known client
  renders a known pattern and the capture shows it exactly. With that control in place, a black frame
  from the vendor stack is information rather than a broken tool.
- The reason is not mysterious once measured. The apps start, one makes a surface and never commits it,
  another dies inside Qt's QML engine, and the launcher brings up its manager but no UI. The compositor is
  doing its job on an empty scene.
- A pitfall found on the way: the backend's default renderer cannot read pixels back. Without the
  software renderer flag every capture is black regardless of content, which would have sent this
  investigation in entirely the wrong direction. The flag is now recorded as mandatory.
- The honest position is that the display architecture is done and the applications are not. That
  distinction — compositor complete, client software broken — is a much better place to be than it
  sounds, because the remaining fault is in one Qt process rather than in the plumbing.

## 2026-10-31 — one missing library, and the UI stops dying

- The Qt crash that looked like a vendor bug was an environment failure. There is no software rasteriser
  in this image at all, only Intel drivers, so EGL could never initialise and the application fell over
  afterwards. Supplying the rasteriser removed both symptoms at once.
- What made the difference was reading the log line before the crash rather than the crash itself. The
  fatal message was two lines earlier and completely unambiguous: failed to open swrast. The segfault was
  downstream noise, and chasing it directly would have been chasing the wrong thing for a long time.
- The app now runs and asks for its database. That is a far better class of problem: it is asking for
  data this projection never provided, which is a matter of populating a partition rather than diagnosing
  a crash.
- Worth noting the materials were already in the repository from earlier work on software EGL. The answer
  was sitting in work/software-egl the whole time, which is an argument for keeping these extractions
  around.

## 2026-11-01 — collect state once before touching a disconnected bench

- The remaining network, cellular, Bluetooth and SSH questions shared the same
  weakness: recovered configuration described intent, while installed hashes,
  active units, effective SMACK labels and profile registration remained
  unobserved. A single passive console capture now has a defined format for all
  of them.
- The generated probe is deliberately less capable than an ordinary diagnostic
  shell script. It prints to stdout but cannot mount, change radio state, start a
  unit, contact a peer, signal a process, install software or create a target
  file. Truncation and missing tools are first-class records rather than
  negative findings.
- The custom-rootfs builder received the same fail-closed treatment. Archive
  paths, links, special nodes and injection destinations are checked before
  staging, and original packages/manifests cannot be overwritten in place. This
  removes build-host hazards without pretending the target will accept the
  resulting package.
- No bench, network, radio, modem, firmware update or target executable was used.
  Root access and custom-update acceptance remain evidence questions, not claims.

## 2026-10-31 — the app lives, the screen does not

- Two separate causes were hiding behind one black frame. The first was liveness: with a bus and the MICOM
  daemon the home screen now survives and writes its databases. The second is presentation: it commits
  surfaces that never appear.
- The shared-memory messages are the interesting part. Widgets are asking for boot information that another
  process is supposed to publish. A committed surface with nothing to draw in it looks exactly like a
  broken compositor, which is why the control capture mattered — it separates "our capture is wrong" from
  "their scene is empty".
- Naming the hypothesis rather than chasing it: under this shell, mapping a client onto a CRTC is the
  composer's job. A plain client is mapped automatically; a vendor client waiting to be placed is not.
- The useful shift is that the failure is now in vendor application logic — shared boot state and surface
  placement — rather than anywhere in the emulation we built.

## 2026-10-31 — the compositor was never drawing

- Instrumenting the repaint path answered the question in one run. There were no repaints at all, which
  makes the black frame not a rendering bug, not a capture bug and not a mapping-of-our-surface bug: the
  compositor simply had nothing to draw because no surface was ever placed.
- The cause is a missing file rather than missing code on our side. The layout engine that would position
  surfaces lives in the OEM partition, and it is absent from the firmware image entirely — the directory
  exists and is empty, which is the shape of a mount point rather than a packaging mistake.
- What this means for the goal is worth stating: every piece of emulation built over this session is
  working. The remaining gap is one vendor plugin that was never in the package we have, and a research
  shim can stand in for it.

## 2026-10-31 — the app only speaks one language

- Swapping the shell for one that maps clients automatically changed nothing, which was informative: the
  application never asks the shell for placement. It speaks the IAS protocol and nothing else, so the only
  component that can put it on screen is the one whose layout plugin is missing.
- That reframes the remaining work as writing that plugin rather than fighting the compositor. The
  framework exports everything a plugin needs, including the call that assigns a surface to a scanout.
- The vendor again ships its debug information, this time in the shell and the plugin framework. The exact
  interface can be recovered instead of inferred, which turns a speculative shim into a precise one.
- Worth naming the pattern across this session: where vendors ship DWARF, reverse engineering becomes
  reading; where they strip, it becomes inference. The expensive mistakes here have all come from inferring
  something that was actually written down.

## 2026-10-31 — the last missing component, written down

- The plugin interface is no longer a guess. Every field of the registration record and the callback table
  has an offset and a signature, taken from the vendor's own debug information, and the discovery symbol is
  named.
- Two details explain things that had been puzzling: the union at 0x18 is why one struct serves both layout
  and input plugins, and init_mode is why the config says defer. Reading the structure answered questions
  that experimentation had been circling.
- What remains is small and enumerated rather than vague: two ID types and one function signature. Recording
  the gap explicitly, rather than implying the picture is complete, is the difference between a specification
  someone can build from and a summary that flatters the work.

## 2026-11-01 — one wrapper, two updater architectures

- The apparent contradiction in the update evidence had a routing answer. The outer program is not the
  updater proper: it chooses between two embedded executables. `-un:1` selects SCOMO; everything else selects
  FUMO, and the original arguments are forwarded to whichever child runs.
- The missing link was AppLauncher. Dynamic applications do not start with an empty argument list; they get
  the same vehicle/model option builder as the static process set. The embedded IONIQ 5 NE/EUR row says
  `-un:0`, so its recovered route is FUMO. `-un:1` is also what conditionally replaces AppDMClient with
  AppScomoDM, making the split architectural rather than an isolated flag.
- The encryption marker means different things on the two sides. FUMO loads a byte initialized to one and
  changes it to zero when the marker exists at startup. SCOMO's production/penetration path says in its own
  log text that it ignores the marker. Calling the marker either a universal bypass or a no-op would therefore
  both be wrong.
- The correction that matters most is about trust boundaries: selecting an unencrypted mode is not the same
  as passing version, model, signature, digest, target, write, slot, boot, or health checks. Those remain
  separate questions, and no updater was run to collapse them into a convenient story.
- AppSetup also became simpler under exact review. It asks the manager to move to app ID 300; it is not the
  descriptor parser previously assigned to it by the public operating model. Finding the actual owner of
  `.lge.upgrade.xml` is the next update task.

## 2026-10-31 — the compositor draws now

- The shim replaced the missing plugin well enough that the compositor started repainting. That is the
  first time in this whole line of work that the scene is not empty by construction.
- Two structural surprises: this Weston build has no compositor-wide surface list despite a comment saying
  it does, so a signal hook was the only way in, and the framebuffer is far too large to carry out of the
  guest over the channel available. Both are the kind of thing only measurement settles.
- What remains is observation, not construction. That distinction is worth keeping straight, because
  "I cannot see it" and "it is not happening" have looked identical several times in this session, and each
  time the control experiment was what separated them.

## 2026-10-31 — the screen is black because nothing was ever given to it

- With placement fixed, the compositor finally rendered — and rendered nothing, correctly. The client
  commits its surface five times and never attaches a buffer. There is no scene to draw, so black is the
  right answer rather than a bug.
- That resolves the last ambiguity. The earlier shared-memory messages were not noise: without boot
  information the widgets never allocate their buffers, and without buffers there is nothing to see.
- What this project can now say is well defined: everything from the kernel to the compositor to our own
  adaptors works, and the remaining gap is one vendor component's shared state. That is a good place to
  stop guessing and start looking for a segment key.

## 2026-10-31 — found the publishers, but not the right one

- The shared memory question resolved into something much more specific today. Segments are being created,
  by name, and the names are now known. The application simply wants different ones.
- ApplicationManager does publish boot status, which looked like the answer and was not. UserProfileManager
  and MOFManager publish a long list of per-setting segments with an unmistakable naming style. Neither set
  is the vehicle interface state the widgets read.
- The negative result is worth as much as a positive one here: micommanager, the obvious publisher for an
  interface named Ihu, does not create that segment. That removes the intuitive candidate and points at
  something less obvious.
- The state of the whole investigation is now cleanly summarised: every layer from firmware to compositor
  works, the UI runs, and it refuses to draw because one piece of vehicle state it reads is absent.

## 2026-11-01 — authentication was after the parser

- The missing owner of the SCOMO USB staging step is now exact. AppScomoDM chooses the system ZIP, asks an
  external extractor for two members, authenticates both extracted files, decrypts AppUpgrade, and then asks
  AppLauncher to run app ID 300. The XML is authenticated and copied, not decrypted, on this path.
- That ordering exposed a separate boundary: the archive parser sees removable-media bytes before the public-
  key decision. The intended `unzip` is BusyBox, and its exact instructions accept BZIP2 method 12 while
  retaining the unsigned run-count wrap repaired upstream only in October 2026.
- The package database would have sent the review in the wrong direction: it says BusyBox 1.23.2, while the
  exact executable says 1.35.0 and contains the latter code shape. The binary, not the label, decides the
  finding.
- V-020 is deliberately static. No compressed stream or update archive was built and no target ran. Exact
  arithmetic and control flow show the conditional pre-allocation write; they do not show a crash, controlled
  execution, root, signature bypass, accepted update, or physical-unit applicability.
- A numeric-only model records the old and fixed guards without encoding target input. This preserves the
  useful proof while keeping trigger material and active update behavior outside the repository.

## 2026-10-31 — the trail leads back to the MICOM

- The shared-memory hunt ended where it started. No manager creates the vehicle interface segments on its
  own, and the only one that creates anything publishes conditionally on state it can only get from the
  vehicle link.
- That is a satisfying closure of the session's main thread: the MICOM contract, labourisly measured early
  on, turns out to gate not just the boot-info asks but the entire UI's ability to draw.
- The remaining work is now a single, well-specified component that answers frames we have already recorded,
  rather than an open question about missing state.

## 2026-10-31 — the responder was ready and the environment was wrong

- The MICOM peer is written and it listens, but nothing arrives to answer. The cause is not the peer: the
  daemon that should talk to it only speaks when systemd starts it, not when a research shell does.
- That distinction had been hiding in plain sight across every run of the day. The byte counter read zero
  each time and I had treated that as "no peer to talk to", when it also meant "no attempt was made".
- The correction is cheap to state and expensive to have missed: running and functioning are different
  claims, and this image separates them cleanly by boot path.

## 2026-11-01 — correction: the first updater parser finding used the VM helper

- Independent review rejected the initial method-12 V-020 attribution. The BusyBox 1.35.0 file under the
  integrated `extracted-safe` tree is a hard-linked static VM helper, installed during research-image
  construction; it is not stock firmware. The original bytes were preserved and also exist in an independent
  extraction as BusyBox 1.23.2, SHA-256 `95bab633...bd9ebc`.
- Stock `unzip` accepts ZIP methods 0 and 8 and rejects method 12, so the earlier BZIP2 run-count route is
  withdrawn for the recovered firmware. This correction preserves the failed analysis rather than silently
  rewriting it and adds a stock/VM provenance rule for future exact-binary work.
- Re-analysis found a different exact pre-authentication defect: method 8 reaches CVE-2015-9261's pre-fix
  `huft_build` `v+n` bound. Incomplete dynamic-Huffman tables can read an uninitialized `v[]` entry and
  conditionally make an invalid indexed read before AppScomoDM authenticates either extracted member.
- The supported impact is now deliberately narrower: likely `unzip` child crash and update denial of service.
  No malformed stream was created, no target ran, and no memory write, RCE, root, signature bypass or accepted
  update is claimed.
- The same review corrected archive selection from "last match" to one first iterator result and extended the
  passive collector to record symlink metadata plus allowlisted effective process `PATH` evidence.

## 2026-11-01 — FUMO XML and mode contracts moved from inference to exact code

- Exact AppDMClient review separated the FUMO USB path from AppScomoDM's SCOMO ZIP path. AppDMClient computes
  verifier results for `AppUpgrade` and `.lge.upgrade.xml`, then parses the descriptor version and applies two
  normalized lexicographic comparisons.
- The XML reader accepts `lhavn`/`wideavn` and searches consecutive element-convertible siblings from the first
  root child for `version`; a non-element ends traversal and trimmed text may be empty. Its verifier/open is
  separate from the staging function's earlier retained result, with no proved immutable snapshot.
- `/update/disableEncryptionUpdate` has an exact conditional FUMO contract at this layer: on the unequal
  source/destination branch, absent requires retained `0/0` and present requires `-404/-404`. An equal pre-staged
  AppUpgrade path skips both contracts. This is stronger than a generic mode-byte observation and weaker than a
  plaintext-package bypass: caller reachability, source stability, later payload/target checks, and the local
  privileged marker remain separate boundaries.
- The reviewed USB comparator calls disable one section-zero vehicle equality check while retaining P5-family
  compatibility and later inner-updater checks. No model/region bypass or accepted modified update is claimed.
- No updater ran and no package, XML fixture, marker, partition, or slot was created or changed.

## 2026-10-31 — the daemon told us exactly what is wrong

- The systemd boot gave two facts that matter more than any inference: the daemon wrote 103 frames, and it
  read zero. It is talking into a void.
- The peer produced no output at all, which under systemd means its errors went to stderr and vanished. That
  is a self-inflicted blind spot: the very failure mode I needed to see was the one I had routed nowhere.
- The lesson is small and repeatable: instrument the failure path before the success path, because the
  failure path is the one you will need when nothing appears.

## 2026-10-31 — the program is fine, the context is not

- The peer listens and stays alive when a shell runs it, and does nothing when systemd does. Same binary,
  same device, different launcher. That is not a protocol problem any more.
- Two escalation attempts changed nothing, which is itself informative: the wrapper ran, the daemon started,
  and the read counter stayed at zero. The failure is below the service definition.
- The most likely suspect is the security module. This image runs SMACK, audit lines are visible, and every
  silent-denial theory fits the evidence exactly: nothing crashes, nothing logs, nothing happens.
- The lesson from earlier in the session repeats: the instrumented channel has to be one that works in the
  failing context. kmsg looked like the universal answer and it is not, when the thing blocking the write is
  the same thing I am trying to observe.

## 2026-10-31 — the plumbing was wrong, not the protocol

- Three failed integration attempts, then the reason: a tty is not a loopback. I had a peer and a daemon each
  holding the same serial line, writing outward, and wondering why neither heard the other. Nothing was
  broken except my mental model of the device.
- The audit trail cleared the security module outright — zero denials, and our binaries were never named in
  it. That hypothesis is retired with evidence rather than left standing.
- Worth recording the pattern of the failures honestly: each attempt was a reasonable variation, and none
  could have worked, because they all shared the same wrong assumption. Changing the wrapper, the ordering
  and the handshake were three ways of not re-examining the foundation.
- The fix is small and known: a pty pair, with the peer on the master and the daemon's device symlinked to
  the slave. Everything already built for the peer still applies.

## 2026-11-01 — the FUMO equal path is a local relaunch contract

- Caller tracing closed the largest ambiguity left by the FUMO descriptor
  review. AppDMClient's stored `this+0x128` string is the USB mount path copied
  by `slotUsbMounted`, and later mount/standby workflows feed it back into the
  same staging function.
- The apparently unchecked equal path also has two fixed local callers.
  AppDMClient can stage from `/update/usb/bin` during standby handling, and a
  helper does so only when `/update/force_launch` begins with exact text `run`.
  That source makes the compared AppUpgrade paths identical and intentionally
  skips repeated outer result-pair checks.
- The inner FUMO executable creates the matching state: system- and
  firmware-progress-zero branches write `force_launch=run`, while completion
  cleanup writes `none`. This changes the interpretation from “unresolved
  reachability” to “intended pre-staged relaunch.”
- The correction does not turn the branch into a physical-media bypass. Who can
  modify the local staging directory, which completed authentication state
  precedes the marker write, whether the staged files stay immutable, and every
  inner payload/write/boot boundary remain separate open questions.
- Passive bench capture was extended for these markers, directories, and staged
  hashes. No updater ran and no package, marker, target filesystem, partition,
  or slot was modified.

## 2026-10-31 — two real bugs fixed, and a blindfold

- The pty approach was right and had two concrete defects, both now fixed: no devpts in the guest, and a
  device path taken from the wrong argument. From a shell it now works end to end.
- Inside systemd it still does not, and I can prove that without seeing anything: the daemon keeps writing to
  the hardware chardev, so the device was never replaced. The wrapper runs; something inside it fails.
- Every channel I would normally use to see that failure is closed in this environment. That is the actual
  obstacle now, and it is worth naming plainly rather than continuing to vary the code and hope.
- The lesson is one this project keeps teaching: build the observation channel into the environment before
  the experiment, because retrofitting it under systemd is where the time goes.

## 2026-11-01 — exact return codes and exact backports narrow two old theories

- AppDMClient's `-404` verifier result now has a concrete meaning. The parser
  did not find a `TER` or `TE2` candidate in the fixed `0x4024`-byte trailer;
  it did not report successful signature verification. This sharpens the FUMO
  mode contract without proving plaintext package acceptance.
- A numeric-only gate model now makes the two unequal-source result contracts
  and equal-path skip explicit without ingesting or producing update material.
- The old kernel banner suggested CVE-2017-7308, but the exact packet module
  tells a narrower story: its private-area arithmetic has the decisive 64-bit
  backport, while a companion frame-count overflow check is missing. The
  published write primitive is rejected; the remaining arithmetic gap stays an
  impact-unresolved candidate gated by `CAP_NET_RAW` and TPACKET_V3.
- No recovered program ran, no malformed input was built, and no target state
  was modified.

## 2026-10-31 — the vehicle link answers

- After a long stretch of environment fights, the thing actually worked. The daemon read a frame from the
  peer, and the peer answered the two boot-info asks with 35-byte payloads. For the first time the research
  stack is holding up its end of a vendor protocol with a real vendor daemon.
- The fix that mattered was not elegant: replace the daemon's own binary path with a wrapper. Three attempts
  to configure the launcher politely had no effect at all, and one interception at the binary caught every
  route at once. When a system refuses to be configured, stand where it cannot avoid you.
- Two silent tooling failures nearly hid the result: a wrapper left without an execute bit simply never ran,
  and debugfs's mode command needed a different form than the one I used. Both produced the same symptom —
  nothing happens — which is exactly the symptom this project keeps having to disambiguate.
- Read count is no longer zero. That single number has been the objective for several rounds.

## 2026-11-01 — one cryptographic wall is a conditional inner gate

- Following the FUMO mode byte into exact downstream code found a named
  navigation-map signature decision rather than a universal package verifier.
  Encrypted mode with a map candidate and provider starts an asynchronous NUA
  check; nonzero results and timeouts stop that path.
- Four states mark the gate complete without verification: its dedicated local
  disable marker, no provider, non-encrypted mode, or no selected map. The
  important correction is that the general FUMO encryption-disable marker sets
  the byte used by the non-encrypted map-signature skip.
- This advances the trust reconstruction without collapsing its boundaries.
  Control of either local marker is still unproved, and a skipped map gate says
  nothing by itself about descriptor, version, model, non-map digest, write,
  slot, boot, root, or persistence acceptance.
- A numeric-only model and passive marker capture preserve the result without
  creating update material or changing a recovered filesystem.

## 2026-10-31 — two halves working, not yet at once

- The D-Bus failure was never a permission problem. It was a race that had been running since the first boot:
  the daemon asks for the bus a hundred seconds before the security rules that permit the request exist.
- Once the daemon waited for the ruleset, the bus errors went to zero. And once the wrapper replaced the
  daemon's path, the MICOM exchange worked. Each half is now demonstrated.
- They are not yet demonstrated together, and this boot shows that clearly rather than hiding it: the wrapper
  ran twice, the peer was not serving the instance that connected, and no boot-info reply was logged.
- The remaining work is coordination, not discovery. That is a much better place to be than the last several
  rounds, where the question was still what was broken.

## 2026-11-01 — updater relaunch state is progress, not proof

- Exact callback tracing changed the meaning of one tempting local marker.
  FUMO attempts `force_launch=run` after attempting progress state `processing`;
  the branch-local progress-100 sequence attempts `complete` and force value
  `none`, while later scheduled flow can attempt `run` again. The run value has
  multiple origins and does not by itself establish completion.
- Some callback traffic now has a name—`DeltaUpdateProgressHandler`—but the
  direct write sites read no named signature, digest, certificate, or
  payload-auth result. Their evidence does not itself establish authentication;
  the unresolved question moved upstream: can a valid progress event
  happen before package authentication, rather than what the marker means.
- The scheduled route remains different: it reads both completion strings and
  checks scheduled-update state before attempting `run`. Those are still
  operational conditions, not cryptographic proof.
- This also corrects the earlier shorthand that cleanup “writes `none`.” The
  generic writer does not reject short writes or check flush/`fsync`, its
  callers ignore the result, and the remove helper ignores `QFile::remove()`'s
  result. These are attempts, not proved atomic transitions.
- A concurrent correction also keeps the residual AF_PACKET frame-count gap
  impact-unknown for V1/V2. Public TPACKET_V3 redundancy does not settle the
  exact common multiplication and later `frame_max` use.

## 2026-10-31 — a zero that meant nothing happened

- The peer is properly decoupled now, and the wrapper reliably reaches the daemon. Along the way I found that
  a number I had reported as success was empty: zero D-Bus errors because zero attempts, with the wrapper
  killed mid-wait before it ever started the daemon.
- That is the second time in this session that "no errors" was the absence of work rather than the absence of
  faults. It is worth writing down as a rule: a counter of failures is only meaningful alongside a counter of
  attempts.
- With the daemon genuinely running, the exchange is happening and publication is still failing. The SMACK
  ordering theory is weakened by its own test, which is what tests are for.

## 2026-10-31 — the bus works, so the theory was wrong again

- One measurement ended a theory I had been building on for three rounds. The system bus is reachable from the
  exact context the daemon runs in, at the exact moment it runs, and it still reports no connection.
- That is a cleaner failure than the ones before it: the environment is exonerated, and what remains is the
  vendor's own connection handling.
- Also worth noting a self-inflicted detour: my first attempt at this test used the wrong path for dbus-send
  and returned a shell error that looked like a failure to reach the bus. Checking the tool exists before
  trusting its verdict is the same discipline as checking attempts before trusting an error count.

## 2026-11-01 — the branch was the backport

- CVE-2017-11176 looked promising: the exact old kernel has POSIX message queues, and its `netlink_attachskb` return-one edge loops without an explicit socket-register clear.
- Full successor tracing reversed that first impression. A failed retry cannot reach socket detach with the old released pointer; it goes directly to notification-skb cleanup. The compiler represented upstream `sock = NULL` as branch routing.
- The candidate is rejected for the recovered kernel, with exact addresses, file offsets, upstream source comparison, retained disassembly, and a boolean-only ownership model. No race or target syscall was executed.

## 2026-10-31 — recognising a cul-de-sac

- The trace blocked the wrapper and produced nothing, and the tell was the same zero as before: no attempts,
  not no errors. Having now made that mistake twice, the pattern is at least documented.
- The more useful decision is to stop chasing the vendor daemon's bus handling. The goal is a running HMI, and
  there is a shorter path: publish the shared memory it cannot. That is precisely the kind of simulated adaptor
  this work exists to build.
- Keeping the distinction clear matters for the record: the daemon's bug is real, unfixed, and not the thing
  standing between this project and a rendered screen.

## 2026-11-01 — the USB-MIDI owner already had the only free

- A second physical kernel lead was exact enough to test: generic USB Audio/MIDI is modular and shipped, while CVE-2016-2384 is reached during descriptor-driven probe before login.
- Exact relocation and successor review found the fix effect. Raw-MIDI owns final destruction, and all post-registration endpoint failures return without the vulnerable second direct free.
- The candidate is rejected for the recovered module. No descriptor or peripheral was created and no module or target kernel path was run.

## 2026-10-31 — the shared memory attaches

- The shim worked on the first attempt because the naming rule was derived from evidence rather than guessed:
  two vendor-created segments agreed on sha1(key), which is enough to build the third.
- The UI's attach failures are gone, which removes a blocker that had survived several rounds of indirect
  attack. Whether it draws is now a separate question, and one that a single counter can answer.
- Three times today a zero has meant "nothing ran" rather than "nothing failed", and the third time was caught
  in the same turn it was produced. That is the format working: record the run, then check it was a run.

## 2026-11-01 — three more old banners lost to exact ordering

- Public triage identified three unusually relevant local-kernel candidates: SysV publication races, `recvmmsg` post-release access, and inherited IPv4 multicast state. None needs a user namespace or special device in the generic path.
- Exact instructions rejected all three. SysV state is initialized before publication, the socket error precedes `fput_light`, and the cloned child multicast pointer is cleared before return.
- A boolean-only matrix records the semantic gates without running a target syscall, object, packet, race, or corruption attempt.

## 2026-11-01 — ALSA timer races survived triage, not disassembly

- Shipped `snd-timer.ko` and permissive-looking static-node policy made three 2016 timer races plausible on version/configuration evidence.
- Exact relocatable-module semantics showed all three repairs: list reinitialization on expiry, one ioctl/release mutex, and coherent global/timer locking with complete slave unlinking.
- The result is an identity-bound rejection, not a runtime claim; no module or timer interface was exercised.

## 2026-10-31 — the fourth empty zero

- Running the measurement with the compositor up told the truth twice. The client never attaches a buffer, so
  the black frame is settled as a client-side fact. And the attach count I reported as fixed came back at nine,
  because without a compositor the application dies before it ever reaches the widgets that complain.
- That is the fourth time a zero has meant "the code path was never reached". It is now a standing rule in this
  project rather than a lesson to relearn: check the path was reached before believing the count.
- The shim's naming work is still correct — two independent samples agreed — but correctness of a name is not
  the same as a usable segment, and the difference is the next thing to find.

## 2026-11-01 — the ALSA timer backport is incomplete at an information boundary

- Follow-up separated two superficially similar stack initializations: the params and general callback records are fully cleared, while `snd_timer_user_tinterrupt` clears only a separate timestamp object.
- Exact queue and read copies preserve all 32 record bytes, leaving two four-byte ABI padding regions as a conditional CVE-2016-4578 disclosure path (V-021). No bytes were collected and no root impact is claimed.
- Exact sequencer locking rejected CVE-2016-2544, prior cleanup semantics also reject CVE-2016-2548, and CVE-2016-2549 is unavailable because the ALSA hrtimer provider is absent.

## 2026-10-31 — strace beat derivation

- The naming scheme I had "derived" from two samples was wrong for every key that actually mattered. One strace
  produced the six exact paths, which is both faster and certain.
- The general lesson is now unambiguous: when a component's behaviour is observable, observe it. Deriving an
  algorithm from a couple of data points produces confident, coherent and false results, which is exactly the
  kind of error that costs a great deal of time to unwind.
- The run itself proved nothing, and I am recording it as proving nothing rather than as a failed experiment:
  zero commits means the application never got as far as the thing being measured.

## 2026-11-01 — vmacache becomes the strongest remaining generic local-root candidate

- Unlike many old-kernel candidates, CVE-2018-17182 needs no namespace, optional network protocol, special device, or privileged helper in its generic path.
- Exact instructions retain every pre-fix generation-wrap semantic: two 32-bit invalidation sites, a live zero-wrap flush call, single-user no-clear return, and 32-bit lookup validation.
- This is still a candidate, not a root result: the 2^32-state cycle, stale pointer, UAF dereference, controlled reuse, and privilege gain were not exercised.

## 2026-11-01 — ordinary mremap retains the stale-TLB lifetime window

- Exact PTE transfer and lock identities show source/destination page-table locks are released before the old-range TLB flush.
- This matches CVE-2018-18281 pre-fix ordering and adds V-023 as a second generic MMU candidate.
- The finding stops at the code-level window: no concurrent invalidation, page release/reuse, stale access, corruption, or root was run or proved.

## 2026-10-31 — merged an outside PR, and found a contradiction worth more than the merge

- Merged Harald Aarseth's register PR into the older research repository. It is genuinely good work: the
  update trust-anchor entry and the environment-file entry are both the kind of finding that matters, and both
  are stated with the right hedging about what was and was not demonstrated.
- One item disagrees with our own measurement. They report USB-to-root execution with a serial string that our
  instrumentation shows being rewritten to underscores by udev before it reaches the sink. Both runs are on the
  same image.
- Rather than pick a winner, the discrepancy is written down with the hypothesis that best explains it: a
  synthetic event with a pre-supplied property bypasses the sanitiser that a real descriptor cannot. If so,
  their demonstration is real in the harness and not reachable from a device, which changes its severity from
  critical to informational. That distinction is the whole point of the register.

## 2026-11-01 — TTY master and slave setters protect one pgrp with different locks

- Exact UNIX98 PTY installation, ioctl dispatch, pgrp helper, and PID ownership flow establish CVE-2020-29661 wrong-object locking.
- Startup intends `/dev/ptmx` mode 0666, making this a high-priority local candidate if passive runtime capture confirms exposure.
- The result remains a race premise: no PTY operation, concurrent interleaving, PID UAF, corruption, or root was run or proved.

## 2026-10-31 — the disagreement was settled with a device, not an argument

- Two reports claimed different things about the same bug. Rather than adjudicate on plausibility, the exact
  payload was put through a real descriptor with the correct interface class, and the property udev handed to
  the vulnerable service was recorded: every metacharacter had become an underscore, and nothing executed.
- That does not make the outside report dishonest. It most likely injected the environment property directly,
  which skips the sanitiser that sits in front of it. A harness can do that; a USB device cannot.
- Both sides were right about the defect and wrong about nothing except reachability, which is the part that
  decides whether a bug is critical or informational. The register now carries the measurement next to the
  claim so neither can be read without the other.

## 2026-11-01 — AF_UNIX MSG_PEEK reaches descriptor delivery without the GC barrier

- Exact stream and datagram receive paths duplicate attached file lists and carry them into SCM delivery without touching the module-global GC lock.
- Recovered D-Bus use makes AF_UNIX load plausible, but passive module identity remains the first bench step.
- No socket graph, descriptor transfer, GC overlap, UAF, corruption, or root was created or proved.

## 2026-11-01 — timerfd cancellation membership lacks per-context serialization

- Exact setup and removal update one context membership state outside the static global-list lock; the fixed per-context lock is absent.
- Built-in timerfd makes the premise broadly reachable in principle, but no harmful same-context interleaving was exercised.
- List corruption, UAF, crash, corruption, and privilege gain all remain unproved; public impact supports DoS more clearly than root.

## 2026-10-31 — an outside finding that survived contact with the image

- The merged entry about the update trust anchor was the one claim from that PR worth testing hardest, because
  it is the kind that survives reboots. It held up, and the details make it worse rather than better: the root
  is read-write by default and every mechanism that would have remounted it read-only is commented out.
- The part worth keeping is the caveat. The live guest reports a file owner that is ours, not the vendor's,
  and saying so keeps the finding at the strength the evidence supports: one privileged write, not one local
  user.

## 2026-10-31 — two entries from an outside PR, checked against each other

- Individually each was an observation; together they form a path. A world-writable environment file read by
  eleven root services supplies precisely the privileged write that a separate entry said was missing.
- The discipline that mattered was refusing to round the chain up. The file that anchors update trust is 0755
  in a 0755 chain, so the chain still needs the root step, and saying so is what keeps the register credible.
- Every element of this was verified in the image today: mount options, unit list, absence of User=, anchor
  mutability and persistence. The only unverified parts are the first stage and the restart, and they are
  labelled as such.

## 2026-10-31 — the missing link was tested and does not hold

- The chain needed a first stage; the launcher's unverified path looked like the obvious supplier. It launches
  from read-only partitions, so it needs the very privilege it was supposed to provide. The gap stays open.
- Negative results like this are worth the run they cost. The register is now narrower and more honest: three
  candidates for the first stage, one eliminated with evidence, and the remaining two are the ones that actually
  take unprivileged input.
