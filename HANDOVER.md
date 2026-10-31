# HANDOVER — IONIQ 5 Gen5W research

Updated **2026-11-04**. The recovered authentic Hyundai/LG launcher chain now
passes the standby/profile-confirm gate and visibly foregrounds authentic
`AppHomeScreen` in the local VM. Authentic AppNavi map pixels still render
separately. The remaining integration goal is stable Home↔Navigation operation,
followed by stateful service/CAN/persistence reconstruction.

## TTY line-discipline reference checkpoint — 2026-11-04

- CVE-2016-0723 is rejected for exact recovered `vmlinux` by retained-reference
  effects matching upstream `5c17c861a357e9458001f021a7afa7aab9937439`;
  stripped machine code cannot establish direct commit provenance.
- Exact `tty_ioctl [0xffffffff812871f8,0xffffffff81287d46)` dispatches command
  `0x5424` to `0xffffffff812879f9`, calls exact `tty_ldisc_ref_wait`, loads the
  retained `ldisc->ops->num` afterward, calls exact `__put_user_4`, and calls
  exact `tty_ldisc_deref` before return. The copy result is not branched on
  before dereference, so user-copy error is covered.
- Complete exact `tty_ldisc_ref_wait`, `tty_ldisc_ref`, and `tty_ldisc_deref`
  ranges bind their `ldsem_down_read`, `ldsem_down_read_trylock`, and
  `ldsem_up_read` calls. The verdict is limited to the named unlocked
  dereference; general TTY safety, installed identity, and all runtime/impact
  observations remain unproved.
- Added the authoritative patch, complete retained assembly, and a twelve-input
  schema-v2 Boolean model. Focused validation passed `8 tests, 4111 subtests`;
  the complete suite passed `578 tests, 152717 subtests`; the public harness and
  bytecode compilation passed; independent exact-binary/package review returned
  **ACCEPT**. No recovered target, target operation, terminal, thread, race, or
  trigger material was used or created.

## compat netfilter path checkpoint — 2026-11-03

- CVE-2016-4997 is rejected for exact recovered `vmlinux` by an absent compiled prerequisite: IA32 emulation is disabled, `CONFIG_COMPAT=y` is absent, weak `compat_sys_setsockopt` aliases exact `sys_ni_syscall` and returns `-ENOSYS`, and no compat iptables translation/check symbol occurs in the authoritative map.
- Native `do_ipt_set_ctl` and `do_ip6t_set_ctl` remain compiled, so the conclusion is limited to the CVE-specific 32-bit compat implementations and is not a general netfilter safety claim. `CONFIG_USER_NS=n` separately removes the public in-container-root setup.
- Added exact stub evidence, authoritative upstream fixes, and a five-input schema-v2 model. Focused validation passed `6 tests, 36 subtests`; the complete suite passed `570 tests, 148606 subtests`; the public harness passed; corrected independent exact-binary/package review returned **ACCEPT**. No target syscall, socket, namespace, packet, filter table, target execution, crash, or privilege action was created.

## key read/revoke race checkpoint — 2026-11-03

- CVE-2015-7550 is rejected for exact recovered `vmlinux` by same-rwsem effects matching upstream `b4a1b4f5047e4f54e194681125c74c0aa64d637d`; stripped code cannot establish commit provenance.
- Exact `keyctl_read_key [0xffffffff811b509a,0xffffffff811b516e)` takes `key +0x20` for reading before `key_validate`, retains the lock through the optional read callback, and unlocks afterward. Exact `key_revoke [0xffffffff811b239c,0xffffffff811b2401)` takes that same rwsem for writing across revoked-state bit 2 and the optional revoke callback.
- The six-input schema-v2 model leaves incomplete fix facts unknown absent an explicit unlocked-window fact. No target/keyctl syscall, key, thread, race, allocation pressure, target execution, crash, or privilege action was created. Focused validation passed `8 tests, 73 subtests`; the complete suite passed `564 tests, 148570 subtests`; the public harness passed; independent exact-binary/package review returned **ACCEPT**.

## Update-source runtime-policy checkpoint — 2026-11-03

- Both recovered eMMC fstab branches configure `/dev/mmcblk0p9` at `/update` as ext4 with `defaults,noatime,journal_checksum`, establishing writable-filesystem configuration rather than live mount success.
- `smack_setup.sh` conditionally creates `/update/usb/bin` and placeholder AppUpgrade/AppScomoUpgrade files, then sets only their `SMACK64EXEC=App::upgrade` transition label. It does not pin uid/gid/mode or set the `SMACK64` access label.
- The recovered policy permits the floor label and 22 named `App::*` labels to write an object labelled `App::upgrade`, but staged object/directory labels, DAC metadata, process uid/gid/labels, loaded rules and update serialization remain runtime gates. Actor write access and V-031 substitution remain unproved.
- Extended `tools/uk_fw/bench_state_bundle.py` to capture `/update` namespace metadata, complete process uid/gid sets plus supplementary groups, and read-only `SMACK64`/`SMACK64EXEC` results for source/trust paths. Absent paths, absent attributes, unavailable provider, query errors, malformed labels and successes remain distinct. Focused validation passed `23 tests, 20 subtests`; the full suite passed `556 tests, 148497 subtests`; the public harness passed; corrected independent review returned **ACCEPT**. See `evidence/update-source-runtime-policy.md`.

## Inner FUMO authentication-coverage checkpoint — 2026-11-03

- V-032 binds exact embedded FUMO SHA-256 `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`, Build ID `863a8730e66a1c5245a1bf458fe2554adee0351a`, startup argument flow, verifier `[0x45820,0x45d75)`, file-MD5 helper `[0x140f50,0x1413e4)`, and worker relaunch `[0x6c9a0,0x6cab5)`.
- Whole-`.text` scans find exactly six direct verifier calls (`0x7be3a,0x80095,0x802f0,0x9d1d2,0x100bb0,0x140092`) and two direct file-MD5 calls (`0x1432f6,0x15170c`). Fixed/enumerated operands cover the descriptor, archive, firmware entries, resources, or navigation files. Parameterized verifier operands are not fully classified: `0x100bb0` receives its target through `%rdx`, and direct caller `0x16e030` forwards a QString from a meta-call argument structure.
- Startup reduces `argv[0]` to a resource base directory, and the worker `execv` wrapper has no direct pre-exec verifier/hash step inside that FDE. The direct call-instruction inventory is complete, but outer-executable reauthentication remains unknown because parameterized target producers, indirect/virtual calls, external helpers/services, and loader/boot checks are unresolved. Final payload binding, runtime mutability, changed-object observation, successful launch, update acceptance, partition writes, slot/boot acceptance, root and persistence also remain unresolved.
- Added exact retained assembly, `evidence/appfumo-authentication-coverage.md`, and a thirteen-input schema-v2 model. Focused validation passed `10 tests, 8203 subtests`; the full suite passed `553 tests, 148482 subtests`; the public harness passed; corrected independent review returned **ACCEPT**. No updater, verifier, helper, target path, launch request, package, partition, slot, boot state, or target syscall was exercised.

## AppDMClient source-identity checkpoint — 2026-11-03

- V-031 records an exact caller-side pathname-reopen boundary in recovered AppDMClient. Verifier wrapper `[0x34870,0x34d43)` returns integer status only; staging verifies AppUpgrade/XML at `0x802db`/`0x80320` and later executes a pathname copy at `0x8296b`; the XML reader verifies at `0xe1ff7` and separately opens at `0xe22d5` or `0xe281f`.
- No retained open description, inode/device comparison, or identity revalidation binds those later consumers to the object examined by the earlier verifier. This proves static TOCTOU structure, not runtime substitution.
- Runtime source mutability/immutability, an actual object mismatch, successful staging/launch, effective indirect/external authentication, update acceptance, partition writes, slot switching, boot acceptance, root and persistence remain unobserved.
- Added retained exact assembly, `evidence/appdmclient-source-identity-boundary.md`, and an eleven-input schema-v2 Boolean model. The pre-recorded state reports the static boundary and conditional launch structure while runtime feasibility remains `null`. Focused validation passed `9 tests, 2056 subtests`; the full suite passed `543 tests, 140279 subtests`; the public harness passed. Independent corrected package review returned **ACCEPT**. No updater, source path, race, launch request, target execution, package, partition, or slot was exercised.

## exec argument-stack cap checkpoint — 2026-11-03

- CVE-2018-14634's oversized argument-space prerequisite is rejected for exact recovered `vmlinux` by preventive cap effects matching upstream `da029c11e6b12f321f36dac8771e833b65cec962`; the stripped binary does not establish commit provenance.
- Complete exact `copy_strings [0xffffffff811161be,0xffffffff811164b0)` retains the historical `ARG_MAX` allowance and accepts larger space only when it is no greater than `min(rlimit(RLIMIT_STACK)/4, 0x600000)`. Oversize space passes the acquired page to exact `put_page` and returns through `-E2BIG`.
- `CONFIG_MMU=y` and `CONFIG_BINFMT_ELF=y` establish static support, not privileged-executable presence, runtime uid/SMACK/seccomp policy, large-vector construction, execution, stack corruption, or installed identity.
- The eleven-input schema-v2 model leaves incomplete construction/cap facts unknown absent an explicit unbounded path. No recovered-kernel exec syscall, target process, oversized target argument/environment vector, privileged target executable execution, target execution, crash, or privilege action was created; ordinary host validation used Python subprocesses outside those target claims. Focused validation passed `8 tests, 2062 subtests`; the full suite passed `534 tests, 138223 subtests`, and the public harness passed with `pass=3 info=4 pending=0 blocked=0 fail=0`. Independent exact-binary review returned **REJECTED-BY-FIX-EFFECTS** and final corrected package review returned **ACCEPT**.

## associative-array leaf-guard checkpoint — 2026-11-03

- CVE-2016-7914 is rejected for exact recovered `vmlinux` by leaf-guard effects matching upstream `8d4a2ec1e0b41b0cf9a0c5cd4511da7f8e4f3de2`; the stripped binary cannot establish commit provenance.
- Exact `assoc_array_insert [0xffffffff8121379b,0xffffffff812140ee)` loads each terminal-node slot, handles null, tests tag bit zero, and branches metadata-tagged node/shortcut pointers past the `ops->compare_object` callback at `0xffffffff812138b7`. Only a non-null leaf-tag fallthrough reaches the callback, and the loop covers all 16 slots.
- `CONFIG_KEYS=y`; exact `__key_link_begin [0xffffffff811b428f,0xffffffff811b437a)` passes `keyring_assoc_array_ops` and directly calls `assoc_array_insert`. This proves compiled reachability, not runtime key policy, attacker-controlled tree shape, callback execution, disclosure, crash, or installed identity.
- The nine-input schema-v2 model leaves incomplete guard facts unknown absent an explicit nonleaf callback path. No target/key syscall, key/keyring state, associative-array mutation, target execution, crash, or privilege action was created. Focused validation passed `8 tests, 524 subtests`; the full suite passed `526 tests, 136161 subtests`, and the public harness passed with `pass=3 info=4 pending=0 blocked=0 fail=0`. Independent exact-binary review returned **REJECTED-BY-FIX-EFFECTS** and final package review returned **ACCEPT**.

## ioprio task-lock checkpoint — 2026-11-03

- CVE-2016-7911 is rejected for exact recovered `vmlinux` by same-lock effects matching upstream `8ba8682107ee2ca3347354e018865d8e1967c5f4`; the stripped binary does not establish commit provenance.
- Exact `get_task_ioprio [0xffffffff811f5e7b,0xffffffff811f5ec0)` locks `task +0x630`, then reads `task->io_context +0x678` and `io_context->ioprio +0x12`, and unlocks afterward. Exact `exit_io_context [0xffffffff811eab51,0xffffffff811eab95)` uses the same lock while loading/clearing the pointer and releases the object only after unlock.
- Complete `SyS_ioprio_get [0xffffffff811f616a,0xffffffff811f6371)` contains three direct getter calls. This proves static caller binding, not runtime syscall policy, task permissions, concurrency, or installed identity.
- The eight-input schema-v2 model leaves incomplete fix facts unknown absent an explicit unlocked-read fact. No target or ioprio syscall, task, thread, race, allocation pressure, crash, or target execution was created. Focused validation passed `8 tests, 267 subtests`; the full suite passed `518 tests, 135637 subtests`, and the public harness passed with `pass=3 info=4 pending=0 blocked=0 fail=0`. Independent review returned **ACCEPT** after correction and re-review.

## block seq-iterator lifetime checkpoint — 2026-11-03

- CVE-2016-7910 is rejected for exact recovered `vmlinux` by the same cleanup-side compiled effect as upstream `77da160530dd1dc94f6ae15a981f24e5f0021e84`. The stripped binary cannot distinguish a direct cherry-pick, the stable backport, or an independently applied identical source change.
- Complete exact ranges are `disk_seqf_next [0xffffffff811f2c92,0xffffffff811f2cb4)`, `disk_seqf_start [0xffffffff811f2cb4,0xffffffff811f2d26)`, and `disk_seqf_stop [0xffffffff811f2d26,0xffffffff811f2d56)`. Successful start stores the iterator at `seq_file.private +0x78`; allocation failure skips that store.
- Stop loads the same field, calls exact `class_dev_iter_exit` and `kfree` on the iterator, then executes a pointer-width zero store to `+0x78` before return. A later failed start followed by framework stop therefore sees null rather than the freed iterator.
- Both exact operation tables use this stop routine; `/proc/partitions` reaches the shared start through `show_partition_start`, while `/proc/diskstats` uses it directly. `CONFIG_BLOCK=y` and `CONFIG_PROC_FS=y` establish static availability, not installed runtime access.
- The eight-input schema-v2 model is tri-state where needed: incomplete fix facts leave retention unknown unless a freed-pointer-retained fact is explicitly supplied. Installed identity, proc visibility, allocation failure, stale use, repeated free, crash, corruption, root and persistence remain unobserved; no proc entry, allocation pressure, or target code was exercised. Independent review **ACCEPT**; focused validation `10 passed, 267 subtests`; complete validation `510 passed, 135370 subtests`; public harness **PASS**.

## netlink dump ownership checkpoint — 2026-11-03

- CVE-2016-9806 is rejected for exact recovered `vmlinux` by machine-code effects equivalent to upstream `92964c79b357efd980812c4de5c1fd2ec8bb5520`.
- Complete exact `netlink_dump [0xffffffff814a74f7,0xffffffff814a7741)` captures `cb->module` and `cb->skb` while holding the callback mutex, clears `cb_running`, unlocks, then gives only the saved register values to exact `module_put` and `consume_skb`.
- Post-unlock cleanup does not reload the reusable callback fields, so a new dump cannot redirect this invocation's cleanup to its objects. The old banner is not authoritative: pristine 4.1.27 source has the vulnerable reload order, while this downstream binary has the fix effects.
- The seven-input schema-v2 model is tri-state where needed: incomplete fix facts leave the vulnerable reload premise unknown rather than asserting it. The authoritative recovered map is `work/eu-260128/kallsyms.tsv` (SHA-256 `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`), with the range also checked against the ELF's embedded address vector.
- This rejection is limited to CVE-2016-9806. Installed identity, runtime netlink reachability, concurrency, crash, corruption, privilege and persistence remain unobserved; no socket, request, message, thread or race was created. Independent review **ACCEPT**; focused validation `9 passed, 136 subtests`; complete validation `500 passed, 135103 subtests`; public harness **PASS**.

## perf move-group race checkpoint — 2026-11-03

- V-030 records the exact CVE-2017-6001 mechanism in recovered `vmlinux`: the `perf_event_open` software-group-to-hardware-context path loads `group_leader->ctx` before waiting for old/new context mutexes, then removes/migrates through the saved context without a nonzero reference, identity revalidation/retry, or post-lock move-state validation.
- Exact `perf_event_ctx_lock_nested.isra.60` in the same binary independently contains the safe reference → lock → identity check → unlock/drop/retry discipline, but the move-group path neither calls nor inlines it.
- `CONFIG_PERF_EVENTS=y`; the exact initialized `perf_event_paranoid` value is 1. Installed identity, mutable runtime policy, production PMU/event support, successful unprivileged event creation, a winning race, stale/dead-context use, controlled corruption, root and persistence remain unobserved.
- Added complete exact FDE evidence, upstream fix `321027c1fe77f892f4ea07846aeae08cefbbb290`, and a nine-input Boolean-only model with an exhaustive 512-state truth table. No syscall, event, thread, race or target execution was performed.

## AF_PACKET frame-count residual checkpoint — 2026-11-03

- Closed the formerly unresolved V1/V2 consequence of the absent `frames_per_block * tp_block_nr` overflow guard. Exact allocation uses the full block count; every logical position bounded by wrapped `frame_max` still yields a vector index below that count and an in-block offset below block size, including wrapped frame count zero.
- Exact RX, TX, poll, readiness, and progression consumers are retained. The separate 32-bit mmap page-count multiplication can understate expected VMA size, but exact `vm_insert_page` rejects addresses at/above `vm_end`.
- Three syntactic signed vector-index edges begin at block count `0x80000001`, but the minimum vector is `0x400000008` bytes and exact `__get_order` yields order 23. Exact `__rmqueue`/`__alloc_pages_nodemask` reject every order above 10, so `__kmalloc` returns null before block allocation, cleanup, publication, or mmap. These edges are predicate-infeasible.
- The missing guard is now classified as a correctness/early-rejection gap, not a defensible frame-lookup corruption/root primitive. Independent review **ACCEPT**; focused validation `11 passed, 23 subtests`; complete validation `483 passed, 134451 subtests`; public harness **PASS**.

## Keystore status gates and boot-manifest parser checkpoint — 2026-11-02

- `CONFIG_KEYSTORE_SECURE_BOOT_IGNORE=y` removes platform secure-boot-status prerequisites from exact `keystore_init` and `keystore_register`; it does not remove the separate manifest initcall or `verify_oem_signature → SHA-256 → manifest_key_verify_digest` chain.
- Matching Intel-authored public source at vendor commit `0c9640bba6a841f524f5947d0741386792674577` confirms Kconfig intent and that the full command-line spelling is `ABL.oemkm=<size>@<physical-address>`. The target differs in registration logging/helper ABI, so exact binary evidence remains authoritative.
- The manifest parser accepts copied size `1..0x4000000`, conditionally reads header/extension data without binding the internal length to that copy, and can reach an OOB read within its 101-entry/16-bit-stride cap.
- A parse-error path overwrites the allocation pointer with `base + 0x24` and later passes that interior cursor to `kfree`, creating a conditional boot-time invalid-free/crash-or-corruption candidate. Runtime control of the loader parameter and physical-memory blob, controlled corruption, code execution, first root, boot acceptance, and persistence remain unproved.
- `keystore_init` also mishandles class/device `ERR_PTR` failures as non-NULL and can return false success; this is weak state handling, not a demonstrated privilege route.
- Independent review **ACCEPT**. Focused validation: `13 passed, 2084 subtests`; complete validation: `472 passed, 134428 subtests`; public harness **PASS**.

## GStreamer FLIC backport checkpoint — 2026-11-02

- Rejected the CVE-2016-9634/9635/9636/9808 FLIC write-bounds family and CVE-2016-9807's `flx_decode_chunks` invalid-read mechanism for exact recovered `libgstflxdec.so` despite embedded GStreamer `1.8.3-r0` metadata.
- Both complete affected FDEs contain the later comprehensive GstByteReader/GstByteWriter rewrite: bounded frame/chunk sub-readers, frame-sized output writer, checked FLI/FLC cumulative positions, checked reads/writes, and helper failure propagation to `GST_FLOW_ERROR` before publication.
- The invalid-read result remains distinct from write corruption even though the same comprehensive rewrite fixes both. Independent review of the CVE-2016-9807 extension returned **ACCEPT**; original family review was accepted in commit `6ff6452`.

## GStreamer VMNC backport checkpoint — 2026-11-02

- CVE-2016-9445 and CVE-2016-9446 are rejected for exact recovered `libgstvmnc.so` even though its embedded recipe path says GStreamer `1.8.3-r0`.
- The complete packet-parser FDE binds WMVi width/height to unsigned 16-bit fields. Every feasible WMVi route checks each against 16384 before the handler; a syntactic bypass edge is predicate-infeasible because it requires the earlier WMVi comparison to be false while `%edi` remains unchanged. Either oversized dimension returns `-1`.
- The handler accepts only 8/16/32-bit depth, assigns bytes-per-pixel as 1/2/4, copies the guarded rectangle dimensions into the allocation fields, and calls `g_malloc0`; the maximum accepted product is `0x40000000`. Both effects of upstream commit `4cb1bcf1422bbcd79c0f683edb7ee85e3f7a31fe` are present.
- Added exact evidence and a bounded deterministic model. This rejects only these two mechanisms; it does not establish general VMNC/media safety or production invocation.

## IPv6 append-data bounds checkpoint — 2026-11-01

- V-029 records exact CVE-2017-9242 pre-fix ordering with `CONFIG_IPV6=y`: `udpv6_sendmsg` reaches the append wrapper and complete `__ip6_append_data` allocates/copies before calculating and rejecting negative remaining copy.
- The later `-EINVAL`/`kfree_skb` cleanup cannot prevent any overwrite caused by the earlier `skb_copy_and_csum_bits` call. Branch-complete review found no equivalent of upstream early-reject commit `232cd35d0804cc241eb887bb8d4d9b3b9881c64a`.
- This is an exact local kernel OOB-write candidate, not root. Required internal skb/fraggap state, actual overwrite, crash, controlled corruption, code execution, privilege gain and persistence remain unobserved.
- Added authoritative, selected and branch-complete evidence plus a six-input Boolean-only model and 64-state tests. Focused validation passed `7 tests, 77 subtests`; independent semantic/model review returned **ACCEPT**.

## Inotify rename-race checkpoint — 2026-11-01

- CVE-2017-7533 is rejected for the exact recovered kernel despite the `4.1.27-abl` banner and `CONFIG_INOTIFY_USER=y`.
- Exact `__fsnotify_parent` and `vfs_rename` take stable dentry-name snapshots before notification; inline names are copied under the dentry lock, external names retain an owner reference, and release occurs after use. These are the effects of upstream fix `49d31c2f389acfe83417083e1208422b4091cd9e`.
- Exact `inotify_handle_event` still has separate length and copy operations, but the reviewed producers no longer pass the concurrently mutable name required by this CVE. The rejection does not generalize to unrelated fsnotify defects.
- Added reviewed evidence, the authoritative patch, a seven-input Boolean-only model and a complete 128-state truth table. Focused validation passed `7 tests, 142 subtests`; independent semantic/model review returned **ACCEPT**.

## AppLauncher on-demand launch checkpoint — 2026-11-01

- **V-028 overturns the just-recorded V-009 negative.** Exact Request adaptor and relocation evidence shows exported `launch(appid, appname, applocation, ...)` methods pass the caller's runtime path to dispatcher `[0x1ffd0,0x205b3)`. It overwrites AppProcess program field `+0x58`, sets direct-launch byte `+0x1c`, and reaches a `QProcess::start` call site without either identified verifier call. A literal scan of fixed `/navi` paths could not exclude this QString input.
- The correction is two-sided: both exact verifier branches treat false as terminal. The defect is the separate on-demand dispatcher, not fail-open behavior after either verifier returns false.
- The recovered session bus uses EXTERNAL and defaults to the daemon's uid because it has no user connection rule. This is not arbitrary cross-uid access. It is a plausible same-uid/SMACK-domain amplification route for the many configured uid-zero HMI processes only if service ownership, Request-object registration, bus authentication, effective labels, a relevant AppProcess object, QProcess acceptance, exec-time target control/access and effective launcher privilege hold at runtime.
- Added `evidence/applauncher-dbus-launch-bypass.md`, a reviewed instruction/configuration excerpt, Boolean-only model, complete 131,072-state tests, and passive metadata for `Dbuslaunch.service` plus `/tmp/session_appmgr`. No D-Bus request, executable, target launch, credential/label transition, anchor write, update or persistence action was created.

## AppUpgrade routing and trust checkpoint — 2026-11-01

- Recovered `AppUpgrade` is an outer Qt wrapper with exact embedded SCOMO and
  FUMO ELF extents. `tools/uk_fw/embedded_elf.py` now extracts only structural
  extents and keeps outer offsets, embedded offsets, and child VAs separate.
- Exact case-sensitive `-un:1` selects SCOMO; `-un:0` or no `-un:1` selects
  FUMO. The wrapper forwards all arguments except `argv[0]`, starts the child
  asynchronously, ignores setup/child status, and normally returns `1`.
- AppLauncher's dynamic app-ID-300 path is not argumentless: it invokes the
  normal vehicle/model option builder and passes the resulting list to
  `QProcess::start`. The recovered embedded NE/EUR row contains `-un:0`.
  Exact `-un:1` plus app ID 311 conditionally substitutes AppScomoDM for
  AppDMClient.
- FUMO's encryption-mode byte starts at `1`; marker existence at startup changes
  it to `0` and logs `Unencryption Update`. Recovered SCOMO
  MASS_PRODUCT/PENETRATION startup explicitly ignores the marker. This closes
  route selection, not package acceptance: version/model, signature/digest,
  payload write, slot selection, boot trust, health, and mark-good remain
  separate unresolved boundaries.
- Exact AppSetup is only an app-ID-300 initiator. The SCOMO USB owner is
  resolved: AppScomoDM selects a `S5W_SYSTEM_*_*_*.zip`, extracts `AppUpgrade`
  and `.lge.upgrade.xml`, verifies both through a fixed public-key-backed helper,
  decrypts only AppUpgrade on this route, performs a basic ELF/executable check,
  and requests app ID 300.
- The separate FUMO/AppDMClient descriptor path is now partially resolved. It
  reads `<source>/.lge.upgrade.xml`, accepts direct `version` text under
  `lhavn`/`wideavn`, and requires a strict current-version upgrade plus an
  equality-allowed second reference. On the unequal source/destination branch,
  marker absence requires retained AppUpgrade/XML verifier results `0/0` and
  marker presence requires `-404/-404`; exact linked code identifies `-404` as
  no recognized fixed-size `TER`/`TE2` trailer, not successful verification.
  An equal pre-staged path skips both
  checks. Caller reconstruction now proves that path is an intended local
  relaunch: `slotUsbMounted` stores its path in `this+0x128`, standby status 12
  can use fixed `/update/usb/bin`, and a helper relaunches from that directory
  only when the first line of `/update/force_launch` is exact `run`. The inner
  FUMO progress handler attempts that pair in system/firmware progress-zero
  branches after attempting `processing`; the branch-local progress-100 sequence
  attempts `complete` and force value `none`, but later scheduled flow can
  attempt `run` again. The weak writer does not prove successful or atomic
  transitions. Some events are traced through exact `DeltaUpdateProgressHandler`
  routes, so `force_launch=run` alone does not establish completion or
  authentication in the traced write-site evidence. Direct USB control
  of the local staging directory, authentication of the upstream progress
  event, and source stability across separate opens remain unresolved. Reviewed USB
  calls disable one section-zero vehicle comparison, but P5-family and later
  AppUpgrade `car-variant`/target checks remain. See
  `evidence/appdmclient-fumo-usb-eligibility.md`. Numeric-only tool
  `tools/uk_fw/appdmclient_fumo_gate_model.py` models the exact trailer and
  retained-result gates without reading or creating update material.
- Inner-FUMO navigation-map signature handling is now named. Gate `0x128070`
  skips its asynchronous NUA verifier for a dedicated local marker, missing
  NaviUpdateApp/NUA provider, no map candidate, or encryption-mode byte zero. The
  last condition proves `/update/disableEncryptionUpdate` indirectly selects
  this one non-encrypted signature skip after setting the startup mode byte.
  Verification start/result failures stop through `0x127e80`; success sets
  `this+0xd5` and re-enters the gate. This corrects an earlier unresolved data
  flow but does not establish universal package-signature or payload acceptance.
  Added numeric-only `tools/uk_fw/fumo_navi_signature_gate_model.py` and passive
  capture of the dedicated marker.
- **V-020 added and independently corrected:** stock `/usr/bin/unzip` resolves
  to BusyBox SHA-256 `95bab633...bd9ebc`, version 1.23.2. It accepts method 8,
  rejects method 12, and retains CVE-2015-9261's pre-fix `huft_build` `v+n`
  bound before AppScomoDM's two verifier calls. The 1.35.0 BusyBox under the
  current integrated tree is a VM-injected helper and is excluded. The strongest
  supported impact is likely `unzip` child crash/update DoS, not a memory write,
  RCE, root, signature bypass, or accepted update. See
  `evidence/busybox-unzip-cve-2015-9261.md` and
  `tools/uk_fw/busybox_huft_bounds_model.py`.
- No recovered updater/helper was run; no archive or compressed stream was
  created; no package, marker, partition, slot, or VM filesystem was modified.
  See `evidence/appupgrade-update-trust.md`,
  `evidence/appdmclient-fumo-usb-eligibility.md`,
  `docs/agent-work/appupgrade-update-trust/CHECKPOINT.md`, and
  `docs/agent-work/busybox-unzip-bounds/CHECKPOINT.md`.

## Disconnected-bench tooling checkpoint — 2026-11-01

- Added `tools/uk_fw/bench_state_bundle.py`, which emits a reviewable POSIX-shell
  probe that writes only to stdout and parses its serial/console transcript
  offline. It does not mount, start services, alter radios, contact peers,
  signal processes, or write target storage.
- The capture closes the first-evidence gaps shared by V-015 through V-019 and
  the inert Dropbear review: installed hashes, process uid/gid and effective
  SMACK labels, unit state/markers, listeners/interfaces, passive Wi-Fi/P2P
  state, oFono devices, local Bluetooth SDP/profile state, Dropbear-chain files,
  and A/B/update flags. It now also captures the FUMO relaunch lifecycle
  (`force_launch` and completion markers), `/update/sysroot`,
  `/update/usb/upgrade`, `/update/usb/bin`, and hashes/metadata for staged
  AppUpgrade/XML and `/tmp/AppUpgrade`. Missing commands/files remain explicit;
  unreadable files and failed reads, metadata queries, commands, or malformed
  hash output set a nonzero terminal status so the parser fails closed instead
  of returning a complete verdict.
- The generated script is audited for target-write/active-operation commands and
  checked with `sh -n` before emission. Synthetic tests cover timestamps,
  duplicate/incomplete sections, fact derivation, adversarial transcript text,
  CLI mode, and the safety audit. No device, network, radio, modem, or recovered
  target binary was used.
- Added `tools/uk_fw/bench_candidate_triage.py` to classify only completed
  passive reports for V-024 through V-026. The producer now captures
  `/dev/pts/ptmx` and device major/minor identity. PTY confirmation requires an
  effective major-5/minor-2 endpoint, permissions, directory, and devpts mount;
  AF_UNIX module-name state remains explicitly unbound from the current file
  hash. The triage does not establish a race, UAF, corruption, root, or exact
  installed-kernel identity. See
  `docs/agent-work/bench-candidate-triage/CHECKPOINT.md`.
- Hardened `tools/uk_fw/rootfs_patch.py`: archive extraction now rejects absolute
  and parent-traversal paths, duplicates, links, FIFOs/device nodes, unsafe
  injection destinations, and in-place package/manifest overwrite. This protects
  the offline custom-firmware build path but does not solve update acceptance.
- Fable delegation remains unavailable: its catalog entry is not advertised for
  native subagents. DeepSeek Flash remains static-ready, but native dispatch
  rejected the configured model identifier; no route was substituted and no
  private target details were delegated. Generic public-only Astra child
  `6c49c736-1356-475d-8773-8cfd1e1fd4f0` supplied the AF_PACKET proof plan; the
  exact V1/V2 trace is now complete and independently accepted. Earlier generic
  children cover public update-system evidence and passive bench-collector design.

## Filesystem/parser and kernel checkpoint — 2026-11-01

- Added `tools/uk_fw/tuxera_fs_probe.py`, an offline, snapshot-backed, read-only
  harness for exact vendor `tntfs`/`texfat` modules. It rejects path/rootfs
  alias hazards, uses QEMU `readonly=on`, mounts only with
  `ro,nodev,nosuid,noexec`, bounds enumeration, and retains JSON results.
- QEMU xHCI triggers a vendor `xhci_toggle_dis_perr_det()` compatibility fault;
  EHCI plus authentic `ehci-pci` is stable. This is a VM compatibility issue,
  not a production finding.
- Authentic Tuxera exFAT `3016.6.23.3` accepted a clean 64 MiB exFAT control.
  Sixteen upstream malformed exfatprogs fixtures produced three clean rejects
  and thirteen clean bounded mounts; no kernel parser fault was observed. This
  is a small corpus negative result, not a broad safety claim.
- Exact vendor-binary review rejects seven version-derived local-root premises
  for recovered EU `260128`: CVE-2016-0728, Dirty COW/CVE-2016-5195, the
  AF_PACKET races CVE-2016-8655 and CVE-2017-1000111, CVE-2017-7308's
  published private-area primitive, ALSA PCM CVE-2017-0861, and the generic
  Stack Clash missing-gap premise. The shipped code contains the relevant
  keyring reference release, `FOLL_COW`, socket locking, 64-bit
  `tp_sizeof_priv` arithmetic, PCM open mutex, and 1 MiB inter-VMA guard-gap
  backports despite its `4.1.27-abl` banner. Three more unprivileged built-in
  candidates are rejected: CVE-2015-7613's SysV state is initialized before
  publication, CVE-2016-7117's delayed socket error is stored before
  `fput_light`, and CVE-2017-8890's cloned child clears the multicast-list field
  used by teardown. See `evidence/vendor-kernel-socket-ipc-backports.md` and
  boolean-only `tools/uk_fw/kernel_backport_matrix.py`. Physical USB-MIDI
  CVE-2016-2384 is also rejected: `CONFIG_SND_USB_AUDIO=m` and both modules
  exist, but exact endpoint failures after raw-MIDI ownership transfer return
  without the second direct object free. Exact `snd-seq.ko` rejects
  CVE-2016-2544; exact `snd-timer.ko` rejects CVE-2016-2545 through
  CVE-2016-2548; and CVE-2016-2549's hrtimer provider is absent. The same timer
  module fixes CVE-2016-4569 and one CVE-2016-4578 callback but retains V-021:
  `snd_timer_user_tinterrupt` queues and returns two untouched four-byte ABI
  padding regions. This is a conditional local information disclosure, not
  root; module load, node/SMACK access, provider/event generation, and observed
  bytes remain unknown. See `evidence/vendor-kernel-alsa-timer-backports.md`
  and `evidence/vendor-kernel-alsa-timer-follow-up.md`. V-022 is a stronger
  remaining local-root candidate: exact `vmlinux` retains CVE-2018-17182's
  32-bit vmacache generations, zero-wrap calls, single-user flush skip, and
  32-bit lookup validation. The generic surface needs no namespace or device,
  but a complete cycle is 2^32 states and no target wrap, stale pointer, UAF,
  corruption, or root transition was executed. See
  `evidence/vendor-kernel-vmacache-cve-2018-17182.md` and Boolean-only
  `tools/uk_fw/vmacache_wrap_model.py`. V-023 is a second exact ordinary-MMU
  candidate: `move_page_tables` transfers PTEs and releases source/destination
  PTLs before the old-range TLB flush at outer exit, matching CVE-2018-18281's
  pre-fix lifetime window. No concurrent invalidation, page release/reuse,
  stale access, corruption, or root is established. See
  `evidence/vendor-kernel-mremap-cve-2018-18281.md`. V-024 retains exact
  CVE-2020-29661 TTY wrong-object locking: a master setter writes the linked
  slave pgrp under the master lock, while the slave setter writes that same
  referenced field under the slave lock. Shipped startup intends world-writable
  `/dev/ptmx`, but runtime exposure, successful concurrency, UAF, and root are
  unobserved. See `evidence/vendor-kernel-tty-pgrp-cve-2020-29661.md`. V-025
  retains exact CVE-2021-0920 semantics in shipped `unix.ko`: both datagram and
  stream MSG_PEEK routes duplicate attached file lists and reach SCM descriptor
  delivery without a barrier on exact `unix_gc_lock`. Module load, GC overlap,
  UAF, corruption, and root remain unobserved. See
  `evidence/vendor-kernel-unix-peek-cve-2021-0920.md`. V-026 retains exact
  CVE-2017-10661 timerfd semantics: membership changes occur outside the only
  global-list lock and no common context lock covers parallel same-file
  transitions. No harmful interleaving, list corruption/UAF, crash, or root is
  established. See `evidence/vendor-kernel-timerfd-cve-2017-10661.md`. V-027
  retains exact CVE-2020-29660 TTY session-lock semantics: `TIOCGSID` reads and
  dereferences the session PID without the control lock/reference while writers
  release before clearing or replacing the same field. The upstream-described
  four-byte read specifically names full preemption, which this voluntary-
  preemption build lacks; no harmful overlap, disclosure, or root is proved.
  See `evidence/vendor-kernel-tty-session-cve-2020-29660.md`.
  CVE-2017-11176 is also rejected by
  exact semantic control flow: `CONFIG_POSIX_MQUEUE=y`, but failed
  lookup after `netlink_attachskb`'s return-one retry enters skb-only cleanup
  rather than detaching the stale socket. The loop has no explicit register
  clear, demonstrating why opcode absence alone is not a backport test. See
  `evidence/vendor-kernel-mq-notify-backport.md` and numeric-only
  `tools/uk_fw/mq_notify_retry_model.py`. The companion AF_PACKET
  `tp_frame_nr` overflow guard is absent, but its V1/V2 consumer trace is now
  closed: allocation uses full block count and wrapped logical positions remain
  within the vector and block. The separate mmap multiplication fails at exact
  VMA insertion bounds. This is a correctness gap, not an established OOB/root
  path; `CAP_NET_RAW`, installed bytes, and runtime allocation remain separate.
- **V-013 added:** exact `snd-seq.ko` lacks CVE-2017-15265's port use-lock fix.
  A tracked benign diagnostic confirmed numeric uid/gid 65534 can open
  `/dev/snd/seq` and complete one create/delete sequence under the recovered
  `root:root 0644` DAC mode. A bounded race issued 200,000 create and 400,000
  delete attempts without a fault; no UAF, root transition, or code execution
  is claimed. See
  `evidence/alsa-sequencer-cve-2017-15265.md` and
  `tools/uk_fw/alsa_seq_probe.py`.
- ALSA sequencer CVE-2018-1000004 lacks the official Linux 4.1 per-client ioctl
  serialization, but its published sequence requires `write()` while recovered
  intended `/dev/snd/seq` policy is `root:root 0644`. V-013 ioctls working
  through an `O_RDONLY` descriptor therefore do not make that trigger available.
  See `evidence/vendor-kernel-alsa-follow-up-cves.md`.
- Exact IPv4 and IPv6 review confirms pre-fix CVE-2017-1000112 UFO control flow.
  It remains conditional: `CONFIG_USER_NS=n` blocks the published unprivileged
  root setup, production `NETIF_F_UFO` interface features are unknown, and the
  no-NIC VM did not dynamically trigger it. See
  `evidence/vendor-kernel-ufo-cve-2017-1000112.md`.
- A clean 64 MiB NTFS 3.1 control mounted cleanly through exact Tuxera NTFS
  `3016.7.1.2.3`. The V-011 inert-node test is also complete: `tntfs` retained
  character node `1:3`; numeric uid/gid 65534 under SMACK `_` opened it
  read-only without `nodev`, while the `nodev` control returned `EACCES`. Only
  QEMU `/dev/null` was used. This confirms a device-policy bypass primitive, not
  USB-to-root; production opener/SMACK/useful-device reachability remains open.
- Next filesystem work: deterministic copy-on-write exFAT/NTFS mutations and
  production mount-path/SMACK reachability analysis for V-011.

## Security checkpoint — 2026-11-01

- **V-020 added — exact pre-auth removable-update parser defect:** stock BusyBox
  method 8 reaches CVE-2015-9261's pre-fix `huft_build`; `v+n` at `0x4788a`
  permits an uninitialized `v[]` read at `0x47938`, with conditional invalid
  table reads before AppScomoDM authenticates `AppUpgrade` and
  `.lge.upgrade.xml`. Stock method 12 is rejected. Physical route selection,
  effective `PATH`, dynamic target crash, memory write, RCE, SMACK escape, root,
  persistence, package acceptance, and owner applicability remain unknown. See
  `evidence/busybox-unzip-cve-2015-9261.md`.
- **V-015 added — strongest static adjacent-network memory-safety candidate:**
  the recovered RPM Btree identifies `connman-1.29+5w.master.38-r1`, and exact
  shipped instructions confirm CVE-2026-115863 rather than relying on that
  version. `connmand+0x1f150` performs the fixed 1,025-byte DOMAIN_LIST copy and
  unbounded DNS-label cursor/store; exact option-24 dispatch and the connected-
  network RA Managed/Other path are present. The information-request routine
  explicitly requests option 24. The installed service defaults to uid 0,
  intends non-excluded `wlan0`, and restarts on failure. A valid reply still
  needs live transaction/client/server/state agreement. PIE, NX stack, canary,
  and full RELRO are present. No packet, crash, RCE, root transition, or
  installed-device reachability is claimed. See
  `evidence/connman-cve-2026-115863.md`.
- **V-016 added — exact CVE-2023-28488 parser order, but the stack copy is
  fortify-blocked:** ordinary IPv4 startup enters `INIT_SELECTING`, opens the
  `AF_PACKET` L2 listener, and registers the affected callback. The callback
  retains the pre-fix `ip.tot_len - 28` ordering, but exact code calls
  `__memcpy_chk` with object size 628. Every recovered libc implementation
  reviewed branches to `__chk_fail`/`__fortify_fail` before copying an
  underflowed size. A packet-free exhaustive model covered all 43,057,152 length
  pairs. Treat this as conditional adjacent-network ConnMan termination, not a
  stack overwrite, RCE, or root path for recovered `260128`; no packet or
  dynamic abort occurred. See `evidence/connman-cve-2023-28488.md` and
  `tools/uk_fw/connman_length_model.py`.
- **V-017 expanded — exact directional oFono TPDU corruption:** exact
  `ofonod` instructions retain the destination checks fixed by CVE-2023-4232
  through CVE-2023-4235, CVE-2023-2794, and CVE-2024-7547. Incoming vendor-QMI
  calls use `sms_decode(..., FALSE, ...)`; deliver, submit-report, and
  status-report copies complete before the handler's late DELIVER check.
  Deliver-report and command are outgoing-only, but exact local transmit-queue
  and SIM-Toolkit callers use `sms_decode(..., TRUE, ...)`. The expanded
  message-free model exhausts each one-byte length domain and confirms writes
  beyond the `0x128`-byte `sms` object without directly reaching the reviewed
  caller canary. The conditional service defaults to uid 0 with SMACK
  `App::tms`. Activation, byte provenance, dynamic corruption, RCE, SMACK
  escape, unrestricted root, and owner applicability remain unproven. See
  `evidence/ofono-sms-decoder-cves.md`.
- **V-018 added — exact CVE-2024-7537 modem-QMI list bounds:** the exact WMS
  list callback obtains a 16-bit TLV length but never validates it against
  `4 + count*5`. A vendor diagnostic computes the product modulo `2^32`; its
  overflow branch falls through to a four-byte allocation while the loop uses
  the original count. The message-free model proves every count above 13,107
  under-allocates. This is a conditional modem-originated TLV-overread/heap-write
  path, not evidence of direct SMS/base-station control, RCE, or unrestricted
  root. See `evidence/ofono-qmi-message-list-cve-2024-7537.md` and
  `tools/uk_fw/ofono_qmi_list_bounds_model.py`.
- **Two wpa_supplicant P2P candidates rejected by exact code:** recovered
  `/usr/sbin/wpa_supplicant`, SHA-256
  `6ad96a34c09b66c29ed2f9ad7ae73dee8389c81064a30dfd36a1212c52a21212`,
  advertises `v2.5` but contains both reviewed fixes (the CVE-2015-1863 fix
  predates upstream 2.5; CVE-2021-27803 is the later backport).
  `p2p_add_device()` gates every SSID copy on length at most 32
  (CVE-2015-1863), and the Provision
  Discovery Request handler unconditionally re-fetches the peer after
  `p2p_add_device()` (CVE-2021-27803). P2P capability and conditional
  `/tmp/no_unece` launch machinery are present; production find/listen state,
  arguments, interface ownership, SMACK label, and radio delivery remain
  unknown. See `evidence/wpa-supplicant-p2p-cves.md`.
- **Dropbear is inert in recovered `260128`:** the RPM record, socket-fed
  template, public-key installer, and one static root authorized public key
  remain, but `/usr/sbin/dropbear`, `dropbearmulti`, `dropbear.socket`,
  `dropbearkey.service`, the host key, and all enable links are absent. The
  template's `-s` would disable passwords but not root public-key login if the
  missing chain were restored; a bounded recovered-filesystem marker/filename
  search identified no candidate private-key material. Do not infer
  a listener, accepted credential, CVE route, or backdoor from these dormant
  artifacts. See `evidence/dropbear-activation-and-authentication.md`.
- **V-019 added — exact CVE-2017-0782 BNEP bounds in both Bluetooth variants:**
  `BSA0107_00.51.00` and `BSA0107_00.63.00` both read peer-controlled BNEP
  extension/control fields before the field-by-field remaining-length checks
  added by the public fix. PCB 11/12 selects `vbtd-63`; other values select
  `vbtd-51`. The unit is enabled, has a configured uid-0 default, restarts
  always, and recovered policy intends `App::bluetooth` if started. Both profile
  files say `PAN : N/A`, startup calls `BNEP_Init`, and no direct
  `BNEP_Register` reference was
  found, so treat V-019 as dormant pending profile/PSM evidence. Adapter state,
  pairing/authorization, accepted channel, physical delivery, allocation-bound
  OOB, disclosure, RCE, SMACK escape, owner PCB, and installed hash remain unknown.
  No radio or packet was used. See `evidence/broadcom-bsa-bluetooth-cves.md`.
- Added `tools/uk_fw/rpm_nvra_inventory.py`, a strict read-only parser for
  printable Berkeley DB dumps. A compatible project-local Berkeley DB 18.1.40
  dump of the exact `Nvra` index produced 1,679 records; the dump and complete
  inventory remain under ignored `work/`. Package metadata is identity/triage
  evidence, not a vulnerability verdict.
- **V-014 added — strongest static physical root path; benign synthetic activation confirmed:** exact shipped
  `v4l_id` and `scsi_id` instructions contain CVE-2026-40225's pre-fix direct
  property prints. Installed rules import both helpers, tag block devices for
  systemd, and retain generic `REMOVE_CMD` execution. The image also ships
  `debug-shell.service`, configured to start `/bin/sh` as root on `/dev/tty9`
  when `ConditionPathExists=/dev/tty9` passes; the upstream SCSI route can
  inject `SYSTEMD_WANTS` to request that existing unit. A fixed benign offline
  `udevadm test` control confirmed the exact rule engine retains a leading-space
  second `SYSTEMD_WANTS` line as a separate property. A matched VM control then
  used exact `systemd-udevd` and exact PID 1 systemd: only the positive synthetic
  property started an otherwise-unreferenced transient BusyBox marker unit; the
  negative run did not. The installed vulnerable helper rules were masked and no
  pre-existing property-selected unit was requested. A separate control confirmed `/dev/tty9` exists
  as `root:root` mode `0600`, character device `4:9`; it did not start the shell
  service. No malicious-device event, physical root transition, VT9
  interaction, or applicability to the owner's unknown installed build is
  claimed. PID 1's
  banner reports `225`, while embedded build paths say `1_249.3-r0`; exact
  instructions, not either version string, establish pre-fix code. See
  `evidence/systemd-udev-cve-2026-40225.md`.
- Added `tools/uk_fw/privilege_surface.py`, a deterministic read-only extracted-
  rootfs audit tool. Its ignored `260128` report walked 236,552 entries and 102
  service files, finding no host-visible setuid/setgid files, 129 executable
  files with writable extracted metadata (mostly `/navi`, normally mounted
  read-only), zero writable directories, and 46 permissive/non-root udev rule
  assignments. Host file-capability coverage is unavailable and explicitly
  reported, not treated as absence. See
  `evidence/privilege-surface-static-audit.md`.
- **V-006 corrected:** QEMU `usb-mtp` exercised the authentic udev → root
  `usb-automount` → `system()` chain. `ID_SERIAL_SHORT` is reduced to
  `[A-Za-z0-9#+\-.:=@_]`; the old `${IFS}`/separator payload became underscores
  and did not execute. Retain V-006 as unsafe shell construction and possible
  denial of service, not a demonstrated USB-to-root path on `260128`.
- **V-012 service reachability confirmed:** the shipped GStreamer ASF plugin
  `libgstasf.so` (`05e887...f45d`) is dynamically affected by CVE-2026-2920.
  Authentic `gst-discoverer-1.0` exits 139, and the normal uid-0 PlayerEngine
  D-Bus service now reaches the same parser with the corrected nested option
  `{"option":{"mediatype":"audio"}}`. A 32-stream file returns true and
  survives; 33- and 34-stream files return true and terminate PlayerEngine with
  signal 11. This proves manual service reachability and process death in the
  isolated VM, not RCE, automatic USB/indexer invocation, or installed-unit
  reachability.
- QEMU has no soundcard. Stock `alsasink` / `media_mixer` therefore rejects even
  valid WMA. The successful service controls use a disposable VM-only
  `/etc/asound.conf` mapping `pcm.media_mixer` to ALSA `type null`, preserving
  the stock sink factory and device name. Under that environment a `file://` URI
  succeeds while a plain path returns false.
- Exact vendor instructions correct the public-source-only overwrite model:
  `AsfStream` stride is `0xd0`/208, not 200. The 33rd stream zeros the low 32
  bits of `flowcombiner`; the first observed fatal use is
  `gst_flow_combiner_add_pad -> g_queue_push_head+0x1d`, with
  `libgstasf.so+0xb6cc` as the return address.
- Tracked tooling remains `tools/uk_fw/asf_stream_probe.py` plus
  `tests/test_asf_stream_probe.py`. Primary write-up and minimal reviewed
  excerpt: `evidence/gstreamer-cve-2026-2920.md` and
  `evidence/artifacts/media-candidates/playerengine-asf-service-evidence.txt`.
- LightMediaScanner's automatic startup route is now separated from V-012. With
  the 33-stream file under `/media/usb/probe`, authentic startup scanning loaded
  its own direct-I/O `asf.so` metadata plugin, reported `processed=1` and
  `errors=0`, wrote its database, and remained alive. The plugin has no
  GStreamer dependency, and a full session-bus capture showed no PlayerEngine or
  thumbnail call. This is a route-specific negative result, not broad media
  safety evidence.
- **V-012 thumbnail route corrected and narrowed:** exact static analysis now
  maps `MediaBrowser requestThumbnails(as)` to
  `com.lge.thumbnailextractor.service.Start(as)`, then
  `VideoContext → uridecodebin → eligible asfdemux`. The earlier assumption that
  `.wma` `Start` followed the audio/TagLib path was wrong; the audio context is
  for cover art. The route is explicit but request-driven. Exact AppMediaPlayer
  review recovers the generated sync/async methods and vtable slots, but its
  reviewed `BrowserInterface -> MediaModeController` scan-handler bodies do not
  directly dispatch them. `VideoPlaybackModel` emits its inherited
  `BasePlaybackModel::thumbnailChanged` signal to `VideoPlaybackController`; the
  connected slot contains no direct thumbnail request. Bounded VM attempts
  observed neither a delivered `Start` nor `libgstasf` in the thumbnail process.
  This is not automatic USB/UI reachability or a thumbnail crash. Reviewed client
  evidence:
  `evidence/artifacts/media-candidates/appmediaplayer-thumbnail-caller-evidence.txt`.
- Next security work: preserve V-014's remaining physical-helper/port/VT gates
  for a disconnected bench rather than starting the root shell. For V-020,
  passively capture installed BusyBox/AppScomoDM hashes, `unzip` provider,
  effective `PATH`, selected `-un` route, uid, and SMACK label; do not put a
  malformed update archive on the owner unit. For V-015, keep
  the current VM NIC-free and defer even benign RA/DHCPv6 controls until the
  disconnected bench can record the installed binary, interface/IPv6 state, and
  restart/recovery behavior. For V-016, record installed `connmand` and libc
  hashes plus ordinary IPv4/ConnMan ownership before considering a crash-only
  control; exact fortification already closes the reviewed stack-write claim.
  For V-017/V-018, first record installed `ofonod`, unit/marker state,
  uid/SMACK label, modem devices, QMI services, benign SMS reception,
  SIM-Toolkit state, and benign stored-message enumeration; keep any later fault
  control crash-only and disconnected, and do not collapse modem-originated QMI
  metadata into direct radio reachability. For Wi-Fi/P2P, passively capture the
  installed supplicant hash, `/tmp/no_unece`, exact arguments, process label,
  interface ownership, and find/listen state; the two reviewed P2P CVEs are
  already fixed. For V-019, capture PCB selection, patchram, installed `vbtd`,
  adapter/profile/SDP state, bond and authorization policy, process label, and
  restart behavior before any malformed radio control. For Dropbear, passive
  file/unit/socket/listener checks are sufficient unless an owner image differs
  from the inert recovered filesystem. Continue identifying an authentic caller
  of V-012 `requestThumbnails` outside
  the now-reviewed scan/property paths—especially QML-facing ownership and
  indirect virtual/callback dispatch—or playback after indexing, and repair the
  VM-only thumbnail service-registration boundary; analyze allocation/lifetime
  behavior without developing a payload. Keep physical bench tests
  non-destructive until recovery and service restart behavior are validated.

## Breakpoint capability matrix complete — 2026-10-29

Eleven checks, 3.94 s, exit 0. Every capability question EC-02 had deferred is now
measured rather than argued:

| Capability | Result |
| --- | --- |
| execute breakpoint fires at armed address | yes, `DR6.B0` set |
| four slots at once | fire in program order |
| slot replacement | yes |
| `DR4`/`DR5` | rejected, `EIO` |
| `DR6` per-slot bits + clearable | yes (`B0` then `B1`, clear reads back 0) |
| detach with slot armed | tracee **killed by `SIGTRAP`** — disarm is mandatory |
| disarm, verify, detach | safe |
| single step | works |
| **per-thread scoping** | **debug registers are per thread; a sibling re-running the same function is unaffected** |

The last item matters most for the design: observing one main thread is sound and
needs neither thread-group control nor `PTRACE_O_TRACECLONE`.

Not tested: data read/write watchpoints, many-thread behaviour, and the vendor
libEGL observation points themselves.

## Breakpoint behaviour and detach discipline measured — 2026-10-29

Round 2 of the capability probe (`dr_breakpoint_probe.c`, 9 checks, 3.85 s,
exit 0) closed the behaviours round 1 left open.

| Check | Result |
| --- | --- |
| four slots armed (`DR7`=0x455) | fire in program order, correct RIPs, **only if each fired slot is disarmed before resume** |
| slot replacement | slot 0 fired at a second address after reprogramming |
| `DR4`/`DR5` | rejected, `errno` 5 (`EIO`) |
| detach with a slot armed | **tracee killed by `SIGTRAP`** — kernel does not clear `ptrace_bps` |
| disarm, verify readback, detach | tracee completes, exit 0 |

Two consequences worth carrying forward:

- EC-02's **C-09** concern is confirmed, not defensive. Detach alone is unsafe.
- EC-02 fixture **V-03** was wrong: there is no fifth slot reachable through
  `DR4`, so a capacity test cannot use it.

Remaining unexercised: per-TID scoping (one traced thread while a sibling runs the
same code) and `DR6` semantics beyond `B0`. EC-02's specification blockers are
unchanged and remain the gate to EC-03.

## Guest hardware breakpoints proven — 2026-10-29

The load-bearing unknown behind EC-02 is resolved by measurement, not by more
specification: the guest **honours `DR0`/`DR7` execute breakpoints** via ptrace
under QEMU TCG with the measured `4.1.27-abl` kernel.

| Check | Result |
| --- | --- |
| T1 nothing armed | tracee exits 0, no trap |
| T2 `DR0`=target, `DR7.L0` | `DR7` 0x0 -> 0x401; `SIGTRAP` at RIP == armed address `0x1002eb0`; `DR6`=0x1 (B0) |
| T3 restore then continue | tracee exits 0, no re-trap |
| T4 `PTRACE_SINGLESTEP` | RIP advanced `0x10040be` -> `0x10040c1` |

Run cost: **3.64 s**, exit 0, no timeout, synthetic busybox workspace with the
measured kernel and the documented `--sdhci-compat` adaptation.

- Source: `tools/uk_fw/guest/dr_breakpoint_probe.c`
  (`f3244f77cca66c9bac87f207885ac76c9e82af893c949e31216ec4c14e7c29bf`)
- Evidence: `navigation-contract-audit/dr-capability-261029/summary.json`
- Workspace builder: `work/vm/dr-probe-build/build_workspace.py`

**Consequence:** EC-02 was never blocked on capability, only on specification.
The EC-04 fixture that the question was deferred to is cheap and needs no vendor
userspace. Remaining EC-02 blockers are spec defects alone.

**Bounds:** proven on a synthetic tracee at user addresses, not on vendor libEGL
observation points. Four-slot capacity, slot replacement, `DR6` semantics beyond
`B0`, and detach-time teardown of `ptrace_bps` remain unexercised. No vendor
binary was executed and no navigation state is claimed.

## EC-02 blocked by over-specification — 2026-10-29

The EGL copy-measurement work has not advanced to implementation. EC-02, the
non-patching hardware-breakpoint mechanism, has now failed lead review four
times. Attempts so far:

| Round | Outcome |
| --- | --- |
| 1 | REQUEST_CHANGES, findings EC-R01..EC-R10 |
| 2 | Partial: EC-R04/05/06/07/09 outstanding |
| 3 | Redesign to a normative `ec02-state-machine.json`; still REQUEST_CHANGES |
| 4 | Still REQUEST_CHANGES on structural defects |

Round 4 defects were real, not editorial: missing pre-arm and subsequent
revalidation failure edges; no `ST_SEIZE -> ST_STOP0` transition and no initial
interrupt; already-forwarded signals left pending and therefore redeliverable;
budget sums disagreeing with their own declarations plus unreachable maxima; a
detach-error terminal falsely reporting "detached"; classifier row shadowing; and
inconsistent single-step routing.

**Diagnosis: over-specification.** The mechanism report grew from 771 to 1,931
lines and gained a 1,187-line state machine for a bounded diagnostic observer.
Each correction exposes a new edge because edge policy is being authored with no
implementation feedback. A fifth textual round would repeat that failure mode.

**Recommendation (owner decision required):** rescope EC-03 to a minimal
verifiable core — `PTRACE_SEIZE`, the four hardware observation points at
`libEGL+0x16f16` / `+0x16f1e` / `+0x16f89` / resolved libc entry, bounded capture,
restoration, and a host-owned timeout — then let the EC-04 fixtures settle the
remaining edge policy empirically.

EC-03 remains gated. Nothing has been measured: no VM boot, no target execution,
no fixture run, and no EGL behaviour claim. The parallel live workstream remains
the now-corrected V-006 root shell sink and the VM-confirmed V-012 ASF parser crash.

## Parallelism/Council checkpoint — 2026-10-27

The next EGL experiment now has a frozen, Council-accepted **plan**, not an
implemented observer or successful measurement. Astra-high led planning; the
three-seat panel (Astra-high, two independent Sol-medium reviewers) completed
independent and reconciliation rounds. Checker outcome is `COMPLETE` for package
fingerprint `c59ac8a0d4ece96fd8fab5fe8a6795789697c95394d6e548a02dc8484052bbb5`.
Packet SHA-256 is
`528649b5b337fb0b76bafd6cb9b020e572851ec33136c6d0927a5c38a12ef790`;
artifacts are under
`navigation-contract-audit/orchestration/council-egl-plan-v1/`.

Critical correction: `-4` proves neither that the original width was `-1` nor
that width changed during the observed update. Measure pre/post fields, update
outcome, EGL call-site arguments, and actual resolved copy-entry arguments.
Downstream contracts must record the vendor EGL and project Mesa module together,
numerical capture caps, debugger-state restoration, and host-owned VM termination.

EC-01/EC-02 are blocked. Workers must use the direct DeepSeek API provider via
a provider-qualified `deepseek/...` route. The live tool rejects
`deepseek/deepseek-v4.1-flash` as unknown; its OpenCode suggestion is explicitly
forbidden, not a fallback. No DeepSeek work ran and no model was substituted.
Do not implement or launch the authentic VM until a supported direct DeepSeek
route is available or the owner explicitly selects another direct model.
The Parallelism ledger is `orchestration/parallelism-ledger.json`.

The scheduler currently lists the prior `keep going` task as **paused**. Another
update attempt failed because interval schedules reject the `time`/`timezone`
fields required by the exposed update schema. No active heartbeat is claimed.

## Continuation records and operating policy — 2026-10-26

Read `PROJECT-OPERATIONS.md` for the same-chat-only continuation contract and
next bounded task. `Ioniq5-CHANGELOG.md` is editable;
`Ioniq5-HISTORY.md` is append-only and now includes a source-labelled
retrospective backfill through the milestones below. Defensive findings,
validation gaps and remediation tests are tracked separately in
`Ioniq5-VULNERABILITIES.md`.

Owner requested retaining the existing active `keep going` scheduled task;
its prompt update was rejected by scheduler-tool validation. No replacement
schedule or successful same-chat binding is claimed. No new threads were created. Installed DeepSeek routing is only
statically checked. **Delegation correction:** inline `spawn_worker` is exposed
and can select a model without creating a chat thread. A useful DeepSeek dispatch
attempt returned host error `store.runWorkerToolResult is not a function`; no
worker result or runtime routing metadata was obtained. Earlier claims that the
interface did not exist were mistaken. Do not duplicate that unknown-status task
or substitute a child thread; host integration needs repair.
Continuation-setup validation: **168 unit tests pass**; `git diff --check` passes.
No fresh VM run or firmware/image mutation was performed during this setup.

Bounded static continuation: `evidence/navigation-launch-status-contract.md`
records that the saved launch-status function sends literal `5` under a one-shot
gate rather than calculating it from the engine result. Exact strings are now
resolved: launcher `launched(30)` precedes a separate AppNavi
`com.lge.hkmc.avn.appnavi.naviboot.SendNaviBootFail(5)` signal at
`/navigation_map`. Enum semantics and the producer of manager window `0` remain
unresolved. Receiver disassembly now identifies `window` as a separately latched
byte at receiver +0x20, gating downstream status handling. The adjacent vendor
`naviWindoeCreate` path updates it and replays cached status. Next trace its
caller at `0x19108d`, not patch the flag or substitute surface ID 3000. That
caller is now identified as the BG-info path. Latest retained DLT positively
shows AppNavi **FG** delivery, but zero BG-info diagnostic matches; the latch
remains zero. Its pending global initially equals `0xffffffff`, not zero. Next
trace initial configure lifecycle. Original compositor classification is now
recovered: **any positive dimension selects FG; BG requires both dimensions
non-positive**. Therefore changing 1926×753 to 1920×720 would not fix this
branch. Current image compositor and shell modules match recovered originals.
Shell size cache starts 0/0 and suppresses unchanged configure calls, so an
initial zero-size surface does not automatically emit BG. Next compare a retained
positive BG lifecycle against AppNavi hide/unmap behavior; do not synthesize BG
or force the latch. Current-image/path hashes are not historical memory digests.
Constructor wiring now confirms AppNavi's callback is the same Qt object's
`visibleChanged(bool)`. Recovered QtWayland hide code has a conditional null-buffer
commit; the recovered EGL client plugin's virtual discriminator returns 1 and
skips it. Verify guest library/plugin identity and selected backend before
proposing a scoped hide adapter. This is static evidence, not a proven fix.
See the Navigation contract note for addresses, hashed correlation and limits.

## Newly supplied community leads

`evidence/community-chat-leads.md` reconciles the owner's summary of two Linux
channels with existing research. These are attributed chat reports, not newly
validated methods. Most importantly: decryption is not update acceptance;
`CV_E...220721` is an unverified different-model lead, not an IONIQ rollback
candidate; historical download availability is model/region dependent. Native
userspace recovery is already solved here, so physical AppNavi entry is not a VM
prerequisite. Exact xcrypt/updater-format or hardware-contract artifacts would be
more useful than repeating first-entry research.

## Latest bounded stack/caller capture

A new VM-only ptrace observer captured 64 readable stack words at the Camera
fault in a 43.7-second snapshot run, then re-delivered SIGSEGV. It identifies a
real memcpy call in vendor EGL `dri2_wl_swrast_put_image2`. Width-derived stride
is cached before `swrast_update_buffers`, which can change width; captured
stride/count registers are -4. This is a strong ordering/invalid-size lead, not
yet measured memcpy-entry arguments or a completed fix.

Complete archive SHA-256:
`e0884a3c11582ed2b986db28f2673b7fde9297a1871f2633ad13672b2dfdeaae`.
Source: `tools/uk_fw/guest/ptrace_crash_observe.c`; build, run, bounded disassembly
and summary under `navigation-contract-audit/` in the current VM workspace.
Guest negative tests, real fault capture and all 168 repository tests pass; base
image rehashed unchanged. No independent model review was available.

Track as **I-001** in `Ioniq5-VULNERABILITIES.md`: mixed vendor-EGL/project-Mesa
VM compatibility is a material precondition; stock-device exploitability is not
established. Next capture before/after update dimensions and copy-entry arguments,
then design a checked VM adaptation. Do not patch libc or force Navigation state.

## Prior focused core capture

A 44.83-second snapshot-only early-startup experiment captured an 80 KiB AppCamera
ELF core with eight thread-register notes. The faulting vector store writes
**64 bytes below a writable mapping**, confirmed by SIGSEGV/SEGV_MAPERR and core
program headers. Early-client decoration value is verified as `1`. Original
caller/copy length remains unknown; the core stores no fault-thread stack bytes.
This is not yet a vendor vulnerability or a Navigation fix.

Complete archive SHA-256:
`10fbb21b674ab1795c5e2b52d4e04ad47611f8674c4ac5ed43d283322c24987c`.
See `evidence/navigation-launch-status-contract.md` and
`navigation-contract-audit/early-core-summary.json` under the current VM workspace.
Base image rehashed unchanged. Next capture bounded stack/caller context at the
fault rather than repeat the whole failed Navigation sequence.

## Prior negative environment control — 2026-10-27

A single-variable decoration-unset control completed as a harness but failed
before authentic agreement/Navigation: repeated Camera/Standby crashes, no
AppNavi launch, manager 0/0, all screenshots splash. It did not verify child
value `1` or geometry. **Do not adopt the unset change.** It existed only in
snapshot guest `/tmp`; the base image rehashed unchanged. Archive SHA-256:
`648b5d30c169b2e4adaa2e8cf069742fd5b3d779b0ef1d6d7e63fead7f6910e9`.
See `evidence/navigation-launch-status-contract.md` for evidence and gaps.
Do not repeat a full navigation run before diagnosing early-client failure;
keep the original working baseline and separate hide-path investigation intact.

## Prior observational backend run — 2026-10-27

A new snapshot-only run completed without timeout and captured 26 AppNavi process
maps. The original launcher-owned process loads the exact analyzed QtWayland
client and EGL graphics plugin. It also inherits
`QT_WAYLAND_DISABLE_WINDOWDECORATION=1:1` and loads the decoration plugin; parser
impact remains unverified. No hide fix or synthetic notification was applied.

Authentic Home visibly rendered before Navigation, but the manager again followed
`11/11 → 35/11 → 11/11`, with FG delivery and `notifyNaviLaunched[5] window[0]`.
**The final return capture is black**, despite manager state 11/11; this run does
not reproduce visible Home restoration. The older positive Home evidence below
remains valid within its original run. Raw Wayland null-buffer requests were not
captured; setting WAYLAND_DEBUG alone did not establish that coverage.

Complete archive SHA-256:
`6019ec6e42cacce8a41fdc79c7dd9705487efdc0a53b741313e6b5b7aad01d84`.
Artifacts and full evidence: `navigation-contract-audit/` beneath
`work/vm/vendor-userspace-260128/`, and
`evidence/navigation-launch-status-contract.md`.
Base rootfs rehashed unchanged; 168 tests pass. Next capture genuine hide/null-
attach execution without changing behavior, and resolve the duplicated decoration
environment independently. Full Home↔Navigation acceptance remains open.

## Prior Home→Navigation integration finding

A launcher-local `execve` interposer now adds the EGL shim only to the original,
signature-checked `/navi/Bin/AppNavi`; it does not directly start a duplicate
navigation process and does not propagate the preload to other vendor clients.
In the latest completed run, the original AppLauncher-owned PID `908`:

- passed AppLauncher's signature check and remained its registered AppID `30`
  process;
- reached `### Navi Engine Init Success ###` and selected the expected logical
  `Samples: 2` config through the executable-scoped zero-MSAA translation;
- created parent surface `3000` with `AID(AppNavi)` and child surface `4903`;
- stayed alive through all four Navigation observations after the launcher-local
  shim suppressed only AppLauncher's slow-TCG `SIGTERM` liveness action.

Static analysis also identified AppNavi's exact startup deadline. In
`NimoExSLApplicationLinux::onInitializeDone()` at `0x33b48be`, elapsed startup
is compared with `0x59d7` (22,999 ms). If `g_firstTimeHideByWM` is already true
or elapsed time exceeds that threshold, the code invokes
`SendToAppLauncherNaviLaunchedToExcute()`. An exact-build, sentinel-gated,
executable-scoped runtime adaptation changed only that immediate to 180,000 ms
in memory; the signed executable on disk remains unchanged. The latest run
proved the guard and PIE-base calculation: AppNavi logged
`STARTUP_DEADLINE_22999_TO_180000_MS`, completed initialization at 106,464 ms
without taking the timeout branch, created surface `3000`, and only then entered
the launch-status function after the authentic first-window event.

That ordering control did **not** complete Navigation. The launch-status path
still emitted `SendNaviBootFail(5)` and ApplicationManager logged
`notifyNaviLaunched[5] window[0]`; manager state remained current/drawing
`35/11`, and all bounded Navigation captures continued to show authentic Home.
The return request restored manager state `11/11` and visible Home. Thus the
remaining blocker is now narrower than process startup or surface creation:
recover why the launch notification carries status `5` and window `0`, and what
contract advances `APP_NAVI_LOADING` (`35`) to `APP_NAVI` (`30`). Do not patch
or fabricate that callback.

Latest completed evidence:

- runner SHA-256
  `906e734012a9a9cac35aed2e9258674215b407a93cdce9e58024a2f78bf8dd9f`;
- host log SHA-256
  `de9977d671cb203f918d878f939777c1eea330bad90dd2ca0643b6ba57c60021`;
- complete archive SHA-256
  `a0e2100ca5a0eb72426db6179c88a27e34abe5928d8a364ce9f14d0e9bfd52b8`;
- state sequence `11/11 → 35/11 → 11/11`;
- current rootfs SHA-256
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`.

The immediately preceding targeted-preload run is useful partial evidence for
AppLauncher-owned surface creation, but its 570-second host timeout interrupted
the archive stream. It is explicitly retained as partial evidence and must not
be cited as a complete archive.

## Latest standby/input and Home finding

Global two-thread llvmpipe permits the delayed authentic Confirm flow that
softpipe starved. The latest bounded run corroborates the gate semantically and
then reaches visible Home:

- the injected pointer remains focused on authentic `AppStandbyClock`, and its
  transformed coordinate `(822.5625, 658.875)` lies inside the enabled Confirm
  control at `x=471..1179`, `y=621..699`;
- authentic logs show `confirmSkPressed()`, `onPressedButton`, `onReleased`, and
  `HANDLER_CONFIRMSCREEN_BUTTON_CONFIRM_CLICKED`;
- standby status changes from `14` to `12`;
- ApplicationManager explicitly reports
  `is_standby_agree_pressed standbyStatus[12] result[1]`;
- both display-exception checks clear:
  `DisplayExceptionFilter a_nMask[66] ret=[0]` and mask `161` `ret=[0]`;
- the handler's intermediate AppID `35` is now dynamically named
  `APP_NAVI_LOADING`, not an unknown setup/profile application;
- ApplicationManager then selects current AppID `11`, requests
  `requestShow AppId[APP_HOME][11]`, receives the authentic Home response
  `ret[1]`, and later records current and drawing application `11`;
- IVI creates run-specific Home surface `1001`, foregrounds it, and the final
  1920×720 capture visibly shows the authentic Home vehicle/battery/media page.

The immediate D-Bus transition out value remains `255`. It can no longer be
classified as rejection by itself: the same request proceeds asynchronously
through current AppID `11`, Home `ret[1]`, drawing AppID `11`, IVI foreground,
and visible composition. Use the downstream state and response chain, not the
immediate integer alone, to classify the transition.

Two explicit VM compatibility adaptations remain material. First, global
`llvmpipe` with two worker threads lets Qt dispatch the queued gesture. Second,
a bounded 55-second `SIGSTOP` of **ApplicationManager only**, after it has sent
authentic `requestShow(APP_HOME)`, prevents its production four-second liveness
watchdog from killing Home while x86 TCG software rendering creates the first
frame. No alive reply, agreement state, handler invocation, application ID, or
Home frame is fabricated. AppStandbyClock and AppHomeScreen binaries remain
unmodified; observational/sizing QML overlays, the 120-second AppLauncher timer,
and the zero-MSAA AppNavi compatibility copy are still non-production VM
adaptations.

Primary positive evidence:

- runner SHA-256
  `25a2ee9726d160c03b52c8dc3c5a76aaba33dd57d7d4be7ecba6f9b2f34485ae`;
- host log SHA-256
  `2c6c7ed142cb84b7dcc5daf5a9adb01a2e86934c731ae5653efa5d0d80d93b95`;
- evidence archive SHA-256
  `87d81b278f8b1bb20236faedd17dda0493b49b6cfc1e0fd2f1acfe8b8d2c6f5e`;
- visible final Home screenshot SHA-256
  `23ccd6e6002d8bceddac3a64b2c94538cb844cc9aa274b44d18ada876d2cc968`.

The earlier focus, Loader, QtWayland, and RIP-sampling archives remain the
canonical negative controls explaining why softpipe did not dispatch the
button. Their SHA-256 values are respectively `dbede61e…ac28`,
`4140b3b8…f134`, `c72c487b…3b73`, and `73cda7a0…c08`.

This top section supersedes the older 2026-10-21 continuation retained later in
this file for provenance. See `evidence/corrections-log.md` before quoting older
negative conclusions.

## What currently works

| Milestone | Measured result / boundary |
|---|---|
| Vendor kernel | EU package Linux `4.1.27-abl`, x86-64; not Android; one exact-build PCI-table adaptation occurs **in guest RAM** |
| Firmware recovery | Validated native TE2/xcrypt envelope decryption recovered rootfs, GUI, AppNavi, updater and RW-data userspaces from official EU `260128` packages |
| Authentic home HMI | `AppHomeScreen` renders a completed 1920×720 frame through recovered Weston/IVI and project-local Mesa 18 `softpipe`; pointer and touch reach authentic Qt/QML |
| Authentic launcher identity | `AppLauncher 3` launches AppNavi as AppID `30`, path `/navi/navi/Bin/AppNavi`, parent IVI surface `3000` |
| Navigation engine | A bounded authentic EU map parcel/core subset reaches `### Navi Engine Init Success ###` |
| Visible navigation pixels | Isolated AppNavi renders its authentic 836×720 map-widget surface `4903`; a compositor capture shows roads, water, buildings and the vehicle marker |
| Authentic full chain | VM-only `AskSysBootinfo` makes AppLauncher select HMC / vehicle `0x26` / Europe / RHD / 12.3-inch / English. Authentic Confirm advances status to `12`, agreement predicate to true, filter results to zero, and manager current/drawing AppID to Home `11`; run-specific surface `1001` is visibly foregrounded |
| Qt/Wayland environment | Removing the probe's pre-set shell variable fixes `ivi:ivi`; clients load `libivi.so` and report `Using the 'ivi' shell integration` |
| Remaining boundary | Full Home↔Navigation operation is not yet demonstrated. The latest AppLauncher-owned AppNavi reaches engine/EGL success and surfaces `3000`/`4903`, but `notifyNaviLaunched[5] window[0]` leaves manager state at `35/11`; data-bearing micom/CAN and persistence contracts remain incomplete |

The primary visible-navigation capture is:

- run `1792908755653936000`;
- PNG `1920×720`, with the native `836×720` map widget at `(0,0)` and the
  still-black AppNavi parent region to its right;
- SHA-256
  `88e8403d808b6936181465ee512aa9e124b75ccc7dbd625a221e41e75ab8b4cb`;
- evidence manifest:
  `work/vm/vendor-userspace-260128/ivi-link-navi-widget-build/visible-navigation-milestone.json`.

The capture is genuine AppNavi-rendered map content, but it is not a complete
navigation UI. The VM-only IVI helper reconstructs the missing relationship
`3000 -> 4903`, restores child destination `836×720`, and foregrounds parent
`3000`. Without that relationship, surface `4903` had a `1×1` destination or
sat behind the opaque black parent. The 40 pure-white pixels seen in earlier
black captures are the Weston cursor, not navigation content.

The earlier baseline launcher-chain experiment was run `1792936845027660000`.
A narrow, fail-closed VM simulator supplies the exact 35-byte
`com.lge.car.micom` `/Ihu` `AskSysBootinfo` reply and acknowledges only
introspection-confirmed transport methods; it does not fabricate CAN signals.
AppNavi reaches engine success, parent `3000`, and map child `4903`; Home reaches
`SCREEN_STATE: DRAW FINISHED` and surface `1004`. The final screenshot remains
the splash hash `b316a82a…0b9a83`. The later AppNavi `SIGTRAP` is explained by
ApplicationManager spawning `killall -5 AppNavi` after repeated failed liveness
checks, not by an unexplained spontaneous crash. A direct-launch no-`strace`
control (run `1792937492664474000`) reproduces the same kill: AppNavi answers
its initial D-Bus `Peer.Ping` at `/navigation_map`, then leaves eight later
Pings unanswered. Tracing adds latency but is not the sole cause. Full evidence
and boundaries:
`work/vm/vendor-userspace-260128/micom-contract/BOOTINFO-AND-SIM-V2.md`.

The boot-image file remains unchanged. Call the running kernel a
**VM-adapted vendor kernel**, not a complete stock-firmware boot. Synthetic
`ABL.oemkm` / `ABL.seed` inputs initialize keystore and manifest subsystems;
they are not recovered device keys or proof of a trust bypass.

## Current constraints

- User-owned UK 2021 IONIQ 5 Ultimate head unit, disconnected from the vehicle.
  **No physical or network access to it is available.** Its installed firmware
  version remains unconfirmed.
- Prefer existing local EU/AU packages, project-local toolchains and saved
  research. Public source/tool research is allowed, but keep downloads and all
  derived artifacts project-local where tooling permits.
- Keep generated files, VM disks, sockets and test temporaries in this project.
  Do not delete anything outside it; preserve unrelated and pre-existing work.
- No flashing, host-root operations, host filesystem mounts, or substitute
  dashboard presented as the vendor UI.
- Fable was requested as reviewer/planner only. Its tested route was unavailable;
  no substitute child is verified as Fable.
- Unit-test results and evidence hashes are **not Council acceptance**. Do not
  refresh legacy accepted-input hashes to manufacture a pass.

## Current navigation continuation

1. The 11 direct authentic `RES/SKIN` files are now injected. Theme image and
   `SIMPLENIGHT.skn` load successfully. Missing
   `VIT_EUR_3D_LANDMARK.hafmma`, `DEM/VIT_AREA_DATA_HM.cad`,
   `StyleKeyId.sqlite`, and `SymbolCode.sqlite` remain logged, but do not stop
   the first visible map frame.
2. Surface `3000` is AppNavi's 1920×720 Qt parent. Surface `4903` is the
   independently rendered 836×720 `Front_Widget` map surface. Wayland traces
   prove `wl_buffer` attach, full damage, and commit on `wl_surface@17`.
3. The isolated no-`ApplicationManager` run omitted the intended IVI hierarchy.
   `tools/uk_fw/guest/ivi_link_navi_widget.S` reconstructs
   `set_parent_child_surface(3000, 4903)` and the native child destination. It
   is exact-configuration VM infrastructure, not recovered firmware.
4. AppLauncher-first startup now creates the 35-byte `MICOMSTATUSMESSAGE`
   segment and avoids the historical repeated eight-second semaphore timeout.
   A consumer-derived `AskSysBootinfo` profile selects NE/Europe correctly.
   Remaining micom work is the data-bearing query/CAN signal contract, not the
   old semaphore symptom; do not reset or pre-create guessed IPC objects.
5. Binding recovered `/system/new_gui/new2.0/hmc/night` over the incomplete
   legacy image tree removed all 15 named `Failed to load image` messages, but
   produced the exact same screenshot hash. Missing image files are therefore
   not the current cause of the black AppNavi parent region; missing service/UI
   state remains the stronger hypothesis.
6. Do not rename `MAP/VIT_EUR_3D_LANDMARK_ASTC.hafmma` to the missing
   `RES/SKIN/VIT_EUR_3D_LANDMARK.hafmma` without tracing the variant selector.

Current ext4 image SHA-256 after the targeted AppNavi preload and guarded
PIE-aware startup-deadline control:
`4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`.
Every mutation has a copy-on-write checkpoint and `e2fsck -fn` log under
`work/vm/vendor-userspace-260128/`.

## Historical 2026-10-21 VM instructions (superseded for HMI work)

From `/Users/researcher/Documents/ChatGPT/reverse engineering/ioniq research`:

```sh
# Interactive serial research shell
/opt/homebrew/bin/python3.13 tools/uk_fw/vm_boot.py run \
  --workspace work/vm/bootable --sdhci-compat --interactive --timeout 0

# Windowed diagnostic ONLY; R/G/B change colour, Q returns to the shell
/opt/homebrew/bin/python3.13 tools/uk_fw/vm_boot.py run \
  --workspace work/vm/graphics --sdhci-compat \
  --display cocoa --cmd /bin/vm-display --interactive --timeout 0

# Automated keyboard and pixel verification
/opt/homebrew/bin/python3.13 tools/uk_fw/vm_boot.py run \
  --workspace work/vm/graphics --sdhci-compat --graphics-smoke
```

Use `/bin/busybox <applet>` in the minimal shell. Ctrl-C stops the launcher.
QEMU has no NIC, uses a snapshot disk, and exposes only local debug sockets.
Preparation refuses to overwrite existing workspaces. Complete preparation,
controls, exact addresses and hashes: `evidence/vendor-kernel-vm.md`.

The display program bypasses missing framebuffer-driver support by mapping
QEMU VGA PCI resources. **It is not a DRM/EGL/Qt compatibility backend.**
Details and actual screenshots: `evidence/vendor-kernel-graphics.md`.

## Latest local recovery work

Read `evidence/local-ui-recovery.md` and its retained evidence directory.

1. **Boot public-key hypothesis:** all 12 plaintext EU/AU `ipk.` containers
   share one RSA-2048 public key and pass strict signature controls. Scanning
   the first/last 16 KiB of 38 opaque envelopes, at every byte offset and in
   both byte orders, made **2,392,520 RSA attempts and found no valid type-1
   block**. This tests one key, one padding format and recorded edge ranges,
   not every possible wrapped-key location or algorithm.
2. **Installed Mac updater hypothesis:** static inspection of Navigation
   Updater `261.015.0.215` found text/API AES routines and constants. Two
   reconstructed constant pairs were tested against the same 38 files under
   bounded CBC-start/IV hypotheses. Two raw gzip-marker matches were the same
   invalid sample in both packages; reserved flags and zlib rejected them.
   **No validated firmware plaintext was recovered.** Other crypto modes and
   derivations were not exhausted. The updater was not launched or contacted
   online.
3. **Earlier plaintext searches:** full-byte ELF/gzip/tar probing covered
   7,134,873,011 bytes across 14 opaque payloads with no validated candidate.
   Prefixes of 1,571 regular map ZIP members and two distinct plaintext voice
   archives were also inspected. See the graphics evidence for exact bounds.

`new_gui.tar.gz`, `mango-rootfs.tar.gz`, `appnavi.tar` and updater payloads remain
opaque. The publicly saved `DecryptToPIPE` and key files are placeholders.
The older Chimaera work documents a real decryptor/key-file mechanism, but does
not itself establish current-package applicability or supply those artifacts.
High entropy or a failed bounded scan is **not proof of permanent offline
impossibility**.

## Useful local resources

- EU: `/Users/researcher/Downloads/NaU/IONIQ5_EU`, version
  `NE_E.EUR.S5W_L.001.001.260128`, model `101489`.
- AU: `/Users/researcher/Downloads/NaU/2021_22_IONIQ_5_AU`, version
  `NE_E.AUS.S5W_L.001.001.260319`.
- Supported boot container: EU `HU/images/iasImage_1280_sub`, SHA-256
  `55e9a31be5ca734a7af111613ae6ce83cdc579b27138c5f54700f78263056eb0`.
- Kernel, correct symbols and saved Ghidra project: `work/eu-260128/`.
  Use `kallsyms.tsv` / `kallsyms_apply.tsv`, **not** the obsolete mispaired
  `kallsyms_fixed.tsv`. About 70 selected functions were decompiled, not the
  entire kernel.
- Existing static BusyBox: `work/vm/busybox`; QEMU: `/opt/homebrew/bin/qemu-system-x86_64`;
  e2fsprogs and LLVM under `/opt/homebrew/opt/`.
- Harness Python: `/opt/homebrew/bin/python3.13`. Full-test Python:
  `/Users/researcher/.platformio/penv/bin/python3` (includes `cryptography`). Do not
  assume the default Homebrew `python3` works.

```sh
mkdir -p work/test-tmp
TMPDIR="$PWD/work/test-tmp" /Users/researcher/.platformio/penv/bin/python3 \
  -m unittest discover -s tests -p 'test_*.py' -v
```

## Local continuation 2026-10-22: envelope format, module execution, graphics

Verified offline in QEMU against the unmodified vendor kernel `4.1.27-abl`. Artifacts
under `work/ui-recovery/`, `work/kbuild/`, `work/envelope-20261021/`; full runbook in
`work/ui-recovery/SUMMARY-and-runbook.md`. This does **not** unlock the real UI.

- **Envelope format** (all opaque payloads, incl. `iasImage`): `[ciphertext body]
  [0x00][base-255 zero-free footer]`; the footer is package-scoped and decodes to
  uniform ciphertext (no length prefix, not block-aligned). `iasImage` adds a
  14,048-byte (878-block) deterministic prefix. This corrects the earlier
  "3,385 header + payload + 13,035" model (arithmetic, not structure).
- **Boot key inside the envelope:** type-1 public unwrap is a clean negative; type-2
  is the wrong direction (≈1.5e-5 false positives). No offline key.
- **Plaintext resources** (map ZIPs, voice archives) hold map data, fonts, PNGs and
  ASR/TTS models — **no UI/ELF**. `CONFIG_BLK_DEV_INITRD` is unset (no initramfs).
- **Unsigned kernel-module execution works in the stock vendor kernel:** vermagic
  `4.1.27-abl SMP mod_unload`; `MODVERSIONS`/`MODULE_SIG` off. Recipe: build against
  the vendor config, rewrite PLT32→PC32, and shift the `init`/`exit` this_module
  relocations +8 (`struct module` init at 0x130, not 0x128). See
  `work/ui-recovery/SECURITY-FINDING-module-load.md`.
- **Graphics:** a module registers `/dev/dri/card0`, KMS `card0-VGA-1`, **and advertises a
  real 1280x720 mode** with **no Intel GPU** (`drm_mode_probed_add` +
  `drm_mode_connector_list_update`; sysfs iterates `connector->modes` directly, so the
  vendor `funcs->detect` layout mismatch is bypassed). Actual scanout/fbcon still needs
  the vendor's `drm_framebuffer`/CRTC structs.
- **The remaining gate:** the vendor userspace is AES-encrypted in the package; the
  key is `/tmp/<32hex>`, generated on-unit per update by `DecryptToPIPE` (public
  tooling is placeholder-only). On-unit the rootfs/navi are plaintext. Both goals
  (run the real UI; install own apps) need device/rootfs access.

## Historical next useful work (superseded by recovered/decrypted userspace)

- **Acquire the plaintext vendor rootfs or the per-update key.** This is now the
  single blocker for both goals. Any read access unblocks it: an engineering-mode
  shell, an `mmcblk0p3`/`p5` + navi dump, or the `/tmp/<32hex>` `DecryptToPIPE` key.
  Runbook (dump → decrypt → boot; key-capture; module path) is in
  `work/ui-recovery/SUMMARY-and-runbook.md`.
- Until then, do not re-probe envelope crypto or DRM struct offsets offline: those
  paths are exhausted (device-gated), as recorded above.
- If genuine application code is recovered, inventory ELF architecture,
  dynamic loader/libraries, launcher/config, services/IPC and display APIs
  **before** trying to execute it in the research VM.
- Keep serial/graphics controls and prepared-image hashes intact. Earlier
  exFAT/archive/XML parser harness work is secondary to the real-UI goal.

## Repository and evidence discipline

The actual Git root is now **this project directory**. Both current remotes,
`ioniq` and `origin`, point to `https://github.com/JaredReabow/Ioniq-5.git`.
Re-query before future integration; the historical parent/Kona layout is stale.
Stage exact reviewed paths, never all of `work/`. No raw firmware, VM disks,
client key bytes or private-key material belong in this continuation's commit.

Primary current notes: `vendor-kernel-vm.md`, `vendor-kernel-graphics.md`,
`local-ui-recovery.md`. Historical exploit, downgrade, partition-map and
trust-pinning claims require their original scope and current-build validation.
No stock-to-root path, authentic payload decryption, bootloader acceptance of a
self-signed image, or hardware flashing has been demonstrated here.

## Public visibility follow-up — 2026-10-28

The sanitized `main` is `ea3fb24fb3af398963ebf17febbef392bb8bd6c3` on the verified `JaredReabow/Ioniq-5` remote. Current remote tree has no owner USB export, upstream raw dump, or frozen Council packet paths; the repository remains private. GitHub still resolves old raw commits `e98e2c8cd1fe477c735907b12c4c0b25976d19c4` and `692eccd380f3a791d800bb6c0ac6dc621af2585a` by SHA. GitHub Support ticket [#4916475](https://help.github.com/ticket/personal/0/4916475) requests server-side cached-view and object cleanup for both. Once GitHub confirms cleanup, verify both old commit IDs no longer resolve, rerun the public harness and unit suite, recheck the explicit remote tree and visibility, then make this same repository public and read back `PUBLIC`. Preserve the existing uncommitted local research and ignored private raw files; do not merge the old Git history into the sanitized branch.
