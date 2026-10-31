# Checkpoint — bounded exact-static CVE-2018-9568 socket clone creator audit

## Result

**Technical verdict: PASS — `direct_patch_shape`.** The named
CVE-2018-9568 clone allocator/creator mismatch is rejected for the exact
recovered EU `260128` kernel. This is a machine-code effect verdict, not direct
upstream cherry-pick provenance or a general socket/allocator safety claim.

Complete `sk_clone_lock [0xffffffff814787f9,0xffffffff81478abd)` allocates the
child through source current `sk_prot` at `source+0x28`. Its fixed first copy is
only `0x60` bytes. `0xffffffff81478831` binds `%r13 = clone+0x78`;
instructions `0xffffffff81478837..0xffffffff8147883c` set source to
`source+0x78` and move that clone endpoint into `%rdi`;
`0xffffffff8147883f` loads source current protocol `P`;
`0xffffffff81478844` loads dword `[P+0x100]`; and
`0xffffffff8147884a` subtracts `0x78` before the `rep movsb` at
`0xffffffff8147884e`. The copied half-open socket-offset interval is therefore
exactly `[0x78,obj_size)`.

Raw exact protocol data binds the size values independently of names:
`tcp_prot` VA `0xffffffff81ac11e0` has little-endian `80 07 00 00` at
`+0x100` (file `0xcc12e0`), so size is `0x780`; `tcpv6_prot` VA
`0xffffffff81ac6cc0` has `40 08 00 00` at `+0x100` (file `0xcc6dc0`), so size
is `0x840`. The creator qword occupies `[0x1a0,0x1a8)`, or
`[0x128,0x130)` relative to the copy start. Exact copy lengths are
`0x780-0x78 = 0x708` and `0x840-0x78 = 0x7c8`, each greater than `0x130`.
Thus the second copy necessarily copies every creator byte from source to clone
before the direct correction; the stale-creator premise is instruction- and
raw-data-bound rather than inferred from source names.

The decisive sequence is:

```text
0xffffffff8147884e  variable creator-overwriting copy
0xffffffff8147885d  security_sk_clone (final inlined sock_copy operation)
0xffffffff81478862  reload source current sk_prot at +0x28
0xffffffff81478867  store it to child sk_prot_creator at +0x1a0
...
0xffffffff81478a12  only observed in-function post-copy sk_free
```

There is no creator-overwriting copy or child `+0x1a0` store after
`0xffffffff81478867`. The copy ends at `0xffffffff8147884e`; normal control is
linear through the reviewed callback, source reload, and creator store. The
complete function has exactly one post-copy direct `sk_free`, at
`0xffffffff81478a12`. Its filter and policy failure decisions at
`0xffffffff814789f4` and `0xffffffff81478a30` both follow the store and converge
on a block that nulls `%rbx` before freeing. The allocation-null edge precedes
the copy and has no child to free. The sole `ret` is at
`0xffffffff81478abc`, so every non-null successful return passed the reset. The
reset therefore occurs after every creator-overwriting copy, before every
observed in-function post-copy free, and before every successful return. The
intervening `security_sk_clone` indirect hook is also closed:
configured/default static `+0x4c8` slots are null, exact `security_fixup_ops`
fills null slots with complete no-op `cap_sk_clone_security`, and that callback
cannot alter source allocator protocol before the post-copy reload.

Caller cleanup is separate. `inet_csk_clone_lock` tests the `sk_clone_lock`
return at `0xffffffff814d2306..0xffffffff814d230c`;
`tcp_create_openreq_child` tests the wrapper return at
`0xffffffff814e66f4..0xffffffff814e66fa`; and `tcp_v4_syn_recv_sock` tests the
helper return at `0xffffffff814e4f2b..0xffffffff814e4f31`. Its later error
cleanup at `0xffffffff814e50df..0xffffffff814e50e7` can therefore occur only
after a non-null, already-corrected child has returned successfully through
`sk_clone_lock`. It is not an in-function pre-correction free. Deferred
`sock_wfree` ultimately reaches the same creator-based `__sk_free` only after
the corrected child has escaped.

Complete allocator/free code independently binds the invariant:

- `sk_alloc` stores the same protocol to current `+0x28` and creator `+0x1a0`;
- `sk_prot_alloc` selects slab/cache at protocol `+0xf8` and object size at
  `+0x100`;
- `__sk_free` loads creator from socket `+0x1a0` at
  `0xffffffff814784ea`, then slab/cache from creator `+0xf8` at
  `0xffffffff814784f4`.

Complete option-1 `do_ipv6_setsockopt.isra.8` code can rewrite current `+0x28`
to exact `tcp_prot` without rewriting creator `+0x1a0`. The compiled child path
is `tcp_v4_syn_recv_sock -> tcp_create_openreq_child -> inet_csk_clone_lock ->
sk_clone_lock`. The affected architecture is therefore present; the result is a
positive correction, not route absence.

## Exact identity and public contract

- `work/eu-260128/vmlinux` SHA-256:
  `f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b`
- GNU Build ID: `273378887b4cf563c10862fdf18b2292765df781`
- `work/eu-260128/kallsyms.tsv` SHA-256:
  `2cfba917c1c8e7444e393e8d94ebfe367e2ba348be4f35ce10fbb331822e3c1f`
- `work/eu-260128/kernel.config` SHA-256:
  `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`
- configuration: NET, INET, IPV6, SLUB, and SLUB_DEBUG enabled; USER_NS and
  MEMCG_KMEM disabled
- canonical ignored public-reference directory:
  `work/online-kernel-candidates-20261107/cve-2018-9568/`
- mainline commit: `9d538fa60bad4f7b23193c89e843797a1cf71ef3`
- mainline parent: `b32ca44a88def4bf92626d8777494c6f14638c42`
- mainline patch SHA-256:
  `c1f7389124f499cc764ce39a25f841bc701f0d3e8e4ab6a86f3c578941ed085d`
- stable commit: `0a11ea32304f6ad6daf5589b6626775b7f00015c`
- stable parent: `cafd2b53da565ca30c48a146635c95d385d83b81`
- stable patch SHA-256:
  `756c9749346bda510e242b02b849448418196bc1f95684dbcbbf362eff60d8ba`

Both public patch captures in that canonical directory have the required
hashes. Byte-for-byte `cmp` and independent SHA-256 checks also prove the
corresponding ignored 20261102 analysis copies match the canonical files. The
separate `20261102` directory is an analytical/disassembly workspace, not
canonical public-patch provenance. The patches are intentionally not copied
into tracked evidence: each includes the complete operational trigger program,
so tracked retention is not appropriate under this task's non-operational
boundary. Exact canonical directory, commit/parent/hash records, and the
source-level fix contract are retained in the assessment.

All ten supplied decisive raw function hashes independently match. The retained
artifact extends that set to a 25-row raw range/data manifest and includes
complete successor-bounded listings for allocation, immediate/deferred final
free, clone, protocol conversion, IPv6 creation, listen/disconnect, and TCP
child cleanup/clone paths.

## Boolean model

`tools/uk_fw/socket_clone_creator_model.py` is schema v2 with 15 Boolean inputs
and Boolean observational outputs. The five one-hot outcomes are:

- `direct_patch_shape`;
- `equivalent_fix`;
- `vulnerable_semantics`;
- `absent_route`; and
- `indeterminate`.

Route absence and reset absence require separate positive evidence. Conflicting
route present/absent, direct/equivalent correction, correction/reset-absence,
or reset-ordering-without-direct-reset state fails closed to `indeterminate`.
Direct classification requires correction after every creator-overwriting copy,
before every observed in-function post-copy free, no later creator overwrite,
all successful returns after reset, and caller cleanup only after a corrected
return. Equivalent correction has a separately explicit all-cleanup-dominance
input.

Tests exhaust all 32,768 Boolean states and assert every classification and
output field, every missing key, unknown keys, non-Boolean types, every named
classification vector, contradictory states, all-or-none CLI behavior,
duplicate/abbreviated/unknown options, and invalid Boolean tokens. Output is
sorted UTF-8 emitted with `sys.stdout.buffer` and one LF, independent of
`PYTHONIOENCODING`.

Deterministic default report SHA-256:
`aa495e1103098e4926d1996a9bf31c4bdea8b0c3c8a6358f0cb71c6ea60cc1cd`.

## Retained paths and hashes

- `tools/uk_fw/socket_clone_creator_model.py`
  `fba507b867df9022d8fad4c5286f5cb9bb107e8ec3ddc241406d049178982363`
- `tests/test_socket_clone_creator_model.py`
  `6ee1a99a148afe38a6c21319ba08a65a1490cbbb8507f410fedbd7f03f3e0ce6`
- `evidence/vendor-kernel-socket-clone-cve-2018-9568.md`
  `8c10e1bfe28aedd7c1a4f5cbcf44913014e33f2b78d9504fcae63111e35b21be`
- `evidence/artifacts/kernel-candidates/kernel-cve-2018-9568-exact-static.asm`
  `e876c4eddfc08de17ded57371c447a93c44a44031265c34fb5ffa1decb253273`
- `docs/agent-work/socket-clone-creator/PLAN.md`
  `daceaa5f5de9d2898af57ba60f44edbb1875fc8a21a845e2f4fef7b506f92865`
- `evidence/artifacts/kernel-candidates/README.md`
  `ea66ca7cf448c33eb04558f95ea1c028c65ba407114c9764e2e381d48b9e1f38`
- `evidence/exploit-inventory.md`
  `5561dc63c8b37d36aeb8ccf343594ad6a49b33eb3ae5a9d56d897729105f55b8`
- `Ioniq5-VULNERABILITIES.md`
  `8e05ca6549e51d257e8f0c1aacd38edc9c2d2938170fad04f77b87af15d1193c`
- `HANDOVER.md`
  `2dd7d2af0585b16d5d3f6847eac28ee8bd264f7193f5b309ae050b8402888210`
- `Ioniq5-CHANGELOG.md`
  `367ddb05a2d1effd32e84105a10c34bcbd2df7e27dcbda84c1b17a76431d5ee3`

Hashes above were recorded before this checkpoint file was created; its
creation does not alter those files.

## Validation

Required interpreter: the project-approved PlatformIO-environment Python
(`<platformio-env>/bin/python3`). Required ELF tools: the Homebrew LLVM
`llvm-objdump` and `llvm-readelf` binaries.

- `py_compile` for model and focused test: **PASS**.
- Focused pytest: **PASS**, `8 passed, 32,913 subtests passed`.
- Full pytest under `tests`: **PASS**, `645 passed, 351,225 subtests passed`.
- `tests/run_all.py`: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`.
- Exact vmlinux/map/config hashes and ELF Build ID: **PASS**.
- Canonical mainline/stable patch hashes: **PASS**.
- Retained artifact hash: **PASS**.
- Independent raw-byte and fresh LLVM instruction-boundary verification of all
  25 retained manifest rows against the exact ELF: **PASS**, 115 checks.
- Decisive copy/reset/free/address-form instruction review: **PASS**.
- `git diff --check`: **PASS**.
- At pre-delivery validation capture, staged paths: none.

A repository-root `pytest -q` attempt was intentionally not treated as the
practical project suite: pytest descended into ignored third-party trees under
`work/` and stopped during collection with 146 missing-dependency/module-name
errors (hostap `wpaspy`, Python-2 `Queue`, and duplicated archived skill tests).
No project test failed in that attempt. The bounded project suite
`pytest -q tests` passed as recorded above, and `tests/run_all.py` passed.

Implementation ran in the parent-assigned Daybreak child thread
`8047cac6-229d-40d4-9a21-68d9bc7c5b1a`; that child did not delegate further.
After implementation stopped, independent strictly read-only Daybreak reviewer
`6ae2a1fc-cad7-4cd8-95f1-6c5a8790a278` returned **ACCEPT** with no blocking
findings for the current package bytes, evidence bindings, model logic, cleanup
ordering, documentation, deterministic output hash, artifact hash, and retained
file-hash records. Self-review separately re-read the complete
assessment/model/tests, checked class precedence and contradiction handling,
regenerated decisive disassembly with the required LLVM tool, and verified
integrations and missing-path references.

## Workspace integrity note

Task-start baseline was
`78aa695145745370e839e3911338fcb9b6d0fe49`. During implementation, a concurrent
external workspace process created commit
`1d6d30611be2721e78d1ccf53af836039fa2f9c3` (parent `78aa695...`) and included
`HANDOVER.md`, `Ioniq5-CHANGELOG.md`,
`tools/uk_fw/ias_backend_soft/.gitignore`, and the protected unrelated
`tools/uk_fw/ias_backend_soft/micom_service.c`. This audit did not create,
stage, amend, reset, stash, or push that commit. Because reset/checkout and
editing protected residue were forbidden, the audit did not attempt to undo it.
The protected untracked binary remains present and was not executed. A later
concurrent external commit, `517a63c985ce2365c33f73efddcd632921d6789b`
(parent `1d6d306...`), advanced HEAD again while registering unrelated V-036;
this audit likewise did not create, stage, amend, reset, or push it. Current
HEAD is therefore `517a63c...`, not the requested starting HEAD. These are
unresolved external workspace-integrity deviations, not part of the CVE
package.

At checkpoint capture, no audit delivery path was staged and no commit or push
had yet been performed by this audit. Delivery occurs only after acceptance and
is outside this pre-delivery checkpoint snapshot.

## Remaining limits

Installed/running kernel identity, runtime socket policy, actual address-form or
clone route use, boot-time slab addresses, a wrong-cache free, corruption,
crash, disclosure, code execution, privilege escalation, unrestricted root,
SMACK escape, persistence, and owner-device applicability remain unobserved.
The direct fix-shaped machine code does not prove source provenance. General
socket/SLUB safety and every vendor-equivalent defect remain unresolved.

## Self-review verdict

**PASS for the bounded exact-static technical package.** The exact result is
supported, the cleanup ordering is complete and correctly separates
in-function from caller cleanup, the model is exhaustive and fail closed, all
requested practical validation passes, and independent strictly read-only
review returned **ACCEPT**. **Repository-state acceptance is qualified by the
concurrent external HEAD/protected-residue commits described above.**
