# Plan — bounded exact-static CVE-2018-9568 socket clone creator audit

## Objective

Determine whether the exact recovered EU `260128` kernel has the
CVE-2018-9568 socket-clone allocator/creator mismatch or the upstream fix's
machine-code effect. Use host-only ELF, disassembly, configuration, and public
patch review. Do not execute recovered code or perform any socket, clone,
network, malformed-input, trigger, exploit, privilege, or persistence action.

Baseline HEAD at task start is
`78aa695145745370e839e3911338fcb9b6d0fe49`. The pre-existing modified
`tools/uk_fw/ias_backend_soft/micom_service.c` and untracked
`tools/uk_fw/ias_backend_soft/micom-service` are protected unrelated residue:
do not edit, execute, stage, reset, stash, remove, commit, or push them.

## Public contract

1. Capture byte-identical copies under canonical ignored directory
   `work/online-kernel-candidates-20261107/cve-2018-9568/` of mainline commit
   `9d538fa60bad4f7b23193c89e843797a1cf71ef3` (parent
   `b32ca44a88def4bf92626d8777494c6f14638c42`) and stable commit
   `0a11ea32304f6ad6daf5589b6626775b7f00015c` (parent
   `cafd2b53da565ca30c48a146635c95d385d83b81`). The separate `20261102`
   directory is an analytical/disassembly workspace, not canonical patch
   provenance. Do not retain tracked patch copies: both public patch bodies
   contain a complete operational trigger program.
2. Verify their expected SHA-256 values, respectively
   `c1f7389124f499cc764ce39a25f841bc701f0d3e8e4ab6a86f3c578941ed085d`
   and
   `756c9749346bda510e242b02b849448418196bc1f95684dbcbbf362eff60d8ba`.
3. Treat the source-level correction as
   `newsk->sk_prot_creator = sk->sk_prot` after `sock_copy`. Similar machine
   code can establish direct patch shape, not source commit provenance.
4. Distinguish direct patch shape, an equivalent fix, vulnerable semantics, an
   established absent route, and indeterminate evidence. Incomplete or
   contradictory evidence must fail closed to indeterminate.

## Exact-static method

1. Bind `work/eu-260128/vmlinux`, `kernel.config`, and `kallsyms.tsv` by SHA-256
   and independently read the ELF Build ID with the required LLVM tools.
2. Use authoritative-map successor bounds and raw ELF bytes for complete
   `sk_prot_alloc`, `sk_alloc`, `__sk_free`, `sk_clone_lock`,
   `inet_csk_clone_lock`, `do_ipv6_setsockopt.isra.8`, `tcp_disconnect`,
   `inet_csk_listen_start`, `tcp_create_openreq_child`, and
   `tcp_v4_syn_recv_sock` ranges. Verify all supplied raw range hashes.
3. Bind `sk_prot` at `sock+0x28`, `sk_prot_creator` at `sock+0x1a0`, protocol
   slab at `proto+0xf8`, and object size at `proto+0x100` from repeated data
   flow, not names alone.
4. Prove allocator/free identity: `sk_alloc` initializes current and creator
   from the same protocol; `sk_prot_alloc` chooses that protocol's slab/size;
   final `__sk_free` chooses the cache from creator.
5. Prove clone identity and ordering: allocation uses source current protocol;
   variable copy starts at `+0x78` for `obj_size-0x78`; both TCP object sizes
   include `+0x1a0`; identify every creator-overwriting copy; prove correction
   after each such copy and before each observed in-function post-copy
   `sk_free`; prove no later creator overwrite before return.
6. Separately distinguish cleanup inside `sk_clone_lock` from later caller
   cleanup that can occur only after a non-null corrected clone returns.
7. Bind the IPv6 address-form branch's current-protocol rewrite without creator
   rewrite and the compiled TCP child route
   `tcp_v4_syn_recv_sock -> tcp_create_openreq_child -> inet_csk_clone_lock ->
   sk_clone_lock`. Record configuration and distinct TCP/TCPv6 object sizes.
8. Retain one non-operational exact-static artifact with complete successor-
   bounded listings and exact protocol-object bytes needed for review.
9. Add a 15-input schema-v2 Boolean-input model with strict exact keys/types,
   all-or-none CLI, deterministic sorted JSON, explicit UTF-8 through
   `sys.stdout.buffer`, exactly one LF, and exhaustive tests asserting every
   classification field over the complete Boolean domain.
10. Integrate only the bounded verdict into the kernel artifact index, exploit
    inventory, `HANDOVER.md`, and `Ioniq5-CHANGELOG.md`.

## Acceptance criteria

- The exact recovered state classifies as `direct_patch_shape` and rejects only
  the named CVE semantics; direct cherry-pick provenance remains false.
- The creator reset is proven after every creator-overwriting copy and before
  every observed in-function cleanup free; caller frees are not conflated with
  that ordering.
- All five classifications are independently representable; missing, unknown,
  non-Boolean, incomplete, and conflicting input fails closed.
- Ignored public patch captures have the canonical hashes and are not copied
  into tracked evidence because their bodies contain an operational trigger.
- `py_compile`, focused tests, exact static/hash checks, `git diff --check`, and,
  if practical, the complete pytest suite and `tests/run_all.py` pass with
  the project-approved `<platformio-env>/bin/python3`.
- This audit stages, commits, and pushes nothing and makes no change to the
  protected residue; any concurrent workspace change is recorded explicitly.

## Limits

No installed/running-device identity, runtime access policy, dynamic route,
wrong-cache free, corruption, privilege escalation, root, or persistence is
observed. Configuration and compiled routes do not establish owner-device
runtime reachability. The audit does not establish broad socket/allocator
safety or absence of every vendor-equivalent defect.
