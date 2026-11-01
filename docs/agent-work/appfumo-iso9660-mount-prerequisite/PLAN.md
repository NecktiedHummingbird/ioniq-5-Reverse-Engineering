# AppFUMO ISO9660 mount-prerequisite follow-up plan

## Scope

Bind the accepted AppFUMO USB pathname result to the exact recovered EU 260128
userspace, canonical-archive bzImage, decompressed vmlinux, embedded kernel
configuration, and canonical rootfs module inventory. This is a post-delivery
follow-up; it does not rewrite the prior pathname acceptance. The worker opened
at `ec93aed`; initial review used `fe3d363`; non-overlapping integration commits
advanced current review HEAD to `a1f135171cf7372c8fb90388f96cc7da77f0e5b4`.

## Work

1. Re-read the accepted pathname assessment/model/tests and adjacent USB/FUMO evidence.
2. Bind the canonical archive and exact bzImage member through its boot-header-
   derived, bounded legacy-LZ4 payload to exact vmlinux identity and unique
   embedded gzip IKCONFIG bytes; bind the 163-member regular `.ko` inventory and
   module metadata.
3. Retain only compact static evidence for ISO9660 recognition, ordinary `sd*`
   builtin-blkid routing, generic direct `mount(2)`, read-only retry, success
   signal dominance, and named canonical kernel prerequisites. Preflight all
   LZ4 literal, match, and aggregate output growth before extension and use a
   chunk-bounded overlap copy without repeated-pattern multiplication.
4. Add bounded schema-v5 semantics that reject the named canonical routes while
   leaving broad inline/renamed/vendor-equivalent and installed-runtime routes
   unknown.
5. Add strict identity/row/output/causality/determinism tests and narrow evidence,
   inventory, README, HANDOVER, and prior-checkpoint integrations. Limit module
   absence to tested exact basenames/paths, bounded identifiers, and SCSI CD-ROM
   alias mappings; do not infer every equivalent implementation absent.
6. Run only focused tests, bytecode compilation, deterministic encoding/hash,
   retained-row/hash, UTF-8/LF, and diff checks.

## Safety and exclusions

Static/read-only target analysis only. Do not execute recovered target code or
perform target mounts, image/archive construction, malformed-input work,
path/command/payload generation, D-Bus activity, target syscalls, privilege,
root, or persistence actions. Do not delegate or use orchestration. Do not
stage, commit, push, reset, or stash. Do not inspect or modify the unrelated
`tools/uk_fw/ias_backend_soft/micom_service.c` change. Temporary output belongs
under ignored `work/` only. Use the project-approved PlatformIO Python and refer
to disassembly tooling generically as Homebrew LLVM.
