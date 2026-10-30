# Tuxera filesystem VM probe checkpoint

## Status

Phase 1 implemented and coordinator-reviewed in the shared workspace.

- Baseline HEAD before work: `e76073078b29a53be422b2e9202edae0776ac3b6`.
- Native Fable routing was checked and is unavailable because the configured
  `openrouter/claude-fable-5.1` catalog entry is not advertised as a v2 native
  subagent route.
- The statically ready DeepSeek Flash route could not be dispatched by the
  current pi child API (`Unknown model deepseek:deepseek-v4.1-flash`). No worker
  result was accepted or attributed.
- Implementation and high-assurance safety review were therefore completed in
  the root thread.

## Implemented contract

- New tool: `tools/uk_fw/tuxera_fs_probe.py`.
- New tests: `tests/test_tuxera_fs_probe.py`.
- Plan: `docs/agent-work/tuxera-fs-harness/PLAN.md`.
- Evidence update: `evidence/usb-root-test-plan.md`.

The tool uses existing `vm_boot.run`, QEMU EHCI/USB storage, `readonly=on`, and a
fixed guest script. It permits only `tntfs`/`texfat`, requires a project-local
regular non-symlink input, rejects the rootfs and hard-link aliases, keeps the VM
offline, loads only the required transport/filesystem modules, accepts exactly
one `/dev/sd?` candidate, mounts with `ro,nodev,nosuid,noexec`, performs bounded
metadata enumeration, and emits a retained JSON classification.

Two defects found during root review were corrected before acceptance:

1. guest `exit` statements killed PID 1 and caused misleading kernel panics; the
   fixed script runs a function and uses `return`;
2. classification originally matched marker text echoed while the shell parsed
   the script; it now uses exact emitted marker lines.

QEMU xHCI is not usable with this exact vendor module: loading `xhci-pci` faults
in vendor `xhci_toggle_dis_perr_det()` under QEMU. The harness therefore uses
QEMU EHCI plus authentic `ehci-pci`, which produced stable USB-storage devices.
This is a VM compatibility observation, not a production vulnerability.

## Dynamic evidence

Clean exFAT baseline:

- image SHA-256 `63dc4f133e2fc41183aafbb8ff2163cc9461571f48cbe738b407d202934da934`;
- authentic Tuxera exFAT `3016.6.23.3` clean mount/unmount;
- host-log SHA-256 `f4965c43c5f9446a5586e51c37745d6692144e2650ea2b8ea8460476d0199573`.

Sixteen bounded malformed exfatprogs fixtures produced thirteen clean mounts and
three clean rejections, with no detected Tuxera kernel fault. Exact hashes and
limits are recorded in `evidence/usb-root-test-plan.md`.

## Verification

```text
34 passed, 4 subtests passed
py_compile: passed
git diff --check: passed
```

The canonical repository suite passed at the integration boundary:
`189 passed, 20 subtests passed`.

## Next exact action

1. Add deterministic, bounded copy-on-write mutation generation for boot, FAT,
   allocation-bitmap, upcase-table, and directory-entry regions.
2. Keep each VM image read-only during parser probing and deduplicate kernel
   faults by first fault/RIP/call trace.
3. The clean NTFS control and V-011 harmless special-file test are complete:
   exact `tntfs` retained character node `1:3`; numeric uid/gid 65534 could
   open it read-only without `nodev`, while the `nodev` control denied it.
   Continue with production mount-path and SMACK-domain reachability only; do
   not recast this post-execution primitive as USB-to-root.
