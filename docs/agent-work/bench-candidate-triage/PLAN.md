# Passive kernel-candidate triage plan

## Objective

Convert one completed `ioniq-bench-state/v1` capture into conservative runtime-gate observations for V-024, V-025, and V-026 without opening a PTY, creating AF_UNIX traffic, creating a timerfd, loading a module, or running a race.

## Acceptance criteria

1. Reject incomplete, malformed, duplicate-key, noncanonical, or producer-incompatible JSON.
2. Preserve three-valued state: observed true, observed false, and unavailable/unknown.
3. Require `/dev/ptmx` to resolve to the PTMX character-device identity (major 5, minor 2), with effective target permissions and a live devpts mount, before calling the PTY surface observed.
4. Keep a loaded module name and a matching current on-disk module hash separate from proof that the loaded bytes came from that file.
5. Treat `uname` only as an exact release-token comparison, never as installed `vmlinux` byte identity.
6. Emit deterministic UTF-8 JSON with LF independently of `PYTHONIOENCODING`.
7. State explicitly that no race, UAF, corruption, root, or persistence follows from passive metadata.
8. Pass focused tests, full tests, probe audit, shell syntax validation, and independent review.

## Non-goals

- No exploit trigger, race schedule, malformed input, socket, PTY, timerfd, module operation, target command, firmware image, or flashing action.
- No claim that a version banner establishes exact installed kernel identity.
- No claim that `/proc/modules` plus a current file hash binds loaded module bytes to that file.
