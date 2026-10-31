# Inotify name-snapshot backport audit checkpoint

## Result

CVE-2017-7533 is rejected for the exact recovered kernel. Although exact `inotify_handle_event` retains separate filename length and copy operations, the watched-parent and rename producers pass a stable dentry-name snapshot. This is an equivalent vendor backport of upstream commit `49d31c2f389acfe83417083e1208422b4091cd9e`, not a conclusion from the `4.1.27-abl` version banner.

## Exact effects

- `__fsnotify_parent` takes a snapshot before exact `fsnotify` and releases it afterward.
- `vfs_rename` takes the old-name snapshot before mutation, routes successful `d_move`/`d_exchange` paths through exact `fsnotify_move`, and releases afterward.
- Short inline names are copied while the dentry lock is held.
- External names gain an owner reference while the same lock is held.
- Release distinguishes inline storage and drops/deferred-frees the retained external owner.
- The CVE-specific mutable-name premise therefore does not reach the separate inotify length/copy operations.

## Artifacts

- Assessment: `evidence/vendor-kernel-inotify-cve-2017-7533.md`
- Reviewed assembly SHA-256: `40fafa08ffb1a19e8118ecdbf94e323c57ce8b740bcaa339f544b72a59663b05`
- Upstream patch SHA-256: `759bb7915fa236b6da1f130e2d9cb356e47aba3bd8b5d84822dc1c74b3923305`
- Model: `tools/uk_fw/inotify_name_snapshot_model.py`
- Tests: `tests/test_inotify_name_snapshot_model.py`
- Deterministic model-report SHA-256: `08b97fdaee4272a4ecc337eeed1eb7831f56a242d374912e477b97b2764a9df1`

## Validation and review

- Focused validation: `7 passed, 142 subtests passed`.
- Complete validation: `439 passed, 131682 subtests passed`; public research harness: **PASS**.
- Independent semantic/model review: **ACCEPT**; no blocking issues found.
- DeepSeek Flash static routing doctor: ready, but native dispatch failed with `Unknown model deepseek:deepseek-v4.1-flash`.
- Fable doctor: route exists but is not advertised for native subagents; no task was dispatched through it.
- No inotify watch, rename, concurrency, race, heap manipulation, target execution, corruption, privilege transition, update action, or persistence mechanism was created.
