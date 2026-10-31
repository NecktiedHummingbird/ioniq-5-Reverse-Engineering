# Inotify rename-race backport audit plan

## Objective

Determine whether the exact recovered kernel retains CVE-2017-7533's mutable-dentry-name race or contains an equivalent vendor backport, without creating a rename race, malicious application, heap-grooming sequence, or exploit.

## Acceptance criteria

1. Preserve authoritative public provenance for CVE-2017-7533, its introduction boundary, and upstream fix commit `49d31c2f389acfe83417083e1208422b4091cd9e`.
2. Bind the exact recovered `__fsnotify_parent`, `vfs_rename`, `inotify_handle_event`, `take_dentry_name_snapshot`, and `release_dentry_name_snapshot` machine-code effects.
3. Trace name-pointer stability across the separate inotify length and copy operations rather than inferring status from the `4.1.27-abl` version banner or symbol names alone.
4. Verify both short inline-name copying under the dentry lock and external-name reference retention/release.
5. Separate fix-effect presence, runtime reachability, attempted race, memory corruption, privilege gain, and persistence.
6. Add a reviewed instruction excerpt, authoritative patch, Boolean-only deterministic model, complete truth-table tests, and explicit claim boundaries.
7. Obtain an independent semantic/model review before committing.

## Safety boundary

No inotify watch, rename operation, concurrency, race schedule, heap grooming, malformed name, target-kernel execution, memory corruption, privilege transition, update action, or persistence mechanism.

## Routing note

The configured DeepSeek Flash builder passed static doctor checks but native dispatch returned `Unknown model deepseek:deepseek-v4.1-flash`. The Fable route is present in the catalog but is not advertised for native subagents. No unreviewed substitute builder will receive private target context; root execution continues from authoritative public sources and local read-only artifacts.
