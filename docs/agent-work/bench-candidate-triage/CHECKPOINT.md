# Passive kernel-candidate triage checkpoint

## Result

Implemented and independently accepted.

## Tracked implementation

- `tools/uk_fw/bench_candidate_triage.py`
- `tests/test_bench_candidate_triage.py`
- `tools/uk_fw/bench_state_bundle.py`
- `tests/test_bench_state_bundle.py`

The passive producer now records `/dev/pts/ptmx` and the hexadecimal device major/minor reported by `stat`, in addition to `/dev/ptmx`, `/dev/pts`, mount state, `/proc/modules`, and the current `unix.ko` file hash.

The consumer:

- validates the producer's exact section sequence, section closure/status, terminal records, section hashes, canonical report hash, and bounded regular-file input;
- rejects duplicate JSON keys and conflicting observations;
- handles the producer's `stat`, `ls`, and unavailable-metadata forms without converting unavailable evidence to false;
- requires an effective mode allowing world read/write, devpts mounted at `/dev/pts`, a valid directory, and PTMX device identity major 5/minor 2;
- keeps module-name-loaded, current-file-hash-match, and loaded-byte binding as separate states;
- emits no operational material.

## Validation

- Focused tests: `38 passed, 5 subtests passed`.
- Full tests: `415 passed, 364 subtests passed`.
- Generated probe audit: `safe=true`, `syntax_ok=true`, `violations=[]`.
- Generated probe SHA-256: `1bf3b127f43aec2ce19997fbaf6a308c1084d60b62676b134e04733ba063c2e6`.
- Independent final review: `ACCEPT` after four review rounds. Earlier rounds identified and caused correction of module-binding overclaim, impossible-report acceptance, PTMX symlink/target ambiguity, tri-state conjunction errors, producer fallback handling, and missing device-number identity.

## Claim boundary

This classifies passive records only. It does not authenticate who produced a capture, bind loaded module memory to the current file, establish exact installed `vmlinux` bytes, exercise a syscall or ioctl, or establish a race, UAF, corruption, code execution, root, SMACK escape, update acceptance, or persistence.
