# AppLauncher D-Bus launch audit checkpoint

## Current result

V-028 records an exact caller-path route that bypasses both identified AppLauncher verifier calls. The exported session-bus request forwards `applocation` to an on-demand dispatcher, which overwrites the process program, sets the direct-launch byte and reaches a `QProcess::start` call site without either helper.

## Corrections and boundaries

- Commit `3090f69` incorrectly constrained launch targets using a literal-string scan. The runtime D-Bus QString means the route is not limited to read-only `/navi` paths.
- The older public claim that failed verification does not stop launch is also too broad. Both exact verifier paths branch to failure on false; the separate on-demand path bypasses them.
- The session bus's no-user-rule default is same-daemon-uid, not arbitrary cross-uid access. Relevance is strongest for the many uid-zero, SMACK-separated HMI processes.
- No owner-unit Request-object registration result, request, successful bus authentication, SMACK route, new AppProcess-object construction, controlled executable at exec time, QProcess acceptance, effective privilege retention, successful exec, credential/label transition, unrestricted root, update-anchor write or persistence has been observed.

## Artifacts

- Assessment: `evidence/applauncher-dbus-launch-bypass.md`
- Reviewed excerpt: `evidence/artifacts/application-candidates/applauncher-dbus-launch-evidence.txt`
- Model: `tools/uk_fw/applauncher_dbus_launch_model.py`
- Tests: `tests/test_applauncher_dbus_launch_model.py`

## Deterministic artifacts

- Model default-report SHA-256: `ee8949cec8c7a9832f7794b59f3552a3237c5f3b0e00777ae95bc5487e629530`
- Current emitted passive probe SHA-256: `5a81fb9f0f5a6ba793672fc3323489f58239de56782598f64e964642cbaa0b84`
- Focused validation: `29 passed, 131104 subtests passed`; emitted probe passed POSIX shell syntax.

## Acceptance status

- Independent final semantic/model review: **ACCEPT**; no blocking semantic/model issues found after adding fail-closed Request-object registration and AppProcess-object construction gates.
- Remaining release step: run complete validation, inspect the exact repository scope, then commit and push.
