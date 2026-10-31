# V-028 — AppLauncher session-bus path bypasses both identified verifier calls

## Result

The exact recovered EU `260128` `/app/bin/AppLauncher` exposes a session-bus `launch(appid, appname, applocation, ...)` API whose `applocation` argument is copied into the program field later passed to `QProcess::start`. Its on-demand dispatcher sets an internal byte that selects the direct launch branch; neither of the two identified verifier calls runs on that branch.

This overturns the narrow negative conclusion recorded in commit `3090f69`: a literal-string scan found only fixed `/navi` targets, but the executable also accepts a **runtime D-Bus QString path**. The finding is therefore not limited to replacement of a fixed read-only navigation binary.

The exact verified branches are fail closed after a false verifier result. The defect is the separate on-demand dispatcher that intentionally marks the process direct, not failure handling inside either identified verifier.

Classification: **exact static same-bus-uid bypass of both identified AppLauncher verifier calls to a privileged `QProcess::start`-attempt candidate**. This does not establish that these two calls are the platform's only possible executable-enforcement mechanisms. A delivered request from an owner-unit application, effective SMACK access, caller-controlled executable bytes, successful `exec`, resulting credentials/label, unrestricted root, update-anchor substitution and persistence remain unobserved.

## Exact identity and reviewed artifact

- path: `/app/bin/AppLauncher`
- ELF: x86-64 `ET_DYN`
- SHA-256: `c8d6d56bc254ad0731e81f40bd83aa9b3be6b49bcbd8efb291157a06c4a84268`
- GNU Build ID: `0452df1033bd1bbae15727a83d4d56576d8b9444`
- reviewed excerpt: `evidence/artifacts/application-candidates/applauncher-dbus-launch-evidence.txt`

All addresses are PIE image-relative virtual addresses. Half-open function extents come from `.eh_frame`; instruction claims were confirmed with `/opt/homebrew/opt/llvm/bin/llvm-objdump`.

## Exact control flow

### 1. An exported request accepts a runtime program path

Startup attempts to register `com.lge.avn.applauncher` on `QDBusConnection::sessionBus()` at `0xbb21..0xbb2f`. The Request constructor `[0x26250,0x26333)` attempts to register object `/Request` with `ExportAdaptors` and builds the adaptor.

The embedded interface `com.lge.avn.applauncher.request` exports three `launch` overloads. Every overload accepts:

- `appid` (`i`),
- `appname` (`s`),
- `applocation` (`s`).

The shortest adaptor `[0x26340,0x26669)` copies the two strings, obtains the application singleton, loads vtable slot `+0x68`, and calls it with the request values at `0x264ac..0x264b8`. Relocation `0x261ca0` binds that slot to exact dispatcher `[0x1ffd0,0x205b3)`.

### 2. Existing-process and new-process branches install `applocation`

The dispatcher first looks up an object by appid at `0x20002`.

If found, it:

1. stores one to object byte `+0x1c` at `0x20010` and again at `0x20020`;
2. assigns the caller's `applocation` to QString `+0x58` at `0x2003d..0x20044`;
3. replaces appid `+0x20` and appname `+0x48`;
4. calls start routine `[0x163f0,0x1854d)` at `0x20207`.

If no object exists, helper `[0x1fd30,0x1ffcf)` accepts appids 1 through 1024 and requires `QFile(applocation).exists()`. It then creates an AppProcess and copies the request's path to `+0x58` and name to `+0x48`. The dispatcher rejoins the same byte-`+0x1c` and start path. This is an existence gate, not a directory, partition, owner, signer or digest allowlist. The existing-object branch does not perform the helper's create-time existence check before replacing the path.

### 3. The byte selects direct launch

The AppProcess constructor initializes byte `+0x1c` to zero at `0x15612`. In the start routine:

- at `0x1641b..0x16429`, a nonzero byte overrides an early state/retry return;
- the program at `+0x58` flows into the QString used for file metadata and `QProcess::start`;
- `QFileInfo::isExecutable()` is called at `0x17326`, but its result is logged rather than used to guard the direct branch;
- at `0x17426`, zero branches to signature handling;
- nonzero falls through to `QProcess::start(program, args, mode)` at `0x1745d`.

The on-demand dispatcher therefore dominates the direct start with the bypass value.

### 4. False verification results do stop verified launches

For an ordinary verified application, `0x17e78` calls helper `[0x15b50,0x163e1)`. A false result branches to failure state at `0x18088`; only true reaches `QProcess::start` at `0x17eb2`.

For appid 30, `0x1812f` calls navigation helper `[0x12100,0x127cd)`. False also branches to `0x18088`; true reaches the start at `0x18169`.

This exact control flow corrects the older public note's claim that a failed check itself does not stop launch. It also prevents the correction from being overstated: **both identified verifier calls are bypassed through a different dispatcher; their own failure handling is not fail-open**.

## Service, D-Bus and SMACK boundaries

`ApplicationLauncher.service` has no `User=` or `Group=` and runs `/app/bin/AppLauncher.sh`; the configured systemd default is uid/gid zero. The script runs `/app/bin/AppLauncher 3`. The exact executable imports no application-level credential-dropping API. Configuration does not establish effective runtime uid, capabilities, sandbox state, retained privilege at exec, or a resulting process label; no owner-unit exec was attempted or observed.

`Dbuslaunch.sh` starts `dbus-daemon --session` and stores its address in `/tmp/session_appmgr{,.env}`. The recovered `session.conf`:

- listens on `unix:tmpdir=/tmp`;
- enables `EXTERNAL` authentication only;
- allows authenticated clients to send to, receive from and own any name;
- has no user connection rule.

The documented no-user-rule default for a session daemon accepts only the uid that owns the daemon. Because the recovered daemon and many HMI services/applications are configured to run as uid zero, the candidate is relevant to **same-uid, SMACK-separated local code**, not automatically to an arbitrary non-root uid. No adaptor-level sender or per-method authorization check was found.

Recovered SMACK policy gives the intended application domains broad `rwx` relationships with `App::manager` (and floor `_`), making a manager-bus route plausible, but policy files show intent rather than effective labels. Runtime labels of the session socket, daemon, launcher, requesting process and executable must be captured before claiming a MAC escape.

## Security consequence and chain correction

The static result changes the prior chain analysis:

- A fixed-string scan cannot constrain `applocation`; it is a runtime argument.
- A compromised same-bus-uid application does not necessarily need to replace `/navi` or wait for a root service restart.
- If the service name is owned, the Request object is registered, that caller can authenticate to the private bus and pass SMACK checks, and a relevant AppProcess object is available, retaining control of an executable path at exec time can reach a launcher start attempt without either identified verifier call when all later gates hold.
- Because AppLauncher is configured as uid zero, this is a plausible route from SMACK-confined same-uid code to privileged execution. Runtime privilege retention, QProcess acceptance, successful exec and the resulting label remain unobserved, so it is not a demonstrated unrestricted-root transition.

That route could then satisfy the privileged-write prerequisite for substituting the persistent update trust anchor, but only after the missing runtime gates, QProcess acceptance, successful exec, effective privilege retention and resulting security context are established. This finding alone does not prove modified-update acceptance, partition writes, slot switching, boot acceptance, health/mark-good or persistence.

## Bounded model

`tools/uk_fw/applauncher_dbus_launch_model.py` consumes Boolean state only. It keeps these branches distinct:

- request delivery requires service ownership, successful Request-object registration, same-bus uid, successful bus authentication, method permission and SMACK access;
- a relevant existing AppProcess object for the appid bypasses the new-object appid/existence gates;
- the new-object route requires both create-time gates, and actual object construction is a separate supplied runtime outcome;
- direct-route selection and arrival at the identified QProcess call are explicit supplied gates rather than inferred from delivery alone;
- a controlled privileged-exec candidate additionally requires QProcess to accept start, an executable target, launcher execute access, caller control at exec time, and effective launcher privilege retained at exec.

The model deliberately reports runtime request, successful exec, credential/label transition, trust-anchor write and persistence as `null`. It emits no D-Bus message, target path, command, executable, payload or firmware bytes.

Deterministic default-report SHA-256: `ee8949cec8c7a9832f7794b59f3552a3237c5f3b0e00777ae95bc5487e629530`.

## Remediation

1. Remove caller-supplied executable paths from the D-Bus contract. Resolve appid through a root-owned, immutable registry.
2. Make signature verification mandatory immediately before every exec and bind it to the exact opened executable (descriptor/inode), not a separately reopened path.
3. Treat missing signatures, malformed ELF metadata, key-read failure and verifier failure as terminal.
4. Authorize the D-Bus sender explicitly by required identity/domain and use a least-privilege bus policy; same uid is not sufficient separation when many services run as uid zero.
5. Run applications under distinct non-root uids with narrow SMACK rules. Drop supplementary groups and capabilities before exec.
6. Keep trust anchors and executable registries on authenticated read-only storage.

Acceptance should include negative tests for arbitrary paths, existing-appid path replacement, missing/non-executable files, invalid signatures, unauthorized same-uid senders and TOCTOU replacement, plus positive tests for genuine registered applications.

## Safety boundary

No D-Bus call was sent, no executable or command was created, no QProcess launch was requested, no recovered target was executed for this finding, and no uid/label transition, trust-anchor write, update operation, slot change or persistence mechanism was attempted.
