# AppLauncher D-Bus launch audit plan

## Objective

Determine whether the exact recovered AppLauncher accepts a runtime executable path through its exported request interface and whether that path can reach `QProcess::start` without either identified verifier call.

## Acceptance criteria

1. Bind service name, object path, interface, launch arguments and adaptor-to-dispatcher call using exact ELF strings, relocations and instructions.
2. Trace both existing-process and new-process branches, including appid/path-existence gates and the destination program field.
3. Bind the bypass field from constructor initialization through dispatcher writes and the exact direct-start branch.
4. Prove whether false results from each verifier stop or permit launch; correct broader historical claims if needed.
5. Record systemd uid defaults, session-bus authentication/policy and SMACK/runtime prerequisites without flattening them into one root claim.
6. Add a Boolean-only deterministic model with a complete truth table and fail-closed CLI; emit no D-Bus message, path, command, executable, payload or firmware bytes.
7. Extend passive bench metadata only as needed to observe service/bus presence without connecting to the bus.
8. Obtain an independent semantic/model review before committing.

## Safety boundary

No D-Bus call, executable creation, QProcess request, recovered-target execution, credential or label transition, update-anchor write, update operation or persistence attempt.
