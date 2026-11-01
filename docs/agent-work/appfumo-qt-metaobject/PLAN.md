# AppFUMO Qt 5 meta-object provenance plan

## Objective

Resolve the declaration and exact generated forwarding semantics of local Qt
metadata row index 64 in the authorized embedded AppUpgrade ELF, without
asserting an absolute method index absent `methodOffset()` and inheritance
context, while keeping
metadata binding, machine-code forwarding, and complete producer provenance as
separate statuses.

## Safety and claim boundaries

- read only the exact ignored ELF; never execute it or recovered helpers;
- require explicit ELF, metadata VA, stringdata VA, and local row index; require
  both an evidence manifest and current evidence excerpt before forwarding can
  become resolved;
- do not broad-scan for meta-objects or infer runtime invocation from metadata;
- create no malformed target input, update package, payload, bypass, launch
  request, network/radio/device operation, root action, or persistence material;
- preserve runtime invocation, external/D-Bus reachability, attacker control,
  update acceptance, root, and persistence as unknown absent separate proof.

## Work phases

1. Independently bind the static `QMetaObject` relocation fields to stringdata,
   revision-7 metadata, and generated static metacall.
2. Implement a bounded ELF64 little-endian x86-64 decoder under
   `tools/uk_fw/` with unambiguous file-backed `PT_LOAD` mapping and strict Qt 5
   revision-7/QByteArrayData validation, complete method-row decoding, and
   non-overlapping checked metadata-word intervals.
3. Add strict optional evidence-manifest handling with bounded current-excerpt
   hashing so metadata-only or stale-evidence output cannot claim machine-code
   forwarding; keep producer provenance unresolved.
4. Add synthetic negative/positive tests and an optional exact-artifact report
   comparison that skips only when the ignored ELF is absent.
5. Retain only bounded metadata, string, jump-table, dispatcher, and verifier-call
   excerpts with identities, addresses, and hashes.
6. Update V-032 documentation and indexes without changing its fail-closed
   Boolean model or unrelated V-036/MICOM/IAS work.

## Acceptance

```sh
<platformio-env>/bin/python3 -m py_compile tools/uk_fw/qt5_metaobject_rev7.py tests/test_qt5_metaobject_rev7.py
<platformio-env>/bin/python3 -m pytest -q tests/test_qt5_metaobject_rev7.py
<platformio-env>/bin/python3 -m pytest -q tests
<platformio-env>/bin/python3 tests/run_all.py
<platformio-env>/bin/python3 tests/run_all.py --only privacy
git diff --check
```

Also regenerate the explicit exact report twice, compare bytes, verify its
pinned SHA-256, and confirm the ignored `work/` artifact remains untracked.
