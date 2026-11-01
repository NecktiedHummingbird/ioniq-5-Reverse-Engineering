# AppFUMO Qt 5 meta-object provenance checkpoint

## Integration base

During the consolidated review-fix cycle, `main`/`ioniq/main` advanced
externally from `c7e1a5007b58b63f5914cb49c021daabd76f1e02` to
`e6eca247961fec42006c6e326d157c22797f851f` (`Re-measure V-036 and record the
stronger reading with its caveat`). That commit and its committed `Ioniq5-HISTORY.md` and
`Ioniq5-VULNERABILITIES.md` changes are preserved unchanged by this package.
Its already-committed Qt changelog paragraph is corrected in this delivery to
match the reviewed local-index wording, evidence binding, report hash, and
validation counts. No unrelated V-036 file was rewritten.

## Completed result

- Bound exact embedded ELF SHA-256
  `464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7`
  and Build ID `863a8730e66a1c5245a1bf458fe2554adee0351a`.
- Rechecked static-object relocation addends: stringdata `0x445260`, metadata
  `0x444760`, and static metacall `0x16df80`.
- Decoded revision-7 header `(7,0,0,0,85,14,0,0,0,0,0,0,0,7)`, local row
  64 `(98,2,631,2,10)`, and parameter record `(10,10,10,99,100)`.
- Resolved local `AppUpgradeEngine` metadata row 64 to public slot
  `QString decryptionFile(QString encFile, QString destPath)`. The method is
  declared in the selected meta-object, but 64 is not asserted as the absolute
  method index because `methodOffset()` and inheritance context are not inputs.
  It is not signal number 64; signal count is 7.
- Rechecked jump-table entry 64 at `0x444700`: raw `0xffd299c6`, signed
  displacement `-2975290`, target `0x16dfc6`.
- Rechecked generated forwarding: `a[1] -> encFile -> %rdx`,
  `a[2] -> destPath -> %rcx`, call `0x100b30`, QString return -> `a[0]`.
  The target's verifier call remains `0x100bb0`.
- A bounded direct-reference scan observed calls to `0x100b30` at `0x10281c`,
  `0x102de9`, `0x103398`, and generated metacall site `0x16e030`. Complete
  producer absence is not claimed.

## Implemented package

- defensive decoder: `tools/uk_fw/qt5_metaobject_rev7.py`;
- synthetic and optional exact tests: `tests/test_qt5_metaobject_rev7.py`;
- bounded static excerpts and strict manifest under
  `evidence/artifacts/update-candidates/`; forwarding can resolve only when an
  explicit bounded current evidence excerpt hashes to the manifest digest;
- complete method-row parameter-interval validation rejects truncation and
  overlap with metadata tables or other parameter records;
- deterministic exact report SHA-256:
  `330799c5215a0d3fda7c8870820240cb023c9b3a6c9673100778a038fe1d14a3`;
- exact excerpt SHA-256:
  `31a90d0d633d22823fe1e4e61aa1c7df159c1a1acef379fe4e7aa38c7195c1ee`;
- strict manifest SHA-256:
  `ecf48b2ec0d5f5c6014e2ef7c4efbfdd25899a3b79da2f4cf808dda062bf16bb`;
- assessment: `evidence/appfumo-qt-metaobject-provenance.md`.

The decoder defaults to metadata `resolved`, forwarding `unresolved`, and
producer provenance `unresolved`. The strict exact evidence manifest plus its
explicit current evidence excerpt changes forwarding to `resolved`; either
input alone or a digest mismatch fails closed. Producer provenance deliberately
remains `unresolved`. V-032's existing Boolean model remains unchanged and
fail-closed.

## Remaining unknowns

Complete producer provenance, runtime invocation, dynamic Qt meta-invocation,
indirect/external paths, object/adaptor registration, external and D-Bus
reachability, attacker control, owner-device identity, final payload binding,
outer-executable reauthentication, update acceptance, partition writes,
slot/boot acceptance, root, and persistence remain unknown.

## Validation

- bytecode compilation: passed;
- focused Qt/FUMO tests: `29 passed, 8228 subtests passed`;
- complete tests-scoped suite: `664 passed, 351250 subtests passed`;
- public harness: **PASS**, `pass=3 info=4 pending=0 blocked=0 fail=0`;
- privacy-only public harness: **PASS**, no blocking finding;
- exact report generated under `ascii`, `latin-1`, and `utf-16`
  `PYTHONIOENCODING` settings: all byte-identical to the retained report;
- deterministic exact report SHA-256:
  `330799c5215a0d3fda7c8870820240cb023c9b3a6c9673100778a038fe1d14a3`;
- `git diff --check`: passed.

No project temporary-directory override was used.

## Safety record

No recovered target or helper was executed. No device, radio, network path,
updater state, archive, package, partition, slot, or boot state was exercised.
No malformed target input, payload, bypass, launch request, race schedule, root
action, or persistence material was created. Synthetic test fixtures are bounded
byte arrays and are never executed.
