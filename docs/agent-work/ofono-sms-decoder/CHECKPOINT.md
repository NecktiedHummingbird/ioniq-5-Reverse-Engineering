# V-017 oFono SMS decoder checkpoint

Status: **implementation complete and locally accepted; commit/push pending.**

Date: 2026-11-01
Research/dispatch baseline: `11ec99a9f80f4e86c623ac4a1bbfd2477f74faa7`
Integration base before this task's commit: `1216f8098bd363148bf7b83bf619713048b75c2f`
(the workspace advanced concurrently with the separately reviewed IAS header
commit; this task does not modify that commit's generated header or README).

## Accepted result

- Exact `/usr/sbin/ofonod` instructions retain both reviewed pre-fix conditions:
  - CVE-2023-4233 address decoding lacks `addr_len > 20` and encoded-byte
    destination limits before the non-alphanumeric BCD write;
  - CVE-2023-2794 deliver decoding checks source availability but not its
    140-byte destination before plain `memcpy@plt`.
- Two compiled vendor `lgeqmimodem` QMI callbacks call
  `ofono_sms_deliver_notify`, which invokes the affected deliver decoder.
- Exact caller layout was retained: `sms` at `rsp+0x30`, later scratch at
  `rsp+0x160`, canary at `rsp+0x1f8`. The maximum reviewed writes leave the
  `sms` object but do not directly reach that canary.
- The conditional service defaults to uid 0 and executes with SMACK
  `App::tms`. Unit/marker activation, owner-device identity, modem/QMI state,
  cellular delivery, dynamic corruption, RCE, SMACK escape, and unrestricted
  root remain unproven.

## Tracked deliverables

- `tools/uk_fw/ofono_sms_bounds_model.py`
- `tests/test_ofono_sms_bounds_model.py`
- `evidence/artifacts/network-candidates/ofono-sms-decoder-evidence.txt`
- `evidence/ofono-sms-decoder-cves.md`
- `docs/agent-work/ofono-sms-decoder/PLAN.md`
- this checkpoint
- consistent V-017 updates to the vulnerability register, inventory, survey,
  network surface, prioritisation, handover, history, changelog, and artifact
  index

Full source history, NVD/ZDI responses, disassembly, upstream patches, and the
generated arithmetic report remain ignored under
`work/public-vuln-research-20261101/`.

## Deterministic arithmetic

Address-length domain, 256 values:

- specification-bounded: 21;
- oversized but array-bounded: 2;
- address-array overflow: 233;
- maximum output: 257 bytes into 23;
- maximum beyond `sms`: 21 bytes.

Deliver `(UDL,DCS)` domain, 65,536 pairs:

- bounded copy: 46,416;
- array overrun remaining inside `sms`: 9,368;
- write beyond `sms`: 9,752;
- maximum copy: 255 bytes into 140;
- maximum beyond `sms`: 64 bytes;
- pairs reaching later scratch: 8,288;
- pairs reaching the caller canary: 0.

Generated ignored JSON SHA-256:
`1ae024c3c5ea5db27672a54c252deec4a1d618b9768b65d4a09f51b2f395f818`.

Reviewed tracked excerpt SHA-256:
`8278be703ee739c9a0f17eeb83d69e59c6a1b367fe163e133bfc6d935f07e4f3`.

## Validation

- Focused:
  `/Users/leo/.platformio/penv/bin/python3 -m pytest -q tests/test_ofono_sms_bounds_model.py`
  -> `8 passed, 5 subtests passed`.
- Full:
  `/Users/leo/.platformio/penv/bin/python3 -m pytest -q tests`
  -> `263 passed, 53 subtests passed`.
- `py_compile` for the new tool: passed.
- staged `git diff --check`: passed after final checkpoint creation.
- Public harness: `pass=3`, `info=4`, `pending=0`, `blocked=0`, `fail=0`.
- Canonical rootfs SHA-256 remains
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`.
- `/opt/homebrew/opt/e2fsprogs/sbin/e2fsck -fn` remains clean at
  `246790/2097152 files`, `6108674/8388608 blocks`.

## Delegation record

Astra's route doctor reported DeepSeek Flash as `static-ready` with route
`deepseek/deepseek-v4.1-flash`; Fable remained unavailable because its catalog
entry was not advertised for native v2 subagents. Native DeepSeek dispatch then
failed immediately with:

```text
Unknown model deepseek:deepseek-v4.1-flash
```

No worker result existed, no fallback model was substituted, and no failed
output was used. The root agent completed and reviewed the bounded implementation
directly.

## Resume actions

1. Re-run `git diff --check`, inspect the complete tracked diff, then commit and
   push if the workspace remains scoped.
2. On a future disconnected bench, first record installed `ofonod`, service/path
   enablement, telematics/no-ISA markers, uid/SMACK label, modem devices, QMI
   services, SIM/carrier state, and benign SMS behavior.
3. Do not introduce malformed modem input without separate approval, proven
   restart/recovery, and a disposable state. Any later control remains
   process-crash-only: no payload, persistence, or privilege action.
4. Continue exact RPM-component review; do not infer applicability from package
   versions.
