# V-017 oFono SMS decoder checkpoint

Status: **original V-017 work committed as `8d1e75a`; directional decoder
expansion and V-018 QMI-list review are locally accepted, with commit/push
pending.**

Date: 2026-11-01
Research/dispatch baseline: `11ec99a9f80f4e86c623ac4a1bbfd2477f74faa7`
Integration base before this task's commit: `1216f8098bd363148bf7b83bf619713048b75c2f`
(the workspace advanced concurrently with the separately reviewed IAS header
commit; this task does not modify that commit's generated header or README).

## Accepted result

- Exact `/usr/sbin/ofonod` instructions retain destination checks fixed by
  CVE-2023-4232 through CVE-2023-4235, CVE-2023-2794, and CVE-2024-7547.
- Two compiled vendor `lgeqmimodem` QMI callbacks call
  `ofono_sms_deliver_notify`. Its `sms_decode(..., FALSE, ...)` dispatch
  completes deliver, submit-report, or status-report decoding before the later
  DELIVER type check.
- Deliver-report and command decoding are outgoing-only. Exact `outgoing=TRUE`
  callers exist in local transmit-queue deserialization and SIM-Toolkit Send
  SMS parsing; these are not the ordinary incoming SMS route.
- Exact incoming delivery-caller layout was retained: `sms` at `rsp+0x30`,
  later scratch at `rsp+0x160`, canary at `rsp+0x1f8`. Incoming modeled maxima
  leave the object but do not directly reach that canary. Outgoing-only caller
  frames remain to be reconstructed; only their object-relative bounds are
  claimed.
- V-018 separately confirms CVE-2024-7537's missing QMI message-list
  count/length check. The vendor overflow diagnostic falls through to a
  four-byte allocation; every original count above 13,107 under-allocates
  relative to its copy loop.
- The conditional service defaults to uid 0 and executes with SMACK
  `App::tms`. Unit activation, owner identity, modem/QMI provenance, direct
  radio reachability, dynamic corruption, RCE, SMACK escape, and unrestricted
  root remain unproven.

## Tracked deliverables

- `tools/uk_fw/ofono_sms_bounds_model.py`
- `tests/test_ofono_sms_bounds_model.py`
- `tools/uk_fw/ofono_qmi_list_bounds_model.py`
- `tests/test_ofono_qmi_list_bounds_model.py`
- `evidence/artifacts/network-candidates/ofono-sms-decoder-evidence.txt`
- `evidence/artifacts/network-candidates/ofono-qmi-list-evidence.txt`
- `evidence/ofono-sms-decoder-cves.md`
- `evidence/ofono-qmi-message-list-cve-2024-7537.md`
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

- bounded copy: 44,461;
- array overrun remaining inside `sms`: 10,235;
- write beyond `sms`: 10,840;
- maximum copy: 255 bytes into 140;
- maximum beyond `sms`: 64 bytes;
- pairs reaching later scratch: 9,240;
- pairs reaching the caller canary: 0.

Extended decoder JSON SHA-256:
`c1676c7b5f5689c5ae568011206738a561a36d1158d2e364131bb0641fd02c45`.

QMI-list arithmetic JSON SHA-256:
`3333224f40632e2e1cadf9dffd10079966db720f484d4d0b92a5d80bc835f9f8`.

Reviewed decoder excerpt SHA-256:
`5e081effe76b4f118d8f6008a6c29a15451e173cc928d20a642c288d00505ae5`.

Reviewed QMI-list excerpt SHA-256:
`fb1b3bad39b4b63b431ea148f52c9bdd054d16ca5757626209e40195fa10a7ca`.

## Validation

Original committed V-017 acceptance: `263 passed, 53 subtests passed`.
Current focused expansion:

- `tests/test_ofono_sms_bounds_model.py`: `11 passed, 19 subtests passed`;
- `tests/test_ofono_qmi_list_bounds_model.py`: `7 passed, 5 subtests passed`;
- `py_compile` for both tools/tests: passed.

Final acceptance:

- full suite: `273 passed, 72 subtests passed`;
- `py_compile` for both tools/tests: passed;
- `git diff --check`: passed;
- public harness: `pass=3`, `info=4`, `pending=0`, `blocked=0`, `fail=0`.
- Canonical rootfs SHA-256 remains
  `4953a005683e009e84390bbf07d65a6a3313cc6abd692a3023e6b660066d036f`.
- `/opt/homebrew/opt/e2fsprogs/sbin/e2fsck -fn` remains clean at
  `246790/2097152 files`, `6108674/8388608 blocks`.

An independent read-only worker review found and drove three corrections before
acceptance: the exact binary's DCS `0x84` and reserved-alphabet behavior replaced
upstream-source assumptions; outgoing-only decoders no longer inherit the
incoming delivery caller's scratch/canary layout; and V-018 now distinguishes a
selected-TLV overread from a necessarily backing-buffer OOB read.

## Delegation record

Astra's route doctor reported DeepSeek Flash as `static-ready` with route
`deepseek/deepseek-v4.1-flash`; Fable remained unavailable because its catalog
entry was not advertised for native v2 subagents. Native DeepSeek dispatch then
failed immediately with:

```text
Unknown model deepseek:deepseek-v4.1-flash
```

No worker result existed, no fallback model was substituted, and no failed
output was used for the original V-017 implementation. The later directional
and V-018 expansion received the independent read-only worker review recorded
above.

## Resume actions

1. Inspect the complete tracked diff, then commit and push if the workspace
   remains scoped.
2. On a future disconnected bench, first record installed `ofonod`, service/path
   enablement, telematics/no-ISA markers, uid/SMACK label, modem devices, QMI
   services, SIM/carrier and SIM-Toolkit state, benign SMS behavior, and benign
   stored-message enumeration.
3. Do not introduce malformed modem input without separate approval, proven
   restart/recovery, and a disposable state. Any later control remains
   process-crash-only: no payload, persistence, or privilege action.
4. Continue exact RPM-component review; do not infer applicability from package
   versions.
