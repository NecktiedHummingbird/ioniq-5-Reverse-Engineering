# oFono SMS decoder CVEs in recovered EU `260128`

Status: **exact pre-fix CVE-2023-4232, CVE-2023-4233, CVE-2023-4234,
CVE-2023-4235, CVE-2023-2794, and CVE-2024-7547 writes are statically
confirmed. The vendor-QMI incoming route reaches CVE-2023-4233,
CVE-2023-2794, CVE-2023-4234, and CVE-2023-4232 before its late type check;
CVE-2023-4235 and CVE-2024-7547 require outgoing/local or SIM-Toolkit decode
routes.
Service activation, cellular delivery, controlled execution, and root access
are unproven.**

Target: recovered European Gen5W Linux
`NE_E.EUR.S5W_L.001.001.260128`. The owner's installed firmware is unknown. No
physical unit, modem, target-binary execution, or network-enabled VM was used.

## Executive conclusion

The exact shipped `/usr/sbin/ofonod` retains six published missing destination
bounds in its TPDU decoders:

1. **CVE-2023-4233:** a one-byte address length can make the non-alphanumeric
   BCD loop write as many as 257 bytes into a 23-byte address array;
2. **CVE-2023-2794:** deliver user data can pass as many as 255 bytes to
   unfortified `memcpy` with a 140-byte destination;
3. **CVE-2023-4232:** status-report user data can copy as many as 255 bytes to a
   143-byte destination;
4. **CVE-2023-4234:** submit-report user data can copy as many as 255 bytes to
   152-byte ACK or 151-byte ERROR destinations;
5. **CVE-2023-4235:** outgoing-direction deliver reports retain equivalent
   missing bounds for 159-/158-byte destinations;
6. **CVE-2024-7547:** outgoing-direction command data can copy as many as 255
   bytes into a 156-byte destination.

This is not inferred from the old RPM version. Exact instructions in the
recovered binary were compared with each upstream fix. The vendor's compiled
`lgeqmimodem` callbacks pass both direct QMI indications and stored/raw-read
messages to `ofono_sms_deliver_notify`. Its `sms_decode(..., FALSE, ...)` call
completes the TP-MTI-selected decoder before checking that the returned type is
DELIVER. Consequently status and submit-report copies occur before the late
type rejection. Outgoing-only deliver-report and command decoders cannot be
selected by this incoming call; exact local transmit-queue and SIM-Toolkit
callers use `sms_decode(..., TRUE, ...)` instead.

If started, the unit runs as uid 0 because it has no `User=` directive. The
executable receives the `App::tms` SMACK label, so uid 0 is not equivalent to
unrestricted access. The service is also conditional, and no recovered enable
symlink for `ofono.path` was found. The owner's installed binary, unit state,
modem state, cellular attachment, and end-to-end byte delivery are unknown.

Accordingly, this is **V-017: exact conditional cellular root-daemon memory
corruption**, not a demonstrated SMS-to-root path.

## Exact component identity

| Item | Exact evidence |
|---|---|
| RPM record | `ofono-0.6.8+5w.master.199-r1.corei7_64` |
| `/usr/sbin/ofonod` | SHA-256 `3f6daee7c2ccd4b4e222c73d3d22478a997ec336e8a9d65042805625d987ac32` |
| ELF Build ID | `f596c565c77e4abb24d6b5b516ffb2bd6110b1ee` |
| `ofono.service` | SHA-256 `acdd93595d4430dfdfca34f2953623489b87e96c49dadad7b1544f91033b0f2d` |
| `ofono.path` | SHA-256 `8df3c4ff684aa89f481e20e37f7cd2351fd1b3a155cfc36139740f316c351d42` |
| D-Bus policy | SHA-256 `d99fb5577a88af21b02ac0e1602c7c5979e00269f8d5263630280357899f549f` |
| `App::tms` policy | SHA-256 `00b8dfa4b1d74915fdfb27b88a1a94c8d769faa3cf2759e283623c063e86c897` |

The binary embeds a vendor build path ending in
`ofono/0.6.8-5w.master.199-r1/git/drivers/lgeqmimodem/sms.c`, plus the names
`lgeqmimodem` and `LGE IVI QMI modem driver`. This identifies the code family;
the instructions below establish the defects.

## Published fixes

The relevant upstream corrections are:

- `1a5fbefa59465bec80425add562bdb1d36ec8e23`, which addresses
  CVE-2023-4233 by rejecting address lengths greater than 20;
- `a90421d8e45d63b304dc010baba24633e7869682`, which additionally rejects
  address fields whose encoded value exceeds ten bytes;
- `5209fd65ff41653d7725e407ccc359c54bb3121f`, which addresses
  CVE-2023-2794 by rejecting deliver user data larger than the internal array;
- `2ff2da7ac374a790f8b2a0216bcb4e3126498225`, which addresses
  CVE-2023-4232 in `decode_status_report()`;
- `8d74bc66146ea78620d140640a0a57af86fc8936`, which addresses
  CVE-2023-4234 in `decode_submit_report()`;
- `02aa0f9bad3d9e47a152fc045d0f51874d901d7e`, which addresses
  CVE-2023-4235 in `decode_deliver_report()`;
- `305df050d02aea8532f7625d6642685aa530f9b0`, which addresses
  CVE-2024-7547 in `decode_command()`.

The recovered instructions have the source-availability checks that precede
those patches, but not the added destination bounds.

## Exact vendor QMI receive route

All addresses are file virtual addresses in this PIE.

Two callbacks in the embedded `lgeqmimodem` SMS region call
`ofono_sms_deliver_notify` at `0xa5580`:

- `0x4a8d6` passes a QMI direct-indication PDU and uses the same 16-bit length
  for total and TPDU lengths;
- `0x4a9e7` passes a stored/raw-read PDU and computes total length from the TPDU
  length plus the first-octet SMSC length.

Nearby embedded function and diagnostic strings identify these regions as
`event_notify`, `raw_read_cb`, `QMI_WMS_RAW_READ`, 3GPP message indications,
and PDU-length handling.

At `0xa55ee`, `ofono_sms_deliver_notify` calls the internal `sms_decode`
implementation at `0xae8a0` with `outgoing=FALSE`. Its output object is a
`0x128`-byte `struct sms` at caller `rsp+0x30`. Only after `sms_decode` returns
does `0xa55fb..0xa5601` check `sms+0x20` and proceed solely for
`SMS_TYPE_DELIVER`.

The exact dispatcher selects the incoming decoder from TP-MTI before returning:

| Incoming TP-MTI | Exact decoder entry | Relevant finding |
|---:|---:|---|
| `0` | `0xae980` / deliver body `0xadca0` | CVE-2023-4233, CVE-2023-2794 |
| `1` | `0xaeb30` | CVE-2023-4234 submit report |
| `2` | `0xae998` | CVE-2023-4232 status report |
| `3` reserved | `0xae980` | interpreted as deliver |

The decoder-specific copy therefore finishes before the QMI delivery handler's
late type rejection. This proves real vendor modem-to-parser routes for the
four incoming-direction findings. It does not prove that a remote sender,
carrier, or base station can make the production modem preserve and forward a
malformed, generally non-conforming TPDU.

## CVE-2023-4233 exact write

The address decoder at `0xada70` reads the address length and type, computes
`(addr_len + 1) / 2`, and at `0xadae7..0xadaed` checks only whether that many
source bytes remain. It has neither upstream destination rejection.

For a non-alphanumeric address, `0xadb48..0xadb70` writes two decoded lookup
bytes for each encoded byte to the address array at `sms+0x3c`; `0xadb78` adds
a terminator. Exhausting the one-byte length domain gives:

| Address length | Result | Count |
|---|---|---:|
| `0..20` | specification-bounded | 21 |
| `21..22` | oversized but still array-bounded | 2 |
| `23..255` | 23-byte address-array overflow | 233 |

At length 255, the decoder consumes 128 encoded bytes and writes 257 bytes. The
write ends at `sms+0x13d`, 21 bytes beyond the `0x128`-byte `sms` object. The
lookup constrains individual written bytes; this is not an arbitrary-byte-write
or code-execution demonstration.

## CVE-2023-2794 exact write

The deliver decoder stores UDL at `sms+0x68`, calls the exact
`sms_udl_in_bytes` routine at `0xad1c0`, and at `0xadd9e..0xadda0` checks only
whether enough source bytes remain. It then calls plain `memcpy@plt` at
`0xaddb0` with destination `sms+0x69`. The destination is 140 bytes; no
comparison with 140 precedes the call.

The packet-free deterministic model exhausts all 65,536 `(UDL,DCS)` byte pairs:

| Exact result when source bytes are present | Pairs |
|---|---:|
| Copy `0..140` bytes | 44,461 |
| Overwrite the array but remain inside the `sms` union | 10,235 |
| Write beyond the `0x128`-byte `sms` object | 10,840 |
| **Total** | **65,536** |

The maximum copy is 255 bytes: 115 beyond the user-data array and 64 beyond the
`sms` object.

## CVE-2023-4232 and CVE-2023-4234 exact writes

The incoming status-report decoder at `0xae998` stores its UDL/DCS fields, calls
`sms_udl_in_bytes` at `0xaeafd`, checks only source availability at
`0xaeb02..0xaeb05`, and calls plain `memcpy@plt` at `0xaeb1d`. The destination
is the 143-byte array at `sms+0x7c`; no comparison with 143 precedes the copy.
A 255-byte copy ends 83 bytes beyond the `0x128`-byte object.

The incoming submit-report decoder at `0xaeb30` handles both ACK and ERROR
forms. It calls `sms_udl_in_bytes` at `0xaec29`, checks only source availability
at `0xaec2e..0xaec31`, and calls plain `memcpy@plt` at `0xaec48`. Both forms use
a destination beginning at `sms+0x3f`; the corresponding capacities are 152
and 151 bytes. A 255-byte copy ends 22 bytes beyond the `sms` object.

Exhausting all 65,536 `(UDL,DCS)` pairs for each exact destination gives:

| Decoder destination | Bounded | Array overflow within `sms` | Beyond `sms` | Maximum beyond `sms` |
|---|---:|---:|---:|---:|
| Status report, 143 bytes | 45,040 | 5,821 | 14,675 | 83 bytes |
| Submit ACK report, 152 bytes | 46,833 | 15,689 | 3,014 | 22 bytes |
| Submit ERROR report, 151 bytes | 46,640 | 15,882 | 3,014 | 22 bytes |

The status and submit-report types are not accepted as DELIVER by the QMI
handler, but rejection occurs after these copies and is therefore not a memory
safety guard.

## Outgoing-only CVE-2023-4235 and CVE-2024-7547

For `outgoing=TRUE`, the dispatcher selects different decoders. The recovered
binary retains both missing destination checks:

- `decode_deliver_report()` begins at `0xaeea8`; after source availability at
  `0xaef53..0xaef56`, it copies through `memcpy@plt` at `0xaec48` or `0xaf026`
  into 159-byte ACK (`sms+0x2c`) or 158-byte ERROR (`sms+0x2d`) arrays. Maximum
  255-byte copies end three or four bytes beyond `sms`, respectively.
- `decode_command()` begins at `0xaeda0`; `0xaee83..0xaee86` checks only source
  availability, then `rep movsb` at `0xaee9e` copies the one-byte command-data
  length into a 156-byte array at `sms+0x59`. The maximum ends 48 bytes beyond
  `sms`.

These two decoders cannot be selected by the reviewed incoming QMI
`sms_decode(..., FALSE, ...)` call. Exact outgoing callers do exist:

- `0xb1953` uses `outgoing=TRUE` while loading serialized transmit-queue records
  from local storage and then duplicates the `0x128`-byte decoded object;
- `0xd8cbb` uses `outgoing=TRUE` in the SIM-Toolkit Send SMS parser and checks
  for SUBMIT or COMMAND only after decoding.

Thus CVE-2023-4235 and CVE-2024-7547 are exact shipped-code findings, but their
defensible entry conditions are local transmit-queue data or a modem/SIM
Toolkit proactive-command path—not the ordinary incoming SMS callback. Direct
unauthenticated over-the-air reachability is unproven.

## Exact caller and mitigations

In the reviewed `ofono_sms_deliver_notify` frame:

- `sms` begins at `rsp+0x30`;
- later scratch begins at `rsp+0x160`, or `sms+0x130`;
- the canary is at `rsp+0x1f8`, or `sms+0x1c8`.

In the incoming `ofono_sms_deliver_notify` frame, the maximum address write
reaches the later scratch area. Deliver copies reach it for 9,240 `(UDL,DCS)`
pairs; status reports for 13,075 pairs; and each submit-report form for 1,918
pairs. None of those incoming maxima directly reaches this caller's canary.
Later code initializes some scratch on reviewed paths, but the decoders and
handler can use object state before and after that point.

The outgoing-only deliver-report and command decoders run in different callers.
Their object-relative overrun sizes are exact, but this delivery-frame
scratch/canary layout must not be applied to them; their caller-frame overwrite
boundaries remain to be reconstructed. The exact incoming layout is more
constrained than generic advisory language, but it does not make the
out-of-bounds stores safe.

The ELF has:

- PIE;
- a non-executable stack;
- GNU RELRO with `BIND_NOW`;
- stack canaries;
- imports for both `memcpy` and `__memcpy_chk`.

The vulnerable deliver copy uses `memcpy`, not `__memcpy_chk`. The mitigations
therefore constrain exploitation but do not prevent the reviewed writes. No
attempt was made to bypass them, groom memory, or develop a control-flow
payload.

## Activation, uid, and SMACK

`ofono.service` contains:

```ini
ConditionPathExists=/tmp/telematics_code_TELEMATICS
Type=dbus
BusName=org.ofono
ExecStart=/usr/sbin/ofonod -nd
Restart=always
```

There is no `User=` or `Group=`, so systemd's system-service default is uid 0.
`smack-relabel-ro.sh` assigns `App::tms` as the executable label. The recovered
`tms` rules permit access to `_`, telematics data/log labels, and many
application labels, but SMACK remains an enforced boundary. Code execution in
this process would therefore be uid 0 in `App::tms`, not proven unrestricted
root.

`ofono.path` requires `/tmp/no_isa` and names `ofono.service`; the service also
requires the telematics marker. The boot script derives the telematics marker
from the MICOM modem option. No `multi-user.target.wants/ofono.path` symlink was
found in the recovered filesystem. The enabled `mof.service` has
`After=ofono.service`, but `After=` only orders units and does not activate the
other unit. Static activation machinery exists; production activation remains
unresolved.

## Claim boundary

### Established

- exact recovered RPM, binary, service, policy, and SMACK identities;
- exact vendor QMI direct-indication and raw-read calls into SMS delivery;
- exact incoming and outgoing decoder dispatch;
- late QMI-handler type rejection after incoming decoder completion;
- absence of both upstream address destination checks;
- absence of the deliver, status-report, submit-report, deliver-report, and
  command-data destination checks added by the cited fixes;
- exact out-of-bounds arithmetic and unfortified copies;
- local transmit-queue and SIM-Toolkit outgoing decode callers;
- conditional uid-0 service configuration and `App::tms` execution label;
- PIE, NX, full RELRO, and stack-canary mitigations.

### Not established

- the firmware or hashes installed on the owner's vehicle;
- telematics/no-ISA marker state or `ofono` unit activation on that vehicle;
- modem presence, QMI service registration, SIM/carrier attachment, or SMS
  receive state;
- preservation and delivery of the required incoming bytes from any cellular
  sender;
- malicious local transmit-queue data or a malformed SIM-Toolkit command;
- direct over-the-air reachability of the outgoing-only decoders;
- a dynamic crash in this exact service;
- instruction-pointer control, arbitrary code execution, SMACK escape,
  unrestricted root, persistence, CAN access, or safety impact.

## Remediation

1. Backport all cited fixes, retaining both the semantic address limit and the
   encoded-byte limit.
2. Reject every decoded user-data or command-data length larger than the exact
   destination before copying; retain independent source-availability checks.
3. Add malformed and boundary SMS decoder tests under ASan/UBSan, including
   every DCS family and both direct-indication and stored-message callbacks.
4. Isolate modem-controlled parsing from uid 0. Use a least-privileged parser
   process and a narrow broker for required device or D-Bus operations.
5. Keep SMACK confinement, reduce `App::tms` access to the minimum, and add
   systemd hardening and restart-rate limits.
6. Confirm that production images explicitly enable only the modem services
   required by the vehicle configuration.

## Safe disconnected-bench plan

Before any malformed control is considered:

1. hash the installed `ofonod`, service, and SMACK policy;
2. record unit enablement, marker state, process uid/label, modem device, QMI
   services, SIM/carrier state, and normal benign SMS behavior;
3. preserve serial/journal evidence and verify restart/recovery with only benign
   controls;
4. require separate owner approval for a process-crash-only malformed test on a
   disposable state—no payload, persistence, or privilege action.

The current VM remains NIC-free and has no emulated modem.

## Evidence and deterministic tooling

- Reviewed excerpt:
  `evidence/artifacts/network-candidates/ofono-sms-decoder-evidence.txt`,
  SHA-256 `5e081effe76b4f118d8f6008a6c29a15451e173cc928d20a642c288d00505ae5`
- Arithmetic model:
  `tools/uk_fw/ofono_sms_bounds_model.py`
- Tests:
  `tests/test_ofono_sms_bounds_model.py`
- Extended generated arithmetic report SHA-256:
  `c1676c7b5f5689c5ae568011206738a561a36d1158d2e364131bb0641fd02c45`
- Planning/checkpoint:
  `docs/agent-work/ofono-sms-decoder/`
- Full downloads, source history, disassemblies, and generated reports remain
  ignored under `work/public-vuln-research-20261101/`.
