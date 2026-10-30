# V-017 oFono SMS decoder exact-build review plan

## Objective

Determine whether the recovered EU Gen5W `260128` oFono daemon contains the
published SMS-decoder defects CVE-2023-4233 and CVE-2023-2794, whether an
authentic modem-to-parser route exists, and what the exact recovered build's
memory and privilege boundaries are.

## Baseline and identities

- Repository baseline: `11ec99a9f80f4e86c623ac4a1bbfd2477f74faa7`.
- Binary: `work/decrypted-eu-260128/extracted-safe/mango-rootfs/usr/sbin/ofonod`.
- Binary SHA-256: `3f6daee7c2ccd4b4e222c73d3d22478a997ec336e8a9d65042805625d987ac32`.
- RPM identity: `ofono-0.6.8+5w.master.199-r1.corei7_64`.
- Embedded build path identifies the vendor tree as
  `ofono/0.6.8-5w.master.199-r1` and the compiled modem driver as
  `drivers/lgeqmimodem`.

## Exact-code facts to preserve

All addresses below are file virtual addresses from the PIE, not runtime
addresses.

- Two vendor QMI SMS paths call `ofono_sms_deliver_notify` at `0xa5580`:
  - direct-transfer callback call at `0x4a8d6` passes the QMI-provided PDU and
    the same 16-bit length as both total and TPDU lengths;
  - stored/raw-read callback call at `0x4a9e7` derives total length from the
    TPDU length plus the first-octet SMSC length.
- `ofono_sms_deliver_notify` calls the internal `sms_decode` implementation at
  `0xae8a0` from `0xa55ee` and requires decoded type `SMS_TYPE_DELIVER` before
  normal handling continues.
- `sms_decode` dispatches deliver decoding to `0xadca0`.
- Address decoding is at `0xada70`. The exact binary checks remaining input
  bytes but has no `addr_len > 20` or `byte_len > 10` rejection before the
  non-alphanumeric BCD loop at `0xadb48..0xadb78`. The destination is the
  23-byte address array at `sms + 0x3c`; the pre-fix maximum writes 257 bytes.
- Deliver user-data decoding calls the exact `sms_udl_in_bytes` logic at
  `0xad1c0`, checks only source availability at `0xadd9e..0xadda0`, then uses
  plain `memcpy@plt` at `0xaddb0` into the 140-byte array at `sms + 0x69`.
  There is no destination-size check corresponding to upstream commit
  `5209fd65ff41653d7725e407ccc359c54bb3121f`.
- Upstream address fixes are
  `1a5fbefa59465bec80425add562bdb1d36ec8e23` and the later byte-length
  hardening `a90421d8e45d63b304dc010baba24633e7869682`.
- The `sms` object in `ofono_sms_deliver_notify` begins at `rsp + 0x30`, is
  `0x128` bytes, and the caller canary is at `rsp + 0x1f8`. Maximum address and
  deliver-data writes do not directly reach that canary in this exact caller;
  do not turn generic CVE wording into a demonstrated control-flow overwrite.
- The ELF is PIE, NX, full RELRO/BIND_NOW, and stack-canary protected. It
  imports both `memcpy` and `__memcpy_chk`; the vulnerable deliver copy is the
  unfortified `memcpy` call above.

## Activation and privilege boundaries

- `ofono.service` runs `/usr/sbin/ofonod -nd` without `User=`, so the process
  is uid 0 if started.
- `ConditionPathExists=/tmp/telematics_code_TELEMATICS` gates the service.
- `ofono.path` also requires `/tmp/no_isa`, but no recovered
  `multi-user.target.wants/ofono.path` symlink has been identified. `After=`
  references from other units order but do not pull the service in.
- `/etc/smack-relabel-ro.sh` assigns `security.SMACK64EXEC=App::tms` to
  `ofonod`. The recovered `App::tms` rules are broad but are still a mandatory
  access-control boundary; never describe this as unrestricted root.
- The exact owner vehicle's modem option, unit activation, cellular attachment,
  carrier/SMS delivery, and installed hashes are unknown. The NIC-free VM has
  no modem and must not be used to synthesize delivery.

## Deliverables

1. `tools/uk_fw/ofono_sms_bounds_model.py`: deterministic, packet-free model of
   the exact address and deliver-user-data length arithmetic. It must not emit
   PDUs, modem messages, network traffic, or exploit material.
2. `tests/test_ofono_sms_bounds_model.py`: unit and exhaustive-partition tests
   for the model.
3. `evidence/artifacts/network-candidates/ofono-sms-decoder-evidence.txt`:
   concise reviewed exact-instruction, service, policy, identity, and upstream
   patch evidence. Do not commit generated full disassemblies or downloaded
   pages from `work/`.
4. `evidence/ofono-sms-decoder-cves.md`: V-017 report with exact reachability,
   arithmetic, mitigations, and explicit limits.
5. Update the existing vulnerability inventory, CVE survey, network surface,
   prioritisation, handover, history/changelog, artifact index, and a compact
   `CHECKPOINT.md` consistently.

## Non-goals and safety boundaries

- No target-binary execution, QMI/modem emulation, crafted SMS/PDU generator,
  packet generation, heap grooming, shellcode, payload, persistence, privilege
  change, or root-transition demonstration.
- No claim that the owner's installed firmware is this build.
- No claim that a base station, carrier, modem, or sender can necessarily
  deliver the required bytes to this vendor QMI path.
- No claim of RCE. The accepted finding is exact pre-fix memory corruption in a
  conditional uid-0/`App::tms` cellular service, with runtime activation and
  exploitability unresolved.

## Acceptance criteria

- Model output reproduces the exact fixed-size boundaries: 23-byte address,
  140-byte deliver-data array, `0x128`-byte `sms`, caller base/canary offsets,
  and the recovered `sms_udl_in_bytes` arithmetic.
- Tests exhaust all 256 address lengths and all 65,536 `(UDL,DCS)` pairs and
  prove the classifications are complete and disjoint.
- Documentation distinguishes source availability checks from destination
  bounds, generic advisories from exact-build instructions, uid 0 from SMACK
  confinement, and unit files from observed production activation.
- Focused tests, full `pytest -q tests`, `py_compile`, `git diff --check`, and
  evidence hash checks pass.
- Original firmware and canonical VM rootfs remain unchanged.
