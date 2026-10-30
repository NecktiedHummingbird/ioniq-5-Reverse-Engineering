# Vendor AF_PACKET backport checks: CVE-2016-8655 and CVE-2017-1000111

Date: 2026-11-01
Target: EU Gen5W Linux `NE_E.EUR.S5W_L.001.001.260128`
Artifact: `/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko`

## Result

The recovered module contains the socket-locking changes from upstream commits
`84ac7260236a49c79eede91617700174c2c19b0c` and
`c27927e372f0785f3303e8fad94b85945e2c97b7`. CVE-2016-8655 and
CVE-2017-1000111 are therefore not defensible AF_PACKET local-root candidates
for this exact recovered build, regardless of its `4.1.27-abl` version banner.

Module SHA-256:
`c810265b3c22f95d2b90494cc206abd6b4e67b7710bff2adcb177ee4867f467b`.
The module retains local symbols, permitting a direct check rather than a
version-only inference.

## Binary evidence

`packet_set_ring` starts at module `.text+0x1f5d`. Before checking the requested
ring/version state it calls `lock_sock_nested`:

```text
0000000000001f91  call ...
  R_X86_64_PC32 lock_sock_nested-0x4
```

All exits converge through the corresponding `release_sock` relocation near
`.text+0x239a`. In the vulnerable implementation the lock was acquired only
after ring allocation and initialization had already begun.

The `PACKET_VERSION` branch in `packet_setsockopt` also has the fixed ordering:

```text
.text+0x3bf6  validate version <= TPACKET_V3
.text+0x3c10  call lock_sock_nested
.text+0x3c15  test rx_ring.pg_vec
.text+0x3c1f  test tx_ring.pg_vec
.text+0x3c2c  store tp_version
.text+0x3c38  call release_sock
```

This is the synchronization pair added by the CVE-2016-8655 fix to prevent
racing a TPACKET_V3 ring initialization against a version change to TPACKET_V1.

The immediately following `PACKET_RESERVE` branch independently contains the
later CVE-2017-1000111 fix:

```text
.text+0x3cc5  reject negative/out-of-range reserve
.text+0x3cda  call lock_sock_nested
.text+0x3cdf  test rx_ring.pg_vec
.text+0x3ced  test tx_ring.pg_vec
.text+0x3cfe  store tp_reserve
.text+0x3d04  jump to the shared release_sock path
```

Retained local artifacts:

- `work/public-vuln-research-20261101/af_packet-packet_set_ring.asm`;
- `work/public-vuln-research-20261101/af_packet-packet_setsockopt.asm`;
- upstream patches `work/public-vuln-research-20261101/cve-2016-8655-fix.patch`
  and `work/public-vuln-research-20261101/cve-2017-1000111-fix.patch`.

## Boundary

This rejects CVE-2016-8655 and CVE-2017-1000111 only. It does not validate
other AF_PACKET defects, does not establish that an unprivileged application has
`CAP_NET_RAW`, and does not describe the owner's unknown installed build. CVE
candidates must be checked against each shipped module rather than inferred from
the base kernel release.
