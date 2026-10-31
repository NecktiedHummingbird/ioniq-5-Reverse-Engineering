# Vendor AF_PACKET backport checks: CVE-2016-8655, CVE-2017-7308, and CVE-2017-1000111

Date: 2026-11-01
Target: EU Gen5W Linux `NE_E.EUR.S5W_L.001.001.260128`
Artifact: `/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko`

## Result

The recovered module contains the socket-locking changes from upstream commits
`84ac7260236a49c79eede91617700174c2c19b0c` and
`c27927e372f0785f3303e8fad94b85945e2c97b7`. CVE-2016-8655 and
CVE-2017-1000111 are therefore not defensible AF_PACKET local-root candidates
for this exact recovered build, regardless of its `4.1.27-abl` version banner.

The module also contains the 64-bit private-area arithmetic from the primary
CVE-2017-7308 fix `2b6867c2ce76c596676bec7d2d525af525fdc6e2`, rejecting the
published `tp_sizeof_priv` signedness/overflow primitive. It does **not** contain
the companion `tp_frame_nr` multiplication guard from
`8f8d28e4d6d815a391285e121c3a53a0b6cb9e7b`. Public-source follow-up found no
documented standalone corruption, privilege escalation, or denial of service
from that omitted guard. However, exact code places the multiplication on the
common V1/V2/V3 ring path and later retains `tp_frame_nr - 1` as `frame_max`;
V1/V2 allocation/indexing consequences remain unresolved. It is therefore an
impact-unknown validation gap, not an assigned exploit primitive or a proved
hardening-only defect.

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

For CVE-2017-7308, the exact TPACKET_V3 private-area check zero-extends
`req3.tp_sizeof_priv` and performs `BLK_PLUS_PRIV` arithmetic in 64 bits before
comparing it with the zero-extended block size:

```text
.text+0x2084  mov  edx,[r12+0x14]    # tp_sizeof_priv, zero-extended
.text+0x208b  add  rdx,7
.text+0x208f  and  rdx,-8
.text+0x2093  add  rdx,0x30
.text+0x2097  cmp  rcx,rdx           # block size versus 64-bit result
.text+0x209a  jbe  invalid
```

This is the code-generation effect of the upstream `(u64)tp_sizeof_priv` fix;
the vulnerable expression could wrap in 32 bits before its signed test. However,
the later frame-count check still multiplies in 32 bits:

```text
.text+0x20b6  div  ecx               # frames_per_block
.text+0x20c2  mov  r13d,[r12+0x4]    # tp_block_nr
.text+0x20c7  imul eax,r13d
.text+0x20cb  cmp  eax,[r12+0xc]     # tp_frame_nr
```

There is no preceding `tp_block_size > UINT_MAX / tp_block_nr` rejection added
by companion commit `8f8d28e4...`. The published Project Zero privilege chain
centres on the fixed private-area bug and states that `tp_frame_nr` is ignored
for block-based TPACKET_V3. Upstream's commit and mailing-list submission assign
no crash, out-of-bounds access, privilege escalation, or standalone DoS to the
frame-count check. The kernel PACKET_MMAP documentation calls `tp_frame_nr`
redundant. That observation is specific to TPACKET_V3: the exact multiplication
at `.text+0x20c7` is on the common version path, and later code stores
`tp_frame_nr - 1` as the ring's `frame_max` at `.text+0x226c..0x226e`. Later
commit `fc62814d690cf62189854464f4bd07457d5e9e50` narrowed the over-broad
original guard after it blocked 4 GiB rings, while preserving the non-wrapping
invariant. Thus public sources do not assign a standalone impact, but they also
do not settle V1/V2 consumers in this exact build. The missing check remains an
impact-unknown validation candidate pending those allocation/indexing traces.

Public references:

- <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8f8d28e4d6d815a391285e121c3a53a0b6cb9e7b>;
- <https://lore.kernel.org/all/b6e4098bf0d0bccc538e133ce5200432be8c4732.1490796500.git.andreyknvl%40google.com/>;
- <https://docs.kernel.org/networking/packet_mmap.html>;
- <https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html>;
- <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fc62814d690cf62189854464f4bd07457d5e9e50>.

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

- tracked exact excerpt
  `evidence/artifacts/kernel-candidates/af-packet-cve-2017-7308.asm`;
- `work/public-vuln-research-20261101/af_packet-packet_set_ring.asm`;
- `work/public-vuln-research-20261101/af_packet-packet_setsockopt.asm`;
- upstream patches `work/public-vuln-research-20261101/cve-2016-8655-fix.patch`
  and `work/public-vuln-research-20261101/cve-2017-1000111-fix.patch`;
- ignored online records under
  `work/online-kernel-candidates-20261101/cve-2017-7308/`: CVE JSON SHA-256
  `dd5c5220fbbbc4e48aa2ad4d95c83aaaaeb4499f70615440bd5e6aaea792149c`,
  upstream primary-fix patch SHA-256
  `a2a31d146687d372bdbe3b40d3a04bf46d544a0d15901664b2ed2130b243a474`,
  companion frame-count-fix patch SHA-256
  `3e84b1acd9dd82dd0aedbb2ef301ce181993a2f68e106d1e3117d4608571b340`,
  and Project Zero article capture SHA-256
  `02d5b421fe672bd8bf449be2c57aaf72077aa9bdc6ea97f4e271de863b9c49d7`.

## Boundary

This rejects CVE-2016-8655, CVE-2017-1000111, and CVE-2017-7308's published
private-area primitive only. The missing companion frame-count guard remains a
real validation gap: no standalone security impact was found in reviewed public
sources, while exact V1/V2 consequences remain untraced. None of these static
checks establishes that an application has `CAP_NET_RAW`, that a packet-ring
version is reachable under its effective SMACK/capability state, or that the
owner's unknown installed build matches this module. CVE
candidates must be checked against each shipped module rather than inferred from
the base kernel release.
