# Recovered EU `260128` wpa_supplicant P2P CVE review

Status: **the exact recovered binary contains the fixes for CVE-2015-1863 and
CVE-2021-27803. P2P capability and conditional launch machinery are present,
but these two published vulnerabilities are not accepted against this build.
Production P2P activation and radio state remain unknown.**

Target: recovered European Gen5W Linux
`NE_E.EUR.S5W_L.001.001.260128`. The owner's installed firmware is unknown. No
physical unit, target execution, radio, wireless frame, network-enabled VM, P2P
discovery, pairing, or malformed input was used.

## Executive conclusion

The package and binary advertise `wpa_supplicant v2.5`, but version-only CVE
matching is wrong for this vendor build:

- `p2p_add_device()` contains CVE-2015-1863's exact `length <= 32` gate on
  the SSID copy path;
- `p2p_process_prov_disc_req()` contains CVE-2021-27803's exact unconditional
  peer relookup after `p2p_add_device()`.

The recovered system can conditionally start the supplicant as part of its
normal Wi-Fi stack, and both wpa_supplicant and ConnMan contain substantial P2P
machinery. That establishes relevance of the code review, not runtime exposure.
No vulnerability ID is assigned for either rejected candidate.

## Exact identities

| Item | Exact evidence |
|---|---|
| RPM record | `wpa-supplicant-2.5+56-r1.corei7_64` |
| `/usr/sbin/wpa_supplicant` | SHA-256 `6ad96a34c09b66c29ed2f9ad7ae73dee8389c81064a30dfd36a1212c52a21212` |
| ELF Build ID | `387944d45d54ccfef07ede83a517c59344f9447a` |
| Embedded version | `wpa_supplicant v2.5` |
| `/app/bin/supplicantmanager` | SHA-256 `331e1e8a4a2d24ac9c74a7dba8232a8f37c093b526e5a19991549112c217cc59` |
| `supplicantmanager.service` | SHA-256 `9f31f774e985532b9549197d67fc1b3fad012330fbf4f93bee7baace5b999a3e` |
| `supplicantmanager.path` | SHA-256 `75642c7c16284e17f035391cd38688db0ea763361dcf4d8d3dc2b248915c5cbb` |

The supplicant is x86-64 PIE/DYN with NX stack, GNU RELRO, `BIND_NOW`, stack
canaries, and checked-libc imports. These are secondary constraints; exact
fixed control flow decides these two CVEs.

## CVE-2015-1863: fixed in the exact binary

Upstream commit `9ed4eee345f85e3025c33c6e20aa25696e341ccd` added one essential
check to `p2p_add_device()`: do not enter the fixed SSID-field copy path when
the peer-controlled length exceeds 32 bytes.

The recovered function starts at static ELF virtual address `0x5b040`. At
`0x5b1ca..0x5b1d3`, it loads the SSID element length, compares it with `0x20`,
and branches to `0x5b22e` when the value is greater. Only the bounded path forms
the SSID value pointer at `0x5b1d5` and reaches the copy sequence.

This instruction pattern is the upstream fix's compiled effect. The old version
string does not make this binary vulnerable to CVE-2015-1863.

## CVE-2021-27803: fixed in the exact binary

The vulnerable corner case requires a full peer table. An invalid Provision
Discovery Request can make `p2p_add_device()` evict the oldest entry, which may
be the entry held by the caller's pre-existing `dev` pointer. Pre-fix code
looked up `dev` after the add only when the old pointer had been NULL, so an old
non-NULL pointer could remain stale.

Upstream commit `8460e3230988ef2ec13ce6b69b687e941f6cdb32` made the
post-add `p2p_get_device(p2p, sa)` unconditional.

The recovered request handler begins at `0x68490`:

1. `0x68571` performs the initial lookup;
2. `0x688e8` calls recovered `p2p_add_device()` at `0x5b040`;
3. successful return branches to `0x68de8`;
4. `0x68dee` unconditionally calls the lookup routine at `0x525a0` with the
   source address;
5. `0x68df3` replaces the working peer pointer with that result;
6. only a non-NULL re-fetched pointer continues; otherwise the diagnostic whose
   string is at `0x14cd70` is emitted.

No test of the old `dev` pointer guards the call at `0x68dee`. This is the fixed
control flow, not the vulnerable conditional relookup.

## Launch chain and runtime gates

The recovered filesystem enables
`multi-user.target.wants/supplicantmanager.path`. That path watches
`/tmp/no_unece` and names `supplicantmanager.service`. The service:

- requires D-Bus and `ApplicationLauncher.service`;
- loads `cfg80211` in `ExecStartPre`;
- starts `/app/bin/supplicantmanager`;
- uses `Restart=always`;
- has no `User=` or `Group=` and therefore defaults to uid 0 if started.

The manager's exact `start_wpa_supplicant()` executes
`/usr/sbin/wpa_supplicant`, parses optional `WPA_SUPPLICANT_PARAMS`, and embeds
the `wlan0` Broadcom firmware/NVRAM configuration. Static search found no other
recovered text unit or script creating `/tmp/no_unece`; production marker
creation remains unresolved.

## P2P capability versus P2P exposure

P2P is compiled into the exact supplicant; the reviewed functions are not dead
source from another package. Exact ConnMan additionally exports
`connman_peer_create`, `connman_peer_register`,
`connman_peer_request_connection`, and related peer APIs, and contains
`fi.w1.wpa_supplicant1.Interface.P2PDevice`, `p2p_find`, `p2p_listen`,
provision-discovery, and GO-negotiation code paths.

This proves the recovered Wi-Fi management stack is P2P-capable. It does not
prove that production configuration enables a P2P device, enters find/listen,
keeps the adapter discoverable, fills the peer table, or delivers hostile radio
management frames to the reviewed parser.

The service files also do not establish the runtime SMACK label. No explicit
`supplicantmanager`/`wpa_supplicant` entry was found in the reviewed static
relabel script; actual xattrs and inherited process labels should be captured on
a physical bench rather than inferred.

## Claim boundary

### Established

- exact package, binary, manager, unit, and path identities;
- conditional path-unit activation and exact exec relationship;
- compiled wpa_supplicant and ConnMan P2P capability;
- CVE-2015-1863's exact `length <= 32` gate dominating the SSID copy;
- CVE-2021-27803's exact unconditional post-add peer relookup;
- PIE, NX, RELRO/BIND_NOW, and canary hardening.

### Not established

- the firmware/hash installed on the owner's vehicle;
- `/tmp/no_unece`, actual `WPA_SUPPLICANT_PARAMS`, or process launch;
- runtime uid/SMACK label, ConnMan ownership, P2P interface creation,
  discovery/listen state, peer-table occupancy, discoverability, or pairing;
- physical management-frame delivery;
- dynamic behavior, crash, memory corruption, code execution, root access,
  persistence, CAN access, or safety impact.

## Remediation and bench validation

The two reviewed fixes should be retained in every vendor branch regardless of
reported package version. Regression tests should directly assert the
SSID copy-length gate and unconditional post-add lookup.

On a disconnected owner-controlled bench, first capture installed hashes,
service/path state, `/tmp/no_unece`, exact launch arguments, process uid/SMACK
label, interface ownership, and passive P2P discovery/listen state. Verify
restart/recovery using benign controls only. Do not introduce malformed frames
without separate approval and disposable state.

## Evidence

- Reviewed excerpt:
  `evidence/artifacts/network-candidates/wpa-p2p-backport-evidence.txt`, SHA-256
  `54b16ddc9c7692310e49db172a0b9353fc9baba2b888bcb3633cb30a1100f137`
- Upstream fixes:
  `9ed4eee345f85e3025c33c6e20aa25696e341ccd` and
  `8460e3230988ef2ec13ce6b69b687e941f6cdb32`
- Full source history, patches, and disassembly remain ignored under
  `work/public-vuln-research-20261101/online/wpa/`.
