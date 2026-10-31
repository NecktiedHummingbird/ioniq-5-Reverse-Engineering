# Recovered EU `260128` Broadcom BSA Bluetooth CVE review

Status: **both PCB-selectable `vbtd` variants contain CVE-2017-0782's exact
pre-fix BNEP remaining-length parser (V-019), but recovered engineering-profile
configuration says `PAN : N/A` for both variants and no direct startup reference
to `BNEP_Register` was found. Treat this as dormant/conditionally reachable code
pending BNEP PSM/profile-registration evidence. Separately, exact static review
conditionally rejects only CVE-2017-13255/13256's public small-maximum physical
OOB-write mechanism in both variants: their SDP scratch allocations use remote
MTU and successful GKI user capacity is at least 64 bytes. On a feasible
ordinary response-building path, effective internal maxima 0..2 can still
exceed their logical limits by reaching scratch offset 2. Adapter
state, security policy, accepted channels, physical delivery, runtime behavior,
RCE, and owner-device applicability remain unproven. Other Android/Bluedroid
CVEs are not transferred to BSA without exact code proof.**

Target: recovered European Gen5W Linux
`NE_E.EUR.S5W_L.001.001.260128`. Static instruction, filesystem, policy, and
public-fix comparison only. No target execution, adapter, radio, packet,
pairing, connection, malformed input, or exploit material was used.

## Exact selectable stacks

| PCB route | Binary | Exact identity |
|---|---|---|
| PCB version 11 or 12 | `/app/bin/vbtd-63` | SHA-256 `c56b68fdd35b16b95688ab54a48ffb9f18034d925c057e86f8b9fe304f8b26b9`; Build ID `04141ed222ee8f150c0eb0e46fdb73624d168920`; `BSA0107_00.63.00` |
| Other PCB value | `/app/bin/vbtd-51` | SHA-256 `55e21d077082e97f56fb113a1d3b216c0f2e63aa02fc4cd754a6593bc6cec9e0`; Build ID `12175aa88ccff70cc56498e0208c9a51aac0c9e9`; `BSA0107_00.51.00` |

`/etc/setup_bt_patchram.sh` reads the MICOM `pcb_version`, selects the matching
Broadcom patchram and binary, and creates `/tmp/vbtd` plus
`/tmp/bt_patchram.hcd`; `/app/bin/vbtd` resolves through that temporary binary
link. `vbtd.service` is enabled from `multi-user.target`, runs
`/app/bin/vbtd -d /dev/ttyS0 -p /tmp/bt_patchram.hcd`, and restarts always. Its
mandatory `EnvironmentFile=/tmp/session_appmgr.env` is an additional runtime
startup/timing gate.

Neither the setup script nor service supplies `User=`/`Group=`, so the intended
service defaults to uid 0. Recovered relabel policy assigns `App::bluetooth`, a
broad application-facing SMACK domain but not unrestricted system access. Both
ELFs are x86-64 PIE with NX stack, RELRO/BIND_NOW, and canaries.

Both binaries export substantial BSA stack code, including BNEP, PAN, SDP,
L2CAP, AVDT/A2DP, AVRCP, PBAP, MAP, OPP, and HFP functions. Code presence and an
enabled unit do not prove that every profile is registered or remotely
accessible. In fact, both recovered engineering profile files explicitly say
`PAN : N/A`. Bounded call-reference review found stack startup calling
`BNEP_Init` (`vbtd-51` `0x84f691`; `vbtd-63` `0x84fbd1`) but no direct reference
to exported `BNEP_Register` (`0x8bf470`/`0x8c1920`). This does not exclude an
indirect or runtime registration path, but it is contrary evidence that must be
resolved before claiming radio reachability.

## CVE-2017-13255 / CVE-2017-13256: physical mechanism conditionally rejected

The public shared fix
`f0edf6571d2d58e66ee0b100ebe49c585d31489f` adds
`max_list_len < 4` rejection to `process_service_attr_req` (CVE-2017-13255,
Android bug 68776054) and `process_service_search_attr_req` (CVE-2017-13256,
Android bug 68817966) before a requested-maximum-sized allocation. The exact
BSA handlers lack an equivalent early guard, but their allocator/caller
architecture is materially different.

The `0..3` matrix is the effective internal maximum after the recovered remote-
MTU cap. It is equivalent to a small peer-requested maximum only under an
ordinary protocol-valid remote MTU; low/invalid remote-MTU subtraction behavior
remains unknown. After valid syntax reaches ordinary response-list construction
and scratch allocation/reuse succeeds, initial state starts the scratch cursor
at base + 3, while accepted valid continuation state starts at base and skips
outer initial-header construction. Initial body construction is then blocked
for effective maxima 0..3, and the outer header can reach no higher than offset
2. Complete `sdpu_build_partial_attrib_entry` ranges in both binaries prove
valid-state copy length and destination advancement are clamped to
`min(remaining, total serialized length - state-derived attr_offset)`.
Corrupted or impossible internal offsets remain unknown. Thus effective maxima
0..2 retain a logical limit exceedance on the feasible initial path, but the
largest proven scratch extent is three bytes. Earlier error exits are outside
this write matrix.

Both handler allocation call sites pass CCB remote MTU rather than the effective
internal maximum. Exact `GKI_getbuf[_r]` selection requires pool capacity
greater than or equal to the request; exact `gki_buffer_init` independently sets
pool 0 user capacity to `0x40` in both binaries. Allocation failure is checked
before scratch writes. Consequently every successful effective-small-maximum
scratch write on the stated path remains within at least 64 user bytes. This
conditionally rejects only the public physical OOB-write mechanism; it does not
establish general SDP or partial-helper safety, runtime handler reachability,
adapter/channel/security policy, controlled behavior, impact, or owner-device
applicability.

See
[`broadcom-bsa-sdp-small-max-cves.md`](broadcom-bsa-sdp-small-max-cves.md), the
[retained exact-static excerpt](artifacts/network-candidates/broadcom-bsa-sdp-small-max-exact-static.txt),
and the [byte-identical public patch](artifacts/network-candidates/f0edf6571d2d58e66ee0b100ebe49c585d31489f.patch).

## V-019 / CVE-2017-0782: exact pre-fix BNEP parser in both variants

The September 2017 Android bulletin links three fixes for CVE-2017-0782:

- `4e47f3db62bab524946c46efe04ed6a2b896b150` adds a PAN receive-buffer
  capacity check before a copy;
- `1b08775917413f1674882130a948add1ae44cc91` adds remaining-length checks
  before each field read in `bnep_process_control_packet()`;
- `c568fa9088ded964e0ac99db236e612de5d82177` corrects extension-length
  advancement.

The exact binaries retain the second commit's pre-fix control flow.

### `vbtd-51`

The exported parser starts at `0x8c5020`. For an extended control packet it
computes `remaining-1` at `0x8c5052`, reads the extension length at `0x8c5056`,
reads the control type at `0x8c5062`, and subtracts again at `0x8c506a`. Only at
`0x8c507c`, after both reads, does it compare the wrapped current value with the
original. The non-extended path at `0x8c50a0..0x8c50a6` reaches the same control
byte read without first proving that one byte remains. Later switch cases also
retain pre-fix multi-byte reads, including `0x8c5130`/`0x8c5139`.

### `vbtd-63`

The second variant has the same structure at `0x8c7480`: extension/control reads
at `0x8c74b6`/`0x8c74c2`, the first wrap comparison only at `0x8c74dc`, the
non-extended route at `0x8c7500..0x8c7506`, and later two-byte reads at
`0x8c7590`/`0x8c7599`.

The embedded diagnostics also retain the pre-fix `"BNEP - bad ctl pkt length"`
family. Exact instructions—not that string alone—establish the missing pre-read
bounds.

## Reachability and attacker state

BNEP is Bluetooth Network Encapsulation Protocol, normally used by PAN over an
L2CAP channel. The recovered `PAN : N/A` settings and missing direct
`BNEP_Register` reference do not establish a live route. If an
indirect/runtime registration exists, a proximate peer would still need an ACL
link and an accepted BNEP/PAN channel whose data reaches the parser. The public
Android severity does not prove this vehicle's profile security policy.

The recovered evidence does not determine:

- selected owner PCB, binary, controller patchram, or installed hash;
- adapter power, discoverability/connectability, or vehicle power mode;
- PAN/BNEP profile registration;
- whether pairing, bonding, user confirmation, or prior trust is required;
- L2CAP/BNEP channel acceptance or service-level authorization;
- whether a malformed short control packet is preserved through controller/HCI;
- restart behavior after a parser fault.

Therefore V-019 is a dormant parser-code finding pending registration evidence,
not a demonstrated unpaired radio-to-root chain.

## Impact boundary

Both variants read beyond the parser's declared packet/remaining-length boundary
before validation and retain 16-bit remaining-length underflow. The instructions
do not prove that a read leaves the backing GKI allocation rather than consuming
pool slack. The generic Android bulletin classifies CVE-2017-0782 as critical
RCE, but that is not the demonstrated outcome here. No allocation-bound OOB
read, crash, disclosure contents, overwrite,
controlled execution, shell, SMACK escape, unrestricted root, persistence, CAN
access, or safety impact was produced.

PIE, NX, RELRO/BIND_NOW, and canaries constrain outcomes but do not fix the
parser. `App::bluetooth` would further constrain outcomes only if recovered
relabel policy is applied at runtime. The configured uid-0 default still makes a
successful memory-safety failure materially important if the service starts.

## Other public Bluetooth candidates: transfer requires exact proof

The binaries' shared Broadcom/Bluedroid genealogy makes old public fixes useful
comparison targets, but an AOSP CVE is not automatically a BSA finding:

| Candidate | Public area | Recovered status |
|---|---|---|
| CVE-2017-0781 | BT_HDR allocation sizing across AVDT/BNEP/L2CAP/MCAP; fix `c513a8ff5cfdcc62cc14da354beb1dd22e56be0e` plus `1e0bb31f6a809b49014483dc118b9d9ad31ade68` | Related protocol code exists; exact BSA GKI allocator and affected call-site semantics are incomplete. **Not accepted.** |
| CVE-2017-0783 | PAN role-interaction information disclosure; fix `1e77fefc8b9c832239e1b32c6a6880376065e24e` | PAN/BNEP exists; exact role-policy comparison and practical disclosure are incomplete. **Not accepted.** |
| CVE-2017-0785 | SDP continuation-state information disclosure; fix `226ea26684d4cd609a5b456d3d2cc762453c2d75` | SDP server exists; exact `num_rsp_handles < cont_offset` comparison is incomplete. **Not accepted.** |
| CVE-2017-13262 | missing BNEP extension-length decrement; fix `a50e70468c0a8d207e416e273d05a08635bdd45f` | The exact receive loops decrement remaining length before calling the extension parser (`vbtd-51` `0x8c0b1b`; `vbtd-63` `0x8c2ef3`), matching the named mechanism's fix. The separate parser-field defect remains V-019. **Rejected for the exact missing-decrement mechanism.** |
| CVE-2018-9355 | `bta_dm_sdp_result()` 32×16-byte local UUID-list overflow; fix `99a263a7f04c5c6f101388007baa18cf1e8c30bf` | The named function exists, but target `vbtd-51` uses a `0x28`-byte frame and global search state rather than the AOSP 512-byte local UUID array. No equivalent write was established. **Not transferred/accepted.** |
| CVE-2018-9588 | `avdt_scb_hdl_report()` AVDT reporting bounds; fix `bf9ff0c5215861ab673e211cd06e009f3157aab2` | The native function exists in both daemons; exact field-by-field fix comparison is incomplete. Requires an active AVDTP reporting channel. **Not accepted.** |
| CVE-2019-2025 | Android Binder `binder_thread_read()` local kernel UAF | Not a Bluetooth flaw and not evidence against `vbtd`. **Excluded.** |
| CVE-2020-0022 (BlueFrag) | Android `hci/src/packet_fragmenter.cc::reassemble_and_dispatch()` offset accounting; fix `3cb7149d8fed2d7d77ceaa95bf845224c4db3baf` | The named Android packet-fragmenter architecture/symbol is absent; BSA uses a different GKI/HCI path. An equivalent BSA reassembly flaw has not been established. **Not transferred/accepted.** |

Android framework, JNI, Binder, Java service, or Android-only ownership flaws
must be excluded unless their vulnerable native operation exists independently
inside these BSA ELFs and has a vehicle-specific caller. Profile names alone are
not equivalence evidence.

## Remediation

Apply all three bulletin-linked CVE-2017-0782 fixes to both BSA branches; the
current exact evidence directly proves absence of the field-by-field parser fix,
not independent absence of every mechanism covered by the other two commits.
Reject before every read or length
subtraction; use non-wrapping `size_t` accounting and one packet-end invariant.
Apply the fix to BNEP even if PAN is normally disabled, then regression-test
both binaries under memory sanitizers with boundary-only parser fixtures.

Reduce service privilege, narrow `App::bluetooth`, disable unused PAN/BNEP and
other profiles, require authenticated/authorized channels, make discoverability
short-lived and user-driven, and add bounded restart diagnostics.

## Disconnected-bench plan

Before any malformed control is considered, passively record installed binary
hash/Build ID, PCB value, selected patchram, service/process uid and SMACK label,
adapter address/state, discoverable/connectable/pairable flags, registered SDP
records, enabled profiles, bond list, and normal connection/restart behavior.
A benign paired PAN control should be approved separately. The current NIC-free
VM must remain radio-free.

## Evidence

- SDP small-maximum assessment:
  `evidence/broadcom-bsa-sdp-small-max-cves.md`
- SDP exact-static excerpt:
  `evidence/artifacts/network-candidates/broadcom-bsa-sdp-small-max-exact-static.txt`,
  SHA-256 `414d7bc0687960762c15b8e270eac9aaa2a5ae660b15c00feff9a5a5d9a1d2f2`
- Byte-identical SDP public patch:
  `evidence/artifacts/network-candidates/f0edf6571d2d58e66ee0b100ebe49c585d31489f.patch`,
  SHA-256 `a0470c20592473144f8114cf41ab4cb2479fe2c108a4aa73fa4864eabd02ca34`
- Reviewed exact BNEP excerpt:
  `evidence/artifacts/network-candidates/vbtd-cve-2017-0782-bnep-evidence.txt`,
  SHA-256 `2eb54a9c6328597226478a69ca2f23f616fc622ac64ed824e2a7ad3746428f44`
- Unit SHA-256:
  `eff7324fe0c75fa1ce393a01cc58fae21c67f49421be4b7ef81cb333c9960a61`
- PCB-selection script SHA-256:
  `b545941d834c3d66abc8b3ec3373abe53c4c043b3290b0362a76b06f6eb1af0d`
- Public patches and complete disassembly remain ignored under
  `work/public-vuln-research-20261101/online/bluetooth/`.
