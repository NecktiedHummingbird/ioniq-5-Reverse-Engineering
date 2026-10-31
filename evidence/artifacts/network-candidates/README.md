# Network candidate excerpts

Sanitized, reviewable excerpts for exact recovered network components. Full
firmware binaries, package databases, downloads, decompiler records,
disassemblies, and generated inventories remain under ignored `work/`.

These excerpts establish only the observations stated in their associated
reports. Component versions and compiled code do not by themselves establish
physical-interface exposure, a dynamic trigger, controlled execution, root
access, or applicability to the owner's installed firmware.

- `connman-cve-2026-115863-static-evidence.txt`: exact DHCPv6 DOMAIN_LIST parser,
  dispatch, conditional activation, and mitigation excerpt for V-015.
- `connman-cve-2023-28488-fortify-evidence.txt`: exact DHCPv4 pre-fix ordering,
  ordinary L2 activation, and recovered `__memcpy_chk`/libc fail-closed outcome
  for V-016. It contains no packet material.
- `ofono-sms-decoder-evidence.txt`: exact CVE-2023-4232 through CVE-2023-4235,
  CVE-2023-2794, and CVE-2024-7547 decoder bounds, incoming/outgoing
  directionality, vendor QMI and SIM-Toolkit/local callers, arithmetic, service
  identity, and SMACK/claim boundary for V-017. It contains no PDU, modem
  message, or packet material.
- `ofono-qmi-list-evidence.txt`: exact CVE-2024-7537 missing QMI list
  count/length validation, overflow-diagnostic four-byte fallback,
  allocation/copy-loop arithmetic, and modem trust boundary for V-018. It
  contains no QMI message, PDU, modem input, or packet material.
- `wpa-p2p-backport-evidence.txt`: exact recovered wpa_supplicant identities,
  conditional launch chain, and instruction-level proof that CVE-2015-1863 and
  CVE-2021-27803 are fixed. It contains no wireless frame or trigger material.
- `dropbear-inert-artifacts-evidence.txt`: exact dormant Dropbear package,
  template, public-key, and missing executable/socket/host-key evidence. It
  contains no private key, login attempt, listener, or credential material.
- `vbtd-cve-2017-0782-bnep-evidence.txt`: exact pre-fix BNEP remaining-length
  instructions in both PCB-selectable Broadcom BSA daemons, plus activation,
  privilege, and radio-reachability boundaries for V-019. It contains no
  Bluetooth packet, trigger, payload, or exploit material.
- `broadcom-bsa-sdp-small-max-exact-static.txt`: exact CVE-2017-13255/13256
  handler, initial/continuation, complete partial-attribute-helper, allocator,
  response-copy, and 64-byte minimum GKI user-capacity excerpts for both PCB-
  selectable BSA daemons. On explicit feasible-response-path and valid-state
  prerequisites, it rejects only the public small-maximum physical OOB-write
  mechanism while retaining the initial effective-limit exceedance and the low/
  invalid-MTU, corrupted-offset, runtime, and other-SDP unknowns. It contains no
  Bluetooth packet, PDU, malformed-input fixture, trigger, payload, or exploit
  material.
- `f0edf6571d2d58e66ee0b100ebe49c585d31489f.patch`: byte-for-byte retained
  public Android fix shared by CVE-2017-13255 and CVE-2017-13256, SHA-256
  `a0470c20592473144f8114cf41ab4cb2479fe2c108a4aa73fa4864eabd02ca34`.
- `broadcom-bsa-sdp-continuation-exact-static.txt`: exact FDE identities,
  result-count/continuation-offset register bindings, unsigned branch polarity,
  independent CCB expected-offset comparison, shared code-5 error routing,
  subtraction and later-indexing dominance, equality handling, and claim
  boundaries for CVE-2017-0785 in both PCB-selectable daemons. It contains no
  complete proprietary disassembly, Bluetooth packet/PDU, malformed fixture,
  trigger, payload, or exploit material.
- `226ea26684d4cd609a5b456d3d2cc762453c2d75.patch`: byte-for-byte retained
  public CVE-2017-0785 Android fix, SHA-256
  `6f80d9cd3534d00e24c9c33717a282f1e6ae180f05f833e502c7a361e86b2721`.
