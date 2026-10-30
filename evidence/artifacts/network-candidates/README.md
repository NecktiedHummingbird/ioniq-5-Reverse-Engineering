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
- `ofono-sms-decoder-evidence.txt`: exact CVE-2023-4233/CVE-2023-2794 missing
  bounds, vendor QMI callbacks, arithmetic, service identity, and SMACK/claim
  boundary for V-017. It contains no PDU, modem message, or packet material.
