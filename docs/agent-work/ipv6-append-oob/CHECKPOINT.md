# IPv6 append-data bounds audit checkpoint

## Result

V-029 records exact CVE-2017-9242 pre-fix ordering. Exact `__ip6_append_data` allocates a current skb and can perform the fraggap copy before computing and rejecting a negative `datalen - transhdrlen - fraggap` result. The upstream early-reject effect is absent from the complete function.

## Boundaries

- `CONFIG_IPV6=y` and exact `udpv6_sendmsg → ip6_append_data → __ip6_append_data.isra.28` static call flow are established.
- Achieving the required internal skb/fraggap state on the owner unit is unobserved.
- No actual overwrite, crash, controlled corruption, code execution, privilege gain, root, or persistence is established.
- NVD supports local denial of service; the upstream commit records skb head/shared-info overwrite but does not itself prove privilege escalation.

## Artifacts

- Assessment: `evidence/vendor-kernel-ipv6-cve-2017-9242.md`
- Reviewed excerpt SHA-256: `8e8f7ebab086d8777cf7da175330073eaef77304dd67ddc5c1efb006b3371cc9`
- Complete affected-function disassembly SHA-256: `a069864ba5f7c3645d7345038724496ba0d853b1ed0bb5187f89c4115eca2c98`
- Complete wrapper disassembly SHA-256: `04afd9d816b3895750f9117f2f76c1e5b6fdeec5a8a97a75de212bd4be25caa5`
- Upstream patch SHA-256: `9bb4c228e28f37e4c423271146cac5dc17977668b0bb3ff16c3725e3631b388d`
- Deterministic model-report SHA-256: `a4d17dd7516f2b01489a5f2f943ec8c5d041fa7b70a1f265419cad1164bd1cfd`

## Validation and review

- Focused validation: `7 passed, 77 subtests passed`.
- Complete validation: `446 passed, 131759 subtests passed`; public research harness: **PASS**.
- Independent semantic/model review: **ACCEPT** after adding branch-complete affected-function and wrapper disassemblies and correcting overwrite wording.
- No socket, syscall, packet, IPv6 option/fragment state, heap manipulation, target execution, overwrite, crash, privilege transition, update action, or persistence mechanism was created.
