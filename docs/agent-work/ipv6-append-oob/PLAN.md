# IPv6 append-data bounds audit plan

## Objective

Determine whether the exact recovered kernel retains CVE-2017-9242's too-late negative-copy check in `__ip6_append_data`, and classify local impact without creating crafted syscalls, packets, socket state, or an overwrite.

## Acceptance criteria

1. Preserve authoritative public provenance for CVE-2017-9242 and upstream fix commit `232cd35d0804cc241eb887bb8d4d9b3b9881c64a`.
2. Bind exact allocation, `skb_copy_and_csum_bits`, trim, copy arithmetic, negative check, and error cleanup ordering in recovered machine code.
3. Determine whether the upstream early-reject effect is present, including equivalent vendor control flow rather than only source-shaped opcodes.
4. Record exact IPv6 configuration and separate static syscall surface from observed runtime socket/policy reachability.
5. Separate affected ordering, achievable crafted state, overwrite, crash, controlled corruption, code execution, privilege gain, and persistence.
6. Add a reviewed instruction excerpt, authoritative patch, Boolean-only deterministic model, complete truth-table tests, and explicit safety boundaries.
7. Obtain independent semantic/model review before committing.

## Safety boundary

No socket, syscall, packet, IPv6 option, fragment state, target-kernel execution, heap grooming, overwrite, crash, privilege transition, update action, or persistence mechanism.

## Routing note

The configured DeepSeek Flash builder remains unavailable to native dispatch (`Unknown model deepseek:deepseek-v4.1-flash`) and Fable is not advertised for native subagents. Root execution uses authoritative public sources and read-only local artifacts without sharing private target context with an unverified substitute.
