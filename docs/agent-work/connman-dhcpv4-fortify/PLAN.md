# ConnMan DHCPv4 CVE-2023-28488 exact-build review plan

## Objective

Determine whether recovered EU `260128` retains CVE-2023-28488's pre-fix DHCPv4
length-check ordering, whether exact compiler/libc fortification changes the
memory-corruption outcome, and whether the affected L2 receive mode belongs to
the ordinary ConnMan IPv4 acquisition path.

## Scope

- Compare the official CNA/NVD record and upstream fix
  `99e2c16ea1cced34a5dc450d76287a1c3e762138` with exact shipped instructions.
- Bind findings to exact `connmand`, libc, service-unit, and package identities.
- Model only the integer/length control flow already present in the exact binary.
- Preserve the current no-NIC VM and perform no target-binary execution.
- Record V-016 only if exact pre-fix code and an installed conditional route are
  established; separate process termination from stack overwrite/RCE.

## Non-goals

- No DHCP packet generator, crafted frame, raw socket, network namespace, live
  service trigger, exploit payload, heap/stack grooming, shellcode, or privilege
  action.
- No claim based only on ConnMan's package version.
- No claim that recovered `260128` matches the owner's installed firmware.
- No physical or network bench interaction.

## Exact contracts to verify

1. Receive length must exceed the 28-byte IPv4+UDP header.
2. Pre-fix code rejects only `read_len < ip_total_len`, then uses
   `ip_total_len - 28` as the copy length without first requiring
   `ip_total_len >= 28`.
3. Exact call is `__memcpy_chk(destination, source, copy_len, 0x274)`.
4. Exact libc implementations compare object size against copy size and branch
   to `__chk_fail`/`__fortify_fail` before copying when the size is excessive.
5. Ordinary IPv4 `g_dhcp_client_start` enters L2 mode during `INIT_SELECTING`.
6. Installed ConnMan service identity, interface exclusions, Wi-Fi intent, and
   restart behavior remain as recorded for V-015.

## Implementation

- Add `tools/uk_fw/connman_length_model.py`, a standard-library-only arithmetic
  model for the exact length checks. It emits deterministic JSON and never
  creates packet bytes or opens a socket.
- Add focused tests in `tests/test_connman_length_model.py` for every boundary
  and exhaustive range counts.
- Add a sanitized exact-build excerpt under
  `evidence/artifacts/network-candidates/` and a conservative V-016 report.
- Update inventories and handover documents only after the exact outcome is
  reviewed.

## Acceptance

- Exhaustive model covers all 16-bit IP total lengths and all possible reads up
  to the exact `0x290` cap without generating inputs.
- Exact vulnerable ordering is present, but any fortify conclusion is tied to
  the exact `__memcpy_chk` call and exact recovered libc implementation.
- The report does not call V-016 root, RCE, or an observed crash.
- Focused and full tests, `py_compile`, `git diff --check`, public harness,
  rootfs SHA-256, and `e2fsck -fn` pass.
- Downloads, full source/disassembly/decompiler output, and generated JSON stay
  under ignored `work/`; only reviewed text and tooling are tracked.

## Delegation

Project policy forbids child threads and requires a verified native route for
worker delegation. Fable is not advertised for native v2 subagents, and the
required direct DeepSeek route remains unavailable. Do not silently substitute
another model or retry the known-broken route; complete this bounded pass in the
current session and record the routing limitation.
