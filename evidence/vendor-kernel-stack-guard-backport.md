# Vendor kernel backport check: Stack Clash guard gap

Date: 2026-11-01
Target: EU Gen5W Linux `NE_E.EUR.S5W_L.001.001.260128`
Artifact: recovered x86-64 vendor `vmlinux`, Linux banner `4.1.27-abl`

## Result

The vendor kernel contains the larger inter-VMA stack guard introduced by
upstream commit `1be7107fbe18eed3e319a6c3e83c78254b693acb`. The generic
CVE-2017-1000364/Stack Clash version-gap hypothesis is therefore not a
supported local-root candidate for this exact recovered build.

## Binary evidence

The recovered kallsyms map contains all central additions from the backport:

- `vm_start_gap` at `0xffffffff810f1113`;
- writable global `stack_guard_gap` at `0xffffffff81a28bc8`;
- boot parser `cmdline_parse_stack_guard_gap`;
- setup records for the `stack_guard_gap` kernel parameter.

The initialized eight-byte value at the recovered `stack_guard_gap` address is
`0x100000` (1,048,576 bytes), the upstream default for 256 4-KiB pages.

`vm_start_gap` directly subtracts that global from a downward-growing VMA start
and saturates on underflow:

```text
ffffffff810f1113  test byte ptr [rdi+0x51],0x1
ffffffff810f1117  mov  rdx,[rdi]
...
ffffffff810f1123  sub  rax,[rip+0x937a9e] # stack_guard_gap
ffffffff810f112a  cmp  rdx,rax
ffffffff810f1132  cmovb rax,rdx_zero
```

Retained local artifacts:

- `work/public-vuln-research-20261101/kernel-vm_start_gap.asm`;
- upstream patch `work/public-vuln-research-20261101/stack-guard-gap-fix.patch`.

## Boundary

The upstream change itself reduces the attack surface rather than proving that
all conceivable stack-jump techniques are impossible. This check establishes
that the missing-one-page-gap premise used by the generic CVE candidate is
false for recovered EU `260128`. It does not identify the owner's installed
build or validate unrelated memory-management fixes.
