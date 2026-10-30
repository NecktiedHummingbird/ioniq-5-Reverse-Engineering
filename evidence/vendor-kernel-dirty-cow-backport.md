# Vendor kernel backport check: CVE-2016-5195 (Dirty COW)

Date: 2026-11-01
Target: EU Gen5W Linux `NE_E.EUR.S5W_L.001.001.260128`
Artifact: recovered x86-64 vendor `vmlinux`, Linux banner `4.1.27-abl`

## Result

The vendor kernel contains the core `FOLL_COW` fix from upstream commit
`19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619`. The `4.1.27-abl` version string
therefore does **not** make CVE-2016-5195 a defensible local-root candidate for
this recovered build.

This is a binary-code finding, not an inference from the version banner.

## Binary evidence

Recovered function addresses from the applied kallsyms map:

- `follow_page_mask`: `0xffffffff810ea961`;
- `__get_user_pages`: `0xffffffff810ead17`.

Inside the inlined write-PTE acceptance logic in `follow_page_mask`:

```text
ffffffff810eaba7  mov  eax,r12d
ffffffff810eabaa  and  eax,0x4010
ffffffff810eabaf  cmp  eax,0x4010
ffffffff810eabb4  jne  reject
ffffffff810eabb6  test byte ptr [rbp-0x38],0x40
ffffffff810eabba  jne  accept
```

The `0x4010` pair is `FOLL_COW | FOLL_FORCE`; the subsequent PTE bit test is the
required dirty-PTE condition. This matches the upstream helper introduced by the
fix:

```c
return pte_write(pte) ||
       ((flags & FOLL_FORCE) && (flags & FOLL_COW) && pte_dirty(pte));
```

The fault-retry path in `__get_user_pages` also sets the new state instead of
clearing `FOLL_WRITE`:

```text
ffffffff810eb1eb  mov  eax,r14d
ffffffff810eb1ee  or   ah,0x40
ffffffff810eb1f1  test byte ptr [r12+0x50],0x2
ffffffff810eb1f7  cmove r14d,eax
```

`or ah,0x40` adds `0x4000` (`FOLL_COW`). The vulnerable pre-fix implementation
instead cleared `FOLL_WRITE` after `VM_FAULT_WRITE` on a non-writable VMA.

Local retained artifacts:

- `work/public-vuln-research-20261101/kernel-follow_page_mask.asm`;
- `work/public-vuln-research-20261101/kernel-__get_user_pages.asm`;
- upstream fix `work/public-vuln-research-20261101/dirtycow-fix.patch`.

## Boundary

This check rejects only CVE-2016-5195 for this exact recovered kernel. It does
not establish that every post-4.1.27 security fix was backported, and it says
nothing about the owner's unknown installed firmware. Other kernel candidates
must likewise be confirmed against code rather than selected from the banner.
