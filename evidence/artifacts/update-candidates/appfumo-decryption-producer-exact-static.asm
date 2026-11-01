# AppFUMO decryptionFile direct-producer exact static excerpts
# Exact ELF SHA-256: 464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7
# Tool: Homebrew LLVM 23.1.3 llvm-objdump / llvm-dwarfdump
# Central dispatch/assignment excerpts retain LLVM's instruction-byte columns.
# Longer excerpts compact away those columns; mnemonics, operands, resolved PLT
# names, addresses, and comments are unchanged.
# Addresses are link-time VAs. Excerpts are disassembly only; no target code was executed.

## Central row-60 dispatch proof

Homebrew LLVM instruction output identifies the jump-table base and signed
entry dispatch:

  16dfb4: 48 8d 05 45 66 2d 00          leaq    0x2d6645(%rip), %rax    # 0x444600
  16dfbb: 89 d2                         movl    %edx, %edx
  16dfbd: 48 63 14 90                   movslq  (%rax,%rdx,4), %rdx
  16dfc1: 48 01 d0                      addq    %rdx, %rax
  16dfc4: ff e0                         jmpq    *%rax

Bounded exact bytes and arithmetic:

  jump-table base                         0x444600
  local row index                         60
  row entry address                       0x444600 + 60 * 4 = 0x4446f0
  bytes at 0x4446f0                       9f 9f d2 ff
  little-endian uint32                    0xffd29f9f
  little-endian int32                     -2973793
  signed target                           0x444600 + (-2973793) = 0x16e59f

The selected generated case then calls the implementation entry:

  16e59f: e8 6c 2b f9 ff                callq   0x101110 <.text+0xdc8e0>

## Alternate package-base QString assignment

The branch at 0x10114f reaches this alternate package-base assignment; the
source is the global QString object at 0x6d4fa8 rather than the object-graph
QString used by 0x101155..0x101173:

  102c90: 48 8d bc 24 40 01 00 00       leaq    0x140(%rsp), %rdi
  102c98: 48 8d 35 09 23 5d 00          leaq    0x5d2309(%rip), %rsi    # 0x6d4fa8
  102c9f: 48 89 7c 24 60                movq    %rdi, 0x60(%rsp)
  102ca4: e8 67 13 f2 ff                callq   0x24010 <_ZN7QStringaSERKS_@plt>

## Bounded literal byte/text identities

Each row is the exact NUL-terminated byte range at the stated VA/file offset in
the exact ELF's file-backed segment:

  0x20bb63  2e77686174736e65772e7461722e677a00
              ".whatsnew.tar.gz\\0"
  0x20bdad  2f7570646174652f77686174736e657700
              "/update/whatsnew\\0"
  0x20be21  74656d7000
              "temp\\0"
  0x20bd9f  2f77686174736e65775f6e657700
              "/whatsnew_new\\0"
  0x20bdbe  2f77686174736e65775f636f6e74726f6c735f6e657700
              "/whatsnew_controls_new\\0"
  0x21f8f8  2f77686174736e65775f6e65775f7573625f696e5f6f746100
              "/whatsnew_new_usb_in_ota\\0"
  0x222d88  2f77686174736e65775f636f6e74726f6c735f6e65775f7573625f696e5f6f746100
              "/whatsnew_controls_new_usb_in_ota\\0"

## Exact .eh_frame containing FDE
0000e1d8 00000054 0000e0b4 FDE cie=00000128 pc=00101110...00104c1b
  Format:       DWARF32
  LSDA Address: 00000000004bae81
  DW_CFA_advance_loc: 2 to 0x101112
  DW_CFA_def_cfa_offset: +16
  DW_CFA_offset: R15 -16
  DW_CFA_advance_loc: 2 to 0x101114
  DW_CFA_def_cfa_offset: +24
  DW_CFA_offset: R14 -24
  DW_CFA_advance_loc: 2 to 0x101116
  DW_CFA_def_cfa_offset: +32
  DW_CFA_offset: R13 -32
  DW_CFA_advance_loc: 2 to 0x101118
  DW_CFA_def_cfa_offset: +40
  DW_CFA_offset: R12 -40
  DW_CFA_advance_loc: 1 to 0x101119
  DW_CFA_def_cfa_offset: +48
  DW_CFA_offset: RBP -48
  DW_CFA_advance_loc: 1 to 0x10111a
  DW_CFA_def_cfa_offset: +56
  DW_CFA_offset: RBX -56
  DW_CFA_advance_loc: 7 to 0x101121
  DW_CFA_def_cfa_offset: +2656
  DW_CFA_advance_loc2: 2593 to 0x101b42
  DW_CFA_remember_state:
  DW_CFA_def_cfa_offset: +56
  DW_CFA_advance_loc: 1 to 0x101b43
  DW_CFA_def_cfa_offset: +48
  DW_CFA_advance_loc: 1 to 0x101b44
  DW_CFA_def_cfa_offset: +40
  DW_CFA_advance_loc: 2 to 0x101b46
  DW_CFA_def_cfa_offset: +32
  DW_CFA_advance_loc: 2 to 0x101b48
  DW_CFA_def_cfa_offset: +24
  DW_CFA_advance_loc: 2 to 0x101b4a
  DW_CFA_def_cfa_offset: +16
  DW_CFA_advance_loc: 2 to 0x101b4c
  DW_CFA_def_cfa_offset: +8
  DW_CFA_advance_loc: 4 to 0x101b50
  DW_CFA_restore_state:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  0x101110: CFA=RSP+8: RIP=[CFA-8]
  0x101112: CFA=RSP+16: R15=[CFA-16], RIP=[CFA-8]
  0x101114: CFA=RSP+24: R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101116: CFA=RSP+32: R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101118: CFA=RSP+40: R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101119: CFA=RSP+48: RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x10111a: CFA=RSP+56: RBX=[CFA-56], RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101121: CFA=RSP+2656: RBX=[CFA-56], RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101b42: CFA=RSP+56: RBX=[CFA-56], RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101b43: CFA=RSP+48: RBX=[CFA-56], RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101b44: CFA=RSP+40: RBX=[CFA-56], RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101b46: CFA=RSP+32: RBX=[CFA-56], RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101b48: CFA=RSP+24: RBX=[CFA-56], RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101b4a: CFA=RSP+16: RBX=[CFA-56], RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101b4c: CFA=RSP+8: RBX=[CFA-56], RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]
  0x101b50: CFA=RSP+2656: RBX=[CFA-56], RBP=[CFA-48], R12=[CFA-40], R13=[CFA-32], R14=[CFA-24], R15=[CFA-16], RIP=[CFA-8]

## Generated static-metacall row-60 target calls containing implementation entry

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  16e587:	callq	0xfed10 <.text+0xda4e0>
  16e58c:	movq	(%rbx), %rdx
  16e58f:	testq	%rdx, %rdx
  16e592:	je	0x16e0a8 <.text+0x149878>
  16e598:	movb	%al, (%rdx)
  16e59a:	jmp	0x16e0a8 <.text+0x149878>
  16e59f:	callq	0x101110 <.text+0xdc8e0>
  16e5a4:	jmp	0x16e0a8 <.text+0x149878>

## copyWhatsNewFiles entry: branch-selected package-base QString

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  101110:	pushq	%r15
  101112:	pushq	%r14
  101114:	pushq	%r13
  101116:	pushq	%r12
  101118:	pushq	%rbp
  101119:	pushq	%rbx
  10111a:	subq	$0xa28, %rsp            # imm = 0xA28
  101121:	movq	%fs:0x28, %rax
  10112a:	movq	%rax, 0xa18(%rsp)
  101132:	xorl	%eax, %eax
  101134:	cmpl	$0x1, 0x5d3e7d(%rip)    # 0x6d4fb8 <_ZN9QListData11shared_nullE+0x758>
  10113b:	leaq	0x5d355e(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
  101142:	movq	%rdi, 0x18(%rsp)
  101147:	movq	%rax, 0x140(%rsp)
  10114f:	je	0x102c90 <.text+0xde460>
  101155:	movq	0x18(%rsp), %rax
  10115a:	leaq	0x140(%rsp), %rdi
  101162:	movq	%rdi, 0x60(%rsp)
  101167:	movq	0x40(%rax), %rax
  10116b:	leaq	0x30(%rax), %rsi
  10116f:	movq	%rax, (%rsp)
  101173:	callq	0x24010 <_ZN7QStringaSERKS_@plt>

## Fixed package system/control suffix construction

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  101178:	leaq	0x1a0(%rsp), %rbx
  101180:	leaq	0x10ac2d(%rip), %rsi    # 0x20bdb4
  101187:	movq	%rbx, %rdi
  10118a:	callq	0x55b90 <.text+0x31360>
  10118f:	leaq	0x180(%rsp), %rbp
  101197:	leaq	0x10ac16(%rip), %rsi    # 0x20bdb4
  10119e:	movq	%rbp, %rdi
  1011a1:	callq	0x55b90 <.text+0x31360>
  1011a6:	leaq	0x160(%rsp), %r12
  1011ae:	leaq	0x108b87(%rip), %rsi    # 0x209d3c
  1011b5:	movq	%r12, %rdi
  1011b8:	callq	0x55b90 <.text+0x31360>
  1011bd:	movq	0x60(%rsp), %r15
  1011c2:	movl	$0x20, %r8d
  1011c8:	xorl	%ecx, %ecx
  1011ca:	movq	%r12, %rsi
  1011cd:	leaq	0x170(%rsp), %r13
  1011d5:	movq	%r13, %rdi
  1011d8:	movq	%r15, %rdx
  1011db:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  1011e0:	leaq	0x190(%rsp), %r14
  1011e8:	movl	$0x20, %r8d
  1011ee:	xorl	%ecx, %ecx
  1011f0:	movq	%rbp, %rdx
  1011f3:	movq	%r13, %rsi
  1011f6:	movq	%r14, %rdi
  1011f9:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  1011fe:	leaq	0x150(%rsp), %rax
  101206:	movl	$0x20, %r8d
  10120c:	xorl	%ecx, %ecx
  10120e:	movq	%rbx, %rdx
  101211:	movq	%r14, %rsi
  101214:	movq	%rax, %rdi
  101217:	movq	%rax, 0x58(%rsp)
  10121c:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  101249:	leaq	0x200(%rsp), %rbx
  101251:	leaq	0x10ab34(%rip), %rsi    # 0x20bd8c
  101258:	movq	%rbx, %rdi
  10125b:	callq	0x55b90 <.text+0x31360>
  101260:	leaq	0x1e0(%rsp), %rbp
  101268:	leaq	0x10ab45(%rip), %rsi    # 0x20bdb4
  10126f:	movq	%rbp, %rdi
  101272:	callq	0x55b90 <.text+0x31360>
  101277:	leaq	0x1c0(%rsp), %r12
  10127f:	leaq	0x108ab6(%rip), %rsi    # 0x209d3c
  101286:	movq	%r12, %rdi
  101289:	callq	0x55b90 <.text+0x31360>
  10128e:	leaq	0x1d0(%rsp), %r13
  101296:	movl	$0x20, %r8d
  10129c:	xorl	%ecx, %ecx
  10129e:	movq	%r15, %rdx
  1012a1:	movq	%r12, %rsi
  1012a4:	movq	%r13, %rdi
  1012a7:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  1012ac:	leaq	0x1f0(%rsp), %r14
  1012b4:	movl	$0x20, %r8d
  1012ba:	xorl	%ecx, %ecx
  1012bc:	movq	%rbp, %rdx
  1012bf:	movq	%r13, %rsi
  1012c2:	movq	%r14, %rdi
  1012c5:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  1012ca:	leaq	0x1b0(%rsp), %rax
  1012d2:	movl	$0x20, %r8d
  1012d8:	xorl	%ecx, %ecx
  1012da:	movq	%rbx, %rdx
  1012dd:	movq	%r14, %rsi
  1012e0:	movq	%rax, %rdi
  1012e3:	movq	%rax, 0x50(%rsp)
  1012e8:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>

## Fixed normal destination suffix construction

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  101315:	cmpl	$0x1, 0x5d3c9c(%rip)    # 0x6d4fb8 <_ZN9QListData11shared_nullE+0x758>
  10131c:	leaq	0x5d337d(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
  101323:	movq	%rax, 0x210(%rsp)
  10132b:	movq	%rax, 0x220(%rsp)
  101333:	je	0x102b20 <.text+0xde2f0>
  101339:	leaq	0x300(%rsp), %rbx
  101341:	leaq	0x10aa57(%rip), %rsi    # 0x20bd9f
  101348:	movq	%rbx, %rdi
  10134b:	callq	0x55b90 <.text+0x31360>
  101350:	leaq	0x2e0(%rsp), %rbp
  101358:	leaq	0x10aa4e(%rip), %rsi    # 0x20bdad
  10135f:	movq	%rbp, %rdi
  101362:	callq	0x55b90 <.text+0x31360>
  101367:	leaq	0x2d0(%rsp), %r12
  10136f:	leaq	0x10898a(%rip), %rsi    # 0x209d00
  101376:	movq	%r12, %rdi
  101379:	callq	0x55b90 <.text+0x31360>
  10137e:	leaq	0x2f0(%rsp), %r13
  101386:	movl	$0x20, %r8d
  10138c:	xorl	%ecx, %ecx
  10138e:	movq	%rbp, %rdx
  101391:	movq	%r12, %rsi
  101394:	movq	%r13, %rdi
  101397:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  10139c:	leaq	0x310(%rsp), %r14
  1013a4:	movl	$0x20, %r8d
  1013aa:	xorl	%ecx, %ecx
  1013ac:	movq	%rbx, %rdx
  1013af:	movq	%r13, %rsi
  1013b2:	movq	%r14, %rdi
  1013b5:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  1013ba:	movq	0x210(%rsp), %rax
  1013c2:	movq	%r14, %rdi
  1013c5:	movq	0x310(%rsp), %rdx
  1013cd:	movq	%rax, 0x310(%rsp)
  1013d5:	movq	%rdx, 0x210(%rsp)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  101402:	leaq	0x350(%rsp), %rbx
  10140a:	leaq	0x10a9ad(%rip), %rsi    # 0x20bdbe
  101411:	movq	%rbx, %rdi
  101414:	callq	0x55b90 <.text+0x31360>
  101419:	leaq	0x330(%rsp), %rbp
  101421:	leaq	0x10a985(%rip), %rsi    # 0x20bdad
  101428:	movq	%rbp, %rdi
  10142b:	callq	0x55b90 <.text+0x31360>
  101430:	leaq	0x320(%rsp), %r12
  101438:	leaq	0x1088c1(%rip), %rsi    # 0x209d00
  10143f:	movq	%r12, %rdi
  101442:	callq	0x55b90 <.text+0x31360>
  101447:	leaq	0x340(%rsp), %r13
  10144f:	movl	$0x20, %r8d
  101455:	xorl	%ecx, %ecx
  101457:	movq	%rbp, %rdx
  10145a:	movq	%r12, %rsi
  10145d:	movq	%r13, %rdi
  101460:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  101465:	leaq	0x360(%rsp), %r14
  10146d:	movl	$0x20, %r8d
  101473:	xorl	%ecx, %ecx
  101475:	movq	%rbx, %rdx
  101478:	movq	%r13, %rsi
  10147b:	movq	%r14, %rdi
  10147e:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  101483:	movq	0x220(%rsp), %rax
  10148b:	movq	0x360(%rsp), %rdx
  101493:	movq	%rax, 0x360(%rsp)
  10149b:	movq	%rdx, 0x220(%rsp)

## Top-level source archive and fixed temp destination construction

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  10155b:	leaq	0x3e0(%rsp), %rbx
  101563:	leaq	0x10a5f9(%rip), %rsi    # 0x20bb63
  10156a:	movq	%rbx, %rdi
  10156d:	callq	0x55b90 <.text+0x31360>
  101572:	leaq	0x3c0(%rsp), %rbp
  10157a:	leaq	0x108753(%rip), %rsi    # 0x209cd4
  101581:	movq	%rbp, %rdi
  101584:	callq	0x55b90 <.text+0x31360>
  101589:	movq	0x60(%rsp), %rdx
  10158e:	movl	$0x20, %r8d
  101594:	xorl	%ecx, %ecx
  101596:	movq	%rbp, %rsi
  101599:	leaq	0x3d0(%rsp), %r12
  1015a1:	movq	%r12, %rdi
  1015a4:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  1015a9:	leaq	0x3b0(%rsp), %rax
  1015b1:	movl	$0x20, %r8d
  1015b7:	xorl	%ecx, %ecx
  1015b9:	movq	%rbx, %rdx
  1015bc:	movq	%r12, %rsi
  1015bf:	movq	%rax, %rdi
  1015c2:	movq	%rax, 0x80(%rsp)
  1015ca:	movq	%rax, %r14
  1015cd:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  1017a4:	cmpl	$0x1, 0x5d380d(%rip)    # 0x6d4fb8 <_ZN9QListData11shared_nullE+0x758>
  1017ab:	leaq	0x5d2eee(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
  1017b2:	movq	%rax, 0x970(%rsp)
  1017ba:	je	0x102cd0 <.text+0xde4a0>
  1017c0:	leaq	0x4b0(%rsp), %rbx
  1017c8:	leaq	0x10a652(%rip), %rsi    # 0x20be21
  1017cf:	movq	%rbx, %rdi
  1017d2:	callq	0x55b90 <.text+0x31360>
  1017d7:	leaq	0x490(%rsp), %rbp
  1017df:	leaq	0x10a5c7(%rip), %rsi    # 0x20bdad
  1017e6:	movq	%rbp, %rdi
  1017e9:	callq	0x55b90 <.text+0x31360>
  1017ee:	leaq	0x480(%rsp), %r12
  1017f6:	leaq	0x1084d7(%rip), %rsi    # 0x209cd4
  1017fd:	movq	%r12, %rdi
  101800:	callq	0x55b90 <.text+0x31360>
  101805:	leaq	0x4a0(%rsp), %r13
  10180d:	movl	$0x20, %r8d
  101813:	xorl	%ecx, %ecx
  101815:	movq	%rbp, %rdx
  101818:	movq	%r12, %rsi
  10181b:	movq	%r13, %rdi
  10181e:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  101823:	leaq	0x4c0(%rsp), %r14
  10182b:	movl	$0x20, %r8d
  101831:	xorl	%ecx, %ecx
  101833:	movq	%rbx, %rdx
  101836:	movq	%r13, %rsi
  101839:	movq	%r14, %rdi
  10183c:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  101841:	movq	0x970(%rsp), %rax
  101849:	movq	%r14, %rdi
  10184c:	movq	0x4c0(%rsp), %rdx
  101854:	movq	%rax, 0x4c0(%rsp)
  10185c:	movq	%rdx, 0x970(%rsp)
  101864:	callq	0x4b960 <.text+0x27130>
  101869:	movq	%r13, %rdi
  10186c:	callq	0x4b960 <.text+0x27130>
  101871:	movq	%r12, %rdi
  101874:	callq	0x4b960 <.text+0x27130>
  101879:	movq	%rbp, %rdi
  10187c:	callq	0x4b960 <.text+0x27130>
  101881:	movq	%rbx, %rdi
  101884:	callq	0x4b960 <.text+0x27130>

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  101b50:	leaq	0x570(%rsp), %rbx
  101b58:	leaq	0x10a004(%rip), %rsi    # 0x20bb63
  101b5f:	movq	%rbx, %rdi
  101b62:	callq	0x55b90 <.text+0x31360>
  101b67:	leaq	0x550(%rsp), %rbp
  101b6f:	leaq	0x10815e(%rip), %rsi    # 0x209cd4
  101b76:	movq	%rbp, %rdi
  101b79:	callq	0x55b90 <.text+0x31360>
  101b7e:	leaq	0x560(%rsp), %r12
  101b86:	movl	$0x20, %r8d
  101b8c:	xorl	%ecx, %ecx
  101b8e:	movq	%r14, %rdx
  101b91:	movq	%rbp, %rsi
  101b94:	movq	%r12, %rdi
  101b97:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  101b9c:	leaq	0x9c0(%rsp), %rax
  101ba4:	movl	$0x20, %r8d
  101baa:	xorl	%ecx, %ecx
  101bac:	movq	%rbx, %rdx
  101baf:	movq	%r12, %rsi
  101bb2:	movq	%rax, %rdi
  101bb5:	movq	%rax, 0x8(%rsp)
  101bba:	movq	%rax, %r13
  101bbd:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  101bc2:	movq	%r12, %rdi
  101bc5:	callq	0x4b960 <.text+0x27130>
  101bca:	movq	%rbp, %rdi
  101bcd:	callq	0x4b960 <.text+0x27130>
  101bd2:	movq	%rbx, %rdi
  101bd5:	callq	0x4b960 <.text+0x27130>
  101bda:	cmpb	$0x0, 0x5d04d3(%rip)    # 0x6d20b4
  101be1:	jne	0x102da0 <.text+0xde570>

## Direct call 0x102de9: encrypted top-level archive branch

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  102da0:	leaq	0x9e0(%rsp), %rbp
  102da8:	movq	%r13, %rsi
  102dab:	movq	%r13, %rbx
  102dae:	movq	0x20(%rsp), %r13
  102db3:	movq	%r13, %rdi
  102db6:	callq	0x55bf0 <.text+0x313c0>
  102dbb:	movq	0x80(%rsp), %r12
  102dc3:	movq	%rbp, %rdi
  102dc6:	movq	%r12, %rsi
  102dc9:	callq	0x55bf0 <.text+0x313c0>
  102dce:	movq	0x18(%rsp), %rsi
  102dd3:	movq	%r13, %rcx
  102dd6:	movq	%rbp, %rdx
  102dd9:	leaq	0x9d0(%rsp), %rax
  102de1:	movq	%rax, %rdi
  102de4:	movq	%rax, 0x10(%rsp)
  102de9:	callq	0x100b30 <.text+0xdc300>

## Alternate OTA destination constants

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  102b20:	leaq	0x260(%rsp), %rbx
  102b28:	leaq	0x11cdc9(%rip), %rsi    # 0x21f8f8
  102b2f:	movq	%rbx, %rdi
  102b32:	callq	0x55b90 <.text+0x31360>
  102b37:	leaq	0x240(%rsp), %rbp
  102b3f:	leaq	0x109267(%rip), %rsi    # 0x20bdad
  102b46:	movq	%rbp, %rdi
  102b49:	callq	0x55b90 <.text+0x31360>
  102b4e:	leaq	0x230(%rsp), %r12
  102b56:	leaq	0x1071a3(%rip), %rsi    # 0x209d00
  102b5d:	movq	%r12, %rdi
  102b60:	callq	0x55b90 <.text+0x31360>
  102b65:	leaq	0x250(%rsp), %r13
  102b6d:	movl	$0x20, %r8d
  102b73:	xorl	%ecx, %ecx
  102b75:	movq	%rbp, %rdx
  102b78:	movq	%r12, %rsi
  102b7b:	movq	%r13, %rdi
  102b7e:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  102b83:	leaq	0x270(%rsp), %r14
  102b8b:	movl	$0x20, %r8d
  102b91:	xorl	%ecx, %ecx
  102b93:	movq	%rbx, %rdx
  102b96:	movq	%r13, %rsi
  102b99:	movq	%r14, %rdi
  102b9c:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  102ba1:	movq	0x210(%rsp), %rax
  102ba9:	movq	%r14, %rdi
  102bac:	movq	0x270(%rsp), %rdx
  102bb4:	movq	%rax, 0x270(%rsp)
  102bbc:	movq	%rdx, 0x210(%rsp)
  102bc4:	callq	0x4b960 <.text+0x27130>
  102bc9:	movq	%r13, %rdi
  102bcc:	callq	0x4b960 <.text+0x27130>
  102bd1:	movq	%r12, %rdi
  102bd4:	callq	0x4b960 <.text+0x27130>
  102bd9:	movq	%rbp, %rdi
  102bdc:	callq	0x4b960 <.text+0x27130>
  102be1:	movq	%rbx, %rdi
  102be4:	callq	0x4b960 <.text+0x27130>
  102be9:	leaq	0x2b0(%rsp), %rbx
  102bf1:	leaq	0x120190(%rip), %rsi    # 0x222d88
  102bf8:	movq	%rbx, %rdi
  102bfb:	callq	0x55b90 <.text+0x31360>
  102c00:	leaq	0x290(%rsp), %rbp
  102c08:	leaq	0x10919e(%rip), %rsi    # 0x20bdad
  102c0f:	movq	%rbp, %rdi
  102c12:	callq	0x55b90 <.text+0x31360>
  102c17:	leaq	0x280(%rsp), %r12
  102c1f:	leaq	0x1070da(%rip), %rsi    # 0x209d00
  102c26:	movq	%r12, %rdi
  102c29:	callq	0x55b90 <.text+0x31360>
  102c2e:	leaq	0x2a0(%rsp), %r13
  102c36:	movl	$0x20, %r8d
  102c3c:	xorl	%ecx, %ecx
  102c3e:	movq	%rbp, %rdx
  102c41:	movq	%r12, %rsi
  102c44:	movq	%r13, %rdi
  102c47:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  102c4c:	leaq	0x2c0(%rsp), %r14
  102c54:	movl	$0x20, %r8d
  102c5a:	xorl	%ecx, %ecx
  102c5c:	movq	%rbx, %rdx
  102c5f:	movq	%r13, %rsi
  102c62:	movq	%r14, %rdi
  102c65:	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  102c6a:	movq	0x220(%rsp), %rax
  102c72:	movq	0x2c0(%rsp), %rdx
  102c7a:	movq	%rax, 0x2c0(%rsp)
  102c82:	movq	%rdx, 0x220(%rsp)
  102c8a:	jmp	0x1014a3 <.text+0xdcc73>

## System-tree encryption branch and directory pairing

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  1022ad:	testb	%bpl, %bpl
  1022b0:	je	0x103dc4 <.text+0xdf594>
  1022b6:	cmpb	$0x0, 0x5cfdf7(%rip)    # 0x6d20b4
  1022bd:	je	0x102eba <.text+0xde68a>
  1022c3:	movq	0x88(%rsp), %rsi
  1022cb:	movl	$0xffffffff, %ecx       # imm = 0xFFFFFFFF
  1022d0:	movl	$0x6500, %edx           # imm = 0x6500
  1022d5:	leaq	0x880(%rsp), %rax
  1022dd:	movq	%rax, %rdi
  1022e0:	movq	%rax, 0x110(%rsp)
  1022e8:	callq	0x22d40 <_ZNK4QDir9entryListE6QFlagsINS_6FilterEES0_INS_8SortFlagEE@plt>
  1022ed:	movq	0x880(%rsp), %rax
  1022f5:	movl	0xc(%rax), %edx
  1022f8:	subl	0x8(%rax), %edx
  1022fb:	movl	%edx, 0x13c(%rsp)
  102302:	testl	%edx, %edx
  102304:	jle	0x103910 <.text+0xdf0e0>

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  102365:	movl	0x138(%rsp), %r13d
  10236d:	movq	0x110(%rsp), %rbp
  102375:	movl	%r13d, %esi
  102378:	movq	%rbp, %rdi
  10237b:	callq	0x66590 <.text+0x41d60>
  102380:	movq	0x120(%rsp), %r15
  102388:	leaq	0x12a8dc(%rip), %rdx    # 0x22cc6b
  10238f:	movq	0x58(%rsp), %rsi
  102394:	movq	%rax, %rbx
  102397:	movq	%r15, %rdi
  10239a:	callq	0x66360 <.text+0x41b30>
  10239f:	movq	0xe0(%rsp), %r14
  1023a7:	movq	%rbx, %rdx
  1023aa:	movq	%r15, %rsi
  1023ad:	movq	%r14, %rdi
  1023b0:	callq	0x662d0 <.text+0x41aa0>
  1023b5:	movq	%r15, %rdi
  1023b8:	callq	0x4b960 <.text+0x27130>
  1023bd:	movl	%r13d, %esi
  1023c0:	movq	%rbp, %rdi
  1023c3:	callq	0x66590 <.text+0x41d60>
  1023c8:	movq	0x128(%rsp), %r15
  1023d0:	leaq	0x12a894(%rip), %rdx    # 0x22cc6b
  1023d7:	movq	0x78(%rsp), %rsi
  1023dc:	movq	%rax, %rbx
  1023df:	movq	%r15, %rdi
  1023e2:	callq	0x66360 <.text+0x41b30>
  1023e7:	movq	0xe8(%rsp), %rdi
  1023ef:	movq	%rbx, %rdx
  1023f2:	movq	%r15, %rsi
  1023f5:	callq	0x662d0 <.text+0x41aa0>
  1023fa:	movq	%r15, %rdi
  1023fd:	callq	0x4b960 <.text+0x27130>
  102402:	movq	0x20(%rsp), %r15
  102407:	movq	%r14, %rsi
  10240a:	movq	%r15, %rdi
  10240d:	callq	0x55bf0 <.text+0x313c0>
  102412:	movq	0x130(%rsp), %rbp
  10241a:	movq	%r15, %rsi
  10241d:	movq	%rbp, %rdi
  102420:	callq	0x55b20 <.text+0x312f0>
  102425:	movq	0x7c0(%rsp), %rdi
  10242d:	callq	0x55ac0 <.text+0x31290>
  102432:	movq	%rax, %rbx
  102435:	callq	0x55c60 <.text+0x31430>
  10243a:	leaq	0x126fff(%rip), %rdx    # 0x229440
  102441:	movq	%rax, %rdi
  102444:	movq	%rbx, %rcx
  102447:	leaq	0x109a61(%rip), %rsi    # 0x20beaf
  10244e:	xorl	%eax, %eax
  102450:	callq	0x137430 <.text+0x112c00>
  102455:	movq	%rbp, %rdi
  102458:	callq	0x4b8e0 <.text+0x270b0>
  10245d:	movq	%r15, %rdi
  102460:	callq	0x4b960 <.text+0x27130>

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  102520:	movl	0xa8(%rsp), %r13d
  102528:	movq	0xd8(%rsp), %rbp
  102530:	movl	%r13d, %esi
  102533:	movq	%rbp, %rdi
  102536:	callq	0x66590 <.text+0x41d60>
  10253b:	movq	0xf0(%rsp), %r15
  102543:	leaq	0x12a721(%rip), %rdx    # 0x22cc6b
  10254a:	movq	0xe0(%rsp), %rsi
  102552:	movq	%rax, %rbx
  102555:	movq	%r15, %rdi
  102558:	callq	0x66360 <.text+0x41b30>
  10255d:	movq	0xb8(%rsp), %r14
  102565:	movq	%rbx, %rdx
  102568:	movq	%r15, %rsi
  10256b:	movq	%r14, %rdi
  10256e:	callq	0x662d0 <.text+0x41aa0>
  102573:	movq	%r15, %rdi
  102576:	callq	0x4b960 <.text+0x27130>
  10257b:	movl	%r13d, %esi
  10257e:	movq	%rbp, %rdi
  102581:	callq	0x66590 <.text+0x41d60>
  102586:	movq	0xf8(%rsp), %r15
  10258e:	leaq	0x12a6d6(%rip), %rdx    # 0x22cc6b
  102595:	movq	0xe8(%rsp), %rsi
  10259d:	movq	%rax, %rbx
  1025a0:	movq	%r15, %rdi
  1025a3:	callq	0x66360 <.text+0x41b30>
  1025a8:	movq	0xc0(%rsp), %rbp
  1025b0:	movq	%rbx, %rdx
  1025b3:	movq	%r15, %rsi
  1025b6:	movq	%rbp, %rdi
  1025b9:	callq	0x662d0 <.text+0x41aa0>
  1025be:	movq	%r15, %rdi
  1025c1:	callq	0x4b960 <.text+0x27130>
  1025c6:	movq	0x20(%rsp), %r15
  1025cb:	movq	%r14, %rsi
  1025ce:	movq	%r15, %rdi
  1025d1:	callq	0x55bf0 <.text+0x313c0>
  1025d6:	movq	0x100(%rsp), %r14
  1025de:	movq	%r15, %rsi
  1025e1:	movq	%r14, %rdi
  1025e4:	callq	0x55b20 <.text+0x312f0>
  1025e9:	movq	0x7f0(%rsp), %rdi
  1025f1:	callq	0x55ac0 <.text+0x31290>
  1025f6:	movq	%rax, %rbx
  1025f9:	callq	0x55c60 <.text+0x31430>
  1025fe:	leaq	0x126e3b(%rip), %rdx    # 0x229440
  102605:	movq	%rax, %rdi
  102608:	movq	%rbx, %rcx
  10260b:	leaq	0x1098b0(%rip), %rsi    # 0x20bec2
  102612:	xorl	%eax, %eax
  102614:	callq	0x137430 <.text+0x112c00>
  102619:	leaq	0x800(%rsp), %rbx
  102621:	movq	%r14, %rdi
  102624:	callq	0x4b8e0 <.text+0x270b0>
  102629:	movq	%r15, %rdi
  10262c:	callq	0x4b960 <.text+0x27130>
  102631:	leaq	0x5d2068(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
  102638:	movq	%r15, %rsi
  10263b:	movq	%rbx, %rdi
  10263e:	movq	%rax, 0xa00(%rsp)
  102646:	callq	0x24320 <_ZN4QDirC1ERK7QString@plt>
  10264b:	movq	%rbp, %rsi
  10264e:	movq	%rbx, %rdi
  102651:	callq	0x22910 <_ZNK4QDir6mkpathERK7QString@plt>
  102656:	movq	%rbx, %rdi
  102659:	movl	%eax, %ebp
  10265b:	callq	0x22580 <_ZN4QDirD1Ev@plt>
  102660:	movq	%r15, %rdi
  102663:	callq	0x4b960 <.text+0x27130>
  102668:	testb	%bpl, %bpl

## Direct call 0x10281c and enumerated source/destination construction

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  102737:	movq	0x820(%rsp), %rax
  10273f:	movl	(%rax), %ebx
  102741:	movq	%rax, 0x930(%rsp)
  102749:	leal	0x1(%rbx), %edx
  10274c:	cmpl	$0x1, %edx
  10274f:	jbe	0x102758 <.text+0xddf28>
  102751:	lock
  102752:	addl	$0x1, (%rax)
  102755:	setne	%dl
  102758:	movq	0x8(%rsp), %rsi
  10275d:	movq	0x28(%rsp), %rdi
  102762:	callq	0x23f10 <_ZN7QString6appendERKS_@plt>
  102767:	movq	0x820(%rsp), %rdi
  10276f:	movl	(%rdi), %eax
  102771:	testl	%eax, %eax
  102773:	jne	0x1036b8 <.text+0xdee88>
  102779:	movl	$0x8, %edx
  10277e:	movl	$0x2, %esi
  102783:	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
  102788:	movq	0x830(%rsp), %rdi
  102790:	movl	(%rdi), %eax
  102792:	testl	%eax, %eax
  102794:	jne	0x103690 <.text+0xdee60>
  10279a:	movl	$0x8, %edx
  10279f:	movl	$0x2, %esi
  1027a4:	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
  1027a9:	movq	0x930(%rsp), %rax
  1027b1:	movl	(%rax), %edx
  1027b3:	movq	%rax, 0x970(%rsp)
  1027bb:	testl	%edx, %edx
  1027bd:	je	0x1027cb <.text+0xddf9b>
  1027bf:	cmpl	$-0x1, %edx
  1027c2:	je	0x1027cb <.text+0xddf9b>
  1027c4:	lock
  1027c5:	addl	$0x1, (%rax)
  1027c8:	setne	%dl
  1027cb:	movq	0x920(%rsp), %rcx
  1027d3:	movslq	0x8(%rcx), %rax
  1027d7:	movl	0xc(%rcx), %edx
  1027da:	subl	%eax, %edx
  1027dc:	cmpl	%r12d, %edx
  1027df:	jle	0x103a00 <.text+0xdf1d0>
  1027e5:	movq	0x40(%rsp), %rbx
  1027ea:	addq	%r15, %rax
  1027ed:	leaq	0x10(%rcx,%rax,8), %rsi
  1027f2:	movq	%rbx, %rdi
  1027f5:	callq	0x22ed0 <_ZNK9QFileInfo16absoluteFilePathEv@plt>
  1027fa:	movq	0x18(%rsp), %rsi
  1027ff:	leaq	0x940(%rsp), %rax
  102807:	movq	%rbx, %rdx
  10280a:	leaq	0x970(%rsp), %r14
  102812:	movq	%rax, %rdi
  102815:	movq	%rax, (%rsp)
  102819:	movq	%r14, %rcx
  10281c:	callq	0x100b30 <.text+0xdc300>

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  102a84:	movq	0x8(%rsp), %rdi
  102a89:	addq	%r15, %rax
  102a8c:	leaq	0x10(%rdx,%rax,8), %rsi
  102a91:	callq	0x237f0 <_ZNK9QFileInfo8fileNameEv@plt>
  102a96:	movq	0x900(%rsp), %rax
  102a9e:	movl	(%rax), %ebx
  102aa0:	movq	%rax, 0x820(%rsp)
  102aa8:	leal	0x1(%rbx), %edx
  102aab:	cmpl	$0x1, %edx
  102aae:	jbe	0x102ab7 <.text+0xde287>
  102ab0:	lock
  102ab1:	addl	$0x1, (%rax)
  102ab4:	setne	%dl
  102ab7:	movq	0x30(%rsp), %r14
  102abc:	movl	$0x1, %edx
  102ac1:	leaq	0x12a1a3(%rip), %rsi    # 0x22cc6b
  102ac8:	movq	%r14, %rdi
  102acb:	callq	0x223d0 <_ZN7QString15fromUtf8_helperEPKci@plt>
  102ad0:	movq	0x38(%rsp), %rdi
  102ad5:	movq	%r14, %rsi
  102ad8:	movq	%rdi, %rbx
  102adb:	callq	0x23f10 <_ZN7QString6appendERKS_@plt>
  102ae0:	movq	0x9e0(%rsp), %rdi
  102ae8:	movl	(%rdi), %eax
  102aea:	testl	%eax, %eax
  102aec:	je	0x102728 <.text+0xddef8>
  102af2:	cmpl	$-0x1, %eax
  102af5:	je	0x102737 <.text+0xddf07>
  102afb:	lock
  102afc:	subl	$0x1, (%rdi)
  102aff:	setne	%al
  102b02:	testb	%al, %al
  102b04:	jne	0x102737 <.text+0xddf07>
  102b0a:	movq	0x9e0(%rsp), %rdi
  102b12:	jmp	0x102728 <.text+0xddef8>

## Controls-tree encryption branch and directory pairing

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  10306d:	testb	%bl, %bl
  10306f:	je	0x103e2e <.text+0xdf5fe>
  103075:	cmpb	$0x0, 0x5cf038(%rip)    # 0x6d20b4
  10307c:	je	0x103a1f <.text+0xdf1ef>
  103082:	movq	0xa0(%rsp), %rsi
  10308a:	movl	$0xffffffff, %ecx       # imm = 0xFFFFFFFF
  10308f:	movl	$0x6500, %edx           # imm = 0x6500
  103094:	movq	0xd8(%rsp), %rdi
  10309c:	callq	0x22d40 <_ZNK4QDir9entryListE6QFlagsINS_6FilterEES0_INS_8SortFlagEE@plt>
  1030a1:	movq	0x8d0(%rsp), %rax
  1030a9:	movl	0xc(%rax), %edx
  1030ac:	subl	0x8(%rax), %edx
  1030af:	movl	%edx, 0xf0(%rsp)
  1030b6:	testl	%edx, %edx
  1030b8:	jle	0x103db2 <.text+0xdf582>
  1030be:	leaq	0x8f0(%rsp), %rax
  1030c6:	movl	$0x0, 0xb8(%rsp)
  1030d1:	movq	%rax, 0xc8(%rsp)
  1030d9:	leaq	0x8e0(%rsp), %rax
  1030e1:	movq	%rax, 0xc0(%rsp)
  1030e9:	leaq	0x900(%rsp), %rax
  1030f1:	movq	%rax, 0xe0(%rsp)
  1030f9:	leaq	0x990(%rsp), %rax
  103101:	movq	%rax, 0xd0(%rsp)
  103109:	leaq	0x910(%rsp), %rax
  103111:	movq	%rax, 0xe8(%rsp)
  103119:	nopl	(%rax)
  103120:	movl	0xb8(%rsp), %ebp
  103127:	movq	0xd8(%rsp), %r14
  10312f:	movl	%ebp, %esi
  103131:	movq	%r14, %rdi
  103134:	callq	0x66590 <.text+0x41d60>
  103139:	movq	0xc8(%rsp), %r15
  103141:	leaq	0x129b23(%rip), %rdx    # 0x22cc6b
  103148:	movq	0x50(%rsp), %rsi
  10314d:	movq	%rax, %rbx
  103150:	movq	%r15, %rdi
  103153:	callq	0x66360 <.text+0x41b30>
  103158:	movq	0xc0(%rsp), %rdi
  103160:	movq	%rbx, %rdx
  103163:	movq	%r15, %rsi
  103166:	callq	0x662d0 <.text+0x41aa0>
  10316b:	movq	%r15, %rdi
  10316e:	callq	0x4b960 <.text+0x27130>
  103173:	movl	%ebp, %esi
  103175:	movq	%r14, %rdi
  103178:	callq	0x66590 <.text+0x41d60>
  10317d:	movq	0xe0(%rsp), %r15
  103185:	leaq	0x129adf(%rip), %rdx    # 0x22cc6b
  10318c:	movq	0x70(%rsp), %rsi
  103191:	movq	%rax, %rbx
  103194:	movq	%r15, %rdi
  103197:	callq	0x66360 <.text+0x41b30>
  10319c:	movq	0xd0(%rsp), %rbp
  1031a4:	movq	%rbx, %rdx
  1031a7:	movq	%r15, %rsi
  1031aa:	movq	%rbp, %rdi
  1031ad:	callq	0x662d0 <.text+0x41aa0>
  1031b2:	movq	%r15, %rdi
  1031b5:	callq	0x4b960 <.text+0x27130>
  1031ba:	movq	0x20(%rsp), %r14
  1031bf:	leaq	0x5d14da(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
  1031c6:	movq	0xe8(%rsp), %r15
  1031ce:	movq	%rax, 0xa00(%rsp)
  1031d6:	movq	%r14, %rsi
  1031d9:	movq	%r15, %rdi
  1031dc:	callq	0x24320 <_ZN4QDirC1ERK7QString@plt>
  1031e1:	movq	%rbp, %rsi
  1031e4:	movq	%r15, %rdi
  1031e7:	callq	0x22910 <_ZNK4QDir6mkpathERK7QString@plt>
  1031ec:	movq	%r15, %rdi
  1031ef:	movl	%eax, %ebx
  1031f1:	callq	0x22580 <_ZN4QDirD1Ev@plt>
  1031f6:	movq	%r14, %rdi
  1031f9:	callq	0x4b960 <.text+0x27130>
  1031fe:	testb	%bl, %bl
  103200:	je	0x103f7a <.text+0xdf74a>
  103206:	movq	0xc0(%rsp), %rsi
  10320e:	leaq	0x9a0(%rsp), %rax
  103216:	movq	%rax, %rdi
  103219:	movq	%rax, %rbx
  10321c:	movq	%rax, 0x48(%rsp)
  103221:	callq	0x24320 <_ZN4QDirC1ERK7QString@plt>

## Direct call 0x103398 and enumerated source/destination construction

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  1032bf:	movq	0x930(%rsp), %rax
  1032c7:	movl	(%rax), %ecx
  1032c9:	movq	%rax, 0x9c0(%rsp)
  1032d1:	leal	0x1(%rcx), %edx
  1032d4:	cmpl	$0x1, %edx
  1032d7:	jbe	0x1032e0 <.text+0xdeab0>
  1032d9:	lock
  1032da:	addl	$0x1, (%rax)
  1032dd:	setne	%dl
  1032e0:	movq	(%rsp), %rsi
  1032e4:	movq	0x10(%rsp), %rdi
  1032e9:	callq	0x23f10 <_ZN7QString6appendERKS_@plt>
  1032ee:	movq	0x930(%rsp), %rdi
  1032f6:	movl	(%rdi), %eax
  1032f8:	testl	%eax, %eax
  1032fa:	jne	0x103ba8 <.text+0xdf378>
  103300:	movl	$0x8, %edx
  103305:	movl	$0x2, %esi
  10330a:	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
  10330f:	movq	0x940(%rsp), %rdi
  103317:	movl	(%rdi), %eax
  103319:	testl	%eax, %eax
  10331b:	jne	0x103b80 <.text+0xdf350>
  103321:	movl	$0x8, %edx
  103326:	movl	$0x2, %esi
  10332b:	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
  103330:	movq	0x9c0(%rsp), %rax
  103338:	movl	(%rax), %edx
  10333a:	movq	%rax, 0x9e0(%rsp)
  103342:	testl	%edx, %edx
  103344:	je	0x103352 <.text+0xdeb22>
  103346:	cmpl	$-0x1, %edx
  103349:	je	0x103352 <.text+0xdeb22>
  10334b:	lock
  10334c:	addl	$0x1, (%rax)
  10334f:	setne	%dl
  103352:	movq	0x9b0(%rsp), %rdx
  10335a:	movslq	0x8(%rdx), %rax
  10335e:	movl	0xc(%rdx), %ecx
  103361:	subl	%eax, %ecx
  103363:	cmpl	%ebx, %ecx
  103365:	jle	0x103a00 <.text+0xdf1d0>
  10336b:	movq	0x30(%rsp), %r15
  103370:	addq	%r13, %rax
  103373:	leaq	0x10(%rdx,%rax,8), %rsi
  103378:	movq	%r15, %rdi
  10337b:	callq	0x22ed0 <_ZNK9QFileInfo16absoluteFilePathEv@plt>
  103380:	movq	0x18(%rsp), %rsi
  103385:	leaq	0x9e0(%rsp), %rbp
  10338d:	movq	%r15, %rdx
  103390:	movq	0x38(%rsp), %rdi
  103395:	movq	%rbp, %rcx
  103398:	callq	0x100b30 <.text+0xdc300>
