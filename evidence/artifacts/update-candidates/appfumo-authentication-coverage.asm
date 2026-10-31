# Exact embedded FUMO authentication-coverage excerpts
# Source: work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf
# SHA-256: 464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7
# Build ID: 863a8730e66a1c5245a1bf458fe2554adee0351a
# ELF64 x86-64 PIE; image base zero; addresses are link-time VAs.
# Generated with /opt/homebrew/opt/llvm/bin/llvm-objdump.
# Every excerpt starts on an instruction boundary confirmed against the full disassembly.
# Whole-.text direct-call inventory for 0x45820: 0x7be3a, 0x80095, 0x802f0, 0x9d1d2, 0x100bb0, 0x140092.
# Whole-.text direct-call inventory for 0x140f50: 0x1432f6, 0x15170c.


## startup argv[0] directory derivation [0x1259c0,0x125a80)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  1259c0: 49 89 c6                     	movq	%rax, %r14
  1259c3: 49 89 c7                     	movq	%rax, %r15
  1259c6: e8 25 ff 00 00               	callq	0x1358f0 <.text+0x1110c0>
  1259cb: 48 8d 85 70 ff ff ff         	leaq	-0x90(%rbp), %rax
  1259d2: 4c 89 73 38                  	movq	%r14, 0x38(%rbx)
  1259d6: 48 89 c7                     	movq	%rax, %rdi
  1259d9: 49 89 c7                     	movq	%rax, %r15
  1259dc: 48 89 85 78 fc ff ff         	movq	%rax, -0x388(%rbp)
  1259e3: e8 88 c4 ef ff               	callq	0x21e70 <_ZN16QCoreApplication9argumentsEv@plt>
  1259e8: 4c 8d ad b0 fc ff ff         	leaq	-0x350(%rbp), %r13
  1259ef: 31 f6                        	xorl	%esi, %esi
  1259f1: 4c 89 ff                     	movq	%r15, %rdi
  1259f4: e8 97 0b f4 ff               	callq	0x66590 <.text+0x41d60>
  1259f9: 48 8d 8d 80 fc ff ff         	leaq	-0x380(%rbp), %rcx
  125a00: 48 89 c6                     	movq	%rax, %rsi
  125a03: 48 89 cf                     	movq	%rcx, %rdi
  125a06: 48 89 8d 70 fc ff ff         	movq	%rcx, -0x390(%rbp)
  125a0d: e8 de 01 f3 ff               	callq	0x55bf0 <.text+0x313c0>
  125a12: 4c 89 ff                     	movq	%r15, %rdi
  125a15: e8 c6 02 f3 ff               	callq	0x55ce0 <.text+0x314b0>
  125a1a: 48 8b 85 80 fc ff ff         	movq	-0x380(%rbp), %rax
  125a21: 4c 89 ef                     	movq	%r13, %rdi
  125a24: 44 8b 60 04                  	movl	0x4(%rax), %r12d
  125a28: e8 f3 ed ef ff               	callq	0x24820 <_ZN16QCoreApplication15applicationNameEv@plt>
  125a2d: 48 8b 85 b0 fc ff ff         	movq	-0x350(%rbp), %rax
  125a34: 4c 8d b5 a0 fc ff ff         	leaq	-0x360(%rbp), %r14
  125a3b: 48 8b b5 70 fc ff ff         	movq	-0x390(%rbp), %rsi
  125a42: 4c 89 f7                     	movq	%r14, %rdi
  125a45: 44 2b 60 04                  	subl	0x4(%rax), %r12d
  125a49: 41 8d 54 24 ff               	leal	-0x1(%r12), %edx
  125a4e: e8 2d e6 ef ff               	callq	0x24080 <_ZNK7QString4leftEi@plt>
  125a53: 48 8b 85 80 fc ff ff         	movq	-0x380(%rbp), %rax
  125a5a: 4c 89 f7                     	movq	%r14, %rdi
  125a5d: 48 8b 95 a0 fc ff ff         	movq	-0x360(%rbp), %rdx
  125a64: 48 89 85 a0 fc ff ff         	movq	%rax, -0x360(%rbp)
  125a6b: 48 89 95 80 fc ff ff         	movq	%rdx, -0x380(%rbp)
  125a72: e8 e9 5e f2 ff               	callq	0x4b960 <.text+0x27130>
  125a77: 4c 89 ef                     	movq	%r13, %rdi
  125a7a: e8 e1 5e f2 ff               	callq	0x4b960 <.text+0x27130>
  125a7f: 4c 8b 25 da f8 5a 00         	movq	0x5af8da(%rip), %r12    # 0x6d5360 <_ZN9QListData11shared_nullE+0xb00>

## startup directory handoff [0x126ce3,0x126d1a)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  126ce3: 0f 1f 44 00 00               	nopl	(%rax,%rax)
  126ce8: bf 78 00 00 00               	movl	$0x78, %edi
  126ced: e8 fe b4 ef ff               	callq	0x221f0 <_Znwm@plt>
  126cf2: 48 8b b5 70 fc ff ff         	movq	-0x390(%rbp), %rsi
  126cf9: 4c 8d ab 20 02 00 00         	leaq	0x220(%rbx), %r13
  126d00: 48 89 c7                     	movq	%rax, %rdi
  126d03: 49 89 c4                     	movq	%rax, %r12
  126d06: 4c 89 ea                     	movq	%r13, %rdx
  126d09: e8 e2 55 f7 ff               	callq	0x9c2f0 <.text+0x77ac0>
  126d0e: 4c 89 25 4b e6 5a 00         	movq	%r12, 0x5ae64b(%rip)    # 0x6d5360 <_ZN9QListData11shared_nullE+0xb00>
  126d15: e9 75 ed ff ff               	jmp	0x125a8f <.text+0x10125f>

## application-constructor handoff to initializer [0x9c6d2,0x9c715)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   9c6d2: 48 89 ef                     	movq	%rbp, %rdi
   9c6d5: e8 a6 14 ff ff               	callq	0x8db80 <.text+0x69350>
   9c6da: 48 8b 54 24 38               	movq	0x38(%rsp), %rdx
   9c6df: 48 89 ef                     	movq	%rbp, %rdi
   9c6e2: 48 8b 74 24 30               	movq	0x30(%rsp), %rsi
   9c6e7: e8 74 15 ff ff               	callq	0x8dc60 <.text+0x69430>
   9c6ec: 48 8b 84 24 28 01 00 00      	movq	0x128(%rsp), %rax
   9c6f4: 64 48 33 04 25 28 00 00 00   	xorq	%fs:0x28, %rax
   9c6fd: 0f 85 c2 00 00 00            	jne	0x9c7c5 <.text+0x77f95>
   9c703: 48 81 c4 38 01 00 00         	addq	$0x138, %rsp            # imm = 0x138
   9c70a: 5b                           	popq	%rbx
   9c70b: 5d                           	popq	%rbp
   9c70c: 41 5c                        	popq	%r12
   9c70e: 41 5d                        	popq	%r13
   9c710: 41 5e                        	popq	%r14
   9c712: 41 5f                        	popq	%r15
   9c714: c3                           	retq

## initializer stores base directory and invokes descriptor reader [0x8dc60,0x8dd51)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   8dc60: 41 55                        	pushq	%r13
   8dc62: 49 89 d5                     	movq	%rdx, %r13
   8dc65: 41 54                        	pushq	%r12
   8dc67: 55                           	pushq	%rbp
   8dc68: 48 89 f5                     	movq	%rsi, %rbp
   8dc6b: 53                           	pushq	%rbx
   8dc6c: 48 89 fb                     	movq	%rdi, %rbx
   8dc6f: 4c 8d 63 30                  	leaq	0x30(%rbx), %r12
   8dc73: 48 83 ec 18                  	subq	$0x18, %rsp
   8dc77: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
   8dc80: 48 89 44 24 08               	movq	%rax, 0x8(%rsp)
   8dc85: 31 c0                        	xorl	%eax, %eax
   8dc87: e8 d4 7f fc ff               	callq	0x55c60 <.text+0x31430>
   8dc8c: 48 8d 15 c5 84 18 00         	leaq	0x1884c5(%rip), %rdx    # 0x216158
   8dc93: 48 8d 35 06 65 18 00         	leaq	0x186506(%rip), %rsi    # 0x2141a0
   8dc9a: 48 89 c7                     	movq	%rax, %rdi
   8dc9d: 31 c0                        	xorl	%eax, %eax
   8dc9f: e8 8c 97 0a 00               	callq	0x137430 <.text+0x112c00>
   8dca4: 48 89 ee                     	movq	%rbp, %rsi
   8dca7: 4c 89 e7                     	movq	%r12, %rdi
   8dcaa: e8 61 63 f9 ff               	callq	0x24010 <_ZN7QStringaSERKS_@plt>
   8dcaf: bf 40 00 00 00               	movl	$0x40, %edi
   8dcb4: e8 37 45 f9 ff               	callq	0x221f0 <_Znwm@plt>
   8dcb9: 48 89 da                     	movq	%rbx, %rdx
   8dcbc: 4c 89 e6                     	movq	%r12, %rsi
   8dcbf: 48 89 c7                     	movq	%rax, %rdi
   8dcc2: 48 89 c5                     	movq	%rax, %rbp
   8dcc5: e8 c6 25 01 00               	callq	0xa0290 <.text+0x7ba60>
   8dcca: 48 89 6b 10                  	movq	%rbp, 0x10(%rbx)
   8dcce: bf b0 00 00 00               	movl	$0xb0, %edi
   8dcd3: e8 18 45 f9 ff               	callq	0x221f0 <_Znwm@plt>
   8dcd8: 48 89 de                     	movq	%rbx, %rsi
   8dcdb: 48 89 c7                     	movq	%rax, %rdi
   8dcde: 48 89 c5                     	movq	%rax, %rbp
   8dce1: e8 aa d9 fe ff               	callq	0x7b690 <.text+0x56e60>
   8dce6: 48 89 6b 28                  	movq	%rbp, 0x28(%rbx)
   8dcea: 4c 89 e6                     	movq	%r12, %rsi
   8dced: 48 89 ef                     	movq	%rbp, %rdi
   8dcf0: c6 43 40 01                  	movb	$0x1, 0x40(%rbx)
   8dcf4: e8 57 df fe ff               	callq	0x7bc50 <.text+0x57420>
   8dcf9: 88 43 40                     	movb	%al, 0x40(%rbx)
   8dcfc: 84 c0                        	testb	%al, %al
   8dcfe: 74 18                        	je	0x8dd18 <.text+0x694e8>
   8dd00: 48 8b 73 28                  	movq	0x28(%rbx), %rsi
   8dd04: 48 8b 7b 10                  	movq	0x10(%rbx), %rdi
   8dd08: 48 8d 56 10                  	leaq	0x10(%rsi), %rdx
   8dd0c: 48 83 c6 20                  	addq	$0x20, %rsi
   8dd10: e8 cb 1c 01 00               	callq	0x9f9e0 <.text+0x7b1b0>
   8dd15: 88 43 40                     	movb	%al, 0x40(%rbx)
   8dd18: 48 8b 44 24 08               	movq	0x8(%rsp), %rax
   8dd1d: 64 48 33 04 25 28 00 00 00   	xorq	%fs:0x28, %rax
   8dd26: 4c 89 6b 38                  	movq	%r13, 0x38(%rbx)
   8dd2a: 75 0b                        	jne	0x8dd37 <.text+0x69507>
   8dd2c: 48 83 c4 18                  	addq	$0x18, %rsp
   8dd30: 5b                           	popq	%rbx
   8dd31: 5d                           	popq	%rbp
   8dd32: 41 5c                        	popq	%r12
   8dd34: 41 5d                        	popq	%r13
   8dd36: c3                           	retq
   8dd37: e8 74 49 f9 ff               	callq	0x226b0 <__stack_chk_fail@plt>
   8dd3c: 48 89 c3                     	movq	%rax, %rbx
   8dd3f: 48 89 ef                     	movq	%rbp, %rdi
   8dd42: e8 f9 50 f9 ff               	callq	0x22e40 <_ZdlPv@plt>
   8dd47: 48 89 df                     	movq	%rbx, %rdi
   8dd4a: e8 41 54 f9 ff               	callq	0x23190 <_Unwind_Resume@plt>
   8dd4f: eb eb                        	jmp	0x8dd3c <.text+0x6950c>

## public-key file verifier wrapper complete FDE [0x45820,0x45d75)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   45820: 41 57                        	pushq	%r15
   45822: 48 8d 3d 31 45 1c 00         	leaq	0x1c4531(%rip), %rdi    # 0x209d5a
   45829: 41 56                        	pushq	%r14
   4582b: 49 89 f6                     	movq	%rsi, %r14
   4582e: be 10 00 00 00               	movl	$0x10, %esi
   45833: 41 55                        	pushq	%r13
   45835: 41 54                        	pushq	%r12
   45837: 55                           	pushq	%rbp
   45838: 53                           	pushq	%rbx
   45839: 48 83 ec 68                  	subq	$0x68, %rsp
   4583d: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
   45846: 48 89 44 24 58               	movq	%rax, 0x58(%rsp)
   4584b: 31 c0                        	xorl	%eax, %eax
   4584d: e8 5e d5 fd ff               	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   45852: be 16 00 00 00               	movl	$0x16, %esi
   45857: 48 8d 3d e5 44 1c 00         	leaq	0x1c44e5(%rip), %rdi    # 0x209d43
   4585e: 48 89 44 24 40               	movq	%rax, 0x40(%rsp)
   45863: e8 48 d5 fd ff               	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   45868: be 04 00 00 00               	movl	$0x4, %esi
   4586d: 48 89 44 24 20               	movq	%rax, 0x20(%rsp)
   45872: 48 8d 3d 87 44 1c 00         	leaq	0x1c4487(%rip), %rdi    # 0x209d00
   45879: e8 32 d5 fd ff               	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   4587e: 48 8d 6c 24 30               	leaq	0x30(%rsp), %rbp
   45883: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   45889: 31 c9                        	xorl	%ecx, %ecx
   4588b: 48 89 44 24 10               	movq	%rax, 0x10(%rsp)
   45890: 4c 8d 7c 24 20               	leaq	0x20(%rsp), %r15
   45895: 48 89 ef                     	movq	%rbp, %rdi
   45898: 4c 8d 64 24 10               	leaq	0x10(%rsp), %r12
   4589d: 4c 89 fa                     	movq	%r15, %rdx
   458a0: 4c 89 e6                     	movq	%r12, %rsi
   458a3: e8 88 d3 fd ff               	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   458a8: 48 8d 5c 24 40               	leaq	0x40(%rsp), %rbx
   458ad: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   458b3: 31 c9                        	xorl	%ecx, %ecx
   458b5: 48 89 da                     	movq	%rbx, %rdx
   458b8: 48 89 ee                     	movq	%rbp, %rsi
   458bb: 48 89 e7                     	movq	%rsp, %rdi
   458be: 49 89 e5                     	movq	%rsp, %r13
   458c1: e8 6a d3 fd ff               	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   458c6: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   458cb: 8b 07                        	movl	(%rdi), %eax
   458cd: 85 c0                        	testl	%eax, %eax
   458cf: 0f 85 03 02 00 00            	jne	0x45ad8 <.text+0x212a8>
   458d5: ba 08 00 00 00               	movl	$0x8, %edx
   458da: be 02 00 00 00               	movl	$0x2, %esi
   458df: e8 fc e5 fd ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   458e4: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   458e9: 8b 07                        	movl	(%rdi), %eax
   458eb: 85 c0                        	testl	%eax, %eax
   458ed: 0f 85 5d 02 00 00            	jne	0x45b50 <.text+0x21320>
   458f3: ba 08 00 00 00               	movl	$0x8, %edx
   458f8: be 02 00 00 00               	movl	$0x2, %esi
   458fd: e8 de e5 fd ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   45902: 48 8b 7c 24 20               	movq	0x20(%rsp), %rdi
   45907: 8b 07                        	movl	(%rdi), %eax
   45909: 85 c0                        	testl	%eax, %eax
   4590b: 0f 85 17 02 00 00            	jne	0x45b28 <.text+0x212f8>
   45911: ba 08 00 00 00               	movl	$0x8, %edx
   45916: be 02 00 00 00               	movl	$0x2, %esi
   4591b: e8 c0 e5 fd ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   45920: 48 8b 7c 24 40               	movq	0x40(%rsp), %rdi
   45925: 8b 07                        	movl	(%rdi), %eax
   45927: 85 c0                        	testl	%eax, %eax
   45929: 0f 85 d1 01 00 00            	jne	0x45b00 <.text+0x212d0>
   4592f: ba 08 00 00 00               	movl	$0x8, %edx
   45934: be 02 00 00 00               	movl	$0x2, %esi
   45939: e8 a2 e5 fd ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   4593e: 4c 89 ee                     	movq	%r13, %rsi
   45941: 48 89 df                     	movq	%rbx, %rdi
   45944: e8 b7 d3 fd ff               	callq	0x22d00 <_ZN5QFileC1ERK7QString@plt>
   45949: 48 89 df                     	movq	%rbx, %rdi
   4594c: e8 4f e0 fd ff               	callq	0x239a0 <_ZNK5QFile6existsEv@plt>
   45951: 84 c0                        	testb	%al, %al
   45953: 0f 84 57 03 00 00            	je	0x45cb0 <.text+0x21480>
   45959: 48 8d 05 40 ed 68 00         	leaq	0x68ed40(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
   45960: 4c 89 e7                     	movq	%r12, %rdi
   45963: 48 89 44 24 10               	movq	%rax, 0x10(%rsp)
   45968: e8 33 da fd ff               	callq	0x233a0 <_ZN10QByteArray5clearEv@plt>
   4596d: be 01 00 00 00               	movl	$0x1, %esi
   45972: 48 89 df                     	movq	%rbx, %rdi
   45975: e8 16 cd fd ff               	callq	0x22690 <_ZN5QFile4openE6QFlagsIN9QIODevice12OpenModeFlagEE@plt>
   4597a: 84 c0                        	testb	%al, %al
   4597c: 0f 84 f6 01 00 00            	je	0x45b78 <.text+0x21348>
   45982: 48 89 de                     	movq	%rbx, %rsi
   45985: 4c 89 ff                     	movq	%r15, %rdi
   45988: e8 73 e7 fd ff               	callq	0x24100 <_ZN9QIODevice7readAllEv@plt>
   4598d: 4c 89 fe                     	movq	%r15, %rsi
   45990: 4c 89 e7                     	movq	%r12, %rdi
   45993: e8 f8 e0 fd ff               	callq	0x23a90 <_ZN10QByteArray6appendERKS_@plt>
   45998: 48 8b 7c 24 20               	movq	0x20(%rsp), %rdi
   4599d: 8b 07                        	movl	(%rdi), %eax
   4599f: 85 c0                        	testl	%eax, %eax
   459a1: 0f 85 59 02 00 00            	jne	0x45c00 <.text+0x213d0>
   459a7: ba 08 00 00 00               	movl	$0x8, %edx
   459ac: be 01 00 00 00               	movl	$0x1, %esi
   459b1: e8 2a e5 fd ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   459b6: 48 89 df                     	movq	%rbx, %rdi
   459b9: e8 62 c6 fd ff               	callq	0x22020 <_ZN11QFileDevice5closeEv@plt>
   459be: 48 8b 74 24 10               	movq	0x10(%rsp), %rsi
   459c3: 83 3e 01                     	cmpl	$0x1, (%rsi)
   459c6: 0f 86 84 02 00 00            	jbe	0x45c50 <.text+0x21420>
   459cc: 0f be 56 0b                  	movsbl	0xb(%rsi), %edx
   459d0: 4c 89 e7                     	movq	%r12, %rdi
   459d3: 8b 76 04                     	movl	0x4(%rsi), %esi
   459d6: c1 ea 1f                     	shrl	$0x1f, %edx
   459d9: 83 c6 01                     	addl	$0x1, %esi
   459dc: e8 0f dd fd ff               	callq	0x236f0 <_ZN10QByteArray11reallocDataEj6QFlagsIN10QArrayData16AllocationOptionEE@plt>
   459e1: 48 8b 74 24 10               	movq	0x10(%rsp), %rsi
   459e6: 44 8b 4e 04                  	movl	0x4(%rsi), %r9d
   459ea: 48 8b 46 10                  	movq	0x10(%rsi), %rax
   459ee: 45 85 c9                     	testl	%r9d, %r9d
   459f1: 0f 84 79 02 00 00            	je	0x45c70 <.text+0x21440>
   459f7: 49 89 c7                     	movq	%rax, %r15
   459fa: 48 83 f8 17                  	cmpq	$0x17, %rax
   459fe: 0f 86 bb 02 00 00            	jbe	0x45cbf <.text+0x2148f>
   45a04: 49 01 f7                     	addq	%rsi, %r15
   45a07: 49 8b 36                     	movq	(%r14), %rsi
   45a0a: 8b 56 04                     	movl	0x4(%rsi), %edx
   45a0d: 48 8b 46 10                  	movq	0x10(%rsi), %rax
   45a11: 85 d2                        	testl	%edx, %edx
   45a13: 74 0a                        	je	0x45a1f <.text+0x211ef>
   45a15: 48 83 f8 17                  	cmpq	$0x17, %rax
   45a19: 0f 86 a0 02 00 00            	jbe	0x45cbf <.text+0x2148f>
   45a1f: 48 01 c6                     	addq	%rax, %rsi
   45a22: 48 89 ef                     	movq	%rbp, %rdi
   45a25: e8 46 ca fd ff               	callq	0x22470 <_ZN7QString18toLocal8Bit_helperEPK5QChari@plt>
   45a2a: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   45a2f: 83 3f 01                     	cmpl	$0x1, (%rdi)
   45a32: 0f 86 48 02 00 00            	jbe	0x45c80 <.text+0x21450>
   45a38: 0f be 57 0b                  	movsbl	0xb(%rdi), %edx
   45a3c: 8b 77 04                     	movl	0x4(%rdi), %esi
   45a3f: 48 89 ef                     	movq	%rbp, %rdi
   45a42: c1 ea 1f                     	shrl	$0x1f, %edx
   45a45: 83 c6 01                     	addl	$0x1, %esi
   45a48: e8 a3 dc fd ff               	callq	0x236f0 <_ZN10QByteArray11reallocDataEj6QFlagsIN10QArrayData16AllocationOptionEE@plt>
   45a4d: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   45a52: 44 8b 47 04                  	movl	0x4(%rdi), %r8d
   45a56: 48 8b 57 10                  	movq	0x10(%rdi), %rdx
   45a5a: 45 85 c0                     	testl	%r8d, %r8d
   45a5d: 0f 84 3d 02 00 00            	je	0x45ca0 <.text+0x21470>
   45a63: 48 89 d0                     	movq	%rdx, %rax
   45a66: 48 83 fa 17                  	cmpq	$0x17, %rdx
   45a6a: 0f 86 4f 02 00 00            	jbe	0x45cbf <.text+0x2148f>
   45a70: 48 01 c7                     	addq	%rax, %rdi
   45a73: 4c 89 fe                     	movq	%r15, %rsi
   45a76: e8 c5 9c 14 00               	callq	0x18f740 <.text+0x16af10>
   45a7b: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   45a80: 89 c5                        	movl	%eax, %ebp
   45a82: 8b 17                        	movl	(%rdi), %edx
   45a84: 85 d2                        	testl	%edx, %edx
   45a86: 0f 85 9c 01 00 00            	jne	0x45c28 <.text+0x213f8>
   45a8c: ba 08 00 00 00               	movl	$0x8, %edx
   45a91: be 01 00 00 00               	movl	$0x1, %esi
   45a96: e8 45 e4 fd ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   45a9b: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   45aa0: 8b 07                        	movl	(%rdi), %eax
   45aa2: 85 c0                        	testl	%eax, %eax
   45aa4: 0f 84 e2 00 00 00            	je	0x45b8c <.text+0x2135c>
   45aaa: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   45ab0: 83 f8 ff                     	cmpl	$-0x1, %eax
   45ab3: 0f 84 e2 00 00 00            	je	0x45b9b <.text+0x2136b>
   45ab9: f0                           	lock
   45aba: 83 2f 01                     	subl	$0x1, (%rdi)
   45abd: 0f 95 c0                     	setne	%al
   45ac0: 84 c0                        	testb	%al, %al
   45ac2: 0f 85 d3 00 00 00            	jne	0x45b9b <.text+0x2136b>
   45ac8: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   45acd: e9 ba 00 00 00               	jmp	0x45b8c <.text+0x2135c>
   45ad2: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   45ad8: 83 f8 ff                     	cmpl	$-0x1, %eax
   45adb: 0f 84 03 fe ff ff            	je	0x458e4 <.text+0x210b4>
   45ae1: f0                           	lock
   45ae2: 83 2f 01                     	subl	$0x1, (%rdi)
   45ae5: 0f 95 c0                     	setne	%al
   45ae8: 84 c0                        	testb	%al, %al
   45aea: 0f 85 f4 fd ff ff            	jne	0x458e4 <.text+0x210b4>
   45af0: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   45af5: e9 db fd ff ff               	jmp	0x458d5 <.text+0x210a5>
   45afa: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   45b00: 83 f8 ff                     	cmpl	$-0x1, %eax
   45b03: 0f 84 35 fe ff ff            	je	0x4593e <.text+0x2110e>
   45b09: f0                           	lock
   45b0a: 83 2f 01                     	subl	$0x1, (%rdi)
   45b0d: 0f 95 c0                     	setne	%al
   45b10: 84 c0                        	testb	%al, %al
   45b12: 0f 85 26 fe ff ff            	jne	0x4593e <.text+0x2110e>
   45b18: 48 8b 7c 24 40               	movq	0x40(%rsp), %rdi
   45b1d: e9 0d fe ff ff               	jmp	0x4592f <.text+0x210ff>
   45b22: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   45b28: 83 f8 ff                     	cmpl	$-0x1, %eax
   45b2b: 0f 84 ef fd ff ff            	je	0x45920 <.text+0x210f0>
   45b31: f0                           	lock
   45b32: 83 2f 01                     	subl	$0x1, (%rdi)
   45b35: 0f 95 c0                     	setne	%al
   45b38: 84 c0                        	testb	%al, %al
   45b3a: 0f 85 e0 fd ff ff            	jne	0x45920 <.text+0x210f0>
   45b40: 48 8b 7c 24 20               	movq	0x20(%rsp), %rdi
   45b45: e9 c7 fd ff ff               	jmp	0x45911 <.text+0x210e1>
   45b4a: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   45b50: 83 f8 ff                     	cmpl	$-0x1, %eax
   45b53: 0f 84 a9 fd ff ff            	je	0x45902 <.text+0x210d2>
   45b59: f0                           	lock
   45b5a: 83 2f 01                     	subl	$0x1, (%rdi)
   45b5d: 0f 95 c0                     	setne	%al
   45b60: 84 c0                        	testb	%al, %al
   45b62: 0f 85 9a fd ff ff            	jne	0x45902 <.text+0x210d2>
   45b68: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   45b6d: e9 81 fd ff ff               	jmp	0x458f3 <.text+0x210c3>
   45b72: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   45b78: bd 9b ff ff ff               	movl	$0xffffff9b, %ebp       # imm = 0xFFFFFF9B
   45b7d: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   45b82: 8b 07                        	movl	(%rdi), %eax
   45b84: 85 c0                        	testl	%eax, %eax
   45b86: 0f 85 24 ff ff ff            	jne	0x45ab0 <.text+0x21280>
   45b8c: ba 08 00 00 00               	movl	$0x8, %edx
   45b91: be 01 00 00 00               	movl	$0x1, %esi
   45b96: e8 45 e3 fd ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   45b9b: 48 89 df                     	movq	%rbx, %rdi
   45b9e: e8 cd d0 fd ff               	callq	0x22c70 <_ZN5QFileD1Ev@plt>
   45ba3: 48 8b 3c 24                  	movq	(%rsp), %rdi
   45ba7: 8b 07                        	movl	(%rdi), %eax
   45ba9: 85 c0                        	testl	%eax, %eax
   45bab: 75 3b                        	jne	0x45be8 <.text+0x213b8>
   45bad: ba 08 00 00 00               	movl	$0x8, %edx
   45bb2: be 02 00 00 00               	movl	$0x2, %esi
   45bb7: e8 24 e3 fd ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   45bbc: 48 8b 4c 24 58               	movq	0x58(%rsp), %rcx
   45bc1: 64 48 33 0c 25 28 00 00 00   	xorq	%fs:0x28, %rcx
   45bca: 89 e8                        	movl	%ebp, %eax
   45bcc: 0f 85 e8 00 00 00            	jne	0x45cba <.text+0x2148a>
   45bd2: 48 83 c4 68                  	addq	$0x68, %rsp
   45bd6: 5b                           	popq	%rbx
   45bd7: 5d                           	popq	%rbp
   45bd8: 41 5c                        	popq	%r12
   45bda: 41 5d                        	popq	%r13
   45bdc: 41 5e                        	popq	%r14
   45bde: 41 5f                        	popq	%r15
   45be0: c3                           	retq
   45be1: 0f 1f 80 00 00 00 00         	nopl	(%rax)
   45be8: 83 f8 ff                     	cmpl	$-0x1, %eax
   45beb: 74 cf                        	je	0x45bbc <.text+0x2138c>
   45bed: f0                           	lock
   45bee: 83 2f 01                     	subl	$0x1, (%rdi)
   45bf1: 0f 95 c0                     	setne	%al
   45bf4: 84 c0                        	testb	%al, %al
   45bf6: 75 c4                        	jne	0x45bbc <.text+0x2138c>
   45bf8: 48 8b 3c 24                  	movq	(%rsp), %rdi
   45bfc: eb af                        	jmp	0x45bad <.text+0x2137d>
   45bfe: 66 90                        	nop
   45c00: 83 f8 ff                     	cmpl	$-0x1, %eax
   45c03: 0f 84 ad fd ff ff            	je	0x459b6 <.text+0x21186>
   45c09: f0                           	lock
   45c0a: 83 2f 01                     	subl	$0x1, (%rdi)
   45c0d: 0f 95 c0                     	setne	%al
   45c10: 84 c0                        	testb	%al, %al
   45c12: 0f 85 9e fd ff ff            	jne	0x459b6 <.text+0x21186>
   45c18: 48 8b 7c 24 20               	movq	0x20(%rsp), %rdi
   45c1d: e9 85 fd ff ff               	jmp	0x459a7 <.text+0x21177>
   45c22: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   45c28: 83 fa ff                     	cmpl	$-0x1, %edx
   45c2b: 0f 84 4c ff ff ff            	je	0x45b7d <.text+0x2134d>
   45c31: f0                           	lock
   45c32: 83 2f 01                     	subl	$0x1, (%rdi)
   45c35: 0f 95 c0                     	setne	%al
   45c38: 84 c0                        	testb	%al, %al
   45c3a: 0f 85 3d ff ff ff            	jne	0x45b7d <.text+0x2134d>
   45c40: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   45c45: e9 42 fe ff ff               	jmp	0x45a8c <.text+0x2125c>
   45c4a: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   45c50: 48 8b 46 10                  	movq	0x10(%rsi), %rax
   45c54: 48 83 f8 18                  	cmpq	$0x18, %rax
   45c58: 0f 85 6e fd ff ff            	jne	0x459cc <.text+0x2119c>
   45c5e: 8b 7e 04                     	movl	0x4(%rsi), %edi
   45c61: 41 bf 18 00 00 00            	movl	$0x18, %r15d
   45c67: 85 ff                        	testl	%edi, %edi
   45c69: 0f 85 95 fd ff ff            	jne	0x45a04 <.text+0x211d4>
   45c6f: 90                           	nop
   45c70: 49 89 c7                     	movq	%rax, %r15
   45c73: e9 8c fd ff ff               	jmp	0x45a04 <.text+0x211d4>
   45c78: 0f 1f 84 00 00 00 00 00      	nopl	(%rax,%rax)
   45c80: 48 8b 57 10                  	movq	0x10(%rdi), %rdx
   45c84: 48 83 fa 18                  	cmpq	$0x18, %rdx
   45c88: 0f 85 aa fd ff ff            	jne	0x45a38 <.text+0x21208>
   45c8e: 8b 4f 04                     	movl	0x4(%rdi), %ecx
   45c91: b8 18 00 00 00               	movl	$0x18, %eax
   45c96: 85 c9                        	testl	%ecx, %ecx
   45c98: 0f 85 d2 fd ff ff            	jne	0x45a70 <.text+0x21240>
   45c9e: 66 90                        	nop
   45ca0: 48 89 d0                     	movq	%rdx, %rax
   45ca3: e9 c8 fd ff ff               	jmp	0x45a70 <.text+0x21240>
   45ca8: 0f 1f 84 00 00 00 00 00      	nopl	(%rax,%rax)
   45cb0: bd 9c ff ff ff               	movl	$0xffffff9c, %ebp       # imm = 0xFFFFFF9C
   45cb5: e9 e1 fe ff ff               	jmp	0x45b9b <.text+0x2136b>
   45cba: e8 f1 c9 fd ff               	callq	0x226b0 <__stack_chk_fail@plt>
   45cbf: 48 8d 35 d2 3d 1c 00         	leaq	0x1c3dd2(%rip), %rsi    # 0x209a98
   45cc6: ba 36 00 00 00               	movl	$0x36, %edx
   45ccb: 48 8d 3d 66 3e 1c 00         	leaq	0x1c3e66(%rip), %rdi    # 0x209b38
   45cd2: e8 29 cc fd ff               	callq	0x22900 <_Z9qt_assertPKcS0_i@plt>
   45cd7: 48 89 c3                     	movq	%rax, %rbx
   45cda: 4c 89 ef                     	movq	%r13, %rdi
   45cdd: e8 7e 5c 00 00               	callq	0x4b960 <.text+0x27130>
   45ce2: 48 89 df                     	movq	%rbx, %rdi
   45ce5: e8 a6 d4 fd ff               	callq	0x23190 <_Unwind_Resume@plt>
   45cea: 49 89 c5                     	movq	%rax, %r13
   45ced: 48 89 ef                     	movq	%rbp, %rdi
   45cf0: e8 6b 5c 00 00               	callq	0x4b960 <.text+0x27130>
   45cf5: 4c 89 ed                     	movq	%r13, %rbp
   45cf8: 4c 89 e7                     	movq	%r12, %rdi
   45cfb: e8 60 5c 00 00               	callq	0x4b960 <.text+0x27130>
   45d00: 4c 89 ff                     	movq	%r15, %rdi
   45d03: e8 58 5c 00 00               	callq	0x4b960 <.text+0x27130>
   45d08: 48 89 df                     	movq	%rbx, %rdi
   45d0b: e8 50 5c 00 00               	callq	0x4b960 <.text+0x27130>
   45d10: 48 89 ef                     	movq	%rbp, %rdi
   45d13: e8 78 d4 fd ff               	callq	0x23190 <_Unwind_Resume@plt>
   45d18: 49 89 c6                     	movq	%rax, %r14
   45d1b: 48 89 ef                     	movq	%rbp, %rdi
   45d1e: e8 bd 5b 00 00               	callq	0x4b8e0 <.text+0x270b0>
   45d23: 4c 89 f5                     	movq	%r14, %rbp
   45d26: 4c 89 e7                     	movq	%r12, %rdi
   45d29: e8 b2 5b 00 00               	callq	0x4b8e0 <.text+0x270b0>
   45d2e: 48 89 df                     	movq	%rbx, %rdi
   45d31: 48 89 eb                     	movq	%rbp, %rbx
   45d34: e8 37 cf fd ff               	callq	0x22c70 <_ZN5QFileD1Ev@plt>
   45d39: eb 9f                        	jmp	0x45cda <.text+0x214aa>
   45d3b: 4c 89 ff                     	movq	%r15, %rdi
   45d3e: 48 89 c5                     	movq	%rax, %rbp
   45d41: e8 9a 5b 00 00               	callq	0x4b8e0 <.text+0x270b0>
   45d46: eb de                        	jmp	0x45d26 <.text+0x214f6>
   45d48: 48 8d 5c 24 40               	leaq	0x40(%rsp), %rbx
   45d4d: 48 89 c5                     	movq	%rax, %rbp
   45d50: eb a6                        	jmp	0x45cf8 <.text+0x214c8>
   45d52: 4c 8d 7c 24 20               	leaq	0x20(%rsp), %r15
   45d57: 48 89 c5                     	movq	%rax, %rbp
   45d5a: 48 8d 5c 24 40               	leaq	0x40(%rsp), %rbx
   45d5f: eb 9f                        	jmp	0x45d00 <.text+0x214d0>
   45d61: 48 89 c5                     	movq	%rax, %rbp
   45d64: eb c0                        	jmp	0x45d26 <.text+0x214f6>
   45d66: 48 89 c5                     	movq	%rax, %rbp
   45d69: eb c3                        	jmp	0x45d2e <.text+0x214fe>
   45d6b: 48 8d 5c 24 40               	leaq	0x40(%rsp), %rbx
   45d70: 48 89 c5                     	movq	%rax, %rbp
   45d73: eb 93                        	jmp	0x45d08 <.text+0x214d8>

## signed-container internal verifier routines [0x18f5a0,0x18f7df)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  18f5a0: 41 54                        	pushq	%r12
  18f5a2: 55                           	pushq	%rbp
  18f5a3: 53                           	pushq	%rbx
  18f5a4: 48 83 ec 50                  	subq	$0x50, %rsp
  18f5a8: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
  18f5b1: 48 89 44 24 48               	movq	%rax, 0x48(%rsp)
  18f5b6: 31 c0                        	xorl	%eax, %eax
  18f5b8: 48 c7 04 24 00 00 00 00      	movq	$0x0, (%rsp)
  18f5c0: 48 c7 44 24 08 00 00 00 00   	movq	$0x0, 0x8(%rsp)
  18f5c9: 48 c7 44 24 10 00 00 00 00   	movq	$0x0, 0x10(%rsp)
  18f5d2: 48 c7 44 24 18 00 00 00 00   	movq	$0x0, 0x18(%rsp)
  18f5db: 48 85 ff                     	testq	%rdi, %rdi
  18f5de: 0f 84 fc 00 00 00            	je	0x18f6e0 <.text+0x16aeb0>
  18f5e4: 48 89 f5                     	movq	%rsi, %rbp
  18f5e7: e8 f4 e3 ff ff               	callq	0x18d9e0 <.text+0x1691b0>
  18f5ec: 48 89 c3                     	movq	%rax, %rbx
  18f5ef: 48 85 c0                     	testq	%rax, %rax
  18f5f2: 0f 84 f8 00 00 00            	je	0x18f6f0 <.text+0x16aec0>
  18f5f8: 48 8d 78 10                  	leaq	0x10(%rax), %rdi
  18f5fc: 48 89 e6                     	movq	%rsp, %rsi
  18f5ff: 49 89 e4                     	movq	%rsp, %r12
  18f602: e8 69 95 01 00               	callq	0x1a8b70 <mbedtls_ctr_drbg_random+0xff70>
  18f607: 48 85 ed                     	testq	%rbp, %rbp
  18f60a: 0f 84 90 00 00 00            	je	0x18f6a0 <.text+0x16ae70>
  18f610: 48 8d 35 89 98 2c 00         	leaq	0x2c9889(%rip), %rsi    # 0x458ea0
  18f617: 48 89 ef                     	movq	%rbp, %rdi
  18f61a: e8 41 36 e9 ff               	callq	0x22c60 <strstr@plt>
  18f61f: 48 85 c0                     	testq	%rax, %rax
  18f622: 74 7c                        	je	0x18f6a0 <.text+0x16ae70>
  18f624: 48 8d 6c 24 20               	leaq	0x20(%rsp), %rbp
  18f629: 48 89 df                     	movq	%rbx, %rdi
  18f62c: 48 c7 44 24 20 00 00 00 00   	movq	$0x0, 0x20(%rsp)
  18f635: 48 c7 44 24 28 00 00 00 00   	movq	$0x0, 0x28(%rsp)
  18f63e: 48 89 ee                     	movq	%rbp, %rsi
  18f641: 48 c7 44 24 30 00 00 00 00   	movq	$0x0, 0x30(%rsp)
  18f64a: 48 c7 44 24 38 00 00 00 00   	movq	$0x0, 0x38(%rsp)
  18f653: e8 68 e4 ff ff               	callq	0x18dac0 <.text+0x169290>
  18f658: 89 c2                        	movl	%eax, %edx
  18f65a: b8 6e fe ff ff               	movl	$0xfffffe6e, %eax       # imm = 0xFFFFFE6E
  18f65f: 85 d2                        	testl	%edx, %edx
  18f661: 75 1a                        	jne	0x18f67d <.text+0x16ae4d>
  18f663: ba 20 00 00 00               	movl	$0x20, %edx
  18f668: 48 89 e6                     	movq	%rsp, %rsi
  18f66b: 48 89 ef                     	movq	%rbp, %rdi
  18f66e: e8 1d 4c e9 ff               	callq	0x24290 <memcmp@plt>
  18f673: ba 6d fe ff ff               	movl	$0xfffffe6d, %edx       # imm = 0xFFFFFE6D
  18f678: 85 c0                        	testl	%eax, %eax
  18f67a: 0f 45 c2                     	cmovnel	%edx, %eax
  18f67d: 48 8b 4c 24 48               	movq	0x48(%rsp), %rcx
  18f682: 64 48 33 0c 25 28 00 00 00   	xorq	%fs:0x28, %rcx
  18f68b: 75 6a                        	jne	0x18f6f7 <.text+0x16aec7>
  18f68d: 48 83 c4 50                  	addq	$0x50, %rsp
  18f691: 5b                           	popq	%rbx
  18f692: 5d                           	popq	%rbp
  18f693: 41 5c                        	popq	%r12
  18f695: c3                           	retq
  18f696: 66 2e 0f 1f 84 00 00 00 00 00	nopw	%cs:(%rax,%rax)
  18f6a0: 48 8b 43 08                  	movq	0x8(%rbx), %rax
  18f6a4: 8b 50 08                     	movl	0x8(%rax), %edx
  18f6a7: 83 fa 02                     	cmpl	$0x2, %edx
  18f6aa: 74 1c                        	je	0x18f6c8 <.text+0x16ae98>
  18f6ac: 31 c0                        	xorl	%eax, %eax
  18f6ae: 83 fa 03                     	cmpl	$0x3, %edx
  18f6b1: 75 ca                        	jne	0x18f67d <.text+0x16ae4d>
  18f6b3: 48 89 ea                     	movq	%rbp, %rdx
  18f6b6: 4c 89 e6                     	movq	%r12, %rsi
  18f6b9: 48 89 df                     	movq	%rbx, %rdi
  18f6bc: e8 0f e9 ff ff               	callq	0x18dfd0 <.text+0x1697a0>
  18f6c1: eb ba                        	jmp	0x18f67d <.text+0x16ae4d>
  18f6c3: 0f 1f 44 00 00               	nopl	(%rax,%rax)
  18f6c8: 48 89 ea                     	movq	%rbp, %rdx
  18f6cb: 4c 89 e6                     	movq	%r12, %rsi
  18f6ce: 48 89 df                     	movq	%rbx, %rdi
  18f6d1: e8 7a e6 ff ff               	callq	0x18dd50 <.text+0x169520>
  18f6d6: eb a5                        	jmp	0x18f67d <.text+0x16ae4d>
  18f6d8: 0f 1f 84 00 00 00 00 00      	nopl	(%rax,%rax)
  18f6e0: b8 70 fe ff ff               	movl	$0xfffffe70, %eax       # imm = 0xFFFFFE70
  18f6e5: eb 96                        	jmp	0x18f67d <.text+0x16ae4d>
  18f6e7: 66 0f 1f 84 00 00 00 00 00   	nopw	(%rax,%rax)
  18f6f0: b8 69 fe ff ff               	movl	$0xfffffe69, %eax       # imm = 0xFFFFFE69
  18f6f5: eb 86                        	jmp	0x18f67d <.text+0x16ae4d>
  18f6f7: e8 b4 2f e9 ff               	callq	0x226b0 <__stack_chk_fail@plt>
  18f6fc: 0f 1f 40 00                  	nopl	(%rax)
  18f700: 48 83 ec 18                  	subq	$0x18, %rsp
  18f704: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
  18f70d: 48 89 44 24 08               	movq	%rax, 0x8(%rsp)
  18f712: 31 c0                        	xorl	%eax, %eax
  18f714: 48 8b 44 24 08               	movq	0x8(%rsp), %rax
  18f719: 64 48 33 04 25 28 00 00 00   	xorq	%fs:0x28, %rax
  18f722: 75 09                        	jne	0x18f72d <.text+0x16aefd>
  18f724: 48 83 c4 18                  	addq	$0x18, %rsp
  18f728: e9 73 fe ff ff               	jmp	0x18f5a0 <.text+0x16ad70>
  18f72d: e8 7e 2f e9 ff               	callq	0x226b0 <__stack_chk_fail@plt>
  18f732: 0f 1f 40 00                  	nopl	(%rax)
  18f736: 66 2e 0f 1f 84 00 00 00 00 00	nopw	%cs:(%rax,%rax)
  18f740: 55                           	pushq	%rbp
  18f741: 48 89 f5                     	movq	%rsi, %rbp
  18f744: 31 f6                        	xorl	%esi, %esi
  18f746: 53                           	pushq	%rbx
  18f747: 48 83 ec 28                  	subq	$0x28, %rsp
  18f74b: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
  18f754: 48 89 44 24 18               	movq	%rax, 0x18(%rsp)
  18f759: 31 c0                        	xorl	%eax, %eax
  18f75b: 48 8d 54 24 14               	leaq	0x14(%rsp), %rdx
  18f760: c7 44 24 14 00 00 00 00      	movl	$0x0, 0x14(%rsp)
  18f768: e8 b3 ed ff ff               	callq	0x18e520 <.text+0x169cf0>
  18f76d: 48 85 c0                     	testq	%rax, %rax
  18f770: 74 36                        	je	0x18f7a8 <.text+0x16af78>
  18f772: 48 89 c3                     	movq	%rax, %rbx
  18f775: eb 0d                        	jmp	0x18f784 <.text+0x16af54>
  18f777: 66 0f 1f 84 00 00 00 00 00   	nopw	(%rax,%rax)
  18f780: 85 c0                        	testl	%eax, %eax
  18f782: 78 44                        	js	0x18f7c8 <.text+0x16af98>
  18f784: 48 89 df                     	movq	%rbx, %rdi
  18f787: e8 d4 fd ff ff               	callq	0x18f560 <.text+0x16ad30>
  18f78c: 83 f8 63                     	cmpl	$0x63, %eax
  18f78f: 7e ef                        	jle	0x18f780 <.text+0x16af50>
  18f791: 48 89 df                     	movq	%rbx, %rdi
  18f794: 48 89 ee                     	movq	%rbp, %rsi
  18f797: e8 64 ff ff ff               	callq	0x18f700 <.text+0x16aed0>
  18f79c: 48 89 df                     	movq	%rbx, %rdi
  18f79f: 89 44 24 14                  	movl	%eax, 0x14(%rsp)
  18f7a3: e8 c8 f6 ff ff               	callq	0x18ee70 <.text+0x16a640>
  18f7a8: 8b 44 24 14                  	movl	0x14(%rsp), %eax
  18f7ac: 48 8b 4c 24 18               	movq	0x18(%rsp), %rcx
  18f7b1: 64 48 33 0c 25 28 00 00 00   	xorq	%fs:0x28, %rcx
  18f7ba: 75 1e                        	jne	0x18f7da <.text+0x16afaa>
  18f7bc: 48 83 c4 28                  	addq	$0x28, %rsp
  18f7c0: 5b                           	popq	%rbx
  18f7c1: 5d                           	popq	%rbp
  18f7c2: c3                           	retq
  18f7c3: 0f 1f 44 00 00               	nopl	(%rax,%rax)
  18f7c8: 48 89 df                     	movq	%rbx, %rdi
  18f7cb: 89 44 24 0c                  	movl	%eax, 0xc(%rsp)
  18f7cf: e8 9c f6 ff ff               	callq	0x18ee70 <.text+0x16a640>
  18f7d4: 8b 44 24 0c                  	movl	0xc(%rsp), %eax
  18f7d8: eb d2                        	jmp	0x18f7ac <.text+0x16af7c>
  18f7da: e8 d1 2e e9 ff               	callq	0x226b0 <__stack_chk_fail@plt>

## signed descriptor call branch [0x7bda2,0x7bea0)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   7bda2: ba 11 00 00 00               	movl	$0x11, %edx
   7bda7: 48 8d 35 aa 64 19 00         	leaq	0x1964aa(%rip), %rsi    # 0x212258
   7bdae: 48 89 c7                     	movq	%rax, %rdi
   7bdb1: 49 89 c6                     	movq	%rax, %r14
   7bdb4: 48 89 04 24                  	movq	%rax, (%rsp)
   7bdb8: e8 13 66 fa ff               	callq	0x223d0 <_ZN7QString15fromUtf8_helperEPKci@plt>
   7bdbd: 48 8d 84 24 20 02 00 00      	leaq	0x220(%rsp), %rax
   7bdc5: 4c 89 f6                     	movq	%r14, %rsi
   7bdc8: 48 89 c7                     	movq	%rax, %rdi
   7bdcb: 48 89 44 24 38               	movq	%rax, 0x38(%rsp)
   7bdd0: e8 3b 81 fa ff               	callq	0x23f10 <_ZN7QString6appendERKS_@plt>
   7bdd5: 48 8b bc 24 80 03 00 00      	movq	0x380(%rsp), %rdi
   7bddd: 8b 07                        	movl	(%rdi), %eax
   7bddf: 85 c0                        	testl	%eax, %eax
   7bde1: 0f 85 f9 05 00 00            	jne	0x7c3e0 <.text+0x57bb0>
   7bde7: ba 08 00 00 00               	movl	$0x8, %edx
   7bdec: be 02 00 00 00               	movl	$0x2, %esi
   7bdf1: e8 ea 80 fa ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   7bdf6: 48 8d 05 a3 88 65 00         	leaq	0x6588a3(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
   7bdfd: 48 89 84 24 30 02 00 00      	movq	%rax, 0x230(%rsp)
   7be05: 48 8b 84 24 20 02 00 00      	movq	0x220(%rsp), %rax
   7be0d: 8b 08                        	movl	(%rax), %ecx
   7be0f: 48 89 84 24 80 03 00 00      	movq	%rax, 0x380(%rsp)
   7be17: 8d 51 01                     	leal	0x1(%rcx), %edx
   7be1a: 83 fa 01                     	cmpl	$0x1, %edx
   7be1d: 76 07                        	jbe	0x7be26 <.text+0x575f6>
   7be1f: f0                           	lock
   7be20: 83 00 01                     	addl	$0x1, (%rax)
   7be23: 0f 95 c2                     	setne	%dl
   7be26: 48 8b 3d 5b 8a 65 00         	movq	0x658a5b(%rip), %rdi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
   7be2d: 48 85 ff                     	testq	%rdi, %rdi
   7be30: 0f 84 ba 1a 00 00            	je	0x7d8f0 <.text+0x590c0>
   7be36: 48 8b 34 24                  	movq	(%rsp), %rsi
   7be3a: e8 e1 99 fc ff               	callq	0x45820 <.text+0x20ff0>
   7be3f: 48 8b bc 24 80 03 00 00      	movq	0x380(%rsp), %rdi
   7be47: 89 c5                        	movl	%eax, %ebp
   7be49: 8b 07                        	movl	(%rdi), %eax
   7be4b: 85 c0                        	testl	%eax, %eax
   7be4d: 0f 85 4d 08 00 00            	jne	0x7c6a0 <.text+0x57e70>
   7be53: ba 08 00 00 00               	movl	$0x8, %edx
   7be58: be 02 00 00 00               	movl	$0x2, %esi
   7be5d: e8 7e 80 fa ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   7be62: 48 8b b4 24 20 02 00 00      	movq	0x220(%rsp), %rsi
   7be6a: 85 ed                        	testl	%ebp, %ebp
   7be6c: 0f 85 be 05 00 00            	jne	0x7c430 <.text+0x57c00>
   7be72: 8b 06                        	movl	(%rsi), %eax
   7be74: 48 89 b4 24 40 02 00 00      	movq	%rsi, 0x240(%rsp)
   7be7c: 83 c0 01                     	addl	$0x1, %eax
   7be7f: 83 f8 01                     	cmpl	$0x1, %eax
   7be82: 76 0f                        	jbe	0x7be93 <.text+0x57663>
   7be84: f0                           	lock
   7be85: 83 06 01                     	addl	$0x1, (%rsi)
   7be88: 0f 95 c0                     	setne	%al
   7be8b: 48 8b b4 24 40 02 00 00      	movq	0x240(%rsp), %rsi
   7be93: 8b 56 04                     	movl	0x4(%rsi), %edx
   7be96: 48 8b 46 10                  	movq	0x10(%rsi), %rax
   7be9a: 85 d2                        	testl	%edx, %edx
   7be9c: 74 0a                        	je	0x7bea8 <.text+0x57678>
   7be9e: 48 83 f8 17                  	cmpq	$0x17, %rax

## plain descriptor open branch [0x7c270,0x7c370)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   7c270: 8b 08                        	movl	(%rax), %ecx
   7c272: 48 89 84 24 70 03 00 00      	movq	%rax, 0x370(%rsp)
   7c27a: 8d 51 01                     	leal	0x1(%rcx), %edx
   7c27d: 83 fa 01                     	cmpl	$0x1, %edx
   7c280: 76 07                        	jbe	0x7c289 <.text+0x57a59>
   7c282: f0                           	lock
   7c283: 83 00 01                     	addl	$0x1, (%rax)
   7c286: 0f 95 c2                     	setne	%dl
   7c289: 48 8d 84 24 80 03 00 00      	leaq	0x380(%rsp), %rax
   7c291: ba 11 00 00 00               	movl	$0x11, %edx
   7c296: 48 8d 35 bb 5f 19 00         	leaq	0x195fbb(%rip), %rsi    # 0x212258
   7c29d: 48 89 c7                     	movq	%rax, %rdi
   7c2a0: 49 89 c6                     	movq	%rax, %r14
   7c2a3: 48 89 04 24                  	movq	%rax, (%rsp)
   7c2a7: e8 24 61 fa ff               	callq	0x223d0 <_ZN7QString15fromUtf8_helperEPKci@plt>
   7c2ac: 48 8d 84 24 70 03 00 00      	leaq	0x370(%rsp), %rax
   7c2b4: 4c 89 f6                     	movq	%r14, %rsi
   7c2b7: 48 89 c7                     	movq	%rax, %rdi
   7c2ba: 48 89 44 24 20               	movq	%rax, 0x20(%rsp)
   7c2bf: e8 4c 7c fa ff               	callq	0x23f10 <_ZN7QString6appendERKS_@plt>
   7c2c4: 48 8b bc 24 80 03 00 00      	movq	0x380(%rsp), %rdi
   7c2cc: 8b 07                        	movl	(%rdi), %eax
   7c2ce: 85 c0                        	testl	%eax, %eax
   7c2d0: 0f 85 32 01 00 00            	jne	0x7c408 <.text+0x57bd8>
   7c2d6: ba 08 00 00 00               	movl	$0x8, %edx
   7c2db: be 02 00 00 00               	movl	$0x2, %esi
   7c2e0: e8 fb 7b fa ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   7c2e5: 48 8b 74 24 20               	movq	0x20(%rsp), %rsi
   7c2ea: 48 8b 3c 24                  	movq	(%rsp), %rdi
   7c2ee: e8 0d 6a fa ff               	callq	0x22d00 <_ZN5QFileC1ERK7QString@plt>
   7c2f3: 48 8b bc 24 70 03 00 00      	movq	0x370(%rsp), %rdi
   7c2fb: 8b 07                        	movl	(%rdi), %eax
   7c2fd: 85 c0                        	testl	%eax, %eax
   7c2ff: 0f 85 2b 05 00 00            	jne	0x7c830 <.text+0x58000>
   7c305: ba 08 00 00 00               	movl	$0x8, %edx
   7c30a: be 02 00 00 00               	movl	$0x2, %esi
   7c30f: e8 cc 7b fa ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   7c314: 48 8b 3c 24                  	movq	(%rsp), %rdi
   7c318: be 01 00 00 00               	movl	$0x1, %esi
   7c31d: e8 6e 63 fa ff               	callq	0x22690 <_ZN5QFile4openE6QFlagsIN9QIODevice12OpenModeFlagEE@plt>
   7c322: 84 c0                        	testb	%al, %al
   7c324: 0f 85 9e 03 00 00            	jne	0x7c6c8 <.text+0x57e98>
   7c32a: 48 8b 3d b7 9a 65 00         	movq	0x659ab7(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   7c331: 48 85 ff                     	testq	%rdi, %rdi
   7c334: 0f 84 13 21 00 00            	je	0x7e44d <.text+0x59c1d>
   7c33a: 48 8d 15 bf 61 19 00         	leaq	0x1961bf(%rip), %rdx    # 0x212500
   7c341: b9 be 00 00 00               	movl	$0xbe, %ecx
   7c346: 48 8d 35 03 5e 19 00         	leaq	0x195e03(%rip), %rsi    # 0x212150
   7c34d: e8 8e b3 0b 00               	callq	0x1376e0 <.text+0x112eb0>
   7c352: 48 8b 3c 24                  	movq	(%rsp), %rdi
   7c356: e8 15 69 fa ff               	callq	0x22c70 <_ZN5QFileD1Ev@plt>
   7c35b: 48 8b 8c 24 b8 0e 00 00      	movq	0xeb8(%rsp), %rcx
   7c363: 64 48 33 0c 25 28 00 00 00   	xorq	%fs:0x28, %rcx
   7c36c: 44 89 e0                     	movl	%r12d, %eax
   7c36f: 0f 85 98 29 00 00            	jne	0x7ed0d <.text+0x5a4dd>

## firmware archive verifier call [0x8001a,0x800ae)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   8001a: 48 8d 35 b8 30 19 00         	leaq	0x1930b8(%rip), %rsi    # 0x2130d9
   80021: 4c 89 e7                     	movq	%r12, %rdi
   80024: e8 67 5b fd ff               	callq	0x55b90 <.text+0x31360>
   80029: 48 8b 05 30 53 65 00         	movq	0x655330(%rip), %rax    # 0x6d5360 <_ZN9QListData11shared_nullE+0xb00>
   80030: 48 8d 9c 24 20 01 00 00      	leaq	0x120(%rsp), %rbx
   80038: 31 c9                        	xorl	%ecx, %ecx
   8003a: 4c 89 e6                     	movq	%r12, %rsi
   8003d: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   80043: 48 89 df                     	movq	%rbx, %rdi
   80046: 48 8d 50 30                  	leaq	0x30(%rax), %rdx
   8004a: e8 e1 2b fa ff               	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   8004f: 48 8b 84 24 10 01 00 00      	movq	0x110(%rsp), %rax
   80057: 48 89 df                     	movq	%rbx, %rdi
   8005a: 48 8b 94 24 20 01 00 00      	movq	0x120(%rsp), %rdx
   80062: 48 8d 9c 24 40 01 00 00      	leaq	0x140(%rsp), %rbx
   8006a: 48 89 84 24 20 01 00 00      	movq	%rax, 0x120(%rsp)
   80072: 48 89 94 24 10 01 00 00      	movq	%rdx, 0x110(%rsp)
   8007a: e8 e1 b8 fc ff               	callq	0x4b960 <.text+0x27130>
   8007f: 4c 89 e6                     	movq	%r12, %rsi
   80082: 48 89 df                     	movq	%rbx, %rdi
   80085: e8 66 5b fd ff               	callq	0x55bf0 <.text+0x313c0>
   8008a: e8 81 64 fe ff               	callq	0x66510 <.text+0x41ce0>
   8008f: 48 89 de                     	movq	%rbx, %rsi
   80092: 48 89 c7                     	movq	%rax, %rdi
   80095: e8 86 57 fc ff               	callq	0x45820 <.text+0x20ff0>
   8009a: 41 89 c7                     	movl	%eax, %r15d
   8009d: 48 89 df                     	movq	%rbx, %rdi
   800a0: e8 bb b8 fc ff               	callq	0x4b960 <.text+0x27130>
   800a5: 45 85 ff                     	testl	%r15d, %r15d
   800a8: 0f 85 52 01 00 00            	jne	0x80200 <.text+0x5b9d0>

## enumerated firmware file verifier call [0x80280,0x80310)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   80280: 4c 8d a4 24 90 00 00 00      	leaq	0x90(%rsp), %r12
   80288: 31 f6                        	xorl	%esi, %esi
   8028a: 4c 89 ef                     	movq	%r13, %rdi
   8028d: e8 fe 62 fe ff               	callq	0x66590 <.text+0x41d60>
   80292: 4c 89 e7                     	movq	%r12, %rdi
   80295: 48 89 c6                     	movq	%rax, %rsi
   80298: e8 53 20 fa ff               	callq	0x222f0 <_ZNK9QFileInfo6suffixEv@plt>
   8029d: 48 8d 35 40 32 19 00         	leaq	0x193240(%rip), %rsi    # 0x2134e4
   802a4: 4c 89 e7                     	movq	%r12, %rdi
   802a7: e8 84 f5 ff ff               	callq	0x7f830 <.text+0x5b000>
   802ac: 41 89 c7                     	movl	%eax, %r15d
   802af: 84 c0                        	testb	%al, %al
   802b1: 0f 84 39 01 00 00            	je	0x803f0 <.text+0x5bbc0>
   802b7: 4c 89 e7                     	movq	%r12, %rdi
   802ba: e8 a1 b6 fc ff               	callq	0x4b960 <.text+0x27130>
   802bf: 45 84 ff                     	testb	%r15b, %r15b
   802c2: 0f 84 a6 01 00 00            	je	0x8046e <.text+0x5bc3e>
   802c8: 48 8d 9c 24 b0 00 00 00      	leaq	0xb0(%rsp), %rbx
   802d0: 31 f6                        	xorl	%esi, %esi
   802d2: 4c 89 ef                     	movq	%r13, %rdi
   802d5: e8 b6 62 fe ff               	callq	0x66590 <.text+0x41d60>
   802da: 48 89 df                     	movq	%rbx, %rdi
   802dd: 48 89 c6                     	movq	%rax, %rsi
   802e0: e8 eb 2b fa ff               	callq	0x22ed0 <_ZNK9QFileInfo16absoluteFilePathEv@plt>
   802e5: e8 26 62 fe ff               	callq	0x66510 <.text+0x41ce0>
   802ea: 48 89 de                     	movq	%rbx, %rsi
   802ed: 48 89 c7                     	movq	%rax, %rdi
   802f0: e8 2b 55 fc ff               	callq	0x45820 <.text+0x20ff0>
   802f5: 48 89 df                     	movq	%rbx, %rdi
   802f8: 41 89 c4                     	movl	%eax, %r12d
   802fb: e8 60 b6 fc ff               	callq	0x4b960 <.text+0x27130>
   80300: 31 f6                        	xorl	%esi, %esi
   80302: 4c 89 ef                     	movq	%r13, %rdi
   80305: 45 85 e4                     	testl	%r12d, %r12d
   80308: 74 76                        	je	0x80380 <.text+0x5bb50>
   8030a: e8 81 62 fe ff               	callq	0x66590 <.text+0x41d60>
   8030f: 48 8d 9c 24 c0 00 00 00      	leaq	0xc0(%rsp), %rbx

## component-resource verifier call [0x9d111,0x9d235)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   9d111: 48 89 84 24 40 02 00 00      	movq	%rax, 0x240(%rsp)
   9d119: 4c 8d ac 24 30 01 00 00      	leaq	0x130(%rsp), %r13
   9d121: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   9d127: 4c 89 ef                     	movq	%r13, %rdi
   9d12a: e8 01 5b f8 ff               	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   9d12f: 48 8b 54 24 08               	movq	0x8(%rsp), %rdx
   9d134: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   9d13a: 31 c9                        	xorl	%ecx, %ecx
   9d13c: 4c 89 ee                     	movq	%r13, %rsi
   9d13f: 48 8d 84 24 40 01 00 00      	leaq	0x140(%rsp), %rax
   9d147: 48 89 c7                     	movq	%rax, %rdi
   9d14a: 48 89 44 24 08               	movq	%rax, 0x8(%rsp)
   9d14f: e8 dc 5a f8 ff               	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   9d154: 48 8b 84 24 e0 00 00 00      	movq	0xe0(%rsp), %rax
   9d15c: 48 8b 94 24 40 01 00 00      	movq	0x140(%rsp), %rdx
   9d164: 48 8b 7c 24 08               	movq	0x8(%rsp), %rdi
   9d169: 48 89 84 24 40 01 00 00      	movq	%rax, 0x140(%rsp)
   9d171: 48 89 94 24 e0 00 00 00      	movq	%rdx, 0xe0(%rsp)
   9d179: e8 e2 e7 fa ff               	callq	0x4b960 <.text+0x27130>
   9d17e: 4c 89 ef                     	movq	%r13, %rdi
   9d181: e8 da e7 fa ff               	callq	0x4b960 <.text+0x27130>
   9d186: 48 89 df                     	movq	%rbx, %rdi
   9d189: e8 d2 e7 fa ff               	callq	0x4b960 <.text+0x27130>
   9d18e: 4c 89 e7                     	movq	%r12, %rdi
   9d191: e8 ca e7 fa ff               	callq	0x4b960 <.text+0x27130>
   9d196: 48 89 ef                     	movq	%rbp, %rdi
   9d199: e8 42 8b fb ff               	callq	0x55ce0 <.text+0x314b0>
   9d19e: 48 8b 84 24 d0 00 00 00      	movq	0xd0(%rsp), %rax
   9d1a6: 8b 08                        	movl	(%rax), %ecx
   9d1a8: 48 89 84 24 40 02 00 00      	movq	%rax, 0x240(%rsp)
   9d1b0: 8d 51 01                     	leal	0x1(%rcx), %edx
   9d1b3: 83 fa 01                     	cmpl	$0x1, %edx
   9d1b6: 76 07                        	jbe	0x9d1bf <.text+0x7898f>
   9d1b8: f0                           	lock
   9d1b9: 83 00 01                     	addl	$0x1, (%rax)
   9d1bc: 0f 95 c2                     	setne	%dl
   9d1bf: 48 8b 3d c2 76 63 00         	movq	0x6376c2(%rip), %rdi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
   9d1c6: 48 85 ff                     	testq	%rdi, %rdi
   9d1c9: 0f 84 e9 09 00 00            	je	0x9dbb8 <.text+0x79388>
   9d1cf: 48 89 de                     	movq	%rbx, %rsi
   9d1d2: e8 49 86 fa ff               	callq	0x45820 <.text+0x20ff0>
   9d1d7: 48 8b bc 24 40 02 00 00      	movq	0x240(%rsp), %rdi
   9d1df: 41 89 c4                     	movl	%eax, %r12d
   9d1e2: 8b 07                        	movl	(%rdi), %eax
   9d1e4: 85 c0                        	testl	%eax, %eax
   9d1e6: 0f 85 ac 05 00 00            	jne	0x9d798 <.text+0x78f68>
   9d1ec: ba 08 00 00 00               	movl	$0x8, %edx
   9d1f1: be 02 00 00 00               	movl	$0x2, %esi
   9d1f6: e8 e5 6c f8 ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   9d1fb: 48 8b 3d e6 8b 63 00         	movq	0x638be6(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9d202: 48 85 ff                     	testq	%rdi, %rdi
   9d205: 0f 84 d5 09 00 00            	je	0x9dbe0 <.text+0x793b0>
   9d20b: 48 8d 15 ae 88 17 00         	leaq	0x1788ae(%rip), %rdx    # 0x215ac0
   9d212: 44 89 e1                     	movl	%r12d, %ecx
   9d215: 31 c0                        	xorl	%eax, %eax
   9d217: 48 8d 35 52 7d 17 00         	leaq	0x177d52(%rip), %rsi    # 0x214f70
   9d21e: e8 0d a2 09 00               	callq	0x137430 <.text+0x112c00>
   9d223: 48 8b b4 24 d0 00 00 00      	movq	0xd0(%rsp), %rsi
   9d22b: 45 85 e4                     	testl	%r12d, %r12d
   9d22e: 0f 85 3c 04 00 00            	jne	0x9d670 <.text+0x78e40>
   9d234: 8b 06                        	movl	(%rsi), %eax

## component verifier/decryption flow opening [0x100b30,0x100c20)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  100b30: 41 57                        	pushq	%r15
  100b32: 41 56                        	pushq	%r14
  100b34: 41 55                        	pushq	%r13
  100b36: 49 89 cd                     	movq	%rcx, %r13
  100b39: 41 54                        	pushq	%r12
  100b3b: 55                           	pushq	%rbp
  100b3c: 48 89 fd                     	movq	%rdi, %rbp
  100b3f: 53                           	pushq	%rbx
  100b40: 48 81 ec f8 00 00 00         	subq	$0xf8, %rsp
  100b47: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
  100b50: 48 89 84 24 e8 00 00 00      	movq	%rax, 0xe8(%rsp)
  100b58: 31 c0                        	xorl	%eax, %eax
  100b5a: 48 8b 02                     	movq	(%rdx), %rax
  100b5d: 8b 08                        	movl	(%rax), %ecx
  100b5f: 48 89 44 24 30               	movq	%rax, 0x30(%rsp)
  100b64: 8d 51 01                     	leal	0x1(%rcx), %edx
  100b67: 83 fa 01                     	cmpl	$0x1, %edx
  100b6a: 0f 86 e0 03 00 00            	jbe	0x100f50 <.text+0xdc720>
  100b70: f0                           	lock
  100b71: 83 00 01                     	addl	$0x1, (%rax)
  100b74: 0f 95 c2                     	setne	%dl
  100b77: 48 8b 44 24 30               	movq	0x30(%rsp), %rax
  100b7c: 8b 08                        	movl	(%rax), %ecx
  100b7e: 48 89 84 24 d0 00 00 00      	movq	%rax, 0xd0(%rsp)
  100b86: 8d 51 01                     	leal	0x1(%rcx), %edx
  100b89: 83 fa 01                     	cmpl	$0x1, %edx
  100b8c: 76 07                        	jbe	0x100b95 <.text+0xdc365>
  100b8e: f0                           	lock
  100b8f: 83 00 01                     	addl	$0x1, (%rax)
  100b92: 0f 95 c2                     	setne	%dl
  100b95: 48 8b 3d ec 3c 5d 00         	movq	0x5d3cec(%rip), %rdi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
  100b9c: 48 85 ff                     	testq	%rdi, %rdi
  100b9f: 0f 84 cb 03 00 00            	je	0x100f70 <.text+0xdc740>
  100ba5: 48 8d 9c 24 d0 00 00 00      	leaq	0xd0(%rsp), %rbx
  100bad: 48 89 de                     	movq	%rbx, %rsi
  100bb0: e8 6b 4c f4 ff               	callq	0x45820 <.text+0x20ff0>
  100bb5: 41 89 c4                     	movl	%eax, %r12d
  100bb8: 48 89 df                     	movq	%rbx, %rdi
  100bbb: e8 a0 ad f4 ff               	callq	0x4b960 <.text+0x27130>
  100bc0: 45 85 e4                     	testl	%r12d, %r12d
  100bc3: 0f 85 a7 02 00 00            	jne	0x100e70 <.text+0xdc640>
  100bc9: 48 8d 3d d4 91 10 00         	leaq	0x1091d4(%rip), %rdi    # 0x209da4
  100bd0: be 04 00 00 00               	movl	$0x4, %esi
  100bd5: e8 d6 21 f2 ff               	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
  100bda: 48 8b 35 a7 3c 5d 00         	movq	0x5d3ca7(%rip), %rsi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
  100be1: 48 89 84 24 d0 00 00 00      	movq	%rax, 0xd0(%rsp)
  100be9: 48 85 f6                     	testq	%rsi, %rsi
  100bec: 0f 84 0e 03 00 00            	je	0x100f00 <.text+0xdc6d0>
  100bf2: 4c 8d 74 24 40               	leaq	0x40(%rsp), %r14
  100bf7: 48 89 da                     	movq	%rbx, %rdx
  100bfa: 4c 89 f7                     	movq	%r14, %rdi
  100bfd: e8 0e 34 f4 ff               	callq	0x44010 <.text+0x1f7e0>
  100c02: 48 89 df                     	movq	%rbx, %rdi
  100c05: e8 56 ad f4 ff               	callq	0x4b960 <.text+0x27130>
  100c0a: 48 8b 44 24 40               	movq	0x40(%rsp), %rax
  100c0f: 8b 08                        	movl	(%rax), %ecx
  100c11: 48 89 84 24 d0 00 00 00      	movq	%rax, 0xd0(%rsp)
  100c19: 8d 51 01                     	leal	0x1(%rcx), %edx
  100c1c: 83 fa 01                     	cmpl	$0x1, %edx
  100c1f: 76 07                        	jbe	0x100c28 <.text+0xdc3f8>

## navigation component verifier/decryption flow opening [0x140030,0x140110)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  140030: 41 57                        	pushq	%r15
  140032: 48 89 d6                     	movq	%rdx, %rsi
  140035: 41 56                        	pushq	%r14
  140037: 41 55                        	pushq	%r13
  140039: 49 89 fd                     	movq	%rdi, %r13
  14003c: 41 54                        	pushq	%r12
  14003e: 55                           	pushq	%rbp
  14003f: 53                           	pushq	%rbx
  140040: 48 81 ec 18 01 00 00         	subq	$0x118, %rsp            # imm = 0x118
  140047: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
  140050: 48 89 84 24 08 01 00 00      	movq	%rax, 0x108(%rsp)
  140058: 31 c0                        	xorl	%eax, %eax
  14005a: 48 8d 6c 24 40               	leaq	0x40(%rsp), %rbp
  14005f: 48 89 4c 24 10               	movq	%rcx, 0x10(%rsp)
  140064: 48 8d 9c 24 f0 00 00 00      	leaq	0xf0(%rsp), %rbx
  14006c: 48 89 ef                     	movq	%rbp, %rdi
  14006f: e8 7c 5b f1 ff               	callq	0x55bf0 <.text+0x313c0>
  140074: 48 89 df                     	movq	%rbx, %rdi
  140077: 48 89 ee                     	movq	%rbp, %rsi
  14007a: e8 71 5b f1 ff               	callq	0x55bf0 <.text+0x313c0>
  14007f: 48 8b 3d 02 48 59 00         	movq	0x594802(%rip), %rdi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
  140086: 48 85 ff                     	testq	%rdi, %rdi
  140089: 0f 84 89 03 00 00            	je	0x140418 <.text+0x11bbe8>
  14008f: 48 89 de                     	movq	%rbx, %rsi
  140092: e8 89 57 f0 ff               	callq	0x45820 <.text+0x20ff0>
  140097: 41 89 c4                     	movl	%eax, %r12d
  14009a: 48 89 df                     	movq	%rbx, %rdi
  14009d: e8 be b8 f0 ff               	callq	0x4b960 <.text+0x27130>
  1400a2: 45 85 e4                     	testl	%r12d, %r12d
  1400a5: 0f 85 95 02 00 00            	jne	0x140340 <.text+0x11bb10>
  1400ab: 4c 8d a4 24 80 00 00 00      	leaq	0x80(%rsp), %r12
  1400b3: 48 8d 35 ea 9c 0c 00         	leaq	0xc9cea(%rip), %rsi     # 0x209da4
  1400ba: 4c 89 e7                     	movq	%r12, %rdi
  1400bd: e8 ce 5a f1 ff               	callq	0x55b90 <.text+0x31360>
  1400c2: 48 8b 35 bf 47 59 00         	movq	0x5947bf(%rip), %rsi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
  1400c9: 48 85 f6                     	testq	%rsi, %rsi
  1400cc: 0f 84 1e 03 00 00            	je	0x1403f0 <.text+0x11bbc0>
  1400d2: 48 8d 44 24 50               	leaq	0x50(%rsp), %rax
  1400d7: 4c 89 e2                     	movq	%r12, %rdx
  1400da: 48 89 c7                     	movq	%rax, %rdi
  1400dd: 48 89 44 24 08               	movq	%rax, 0x8(%rsp)
  1400e2: e8 29 3f f0 ff               	callq	0x44010 <.text+0x1f7e0>
  1400e7: 4c 89 e7                     	movq	%r12, %rdi
  1400ea: e8 71 b8 f0 ff               	callq	0x4b960 <.text+0x27130>
  1400ef: 48 8b 74 24 08               	movq	0x8(%rsp), %rsi
  1400f4: 48 89 df                     	movq	%rbx, %rdi
  1400f7: e8 f4 5a f1 ff               	callq	0x55bf0 <.text+0x313c0>
  1400fc: 48 8b 3d 85 47 59 00         	movq	0x594785(%rip), %rdi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
  140103: 44 8b 3d e2 4e 59 00         	movl	0x594ee2(%rip), %r15d   # 0x6d4fec <_ZN9QListData11shared_nullE+0x78c>
  14010a: 48 85 ff                     	testq	%rdi, %rdi
  14010d: 0f 84 b5 02 00 00            	je	0x1403c8 <.text+0x11bb98>

## worker relaunch execv wrapper complete FDE [0x6c9a0,0x6cab5)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   6c9a0: 55                           	pushq	%rbp
   6c9a1: 53                           	pushq	%rbx
   6c9a2: 48 83 ec 28                  	subq	$0x28, %rsp
   6c9a6: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
   6c9af: 48 89 44 24 18               	movq	%rax, 0x18(%rsp)
   6c9b4: 31 c0                        	xorl	%eax, %eax
   6c9b6: 89 74 24 04                  	movl	%esi, 0x4(%rsp)
   6c9ba: 48 89 54 24 08               	movq	%rdx, 0x8(%rsp)
   6c9bf: e8 3c 60 fb ff               	callq	0x22a00 <vfork@plt>
   6c9c4: 83 f8 ff                     	cmpl	$-0x1, %eax
   6c9c7: 74 57                        	je	0x6ca20 <.text+0x481f0>
   6c9c9: 89 c3                        	movl	%eax, %ebx
   6c9cb: 85 c0                        	testl	%eax, %eax
   6c9cd: 74 31                        	je	0x6ca00 <.text+0x481d0>
   6c9cf: 48 8d 35 aa 45 1a 00         	leaq	0x1a45aa(%rip), %rsi    # 0x210f80
   6c9d6: 31 ff                        	xorl	%edi, %edi
   6c9d8: 31 c0                        	xorl	%eax, %eax
   6c9da: e8 91 ae ff ff               	callq	0x67870 <.text+0x43040>
   6c9df: 48 63 c3                     	movslq	%ebx, %rax
   6c9e2: 48 8b 4c 24 18               	movq	0x18(%rsp), %rcx
   6c9e7: 64 48 33 0c 25 28 00 00 00   	xorq	%fs:0x28, %rcx
   6c9f0: 75 47                        	jne	0x6ca39 <.text+0x48209>
   6c9f2: 48 83 c4 28                  	addq	$0x28, %rsp
   6c9f6: 5b                           	popq	%rbx
   6c9f7: 5d                           	popq	%rbp
   6c9f8: c3                           	retq
   6c9f9: 0f 1f 80 00 00 00 00         	nopl	(%rax)
   6ca00: 8b 44 24 04                  	movl	0x4(%rsp), %eax
   6ca04: 8d 78 03                     	leal	0x3(%rax), %edi
   6ca07: 48 63 ff                     	movslq	%edi, %rdi
   6ca0a: 48 c1 e7 03                  	shlq	$0x3, %rdi
   6ca0e: e8 fd fb ff ff               	callq	0x6c610 <.text+0x47de0>
   6ca13: 48 89 c3                     	movq	%rax, %rbx
   6ca16: 48 85 c0                     	testq	%rax, %rax
   6ca19: 75 23                        	jne	0x6ca3e <.text+0x4820e>
   6ca1b: 31 c0                        	xorl	%eax, %eax
   6ca1d: eb c3                        	jmp	0x6c9e2 <.text+0x481b2>
   6ca1f: 90                           	nop
   6ca20: 48 8d 35 0e 45 1a 00         	leaq	0x1a450e(%rip), %rsi    # 0x210f35
   6ca27: 31 ff                        	xorl	%edi, %edi
   6ca29: 31 c0                        	xorl	%eax, %eax
   6ca2b: e8 40 ae ff ff               	callq	0x67870 <.text+0x43040>
   6ca30: 48 c7 c0 ff ff ff ff         	movq	$-0x1, %rax
   6ca37: eb a9                        	jmp	0x6c9e2 <.text+0x481b2>
   6ca39: e8 72 5c fb ff               	callq	0x226b0 <__stack_chk_fail@plt>
   6ca3e: 48 8d 3d fe 44 1a 00         	leaq	0x1a44fe(%rip), %rdi    # 0x210f43
   6ca45: 31 ed                        	xorl	%ebp, %ebp
   6ca47: e8 64 54 fb ff               	callq	0x21eb0 <strdup@plt>
   6ca4c: 48 8d 3d 0d 45 1a 00         	leaq	0x1a450d(%rip), %rdi    # 0x210f60
   6ca53: 48 89 03                     	movq	%rax, (%rbx)
   6ca56: e8 55 54 fb ff               	callq	0x21eb0 <strdup@plt>
   6ca5b: 48 8d 3d 06 11 1a 00         	leaq	0x1a1106(%rip), %rdi    # 0x20db68
   6ca62: 48 89 43 08                  	movq	%rax, 0x8(%rbx)
   6ca66: e8 45 54 fb ff               	callq	0x21eb0 <strdup@plt>
   6ca6b: 8b 54 24 04                  	movl	0x4(%rsp), %edx
   6ca6f: 48 8d 35 fd 44 1a 00         	leaq	0x1a44fd(%rip), %rsi    # 0x210f73
   6ca76: 31 ff                        	xorl	%edi, %edi
   6ca78: 48 89 43 10                  	movq	%rax, 0x10(%rbx)
   6ca7c: 31 c0                        	xorl	%eax, %eax
   6ca7e: e8 ed ad ff ff               	callq	0x67870 <.text+0x43040>
   6ca83: 39 6c 24 04                  	cmpl	%ebp, 0x4(%rsp)
   6ca87: 7e 19                        	jle	0x6caa2 <.text+0x48272>
   6ca89: 48 8b 44 24 08               	movq	0x8(%rsp), %rax
   6ca8e: 48 8b 3c e8                  	movq	(%rax,%rbp,8), %rdi
   6ca92: e8 19 54 fb ff               	callq	0x21eb0 <strdup@plt>
   6ca97: 48 89 44 eb 18               	movq	%rax, 0x18(%rbx,%rbp,8)
   6ca9c: 48 83 c5 01                  	addq	$0x1, %rbp
   6caa0: eb e1                        	jmp	0x6ca83 <.text+0x48253>
   6caa2: 48 8b 3b                     	movq	(%rbx), %rdi
   6caa5: 48 89 de                     	movq	%rbx, %rsi
   6caa8: e8 43 71 fb ff               	callq	0x23bf0 <execv@plt>
   6caad: 83 cf ff                     	orl	$-0x1, %edi
   6cab0: e8 bb 74 fb ff               	callq	0x23f70 <_exit@plt>

## file MD5 helper complete FDE [0x140f50,0x1413e4)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  140f50: 55                           	pushq	%rbp
  140f51: 48 89 d6                     	movq	%rdx, %rsi
  140f54: 48 89 e5                     	movq	%rsp, %rbp
  140f57: 41 57                        	pushq	%r15
  140f59: 41 56                        	pushq	%r14
  140f5b: 41 55                        	pushq	%r13
  140f5d: 49 89 fd                     	movq	%rdi, %r13
  140f60: 41 54                        	pushq	%r12
  140f62: 49 89 d4                     	movq	%rdx, %r12
  140f65: 53                           	pushq	%rbx
  140f66: 48 81 ec c8 00 00 00         	subq	$0xc8, %rsp
  140f6d: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
  140f76: 48 89 45 c8                  	movq	%rax, -0x38(%rbp)
  140f7a: 31 c0                        	xorl	%eax, %eax
  140f7c: 48 8d 05 1d 37 59 00         	leaq	0x59371d(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
  140f83: 48 89 07                     	movq	%rax, (%rdi)
  140f86: 48 8d 45 b0                  	leaq	-0x50(%rbp), %rax
  140f8a: 48 89 c7                     	movq	%rax, %rdi
  140f8d: 48 89 85 28 ff ff ff         	movq	%rax, -0xd8(%rbp)
  140f94: e8 67 1d ee ff               	callq	0x22d00 <_ZN5QFileC1ERK7QString@plt>
  140f99: 4c 8d b5 30 ff ff ff         	leaq	-0xd0(%rbp), %r14
  140fa0: be 01 00 00 00               	movl	$0x1, %esi
  140fa5: 4c 89 f7                     	movq	%r14, %rdi
  140fa8: e8 63 2d ee ff               	callq	0x23d10 <_ZN18QCryptographicHashC1ENS_9AlgorithmE@plt>
  140fad: 48 8d 5d a0                  	leaq	-0x60(%rbp), %rbx
  140fb1: 4c 89 e6                     	movq	%r12, %rsi
  140fb4: 4c 8d bd 40 ff ff ff         	leaq	-0xc0(%rbp), %r15
  140fbb: 48 89 df                     	movq	%rbx, %rdi
  140fbe: e8 2d 4c f1 ff               	callq	0x55bf0 <.text+0x313c0>
  140fc3: 48 89 de                     	movq	%rbx, %rsi
  140fc6: 4c 89 ff                     	movq	%r15, %rdi
  140fc9: e8 52 4b f1 ff               	callq	0x55b20 <.text+0x312f0>
  140fce: 48 8b bd 40 ff ff ff         	movq	-0xc0(%rbp), %rdi
  140fd5: e8 e6 4a f1 ff               	callq	0x55ac0 <.text+0x31290>
  140fda: 48 89 85 20 ff ff ff         	movq	%rax, -0xe0(%rbp)
  140fe1: e8 7a 4c f1 ff               	callq	0x55c60 <.text+0x31430>
  140fe6: 4c 8b 8d 20 ff ff ff         	movq	-0xe0(%rbp), %r9
  140fed: 48 89 c7                     	movq	%rax, %rdi
  140ff0: 31 c0                        	xorl	%eax, %eax
  140ff2: b9 65 03 00 00               	movl	$0x365, %ecx            # imm = 0x365
  140ff7: 4c 8d 05 b9 c2 0e 00         	leaq	0xec2b9(%rip), %r8      # 0x22d2b7
  140ffe: 48 8d 15 90 bc 0e 00         	leaq	0xebc90(%rip), %rdx     # 0x22cc95
  141005: 48 8d 35 84 b8 0e 00         	leaq	0xeb884(%rip), %rsi     # 0x22c890
  14100c: e8 1f 64 ff ff               	callq	0x137430 <.text+0x112c00>
  141011: 4c 89 ff                     	movq	%r15, %rdi
  141014: e8 c7 a8 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  141019: 48 89 df                     	movq	%rbx, %rdi
  14101c: e8 3f a9 f0 ff               	callq	0x4b960 <.text+0x27130>
  141021: 4c 8b bd 28 ff ff ff         	movq	-0xd8(%rbp), %r15
  141028: be 01 00 00 00               	movl	$0x1, %esi
  14102d: 4c 89 ff                     	movq	%r15, %rdi
  141030: e8 5b 16 ee ff               	callq	0x22690 <_ZN5QFile4openE6QFlagsIN9QIODevice12OpenModeFlagEE@plt>
  141035: 84 c0                        	testb	%al, %al
  141037: 0f 84 93 00 00 00            	je	0x1410d0 <.text+0x11c8a0>
  14103d: 4c 89 fe                     	movq	%r15, %rsi
  141040: 4c 89 f7                     	movq	%r14, %rdi
  141043: 4c 89 bd 28 ff ff ff         	movq	%r15, -0xd8(%rbp)
  14104a: e8 f1 17 ee ff               	callq	0x22840 <_ZN18QCryptographicHash7addDataEP9QIODevice@plt>
  14104f: 84 c0                        	testb	%al, %al
  141051: 0f 85 19 01 00 00            	jne	0x141170 <.text+0x11c940>
  141057: 4c 89 e6                     	movq	%r12, %rsi
  14105a: 48 89 df                     	movq	%rbx, %rdi
  14105d: e8 8e 4b f1 ff               	callq	0x55bf0 <.text+0x313c0>
  141062: 4c 8d a5 50 ff ff ff         	leaq	-0xb0(%rbp), %r12
  141069: 48 89 de                     	movq	%rbx, %rsi
  14106c: 4c 89 e7                     	movq	%r12, %rdi
  14106f: e8 ac 4a f1 ff               	callq	0x55b20 <.text+0x312f0>
  141074: 48 8b bd 50 ff ff ff         	movq	-0xb0(%rbp), %rdi
  14107b: e8 40 4a f1 ff               	callq	0x55ac0 <.text+0x31290>
  141080: 49 89 c7                     	movq	%rax, %r15
  141083: e8 d8 4b f1 ff               	callq	0x55c60 <.text+0x31430>
  141088: 48 89 c7                     	movq	%rax, %rdi
  14108b: 4d 89 f9                     	movq	%r15, %r9
  14108e: b9 6a 03 00 00               	movl	$0x36a, %ecx            # imm = 0x36A
  141093: 4c 8d 05 1d c2 0e 00         	leaq	0xec21d(%rip), %r8      # 0x22d2b7
  14109a: 31 c0                        	xorl	%eax, %eax
  14109c: 48 8d 15 f2 bb 0e 00         	leaq	0xebbf2(%rip), %rdx     # 0x22cc95
  1410a3: 48 8d 35 0e b8 0e 00         	leaq	0xeb80e(%rip), %rsi     # 0x22c8b8
  1410aa: e8 81 63 ff ff               	callq	0x137430 <.text+0x112c00>
  1410af: 4c 89 e7                     	movq	%r12, %rdi
  1410b2: e8 29 a8 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  1410b7: 48 89 df                     	movq	%rbx, %rdi
  1410ba: e8 a1 a8 f0 ff               	callq	0x4b960 <.text+0x27130>
  1410bf: 48 8b bd 28 ff ff ff         	movq	-0xd8(%rbp), %rdi
  1410c6: e8 55 0f ee ff               	callq	0x22020 <_ZN11QFileDevice5closeEv@plt>
  1410cb: eb 65                        	jmp	0x141132 <.text+0x11c902>
  1410cd: 0f 1f 00                     	nopl	(%rax)
  1410d0: 4c 8d 7d 90                  	leaq	-0x70(%rbp), %r15
  1410d4: 4c 89 e6                     	movq	%r12, %rsi
  1410d7: 4c 89 ff                     	movq	%r15, %rdi
  1410da: e8 11 4b f1 ff               	callq	0x55bf0 <.text+0x313c0>
  1410df: 4c 89 fe                     	movq	%r15, %rsi
  1410e2: 48 89 df                     	movq	%rbx, %rdi
  1410e5: e8 36 4a f1 ff               	callq	0x55b20 <.text+0x312f0>
  1410ea: 48 8b 7d a0                  	movq	-0x60(%rbp), %rdi
  1410ee: e8 cd 49 f1 ff               	callq	0x55ac0 <.text+0x31290>
  1410f3: 49 89 c4                     	movq	%rax, %r12
  1410f6: e8 65 4b f1 ff               	callq	0x55c60 <.text+0x31430>
  1410fb: 48 89 c7                     	movq	%rax, %rdi
  1410fe: 4d 89 e1                     	movq	%r12, %r9
  141101: b9 75 03 00 00               	movl	$0x375, %ecx            # imm = 0x375
  141106: 4c 8d 05 aa c1 0e 00         	leaq	0xec1aa(%rip), %r8      # 0x22d2b7
  14110d: 31 c0                        	xorl	%eax, %eax
  14110f: 48 8d 15 7f bb 0e 00         	leaq	0xebb7f(%rip), %rdx     # 0x22cc95
  141116: 48 8d 35 03 b8 0e 00         	leaq	0xeb803(%rip), %rsi     # 0x22c920
  14111d: e8 0e 63 ff ff               	callq	0x137430 <.text+0x112c00>
  141122: 48 89 df                     	movq	%rbx, %rdi
  141125: e8 b6 a7 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  14112a: 4c 89 ff                     	movq	%r15, %rdi
  14112d: e8 2e a8 f0 ff               	callq	0x4b960 <.text+0x27130>
  141132: 4c 89 f7                     	movq	%r14, %rdi
  141135: e8 d6 22 ee ff               	callq	0x23410 <_ZN18QCryptographicHashD1Ev@plt>
  14113a: 48 8b bd 28 ff ff ff         	movq	-0xd8(%rbp), %rdi
  141141: e8 2a 1b ee ff               	callq	0x22c70 <_ZN5QFileD1Ev@plt>
  141146: 4c 89 e8                     	movq	%r13, %rax
  141149: 48 8b 4d c8                  	movq	-0x38(%rbp), %rcx
  14114d: 64 48 33 0c 25 28 00 00 00   	xorq	%fs:0x28, %rcx
  141156: 0f 85 a3 01 00 00            	jne	0x1412ff <.text+0x11cacf>
  14115c: 48 8d 65 d8                  	leaq	-0x28(%rbp), %rsp
  141160: 5b                           	popq	%rbx
  141161: 41 5c                        	popq	%r12
  141163: 41 5d                        	popq	%r13
  141165: 41 5e                        	popq	%r14
  141167: 41 5f                        	popq	%r15
  141169: 5d                           	popq	%rbp
  14116a: c3                           	retq
  14116b: 0f 1f 44 00 00               	nopl	(%rax,%rax)
  141170: 4c 8d bd 60 ff ff ff         	leaq	-0xa0(%rbp), %r15
  141177: 4c 89 f6                     	movq	%r14, %rsi
  14117a: 4c 89 ff                     	movq	%r15, %rdi
  14117d: e8 8e 15 ee ff               	callq	0x22710 <_ZNK18QCryptographicHash6resultEv@plt>
  141182: 48 8d 85 70 ff ff ff         	leaq	-0x90(%rbp), %rax
  141189: 4c 89 fe                     	movq	%r15, %rsi
  14118c: 48 89 c7                     	movq	%rax, %rdi
  14118f: 48 89 85 20 ff ff ff         	movq	%rax, -0xe0(%rbp)
  141196: e8 55 22 ee ff               	callq	0x233f0 <_ZNK10QByteArray5toHexEv@plt>
  14119b: 48 8b bd 70 ff ff ff         	movq	-0x90(%rbp), %rdi
  1411a2: 8b 57 04                     	movl	0x4(%rdi), %edx
  1411a5: 89 95 18 ff ff ff            	movl	%edx, -0xe8(%rbp)
  1411ab: e8 10 49 f1 ff               	callq	0x55ac0 <.text+0x31290>
  1411b0: 31 f6                        	xorl	%esi, %esi
  1411b2: 48 85 c0                     	testq	%rax, %rax
  1411b5: 74 11                        	je	0x1411c8 <.text+0x11c998>
  1411b7: 8b 95 18 ff ff ff            	movl	-0xe8(%rbp), %edx
  1411bd: 85 d2                        	testl	%edx, %edx
  1411bf: 0f 85 03 01 00 00            	jne	0x1412c8 <.text+0x11ca98>
  1411c5: 0f 1f 00                     	nopl	(%rax)
  1411c8: 48 89 c7                     	movq	%rax, %rdi
  1411cb: e8 e0 1b ee ff               	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
  1411d0: 49 8b 55 00                  	movq	(%r13), %rdx
  1411d4: 48 89 df                     	movq	%rbx, %rdi
  1411d7: 49 89 45 00                  	movq	%rax, (%r13)
  1411db: 48 89 55 a0                  	movq	%rdx, -0x60(%rbp)
  1411df: e8 7c a7 f0 ff               	callq	0x4b960 <.text+0x27130>
  1411e4: 48 8b bd 20 ff ff ff         	movq	-0xe0(%rbp), %rdi
  1411eb: e8 f0 a6 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  1411f0: 4c 89 ff                     	movq	%r15, %rdi
  1411f3: e8 e8 a6 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  1411f8: 48 8b bd 28 ff ff ff         	movq	-0xd8(%rbp), %rdi
  1411ff: e8 1c 0e ee ff               	callq	0x22020 <_ZN11QFileDevice5closeEv@plt>
  141204: 4c 8d 7d 90                  	leaq	-0x70(%rbp), %r15
  141208: 4c 89 ee                     	movq	%r13, %rsi
  14120b: 48 89 df                     	movq	%rbx, %rdi
  14120e: e8 dd 49 f1 ff               	callq	0x55bf0 <.text+0x313c0>
  141213: 48 89 de                     	movq	%rbx, %rsi
  141216: 4c 89 ff                     	movq	%r15, %rdi
  141219: e8 02 49 f1 ff               	callq	0x55b20 <.text+0x312f0>
  14121e: 48 8b 7d 90                  	movq	-0x70(%rbp), %rdi
  141222: e8 99 48 f1 ff               	callq	0x55ac0 <.text+0x31290>
  141227: 48 8b bd 20 ff ff ff         	movq	-0xe0(%rbp), %rdi
  14122e: 4c 89 e6                     	movq	%r12, %rsi
  141231: 48 89 85 18 ff ff ff         	movq	%rax, -0xe8(%rbp)
  141238: 4c 8d 65 80                  	leaq	-0x80(%rbp), %r12
  14123c: e8 af 49 f1 ff               	callq	0x55bf0 <.text+0x313c0>
  141241: 48 8b b5 20 ff ff ff         	movq	-0xe0(%rbp), %rsi
  141248: 4c 89 e7                     	movq	%r12, %rdi
  14124b: e8 d0 48 f1 ff               	callq	0x55b20 <.text+0x312f0>
  141250: 48 8b 7d 80                  	movq	-0x80(%rbp), %rdi
  141254: e8 67 48 f1 ff               	callq	0x55ac0 <.text+0x31290>
  141259: 48 89 85 10 ff ff ff         	movq	%rax, -0xf0(%rbp)
  141260: e8 fb 49 f1 ff               	callq	0x55c60 <.text+0x31430>
  141265: 4c 8b 8d 10 ff ff ff         	movq	-0xf0(%rbp), %r9
  14126c: 48 83 ec 08                  	subq	$0x8, %rsp
  141270: 48 89 c7                     	movq	%rax, %rdi
  141273: b9 72 03 00 00               	movl	$0x372, %ecx            # imm = 0x372
  141278: ff b5 18 ff ff ff            	pushq	-0xe8(%rbp)
  14127e: 4c 8d 05 32 c0 0e 00         	leaq	0xec032(%rip), %r8      # 0x22d2b7
  141285: 31 c0                        	xorl	%eax, %eax
  141287: 48 8d 15 07 ba 0e 00         	leaq	0xeba07(%rip), %rdx     # 0x22cc95
  14128e: 48 8d 35 5b b6 0e 00         	leaq	0xeb65b(%rip), %rsi     # 0x22c8f0
  141295: e8 96 61 ff ff               	callq	0x137430 <.text+0x112c00>
  14129a: 58                           	popq	%rax
  14129b: 4c 89 e7                     	movq	%r12, %rdi
  14129e: 5a                           	popq	%rdx
  14129f: e8 3c a6 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  1412a4: 48 8b bd 20 ff ff ff         	movq	-0xe0(%rbp), %rdi
  1412ab: e8 b0 a6 f0 ff               	callq	0x4b960 <.text+0x27130>
  1412b0: 4c 89 ff                     	movq	%r15, %rdi
  1412b3: e8 28 a6 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  1412b8: 48 89 df                     	movq	%rbx, %rdi
  1412bb: e8 a0 a6 f0 ff               	callq	0x4b960 <.text+0x27130>
  1412c0: e9 6d fe ff ff               	jmp	0x141132 <.text+0x11c902>
  1412c5: 0f 1f 00                     	nopl	(%rax)
  1412c8: 80 38 00                     	cmpb	$0x0, (%rax)
  1412cb: 0f 84 f7 fe ff ff            	je	0x1411c8 <.text+0x11c998>
  1412d1: 48 8d 48 01                  	leaq	0x1(%rax), %rcx
  1412d5: 31 f6                        	xorl	%esi, %esi
  1412d7: 66 0f 1f 84 00 00 00 00 00   	nopw	(%rax,%rax)
  1412e0: 83 c6 01                     	addl	$0x1, %esi
  1412e3: 39 f2                        	cmpl	%esi, %edx
  1412e5: 75 09                        	jne	0x1412f0 <.text+0x11cac0>
  1412e7: 89 d6                        	movl	%edx, %esi
  1412e9: e9 da fe ff ff               	jmp	0x1411c8 <.text+0x11c998>
  1412ee: 66 90                        	nop
  1412f0: 48 83 c1 01                  	addq	$0x1, %rcx
  1412f4: 80 79 ff 00                  	cmpb	$0x0, -0x1(%rcx)
  1412f8: 75 e6                        	jne	0x1412e0 <.text+0x11cab0>
  1412fa: e9 c9 fe ff ff               	jmp	0x1411c8 <.text+0x11c998>
  1412ff: e8 ac 13 ee ff               	callq	0x226b0 <__stack_chk_fail@plt>
  141304: 49 89 c4                     	movq	%rax, %r12
  141307: 48 89 df                     	movq	%rbx, %rdi
  14130a: 4c 89 e3                     	movq	%r12, %rbx
  14130d: e8 4e a6 f0 ff               	callq	0x4b960 <.text+0x27130>
  141312: 4c 89 f7                     	movq	%r14, %rdi
  141315: e8 f6 20 ee ff               	callq	0x23410 <_ZN18QCryptographicHashD1Ev@plt>
  14131a: 48 8b bd 28 ff ff ff         	movq	-0xd8(%rbp), %rdi
  141321: e8 4a 19 ee ff               	callq	0x22c70 <_ZN5QFileD1Ev@plt>
  141326: 4c 89 ef                     	movq	%r13, %rdi
  141329: e8 32 a6 f0 ff               	callq	0x4b960 <.text+0x27130>
  14132e: 48 89 df                     	movq	%rbx, %rdi
  141331: e8 5a 1e ee ff               	callq	0x23190 <_Unwind_Resume@plt>
  141336: 49 89 c7                     	movq	%rax, %r15
  141339: 4c 89 e7                     	movq	%r12, %rdi
  14133c: e8 9f a5 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  141341: 4d 89 fc                     	movq	%r15, %r12
  141344: eb c1                        	jmp	0x141307 <.text+0x11cad7>
  141346: 48 8b bd 20 ff ff ff         	movq	-0xe0(%rbp), %rdi
  14134d: 48 89 c3                     	movq	%rax, %rbx
  141350: e8 8b a5 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  141355: 4c 89 ff                     	movq	%r15, %rdi
  141358: e8 83 a5 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  14135d: eb b3                        	jmp	0x141312 <.text+0x11cae2>
  14135f: eb a3                        	jmp	0x141304 <.text+0x11cad4>
  141361: 49 89 c4                     	movq	%rax, %r12
  141364: 48 8b bd 20 ff ff ff         	movq	-0xe0(%rbp), %rdi
  14136b: e8 f0 a5 f0 ff               	callq	0x4b960 <.text+0x27130>
  141370: 4c 89 ff                     	movq	%r15, %rdi
  141373: e8 68 a5 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  141378: eb 8d                        	jmp	0x141307 <.text+0x11cad7>
  14137a: 4c 89 e7                     	movq	%r12, %rdi
  14137d: 48 89 85 18 ff ff ff         	movq	%rax, -0xe8(%rbp)
  141384: e8 57 a5 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  141389: 48 8b 85 18 ff ff ff         	movq	-0xe8(%rbp), %rax
  141390: 49 89 c4                     	movq	%rax, %r12
  141393: eb cf                        	jmp	0x141364 <.text+0x11cb34>
  141395: 48 89 c3                     	movq	%rax, %rbx
  141398: eb 8c                        	jmp	0x141326 <.text+0x11caf6>
  14139a: 48 89 c3                     	movq	%rax, %rbx
  14139d: eb b6                        	jmp	0x141355 <.text+0x11cb25>
  14139f: 49 89 c4                     	movq	%rax, %r12
  1413a2: 48 89 df                     	movq	%rbx, %rdi
  1413a5: e8 36 a5 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  1413aa: 4c 89 e3                     	movq	%r12, %rbx
  1413ad: 4c 89 ff                     	movq	%r15, %rdi
  1413b0: e8 ab a5 f0 ff               	callq	0x4b960 <.text+0x27130>
  1413b5: e9 58 ff ff ff               	jmp	0x141312 <.text+0x11cae2>
  1413ba: 48 89 c3                     	movq	%rax, %rbx
  1413bd: eb ee                        	jmp	0x1413ad <.text+0x11cb7d>
  1413bf: 48 89 c3                     	movq	%rax, %rbx
  1413c2: e9 4b ff ff ff               	jmp	0x141312 <.text+0x11cae2>
  1413c7: 4c 89 ff                     	movq	%r15, %rdi
  1413ca: 49 89 c4                     	movq	%rax, %r12
  1413cd: e8 0e a5 f0 ff               	callq	0x4b8e0 <.text+0x270b0>
  1413d2: e9 30 ff ff ff               	jmp	0x141307 <.text+0x11cad7>
  1413d7: e9 28 ff ff ff               	jmp	0x141304 <.text+0x11cad4>
  1413dc: 48 89 c3                     	movq	%rax, %rbx
  1413df: e9 36 ff ff ff               	jmp	0x14131a <.text+0x11caea>

## first MD5 caller receives QFileInfo absolute path [0x1432b8,0x143330)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  1432b8: 4c 8b ad f8 fd ff ff         	movq	-0x208(%rbp), %r13
  1432bf: 48 8d 85 c0 fe ff ff         	leaq	-0x140(%rbp), %rax
  1432c6: 4c 89 fe                     	movq	%r15, %rsi
  1432c9: 48 8d 9d d0 fe ff ff         	leaq	-0x130(%rbp), %rbx
  1432d0: 48 89 85 58 fe ff ff         	movq	%rax, -0x1a8(%rbp)
  1432d7: 4c 89 ef                     	movq	%r13, %rdi
  1432da: e8 f1 fb ed ff               	callq	0x22ed0 <_ZNK9QFileInfo16absoluteFilePathEv@plt>
  1432df: 4c 89 eb                     	movq	%r13, %rbx
  1432e2: 4c 89 ea                     	movq	%r13, %rdx
  1432e5: 4c 8b ad 38 fe ff ff         	movq	-0x1c8(%rbp), %r13
  1432ec: 48 8b b5 28 fe ff ff         	movq	-0x1d8(%rbp), %rsi
  1432f3: 4c 89 ef                     	movq	%r13, %rdi
  1432f6: e8 55 dc ff ff               	callq	0x140f50 <.text+0x11c720>
  1432fb: 48 8b 85 c0 fe ff ff         	movq	-0x140(%rbp), %rax
  143302: 4c 89 ef                     	movq	%r13, %rdi
  143305: 48 8b 95 60 ff ff ff         	movq	-0xa0(%rbp), %rdx
  14330c: 48 89 85 60 ff ff ff         	movq	%rax, -0xa0(%rbp)
  143313: 48 89 95 c0 fe ff ff         	movq	%rdx, -0x140(%rbp)
  14331a: e8 41 86 f0 ff               	callq	0x4b960 <.text+0x27130>
  14331f: 48 89 df                     	movq	%rbx, %rdi
  143322: e8 39 86 f0 ff               	callq	0x4b960 <.text+0x27130>
  143327: 48 8b 85 b0 fe ff ff         	movq	-0x150(%rbp), %rax
  14332e: 44 8b 50 14                  	movl	0x14(%rax), %r10d

## second MD5 caller receives QFileInfo absolute path [0x1516c6,0x151740)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  1516c6: 48 8b b5 00 fc ff ff         	movq	-0x400(%rbp), %rsi
  1516cd: 48 8b bd a0 fb ff ff         	movq	-0x460(%rbp), %rdi
  1516d4: 48 8d 85 80 fc ff ff         	leaq	-0x380(%rbp), %rax
  1516db: 48 8d 9d 90 fc ff ff         	leaq	-0x370(%rbp), %rbx
  1516e2: 48 89 85 18 fc ff ff         	movq	%rax, -0x3e8(%rbp)
  1516e9: e8 e2 17 ed ff               	callq	0x22ed0 <_ZNK9QFileInfo16absoluteFilePathEv@plt>
  1516ee: 48 8b 35 0b 48 58 00         	movq	0x58480b(%rip), %rsi    # 0x6d5f00 <_ZN9QListData11shared_nullE+0x16a0>
  1516f5: 48 85 f6                     	testq	%rsi, %rsi
  1516f8: 0f 84 e2 07 00 00            	je	0x151ee0 <.text+0x12d6b0>
  1516fe: 48 8b 95 a0 fb ff ff         	movq	-0x460(%rbp), %rdx
  151705: 48 8b bd 60 fb ff ff         	movq	-0x4a0(%rbp), %rdi
  15170c: e8 3f f8 fe ff               	callq	0x140f50 <.text+0x11c720>
  151711: 48 8b 85 80 fc ff ff         	movq	-0x380(%rbp), %rax
  151718: 48 8b 95 f0 fe ff ff         	movq	-0x110(%rbp), %rdx
  15171f: 48 8b bd 60 fb ff ff         	movq	-0x4a0(%rbp), %rdi
  151726: 48 89 85 f0 fe ff ff         	movq	%rax, -0x110(%rbp)
  15172d: 48 89 95 80 fc ff ff         	movq	%rdx, -0x380(%rbp)
  151734: e8 27 a2 ef ff               	callq	0x4b960 <.text+0x27130>
  151739: 48 8b bd a0 fb ff ff         	movq	-0x460(%rbp), %rdi

## Relevant string offsets (file offsets equal VAs in this load segment)
209d25 /HU/images/AppUpgrade/
209d43 /app/share/AppUpgrade/
209d5a teruten5_pub.key
20b4d8 /app/share/AppUpgrade/DecryptToPIPE
20db68 /navi/tmp/sysroot/hkmc_avn5_tot_d.up
210f43 /navi/tmp/sysroot/AppUpgrade
210f60 handle_run_process
212258 /.lge.upgrade.xml
2130d9 %1/HU/firmware/update.tar.gz
22085e DecryptToPIPE
22d2b7 getMD5
22e773 NaviChecksumThread.cpp

## Direct callers of parameterized verifier path 0x100b30

### enumerated absolute path caller [0x1027e5,0x102830)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  1027e5: 48 8b 5c 24 40               	movq	0x40(%rsp), %rbx
  1027ea: 4c 01 f8                     	addq	%r15, %rax
  1027ed: 48 8d 74 c1 10               	leaq	0x10(%rcx,%rax,8), %rsi
  1027f2: 48 89 df                     	movq	%rbx, %rdi
  1027f5: e8 d6 06 f2 ff               	callq	0x22ed0 <_ZNK9QFileInfo16absoluteFilePathEv@plt>
  1027fa: 48 8b 74 24 18               	movq	0x18(%rsp), %rsi
  1027ff: 48 8d 84 24 40 09 00 00      	leaq	0x940(%rsp), %rax
  102807: 48 89 da                     	movq	%rbx, %rdx
  10280a: 4c 8d b4 24 70 09 00 00      	leaq	0x970(%rsp), %r14
  102812: 48 89 c7                     	movq	%rax, %rdi
  102815: 48 89 04 24                  	movq	%rax, (%rsp)
  102819: 4c 89 f1                     	movq	%r14, %rcx
  10281c: e8 0f e3 ff ff               	callq	0x100b30 <.text+0xdc300>
  102821: 48 8b bc 24 40 08 00 00      	movq	0x840(%rsp), %rdi
  102829: 8b 07                        	movl	(%rdi), %eax
  10282b: 85 c0                        	testl	%eax, %eax
  10282d: 0f 85 d5 0e 00 00            	jne	0x103708 <.text+0xdeed8>

### copied QString caller with earlier provenance outside excerpt [0x102da0,0x102df0)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  102da0: 48 8d ac 24 e0 09 00 00      	leaq	0x9e0(%rsp), %rbp
  102da8: 4c 89 ee                     	movq	%r13, %rsi
  102dab: 4c 89 eb                     	movq	%r13, %rbx
  102dae: 4c 8b 6c 24 20               	movq	0x20(%rsp), %r13
  102db3: 4c 89 ef                     	movq	%r13, %rdi
  102db6: e8 35 2e f5 ff               	callq	0x55bf0 <.text+0x313c0>
  102dbb: 4c 8b a4 24 80 00 00 00      	movq	0x80(%rsp), %r12
  102dc3: 48 89 ef                     	movq	%rbp, %rdi
  102dc6: 4c 89 e6                     	movq	%r12, %rsi
  102dc9: e8 22 2e f5 ff               	callq	0x55bf0 <.text+0x313c0>
  102dce: 48 8b 74 24 18               	movq	0x18(%rsp), %rsi
  102dd3: 4c 89 e9                     	movq	%r13, %rcx
  102dd6: 48 89 ea                     	movq	%rbp, %rdx
  102dd9: 48 8d 84 24 d0 09 00 00      	leaq	0x9d0(%rsp), %rax
  102de1: 48 89 c7                     	movq	%rax, %rdi
  102de4: 48 89 44 24 10               	movq	%rax, 0x10(%rsp)
  102de9: e8 42 dd ff ff               	callq	0x100b30 <.text+0xdc300>
  102dee: 48 89 ef                     	movq	%rbp, %rdi

### enumerated absolute path caller [0x10336b,0x1033a0)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  10336b: 4c 8b 7c 24 30               	movq	0x30(%rsp), %r15
  103370: 4c 01 e8                     	addq	%r13, %rax
  103373: 48 8d 74 c2 10               	leaq	0x10(%rdx,%rax,8), %rsi
  103378: 4c 89 ff                     	movq	%r15, %rdi
  10337b: e8 50 fb f1 ff               	callq	0x22ed0 <_ZNK9QFileInfo16absoluteFilePathEv@plt>
  103380: 48 8b 74 24 18               	movq	0x18(%rsp), %rsi
  103385: 48 8d ac 24 e0 09 00 00      	leaq	0x9e0(%rsp), %rbp
  10338d: 4c 89 fa                     	movq	%r15, %rdx
  103390: 48 8b 7c 24 38               	movq	0x38(%rsp), %rdi
  103395: 48 89 e9                     	movq	%rbp, %rcx
  103398: e8 93 d7 ff ff               	callq	0x100b30 <.text+0xdc300>
  10339d: 48 8b bc 24 50 09 00 00      	movq	0x950(%rsp), %rdi

### meta-call argument forwarding caller [0x16df80,0x16e085)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  16df80: 41 55                        	pushq	%r13
  16df82: 41 54                        	pushq	%r12
  16df84: 55                           	pushq	%rbp
  16df85: 53                           	pushq	%rbx
  16df86: 48 89 cb                     	movq	%rcx, %rbx
  16df89: 48 81 ec c8 00 00 00         	subq	$0xc8, %rsp
  16df90: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
  16df99: 48 89 84 24 b8 00 00 00      	movq	%rax, 0xb8(%rsp)
  16dfa1: 31 c0                        	xorl	%eax, %eax
  16dfa3: 85 f6                        	testl	%esi, %esi
  16dfa5: 0f 85 25 01 00 00            	jne	0x16e0d0 <.text+0x1498a0>
  16dfab: 83 fa 54                     	cmpl	$0x54, %edx
  16dfae: 0f 87 f4 00 00 00            	ja	0x16e0a8 <.text+0x149878>
  16dfb4: 48 8d 05 45 66 2d 00         	leaq	0x2d6645(%rip), %rax    # 0x444600
  16dfbb: 89 d2                        	movl	%edx, %edx
  16dfbd: 48 63 14 90                  	movslq	(%rax,%rdx,4), %rdx
  16dfc1: 48 01 d0                     	addq	%rdx, %rax
  16dfc4: ff e0                        	jmpq	*%rax
  16dfc6: 48 8b 51 10                  	movq	0x10(%rcx), %rdx
  16dfca: 4c 8d 64 24 70               	leaq	0x70(%rsp), %r12
  16dfcf: 48 8b 02                     	movq	(%rdx), %rax
  16dfd2: 48 89 44 24 70               	movq	%rax, 0x70(%rsp)
  16dfd7: 4c 39 e2                     	cmpq	%r12, %rdx
  16dfda: 0f 84 5a 0f 00 00            	je	0x16ef3a <.text+0x14a70a>
  16dfe0: 8b 08                        	movl	(%rax), %ecx
  16dfe2: 8d 51 01                     	leal	0x1(%rcx), %edx
  16dfe5: 83 fa 01                     	cmpl	$0x1, %edx
  16dfe8: 76 07                        	jbe	0x16dff1 <.text+0x1497c1>
  16dfea: f0                           	lock
  16dfeb: 83 00 01                     	addl	$0x1, (%rax)
  16dfee: 0f 95 c2                     	setne	%dl
  16dff1: 48 8b 53 08                  	movq	0x8(%rbx), %rdx
  16dff5: 4c 8d 6c 24 60               	leaq	0x60(%rsp), %r13
  16dffa: 48 8b 02                     	movq	(%rdx), %rax
  16dffd: 48 89 44 24 60               	movq	%rax, 0x60(%rsp)
  16e002: 4c 39 ea                     	cmpq	%r13, %rdx
  16e005: 0f 84 2f 0f 00 00            	je	0x16ef3a <.text+0x14a70a>
  16e00b: 8b 08                        	movl	(%rax), %ecx
  16e00d: 8d 51 01                     	leal	0x1(%rcx), %edx
  16e010: 83 fa 01                     	cmpl	$0x1, %edx
  16e013: 76 07                        	jbe	0x16e01c <.text+0x1497ec>
  16e015: f0                           	lock
  16e016: 83 00 01                     	addl	$0x1, (%rax)
  16e019: 0f 95 c2                     	setne	%dl
  16e01c: 48 8d ac 24 90 00 00 00      	leaq	0x90(%rsp), %rbp
  16e024: 48 89 fe                     	movq	%rdi, %rsi
  16e027: 4c 89 e1                     	movq	%r12, %rcx
  16e02a: 4c 89 ea                     	movq	%r13, %rdx
  16e02d: 48 89 ef                     	movq	%rbp, %rdi
  16e030: e8 fb 2a f9 ff               	callq	0x100b30 <.text+0xdc300>
  16e035: 48 8b 7c 24 60               	movq	0x60(%rsp), %rdi
  16e03a: 8b 07                        	movl	(%rdi), %eax
  16e03c: 85 c0                        	testl	%eax, %eax
  16e03e: 0f 85 a4 0e 00 00            	jne	0x16eee8 <.text+0x14a6b8>
  16e044: ba 08 00 00 00               	movl	$0x8, %edx
  16e049: be 02 00 00 00               	movl	$0x2, %esi
  16e04e: e8 8d 5e eb ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
  16e053: 48 8b 7c 24 70               	movq	0x70(%rsp), %rdi
  16e058: 8b 07                        	movl	(%rdi), %eax
  16e05a: 85 c0                        	testl	%eax, %eax
  16e05c: 0f 85 56 0c 00 00            	jne	0x16ecb8 <.text+0x14a488>
  16e062: ba 08 00 00 00               	movl	$0x8, %edx
  16e067: be 02 00 00 00               	movl	$0x2, %esi
  16e06c: e8 6f 5e eb ff               	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
  16e071: 48 8b 3b                     	movq	(%rbx), %rdi
  16e074: 48 85 ff                     	testq	%rdi, %rdi
  16e077: 74 08                        	je	0x16e081 <.text+0x149851>
  16e079: 48 89 ee                     	movq	%rbp, %rsi
  16e07c: e8 8f 5f eb ff               	callq	0x24010 <_ZN7QStringaSERKS_@plt>
  16e081: 48 8b bc 24 90 00 00 00      	movq	0x90(%rsp), %rdi

## Direct caller of parameterized navigation verifier path 0x140030 [0x9d4d5,0x9d510)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   9d4d5: 48 8d ac 24 30 02 00 00      	leaq	0x230(%rsp), %rbp
   9d4dd: e8 7e 8f fc ff               	callq	0x66460 <.text+0x41c30>
   9d4e2: 4c 8d a4 24 f0 01 00 00      	leaq	0x1f0(%rsp), %r12
   9d4ea: 48 89 d9                     	movq	%rbx, %rcx
   9d4ed: 48 89 c6                     	movq	%rax, %rsi
   9d4f0: 48 8d ac 24 30 02 00 00      	leaq	0x230(%rsp), %rbp
   9d4f8: 4c 89 e7                     	movq	%r12, %rdi
   9d4fb: 48 89 ea                     	movq	%rbp, %rdx
   9d4fe: e8 2d 2b 0a 00               	callq	0x140030 <.text+0x11b800>
   9d503: 48 8b 84 24 e0 01 00 00      	movq	0x1e0(%rsp), %rax
   9d50b: 4c 89 e7                     	movq	%r12, %rdi
   9d50e: 48 8b 94 24 f0 01 00 00      	movq	0x1f0(%rsp), %rdx
