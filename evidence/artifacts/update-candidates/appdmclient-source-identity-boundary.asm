# Exact AppDMClient source-identity boundary excerpts
# Binary: work/decrypted-eu-260128/extracted-safe/mango-rootfs/app/bin/AppDMClient
# SHA-256: 9a1fb796d7ac24fcce71c16e3dbee9306c888f43e705ee081f41b7d473978bd0
# Build ID: b2dbcc5231f444d8f1dd68eb7a2376323ce805df
# Address namespace: ELF link-time virtual addresses (PIE image base zero)
# Tool: /opt/homebrew/opt/llvm/bin/llvm-objdump
# FDEs: verifier wrapper [0x34870,0x34d43); staging [0x7ff60,0x830e4); XML reader [0xe1e90,0xe3166)
# Referenced NUL-terminated strings in the same PIE VA namespace:
#   0x17ffff: "%1/AppUpgrade"
#   0x17531e: "%1/.lge.upgrade.xml"
#   0x17545f: "cp -f %1 %2"
#   0x173998: "mkdir -p %1"
#   0x178f90: "/app/share/AppUpgrade/DecryptToPIPE"
#   0x172c07: "/tmp"

# Verifier wrapper: fixed key open/read/close, target pathname passed to linked verifier, integer return

work/decrypted-eu-260128/extracted-safe/mango-rootfs/app/bin/AppDMClient:	file format elf64-x86-64

Disassembly of section .text:

000000000001d1b0 <.text>:
   34870: 41 57                        	pushq	%r15
   34872: 48 8d 3d 44 e3 13 00         	leaq	0x13e344(%rip), %rdi    # 0x172bbd
   34879: 49 89 f7                     	movq	%rsi, %r15
   3487c: be 10 00 00 00               	movl	$0x10, %esi
   34881: 41 56                        	pushq	%r14
   34883: 41 55                        	pushq	%r13
   34885: 41 54                        	pushq	%r12
   34887: 55                           	pushq	%rbp
   34888: 53                           	pushq	%rbx
   34889: 48 83 ec 68                  	subq	$0x68, %rsp
   3488d: 64 48 8b 04 25 28 00 00 00   	movq	%fs:0x28, %rax
   34896: 48 89 44 24 58               	movq	%rax, 0x58(%rsp)
   3489b: 31 c0                        	xorl	%eax, %eax
   3489d: e8 ee 71 fe ff               	callq	0x1ba90 <_ZN7QString16fromAscii_helperEPKci@plt>
   348a2: be 16 00 00 00               	movl	$0x16, %esi
   348a7: 48 8d 3d f4 e2 13 00         	leaq	0x13e2f4(%rip), %rdi    # 0x172ba2
   348ae: 48 89 44 24 40               	movq	%rax, 0x40(%rsp)
   348b3: e8 d8 71 fe ff               	callq	0x1ba90 <_ZN7QString16fromAscii_helperEPKci@plt>
   348b8: be 04 00 00 00               	movl	$0x4, %esi
   348bd: 48 89 44 24 20               	movq	%rax, 0x20(%rsp)
   348c2: 48 8d 3d a7 e2 13 00         	leaq	0x13e2a7(%rip), %rdi    # 0x172b70
   348c9: e8 c2 71 fe ff               	callq	0x1ba90 <_ZN7QString16fromAscii_helperEPKci@plt>
   348ce: 48 8d 6c 24 30               	leaq	0x30(%rsp), %rbp
   348d3: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   348d9: 31 c9                        	xorl	%ecx, %ecx
   348db: 48 89 44 24 10               	movq	%rax, 0x10(%rsp)
   348e0: 4c 8d 74 24 20               	leaq	0x20(%rsp), %r14
   348e5: 48 89 ef                     	movq	%rbp, %rdi
   348e8: 4c 8d 64 24 10               	leaq	0x10(%rsp), %r12
   348ed: 4c 89 f2                     	movq	%r14, %rdx
   348f0: 4c 89 e6                     	movq	%r12, %rsi
   348f3: e8 48 70 fe ff               	callq	0x1b940 <_ZNK7QString3argERKS_i5QChar@plt>
   348f8: 48 8d 5c 24 40               	leaq	0x40(%rsp), %rbx
   348fd: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   34903: 31 c9                        	xorl	%ecx, %ecx
   34905: 48 89 da                     	movq	%rbx, %rdx
   34908: 48 89 ee                     	movq	%rbp, %rsi
   3490b: 48 89 e7                     	movq	%rsp, %rdi
   3490e: 49 89 e5                     	movq	%rsp, %r13
   34911: e8 2a 70 fe ff               	callq	0x1b940 <_ZNK7QString3argERKS_i5QChar@plt>
   34916: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   3491b: 8b 07                        	movl	(%rdi), %eax
   3491d: 85 c0                        	testl	%eax, %eax
   3491f: 0f 85 bb 01 00 00            	jne	0x34ae0 <.text+0x17930>
   34925: ba 08 00 00 00               	movl	$0x8, %edx
   3492a: be 02 00 00 00               	movl	$0x2, %esi
   3492f: e8 cc 7f fe ff               	callq	0x1c900 <_ZN10QArrayData10deallocateEPS_mm@plt>
   34934: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   34939: 8b 07                        	movl	(%rdi), %eax
   3493b: 85 c0                        	testl	%eax, %eax
   3493d: 0f 85 15 02 00 00            	jne	0x34b58 <.text+0x179a8>
   34943: ba 08 00 00 00               	movl	$0x8, %edx
   34948: be 02 00 00 00               	movl	$0x2, %esi
   3494d: e8 ae 7f fe ff               	callq	0x1c900 <_ZN10QArrayData10deallocateEPS_mm@plt>
   34952: 48 8b 7c 24 20               	movq	0x20(%rsp), %rdi
   34957: 8b 07                        	movl	(%rdi), %eax
   34959: 85 c0                        	testl	%eax, %eax
   3495b: 0f 85 cf 01 00 00            	jne	0x34b30 <.text+0x17980>
   34961: ba 08 00 00 00               	movl	$0x8, %edx
   34966: be 02 00 00 00               	movl	$0x2, %esi
   3496b: e8 90 7f fe ff               	callq	0x1c900 <_ZN10QArrayData10deallocateEPS_mm@plt>
   34970: 48 8b 7c 24 40               	movq	0x40(%rsp), %rdi
   34975: 8b 07                        	movl	(%rdi), %eax
   34977: 85 c0                        	testl	%eax, %eax
   34979: 0f 85 89 01 00 00            	jne	0x34b08 <.text+0x17958>
   3497f: ba 08 00 00 00               	movl	$0x8, %edx
   34984: be 02 00 00 00               	movl	$0x2, %esi
   34989: e8 72 7f fe ff               	callq	0x1c900 <_ZN10QArrayData10deallocateEPS_mm@plt>
   3498e: 4c 89 ee                     	movq	%r13, %rsi
   34991: 48 89 df                     	movq	%rbx, %rdi
   34994: e8 77 70 fe ff               	callq	0x1ba10 <_ZN5QFileC1ERK7QString@plt>
   34999: 48 89 df                     	movq	%rbx, %rdi
   3499c: e8 2f 7b fe ff               	callq	0x1c4d0 <_ZNK5QFile6existsEv@plt>
   349a1: 84 c0                        	testb	%al, %al
   349a3: 0f 84 e7 02 00 00            	je	0x34c90 <.text+0x17ae0>
   349a9: 48 8d 05 d0 a4 3e 00         	leaq	0x3ea4d0(%rip), %rax    # 0x41ee80 <_ZN10QArrayData11shared_nullE>
   349b0: 4c 89 e7                     	movq	%r12, %rdi
   349b3: 48 89 44 24 10               	movq	%rax, 0x10(%rsp)
   349b8: e8 c3 75 fe ff               	callq	0x1bf80 <_ZN10QByteArray5clearEv@plt>
   349bd: be 01 00 00 00               	movl	$0x1, %esi
   349c2: 48 89 df                     	movq	%rbx, %rdi
   349c5: e8 56 6b fe ff               	callq	0x1b520 <_ZN5QFile4openE6QFlagsIN9QIODevice12OpenModeFlagEE@plt>
   349ca: 84 c0                        	testb	%al, %al
   349cc: 0f 84 ae 01 00 00            	je	0x34b80 <.text+0x179d0>
   349d2: 48 89 de                     	movq	%rbx, %rsi
   349d5: 4c 89 f7                     	movq	%r14, %rdi
   349d8: e8 33 81 fe ff               	callq	0x1cb10 <_ZN9QIODevice7readAllEv@plt>
   349dd: 4c 89 f6                     	movq	%r14, %rsi
   349e0: 4c 89 e7                     	movq	%r12, %rdi
   349e3: e8 98 7b fe ff               	callq	0x1c580 <_ZN10QByteArray6appendERKS_@plt>
   349e8: 48 8b 7c 24 20               	movq	0x20(%rsp), %rdi
   349ed: 8b 07                        	movl	(%rdi), %eax
   349ef: 85 c0                        	testl	%eax, %eax
   349f1: 0f 85 41 02 00 00            	jne	0x34c38 <.text+0x17a88>
   349f7: ba 08 00 00 00               	movl	$0x8, %edx
   349fc: be 01 00 00 00               	movl	$0x1, %esi
   34a01: e8 fa 7e fe ff               	callq	0x1c900 <_ZN10QArrayData10deallocateEPS_mm@plt>
   34a06: 48 89 df                     	movq	%rbx, %rdi
   34a09: e8 52 65 fe ff               	callq	0x1af60 <_ZN11QFileDevice5closeEv@plt>
   34a0e: 48 8b 44 24 10               	movq	0x10(%rsp), %rax
   34a13: 83 38 01                     	cmpl	$0x1, (%rax)
   34a16: 0f 86 5c 02 00 00            	jbe	0x34c78 <.text+0x17ac8>
   34a1c: 0f be 50 0b                  	movsbl	0xb(%rax), %edx
   34a20: 4c 89 e7                     	movq	%r12, %rdi
   34a23: 8b 70 04                     	movl	0x4(%rax), %esi
   34a26: c1 ea 1f                     	shrl	$0x1f, %edx
   34a29: 83 c6 01                     	addl	$0x1, %esi
   34a2c: e8 2f 78 fe ff               	callq	0x1c260 <_ZN10QByteArray11reallocDataEj6QFlagsIN10QArrayData16AllocationOptionEE@plt>
   34a31: 48 8b 44 24 10               	movq	0x10(%rsp), %rax
   34a36: 4c 8b 70 10                  	movq	0x10(%rax), %r14
   34a3a: 49 8b 37                     	movq	(%r15), %rsi
   34a3d: 48 89 ef                     	movq	%rbp, %rdi
   34a40: 49 01 c6                     	addq	%rax, %r14
   34a43: 8b 56 04                     	movl	0x4(%rsi), %edx
   34a46: 48 03 76 10                  	addq	0x10(%rsi), %rsi
   34a4a: e8 31 69 fe ff               	callq	0x1b380 <_ZN7QString18toLocal8Bit_helperEPK5QChari@plt>
   34a4f: 48 8b 44 24 30               	movq	0x30(%rsp), %rax
   34a54: 83 38 01                     	cmpl	$0x1, (%rax)
   34a57: 0f 86 03 02 00 00            	jbe	0x34c60 <.text+0x17ab0>
   34a5d: 0f be 50 0b                  	movsbl	0xb(%rax), %edx
   34a61: 48 89 ef                     	movq	%rbp, %rdi
   34a64: 8b 70 04                     	movl	0x4(%rax), %esi
   34a67: c1 ea 1f                     	shrl	$0x1f, %edx
   34a6a: 83 c6 01                     	addl	$0x1, %esi
   34a6d: e8 ee 77 fe ff               	callq	0x1c260 <_ZN10QByteArray11reallocDataEj6QFlagsIN10QArrayData16AllocationOptionEE@plt>
   34a72: 48 8b 44 24 30               	movq	0x30(%rsp), %rax
   34a77: 48 8b 78 10                  	movq	0x10(%rax), %rdi
   34a7b: 48 01 c7                     	addq	%rax, %rdi
   34a7e: 4c 89 f6                     	movq	%r14, %rsi
   34a81: e8 ba c5 0e 00               	callq	0x121040 <.text+0x103e90>
   34a86: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   34a8b: 89 c5                        	movl	%eax, %ebp
   34a8d: 8b 17                        	movl	(%rdi), %edx
   34a8f: 85 d2                        	testl	%edx, %edx
   34a91: 0f 85 79 01 00 00            	jne	0x34c10 <.text+0x17a60>
   34a97: ba 08 00 00 00               	movl	$0x8, %edx
   34a9c: be 01 00 00 00               	movl	$0x1, %esi
   34aa1: e8 5a 7e fe ff               	callq	0x1c900 <_ZN10QArrayData10deallocateEPS_mm@plt>
   34aa6: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   34aab: 8b 07                        	movl	(%rdi), %eax
   34aad: 85 c0                        	testl	%eax, %eax
   34aaf: 0f 84 df 00 00 00            	je	0x34b94 <.text+0x179e4>
   34ab5: 0f 1f 00                     	nopl	(%rax)
   34ab8: 83 f8 ff                     	cmpl	$-0x1, %eax
   34abb: 0f 84 e2 00 00 00            	je	0x34ba3 <.text+0x179f3>
   34ac1: f0                           	lock
   34ac2: 83 2f 01                     	subl	$0x1, (%rdi)
   34ac5: 0f 95 c0                     	setne	%al
   34ac8: 84 c0                        	testb	%al, %al
   34aca: 0f 85 d3 00 00 00            	jne	0x34ba3 <.text+0x179f3>
   34ad0: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   34ad5: e9 ba 00 00 00               	jmp	0x34b94 <.text+0x179e4>
   34ada: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   34ae0: 83 f8 ff                     	cmpl	$-0x1, %eax
   34ae3: 0f 84 4b fe ff ff            	je	0x34934 <.text+0x17784>
   34ae9: f0                           	lock
   34aea: 83 2f 01                     	subl	$0x1, (%rdi)
   34aed: 0f 95 c0                     	setne	%al
   34af0: 84 c0                        	testb	%al, %al
   34af2: 0f 85 3c fe ff ff            	jne	0x34934 <.text+0x17784>
   34af8: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   34afd: e9 23 fe ff ff               	jmp	0x34925 <.text+0x17775>
   34b02: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   34b08: 83 f8 ff                     	cmpl	$-0x1, %eax
   34b0b: 0f 84 7d fe ff ff            	je	0x3498e <.text+0x177de>
   34b11: f0                           	lock
   34b12: 83 2f 01                     	subl	$0x1, (%rdi)
   34b15: 0f 95 c0                     	setne	%al
   34b18: 84 c0                        	testb	%al, %al
   34b1a: 0f 85 6e fe ff ff            	jne	0x3498e <.text+0x177de>
   34b20: 48 8b 7c 24 40               	movq	0x40(%rsp), %rdi
   34b25: e9 55 fe ff ff               	jmp	0x3497f <.text+0x177cf>
   34b2a: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   34b30: 83 f8 ff                     	cmpl	$-0x1, %eax
   34b33: 0f 84 37 fe ff ff            	je	0x34970 <.text+0x177c0>
   34b39: f0                           	lock
   34b3a: 83 2f 01                     	subl	$0x1, (%rdi)
   34b3d: 0f 95 c0                     	setne	%al
   34b40: 84 c0                        	testb	%al, %al
   34b42: 0f 85 28 fe ff ff            	jne	0x34970 <.text+0x177c0>
   34b48: 48 8b 7c 24 20               	movq	0x20(%rsp), %rdi
   34b4d: e9 0f fe ff ff               	jmp	0x34961 <.text+0x177b1>
   34b52: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   34b58: 83 f8 ff                     	cmpl	$-0x1, %eax
   34b5b: 0f 84 f1 fd ff ff            	je	0x34952 <.text+0x177a2>
   34b61: f0                           	lock
   34b62: 83 2f 01                     	subl	$0x1, (%rdi)
   34b65: 0f 95 c0                     	setne	%al
   34b68: 84 c0                        	testb	%al, %al
   34b6a: 0f 85 e2 fd ff ff            	jne	0x34952 <.text+0x177a2>
   34b70: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   34b75: e9 c9 fd ff ff               	jmp	0x34943 <.text+0x17793>
   34b7a: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   34b80: bd 9b ff ff ff               	movl	$0xffffff9b, %ebp       # imm = 0xFFFFFF9B
   34b85: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   34b8a: 8b 07                        	movl	(%rdi), %eax
   34b8c: 85 c0                        	testl	%eax, %eax
   34b8e: 0f 85 24 ff ff ff            	jne	0x34ab8 <.text+0x17908>
   34b94: ba 08 00 00 00               	movl	$0x8, %edx
   34b99: be 01 00 00 00               	movl	$0x1, %esi
   34b9e: e8 5d 7d fe ff               	callq	0x1c900 <_ZN10QArrayData10deallocateEPS_mm@plt>
   34ba3: 48 89 df                     	movq	%rbx, %rdi
   34ba6: e8 d5 6d fe ff               	callq	0x1b980 <_ZN5QFileD1Ev@plt>
   34bab: 48 8b 3c 24                  	movq	(%rsp), %rdi
   34baf: 8b 07                        	movl	(%rdi), %eax
   34bb1: 85 c0                        	testl	%eax, %eax
   34bb3: 75 3b                        	jne	0x34bf0 <.text+0x17a40>
   34bb5: ba 08 00 00 00               	movl	$0x8, %edx
   34bba: be 02 00 00 00               	movl	$0x2, %esi
   34bbf: e8 3c 7d fe ff               	callq	0x1c900 <_ZN10QArrayData10deallocateEPS_mm@plt>
   34bc4: 48 8b 4c 24 58               	movq	0x58(%rsp), %rcx
   34bc9: 64 48 33 0c 25 28 00 00 00   	xorq	%fs:0x28, %rcx
   34bd2: 89 e8                        	movl	%ebp, %eax
   34bd4: 0f 85 c0 00 00 00            	jne	0x34c9a <.text+0x17aea>
   34bda: 48 83 c4 68                  	addq	$0x68, %rsp
   34bde: 5b                           	popq	%rbx
   34bdf: 5d                           	popq	%rbp
   34be0: 41 5c                        	popq	%r12
   34be2: 41 5d                        	popq	%r13
   34be4: 41 5e                        	popq	%r14
   34be6: 41 5f                        	popq	%r15
   34be8: c3                           	retq
   34be9: 0f 1f 80 00 00 00 00         	nopl	(%rax)
   34bf0: 83 f8 ff                     	cmpl	$-0x1, %eax
   34bf3: 74 cf                        	je	0x34bc4 <.text+0x17a14>
   34bf5: f0                           	lock
   34bf6: 83 2f 01                     	subl	$0x1, (%rdi)
   34bf9: 0f 95 c0                     	setne	%al
   34bfc: 84 c0                        	testb	%al, %al
   34bfe: 75 c4                        	jne	0x34bc4 <.text+0x17a14>
   34c00: 48 8b 3c 24                  	movq	(%rsp), %rdi
   34c04: eb af                        	jmp	0x34bb5 <.text+0x17a05>
   34c06: 66 2e 0f 1f 84 00 00 00 00 00	nopw	%cs:(%rax,%rax)
   34c10: 83 fa ff                     	cmpl	$-0x1, %edx
   34c13: 0f 84 6c ff ff ff            	je	0x34b85 <.text+0x179d5>
   34c19: f0                           	lock
   34c1a: 83 2f 01                     	subl	$0x1, (%rdi)
   34c1d: 0f 95 c0                     	setne	%al
   34c20: 84 c0                        	testb	%al, %al
   34c22: 0f 85 5d ff ff ff            	jne	0x34b85 <.text+0x179d5>
   34c28: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   34c2d: e9 65 fe ff ff               	jmp	0x34a97 <.text+0x178e7>
   34c32: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   34c38: 83 f8 ff                     	cmpl	$-0x1, %eax
   34c3b: 0f 84 c5 fd ff ff            	je	0x34a06 <.text+0x17856>
   34c41: f0                           	lock
   34c42: 83 2f 01                     	subl	$0x1, (%rdi)
   34c45: 0f 95 c0                     	setne	%al
   34c48: 84 c0                        	testb	%al, %al
   34c4a: 0f 85 b6 fd ff ff            	jne	0x34a06 <.text+0x17856>
   34c50: 48 8b 7c 24 20               	movq	0x20(%rsp), %rdi
   34c55: e9 9d fd ff ff               	jmp	0x349f7 <.text+0x17847>
   34c5a: 66 0f 1f 44 00 00            	nopw	(%rax,%rax)
   34c60: 48 8b 78 10                  	movq	0x10(%rax), %rdi
   34c64: 48 83 ff 18                  	cmpq	$0x18, %rdi
   34c68: 0f 85 ef fd ff ff            	jne	0x34a5d <.text+0x178ad>
   34c6e: e9 08 fe ff ff               	jmp	0x34a7b <.text+0x178cb>
   34c73: 0f 1f 44 00 00               	nopl	(%rax,%rax)
   34c78: 4c 8b 70 10                  	movq	0x10(%rax), %r14
   34c7c: 49 83 fe 18                  	cmpq	$0x18, %r14
   34c80: 0f 85 96 fd ff ff            	jne	0x34a1c <.text+0x1786c>
   34c86: e9 af fd ff ff               	jmp	0x34a3a <.text+0x1788a>
   34c8b: 0f 1f 44 00 00               	nopl	(%rax,%rax)
   34c90: bd 9c ff ff ff               	movl	$0xffffff9c, %ebp       # imm = 0xFFFFFF9C
   34c95: e9 09 ff ff ff               	jmp	0x34ba3 <.text+0x179f3>
   34c9a: e8 91 68 fe ff               	callq	0x1b530 <__stack_chk_fail@plt>
   34c9f: 4c 89 f7                     	movq	%r14, %rdi
   34ca2: 48 89 c5                     	movq	%rax, %rbp
   34ca5: e8 16 c3 ff ff               	callq	0x30fc0 <.text+0x13e10>
   34caa: 4c 89 e7                     	movq	%r12, %rdi
   34cad: e8 0e c3 ff ff               	callq	0x30fc0 <.text+0x13e10>
   34cb2: 48 89 df                     	movq	%rbx, %rdi
   34cb5: 48 89 eb                     	movq	%rbp, %rbx
   34cb8: e8 c3 6c fe ff               	callq	0x1b980 <_ZN5QFileD1Ev@plt>
   34cbd: 4c 89 ef                     	movq	%r13, %rdi
   34cc0: e8 0b ba ff ff               	callq	0x306d0 <.text+0x13520>
   34cc5: 48 89 df                     	movq	%rbx, %rdi
   34cc8: e8 e3 70 fe ff               	callq	0x1bdb0 <_Unwind_Resume@plt>
   34ccd: 49 89 c6                     	movq	%rax, %r14
   34cd0: 48 89 ef                     	movq	%rbp, %rdi
   34cd3: e8 e8 c2 ff ff               	callq	0x30fc0 <.text+0x13e10>
   34cd8: 4c 89 f5                     	movq	%r14, %rbp
   34cdb: eb cd                        	jmp	0x34caa <.text+0x17afa>
   34cdd: 49 89 c5                     	movq	%rax, %r13
   34ce0: 48 89 ef                     	movq	%rbp, %rdi
   34ce3: e8 e8 b9 ff ff               	callq	0x306d0 <.text+0x13520>
   34ce8: 4c 89 ed                     	movq	%r13, %rbp
   34ceb: 4c 89 e7                     	movq	%r12, %rdi
   34cee: e8 dd b9 ff ff               	callq	0x306d0 <.text+0x13520>
   34cf3: 4c 89 f7                     	movq	%r14, %rdi
   34cf6: e8 d5 b9 ff ff               	callq	0x306d0 <.text+0x13520>
   34cfb: 48 89 df                     	movq	%rbx, %rdi
   34cfe: e8 cd b9 ff ff               	callq	0x306d0 <.text+0x13520>
   34d03: 48 89 ef                     	movq	%rbp, %rdi
   34d06: e8 a5 70 fe ff               	callq	0x1bdb0 <_Unwind_Resume@plt>
   34d0b: 48 8d 5c 24 40               	leaq	0x40(%rsp), %rbx
   34d10: 48 89 c5                     	movq	%rax, %rbp
   34d13: eb d6                        	jmp	0x34ceb <.text+0x17b3b>
   34d15: 4c 8d 74 24 20               	leaq	0x20(%rsp), %r14
   34d1a: 48 89 c5                     	movq	%rax, %rbp
   34d1d: 48 8d 5c 24 40               	leaq	0x40(%rsp), %rbx
   34d22: eb cf                        	jmp	0x34cf3 <.text+0x17b43>
   34d24: 48 8d 5c 24 40               	leaq	0x40(%rsp), %rbx
   34d29: 48 89 c5                     	movq	%rax, %rbp
   34d2c: eb cd                        	jmp	0x34cfb <.text+0x17b4b>
   34d2e: 48 89 c5                     	movq	%rax, %rbp
   34d31: e9 7c ff ff ff               	jmp	0x34cb2 <.text+0x17b02>
   34d36: 48 89 c3                     	movq	%rax, %rbx
   34d39: eb 82                        	jmp	0x34cbd <.text+0x17b0d>
   34d3b: 48 89 c5                     	movq	%rax, %rbp
   34d3e: e9 67 ff ff ff               	jmp	0x34caa <.text+0x17afa>

# Staging: source AppUpgrade/XML verifier calls and retained integer results

work/decrypted-eu-260128/extracted-safe/mango-rootfs/app/bin/AppDMClient:	file format elf64-x86-64

Disassembly of section .text:

000000000001d1b0 <.text>:
   8011b: 48 8d 35 eb 51 0f 00         	leaq	0xf51eb(%rip), %rsi     # 0x17530d
   80122: 48 89 c7                     	movq	%rax, %rdi
   80125: 48 89 44 24 40               	movq	%rax, 0x40(%rsp)
   8012a: e8 a1 ae 00 00               	callq	0x8afd0 <.text+0x6de20>
   8012f: 48 8d 84 24 90 00 00 00      	leaq	0x90(%rsp), %rax
   80137: 48 8d 35 a7 43 10 00         	leaq	0x1043a7(%rip), %rsi    # 0x1844e5
   8013e: 48 89 c7                     	movq	%rax, %rdi
   80141: 48 89 44 24 48               	movq	%rax, 0x48(%rsp)
   80146: e8 85 ae 00 00               	callq	0x8afd0 <.text+0x6de20>
   8014b: 48 8d ac 24 c0 00 00 00      	leaq	0xc0(%rsp), %rbp
   80153: 41 c6 87 1f 01 00 00 00      	movb	$0x0, 0x11f(%r15)
   8015b: 48 8d 05 1e ed 39 00         	leaq	0x39ed1e(%rip), %rax    # 0x41ee80 <_ZN10QArrayData11shared_nullE>
   80162: 48 89 ef                     	movq	%rbp, %rdi
   80165: 48 8d 35 93 fe 0f 00         	leaq	0xffe93(%rip), %rsi     # 0x17ffff
   8016c: 48 89 84 24 a0 00 00 00      	movq	%rax, 0xa0(%rsp)
   80174: e8 57 ae 00 00               	callq	0x8afd0 <.text+0x6de20>
   80179: 48 8d 84 24 b0 00 00 00      	leaq	0xb0(%rsp), %rax
   80181: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   80187: 31 c9                        	xorl	%ecx, %ecx
   80189: 4c 89 ea                     	movq	%r13, %rdx
   8018c: 48 89 ee                     	movq	%rbp, %rsi
   8018f: 48 89 c7                     	movq	%rax, %rdi
   80192: 48 89 04 24                  	movq	%rax, (%rsp)
   80196: e8 a5 b7 f9 ff               	callq	0x1b940 <_ZNK7QString3argERKS_i5QChar@plt>
   8019b: 48 89 ef                     	movq	%rbp, %rdi
   8019e: e8 2d 05 fb ff               	callq	0x306d0 <.text+0x13520>
   801a3: 48 8d ac 24 f0 00 00 00      	leaq	0xf0(%rsp), %rbp
   801ab: 48 8d 35 cd 37 0f 00         	leaq	0xf37cd(%rip), %rsi     # 0x17397f
   801b2: 48 89 ef                     	movq	%rbp, %rdi
   801b5: e8 16 ae 00 00               	callq	0x8afd0 <.text+0x6de20>
   801ba: 4c 8d a4 24 e0 00 00 00      	leaq	0xe0(%rsp), %r12
   801c2: 48 8d 35 36 fe 0f 00         	leaq	0xffe36(%rip), %rsi     # 0x17ffff
   801c9: 4c 89 e7                     	movq	%r12, %rdi
   801cc: e8 ff ad 00 00               	callq	0x8afd0 <.text+0x6de20>
   801d1: 48 8d 84 24 d0 00 00 00      	leaq	0xd0(%rsp), %rax
   801d9: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   801df: 31 c9                        	xorl	%ecx, %ecx
   801e1: 48 89 ea                     	movq	%rbp, %rdx
   801e4: 4c 89 e6                     	movq	%r12, %rsi
   801e7: 48 89 c7                     	movq	%rax, %rdi
   801ea: 48 89 44 24 08               	movq	%rax, 0x8(%rsp)
   801ef: e8 4c b7 f9 ff               	callq	0x1b940 <_ZNK7QString3argERKS_i5QChar@plt>
   801f4: 4c 89 e7                     	movq	%r12, %rdi
   801f7: e8 d4 04 fb ff               	callq	0x306d0 <.text+0x13520>
   801fc: 48 89 ef                     	movq	%rbp, %rdi
   801ff: e8 cc 04 fb ff               	callq	0x306d0 <.text+0x13520>
   80204: 48 8d ac 24 10 01 00 00      	leaq	0x110(%rsp), %rbp
   8020c: 48 8d 35 0b 51 0f 00         	leaq	0xf510b(%rip), %rsi     # 0x17531e
   80213: 48 89 ef                     	movq	%rbp, %rdi
   80216: e8 b5 ad 00 00               	callq	0x8afd0 <.text+0x6de20>
   8021b: 48 8d 84 24 00 01 00 00      	leaq	0x100(%rsp), %rax
   80223: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   80229: 31 c9                        	xorl	%ecx, %ecx
   8022b: 4c 89 ea                     	movq	%r13, %rdx
   8022e: 48 89 ee                     	movq	%rbp, %rsi
   80231: 48 89 c7                     	movq	%rax, %rdi
   80234: 48 89 44 24 30               	movq	%rax, 0x30(%rsp)
   80239: e8 02 b7 f9 ff               	callq	0x1b940 <_ZNK7QString3argERKS_i5QChar@plt>
   8023e: 48 89 ef                     	movq	%rbp, %rdi
   80241: e8 8a 04 fb ff               	callq	0x306d0 <.text+0x13520>
   80246: 48 8d ac 24 40 01 00 00      	leaq	0x140(%rsp), %rbp
   8024e: 48 8d 35 2a 37 0f 00         	leaq	0xf372a(%rip), %rsi     # 0x17397f
   80255: 48 89 ef                     	movq	%rbp, %rdi
   80258: e8 73 ad 00 00               	callq	0x8afd0 <.text+0x6de20>
   8025d: 4c 8d a4 24 30 01 00 00      	leaq	0x130(%rsp), %r12
   80265: 48 8d 35 b2 50 0f 00         	leaq	0xf50b2(%rip), %rsi     # 0x17531e
   8026c: 4c 89 e7                     	movq	%r12, %rdi
   8026f: e8 5c ad 00 00               	callq	0x8afd0 <.text+0x6de20>
   80274: 48 8d 84 24 20 01 00 00      	leaq	0x120(%rsp), %rax
   8027c: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   80282: 31 c9                        	xorl	%ecx, %ecx
   80284: 48 89 ea                     	movq	%rbp, %rdx
   80287: 4c 89 e6                     	movq	%r12, %rsi
   8028a: 48 89 c7                     	movq	%rax, %rdi
   8028d: 48 89 44 24 50               	movq	%rax, 0x50(%rsp)
   80292: e8 a9 b6 f9 ff               	callq	0x1b940 <_ZNK7QString3argERKS_i5QChar@plt>
   80297: 4c 89 e7                     	movq	%r12, %rdi
   8029a: e8 31 04 fb ff               	callq	0x306d0 <.text+0x13520>
   8029f: 48 89 ef                     	movq	%rbp, %rdi
   802a2: e8 29 04 fb ff               	callq	0x306d0 <.text+0x13520>
   802a7: 48 8b 84 24 b0 00 00 00      	movq	0xb0(%rsp), %rax
   802af: 8b 08                        	movl	(%rax), %ecx
   802b1: 48 89 84 24 20 07 00 00      	movq	%rax, 0x720(%rsp)
   802b9: 8d 51 01                     	leal	0x1(%rcx), %edx
   802bc: 83 fa 01                     	cmpl	$0x1, %edx
   802bf: 76 07                        	jbe	0x802c8 <.text+0x63118>
   802c1: f0                           	lock
   802c2: 83 00 01                     	addl	$0x1, (%rax)
   802c5: 0f 95 c2                     	setne	%dl
   802c8: 48 8b 3d 51 ed 39 00         	movq	0x39ed51(%rip), %rdi    # 0x41f020 <_ZN9QListData11shared_nullE+0x40>
   802cf: 48 85 ff                     	testq	%rdi, %rdi
   802d2: 0f 84 e8 1c 00 00            	je	0x81fc0 <.text+0x64e10>
   802d8: 48 89 de                     	movq	%rbx, %rsi
   802db: e8 90 45 fb ff               	callq	0x34870 <.text+0x176c0>
   802e0: 48 89 df                     	movq	%rbx, %rdi
   802e3: 89 44 24 10                  	movl	%eax, 0x10(%rsp)
   802e7: e8 e4 03 fb ff               	callq	0x306d0 <.text+0x13520>
   802ec: 48 8b 84 24 00 01 00 00      	movq	0x100(%rsp), %rax
   802f4: 8b 08                        	movl	(%rax), %ecx
   802f6: 48 89 84 24 20 07 00 00      	movq	%rax, 0x720(%rsp)
   802fe: 8d 51 01                     	leal	0x1(%rcx), %edx
   80301: 83 fa 01                     	cmpl	$0x1, %edx
   80304: 76 07                        	jbe	0x8030d <.text+0x6315d>
   80306: f0                           	lock
   80307: 83 00 01                     	addl	$0x1, (%rax)
   8030a: 0f 95 c2                     	setne	%dl
   8030d: 48 8b 3d 0c ed 39 00         	movq	0x39ed0c(%rip), %rdi    # 0x41f020 <_ZN9QListData11shared_nullE+0x40>
   80314: 48 85 ff                     	testq	%rdi, %rdi
   80317: 0f 84 53 1c 00 00            	je	0x81f70 <.text+0x64dc0>
   8031d: 48 89 de                     	movq	%rbx, %rsi
   80320: e8 4b 45 fb ff               	callq	0x34870 <.text+0x176c0>
   80325: 48 8d ac 24 50 01 00 00      	leaq	0x150(%rsp), %rbp
   8032d: 48 89 df                     	movq	%rbx, %rdi
   80330: 89 44 24 18                  	movl	%eax, 0x18(%rsp)
   80334: e8 97 03 fb ff               	callq	0x306d0 <.text+0x13520>
   80339: 48 8d 05 a4 20 0f 00         	leaq	0xf20a4(%rip), %rax     # 0x1723e4
   80340: 48 89 de                     	movq	%rbx, %rsi
   80343: 48 89 ef                     	movq	%rbp, %rdi
   80346: c7 84 24 20 07 00 00 02 00 00 00     	movl	$0x2, 0x720(%rsp)
   80351: c7 84 24 24 07 00 00 00 00 00 00     	movl	$0x0, 0x724(%rsp)
   8035c: 48 c7 84 24 28 07 00 00 00 00 00 00  	movq	$0x0, 0x728(%rsp)

# Staging: source/destination pathname comparison and conditional verifier-result gates

work/decrypted-eu-260128/extracted-safe/mango-rootfs/app/bin/AppDMClient:	file format elf64-x86-64

Disassembly of section .text:

000000000001d1b0 <.text>:
   80b8d: e8 8e 05 fb ff               	callq	0x31120 <.text+0x13f70>
   80b92: 48 89 ef                     	movq	%rbp, %rdi
   80b95: e8 f6 c0 f9 ff               	callq	0x1cc90 <_ZN6QDebugD1Ev@plt>
   80b9a: 4c 89 f7                     	movq	%r14, %rdi
   80b9d: e8 9e a8 f9 ff               	callq	0x1b440 <_ZN4QDirD1Ev@plt>
   80ba2: 48 8b 74 24 08               	movq	0x8(%rsp), %rsi
   80ba7: 48 8b 3c 24                  	movq	(%rsp), %rdi
   80bab: e8 c0 ab f9 ff               	callq	0x1b770 <_ZeqRK7QStringS1_@plt>
   80bb0: 84 c0                        	testb	%al, %al
   80bb2: 0f 85 ef 02 00 00            	jne	0x80ea7 <.text+0x63cf7>
   80bb8: 4c 89 ff                     	movq	%r15, %rdi
   80bbb: e8 30 8b fe ff               	callq	0x696f0 <.text+0x4c540>
   80bc0: 84 c0                        	testb	%al, %al
   80bc2: 0f 85 18 0a 00 00            	jne	0x815e0 <.text+0x64430>
   80bc8: 81 7c 24 10 6c fe ff ff      	cmpl	$0xfffffe6c, 0x10(%rsp) # imm = 0xFFFFFE6C
   80bd0: 0f 85 da 18 00 00            	jne	0x824b0 <.text+0x65300>
   80bd6: 81 7c 24 18 6c fe ff ff      	cmpl	$0xfffffe6c, 0x18(%rsp) # imm = 0xFFFFFE6C
   80bde: 0f 85 cc 18 00 00            	jne	0x824b0 <.text+0x65300>
   80be4: 49 8b 75 00                  	movq	(%r13), %rsi
   80be8: 8b 06                        	movl	(%rsi), %eax
   80bea: 48 89 b4 24 10 07 00 00      	movq	%rsi, 0x710(%rsp)
   80bf2: 83 c0 01                     	addl	$0x1, %eax
   80bf5: 83 f8 01                     	cmpl	$0x1, %eax
   80bf8: 76 0f                        	jbe	0x80c09 <.text+0x63a59>
   80bfa: f0                           	lock
   80bfb: 83 06 01                     	addl	$0x1, (%rsi)
   80bfe: 0f 95 c0                     	setne	%al
   80c01: 48 8b b4 24 10 07 00 00      	movq	0x710(%rsp), %rsi
   80c09: 8b 56 04                     	movl	0x4(%rsi), %edx
   80c0c: 4c 8d a4 24 40 04 00 00      	leaq	0x440(%rsp), %r12

# Staging: later cp -f pathname command construction and QProcess execution

work/decrypted-eu-260128/extracted-safe/mango-rootfs/app/bin/AppDMClient:	file format elf64-x86-64

Disassembly of section .text:

000000000001d1b0 <.text>:
   828ef: 48 8b 34 24                  	movq	(%rsp), %rsi
   828f3: 48 89 c7                     	movq	%rax, %rdi
   828f6: e8 a5 3f fc ff               	callq	0x468a0 <.text+0x296f0>
   828fb: 48 8b 38                     	movq	(%rax), %rdi
   828fe: e8 0d 9b f9 ff               	callq	0x1c410 <_Z4endlR11QTextStream@plt>
   82903: 48 89 ef                     	movq	%rbp, %rdi
   82906: e8 85 a3 f9 ff               	callq	0x1cc90 <_ZN6QDebugD1Ev@plt>
   8290b: 48 8d ac 24 80 04 00 00      	leaq	0x480(%rsp), %rbp
   82913: 48 8d 35 45 2b 0f 00         	leaq	0xf2b45(%rip), %rsi     # 0x17545f
   8291a: 48 89 ef                     	movq	%rbp, %rdi
   8291d: e8 ae 86 00 00               	callq	0x8afd0 <.text+0x6de20>
   82922: 48 8b 14 24                  	movq	(%rsp), %rdx
   82926: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   8292c: 31 c9                        	xorl	%ecx, %ecx
   8292e: 48 89 ee                     	movq	%rbp, %rsi
   82931: 4c 8d a4 24 90 04 00 00      	leaq	0x490(%rsp), %r12
   82939: 4c 89 e7                     	movq	%r12, %rdi
   8293c: e8 ff 8f f9 ff               	callq	0x1b940 <_ZNK7QString3argERKS_i5QChar@plt>
   82941: 48 8b 54 24 08               	movq	0x8(%rsp), %rdx
   82946: 41 b8 20 00 00 00            	movl	$0x20, %r8d
   8294c: 31 c9                        	xorl	%ecx, %ecx
   8294e: 4c 89 e6                     	movq	%r12, %rsi
   82951: 48 8d 84 24 a0 04 00 00      	leaq	0x4a0(%rsp), %rax
   82959: 48 89 c7                     	movq	%rax, %rdi
   8295c: 48 89 44 24 10               	movq	%rax, 0x10(%rsp)
   82961: e8 da 8f f9 ff               	callq	0x1b940 <_ZNK7QString3argERKS_i5QChar@plt>
   82966: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   8296b: e8 f0 9a f9 ff               	callq	0x1c460 <_ZN8QProcess7executeERK7QString@plt>
   82970: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   82975: e8 56 dd fa ff               	callq	0x306d0 <.text+0x13520>
   8297a: 4c 89 e7                     	movq	%r12, %rdi
   8297d: e8 4e dd fa ff               	callq	0x306d0 <.text+0x13520>
   82982: 48 89 ef                     	movq	%rbp, %rdi
   82985: e8 46 dd fa ff               	callq	0x306d0 <.text+0x13520>
   8298a: e9 df e3 ff ff               	jmp	0x80d6e <.text+0x63bbe>
   8298f: 90                           	nop

# XML reader: separate verifier-wrapper call

work/decrypted-eu-260128/extracted-safe/mango-rootfs/app/bin/AppDMClient:	file format elf64-x86-64

Disassembly of section .text:

000000000001d1b0 <.text>:
   e1fbe: 48 89 c7                     	movq	%rax, %rdi
   e1fc1: 49 89 c4                     	movq	%rax, %r12
   e1fc4: e8 e7 ae f3 ff               	callq	0x1ceb0 <_ZN12QDomDocumentC1Ev@plt>
   e1fc9: 48 8b 44 24 50               	movq	0x50(%rsp), %rax
   e1fce: 8b 08                        	movl	(%rax), %ecx
   e1fd0: 48 89 84 24 20 02 00 00      	movq	%rax, 0x220(%rsp)
   e1fd8: 8d 51 01                     	leal	0x1(%rcx), %edx
   e1fdb: 83 fa 01                     	cmpl	$0x1, %edx
   e1fde: 76 07                        	jbe	0xe1fe7 <.text+0xc4e37>
   e1fe0: f0                           	lock
   e1fe1: 83 00 01                     	addl	$0x1, (%rax)
   e1fe4: 0f 95 c2                     	setne	%dl
   e1fe7: e8 04 92 fa ff               	callq	0x8b1f0 <.text+0x6e040>
   e1fec: 4c 8b 74 24 18               	movq	0x18(%rsp), %r14
   e1ff1: 48 89 c7                     	movq	%rax, %rdi
   e1ff4: 4c 89 f6                     	movq	%r14, %rsi
   e1ff7: e8 74 28 f5 ff               	callq	0x34870 <.text+0x176c0>
   e1ffc: 89 c3                        	movl	%eax, %ebx
   e1ffe: 4c 89 f7                     	movq	%r14, %rdi
   e2001: e8 ca e6 f4 ff               	callq	0x306d0 <.text+0x13520>
   e2006: 85 db                        	testl	%ebx, %ebx
   e2008: 0f 85 aa 02 00 00            	jne	0xe22b8 <.text+0xc5108>
   e200e: 48 8d 05 6b ce 33 00         	leaq	0x33ce6b(%rip), %rax    # 0x41ee80 <_ZN10QArrayData11shared_nullE>
   e2015: 4c 89 f6                     	movq	%r14, %rsi
   e2018: c7 84 24 20 02 00 00 02 00 00 00     	movl	$0x2, 0x220(%rsp)
   e2023: 48 89 84 24 b0 01 00 00      	movq	%rax, 0x1b0(%rsp)
   e202b: 48 8d 5c 24 60               	leaq	0x60(%rsp), %rbx

# XML reader direct branch: later QFile construction/open and QDomDocument parse

work/decrypted-eu-260128/extracted-safe/mango-rootfs/app/bin/AppDMClient:	file format elf64-x86-64

Disassembly of section .text:

000000000001d1b0 <.text>:
   e2280: 48 8d 35 d3 33 09 00         	leaq	0x933d3(%rip), %rsi     # 0x17565a
   e2287: 48 89 c7                     	movq	%rax, %rdi
   e228a: e8 91 ee f4 ff               	callq	0x31120 <.text+0x13f70>
   e228f: 48 8d 9c 24 b0 01 00 00      	leaq	0x1b0(%rsp), %rbx
   e2297: 48 89 ef                     	movq	%rbp, %rdi
   e229a: e8 f1 a9 f3 ff               	callq	0x1cc90 <_ZN6QDebugD1Ev@plt>
   e229f: 4c 89 ef                     	movq	%r13, %rdi
   e22a2: e8 29 e4 f4 ff               	callq	0x306d0 <.text+0x13520>
   e22a7: 48 89 df                     	movq	%rbx, %rdi
   e22aa: e8 11 ed f4 ff               	callq	0x30fc0 <.text+0x13e10>
   e22af: e9 02 01 00 00               	jmp	0xe23b6 <.text+0xc5206>
   e22b4: 0f 1f 40 00                  	nopl	(%rax)
   e22b8: 4c 8d 74 24 50               	leaq	0x50(%rsp), %r14
   e22bd: 4c 89 ff                     	movq	%r15, %rdi
   e22c0: 4c 89 f6                     	movq	%r14, %rsi
   e22c3: 4c 89 74 24 10               	movq	%r14, 0x10(%rsp)
   e22c8: e8 43 97 f3 ff               	callq	0x1ba10 <_ZN5QFileC1ERK7QString@plt>
   e22cd: be 01 00 00 00               	movl	$0x1, %esi
   e22d2: 4c 89 ff                     	movq	%r15, %rdi
   e22d5: e8 46 92 f3 ff               	callq	0x1b520 <_ZN5QFile4openE6QFlagsIN9QIODevice12OpenModeFlagEE@plt>
   e22da: 84 c0                        	testb	%al, %al
   e22dc: 0f 85 0e 01 00 00            	jne	0xe23f0 <.text+0xc5240>
   e22e2: 48 8b 74 24 18               	movq	0x18(%rsp), %rsi
   e22e7: 48 8d 9c 24 30 01 00 00      	leaq	0x130(%rsp), %rbx
   e22ef: c7 84 24 20 02 00 00 02 00 00 00     	movl	$0x2, 0x220(%rsp)
   e22fa: 48 8d 05 e3 00 09 00         	leaq	0x900e3(%rip), %rax     # 0x1723e4
   e2301: 48 89 df                     	movq	%rbx, %rdi
   e2304: c7 84 24 24 02 00 00 00 00 00 00     	movl	$0x0, 0x224(%rsp)
   e230f: 48 c7 84 24 28 02 00 00 00 00 00 00  	movq	$0x0, 0x228(%rsp)
   e231b: 48 c7 84 24 30 02 00 00 00 00 00 00  	movq	$0x0, 0x230(%rsp)
   e2327: 48 89 84 24 38 02 00 00      	movq	%rax, 0x238(%rsp)
   e232f: e8 ac a4 f3 ff               	callq	0x1c7e0 <_ZNK14QMessageLogger5debugEv@plt>
   e2334: 48 8d 35 84 16 09 00         	leaq	0x91684(%rip), %rsi     # 0x1739bf
   e233b: 48 89 df                     	movq	%rbx, %rdi
   e233e: e8 dd ed f4 ff               	callq	0x31120 <.text+0x13f70>
   e2343: 48 8d 35 c1 2f 09 00         	leaq	0x92fc1(%rip), %rsi     # 0x17530b
   e234a: 48 89 c7                     	movq	%rax, %rdi
   e234d: e8 ce ed f4 ff               	callq	0x31120 <.text+0x13f70>
   e2352: 48 8d 35 07 3a 0a 00         	leaq	0xa3a07(%rip), %rsi     # 0x185d60
   e2359: 48 89 c7                     	movq	%rax, %rdi
   e235c: e8 bf ed f4 ff               	callq	0x31120 <.text+0x13f70>
   e2361: 48 8d 35 a1 02 09 00         	leaq	0x902a1(%rip), %rsi     # 0x172609
   e2368: 48 89 c7                     	movq	%rax, %rdi
   e236b: e8 b0 ed f4 ff               	callq	0x31120 <.text+0x13f70>
   e2370: be a0 08 00 00               	movl	$0x8a0, %esi            # imm = 0x8A0
   e2375: 48 89 c7                     	movq	%rax, %rdi
   e2378: e8 c3 44 f6 ff               	callq	0x46840 <.text+0x29690>
   e237d: 48 8d 35 a7 19 09 00         	leaq	0x919a7(%rip), %rsi     # 0x173d2b
   e2384: 48 89 c7                     	movq	%rax, %rdi
   e2387: e8 94 ed f4 ff               	callq	0x31120 <.text+0x13f70>
   e238c: 48 8d 35 62 21 0a 00         	leaq	0xa2162(%rip), %rsi     # 0x1844f5
   e2393: 48 89 c7                     	movq	%rax, %rdi
   e2396: e8 85 ed f4 ff               	callq	0x31120 <.text+0x13f70>
   e239b: 4c 89 f6                     	movq	%r14, %rsi
   e239e: 48 89 c7                     	movq	%rax, %rdi
   e23a1: e8 fa 44 f6 ff               	callq	0x468a0 <.text+0x296f0>
   e23a6: 48 89 df                     	movq	%rbx, %rdi
   e23a9: e8 e2 a8 f3 ff               	callq	0x1cc90 <_ZN6QDebugD1Ev@plt>
   e23ae: 4c 89 ff                     	movq	%r15, %rdi
   e23b1: e8 ca 95 f3 ff               	callq	0x1b980 <_ZN5QFileD1Ev@plt>
   e23b6: 48 8b 7c 24 10               	movq	0x10(%rsp), %rdi
   e23bb: e8 10 e3 f4 ff               	callq	0x306d0 <.text+0x13520>
   e23c0: 48 8b 44 24 28               	movq	0x28(%rsp), %rax
   e23c5: 48 8b 8c 24 48 02 00 00      	movq	0x248(%rsp), %rcx
   e23cd: 64 48 33 0c 25 28 00 00 00   	xorq	%fs:0x28, %rcx
   e23d6: 0f 85 d3 09 00 00            	jne	0xe2daf <.text+0xc5bff>
   e23dc: 48 81 c4 58 02 00 00         	addq	$0x258, %rsp            # imm = 0x258
   e23e3: 5b                           	popq	%rbx
   e23e4: 5d                           	popq	%rbp
   e23e5: 41 5c                        	popq	%r12
   e23e7: 41 5d                        	popq	%r13
   e23e9: 41 5e                        	popq	%r14
   e23eb: 41 5f                        	popq	%r15
   e23ed: c3                           	retq
   e23ee: 66 90                        	nop
   e23f0: 45 31 c0                     	xorl	%r8d, %r8d
   e23f3: 31 c9                        	xorl	%ecx, %ecx
   e23f5: 31 d2                        	xorl	%edx, %edx
   e23f7: 4c 89 fe                     	movq	%r15, %rsi
   e23fa: 4c 89 e7                     	movq	%r12, %rdi
   e23fd: e8 9e 94 f3 ff               	callq	0x1b8a0 <_ZN12QDomDocument10setContentEP9QIODeviceP7QStringPiS4_@plt>
   e2402: 4c 89 ff                     	movq	%r15, %rdi
   e2405: 84 c0                        	testb	%al, %al
   e2407: 0f 84 83 05 00 00            	je	0xe2990 <.text+0xc57e0>
   e240d: e8 4e 8b f3 ff               	callq	0x1af60 <_ZN11QFileDevice5closeEv@plt>
   e2412: 4c 89 ff                     	movq	%r15, %rdi
   e2415: e8 66 95 f3 ff               	callq	0x1b980 <_ZN5QFileD1Ev@plt>
   e241a: 48 8d 84 24 50 01 00 00      	leaq	0x150(%rsp), %rax

# XML reader encrypted branch: later pathname command, system, temporary QFile open, and QByteArray parse

work/decrypted-eu-260128/extracted-safe/mango-rootfs/app/bin/AppDMClient:	file format elf64-x86-64

Disassembly of section .text:

000000000001d1b0 <.text>:
   e2760: e8 6b df f4 ff               	callq	0x306d0 <.text+0x13520>
   e2765: 48 8b 7c 24 30               	movq	0x30(%rsp), %rdi
   e276a: e8 61 df f4 ff               	callq	0x306d0 <.text+0x13520>
   e276f: 48 89 df                     	movq	%rbx, %rdi
   e2772: e8 59 df f4 ff               	callq	0x306d0 <.text+0x13520>
   e2777: 48 8b b4 24 00 02 00 00      	movq	0x200(%rsp), %rsi
   e277f: 8b 06                        	movl	(%rsi), %eax
   e2781: 48 89 b4 24 20 02 00 00      	movq	%rsi, 0x220(%rsp)
   e2789: 83 c0 01                     	addl	$0x1, %eax
   e278c: 83 f8 01                     	cmpl	$0x1, %eax
   e278f: 76 0f                        	jbe	0xe27a0 <.text+0xc55f0>
   e2791: f0                           	lock
   e2792: 83 06 01                     	addl	$0x1, (%rsi)
   e2795: 0f 95 c0                     	setne	%al
   e2798: 48 8b b4 24 20 02 00 00      	movq	0x220(%rsp), %rsi
   e27a0: 8b 56 04                     	movl	0x4(%rsi), %edx
   e27a3: 48 8d 9c 24 f0 00 00 00      	leaq	0xf0(%rsp), %rbx
   e27ab: 48 03 76 10                  	addq	0x10(%rsi), %rsi
   e27af: 48 89 df                     	movq	%rbx, %rdi
   e27b2: e8 c9 8b f3 ff               	callq	0x1b380 <_ZN7QString18toLocal8Bit_helperEPK5QChari@plt>
   e27b7: 48 8b bc 24 f0 00 00 00      	movq	0xf0(%rsp), %rdi
   e27bf: 48 03 7f 10                  	addq	0x10(%rdi), %rdi
   e27c3: e8 78 a9 f3 ff               	callq	0x1d140 <system@plt>
   e27c8: 48 89 df                     	movq	%rbx, %rdi
   e27cb: e8 f0 e7 f4 ff               	callq	0x30fc0 <.text+0x13e10>
   e27d0: 48 8b 5c 24 18               	movq	0x18(%rsp), %rbx
   e27d5: 48 89 df                     	movq	%rbx, %rdi
   e27d8: e8 f3 de f4 ff               	callq	0x306d0 <.text+0x13520>
   e27dd: 4c 89 ee                     	movq	%r13, %rsi
   e27e0: 48 89 df                     	movq	%rbx, %rdi
   e27e3: e8 28 92 f3 ff               	callq	0x1ba10 <_ZN5QFileC1ERK7QString@plt>
   e27e8: 48 89 df                     	movq	%rbx, %rdi
   e27eb: e8 30 9b f3 ff               	callq	0x1c320 <_ZN5QFile6removeEv@plt>
   e27f0: 48 89 df                     	movq	%rbx, %rdi
   e27f3: 48 89 5c 24 18               	movq	%rbx, 0x18(%rsp)
   e27f8: e8 83 91 f3 ff               	callq	0x1b980 <_ZN5QFileD1Ev@plt>
   e27fd: e8 3e 98 f3 ff               	callq	0x1c040 <sync@plt>
   e2802: 48 8b 74 24 08               	movq	0x8(%rsp), %rsi
   e2807: 4c 89 ff                     	movq	%r15, %rdi
   e280a: e8 01 92 f3 ff               	callq	0x1ba10 <_ZN5QFileC1ERK7QString@plt>
   e280f: 48 8d 9c 24 b0 01 00 00      	leaq	0x1b0(%rsp), %rbx
   e2817: be 01 00 00 00               	movl	$0x1, %esi
   e281c: 4c 89 ff                     	movq	%r15, %rdi
   e281f: e8 fc 8c f3 ff               	callq	0x1b520 <_ZN5QFile4openE6QFlagsIN9QIODevice12OpenModeFlagEE@plt>
   e2824: 84 c0                        	testb	%al, %al
   e2826: 0f 84 34 02 00 00            	je	0xe2a60 <.text+0xc58b0>
   e282c: 48 8d ac 24 10 01 00 00      	leaq	0x110(%rsp), %rbp
   e2834: 4c 89 fe                     	movq	%r15, %rsi
   e2837: 48 8d 9c 24 b0 01 00 00      	leaq	0x1b0(%rsp), %rbx
   e283f: 48 89 ef                     	movq	%rbp, %rdi
   e2842: e8 c9 a2 f3 ff               	callq	0x1cb10 <_ZN9QIODevice7readAllEv@plt>
   e2847: 48 8d 9c 24 b0 01 00 00      	leaq	0x1b0(%rsp), %rbx
   e284f: 48 89 ee                     	movq	%rbp, %rsi
   e2852: 48 89 df                     	movq	%rbx, %rdi
   e2855: e8 26 9d f3 ff               	callq	0x1c580 <_ZN10QByteArray6appendERKS_@plt>
   e285a: 48 89 ef                     	movq	%rbp, %rdi
   e285d: e8 5e e7 f4 ff               	callq	0x30fc0 <.text+0x13e10>
   e2862: 4c 89 ff                     	movq	%r15, %rdi
   e2865: e8 f6 86 f3 ff               	callq	0x1af60 <_ZN11QFileDevice5closeEv@plt>
   e286a: 4c 89 ff                     	movq	%r15, %rdi
   e286d: e8 ae 9a f3 ff               	callq	0x1c320 <_ZN5QFile6removeEv@plt>
   e2872: 45 31 c0                     	xorl	%r8d, %r8d
   e2875: 31 c9                        	xorl	%ecx, %ecx
   e2877: 31 d2                        	xorl	%edx, %edx
   e2879: 48 89 de                     	movq	%rbx, %rsi
   e287c: 4c 89 e7                     	movq	%r12, %rdi
   e287f: e8 7c 91 f3 ff               	callq	0x1ba00 <_ZN12QDomDocument10setContentERK10QByteArrayP7QStringPiS5_@plt>
   e2884: 84 c0                        	testb	%al, %al
   e2886: 0f 85 bc 02 00 00            	jne	0xe2b48 <.text+0xc5998>
   e288c: 48 8b 74 24 18               	movq	0x18(%rsp), %rsi
   e2891: 48 8d ac 24 20 01 00 00      	leaq	0x120(%rsp), %rbp
   e2899: c7 84 24 20 02 00 00 02 00 00 00     	movl	$0x2, 0x220(%rsp)
   e28a4: 48 8d 05 39 fb 08 00         	leaq	0x8fb39(%rip), %rax     # 0x1723e4
   e28ab: 48 89 ef                     	movq	%rbp, %rdi
   e28ae: c7 84 24 24 02 00 00 00 00 00 00     	movl	$0x0, 0x224(%rsp)
