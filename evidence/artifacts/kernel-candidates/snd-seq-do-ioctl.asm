
work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko:	file format elf64-x86-64

Disassembly of section .text:

0000000000001621 <snd_seq_do_ioctl>:
    1621: 55                           	push	rbp
    1622: 48 89 e5                     	mov	rbp, rsp
    1625: 41 54                        	push	r12
    1627: 53                           	push	rbx
    1628: 49 89 d4                     	mov	r12, rdx
    162b: 48 83 ec 10                  	sub	rsp, 0x10
    162f: 81 fe 00 53 04 80            	cmp	esi, 0x80045300
    1635: 74 1a                        	je	0x1651 <snd_seq_do_ioctl+0x30>
    1637: 81 fe 01 53 04 80            	cmp	esi, 0x80045301
    163d: 75 31                        	jne	0x1670 <snd_seq_do_ioctl+0x4f>
    163f: 48 89 7d e8                  	mov	qword ptr [rbp - 0x18], rdi
    1643: e8 00 00 00 00               	call	0x1648 <snd_seq_do_ioctl+0x27>
		0000000000001644:  R_X86_64_PC32	might_fault-0x4
    1648: 48 8b 7d e8                  	mov	rdi, qword ptr [rbp - 0x18]
    164c: 8b 47 48                     	mov	eax, dword ptr [rdi + 0x48]
    164f: eb 0a                        	jmp	0x165b <snd_seq_do_ioctl+0x3a>
    1651: e8 00 00 00 00               	call	0x1656 <snd_seq_do_ioctl+0x35>
		0000000000001652:  R_X86_64_PC32	might_fault-0x4
    1656: b8 01 00 01 00               	mov	eax, 0x10001
    165b: 4c 89 e1                     	mov	rcx, r12
    165e: e8 00 00 00 00               	call	0x1663 <snd_seq_do_ioctl+0x42>
		000000000000165f:  R_X86_64_PC32	__put_user_4-0x4
    1663: 31 db                        	xor	ebx, ebx
    1665: 85 c0                        	test	eax, eax
    1667: 74 5e                        	je	0x16c7 <snd_seq_do_ioctl+0xa6>
    1669: bb f2 ff ff ff               	mov	ebx, 0xfffffff2
    166e: eb 57                        	jmp	0x16c7 <snd_seq_do_ioctl+0xa6>
    1670: 48 85 d2                     	test	rdx, rdx
    1673: 49 c7 c0 00 00 00 00         	mov	r8, 0x0
		0000000000001676:  R_X86_64_32S	.data+0x60
    167a: 74 ed                        	je	0x1669 <snd_seq_do_ioctl+0x48>
    167c: 41 8b 10                     	mov	edx, dword ptr [r8]
    167f: 85 d2                        	test	edx, edx
    1681: 74 15                        	je	0x1698 <snd_seq_do_ioctl+0x77>
    1683: 39 d6                        	cmp	esi, edx
    1685: 75 0b                        	jne	0x1692 <snd_seq_do_ioctl+0x71>
    1687: 4c 89 e6                     	mov	rsi, r12
    168a: 41 ff 50 08                  	call	qword ptr [r8 + 0x8]
    168e: 89 c3                        	mov	ebx, eax
    1690: eb 35                        	jmp	0x16c7 <snd_seq_do_ioctl+0xa6>
    1692: 49 83 c0 10                  	add	r8, 0x10
    1696: eb e4                        	jmp	0x167c <snd_seq_do_ioctl+0x5b>
    1698: f6 05 00 00 00 00 04         	test	byte ptr [rip], 0x4     # 0x169f <snd_seq_do_ioctl+0x7e>
		000000000000169a:  R_X86_64_PC32	__verbose+0x1d
    169f: bb e7 ff ff ff               	mov	ebx, 0xffffffe7
    16a4: 74 21                        	je	0x16c7 <snd_seq_do_ioctl+0xa6>
    16a6: 48 89 f0                     	mov	rax, rsi
    16a9: 44 0f b6 c6                  	movzx	r8d, sil
    16ad: 89 f2                        	mov	edx, esi
    16af: 0f b6 cc                     	movzx	ecx, ah
    16b2: 48 c7 c6 00 00 00 00         	mov	rsi, 0x0
		00000000000016b5:  R_X86_64_32S	.rodata.str1.1+0x1d2
    16b9: 48 c7 c7 00 00 00 00         	mov	rdi, 0x0
		00000000000016bc:  R_X86_64_32S	__verbose
    16c0: 31 c0                        	xor	eax, eax
    16c2: e8 00 00 00 00               	call	0x16c7 <snd_seq_do_ioctl+0xa6>
		00000000000016c3:  R_X86_64_PC32	__dynamic_pr_debug-0x4
    16c7: 5a                           	pop	rdx
    16c8: 89 d8                        	mov	eax, ebx
    16ca: 59                           	pop	rcx
    16cb: 5b                           	pop	rbx
    16cc: 41 5c                        	pop	r12
    16ce: 5d                           	pop	rbp
    16cf: c3                           	ret

00000000000016d0 <snd_seq_kernel_client_ctl>:
    16d0: 55                           	push	rbp
    16d1: 48 89 e5                     	mov	rbp, rsp
    16d4: 41 54                        	push	r12
    16d6: 53                           	push	rbx
    16d7: 48 83 ec 10                  	sub	rsp, 0x10
    16db: 89 75 e4                     	mov	dword ptr [rbp - 0x1c], esi
    16de: 48 89 55 e8                  	mov	qword ptr [rbp - 0x18], rdx
    16e2: e8 ae fe ff ff               	call	0x1595 <clientptr>
    16e7: 48 85 c0                     	test	rax, rax
    16ea: b9 fa ff ff ff               	mov	ecx, 0xfffffffa
    16ef: 74 33                        	je	0x1724 <snd_seq_kernel_client_ctl+0x54>
    16f1: 65 48 8b 1c 25 00 00 00 00   	mov	rbx, qword ptr gs:[0x0]
		00000000000016f6:  R_X86_64_32S	cpu_tss+0x4
    16fa: 48 8b 55 e8                  	mov	rdx, qword ptr [rbp - 0x18]
    16fe: 4c 8b a3 18 c0 ff ff         	mov	r12, qword ptr [rbx - 0x3fe8]
    1705: 48 89 c7                     	mov	rdi, rax
    1708: 8b 75 e4                     	mov	esi, dword ptr [rbp - 0x1c]
    170b: 48 c7 83 18 c0 ff ff ff ff ff ff     	mov	qword ptr [rbx - 0x3fe8], -0x1
    1716: e8 06 ff ff ff               	call	0x1621 <snd_seq_do_ioctl>
    171b: 4c 89 a3 18 c0 ff ff         	mov	qword ptr [rbx - 0x3fe8], r12
    1722: 89 c1                        	mov	ecx, eax
    1724: 5a                           	pop	rdx
    1725: 89 c8                        	mov	eax, ecx
    1727: 59                           	pop	rcx
    1728: 5b                           	pop	rbx
    1729: 41 5c                        	pop	r12
    172b: 5d                           	pop	rbp
    172c: c3                           	ret

000000000000172d <snd_seq_ioctl>:
    172d: 48 8b bf d0 00 00 00         	mov	rdi, qword ptr [rdi + 0xd0]
    1734: 48 85 ff                     	test	rdi, rdi
    1737: 74 0d                        	je	0x1746 <snd_seq_ioctl+0x19>
    1739: 55                           	push	rbp
    173a: 48 89 e5                     	mov	rbp, rsp
    173d: e8 df fe ff ff               	call	0x1621 <snd_seq_do_ioctl>
    1742: 5d                           	pop	rbp
    1743: 48 98                        	cdqe
    1745: c3                           	ret
    1746: 48 c7 c0 fa ff ff ff         	mov	rax, -0x6
    174d: c3                           	ret
