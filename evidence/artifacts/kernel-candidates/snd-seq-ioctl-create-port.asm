
work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko:	file format elf64-x86-64

Disassembly of section .text:

0000000000000f91 <snd_seq_ioctl_create_port>:
     f91: 55                           	push	rbp
     f92: ba a8 00 00 00               	mov	edx, 0xa8
     f97: 48 89 e5                     	mov	rbp, rsp
     f9a: 41 55                        	push	r13
     f9c: 41 54                        	push	r12
     f9e: 53                           	push	rbx
     f9f: 49 89 fc                     	mov	r12, rdi
     fa2: 48 8d bd 30 ff ff ff         	lea	rdi, [rbp - 0xd0]
     fa9: 49 89 f5                     	mov	r13, rsi
     fac: 48 81 ec b8 00 00 00         	sub	rsp, 0xb8
     fb3: 65 48 8b 04 25 28 00 00 00   	mov	rax, qword ptr gs:[0x28]
     fbc: 48 89 45 d8                  	mov	qword ptr [rbp - 0x28], rax
     fc0: 31 c0                        	xor	eax, eax
     fc2: e8 d6 f2 ff ff               	call	0x29d <copy_from_user>
     fc7: 48 85 c0                     	test	rax, rax
     fca: 74 0a                        	je	0xfd6 <snd_seq_ioctl_create_port+0x45>
     fcc: b8 f2 ff ff ff               	mov	eax, 0xfffffff2
     fd1: e9 10 01 00 00               	jmp	0x10e6 <snd_seq_ioctl_create_port+0x155>
     fd6: 0f b6 95 30 ff ff ff         	movzx	edx, byte ptr [rbp - 0xd0]
     fdd: 83 c8 ff                     	or	eax, -0x1
     fe0: 41 3b 54 24 48               	cmp	edx, dword ptr [r12 + 0x48]
     fe5: 0f 85 fb 00 00 00            	jne	0x10e6 <snd_seq_ioctl_create_port+0x155>
     feb: f6 45 98 01                  	test	byte ptr [rbp - 0x68], 0x1
     fef: 89 c6                        	mov	esi, eax
     ff1: 74 07                        	je	0xffa <snd_seq_ioctl_create_port+0x69>
     ff3: 0f b6 b5 31 ff ff ff         	movzx	esi, byte ptr [rbp - 0xcf]
     ffa: 4c 89 e7                     	mov	rdi, r12
     ffd: e8 00 00 00 00               	call	0x1002 <snd_seq_ioctl_create_port+0x71>
		0000000000000ffe:  R_X86_64_PC32	snd_seq_create_port-0x4
    1002: 48 89 c3                     	mov	rbx, rax
    1005: b8 f4 ff ff ff               	mov	eax, 0xfffffff4
    100a: 48 85 db                     	test	rbx, rbx
    100d: 0f 84 d3 00 00 00            	je	0x10e6 <snd_seq_ioctl_create_port+0x155>
    1013: 41 8b 04 24                  	mov	eax, dword ptr [r12]
    1017: 83 f8 01                     	cmp	eax, 0x1
    101a: 75 1d                        	jne	0x1039 <snd_seq_ioctl_create_port+0xa8>
    101c: 48 83 7d 90 00               	cmp	qword ptr [rbp - 0x70], 0x0
    1021: 74 7d                        	je	0x10a0 <snd_seq_ioctl_create_port+0x10f>
    1023: 0f b6 73 01                  	movzx	esi, byte ptr [rbx + 0x1]
    1027: 4c 89 e7                     	mov	rdi, r12
    102a: e8 00 00 00 00               	call	0x102f <snd_seq_ioctl_create_port+0x9e>
		000000000000102b:  R_X86_64_PC32	snd_seq_delete_port-0x4
    102f: b8 ea ff ff ff               	mov	eax, 0xffffffea
    1034: e9 ad 00 00 00               	jmp	0x10e6 <snd_seq_ioctl_create_port+0x155>
    1039: 83 f8 02                     	cmp	eax, 0x2
    103c: 75 62                        	jne	0x10a0 <snd_seq_ioctl_create_port+0x10f>
    103e: 48 8b 45 90                  	mov	rax, qword ptr [rbp - 0x70]
    1042: 48 85 c0                     	test	rax, rax
    1045: 74 59                        	je	0x10a0 <snd_seq_ioctl_create_port+0x10f>
    1047: 48 8b 10                     	mov	rdx, qword ptr [rax]
    104a: 48 85 d2                     	test	rdx, rdx
    104d: 74 04                        	je	0x1053 <snd_seq_ioctl_create_port+0xc2>
    104f: 48 89 53 08                  	mov	qword ptr [rbx + 0x8], rdx
    1053: 48 8b 50 08                  	mov	rdx, qword ptr [rax + 0x8]
    1057: 48 89 93 28 01 00 00         	mov	qword ptr [rbx + 0x128], rdx
    105e: 48 8b 50 38                  	mov	rdx, qword ptr [rax + 0x38]
    1062: 48 89 93 20 01 00 00         	mov	qword ptr [rbx + 0x120], rdx
    1069: 48 8b 50 30                  	mov	rdx, qword ptr [rax + 0x30]
    106d: 48 89 93 18 01 00 00         	mov	qword ptr [rbx + 0x118], rdx
    1074: 48 8b 50 10                  	mov	rdx, qword ptr [rax + 0x10]
    1078: 48 89 93 b0 00 00 00         	mov	qword ptr [rbx + 0xb0], rdx
    107f: 48 8b 50 18                  	mov	rdx, qword ptr [rax + 0x18]
    1083: 48 89 93 b8 00 00 00         	mov	qword ptr [rbx + 0xb8], rdx
    108a: 48 8b 50 20                  	mov	rdx, qword ptr [rax + 0x20]
    108e: 48 89 93 08 01 00 00         	mov	qword ptr [rbx + 0x108], rdx
    1095: 48 8b 40 28                  	mov	rax, qword ptr [rax + 0x28]
    1099: 48 89 83 10 01 00 00         	mov	qword ptr [rbx + 0x110], rax
    10a0: 8b 03                        	mov	eax, dword ptr [rbx]
    10a2: 48 8d b5 30 ff ff ff         	lea	rsi, [rbp - 0xd0]
    10a9: 48 89 df                     	mov	rdi, rbx
    10ac: 66 89 85 30 ff ff ff         	mov	word ptr [rbp - 0xd0], ax
    10b3: e8 00 00 00 00               	call	0x10b8 <snd_seq_ioctl_create_port+0x127>
		00000000000010b4:  R_X86_64_PC32	snd_seq_set_port_info-0x4
    10b8: 0f b6 73 01                  	movzx	esi, byte ptr [rbx + 0x1]
    10bc: 0f b6 3b                     	movzx	edi, byte ptr [rbx]
    10bf: ba 3f 00 00 00               	mov	edx, 0x3f
    10c4: e8 00 00 00 00               	call	0x10c9 <snd_seq_ioctl_create_port+0x138>
		00000000000010c5:  R_X86_64_PC32	snd_seq_system_broadcast-0x4
    10c9: 48 8d b5 30 ff ff ff         	lea	rsi, [rbp - 0xd0]
    10d0: ba a8 00 00 00               	mov	edx, 0xa8
    10d5: 4c 89 ef                     	mov	rdi, r13
    10d8: e8 52 f2 ff ff               	call	0x32f <copy_to_user>
    10dd: 48 85 c0                     	test	rax, rax
    10e0: 0f 85 e6 fe ff ff            	jne	0xfcc <snd_seq_ioctl_create_port+0x3b>
    10e6: 48 8b 4d d8                  	mov	rcx, qword ptr [rbp - 0x28]
    10ea: 65 48 33 0c 25 28 00 00 00   	xor	rcx, qword ptr gs:[0x28]
    10f3: 74 05                        	je	0x10fa <snd_seq_ioctl_create_port+0x169>
    10f5: e8 00 00 00 00               	call	0x10fa <snd_seq_ioctl_create_port+0x169>
		00000000000010f6:  R_X86_64_PC32	__stack_chk_fail-0x4
    10fa: 48 81 c4 b8 00 00 00         	add	rsp, 0xb8
    1101: 5b                           	pop	rbx
    1102: 41 5c                        	pop	r12
    1104: 41 5d                        	pop	r13
    1106: 5d                           	pop	rbp
    1107: c3                           	ret

0000000000001108 <snd_seq_ioctl_system_info>:
    1108: 55                           	push	rbp
    1109: b9 0c 00 00 00               	mov	ecx, 0xc
    110e: 48 89 e5                     	mov	rbp, rsp
    1111: 41 54                        	push	r12
    1113: 53                           	push	rbx
    1114: 48 8d 5d b8                  	lea	rbx, [rbp - 0x48]
    1118: 49 89 f4                     	mov	r12, rsi
    111b: 48 83 ec 40                  	sub	rsp, 0x40
    111f: 65 48 8b 04 25 28 00 00 00   	mov	rax, qword ptr gs:[0x28]
    1128: 48 89 45 e8                  	mov	qword ptr [rbp - 0x18], rax
    112c: 31 c0                        	xor	eax, eax
    112e: 48 89 df                     	mov	rdi, rbx
    1131: f3 ab                        	rep		stosd	dword ptr es:[rdi], eax
    1133: 8b 05 00 00 00 00            	mov	eax, dword ptr [rip]    # 0x1139 <snd_seq_ioctl_system_info+0x31>
		0000000000001135:  R_X86_64_PC32	.bss+0x2e4
    1139: c7 45 b8 20 00 00 00         	mov	dword ptr [rbp - 0x48], 0x20
    1140: c7 45 bc c0 00 00 00         	mov	dword ptr [rbp - 0x44], 0xc0
    1147: c7 45 c0 fe 00 00 00         	mov	dword ptr [rbp - 0x40], 0xfe
    114e: c7 45 c4 00 01 00 00         	mov	dword ptr [rbp - 0x3c], 0x100
    1155: 89 45 c8                     	mov	dword ptr [rbp - 0x38], eax
    1158: e8 00 00 00 00               	call	0x115d <snd_seq_ioctl_system_info+0x55>
		0000000000001159:  R_X86_64_PC32	snd_seq_queue_get_cur_queues-0x4
    115d: ba 30 00 00 00               	mov	edx, 0x30
    1162: 48 89 de                     	mov	rsi, rbx
    1165: 4c 89 e7                     	mov	rdi, r12
    1168: 89 45 cc                     	mov	dword ptr [rbp - 0x34], eax
    116b: e8 bf f1 ff ff               	call	0x32f <copy_to_user>
    1170: 48 83 f8 01                  	cmp	rax, 0x1
    1174: 19 c0                        	sbb	eax, eax
    1176: f7 d0                        	not	eax
    1178: 83 e0 f2                     	and	eax, -0xe
    117b: 48 8b 55 e8                  	mov	rdx, qword ptr [rbp - 0x18]
    117f: 65 48 33 14 25 28 00 00 00   	xor	rdx, qword ptr gs:[0x28]
    1188: 74 05                        	je	0x118f <snd_seq_ioctl_system_info+0x87>
    118a: e8 00 00 00 00               	call	0x118f <snd_seq_ioctl_system_info+0x87>
		000000000000118b:  R_X86_64_PC32	__stack_chk_fail-0x4
    118f: 48 83 c4 40                  	add	rsp, 0x40
    1193: 5b                           	pop	rbx
    1194: 41 5c                        	pop	r12
    1196: 5d                           	pop	rbp
    1197: c3                           	ret

0000000000001198 <snd_seq_info_dump_subscribers>:
    1198: 55                           	push	rbp
    1199: 48 8d 46 18                  	lea	rax, [rsi + 0x18]
    119d: 48 89 e5                     	mov	rbp, rsp
    11a0: 41 57                        	push	r15
    11a2: 41 56                        	push	r14
    11a4: 41 55                        	push	r13
    11a6: 41 54                        	push	r12
    11a8: 49 89 f4                     	mov	r12, rsi
    11ab: 53                           	push	rbx
    11ac: 48 89 fb                     	mov	rbx, rdi
    11af: 48 89 c7                     	mov	rdi, rax
    11b2: 41 89 d7                     	mov	r15d, edx
    11b5: 49 89 cd                     	mov	r13, rcx
    11b8: 48 83 ec 18                  	sub	rsp, 0x18
    11bc: 48 89 45 c8                  	mov	qword ptr [rbp - 0x38], rax
    11c0: e8 00 00 00 00               	call	0x11c5 <snd_seq_info_dump_subscribers+0x2d>
		00000000000011c1:  R_X86_64_PC32	down_read-0x4
    11c5: 4d 3b 24 24                  	cmp	r12, qword ptr [r12]
    11c9: 75 0e                        	jne	0x11d9 <snd_seq_info_dump_subscribers+0x41>
    11cb: 48 8b 7d c8                  	mov	rdi, qword ptr [rbp - 0x38]
    11cf: e8 00 00 00 00               	call	0x11d4 <snd_seq_info_dump_subscribers+0x3c>
		00000000000011d0:  R_X86_64_PC32	up_read-0x4
    11d4: e9 dd 00 00 00               	jmp	0x12b6 <snd_seq_info_dump_subscribers+0x11e>
    11d9: 4c 89 ee                     	mov	rsi, r13
    11dc: 48 89 df                     	mov	rdi, rbx
    11df: 31 c0                        	xor	eax, eax
    11e1: e8 00 00 00 00               	call	0x11e6 <snd_seq_info_dump_subscribers+0x4e>
		00000000000011e2:  R_X86_64_PC32	snd_iprintf-0x4
    11e6: 4d 8b 2c 24                  	mov	r13, qword ptr [r12]
    11ea: c7 45 c4 00 00 00 00         	mov	dword ptr [rbp - 0x3c], 0x0
    11f1: 4d 39 e5                     	cmp	r13, r12
    11f4: 0f 84 a2 00 00 00            	je	0x129c <snd_seq_info_dump_subscribers+0x104>
    11fa: 4d 8d 75 a0                  	lea	r14, [r13 - 0x60]
    11fe: 49 8d 45 b0                  	lea	rax, [r13 - 0x50]
