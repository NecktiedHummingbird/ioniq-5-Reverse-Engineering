
work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/snd-pcm.ko:	file format elf64-x86-64

Disassembly of section .text:

0000000000000c6c <snd_pcm_control_ioctl>:
     c6c: 55                           	push	rbp
     c6d: 81 fa 30 55 04 80            	cmp	edx, 0x80045530
     c73: 48 89 e5                     	mov	rbp, rsp
     c76: 41 57                        	push	r15
     c78: 41 56                        	push	r14
     c7a: 49 89 fe                     	mov	r14, rdi
     c7d: 41 55                        	push	r13
     c7f: 41 54                        	push	r12
     c81: 49 89 cc                     	mov	r12, rcx
     c84: 53                           	push	rbx
     c85: 41 50                        	push	r8
     c87: 74 22                        	je	0xcab <snd_pcm_control_ioctl+0x3f>
     c89: 81 fa 31 55 20 c1            	cmp	edx, 0xc1205531
     c8f: 0f 84 a2 00 00 00            	je	0xd37 <snd_pcm_control_ioctl+0xcb>
     c95: 81 fa 32 55 04 40            	cmp	edx, 0x40045532
     c9b: b8 fd fd ff ff               	mov	eax, 0xfffffdfd
     ca0: 0f 85 cc 01 00 00            	jne	0xe72 <snd_pcm_control_ioctl+0x206>
     ca6: e9 83 01 00 00               	jmp	0xe2e <snd_pcm_control_ioctl+0x1c2>
     cab: e8 00 00 00 00               	call	0xcb0 <snd_pcm_control_ioctl+0x44>
		0000000000000cac:  R_X86_64_PC32	might_fault-0x4
     cb0: 4c 89 e0                     	mov	rax, r12
     cb3: e8 00 00 00 00               	call	0xcb8 <snd_pcm_control_ioctl+0x4c>
		0000000000000cb4:  R_X86_64_PC32	__get_user_4-0x4
     cb8: 85 c0                        	test	eax, eax
     cba: 89 d3                        	mov	ebx, edx
     cbc: 74 0a                        	je	0xcc8 <snd_pcm_control_ioctl+0x5c>
     cbe: b8 f2 ff ff ff               	mov	eax, 0xfffffff2
     cc3: e9 aa 01 00 00               	jmp	0xe72 <snd_pcm_control_ioctl+0x206>
     cc8: 48 c7 c7 00 00 00 00         	mov	rdi, 0x0
		0000000000000ccb:  R_X86_64_32S	.data+0xa0
     ccf: e8 00 00 00 00               	call	0xcd4 <snd_pcm_control_ioctl+0x68>
		0000000000000cd0:  R_X86_64_PC32	mutex_lock-0x4
     cd4: 48 8b 05 00 00 00 00         	mov	rax, qword ptr [rip]    # 0xcdb <snd_pcm_control_ioctl+0x6f>
		0000000000000cd7:  R_X86_64_PC32	.data+0xdc
     cdb: 48 8d 48 f8                  	lea	rcx, [rax - 0x8]
     cdf: 48 8d 41 08                  	lea	rax, [rcx + 0x8]
     ce3: 48 3d 00 00 00 00            	cmp	rax, 0x0
		0000000000000ce5:  R_X86_64_32S	.data+0xe0
     ce9: 74 22                        	je	0xd0d <snd_pcm_control_ioctl+0xa1>
     ceb: 48 8b 01                     	mov	rax, qword ptr [rcx]
     cee: 49 39 c6                     	cmp	r14, rax
     cf1: 75 09                        	jne	0xcfc <snd_pcm_control_ioctl+0x90>
     cf3: 44 8b 69 18                  	mov	r13d, dword ptr [rcx + 0x18]
     cf7: 44 39 eb                     	cmp	ebx, r13d
     cfa: 7c 15                        	jl	0xd11 <snd_pcm_control_ioctl+0xa5>
     cfc: 41 8b 36                     	mov	esi, dword ptr [r14]
     cff: 39 30                        	cmp	dword ptr [rax], esi
     d01: 7f 0a                        	jg	0xd0d <snd_pcm_control_ioctl+0xa1>
     d03: 48 8b 49 08                  	mov	rcx, qword ptr [rcx + 0x8]
     d07: 48 83 e9 08                  	sub	rcx, 0x8
     d0b: eb d2                        	jmp	0xcdf <snd_pcm_control_ioctl+0x73>
     d0d: 41 83 cd ff                  	or	r13d, -0x1
     d11: 48 c7 c7 00 00 00 00         	mov	rdi, 0x0
		0000000000000d14:  R_X86_64_32S	.data+0xa0
     d18: e8 00 00 00 00               	call	0xd1d <snd_pcm_control_ioctl+0xb1>
		0000000000000d19:  R_X86_64_PC32	mutex_unlock-0x4
     d1d: e8 00 00 00 00               	call	0xd22 <snd_pcm_control_ioctl+0xb6>
		0000000000000d1e:  R_X86_64_PC32	might_fault-0x4
     d22: 44 89 e8                     	mov	eax, r13d
     d25: 4c 89 e1                     	mov	rcx, r12
     d28: e8 00 00 00 00               	call	0xd2d <snd_pcm_control_ioctl+0xc1>
		0000000000000d29:  R_X86_64_PC32	__put_user_4-0x4
     d2d: 85 c0                        	test	eax, eax
     d2f: 0f 84 3d 01 00 00            	je	0xe72 <snd_pcm_control_ioctl+0x206>
     d35: eb 87                        	jmp	0xcbe <snd_pcm_control_ioctl+0x52>
     d37: e8 00 00 00 00               	call	0xd3c <snd_pcm_control_ioctl+0xd0>
		0000000000000d38:  R_X86_64_PC32	might_fault-0x4
     d3c: 4c 89 e0                     	mov	rax, r12
     d3f: e8 00 00 00 00               	call	0xd44 <snd_pcm_control_ioctl+0xd8>
		0000000000000d40:  R_X86_64_PC32	__get_user_4-0x4
     d44: 85 c0                        	test	eax, eax
     d46: 49 89 d5                     	mov	r13, rdx
     d49: 0f 85 6f ff ff ff            	jne	0xcbe <snd_pcm_control_ioctl+0x52>
     d4f: e8 00 00 00 00               	call	0xd54 <snd_pcm_control_ioctl+0xe8>
		0000000000000d50:  R_X86_64_PC32	might_fault-0x4
     d54: 49 8d 44 24 08               	lea	rax, [r12 + 0x8]
     d59: e8 00 00 00 00               	call	0xd5e <snd_pcm_control_ioctl+0xf2>
		0000000000000d5a:  R_X86_64_PC32	__get_user_4-0x4
     d5e: 85 c0                        	test	eax, eax
     d60: 48 89 d3                     	mov	rbx, rdx
     d63: 0f 85 55 ff ff ff            	jne	0xcbe <snd_pcm_control_ioctl+0x52>
     d69: 83 fa 01                     	cmp	edx, 0x1
     d6c: b8 ea ff ff ff               	mov	eax, 0xffffffea
     d71: 0f 87 fb 00 00 00            	ja	0xe72 <snd_pcm_control_ioctl+0x206>
     d77: e8 00 00 00 00               	call	0xd7c <snd_pcm_control_ioctl+0x110>
		0000000000000d78:  R_X86_64_PC32	might_fault-0x4
     d7c: 49 8d 44 24 04               	lea	rax, [r12 + 0x4]
     d81: e8 00 00 00 00               	call	0xd86 <snd_pcm_control_ioctl+0x11a>
		0000000000000d82:  R_X86_64_PC32	__get_user_4-0x4
     d86: 85 c0                        	test	eax, eax
     d88: 49 89 d7                     	mov	r15, rdx
     d8b: 0f 85 2d ff ff ff            	jne	0xcbe <snd_pcm_control_ioctl+0x52>
     d91: 48 c7 c7 00 00 00 00         	mov	rdi, 0x0
		0000000000000d94:  R_X86_64_32S	.data+0xa0
     d98: e8 00 00 00 00               	call	0xd9d <snd_pcm_control_ioctl+0x131>
		0000000000000d99:  R_X86_64_PC32	mutex_lock-0x4
     d9d: 48 8b 05 00 00 00 00         	mov	rax, qword ptr [rip]    # 0xda4 <snd_pcm_control_ioctl+0x138>
		0000000000000da0:  R_X86_64_PC32	.data+0xdc
     da4: 48 8d 78 f8                  	lea	rdi, [rax - 0x8]
     da8: 48 8d 47 08                  	lea	rax, [rdi + 0x8]
     dac: 48 3d 00 00 00 00            	cmp	rax, 0x0
		0000000000000dae:  R_X86_64_32S	.data+0xe0
     db2: 74 63                        	je	0xe17 <snd_pcm_control_ioctl+0x1ab>
     db4: 4c 3b 37                     	cmp	r14, qword ptr [rdi]
     db7: 75 06                        	jne	0xdbf <snd_pcm_control_ioctl+0x153>
     db9: 44 3b 6f 18                  	cmp	r13d, dword ptr [rdi + 0x18]
     dbd: 74 0a                        	je	0xdc9 <snd_pcm_control_ioctl+0x15d>
     dbf: 48 8b 7f 08                  	mov	rdi, qword ptr [rdi + 0x8]
     dc3: 48 83 ef 08                  	sub	rdi, 0x8
     dc7: eb df                        	jmp	0xda8 <snd_pcm_control_ioctl+0x13c>
     dc9: 48 85 ff                     	test	rdi, rdi
     dcc: 41 bd fa ff ff ff            	mov	r13d, 0xfffffffa
     dd2: 74 49                        	je	0xe1d <snd_pcm_control_ioctl+0x1b1>
     dd4: 48 63 db                     	movsxd	rbx, ebx
     dd7: 41 bd fe ff ff ff            	mov	r13d, 0xfffffffe
     ddd: 48 69 db f8 02 00 00         	imul	rbx, rbx, 0x2f8
     de4: 48 01 fb                     	add	rbx, rdi
     de7: 8b 83 c8 00 00 00            	mov	eax, dword ptr [rbx + 0xc8]
     ded: 85 c0                        	test	eax, eax
     def: 74 2c                        	je	0xe1d <snd_pcm_control_ioctl+0x1b1>
     df1: 44 39 f8                     	cmp	eax, r15d
     df4: 41 bd fa ff ff ff            	mov	r13d, 0xfffffffa
     dfa: 76 21                        	jbe	0xe1d <snd_pcm_control_ioctl+0x1b1>
     dfc: 4c 8b ab d0 00 00 00         	mov	r13, qword ptr [rbx + 0xd0]
     e03: 4d 85 ed                     	test	r13, r13
     e06: 74 0f                        	je	0xe17 <snd_pcm_control_ioctl+0x1ab>
     e08: 45 39 7d 18                  	cmp	dword ptr [r13 + 0x18], r15d
     e0c: 74 3d                        	je	0xe4b <snd_pcm_control_ioctl+0x1df>
     e0e: 4d 8b ad 38 01 00 00         	mov	r13, qword ptr [r13 + 0x138]
     e15: eb ec                        	jmp	0xe03 <snd_pcm_control_ioctl+0x197>
     e17: 41 bd fa ff ff ff            	mov	r13d, 0xfffffffa
     e1d: 48 c7 c7 00 00 00 00         	mov	rdi, 0x0
		0000000000000e20:  R_X86_64_32S	.data+0xa0
     e24: e8 00 00 00 00               	call	0xe29 <snd_pcm_control_ioctl+0x1bd>
		0000000000000e25:  R_X86_64_PC32	mutex_unlock-0x4
     e29: 44 89 e8                     	mov	eax, r13d
     e2c: eb 44                        	jmp	0xe72 <snd_pcm_control_ioctl+0x206>
     e2e: 48 89 f3                     	mov	rbx, rsi
     e31: e8 00 00 00 00               	call	0xe36 <snd_pcm_control_ioctl+0x1ca>
		0000000000000e32:  R_X86_64_PC32	might_fault-0x4
     e36: 4c 89 e0                     	mov	rax, r12
     e39: e8 00 00 00 00               	call	0xe3e <snd_pcm_control_ioctl+0x1d2>
		0000000000000e3a:  R_X86_64_PC32	__get_user_4-0x4
     e3e: 85 c0                        	test	eax, eax
     e40: 0f 85 78 fe ff ff            	jne	0xcbe <snd_pcm_control_ioctl+0x52>
     e46: 89 53 20                     	mov	dword ptr [rbx + 0x20], edx
     e49: eb 27                        	jmp	0xe72 <snd_pcm_control_ioctl+0x206>
     e4b: 48 8d 9f a8 06 00 00         	lea	rbx, [rdi + 0x6a8]
     e52: 48 89 df                     	mov	rdi, rbx
     e55: e8 00 00 00 00               	call	0xe5a <snd_pcm_control_ioctl+0x1ee>
		0000000000000e56:  R_X86_64_PC32	mutex_lock-0x4
     e5a: 4c 89 ef                     	mov	rdi, r13
     e5d: 4c 89 e6                     	mov	rsi, r12
     e60: e8 00 00 00 00               	call	0xe65 <snd_pcm_control_ioctl+0x1f9>
		0000000000000e61:  R_X86_64_PC32	snd_pcm_info_user-0x4
     e65: 48 89 df                     	mov	rdi, rbx
     e68: 41 89 c5                     	mov	r13d, eax
     e6b: e8 00 00 00 00               	call	0xe70 <snd_pcm_control_ioctl+0x204>
		0000000000000e6c:  R_X86_64_PC32	mutex_unlock-0x4
     e70: eb ab                        	jmp	0xe1d <snd_pcm_control_ioctl+0x1b1>
     e72: 5a                           	pop	rdx
     e73: 5b                           	pop	rbx
     e74: 41 5c                        	pop	r12
     e76: 41 5d                        	pop	r13
     e78: 41 5e                        	pop	r14
     e7a: 41 5f                        	pop	r15
     e7c: 5d                           	pop	rbp
     e7d: c3                           	ret
