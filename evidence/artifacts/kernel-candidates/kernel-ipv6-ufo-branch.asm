
work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff8151cd2a: 48 8b 45 90          	mov	rax, qword ptr [rbp - 0x70]
ffffffff8151cd2e: 8b 7d 20             	mov	edi, dword ptr [rbp + 0x20]
ffffffff8151cd31: 01 78 14             	add	dword ptr [rax + 0x14], edi
ffffffff8151cd34: 8b 45 a8             	mov	eax, dword ptr [rbp - 0x58]
ffffffff8151cd37: 39 f8                	cmp	eax, edi
ffffffff8151cd39: 72 23                	jb	0xffffffff8151cd5e <.text+0x51cd5e>
ffffffff8151cd3b: 4d 85 f6             	test	r14, r14
ffffffff8151cd3e: 0f 84 e1 01 00 00    	je	0xffffffff8151cf25 <.text+0x51cf25>
ffffffff8151cd44: 41 8b 86 c8 00 00 00 	mov	eax, dword ptr [r14 + 0xc8]
ffffffff8151cd4b: 49 8b 96 d0 00 00 00 	mov	rdx, qword ptr [r14 + 0xd0]
ffffffff8151cd52: 66 83 7c 02 02 00    	cmp	word ptr [rdx + rax + 0x2], 0x0
ffffffff8151cd58: 0f 84 38 05 00 00    	je	0xffffffff8151d296 <.text+0x51d296>
ffffffff8151cd5e: 80 bb 49 01 00 00 11 	cmp	byte ptr [rbx + 0x149], 0x11
ffffffff8151cd65: 0f 85 a9 01 00 00    	jne	0xffffffff8151cf14 <.text+0x51cf14>
ffffffff8151cd6b: 49 8b 47 18          	mov	rax, qword ptr [r15 + 0x18]
ffffffff8151cd6f: f6 80 f2 00 00 00 02 	test	byte ptr [rax + 0xf2], 0x2
ffffffff8151cd76: 0f 84 98 01 00 00    	je	0xffffffff8151cf14 <.text+0x51cf14>
ffffffff8151cd7c: 66 83 bb 4a 01 00 00 02      	cmp	word ptr [rbx + 0x14a], 0x2
ffffffff8151cd84: 0f 85 8a 01 00 00    	jne	0xffffffff8151cf14 <.text+0x51cf14>
ffffffff8151cd8a: f6 83 61 03 00 00 01 	test	byte ptr [rbx + 0x361], 0x1
ffffffff8151cd91: 0f 85 7d 01 00 00    	jne	0xffffffff8151cf14 <.text+0x51cf14>
ffffffff8151cd97: 48 8b 45 98          	mov	rax, qword ptr [rbp - 0x68]
ffffffff8151cd9b: 4c 8b 60 08          	mov	r12, qword ptr [rax + 0x8]
ffffffff8151cd9f: 4d 85 e4             	test	r12, r12
ffffffff8151cda2: 74 09                	je	0xffffffff8151cdad <.text+0x51cdad>
ffffffff8151cda4: 4c 39 e0             	cmp	rax, r12
ffffffff8151cda7: 0f 85 b4 00 00 00    	jne	0xffffffff8151ce61 <.text+0x51ce61>
ffffffff8151cdad: 8b 45 88             	mov	eax, dword ptr [rbp - 0x78]
ffffffff8151cdb0: 03 45 ac             	add	eax, dword ptr [rbp - 0x54]
ffffffff8151cdb3: 48 8d 4d bc          	lea	rcx, [rbp - 0x44]
ffffffff8151cdb7: 8b 7d 28             	mov	edi, dword ptr [rbp + 0x28]
ffffffff8151cdba: 8b 55 30             	mov	edx, dword ptr [rbp + 0x30]
ffffffff8151cdbd: 8d 74 07 14          	lea	esi, [rdi + rax + 0x14]
ffffffff8151cdc1: 83 e2 40             	and	edx, 0x40
ffffffff8151cdc4: 48 89 df             	mov	rdi, rbx
ffffffff8151cdc7: 48 63 f6             	movsxd	rsi, esi
ffffffff8151cdca: e8 c2 ab f5 ff       	call	0xffffffff81477991 <.text+0x477991>
ffffffff8151cdcf: 48 85 c0             	test	rax, rax
ffffffff8151cdd2: 49 89 c4             	mov	r12, rax
ffffffff8151cdd5: 75 08                	jne	0xffffffff8151cddf <.text+0x51cddf>
ffffffff8151cdd7: 8b 45 bc             	mov	eax, dword ptr [rbp - 0x44]
ffffffff8151cdda: e9 23 01 00 00       	jmp	0xffffffff8151cf02 <.text+0x51cf02>
ffffffff8151cddf: 48 63 45 88          	movsxd	rax, dword ptr [rbp - 0x78]
ffffffff8151cde3: 8b 75 ac             	mov	esi, dword ptr [rbp - 0x54]
ffffffff8151cde6: 4c 89 e7             	mov	rdi, r12
ffffffff8151cde9: 49 01 84 24 d8 00 00 00      	add	qword ptr [r12 + 0xd8], rax
ffffffff8151cdf1: 03 75 28             	add	esi, dword ptr [rbp + 0x28]
ffffffff8151cdf4: 8b 45 88             	mov	eax, dword ptr [rbp - 0x78]
ffffffff8151cdf7: 41 01 84 24 c4 00 00 00      	add	dword ptr [r12 + 0xc4], eax
ffffffff8151cdff: e8 fb df f5 ff       	call	0xffffffff8147adff <.text+0x47adff>
ffffffff8151ce04: 49 8b 84 24 d8 00 00 00      	mov	rax, qword ptr [r12 + 0xd8]
ffffffff8151ce0c: 49 2b 84 24 d0 00 00 00      	sub	rax, qword ptr [r12 + 0xd0]
ffffffff8151ce14: 66 41 c7 84 24 bc 00 00 00 86 dd     	mov	word ptr [r12 + 0xbc], 0xdd86
ffffffff8151ce1f: 41 c7 84 24 98 00 00 00 00 00 00 00  	mov	dword ptr [r12 + 0x98], 0x0
ffffffff8151ce2b: 48 8b 7d 98          	mov	rdi, qword ptr [rbp - 0x68]
ffffffff8151ce2f: 66 41 89 84 24 c0 00 00 00   	mov	word ptr [r12 + 0xc0], ax
ffffffff8151ce38: 03 45 ac             	add	eax, dword ptr [rbp - 0x54]
ffffffff8151ce3b: 66 41 89 84 24 be 00 00 00   	mov	word ptr [r12 + 0xbe], ax
ffffffff8151ce44: 48 8b 45 98          	mov	rax, qword ptr [rbp - 0x68]
ffffffff8151ce48: 48 8b 40 08          	mov	rax, qword ptr [rax + 0x8]
ffffffff8151ce4c: 49 89 3c 24          	mov	qword ptr [r12], rdi
ffffffff8151ce50: 49 89 44 24 08       	mov	qword ptr [r12 + 0x8], rax
ffffffff8151ce55: 4c 89 20             	mov	qword ptr [rax], r12
ffffffff8151ce58: 4c 89 67 08          	mov	qword ptr [rdi + 0x8], r12
ffffffff8151ce5c: ff 47 10             	inc	dword ptr [rdi + 0x10]
ffffffff8151ce5f: eb 18                	jmp	0xffffffff8151ce79 <.text+0x51ce79>
ffffffff8151ce61: 41 8b 84 24 c8 00 00 00      	mov	eax, dword ptr [r12 + 0xc8]
ffffffff8151ce69: 49 8b 94 24 d0 00 00 00      	mov	rdx, qword ptr [r12 + 0xd0]
ffffffff8151ce71: 66 83 7c 02 02 00    	cmp	word ptr [rdx + rax + 0x2], 0x0
ffffffff8151ce77: 75 68                	jne	0xffffffff8151cee1 <.text+0x51cee1>
ffffffff8151ce79: 41 80 8c 24 91 00 00 00 06   	or	byte ptr [r12 + 0x91], 0x6
ffffffff8151ce82: 41 8b 94 24 c8 00 00 00      	mov	edx, dword ptr [r12 + 0xc8]
ffffffff8151ce8a: 48 8d 75 c0          	lea	rsi, [rbp - 0x40]
ffffffff8151ce8e: 8b 45 a8             	mov	eax, dword ptr [rbp - 0x58]
ffffffff8151ce91: 49 8b 8c 24 d0 00 00 00      	mov	rcx, qword ptr [r12 + 0xd0]
ffffffff8151ce99: 83 e8 08             	sub	eax, 0x8
ffffffff8151ce9c: 2b 45 ac             	sub	eax, dword ptr [rbp - 0x54]
ffffffff8151ce9f: 83 e0 f8             	and	eax, -0x8
ffffffff8151cea2: 66 89 44 11 02       	mov	word ptr [rcx + rdx + 0x2], ax
ffffffff8151cea7: 41 8b 84 24 c8 00 00 00      	mov	eax, dword ptr [r12 + 0xc8]
ffffffff8151ceaf: 49 8b 94 24 d0 00 00 00      	mov	rdx, qword ptr [r12 + 0xd0]
ffffffff8151ceb7: 66 c7 44 02 06 02 00 	mov	word ptr [rdx + rax + 0x6], 0x2
ffffffff8151cebe: 48 8b 7b 30          	mov	rdi, qword ptr [rbx + 0x30]
ffffffff8151cec2: 4c 89 fa             	mov	rdx, r15
ffffffff8151cec5: e8 28 00 03 00       	call	0xffffffff8154cef2 <.text+0x54cef2>
ffffffff8151ceca: 41 8b 84 24 c8 00 00 00      	mov	eax, dword ptr [r12 + 0xc8]
ffffffff8151ced2: 49 8b 94 24 d0 00 00 00      	mov	rdx, qword ptr [r12 + 0xd0]
ffffffff8151ceda: 8b 4d c4             	mov	ecx, dword ptr [rbp - 0x3c]
ffffffff8151cedd: 89 4c 02 1c          	mov	dword ptr [rdx + rax + 0x1c], ecx
ffffffff8151cee1: 44 8b 45 20          	mov	r8d, dword ptr [rbp + 0x20]
ffffffff8151cee5: 44 2b 45 28          	sub	r8d, dword ptr [rbp + 0x28]
ffffffff8151cee9: 4c 89 e6             	mov	rsi, r12
ffffffff8151ceec: 48 8b 8d 50 ff ff ff 	mov	rcx, qword ptr [rbp - 0xb0]
ffffffff8151cef3: 48 8b 95 58 ff ff ff 	mov	rdx, qword ptr [rbp - 0xa8]
ffffffff8151cefa: 48 89 df             	mov	rdi, rbx
ffffffff8151cefd: e8 09 e5 f5 ff       	call	0xffffffff8147b40b <.text+0x47b40b>
ffffffff8151cf02: 85 c0                	test	eax, eax
ffffffff8151cf04: 89 45 c0             	mov	dword ptr [rbp - 0x40], eax
ffffffff8151cf07: 0f 85 76 06 00 00    	jne	0xffffffff8151d583 <.text+0x51d583>
ffffffff8151cf0d: 31 c0                	xor	eax, eax
ffffffff8151cf0f: e9 a4 06 00 00       	jmp	0xffffffff8151d5b8 <.text+0x51d5b8>
ffffffff8151cf14: 8b 45 a8             	mov	eax, dword ptr [rbp - 0x58]
ffffffff8151cf17: 4d 85 f6             	test	r14, r14
ffffffff8151cf1a: 89 45 a0             	mov	dword ptr [rbp - 0x60], eax
ffffffff8151cf1d: 0f 85 79 03 00 00    	jne	0xffffffff8151d29c <.text+0x51d29c>
ffffffff8151cf23: eb 06                	jmp	0xffffffff8151cf2b <.text+0x51cf2b>
