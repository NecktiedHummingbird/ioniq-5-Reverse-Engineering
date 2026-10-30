
work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff814cd140: 48 8b 45 b0          	mov	rax, qword ptr [rbp - 0x50]
ffffffff814cd144: 89 78 14             	mov	dword ptr [rax + 0x14], edi
ffffffff814cd147: 8b 45 9c             	mov	eax, dword ptr [rbp - 0x64]
ffffffff814cd14a: 3b 45 18             	cmp	eax, dword ptr [rbp + 0x18]
ffffffff814cd14d: 7c 23                	jl	0xffffffff814cd172 <.text+0x4cd172>
ffffffff814cd14f: 4d 85 f6             	test	r14, r14
ffffffff814cd152: 0f 84 ad 01 00 00    	je	0xffffffff814cd305 <.text+0x4cd305>
ffffffff814cd158: 41 8b 86 c8 00 00 00 	mov	eax, dword ptr [r14 + 0xc8]
ffffffff814cd15f: 49 8b 96 d0 00 00 00 	mov	rdx, qword ptr [r14 + 0xd0]
ffffffff814cd166: 66 83 7c 02 02 00    	cmp	word ptr [rdx + rax + 0x2], 0x0
ffffffff814cd16c: 0f 84 02 04 00 00    	je	0xffffffff814cd574 <.text+0x4cd574>
ffffffff814cd172: 80 bb 49 01 00 00 11 	cmp	byte ptr [rbx + 0x149], 0x11
ffffffff814cd179: 0f 85 74 01 00 00    	jne	0xffffffff814cd2f3 <.text+0x4cd2f3>
ffffffff814cd17f: 48 8b 45 a0          	mov	rax, qword ptr [rbp - 0x60]
ffffffff814cd183: 48 8b 40 18          	mov	rax, qword ptr [rax + 0x18]
ffffffff814cd187: f6 80 f2 00 00 00 02 	test	byte ptr [rax + 0xf2], 0x2
ffffffff814cd18e: 0f 84 5f 01 00 00    	je	0xffffffff814cd2f3 <.text+0x4cd2f3>
ffffffff814cd194: 48 8b 45 a0          	mov	rax, qword ptr [rbp - 0x60]
ffffffff814cd198: 66 83 78 68 00       	cmp	word ptr [rax + 0x68], 0x0
ffffffff814cd19d: 0f 85 50 01 00 00    	jne	0xffffffff814cd2f3 <.text+0x4cd2f3>
ffffffff814cd1a3: 8b 83 48 01 00 00    	mov	eax, dword ptr [rbx + 0x148]
ffffffff814cd1a9: 25 04 00 ff ff       	and	eax, 0xffff0004
ffffffff814cd1ae: 3d 00 00 02 00       	cmp	eax, 0x20000
ffffffff814cd1b3: 0f 85 3a 01 00 00    	jne	0xffffffff814cd2f3 <.text+0x4cd2f3>
ffffffff814cd1b9: 4d 8b 65 08          	mov	r12, qword ptr [r13 + 0x8]
ffffffff814cd1bd: 4d 39 e5             	cmp	r13, r12
ffffffff814cd1c0: 74 09                	je	0xffffffff814cd1cb <.text+0x4cd1cb>
ffffffff814cd1c2: 4d 85 e4             	test	r12, r12
ffffffff814cd1c5: 0f 85 a2 00 00 00    	jne	0xffffffff814cd26d <.text+0x4cd26d>
ffffffff814cd1cb: 8b 45 98             	mov	eax, dword ptr [rbp - 0x68]
ffffffff814cd1ce: 03 45 bc             	add	eax, dword ptr [rbp - 0x44]
ffffffff814cd1d1: 48 89 df             	mov	rdi, rbx
ffffffff814cd1d4: 8b 4d 20             	mov	ecx, dword ptr [rbp + 0x20]
ffffffff814cd1d7: 8b 55 28             	mov	edx, dword ptr [rbp + 0x28]
ffffffff814cd1da: 8d 74 01 14          	lea	esi, [rcx + rax + 0x14]
ffffffff814cd1de: 48 8d 4d c4          	lea	rcx, [rbp - 0x3c]
ffffffff814cd1e2: 83 e2 40             	and	edx, 0x40
ffffffff814cd1e5: 48 63 f6             	movsxd	rsi, esi
ffffffff814cd1e8: e8 a4 a7 fa ff       	call	0xffffffff81477991 <.text+0x477991>
ffffffff814cd1ed: 48 85 c0             	test	rax, rax
ffffffff814cd1f0: 49 89 c4             	mov	r12, rax
ffffffff814cd1f3: 75 08                	jne	0xffffffff814cd1fd <.text+0x4cd1fd>
ffffffff814cd1f5: 8b 45 c4             	mov	eax, dword ptr [rbp - 0x3c]
ffffffff814cd1f8: e9 e4 00 00 00       	jmp	0xffffffff814cd2e1 <.text+0x4cd2e1>
ffffffff814cd1fd: 48 63 45 98          	movsxd	rax, dword ptr [rbp - 0x68]
ffffffff814cd201: 8b 75 bc             	mov	esi, dword ptr [rbp - 0x44]
ffffffff814cd204: 4c 89 e7             	mov	rdi, r12
ffffffff814cd207: 49 01 84 24 d8 00 00 00      	add	qword ptr [r12 + 0xd8], rax
ffffffff814cd20f: 03 75 20             	add	esi, dword ptr [rbp + 0x20]
ffffffff814cd212: 8b 45 98             	mov	eax, dword ptr [rbp - 0x68]
ffffffff814cd215: 41 01 84 24 c4 00 00 00      	add	dword ptr [r12 + 0xc4], eax
ffffffff814cd21d: e8 dd db fa ff       	call	0xffffffff8147adff <.text+0x47adff>
ffffffff814cd222: 49 8b 84 24 d8 00 00 00      	mov	rax, qword ptr [r12 + 0xd8]
ffffffff814cd22a: 49 2b 84 24 d0 00 00 00      	sub	rax, qword ptr [r12 + 0xd0]
ffffffff814cd232: 41 c7 84 24 98 00 00 00 00 00 00 00  	mov	dword ptr [r12 + 0x98], 0x0
ffffffff814cd23e: 66 41 89 84 24 c0 00 00 00   	mov	word ptr [r12 + 0xc0], ax
ffffffff814cd247: 03 45 bc             	add	eax, dword ptr [rbp - 0x44]
ffffffff814cd24a: 66 41 89 84 24 be 00 00 00   	mov	word ptr [r12 + 0xbe], ax
ffffffff814cd253: 49 8b 45 08          	mov	rax, qword ptr [r13 + 0x8]
ffffffff814cd257: 4d 89 2c 24          	mov	qword ptr [r12], r13
ffffffff814cd25b: 49 89 44 24 08       	mov	qword ptr [r12 + 0x8], rax
ffffffff814cd260: 4c 89 20             	mov	qword ptr [rax], r12
ffffffff814cd263: 4d 89 65 08          	mov	qword ptr [r13 + 0x8], r12
ffffffff814cd267: 41 ff 45 10          	inc	dword ptr [r13 + 0x10]
ffffffff814cd26b: eb 18                	jmp	0xffffffff814cd285 <.text+0x4cd285>
ffffffff814cd26d: 41 8b 84 24 c8 00 00 00      	mov	eax, dword ptr [r12 + 0xc8]
ffffffff814cd275: 49 8b 94 24 d0 00 00 00      	mov	rdx, qword ptr [r12 + 0xd0]
ffffffff814cd27d: 66 83 7c 02 02 00    	cmp	word ptr [rdx + rax + 0x2], 0x0
ffffffff814cd283: 75 3b                	jne	0xffffffff814cd2c0 <.text+0x4cd2c0>
ffffffff814cd285: 41 80 8c 24 91 00 00 00 06   	or	byte ptr [r12 + 0x91], 0x6
ffffffff814cd28e: 41 8b 84 24 c8 00 00 00      	mov	eax, dword ptr [r12 + 0xc8]
ffffffff814cd296: 49 8b 94 24 d0 00 00 00      	mov	rdx, qword ptr [r12 + 0xd0]
ffffffff814cd29e: 8b 8d 78 ff ff ff    	mov	ecx, dword ptr [rbp - 0x88]
ffffffff814cd2a4: 66 89 4c 02 02       	mov	word ptr [rdx + rax + 0x2], cx
ffffffff814cd2a9: 41 8b 84 24 c8 00 00 00      	mov	eax, dword ptr [r12 + 0xc8]
ffffffff814cd2b1: 49 8b 94 24 d0 00 00 00      	mov	rdx, qword ptr [r12 + 0xd0]
ffffffff814cd2b9: 66 c7 44 02 06 02 00 	mov	word ptr [rdx + rax + 0x6], 0x2
ffffffff814cd2c0: 44 8b 45 18          	mov	r8d, dword ptr [rbp + 0x18]
ffffffff814cd2c4: 44 2b 45 20          	sub	r8d, dword ptr [rbp + 0x20]
ffffffff814cd2c8: 4c 89 e6             	mov	rsi, r12
ffffffff814cd2cb: 48 8b 8d 68 ff ff ff 	mov	rcx, qword ptr [rbp - 0x98]
ffffffff814cd2d2: 48 8b 95 70 ff ff ff 	mov	rdx, qword ptr [rbp - 0x90]
ffffffff814cd2d9: 48 89 df             	mov	rdi, rbx
ffffffff814cd2dc: e8 2a e1 fa ff       	call	0xffffffff8147b40b <.text+0x47b40b>
ffffffff814cd2e1: 85 c0                	test	eax, eax
ffffffff814cd2e3: 89 45 c4             	mov	dword ptr [rbp - 0x3c], eax
ffffffff814cd2e6: 0f 85 38 05 00 00    	jne	0xffffffff814cd824 <.text+0x4cd824>
ffffffff814cd2ec: 31 c0                	xor	eax, eax
ffffffff814cd2ee: e9 4e 05 00 00       	jmp	0xffffffff814cd841 <.text+0x4cd841>
ffffffff814cd2f3: 4d 85 f6             	test	r14, r14
ffffffff814cd2f6: c7 45 b8 00 00 00 00 	mov	dword ptr [rbp - 0x48], 0x0
ffffffff814cd2fd: 0f 85 78 02 00 00    	jne	0xffffffff814cd57b <.text+0x4cd57b>
ffffffff814cd303: eb 07                	jmp	0xffffffff814cd30c <.text+0x4cd30c>
