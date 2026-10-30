
work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff811b6496: 48 3d 00 f0 ff ff    	cmp	rax, -0x1000
ffffffff811b649c: 77 48                	ja	0xffffffff811b64e6 <.text+0x1b64e6>
ffffffff811b649e: 49 3b 45 58          	cmp	rax, qword ptr [r13 + 0x58]
ffffffff811b64a2: 75 0c                	jne	0xffffffff811b64b0 <.text+0x1b64b0>
ffffffff811b64a4: 48 89 c7             	mov	rdi, rax
ffffffff811b64a7: 31 db                	xor	ebx, ebx
ffffffff811b64a9: e8 bd c0 ff ff       	call	0xffffffff811b256b <.text+0x1b256b>
ffffffff811b64ae: eb 36                	jmp	0xffffffff811b64e6 <.text+0x1b64e6>
ffffffff811b64b0: 4c 89 e6             	mov	rsi, r12
ffffffff811b64b3: 4c 89 ef             	mov	rdi, r13
ffffffff811b64b6: e8 a4 fb ff ff       	call	0xffffffff811b605f <.text+0x1b605f>
ffffffff811b64bb: 48 63 d8             	movsxd	rbx, eax
ffffffff811b64be: 48 85 db             	test	rbx, rbx
ffffffff811b64c1: 78 23                	js	0xffffffff811b64e6 <.text+0x1b64e6>
ffffffff811b64c3: 4c 89 ef             	mov	rdi, r13
ffffffff811b64c6: e8 9f cb eb ff       	call	0xffffffff8107306a <.text+0x7306a>
ffffffff811b64cb: 48 c7 c7 40 eb a2 81 	mov	rdi, -0x7e5d14c0
ffffffff811b64d2: e8 60 92 3a 00       	call	0xffffffff8155f737 <.text+0x55f737>
ffffffff811b64d7: 4c 89 e7             	mov	rdi, r12
ffffffff811b64da: 49 63 5c 24 04       	movsxd	rbx, dword ptr [r12 + 0x4]
ffffffff811b64df: e8 87 c0 ff ff       	call	0xffffffff811b256b <.text+0x1b256b>
ffffffff811b64e4: eb 14                	jmp	0xffffffff811b64fa <.text+0x1b64fa>
ffffffff811b64e6: 48 c7 c7 40 eb a2 81 	mov	rdi, -0x7e5d14c0
ffffffff811b64ed: e8 45 92 3a 00       	call	0xffffffff8155f737 <.text+0x55f737>
ffffffff811b64f2: 4c 89 ef             	mov	rdi, r13
ffffffff811b64f5: e8 a7 ca eb ff       	call	0xffffffff81072fa1 <.text+0x72fa1>
ffffffff811b64fa: 48 89 d8             	mov	rax, rbx
