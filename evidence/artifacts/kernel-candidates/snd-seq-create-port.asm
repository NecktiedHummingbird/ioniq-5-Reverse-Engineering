
work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko:	file format elf64-x86-64

Disassembly of section .text:

0000000000006820 <snd_seq_create_port>:
    6820: 48 85 ff                     	test	rdi, rdi
    6823: 0f 84 16 02 00 00            	je	0x6a3f <snd_seq_create_port+0x21f>
    6829: 55                           	push	rbp
    682a: 48 89 e5                     	mov	rbp, rsp
    682d: 41 57                        	push	r15
    682f: 41 56                        	push	r14
    6831: 41 55                        	push	r13
    6833: 41 54                        	push	r12
    6835: 41 89 f5                     	mov	r13d, esi
    6838: 53                           	push	rbx
    6839: 49 89 fc                     	mov	r12, rdi
    683c: 48 83 ec 18                  	sub	rsp, 0x18
    6840: 81 7f 78 fd 00 00 00         	cmp	dword ptr [rdi + 0x78], 0xfd
    6847: 7e 18                        	jle	0x6861 <snd_seq_create_port+0x41>
    6849: 8b 77 48                     	mov	esi, dword ptr [rdi + 0x48]
    684c: 31 c0                        	xor	eax, eax
    684e: 48 c7 c7 00 00 00 00         	mov	rdi, 0x0
		0000000000006851:  R_X86_64_32S	.rodata.str1.1+0xb71
    6855: e8 00 00 00 00               	call	0x685a <snd_seq_create_port+0x3a>
		0000000000006856:  R_X86_64_PC32	printk-0x4
    685a: 31 c0                        	xor	eax, eax
    685c: e9 cf 01 00 00               	jmp	0x6a30 <snd_seq_create_port+0x210>
    6861: 48 8b 3d 00 00 00 00         	mov	rdi, qword ptr [rip]    # 0x6868 <snd_seq_create_port+0x48>
		0000000000006864:  R_X86_64_PC32	kmalloc_caches+0x44
    6868: be d0 80 00 00               	mov	esi, 0x80d0
    686d: e8 00 00 00 00               	call	0x6872 <snd_seq_create_port+0x52>
		000000000000686e:  R_X86_64_PC32	kmem_cache_alloc-0x4
    6872: 48 85 c0                     	test	rax, rax
    6875: 48 89 c3                     	mov	rbx, rax
    6878: 74 e0                        	je	0x685a <snd_seq_create_port+0x3a>
    687a: 41 8b 44 24 48               	mov	eax, dword ptr [r12 + 0x48]
    687f: 83 ca ff                     	or	edx, -0x1
    6882: 48 c7 c6 00 00 00 00         	mov	rsi, 0x0
		0000000000006885:  R_X86_64_32S	.rodata.str1.1+0xb9c
    6889: c6 43 01 ff                  	mov	byte ptr [rbx + 0x1], -0x1
    688d: 48 c7 43 08 00 00 00 00      	mov	qword ptr [rbx + 0x8], 0x0
		0000000000006891:  R_X86_64_32S	__this_module
    6895: 4d 8d bc 24 98 00 00 00      	lea	r15, [r12 + 0x98]
    689d: 88 03                        	mov	byte ptr [rbx], al
    689f: 48 8d 43 10                  	lea	rax, [rbx + 0x10]
    68a3: 48 89 c7                     	mov	rdi, rax
    68a6: 48 89 45 c8                  	mov	qword ptr [rbp - 0x38], rax
    68aa: 31 c0                        	xor	eax, eax
    68ac: e8 00 00 00 00               	call	0x68b1 <snd_seq_create_port+0x91>
		00000000000068ad:  R_X86_64_PC32	sprintf-0x4
    68b1: 80 63 7c fe                  	and	byte ptr [rbx + 0x7c], -0x2
    68b5: 48 8d 43 68                  	lea	rax, [rbx + 0x68]
    68b9: 48 8d bb 80 00 00 00         	lea	rdi, [rbx + 0x80]
    68c0: 48 c7 c2 00 00 00 00         	mov	rdx, 0x0
		00000000000068c3:  R_X86_64_32S	.bss+0xb00
    68c7: 48 c7 c6 00 00 00 00         	mov	rsi, 0x0
		00000000000068ca:  R_X86_64_32S	.rodata.str1.1+0xba4
    68ce: c7 43 60 00 00 00 00         	mov	dword ptr [rbx + 0x60], 0x0
    68d5: 48 89 43 68                  	mov	qword ptr [rbx + 0x68], rax
    68d9: 48 89 43 70                  	mov	qword ptr [rbx + 0x70], rax
    68dd: c7 43 78 00 00 00 00         	mov	dword ptr [rbx + 0x78], 0x0
    68e4: c7 83 a8 00 00 00 00 00 00 00	mov	dword ptr [rbx + 0xa8], 0x0
    68ee: 66 c7 83 ac 00 00 00 00 00   	mov	word ptr [rbx + 0xac], 0x0
    68f7: e8 00 00 00 00               	call	0x68fc <snd_seq_create_port+0xdc>
		00000000000068f8:  R_X86_64_PC32	__init_rwsem-0x4
    68fc: 80 a3 d4 00 00 00 fe         	and	byte ptr [rbx + 0xd4], -0x2
    6903: 48 8d 83 c0 00 00 00         	lea	rax, [rbx + 0xc0]
    690a: 48 8d bb d8 00 00 00         	lea	rdi, [rbx + 0xd8]
    6911: 48 c7 c6 00 00 00 00         	mov	rsi, 0x0
		0000000000006914:  R_X86_64_32S	.rodata.str1.1+0xba4
    6918: 48 c7 c2 00 00 00 00         	mov	rdx, 0x0
		000000000000691b:  R_X86_64_32S	.bss+0xb00
    691f: 48 c7 83 b0 00 00 00 00 00 00 00     	mov	qword ptr [rbx + 0xb0], 0x0
    692a: 48 89 83 c0 00 00 00         	mov	qword ptr [rbx + 0xc0], rax
    6931: 48 89 83 c8 00 00 00         	mov	qword ptr [rbx + 0xc8], rax
    6938: 48 c7 83 b8 00 00 00 00 00 00 00     	mov	qword ptr [rbx + 0xb8], 0x0
    6943: c7 83 d0 00 00 00 00 00 00 00	mov	dword ptr [rbx + 0xd0], 0x0
    694d: c7 83 00 01 00 00 00 00 00 00	mov	dword ptr [rbx + 0x100], 0x0
    6957: 66 c7 83 04 01 00 00 00 00   	mov	word ptr [rbx + 0x104], 0x0
    6960: e8 00 00 00 00               	call	0x6965 <snd_seq_create_port+0x145>
		0000000000006961:  R_X86_64_PC32	__init_rwsem-0x4
    6965: 45 85 ed                     	test	r13d, r13d
    6968: ba 00 00 00 00               	mov	edx, 0x0
    696d: 4c 89 ff                     	mov	rdi, r15
    6970: 41 0f 49 d5                  	cmovns	edx, r13d
    6974: 48 c7 83 08 01 00 00 00 00 00 00     	mov	qword ptr [rbx + 0x108], 0x0
    697f: 48 c7 83 10 01 00 00 00 00 00 00     	mov	qword ptr [rbx + 0x110], 0x0
    698a: 41 89 d6                     	mov	r14d, edx
    698d: e8 00 00 00 00               	call	0x6992 <snd_seq_create_port+0x172>
		000000000000698e:  R_X86_64_PC32	mutex_lock-0x4
    6992: 4d 8d 84 24 90 00 00 00      	lea	r8, [r12 + 0x90]
    699a: 4c 89 c7                     	mov	rdi, r8
    699d: 4c 89 45 c0                  	mov	qword ptr [rbp - 0x40], r8
    69a1: e8 00 00 00 00               	call	0x69a6 <snd_seq_create_port+0x186>
		00000000000069a2:  R_X86_64_PC32	_raw_write_lock_irqsave-0x4
    69a6: 49 8b 94 24 80 00 00 00      	mov	rdx, qword ptr [r12 + 0x80]
    69ae: 4c 8b 45 c0                  	mov	r8, qword ptr [rbp - 0x40]
    69b2: 49 8d b4 24 80 00 00 00      	lea	rsi, [r12 + 0x80]
    69ba: 48 8d 4a b0                  	lea	rcx, [rdx - 0x50]
    69be: 4c 8d 49 50                  	lea	r9, [rcx + 0x50]
    69c2: 49 39 f1                     	cmp	r9, rsi
    69c5: 74 09                        	je	0x69d0 <snd_seq_create_port+0x1b0>
    69c7: 0f b6 79 01                  	movzx	edi, byte ptr [rcx + 0x1]
    69cb: 41 39 fe                     	cmp	r14d, edi
    69ce: 7d 4d                        	jge	0x6a1d <snd_seq_create_port+0x1fd>
    69d0: 48 8b 79 58                  	mov	rdi, qword ptr [rcx + 0x58]
    69d4: 4c 8d 53 50                  	lea	r10, [rbx + 0x50]
    69d8: 48 89 c6                     	mov	rsi, rax
    69db: 4c 89 51 58                  	mov	qword ptr [rcx + 0x58], r10
    69df: 4c 89 4b 50                  	mov	qword ptr [rbx + 0x50], r9
    69e3: 48 89 7b 58                  	mov	qword ptr [rbx + 0x58], rdi
    69e7: 4c 89 17                     	mov	qword ptr [rdi], r10
    69ea: 4c 89 c7                     	mov	rdi, r8
    69ed: 41 ff 44 24 78               	inc	dword ptr [r12 + 0x78]
    69f2: 44 88 73 01                  	mov	byte ptr [rbx + 0x1], r14b
    69f6: e8 00 00 00 00               	call	0x69fb <snd_seq_create_port+0x1db>
		00000000000069f7:  R_X86_64_PC32	_raw_write_unlock_irqrestore-0x4
    69fb: 4c 89 ff                     	mov	rdi, r15
    69fe: e8 00 00 00 00               	call	0x6a03 <snd_seq_create_port+0x1e3>
		00000000000069ff:  R_X86_64_PC32	mutex_unlock-0x4
    6a03: 48 8b 7d c8                  	mov	rdi, qword ptr [rbp - 0x38]
    6a07: 44 89 f2                     	mov	edx, r14d
    6a0a: 48 c7 c6 00 00 00 00         	mov	rsi, 0x0
		0000000000006a0d:  R_X86_64_32S	.rodata.str1.1+0xb9c
    6a11: 31 c0                        	xor	eax, eax
    6a13: e8 00 00 00 00               	call	0x6a18 <snd_seq_create_port+0x1f8>
		0000000000006a14:  R_X86_64_PC32	sprintf-0x4
    6a18: 48 89 d8                     	mov	rax, rbx
    6a1b: eb 13                        	jmp	0x6a30 <snd_seq_create_port+0x210>
    6a1d: 48 8b 49 50                  	mov	rcx, qword ptr [rcx + 0x50]
    6a21: ff c7                        	inc	edi
    6a23: 45 85 ed                     	test	r13d, r13d
    6a26: 44 0f 48 f7                  	cmovs	r14d, edi
    6a2a: 48 83 e9 50                  	sub	rcx, 0x50
    6a2e: eb 8e                        	jmp	0x69be <snd_seq_create_port+0x19e>
    6a30: 48 83 c4 18                  	add	rsp, 0x18
    6a34: 5b                           	pop	rbx
    6a35: 41 5c                        	pop	r12
    6a37: 41 5d                        	pop	r13
    6a39: 41 5e                        	pop	r14
    6a3b: 41 5f                        	pop	r15
    6a3d: 5d                           	pop	rbp
    6a3e: c3                           	ret
    6a3f: 31 c0                        	xor	eax, eax
    6a41: c3                           	ret
