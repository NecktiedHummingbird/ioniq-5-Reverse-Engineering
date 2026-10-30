
work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko:	file format elf64-x86-64

Disassembly of section .text:

000000000000174e <seq_create_client1>:
    174e: 55                           	push	rbp
    174f: 48 89 e5                     	mov	rbp, rsp
    1752: 41 55                        	push	r13
    1754: 41 54                        	push	r12
    1756: 41 89 fc                     	mov	r12d, edi
    1759: 53                           	push	rbx
    175a: 51                           	push	rcx
    175b: 48 8b 3d 00 00 00 00         	mov	rdi, qword ptr [rip]    # 0x1762 <seq_create_client1+0x14>
		000000000000175e:  R_X86_64_PC32	kmalloc_caches+0x3c
    1762: 41 89 f5                     	mov	r13d, esi
    1765: be d0 80 00 00               	mov	esi, 0x80d0
    176a: e8 00 00 00 00               	call	0x176f <seq_create_client1+0x21>
		000000000000176b:  R_X86_64_PC32	kmem_cache_alloc-0x4
    176f: 48 89 c3                     	mov	rbx, rax
    1772: 31 c0                        	xor	eax, eax
    1774: 48 85 db                     	test	rbx, rbx
    1777: 0f 84 08 01 00 00            	je	0x1885 <seq_create_client1+0x137>
    177d: 44 89 ef                     	mov	edi, r13d
    1780: e8 00 00 00 00               	call	0x1785 <seq_create_client1+0x37>
		0000000000001781:  R_X86_64_PC32	snd_seq_pool_new-0x4
    1785: 48 85 c0                     	test	rax, rax
    1788: 48 89 83 c8 00 00 00         	mov	qword ptr [rbx + 0xc8], rax
    178f: 0f 84 e6 00 00 00            	je	0x187b <seq_create_client1+0x12d>
    1795: 48 8d bb 98 00 00 00         	lea	rdi, [rbx + 0x98]
    179c: 48 c7 c6 00 00 00 00         	mov	rsi, 0x0
		000000000000179f:  R_X86_64_32S	.rodata.str1.1+0x20d
    17a3: 48 c7 c2 00 00 00 00         	mov	rdx, 0x0
		00000000000017a6:  R_X86_64_32S	.bss+0x20
    17aa: c7 03 00 00 00 00            	mov	dword ptr [rbx], 0x0
    17b0: c7 43 70 00 00 00 00         	mov	dword ptr [rbx + 0x70], 0x0
    17b7: c7 83 90 00 00 00 00 00 00 00	mov	dword ptr [rbx + 0x90], 0x0
    17c1: 66 c7 83 94 00 00 00 00 00   	mov	word ptr [rbx + 0x94], 0x0
    17ca: e8 00 00 00 00               	call	0x17cf <seq_create_client1+0x81>
		00000000000017cb:  R_X86_64_PC32	__mutex_init-0x4
    17cf: 48 8d 83 80 00 00 00         	lea	rax, [rbx + 0x80]
    17d6: 48 c7 c7 00 00 00 00         	mov	rdi, 0x0
		00000000000017d9:  R_X86_64_32S	.bss+0x9c0
    17dd: 48 89 83 80 00 00 00         	mov	qword ptr [rbx + 0x80], rax
    17e4: 48 89 83 88 00 00 00         	mov	qword ptr [rbx + 0x88], rax
    17eb: e8 00 00 00 00               	call	0x17f0 <seq_create_client1+0xa2>
		00000000000017ec:  R_X86_64_PC32	_raw_spin_lock_irqsave-0x4
    17f0: 45 85 e4                     	test	r12d, r12d
    17f3: 48 89 c6                     	mov	rsi, rax
    17f6: 79 37                        	jns	0x182f <seq_create_client1+0xe1>
    17f8: 31 d2                        	xor	edx, edx
    17fa: 48 83 3c d5 00 00 00 00 00   	cmp	qword ptr [8*rdx], 0x0
		00000000000017fe:  R_X86_64_32S	.bss+0x700
    1803: 8d 8a 80 00 00 00            	lea	ecx, [rdx + 0x80]
    1809: 75 09                        	jne	0x1814 <seq_create_client1+0xc6>
    180b: 80 ba 00 00 00 00 00         	cmp	byte ptr [rdx], 0x0
		000000000000180d:  R_X86_64_32S	.bss+0x980
    1812: 74 0b                        	je	0x181f <seq_create_client1+0xd1>
    1814: 48 ff c2                     	inc	rdx
    1817: 48 83 fa 40                  	cmp	rdx, 0x40
    181b: 75 dd                        	jne	0x17fa <seq_create_client1+0xac>
    181d: eb 44                        	jmp	0x1863 <seq_create_client1+0x115>
    181f: 89 4b 48                     	mov	dword ptr [rbx + 0x48], ecx
    1822: 48 63 c9                     	movsxd	rcx, ecx
    1825: 48 89 1c cd 00 00 00 00      	mov	qword ptr [8*rcx], rbx
		0000000000001829:  R_X86_64_32S	.bss+0x300
    182d: eb 23                        	jmp	0x1852 <seq_create_client1+0x104>
    182f: 49 63 c4                     	movsxd	rax, r12d
    1832: 48 83 3c c5 00 00 00 00 00   	cmp	qword ptr [8*rax], 0x0
		0000000000001836:  R_X86_64_32S	.bss+0x300
    183b: 75 26                        	jne	0x1863 <seq_create_client1+0x115>
    183d: 80 b8 00 00 00 00 00         	cmp	byte ptr [rax], 0x0
		000000000000183f:  R_X86_64_32S	.bss+0x900
    1844: 75 1d                        	jne	0x1863 <seq_create_client1+0x115>
    1846: 44 89 63 48                  	mov	dword ptr [rbx + 0x48], r12d
    184a: 48 89 1c c5 00 00 00 00      	mov	qword ptr [8*rax], rbx
		000000000000184e:  R_X86_64_32S	.bss+0x300
    1852: 48 c7 c7 00 00 00 00         	mov	rdi, 0x0
		0000000000001855:  R_X86_64_32S	.bss+0x9c0
    1859: e8 00 00 00 00               	call	0x185e <seq_create_client1+0x110>
		000000000000185a:  R_X86_64_PC32	_raw_spin_unlock_irqrestore-0x4
    185e: 48 89 d8                     	mov	rax, rbx
    1861: eb 22                        	jmp	0x1885 <seq_create_client1+0x137>
    1863: 48 c7 c7 00 00 00 00         	mov	rdi, 0x0
		0000000000001866:  R_X86_64_32S	.bss+0x9c0
    186a: e8 00 00 00 00               	call	0x186f <seq_create_client1+0x121>
		000000000000186b:  R_X86_64_PC32	_raw_spin_unlock_irqrestore-0x4
    186f: 48 8d bb c8 00 00 00         	lea	rdi, [rbx + 0xc8]
    1876: e8 00 00 00 00               	call	0x187b <seq_create_client1+0x12d>
		0000000000001877:  R_X86_64_PC32	snd_seq_pool_delete-0x4
    187b: 48 89 df                     	mov	rdi, rbx
    187e: e8 00 00 00 00               	call	0x1883 <seq_create_client1+0x135>
		000000000000187f:  R_X86_64_PC32	kfree-0x4
    1883: 31 c0                        	xor	eax, eax
    1885: 5a                           	pop	rdx
    1886: 5b                           	pop	rbx
    1887: 41 5c                        	pop	r12
    1889: 41 5d                        	pop	r13
    188b: 5d                           	pop	rbp
    188c: c3                           	ret
