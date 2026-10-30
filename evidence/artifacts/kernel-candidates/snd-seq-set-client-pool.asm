
work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko:	file format elf64-x86-64

Disassembly of section .text:

0000000000002293 <snd_seq_ioctl_set_client_pool>:
    2293: 55                           	push	rbp
    2294: ba 58 00 00 00               	mov	edx, 0x58
    2299: 48 89 e5                     	mov	rbp, rsp
    229c: 41 54                        	push	r12
    229e: 53                           	push	rbx
    229f: 48 89 fb                     	mov	rbx, rdi
    22a2: 48 8d 7d 90                  	lea	rdi, [rbp - 0x70]
    22a6: 49 89 f4                     	mov	r12, rsi
    22a9: 48 83 ec 60                  	sub	rsp, 0x60
    22ad: 65 48 8b 04 25 28 00 00 00   	mov	rax, qword ptr gs:[0x28]
    22b6: 48 89 45 e8                  	mov	qword ptr [rbp - 0x18], rax
    22ba: 31 c0                        	xor	eax, eax
    22bc: e8 dc df ff ff               	call	0x29d <copy_from_user>
    22c1: 48 85 c0                     	test	rax, rax
    22c4: ba f2 ff ff ff               	mov	edx, 0xfffffff2
    22c9: 0f 85 ca 00 00 00            	jne	0x2399 <snd_seq_ioctl_set_client_pool+0x106>
    22cf: 8b 7b 48                     	mov	edi, dword ptr [rbx + 0x48]
    22d2: 3b 7d 90                     	cmp	edi, dword ptr [rbp - 0x70]
    22d5: ba ea ff ff ff               	mov	edx, 0xffffffea
    22da: 0f 85 b9 00 00 00            	jne	0x2399 <snd_seq_ioctl_set_client_pool+0x106>
    22e0: 8b 55 94                     	mov	edx, dword ptr [rbp - 0x6c]
    22e3: 8d 42 ff                     	lea	eax, [rdx - 0x1]
    22e6: 3d cf 07 00 00               	cmp	eax, 0x7cf
    22eb: 76 0b                        	jbe	0x22f8 <snd_seq_ioctl_set_client_pool+0x65>
    22ed: 83 3b 01                     	cmp	dword ptr [rbx], 0x1
    22f0: 0f 85 80 00 00 00            	jne	0x2376 <snd_seq_ioctl_set_client_pool+0xe3>
    22f6: eb 49                        	jmp	0x2341 <snd_seq_ioctl_set_client_pool+0xae>
    22f8: 48 8b 83 c8 00 00 00         	mov	rax, qword ptr [rbx + 0xc8]
    22ff: 48 85 c0                     	test	rax, rax
    2302: 74 1c                        	je	0x2320 <snd_seq_ioctl_set_client_pool+0x8d>
    2304: 83 78 10 00                  	cmp	dword ptr [rax + 0x10], 0x0
    2308: 7e 16                        	jle	0x2320 <snd_seq_ioctl_set_client_pool+0x8d>
    230a: 3b 50 18                     	cmp	edx, dword ptr [rax + 0x18]
    230d: 74 de                        	je	0x22ed <snd_seq_ioctl_set_client_pool+0x5a>
    230f: e8 00 00 00 00               	call	0x2314 <snd_seq_ioctl_set_client_pool+0x81>
		0000000000002310:  R_X86_64_PC32	snd_seq_queue_client_leave_cells-0x4
    2314: 48 8b bb c8 00 00 00         	mov	rdi, qword ptr [rbx + 0xc8]
    231b: e8 00 00 00 00               	call	0x2320 <snd_seq_ioctl_set_client_pool+0x8d>
		000000000000231c:  R_X86_64_PC32	snd_seq_pool_done-0x4
    2320: 8b 55 94                     	mov	edx, dword ptr [rbp - 0x6c]
    2323: 48 8b 83 c8 00 00 00         	mov	rax, qword ptr [rbx + 0xc8]
    232a: 89 50 18                     	mov	dword ptr [rax + 0x18], edx
    232d: 48 8b bb c8 00 00 00         	mov	rdi, qword ptr [rbx + 0xc8]
    2334: e8 00 00 00 00               	call	0x2339 <snd_seq_ioctl_set_client_pool+0xa6>
		0000000000002335:  R_X86_64_PC32	snd_seq_pool_init-0x4
    2339: 85 c0                        	test	eax, eax
    233b: 89 c2                        	mov	edx, eax
    233d: 79 ae                        	jns	0x22ed <snd_seq_ioctl_set_client_pool+0x5a>
    233f: eb 58                        	jmp	0x2399 <snd_seq_ioctl_set_client_pool+0x106>
    2341: 48 8b bb d8 00 00 00         	mov	rdi, qword ptr [rbx + 0xd8]
    2348: 48 85 ff                     	test	rdi, rdi
    234b: 74 29                        	je	0x2376 <snd_seq_ioctl_set_client_pool+0xe3>
    234d: 8b 75 98                     	mov	esi, dword ptr [rbp - 0x68]
    2350: 8d 46 ff                     	lea	eax, [rsi - 0x1]
    2353: 3d cf 07 00 00               	cmp	eax, 0x7cf
    2358: 77 1c                        	ja	0x2376 <snd_seq_ioctl_set_client_pool+0xe3>
    235a: 3b b3 e0 00 00 00            	cmp	esi, dword ptr [rbx + 0xe0]
    2360: 74 14                        	je	0x2376 <snd_seq_ioctl_set_client_pool+0xe3>
    2362: e8 00 00 00 00               	call	0x2367 <snd_seq_ioctl_set_client_pool+0xd4>
		0000000000002363:  R_X86_64_PC32	snd_seq_fifo_resize-0x4
    2367: 85 c0                        	test	eax, eax
    2369: 89 c2                        	mov	edx, eax
    236b: 78 2c                        	js	0x2399 <snd_seq_ioctl_set_client_pool+0x106>
    236d: 8b 45 98                     	mov	eax, dword ptr [rbp - 0x68]
    2370: 89 83 e0 00 00 00            	mov	dword ptr [rbx + 0xe0], eax
    2376: 8b 45 9c                     	mov	eax, dword ptr [rbp - 0x64]
    2379: 85 c0                        	test	eax, eax
    237b: 7e 0f                        	jle	0x238c <snd_seq_ioctl_set_client_pool+0xf9>
    237d: 48 8b 93 c8 00 00 00         	mov	rdx, qword ptr [rbx + 0xc8]
    2384: 3b 42 18                     	cmp	eax, dword ptr [rdx + 0x18]
    2387: 7f 03                        	jg	0x238c <snd_seq_ioctl_set_client_pool+0xf9>
    2389: 89 42 1c                     	mov	dword ptr [rdx + 0x1c], eax
    238c: 4c 89 e6                     	mov	rsi, r12
    238f: 48 89 df                     	mov	rdi, rbx
    2392: e8 fb fd ff ff               	call	0x2192 <snd_seq_ioctl_get_client_pool>
    2397: 89 c2                        	mov	edx, eax
    2399: 48 8b 4d e8                  	mov	rcx, qword ptr [rbp - 0x18]
    239d: 65 48 33 0c 25 28 00 00 00   	xor	rcx, qword ptr gs:[0x28]
    23a6: 89 d0                        	mov	eax, edx
    23a8: 74 05                        	je	0x23af <snd_seq_ioctl_set_client_pool+0x11c>
    23aa: e8 00 00 00 00               	call	0x23af <snd_seq_ioctl_set_client_pool+0x11c>
		00000000000023ab:  R_X86_64_PC32	__stack_chk_fail-0x4
    23af: 48 83 c4 60                  	add	rsp, 0x60
    23b3: 5b                           	pop	rbx
    23b4: 41 5c                        	pop	r12
    23b6: 5d                           	pop	rbp
    23b7: c3                           	ret
