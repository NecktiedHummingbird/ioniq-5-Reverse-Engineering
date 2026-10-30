
work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/sound/core/snd-pcm.ko:	file format elf64-x86-64

Disassembly of section .text:

0000000000003e8f <snd_pcm_release>:
    3e8f: 55                           	push	rbp
    3e90: b8 fa ff ff ff               	mov	eax, 0xfffffffa
    3e95: 48 89 e5                     	mov	rbp, rsp
    3e98: 41 57                        	push	r15
    3e9a: 41 56                        	push	r14
    3e9c: 41 55                        	push	r13
    3e9e: 41 54                        	push	r12
    3ea0: 53                           	push	rbx
    3ea1: 51                           	push	rcx
    3ea2: 4c 8b b6 d0 00 00 00         	mov	r14, qword ptr [rsi + 0xd0]
    3ea9: 4d 8b 26                     	mov	r12, qword ptr [r14]
    3eac: 4d 85 e4                     	test	r12, r12
    3eaf: 74 62                        	je	0x3f13 <snd_pcm_release+0x84>
    3eb1: 49 8b 1c 24                  	mov	rbx, qword ptr [r12]
    3eb5: 49 89 f7                     	mov	r15, rsi
    3eb8: 4c 8d ab a8 06 00 00         	lea	r13, [rbx + 0x6a8]
    3ebf: 4c 89 ef                     	mov	rdi, r13
    3ec2: e8 00 00 00 00               	call	0x3ec7 <snd_pcm_release+0x38>
		0000000000003ec3:  R_X86_64_PC32	mutex_lock-0x4
    3ec7: 4c 89 e7                     	mov	rdi, r12
    3eca: e8 00 00 00 00               	call	0x3ecf <snd_pcm_release+0x40>
		0000000000003ecb:  R_X86_64_PC32	snd_pcm_release_substream-0x4
    3ecf: 4c 89 f7                     	mov	rdi, r14
    3ed2: e8 00 00 00 00               	call	0x3ed7 <snd_pcm_release+0x48>
		0000000000003ed3:  R_X86_64_PC32	kfree-0x4
    3ed7: 4c 89 ef                     	mov	rdi, r13
    3eda: e8 00 00 00 00               	call	0x3edf <snd_pcm_release+0x50>
		0000000000003edb:  R_X86_64_PC32	mutex_unlock-0x4
    3edf: 48 8d bb d0 06 00 00         	lea	rdi, [rbx + 0x6d0]
    3ee6: 31 c9                        	xor	ecx, ecx
    3ee8: ba 01 00 00 00               	mov	edx, 0x1
    3eed: be 03 00 00 00               	mov	esi, 0x3
    3ef2: e8 00 00 00 00               	call	0x3ef7 <snd_pcm_release+0x68>
		0000000000003ef3:  R_X86_64_PC32	__wake_up-0x4
    3ef7: 48 8b 03                     	mov	rax, qword ptr [rbx]
    3efa: 48 8b b8 68 01 00 00         	mov	rdi, qword ptr [rax + 0x168]
    3f01: e8 00 00 00 00               	call	0x3f06 <snd_pcm_release+0x77>
		0000000000003f02:  R_X86_64_PC32	module_put-0x4
    3f06: 48 8b 3b                     	mov	rdi, qword ptr [rbx]
    3f09: 4c 89 fe                     	mov	rsi, r15
    3f0c: e8 00 00 00 00               	call	0x3f11 <snd_pcm_release+0x82>
		0000000000003f0d:  R_X86_64_PC32	snd_card_file_remove-0x4
    3f11: 31 c0                        	xor	eax, eax
    3f13: 5a                           	pop	rdx
    3f14: 5b                           	pop	rbx
    3f15: 41 5c                        	pop	r12
    3f17: 41 5d                        	pop	r13
    3f19: 41 5e                        	pop	r14
    3f1b: 41 5f                        	pop	r15
    3f1d: 5d                           	pop	rbp
    3f1e: c3                           	ret
