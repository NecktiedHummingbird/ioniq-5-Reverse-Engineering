# Exact recovered vmlinux keystore/manifest selected complete-function disassembly
# vmlinux SHA-256 f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b
# Build ID 273378887b4cf563c10862fdf18b2292765df781
# Linked kernel virtual addresses; half-open symbol ranges listed before each function

# get_apl_manifest_offsets [0xffffffff8105986e,0xffffffff810598f3)

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff8105986e: 55                   	pushq	%rbp
ffffffff8105986f: 48 85 ff             	testq	%rdi, %rdi
ffffffff81059872: 48 89 e5             	movq	%rsp, %rbp
ffffffff81059875: 41 55                	pushq	%r13
ffffffff81059877: 49 89 fd             	movq	%rdi, %r13
ffffffff8105987a: 41 54                	pushq	%r12
ffffffff8105987c: 53                   	pushq	%rbx
ffffffff8105987d: 51                   	pushq	%rcx
ffffffff8105987e: 4c 8b 25 ab 4a 9c 00 	movq	0x9c4aab(%rip), %r12    # 0xffffffff81a1e330
ffffffff81059885: 75 1b                	jne	0xffffffff810598a2 <.text+0x598a2>
ffffffff81059887: 31 f6                	xorl	%esi, %esi
ffffffff81059889: 48 c7 c7 46 e1 7e 81 	movq	$-0x7e811eba, %rdi      # imm = 0x817EE146
ffffffff81059890: 31 c0                	xorl	%eax, %eax
ffffffff81059892: e8 7e 28 50 00       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81059897: bb f2 ff ff ff       	movl	$0xfffffff2, %ebx       # imm = 0xFFFFFFF2
ffffffff8105989c: eb 4b                	jmp	0xffffffff810598e9 <.text+0x598e9>
ffffffff8105989e: 4d 8b 24 24          	movq	(%r12), %r12
ffffffff810598a2: 49 81 fc 30 e3 a1 81 	cmpq	$-0x7e5e1cd0, %r12      # imm = 0x81A1E330
ffffffff810598a9: 74 39                	je	0xffffffff810598e4 <.text+0x598e4>
ffffffff810598ab: 49 8b 74 24 20       	movq	0x20(%r12), %rsi
ffffffff810598b0: 48 c7 c7 68 e1 7e 81 	movq	$-0x7e811e98, %rdi      # imm = 0x817EE168
ffffffff810598b7: e8 96 b6 1a 00       	callq	0xffffffff81204f52 <.text+0x204f52>
ffffffff810598bc: 85 c0                	testl	%eax, %eax
ffffffff810598be: 89 c3                	movl	%eax, %ebx
ffffffff810598c0: 75 dc                	jne	0xffffffff8105989e <.text+0x5989e>
ffffffff810598c2: 49 8b 7c 24 28       	movq	0x28(%r12), %rdi
ffffffff810598c7: 49 8d 4d 04          	leaq	0x4(%r13), %rcx
ffffffff810598cb: 31 c0                	xorl	%eax, %eax
ffffffff810598cd: 4c 89 ea             	movq	%r13, %rdx
ffffffff810598d0: 48 c7 c6 6e e1 7e 81 	movq	$-0x7e811e92, %rsi      # imm = 0x817EE16E
ffffffff810598d7: e8 a3 c8 1a 00       	callq	0xffffffff8120617f <.text+0x20617f>
ffffffff810598dc: 83 f8 02             	cmpl	$0x2, %eax
ffffffff810598df: 0f 45 d8             	cmovnel	%eax, %ebx
ffffffff810598e2: eb 05                	jmp	0xffffffff810598e9 <.text+0x598e9>
ffffffff810598e4: bb c3 ff ff ff       	movl	$0xffffffc3, %ebx       # imm = 0xFFFFFFC3
ffffffff810598e9: 5a                   	popq	%rdx
ffffffff810598ea: 89 d8                	movl	%ebx, %eax
ffffffff810598ec: 5b                   	popq	%rbx
ffffffff810598ed: 41 5c                	popq	%r12
ffffffff810598ef: 41 5d                	popq	%r13
ffffffff810598f1: 5d                   	popq	%rbp
ffffffff810598f2: c3                   	retq

# keystore_register [0xffffffff811c17ab,0xffffffff811c18fb)

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff811c17ab: 55                   	pushq	%rbp
ffffffff811c17ac: 48 89 e5             	movq	%rsp, %rbp
ffffffff811c17af: 41 56                	pushq	%r14
ffffffff811c17b1: 41 55                	pushq	%r13
ffffffff811c17b3: 41 54                	pushq	%r12
ffffffff811c17b5: 53                   	pushq	%rbx
ffffffff811c17b6: 41 89 fe             	movl	%edi, %r14d
ffffffff811c17b9: 49 89 f5             	movq	%rsi, %r13
ffffffff811c17bc: 48 83 ec 50          	subq	$0x50, %rsp
ffffffff811c17c0: 65 48 8b 04 25 28 00 00 00   	movq	%gs:0x28, %rax
ffffffff811c17c9: 48 89 45 d8          	movq	%rax, -0x28(%rbp)
ffffffff811c17cd: 31 c0                	xorl	%eax, %eax
ffffffff811c17cf: f6 05 84 de 90 00 04 	testb	$0x4, 0x90de84(%rip)    # 0xffffffff81acf65a
ffffffff811c17d6: 74 1a                	je	0xffffffff811c17f2 <.text+0x1c17f2>
ffffffff811c17d8: 48 c7 c2 b0 56 62 81 	movq	$-0x7e9da950, %rdx      # imm = 0x816256B0
ffffffff811c17df: 48 c7 c6 56 fe 80 81 	movq	$-0x7e7f01aa, %rsi      # imm = 0x8180FE56
ffffffff811c17e6: 48 c7 c7 38 f6 ac 81 	movq	$-0x7e5309c8, %rdi      # imm = 0x81ACF638
ffffffff811c17ed: e8 44 b2 05 00       	callq	0xffffffff8121ca36 <.text+0x21ca36>
ffffffff811c17f2: 4d 85 ed             	testq	%r13, %r13
ffffffff811c17f5: bb f2 ff ff ff       	movl	$0xfffffff2, %ebx       # imm = 0xFFFFFFF2
ffffffff811c17fa: 0f 84 b0 00 00 00    	je	0xffffffff811c18b0 <.text+0x1c18b0>
ffffffff811c1800: 48 8d 7d b8          	leaq	-0x48(%rbp), %rdi
ffffffff811c1804: be 20 00 00 00       	movl	$0x20, %esi
ffffffff811c1809: e8 b4 16 00 00       	callq	0xffffffff811c2ec2 <.text+0x1c2ec2>
ffffffff811c180e: 85 c0                	testl	%eax, %eax
ffffffff811c1810: 89 c3                	movl	%eax, %ebx
ffffffff811c1812: 74 1c                	je	0xffffffff811c1830 <.text+0x1c1830>
ffffffff811c1814: 89 c2                	movl	%eax, %edx
ffffffff811c1816: 48 c7 c6 b0 56 62 81 	movq	$-0x7e9da950, %rsi      # imm = 0x816256B0
ffffffff811c181d: 48 c7 c7 6c fe 80 81 	movq	$-0x7e7f0194, %rdi      # imm = 0x8180FE6C
ffffffff811c1824: 31 c0                	xorl	%eax, %eax
ffffffff811c1826: e8 ea a8 39 00       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff811c182b: e9 80 00 00 00       	jmp	0xffffffff811c18b0 <.text+0x1c18b0>
ffffffff811c1830: 4c 8d 65 98          	leaq	-0x68(%rbp), %r12
ffffffff811c1834: 48 8d 75 b8          	leaq	-0x48(%rbp), %rsi
ffffffff811c1838: 41 b8 20 00 00 00    	movl	$0x20, %r8d
ffffffff811c183e: ba 20 00 00 00       	movl	$0x20, %edx
ffffffff811c1843: 44 89 f7             	movl	%r14d, %edi
ffffffff811c1846: 4c 89 e1             	movq	%r12, %rcx
ffffffff811c1849: e8 02 18 00 00       	callq	0xffffffff811c3050 <.text+0x1c3050>
ffffffff811c184e: 85 c0                	testl	%eax, %eax
ffffffff811c1850: 89 c3                	movl	%eax, %ebx
ffffffff811c1852: 74 19                	je	0xffffffff811c186d <.text+0x1c186d>
ffffffff811c1854: 89 c2                	movl	%eax, %edx
ffffffff811c1856: 48 c7 c6 b0 56 62 81 	movq	$-0x7e9da950, %rsi      # imm = 0x816256B0
ffffffff811c185d: 48 c7 c7 9c fe 80 81 	movq	$-0x7e7f0164, %rdi      # imm = 0x8180FE9C
ffffffff811c1864: 31 c0                	xorl	%eax, %eax
ffffffff811c1866: e8 aa a8 39 00       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff811c186b: eb 37                	jmp	0xffffffff811c18a4 <.text+0x1c18a4>
ffffffff811c186d: be 08 00 00 00       	movl	$0x8, %esi
ffffffff811c1872: 4c 89 ef             	movq	%r13, %rdi
ffffffff811c1875: e8 3d 73 00 00       	callq	0xffffffff811c8bb7 <.text+0x1c8bb7>
ffffffff811c187a: 48 8d 55 b8          	leaq	-0x48(%rbp), %rdx
ffffffff811c187e: 4c 89 e6             	movq	%r12, %rsi
ffffffff811c1881: 4c 89 ef             	movq	%r13, %rdi
ffffffff811c1884: e8 4a 21 00 00       	callq	0xffffffff811c39d3 <.text+0x1c39d3>
ffffffff811c1889: 85 c0                	testl	%eax, %eax
ffffffff811c188b: 89 c3                	movl	%eax, %ebx
ffffffff811c188d: 74 15                	je	0xffffffff811c18a4 <.text+0x1c18a4>
ffffffff811c188f: 48 c7 c6 b0 56 62 81 	movq	$-0x7e9da950, %rsi      # imm = 0x816256B0
ffffffff811c1896: 48 c7 c7 cd fe 80 81 	movq	$-0x7e7f0133, %rdi      # imm = 0x8180FECD
ffffffff811c189d: 31 c0                	xorl	%eax, %eax
ffffffff811c189f: e8 71 a8 39 00       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff811c18a4: b9 08 00 00 00       	movl	$0x8, %ecx
ffffffff811c18a9: 31 c0                	xorl	%eax, %eax
ffffffff811c18ab: 4c 89 e7             	movq	%r12, %rdi
ffffffff811c18ae: f3 ab                	rep		stosl	%eax, %es:(%rdi)
ffffffff811c18b0: f6 05 7b dd 90 00 04 	testb	$0x4, 0x90dd7b(%rip)    # 0xffffffff81acf632
ffffffff811c18b7: 74 1f                	je	0xffffffff811c18d8 <.text+0x1c18d8>
ffffffff811c18b9: 48 63 cb             	movslq	%ebx, %rcx
ffffffff811c18bc: 48 c7 c2 b0 56 62 81 	movq	$-0x7e9da950, %rdx      # imm = 0x816256B0
ffffffff811c18c3: 48 c7 c6 f6 fe 80 81 	movq	$-0x7e7f010a, %rsi      # imm = 0x8180FEF6
ffffffff811c18ca: 48 c7 c7 10 f6 ac 81 	movq	$-0x7e5309f0, %rdi      # imm = 0x81ACF610
ffffffff811c18d1: 31 c0                	xorl	%eax, %eax
ffffffff811c18d3: e8 5e b1 05 00       	callq	0xffffffff8121ca36 <.text+0x21ca36>
ffffffff811c18d8: 48 8b 4d d8          	movq	-0x28(%rbp), %rcx
ffffffff811c18dc: 65 48 33 0c 25 28 00 00 00   	xorq	%gs:0x28, %rcx
ffffffff811c18e5: 89 d8                	movl	%ebx, %eax
ffffffff811c18e7: 74 05                	je	0xffffffff811c18ee <.text+0x1c18ee>
ffffffff811c18e9: e8 40 a8 e9 ff       	callq	0xffffffff8105c12e <.text+0x5c12e>
ffffffff811c18ee: 48 83 c4 50          	addq	$0x50, %rsp
ffffffff811c18f2: 5b                   	popq	%rbx
ffffffff811c18f3: 41 5c                	popq	%r12
ffffffff811c18f5: 41 5d                	popq	%r13
ffffffff811c18f7: 41 5e                	popq	%r14
ffffffff811c18f9: 5d                   	popq	%rbp
ffffffff811c18fa: c3                   	retq

# verify_oem_signature [0xffffffff811c5a36,0xffffffff811c5bad)

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff811c5a36: 55                   	pushq	%rbp
ffffffff811c5a37: 48 89 e5             	movq	%rsp, %rbp
ffffffff811c5a3a: 41 56                	pushq	%r14
ffffffff811c5a3c: 41 55                	pushq	%r13
ffffffff811c5a3e: 41 54                	pushq	%r12
ffffffff811c5a40: 53                   	pushq	%rbx
ffffffff811c5a41: 41 89 f6             	movl	%esi, %r14d
ffffffff811c5a44: 48 89 fb             	movq	%rdi, %rbx
ffffffff811c5a47: 49 89 d4             	movq	%rdx, %r12
ffffffff811c5a4a: 41 89 cd             	movl	%ecx, %r13d
ffffffff811c5a4d: 48 83 ec 30          	subq	$0x30, %rsp
ffffffff811c5a51: 65 48 8b 04 25 28 00 00 00   	movq	%gs:0x28, %rax
ffffffff811c5a5a: 48 89 45 d8          	movq	%rax, -0x28(%rbp)
ffffffff811c5a5e: 31 c0                	xorl	%eax, %eax
ffffffff811c5a60: f6 05 2b a5 90 00 04 	testb	$0x4, 0x90a52b(%rip)    # 0xffffffff81acff92
ffffffff811c5a67: 74 1a                	je	0xffffffff811c5a83 <.text+0x1c5a83>
ffffffff811c5a69: 48 c7 c2 90 59 62 81 	movq	$-0x7e9da670, %rdx      # imm = 0x81625990
ffffffff811c5a70: 48 c7 c6 56 fe 80 81 	movq	$-0x7e7f01aa, %rsi      # imm = 0x8180FE56
ffffffff811c5a77: 48 c7 c7 70 ff ac 81 	movq	$-0x7e530090, %rdi      # imm = 0x81ACFF70
ffffffff811c5a7e: e8 b3 6f 05 00       	callq	0xffffffff8121ca36 <.text+0x21ca36>
ffffffff811c5a83: 48 85 db             	testq	%rbx, %rbx
ffffffff811c5a86: 74 05                	je	0xffffffff811c5a8d <.text+0x1c5a8d>
ffffffff811c5a88: 4d 85 e4             	testq	%r12, %r12
ffffffff811c5a8b: 75 33                	jne	0xffffffff811c5ac0 <.text+0x1c5ac0>
ffffffff811c5a8d: f6 05 d6 a4 90 00 04 	testb	$0x4, 0x90a4d6(%rip)    # 0xffffffff81acff6a
ffffffff811c5a94: bb f2 ff ff ff       	movl	$0xfffffff2, %ebx       # imm = 0xFFFFFFF2
ffffffff811c5a99: 0f 84 eb 00 00 00    	je	0xffffffff811c5b8a <.text+0x1c5b8a>
ffffffff811c5a9f: 48 c7 c1 f2 ff ff ff 	movq	$-0xe, %rcx
ffffffff811c5aa6: 48 c7 c2 90 59 62 81 	movq	$-0x7e9da670, %rdx      # imm = 0x81625990
ffffffff811c5aad: 48 c7 c6 f6 fe 80 81 	movq	$-0x7e7f010a, %rsi      # imm = 0x8180FEF6
ffffffff811c5ab4: 48 c7 c7 48 ff ac 81 	movq	$-0x7e5300b8, %rdi      # imm = 0x81ACFF48
ffffffff811c5abb: e9 c3 00 00 00       	jmp	0xffffffff811c5b83 <.text+0x1c5b83>
ffffffff811c5ac0: 48 8d 55 b8          	leaq	-0x48(%rbp), %rdx
ffffffff811c5ac4: 48 89 df             	movq	%rbx, %rdi
ffffffff811c5ac7: b9 20 00 00 00       	movl	$0x20, %ecx
ffffffff811c5acc: 44 89 f6             	movl	%r14d, %esi
ffffffff811c5acf: e8 e7 2f 00 00       	callq	0xffffffff811c8abb <.text+0x1c8abb>
ffffffff811c5ad4: 85 c0                	testl	%eax, %eax
ffffffff811c5ad6: 89 c3                	movl	%eax, %ebx
ffffffff811c5ad8: 79 3e                	jns	0xffffffff811c5b18 <.text+0x1c5b18>
ffffffff811c5ada: 89 c6                	movl	%eax, %esi
ffffffff811c5adc: 48 c7 c2 90 59 62 81 	movq	$-0x7e9da670, %rdx      # imm = 0x81625990
ffffffff811c5ae3: 31 c0                	xorl	%eax, %eax
ffffffff811c5ae5: 48 c7 c7 05 10 81 81 	movq	$-0x7e7eeffb, %rdi      # imm = 0x81811005
ffffffff811c5aec: e8 24 66 39 00       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff811c5af1: f6 05 4a a4 90 00 04 	testb	$0x4, 0x90a44a(%rip)    # 0xffffffff81acff42
ffffffff811c5af8: 0f 84 8c 00 00 00    	je	0xffffffff811c5b8a <.text+0x1c5b8a>
ffffffff811c5afe: 48 63 cb             	movslq	%ebx, %rcx
ffffffff811c5b01: 48 c7 c2 90 59 62 81 	movq	$-0x7e9da670, %rdx      # imm = 0x81625990
ffffffff811c5b08: 48 c7 c6 f6 fe 80 81 	movq	$-0x7e7f010a, %rsi      # imm = 0x8180FEF6
ffffffff811c5b0f: 48 c7 c7 20 ff ac 81 	movq	$-0x7e5300e0, %rdi      # imm = 0x81ACFF20
ffffffff811c5b16: eb 6b                	jmp	0xffffffff811c5b83 <.text+0x1c5b83>
ffffffff811c5b18: 48 8d 75 b8          	leaq	-0x48(%rbp), %rsi
ffffffff811c5b1c: ba 20 00 00 00       	movl	$0x20, %edx
ffffffff811c5b21: 48 c7 c7 39 10 81 81 	movq	$-0x7e7eefc7, %rdi      # imm = 0x81811039
ffffffff811c5b28: e8 29 43 00 00       	callq	0xffffffff811c9e56 <.text+0x1c9e56>
ffffffff811c5b2d: 44 89 ea             	movl	%r13d, %edx
ffffffff811c5b30: 4c 89 e6             	movq	%r12, %rsi
ffffffff811c5b33: 48 c7 c7 40 10 81 81 	movq	$-0x7e7eefc0, %rdi      # imm = 0x81811040
ffffffff811c5b3a: e8 17 43 00 00       	callq	0xffffffff811c9e56 <.text+0x1c9e56>
ffffffff811c5b3f: 48 8d 7d b8          	leaq	-0x48(%rbp), %rdi
ffffffff811c5b43: 41 b9 2f 00 00 00    	movl	$0x2f, %r9d
ffffffff811c5b49: 49 c7 c0 4a 10 81 81 	movq	$-0x7e7eefb6, %r8       # imm = 0x8181104A
ffffffff811c5b50: 44 89 e9             	movl	%r13d, %ecx
ffffffff811c5b53: 4c 89 e2             	movq	%r12, %rdx
ffffffff811c5b56: be 20 00 00 00       	movl	$0x20, %esi
ffffffff811c5b5b: e8 af 6e 00 00       	callq	0xffffffff811cca0f <.text+0x1cca0f>
ffffffff811c5b60: f6 05 b3 a3 90 00 04 	testb	$0x4, 0x90a3b3(%rip)    # 0xffffffff81acff1a
ffffffff811c5b67: 89 c3                	movl	%eax, %ebx
ffffffff811c5b69: 74 1f                	je	0xffffffff811c5b8a <.text+0x1c5b8a>
ffffffff811c5b6b: 48 63 c8             	movslq	%eax, %rcx
ffffffff811c5b6e: 48 c7 c2 90 59 62 81 	movq	$-0x7e9da670, %rdx      # imm = 0x81625990
ffffffff811c5b75: 48 c7 c6 f6 fe 80 81 	movq	$-0x7e7f010a, %rsi      # imm = 0x8180FEF6
ffffffff811c5b7c: 48 c7 c7 f8 fe ac 81 	movq	$-0x7e530108, %rdi      # imm = 0x81ACFEF8
ffffffff811c5b83: 31 c0                	xorl	%eax, %eax
ffffffff811c5b85: e8 ac 6e 05 00       	callq	0xffffffff8121ca36 <.text+0x21ca36>
ffffffff811c5b8a: 48 8b 4d d8          	movq	-0x28(%rbp), %rcx
ffffffff811c5b8e: 65 48 33 0c 25 28 00 00 00   	xorq	%gs:0x28, %rcx
ffffffff811c5b97: 89 d8                	movl	%ebx, %eax
ffffffff811c5b99: 74 05                	je	0xffffffff811c5ba0 <.text+0x1c5ba0>
ffffffff811c5b9b: e8 8e 65 e9 ff       	callq	0xffffffff8105c12e <.text+0x5c12e>
ffffffff811c5ba0: 48 83 c4 30          	addq	$0x30, %rsp
ffffffff811c5ba4: 5b                   	popq	%rbx
ffffffff811c5ba5: 41 5c                	popq	%r12
ffffffff811c5ba7: 41 5d                	popq	%r13
ffffffff811c5ba9: 41 5e                	popq	%r14
ffffffff811c5bab: 5d                   	popq	%rbp
ffffffff811c5bac: c3                   	retq

# manifest_key_verify_digest [0xffffffff811cca0f,0xffffffff811ccc84)

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff811cca0f: 55                   	pushq	%rbp
ffffffff811cca10: 48 89 e5             	movq	%rsp, %rbp
ffffffff811cca13: 41 57                	pushq	%r15
ffffffff811cca15: 41 56                	pushq	%r14
ffffffff811cca17: 41 55                	pushq	%r13
ffffffff811cca19: 41 54                	pushq	%r12
ffffffff811cca1b: 53                   	pushq	%rbx
ffffffff811cca1c: 48 83 ec 78          	subq	$0x78, %rsp
ffffffff811cca20: 89 b5 7c ff ff ff    	movl	%esi, -0x84(%rbp)
ffffffff811cca26: 89 8d 78 ff ff ff    	movl	%ecx, -0x88(%rbp)
ffffffff811cca2c: 65 48 8b 04 25 28 00 00 00   	movq	%gs:0x28, %rax
ffffffff811cca35: 48 89 45 c8          	movq	%rax, -0x38(%rbp)
ffffffff811cca39: 31 c0                	xorl	%eax, %eax
ffffffff811cca3b: 48 85 ff             	testq	%rdi, %rdi
ffffffff811cca3e: 0f 84 18 02 00 00    	je	0xffffffff811ccc5c <.text+0x1ccc5c>
ffffffff811cca44: 48 85 d2             	testq	%rdx, %rdx
ffffffff811cca47: 49 89 d6             	movq	%rdx, %r14
ffffffff811cca4a: 0f 84 0c 02 00 00    	je	0xffffffff811ccc5c <.text+0x1ccc5c>
ffffffff811cca50: f6 05 9b 39 90 00 04 	testb	$0x4, 0x90399b(%rip)    # 0xffffffff81ad03f2
ffffffff811cca57: 49 89 fd             	movq	%rdi, %r13
ffffffff811cca5a: 74 32                	je	0xffffffff811cca8e <.text+0x1cca8e>
ffffffff811cca5c: 44 89 ca             	movl	%r9d, %edx
ffffffff811cca5f: 48 c7 c6 ec 2d 81 81 	movq	$-0x7e7ed214, %rsi      # imm = 0x81812DEC
ffffffff811cca66: 48 c7 c7 d0 03 ad 81 	movq	$-0x7e52fc30, %rdi      # imm = 0x81AD03D0
ffffffff811cca6d: 4c 89 85 68 ff ff ff 	movq	%r8, -0x98(%rbp)
ffffffff811cca74: 44 89 8d 74 ff ff ff 	movl	%r9d, -0x8c(%rbp)
ffffffff811cca7b: e8 b6 ff 04 00       	callq	0xffffffff8121ca36 <.text+0x21ca36>
ffffffff811cca80: 4c 8b 85 68 ff ff ff 	movq	-0x98(%rbp), %r8
ffffffff811cca87: 44 8b 8d 74 ff ff ff 	movl	-0x8c(%rbp), %r9d
ffffffff811cca8e: 48 8d 7d 88          	leaq	-0x78(%rbp), %rdi
ffffffff811cca92: 31 c0                	xorl	%eax, %eax
ffffffff811cca94: b9 04 00 00 00       	movl	$0x4, %ecx
ffffffff811cca99: 44 89 ca             	movl	%r9d, %edx
ffffffff811cca9c: f3 ab                	rep		stosl	%eax, %es:(%rdi)
ffffffff811cca9e: c1 ea 05             	shrl	$0x5, %edx
ffffffff811ccaa1: 44 89 c9             	movl	%r9d, %ecx
ffffffff811ccaa4: b8 ea ff ff ff       	movl	$0xffffffea, %eax       # imm = 0xFFFFFFEA
ffffffff811ccaa9: 83 e1 1f             	andl	$0x1f, %ecx
ffffffff811ccaac: 83 fa 03             	cmpl	$0x3, %edx
ffffffff811ccaaf: 0f 87 ac 01 00 00    	ja	0xffffffff811ccc61 <.text+0x1ccc61>
ffffffff811ccab5: b8 01 00 00 00       	movl	$0x1, %eax
ffffffff811ccaba: d3 e0                	shll	%cl, %eax
ffffffff811ccabc: 4d 85 c0             	testq	%r8, %r8
ffffffff811ccabf: 89 44 95 88          	movl	%eax, -0x78(%rbp,%rdx,4)
ffffffff811ccac3: 75 0c                	jne	0xffffffff811ccad1 <.text+0x1ccad1>
ffffffff811ccac5: 49 c7 c7 f2 ff ff ff 	movq	$-0xe, %r15
ffffffff811ccacc: e9 48 01 00 00       	jmp	0xffffffff811ccc19 <.text+0x1ccc19>
ffffffff811ccad1: 48 8b 3d f8 e7 a5 00 	movq	0xa5e7f8(%rip), %rdi    # 0xffffffff81c2b2d0
ffffffff811ccad8: 4c 89 c2             	movq	%r8, %rdx
ffffffff811ccadb: 48 c7 c6 60 23 a3 81 	movq	$-0x7e5cdca0, %rsi      # imm = 0x81A32360
ffffffff811ccae2: 48 83 cf 01          	orq	$0x1, %rdi
ffffffff811ccae6: e8 7d 75 fe ff       	callq	0xffffffff811b4068 <.text+0x1b4068>
ffffffff811ccaeb: 49 89 c7             	movq	%rax, %r15
ffffffff811ccaee: 49 83 e7 fe          	andq	$-0x2, %r15
ffffffff811ccaf2: 48 3d 00 f0 ff ff    	cmpq	$-0x1000, %rax          # imm = 0xF000
ffffffff811ccaf8: 76 2c                	jbe	0xffffffff811ccb26 <.text+0x1ccb26>
ffffffff811ccafa: 48 8d 48 14          	leaq	0x14(%rax), %rcx
ffffffff811ccafe: 48 83 f9 09          	cmpq	$0x9, %rcx
ffffffff811ccb02: 77 1f                	ja	0xffffffff811ccb23 <.text+0x1ccb23>
ffffffff811ccb04: ba 01 00 00 00       	movl	$0x1, %edx
ffffffff811ccb09: 49 89 c7             	movq	%rax, %r15
ffffffff811ccb0c: 48 d3 e2             	shlq	%cl, %rdx
ffffffff811ccb0f: f7 c2 81 02 00 00    	testl	$0x281, %edx            # imm = 0x281
ffffffff811ccb15: 74 0f                	je	0xffffffff811ccb26 <.text+0x1ccb26>
ffffffff811ccb17: 49 c7 c7 82 ff ff ff 	movq	$-0x7e, %r15
ffffffff811ccb1e: e9 f6 00 00 00       	jmp	0xffffffff811ccc19 <.text+0x1ccc19>
ffffffff811ccb23: 49 89 c7             	movq	%rax, %r15
ffffffff811ccb26: 49 81 ff 00 f0 ff ff 	cmpq	$-0x1000, %r15          # imm = 0xF000
ffffffff811ccb2d: 0f 87 e6 00 00 00    	ja	0xffffffff811ccc19 <.text+0x1ccc19>
ffffffff811ccb33: 49 83 bf a8 00 00 00 00      	cmpq	$0x0, 0xa8(%r15)
ffffffff811ccb3b: 74 88                	je	0xffffffff811ccac5 <.text+0x1ccac5>
ffffffff811ccb3d: 49 83 bf 88 00 00 00 00      	cmpq	$0x0, 0x88(%r15)
ffffffff811ccb45: 0f 84 7a ff ff ff    	je	0xffffffff811ccac5 <.text+0x1ccac5>
ffffffff811ccb4b: 48 8d 5d bb          	leaq	-0x45(%rbp), %rbx
ffffffff811ccb4f: 31 c0                	xorl	%eax, %eax
ffffffff811ccb51: b9 0d 00 00 00       	movl	$0xd, %ecx
ffffffff811ccb56: ba 06 00 00 00       	movl	$0x6, %edx
ffffffff811ccb5b: 48 c7 c6 09 2e 81 81 	movq	$-0x7e7ed1f7, %rsi      # imm = 0x81812E09
ffffffff811ccb62: 48 89 df             	movq	%rbx, %rdi
ffffffff811ccb65: f3 aa                	rep		stosb	%al, %es:(%rdi)
ffffffff811ccb67: 48 89 df             	movq	%rbx, %rdi
ffffffff811ccb6a: e8 1a 49 04 00       	callq	0xffffffff81211489 <.text+0x211489>
ffffffff811ccb6f: 4d 8b a7 88 00 00 00 	movq	0x88(%r15), %r12
ffffffff811ccb76: 48 89 de             	movq	%rbx, %rsi
ffffffff811ccb79: 4c 89 e7             	movq	%r12, %rdi
ffffffff811ccb7c: e8 ac 86 03 00       	callq	0xffffffff8120522d <.text+0x20522d>
ffffffff811ccb81: 48 85 c0             	testq	%rax, %rax
ffffffff811ccb84: 74 42                	je	0xffffffff811ccbc8 <.text+0x1ccbc8>
ffffffff811ccb86: 48 8d 5d 98          	leaq	-0x68(%rbp), %rbx
ffffffff811ccb8a: 48 8d 70 0c          	leaq	0xc(%rax), %rsi
ffffffff811ccb8e: ba 10 00 00 00       	movl	$0x10, %edx
ffffffff811ccb93: 48 89 df             	movq	%rbx, %rdi
ffffffff811ccb96: e8 9e 48 04 00       	callq	0xffffffff81211439 <.text+0x211439>
ffffffff811ccb9b: 85 c0                	testl	%eax, %eax
ffffffff811ccb9d: 74 10                	je	0xffffffff811ccbaf <.text+0x1ccbaf>
ffffffff811ccb9f: 49 8b b7 88 00 00 00 	movq	0x88(%r15), %rsi
ffffffff811ccba6: 48 c7 c7 10 2e 81 81 	movq	$-0x7e7ed1f0, %rdi      # imm = 0x81812E10
ffffffff811ccbad: eb 23                	jmp	0xffffffff811ccbd2 <.text+0x1ccbd2>
ffffffff811ccbaf: 48 8d 7d 88          	leaq	-0x78(%rbp), %rdi
ffffffff811ccbb3: 48 89 de             	movq	%rbx, %rsi
ffffffff811ccbb6: e8 1c fe ff ff       	callq	0xffffffff811cc9d7 <.text+0x1cc9d7>
ffffffff811ccbbb: 85 c0                	testl	%eax, %eax
ffffffff811ccbbd: 74 23                	je	0xffffffff811ccbe2 <.text+0x1ccbe2>
ffffffff811ccbbf: 49 c7 c7 fd ff ff ff 	movq	$-0x3, %r15
ffffffff811ccbc6: eb 51                	jmp	0xffffffff811ccc19 <.text+0x1ccc19>
ffffffff811ccbc8: 4c 89 e6             	movq	%r12, %rsi
ffffffff811ccbcb: 48 c7 c7 48 2e 81 81 	movq	$-0x7e7ed1b8, %rdi      # imm = 0x81812E48
ffffffff811ccbd2: 31 c0                	xorl	%eax, %eax
ffffffff811ccbd4: 49 c7 c7 ea ff ff ff 	movq	$-0x16, %r15
ffffffff811ccbdb: e8 35 f5 38 00       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff811ccbe0: eb 37                	jmp	0xffffffff811ccc19 <.text+0x1ccc19>
ffffffff811ccbe2: 8b b5 78 ff ff ff    	movl	-0x88(%rbp), %esi
ffffffff811ccbe8: 4c 89 f7             	movq	%r14, %rdi
ffffffff811ccbeb: 89 85 74 ff ff ff    	movl	%eax, -0x8c(%rbp)
ffffffff811ccbf1: e8 26 1f 05 00       	callq	0xffffffff8121eb1c <.text+0x21eb1c>
ffffffff811ccbf6: 48 85 c0             	testq	%rax, %rax
ffffffff811ccbf9: 49 89 c4             	movq	%rax, %r12
ffffffff811ccbfc: 8b 95 74 ff ff ff    	movl	-0x8c(%rbp), %edx
ffffffff811ccc02: 75 1a                	jne	0xffffffff811ccc1e <.text+0x1ccc1e>
ffffffff811ccc04: 48 c7 c7 70 2e 81 81 	movq	$-0x7e7ed190, %rdi      # imm = 0x81812E70
ffffffff811ccc0b: 31 c0                	xorl	%eax, %eax
ffffffff811ccc0d: e8 03 f5 38 00       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff811ccc12: b8 ea ff ff ff       	movl	$0xffffffea, %eax       # imm = 0xFFFFFFEA
ffffffff811ccc17: eb 48                	jmp	0xffffffff811ccc61 <.text+0x1ccc61>
ffffffff811ccc19: 44 89 f8             	movl	%r15d, %eax
ffffffff811ccc1c: eb 43                	jmp	0xffffffff811ccc61 <.text+0x1ccc61>
ffffffff811ccc1e: 89 d0                	movl	%edx, %eax
ffffffff811ccc20: 48 89 df             	movq	%rbx, %rdi
ffffffff811ccc23: b9 08 00 00 00       	movl	$0x8, %ecx
ffffffff811ccc28: f3 ab                	rep		stosl	%eax, %es:(%rdi)
ffffffff811ccc2a: 8a 85 7c ff ff ff    	movb	-0x84(%rbp), %al
ffffffff811ccc30: 48 89 de             	movq	%rbx, %rsi
ffffffff811ccc33: 4c 89 ff             	movq	%r15, %rdi
ffffffff811ccc36: 4c 89 6d 98          	movq	%r13, -0x68(%rbp)
ffffffff811ccc3a: c6 45 a1 01          	movb	$0x1, -0x5f(%rbp)
ffffffff811ccc3e: c6 45 a3 04          	movb	$0x4, -0x5d(%rbp)
ffffffff811ccc42: 4c 89 65 a8          	movq	%r12, -0x58(%rbp)
ffffffff811ccc46: 88 45 a0             	movb	%al, -0x60(%rbp)
ffffffff811ccc49: e8 93 3b 01 00       	callq	0xffffffff811e07e1 <.text+0x1e07e1>
ffffffff811ccc4e: 4c 89 e7             	movq	%r12, %rdi
ffffffff811ccc51: 89 c3                	movl	%eax, %ebx
ffffffff811ccc53: e8 c6 3f 05 00       	callq	0xffffffff81220c1e <.text+0x220c1e>
ffffffff811ccc58: 89 d8                	movl	%ebx, %eax
ffffffff811ccc5a: eb 05                	jmp	0xffffffff811ccc61 <.text+0x1ccc61>
ffffffff811ccc5c: b8 f2 ff ff ff       	movl	$0xfffffff2, %eax       # imm = 0xFFFFFFF2
ffffffff811ccc61: 48 8b 5d c8          	movq	-0x38(%rbp), %rbx
ffffffff811ccc65: 65 48 33 1c 25 28 00 00 00   	xorq	%gs:0x28, %rbx
ffffffff811ccc6e: 74 05                	je	0xffffffff811ccc75 <.text+0x1ccc75>
ffffffff811ccc70: e8 b9 f4 e8 ff       	callq	0xffffffff8105c12e <.text+0x5c12e>
ffffffff811ccc75: 48 83 c4 78          	addq	$0x78, %rsp
ffffffff811ccc79: 5b                   	popq	%rbx
ffffffff811ccc7a: 41 5c                	popq	%r12
ffffffff811ccc7c: 41 5d                	popq	%r13
ffffffff811ccc7e: 41 5e                	popq	%r14
ffffffff811ccc80: 41 5f                	popq	%r15
ffffffff811ccc82: 5d                   	popq	%rbp
ffffffff811ccc83: c3                   	retq

# device_create_groups_vargs [0xffffffff81399b24,0xffffffff81399c01)

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff81399b24: 55                   	pushq	%rbp
ffffffff81399b25: 48 89 e5             	movq	%rsp, %rbp
ffffffff81399b28: 41 57                	pushq	%r15
ffffffff81399b2a: 41 56                	pushq	%r14
ffffffff81399b2c: 41 55                	pushq	%r13
ffffffff81399b2e: 41 54                	pushq	%r12
ffffffff81399b30: 53                   	pushq	%rbx
ffffffff81399b31: 48 83 ec 18          	subq	$0x18, %rsp
ffffffff81399b35: 48 85 ff             	testq	%rdi, %rdi
ffffffff81399b38: 4c 89 45 c0          	movq	%r8, -0x40(%rbp)
ffffffff81399b3c: 4c 89 4d c8          	movq	%r9, -0x38(%rbp)
ffffffff81399b40: 0f 84 92 00 00 00    	je	0xffffffff81399bd8 <.text+0x399bd8>
ffffffff81399b46: 48 81 ff 00 f0 ff ff 	cmpq	$-0x1000, %rdi          # imm = 0xF000
ffffffff81399b4d: 48 89 fb             	movq	%rdi, %rbx
ffffffff81399b50: 0f 87 82 00 00 00    	ja	0xffffffff81399bd8 <.text+0x399bd8>
ffffffff81399b56: bf 88 02 00 00       	movl	$0x288, %edi            # imm = 0x288
ffffffff81399b5b: 49 89 f6             	movq	%rsi, %r14
ffffffff81399b5e: 41 89 d7             	movl	%edx, %r15d
ffffffff81399b61: 49 89 cd             	movq	%rcx, %r13
ffffffff81399b64: e8 36 f0 ff ff       	callq	0xffffffff81398b9f <.text+0x398b9f>
ffffffff81399b69: 48 85 c0             	testq	%rax, %rax
ffffffff81399b6c: 49 89 c4             	movq	%rax, %r12
ffffffff81399b6f: 74 71                	je	0xffffffff81399be2 <.text+0x399be2>
ffffffff81399b71: 48 89 c7             	movq	%rax, %rdi
ffffffff81399b74: e8 a7 e3 ff ff       	callq	0xffffffff81397f20 <.text+0x397f20>
ffffffff81399b79: 4c 8b 45 c0          	movq	-0x40(%rbp), %r8
ffffffff81399b7d: 48 8b 55 10          	movq	0x10(%rbp), %rdx
ffffffff81399b81: 49 8d 7c 24 10       	leaq	0x10(%r12), %rdi
ffffffff81399b86: 48 8b 75 c8          	movq	-0x38(%rbp), %rsi
ffffffff81399b8a: 49 89 9c 24 60 02 00 00      	movq	%rbx, 0x260(%r12)
ffffffff81399b92: 45 89 bc 24 20 02 00 00      	movl	%r15d, 0x220(%r12)
ffffffff81399b9a: 4d 89 34 24          	movq	%r14, (%r12)
ffffffff81399b9e: 4d 89 84 24 68 02 00 00      	movq	%r8, 0x268(%r12)
ffffffff81399ba6: 49 c7 84 24 70 02 00 00 2a 80 39 81  	movq	$-0x7ec67fd6, 0x270(%r12) # imm = 0x8139802A
ffffffff81399bb2: 4d 89 ac 24 a0 00 00 00      	movq	%r13, 0xa0(%r12)
ffffffff81399bba: e8 d5 6a e6 ff       	callq	0xffffffff81200694 <.text+0x200694>
ffffffff81399bbf: 85 c0                	testl	%eax, %eax
ffffffff81399bc1: 89 c3                	movl	%eax, %ebx
ffffffff81399bc3: 75 22                	jne	0xffffffff81399be7 <.text+0x399be7>
ffffffff81399bc5: 4c 89 e7             	movq	%r12, %rdi
ffffffff81399bc8: e8 34 f9 ff ff       	callq	0xffffffff81399501 <.text+0x399501>
ffffffff81399bcd: 89 c3                	movl	%eax, %ebx
ffffffff81399bcf: 4c 89 e0             	movq	%r12, %rax
ffffffff81399bd2: 85 db                	testl	%ebx, %ebx
ffffffff81399bd4: 75 11                	jne	0xffffffff81399be7 <.text+0x399be7>
ffffffff81399bd6: eb 1a                	jmp	0xffffffff81399bf2 <.text+0x399bf2>
ffffffff81399bd8: bb ed ff ff ff       	movl	$0xffffffed, %ebx       # imm = 0xFFFFFFED
ffffffff81399bdd: 45 31 e4             	xorl	%r12d, %r12d
ffffffff81399be0: eb 05                	jmp	0xffffffff81399be7 <.text+0x399be7>
ffffffff81399be2: bb f4 ff ff ff       	movl	$0xfffffff4, %ebx       # imm = 0xFFFFFFF4
ffffffff81399be7: 4c 89 e7             	movq	%r12, %rdi
ffffffff81399bea: e8 29 e5 ff ff       	callq	0xffffffff81398118 <.text+0x398118>
ffffffff81399bef: 48 63 c3             	movslq	%ebx, %rax
ffffffff81399bf2: 48 83 c4 18          	addq	$0x18, %rsp
ffffffff81399bf6: 5b                   	popq	%rbx
ffffffff81399bf7: 41 5c                	popq	%r12
ffffffff81399bf9: 41 5d                	popq	%r13
ffffffff81399bfb: 41 5e                	popq	%r14
ffffffff81399bfd: 41 5f                	popq	%r15
ffffffff81399bff: 5d                   	popq	%rbp
ffffffff81399c00: c3                   	retq

# device_create_vargs [0xffffffff81399c01,0xffffffff81399c15)

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff81399c01: 55                   	pushq	%rbp
ffffffff81399c02: 48 89 e5             	movq	%rsp, %rbp
ffffffff81399c05: 50                   	pushq	%rax
ffffffff81399c06: 41 51                	pushq	%r9
ffffffff81399c08: 4d 89 c1             	movq	%r8, %r9
ffffffff81399c0b: 45 31 c0             	xorl	%r8d, %r8d
ffffffff81399c0e: e8 11 ff ff ff       	callq	0xffffffff81399b24 <.text+0x399b24>
ffffffff81399c13: c9                   	leave
ffffffff81399c14: c3                   	retq

# device_create [0xffffffff81399c15,0xffffffff81399c66)

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff81399c15: 55                   	pushq	%rbp
ffffffff81399c16: 48 89 e5             	movq	%rsp, %rbp
ffffffff81399c19: 48 83 ec 50          	subq	$0x50, %rsp
ffffffff81399c1d: 65 48 8b 04 25 28 00 00 00   	movq	%gs:0x28, %rax
ffffffff81399c26: 48 89 45 c8          	movq	%rax, -0x38(%rbp)
ffffffff81399c2a: 31 c0                	xorl	%eax, %eax
ffffffff81399c2c: 48 8d 45 10          	leaq	0x10(%rbp), %rax
ffffffff81399c30: 4c 89 4d f8          	movq	%r9, -0x8(%rbp)
ffffffff81399c34: 4c 8d 4d b0          	leaq	-0x50(%rbp), %r9
ffffffff81399c38: c7 45 b0 28 00 00 00 	movl	$0x28, -0x50(%rbp)
ffffffff81399c3f: 48 89 45 b8          	movq	%rax, -0x48(%rbp)
ffffffff81399c43: 48 8d 45 d0          	leaq	-0x30(%rbp), %rax
ffffffff81399c47: 48 89 45 c0          	movq	%rax, -0x40(%rbp)
ffffffff81399c4b: e8 b1 ff ff ff       	callq	0xffffffff81399c01 <.text+0x399c01>
ffffffff81399c50: 48 8b 55 c8          	movq	-0x38(%rbp), %rdx
ffffffff81399c54: 65 48 33 14 25 28 00 00 00   	xorq	%gs:0x28, %rdx
ffffffff81399c5d: 74 05                	je	0xffffffff81399c64 <.text+0x399c64>
ffffffff81399c5f: e8 ca 24 cc ff       	callq	0xffffffff8105c12e <.text+0x5c12e>
ffffffff81399c64: c9                   	leave
ffffffff81399c65: c3                   	retq

# __class_create [0xffffffff8139d681,0xffffffff8139d6ef)

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff8139d681: 55                   	pushq	%rbp
ffffffff8139d682: 48 89 e5             	movq	%rsp, %rbp
ffffffff8139d685: 41 56                	pushq	%r14
ffffffff8139d687: 41 55                	pushq	%r13
ffffffff8139d689: 49 89 fd             	movq	%rdi, %r13
ffffffff8139d68c: 48 8b 3d 45 4a 88 00 	movq	0x884a45(%rip), %rdi    # 0xffffffff81c220d8
ffffffff8139d693: 41 54                	pushq	%r12
ffffffff8139d695: 53                   	pushq	%rbx
ffffffff8139d696: 49 89 f6             	movq	%rsi, %r14
ffffffff8139d699: be d0 80 00 00       	movl	$0x80d0, %esi           # imm = 0x80D0
ffffffff8139d69e: 49 89 d4             	movq	%rdx, %r12
ffffffff8139d6a1: e8 a0 90 d6 ff       	callq	0xffffffff81106746 <.text+0x106746>
ffffffff8139d6a6: 48 85 c0             	testq	%rax, %rax
ffffffff8139d6a9: 48 89 c3             	movq	%rax, %rbx
ffffffff8139d6ac: 74 27                	je	0xffffffff8139d6d5 <.text+0x39d6d5>
ffffffff8139d6ae: 4c 89 e6             	movq	%r12, %rsi
ffffffff8139d6b1: 4c 89 30             	movq	%r14, (%rax)
ffffffff8139d6b4: 4c 89 68 08          	movq	%r13, 0x8(%rax)
ffffffff8139d6b8: 48 c7 40 38 c5 cf 39 81      	movq	$-0x7ec6303b, 0x38(%rax) # imm = 0x8139CFC5
ffffffff8139d6c0: 48 89 c7             	movq	%rax, %rdi
ffffffff8139d6c3: e8 b1 fd ff ff       	callq	0xffffffff8139d479 <.text+0x39d479>
ffffffff8139d6c8: 41 89 c4             	movl	%eax, %r12d
ffffffff8139d6cb: 48 89 d8             	movq	%rbx, %rax
ffffffff8139d6ce: 45 85 e4             	testl	%r12d, %r12d
ffffffff8139d6d1: 75 08                	jne	0xffffffff8139d6db <.text+0x39d6db>
ffffffff8139d6d3: eb 11                	jmp	0xffffffff8139d6e6 <.text+0x39d6e6>
ffffffff8139d6d5: 41 bc f4 ff ff ff    	movl	$0xfffffff4, %r12d      # imm = 0xFFFFFFF4
ffffffff8139d6db: 48 89 df             	movq	%rbx, %rdi
ffffffff8139d6de: e8 db 99 d6 ff       	callq	0xffffffff811070be <.text+0x1070be>
ffffffff8139d6e3: 49 63 c4             	movslq	%r12d, %rax
ffffffff8139d6e6: 5b                   	popq	%rbx
ffffffff8139d6e7: 41 5c                	popq	%r12
ffffffff8139d6e9: 41 5d                	popq	%r13
ffffffff8139d6eb: 41 5e                	popq	%r14
ffffffff8139d6ed: 5d                   	popq	%rbp
ffffffff8139d6ee: c3                   	retq

# keystore_init [0xffffffff81b1dc66,0xffffffff81b1ddd2)

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .init.text:

ffffffff81aff000 <.init.text>:
ffffffff81b1dc66: 55                   	pushq	%rbp
ffffffff81b1dc67: 48 c7 c7 3b fc 80 81 	movq	$-0x7e7f03c5, %rdi      # imm = 0x8180FC3B
ffffffff81b1dc6e: 31 c0                	xorl	%eax, %eax
ffffffff81b1dc70: 48 89 e5             	movq	%rsp, %rbp
ffffffff81b1dc73: 53                   	pushq	%rbx
ffffffff81b1dc74: 51                   	pushq	%rcx
ffffffff81b1dc75: e8 9b e4 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1dc7a: 48 c7 c7 5f fc 80 81 	movq	$-0x7e7f03a1, %rdi      # imm = 0x8180FC5F
ffffffff81b1dc81: 31 c0                	xorl	%eax, %eax
ffffffff81b1dc83: e8 8d e4 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1dc88: e8 31 39 6a ff       	callq	0xffffffff811c15be <.text+0x1c15be>
ffffffff81b1dc8d: 85 c0                	testl	%eax, %eax
ffffffff81b1dc8f: 74 19                	je	0xffffffff81b1dcaa <.init.text+0x1ecaa>
ffffffff81b1dc91: 89 c3                	movl	%eax, %ebx
ffffffff81b1dc93: 89 c6                	movl	%eax, %esi
ffffffff81b1dc95: 48 c7 c7 8d fc 80 81 	movq	$-0x7e7f0373, %rdi      # imm = 0x8180FC8D
ffffffff81b1dc9c: 31 c0                	xorl	%eax, %eax
ffffffff81b1dc9e: e8 72 e4 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1dca3: 89 d8                	movl	%ebx, %eax
ffffffff81b1dca5: e9 24 01 00 00       	jmp	0xffffffff81b1ddce <.init.text+0x1edce>
ffffffff81b1dcaa: 31 f6                	xorl	%esi, %esi
ffffffff81b1dcac: 48 c7 c1 75 fb 80 81 	movq	$-0x7e7f048b, %rcx      # imm = 0x8180FB75
ffffffff81b1dcb3: ba 01 00 00 00       	movl	$0x1, %edx
ffffffff81b1dcb8: 48 c7 c7 30 ac c2 81 	movq	$-0x7e3d53d0, %rdi      # imm = 0x81C2AC30
ffffffff81b1dcbf: e8 37 6a 5f ff       	callq	0xffffffff811146fb <.text+0x1146fb>
ffffffff81b1dcc4: 85 c0                	testl	%eax, %eax
ffffffff81b1dcc6: 74 15                	je	0xffffffff81b1dcdd <.init.text+0x1ecdd>
ffffffff81b1dcc8: 89 c6                	movl	%eax, %esi
ffffffff81b1dcca: 48 c7 c7 b7 fc 80 81 	movq	$-0x7e7f0349, %rdi      # imm = 0x8180FCB7
ffffffff81b1dcd1: 31 c0                	xorl	%eax, %eax
ffffffff81b1dcd3: e8 3d e4 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1dcd8: e9 ec 00 00 00       	jmp	0xffffffff81b1ddc9 <.init.text+0x1edc9>
ffffffff81b1dcdd: 31 ff                	xorl	%edi, %edi
ffffffff81b1dcdf: 48 c7 c2 c0 ab c2 81 	movq	$-0x7e3d5440, %rdx      # imm = 0x81C2ABC0
ffffffff81b1dce6: 48 c7 c6 75 fb 80 81 	movq	$-0x7e7f048b, %rsi      # imm = 0x8180FB75
ffffffff81b1dced: e8 8f f9 87 ff       	callq	0xffffffff8139d681 <.text+0x39d681>
ffffffff81b1dcf2: 48 85 c0             	testq	%rax, %rax
ffffffff81b1dcf5: 48 89 05 2c cf 10 00 	movq	%rax, 0x10cf2c(%rip)    # 0xffffffff81c2ac28
ffffffff81b1dcfc: 75 11                	jne	0xffffffff81b1dd0f <.init.text+0x1ed0f>
ffffffff81b1dcfe: 48 c7 c7 e7 fc 80 81 	movq	$-0x7e7f0319, %rdi      # imm = 0x8180FCE7
ffffffff81b1dd05: e8 0b e4 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1dd0a: e9 aa 00 00 00       	jmp	0xffffffff81b1ddb9 <.init.text+0x1edb9>
ffffffff81b1dd0f: 8b 15 1b cf 10 00    	movl	0x10cf1b(%rip), %edx    # 0xffffffff81c2ac30
ffffffff81b1dd15: 31 c9                	xorl	%ecx, %ecx
ffffffff81b1dd17: 31 f6                	xorl	%esi, %esi
ffffffff81b1dd19: 48 89 c7             	movq	%rax, %rdi
ffffffff81b1dd1c: 49 c7 c0 75 fb 80 81 	movq	$-0x7e7f048b, %r8       # imm = 0x8180FB75
ffffffff81b1dd23: 31 c0                	xorl	%eax, %eax
ffffffff81b1dd25: e8 eb be 87 ff       	callq	0xffffffff81399c15 <.text+0x399c15>
ffffffff81b1dd2a: 48 85 c0             	testq	%rax, %rax
ffffffff81b1dd2d: 74 7e                	je	0xffffffff81b1ddad <.init.text+0x1edad>
ffffffff81b1dd2f: 48 c7 c6 20 54 62 81 	movq	$-0x7e9dabe0, %rsi      # imm = 0x81625420
ffffffff81b1dd36: 48 c7 c7 c0 ab c2 81 	movq	$-0x7e3d5440, %rdi      # imm = 0x81C2ABC0
ffffffff81b1dd3d: e8 a7 67 5f ff       	callq	0xffffffff811144e9 <.text+0x1144e9>
ffffffff81b1dd42: 8b 35 e8 ce 10 00    	movl	0x10cee8(%rip), %esi    # 0xffffffff81c2ac30
ffffffff81b1dd48: ba 01 00 00 00       	movl	$0x1, %edx
ffffffff81b1dd4d: 48 c7 c7 c0 ab c2 81 	movq	$-0x7e3d5440, %rdi      # imm = 0x81C2ABC0
ffffffff81b1dd54: e8 ee 66 5f ff       	callq	0xffffffff81114447 <.text+0x114447>
ffffffff81b1dd59: 85 c0                	testl	%eax, %eax
ffffffff81b1dd5b: 74 30                	je	0xffffffff81b1dd8d <.init.text+0x1ed8d>
ffffffff81b1dd5d: 89 c6                	movl	%eax, %esi
ffffffff81b1dd5f: 48 c7 c7 12 fd 80 81 	movq	$-0x7e7f02ee, %rdi      # imm = 0x8180FD12
ffffffff81b1dd66: 31 c0                	xorl	%eax, %eax
ffffffff81b1dd68: e8 a8 e3 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1dd6d: 48 c7 c7 c0 ab c2 81 	movq	$-0x7e3d5440, %rdi      # imm = 0x81C2ABC0
ffffffff81b1dd74: e8 1c 67 5f ff       	callq	0xffffffff81114495 <.text+0x114495>
ffffffff81b1dd79: 8b 35 b1 ce 10 00    	movl	0x10ceb1(%rip), %esi    # 0xffffffff81c2ac30
ffffffff81b1dd7f: 48 8b 3d a2 ce 10 00 	movq	0x10cea2(%rip), %rdi    # 0xffffffff81c2ac28
ffffffff81b1dd86: e8 94 b2 87 ff       	callq	0xffffffff8139901f <.text+0x39901f>
ffffffff81b1dd8b: eb 20                	jmp	0xffffffff81b1ddad <.init.text+0x1edad>
ffffffff81b1dd8d: 48 c7 c7 38 fd 80 81 	movq	$-0x7e7f02c8, %rdi      # imm = 0x8180FD38
ffffffff81b1dd94: 31 c0                	xorl	%eax, %eax
ffffffff81b1dd96: e8 7a e3 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1dd9b: 48 c7 c7 44 fd 80 81 	movq	$-0x7e7f02bc, %rdi      # imm = 0x8180FD44
ffffffff81b1dda2: 31 c0                	xorl	%eax, %eax
ffffffff81b1dda4: e8 6c e3 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1dda9: 31 c0                	xorl	%eax, %eax
ffffffff81b1ddab: eb 21                	jmp	0xffffffff81b1ddce <.init.text+0x1edce>
ffffffff81b1ddad: 48 8b 3d 74 ce 10 00 	movq	0x10ce74(%rip), %rdi    # 0xffffffff81c2ac28
ffffffff81b1ddb4: e8 af f8 87 ff       	callq	0xffffffff8139d668 <.text+0x39d668>
ffffffff81b1ddb9: 8b 3d 71 ce 10 00    	movl	0x10ce71(%rip), %edi    # 0xffffffff81c2ac30
ffffffff81b1ddbf: be 01 00 00 00       	movl	$0x1, %esi
ffffffff81b1ddc4: e8 e3 65 5f ff       	callq	0xffffffff811143ac <.text+0x1143ac>
ffffffff81b1ddc9: b8 ed ff ff ff       	movl	$0xffffffed, %eax       # imm = 0xFFFFFFED
ffffffff81b1ddce: 5a                   	popq	%rdx
ffffffff81b1ddcf: 5b                   	popq	%rbx
ffffffff81b1ddd0: 5d                   	popq	%rbp
ffffffff81b1ddd1: c3                   	retq

# manifest_init [0xffffffff81b1ddd2,0xffffffff81b1e03e)

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .init.text:

ffffffff81aff000 <.init.text>:
ffffffff81b1ddd2: 55                   	pushq	%rbp
ffffffff81b1ddd3: 48 89 e5             	movq	%rsp, %rbp
ffffffff81b1ddd6: 41 54                	pushq	%r12
ffffffff81b1ddd8: 53                   	pushq	%rbx
ffffffff81b1ddd9: 48 8d 7d e0          	leaq	-0x20(%rbp), %rdi
ffffffff81b1dddd: 48 83 ec 10          	subq	$0x10, %rsp
ffffffff81b1dde1: c7 05 f5 d4 10 00 00 00 00 00	movl	$0x0, 0x10d4f5(%rip) # 0xffffffff81c2b2e0
ffffffff81b1ddeb: 65 48 8b 04 25 28 00 00 00   	movq	%gs:0x28, %rax
ffffffff81b1ddf4: 48 89 45 e8          	movq	%rax, -0x18(%rbp)
ffffffff81b1ddf8: 31 c0                	xorl	%eax, %eax
ffffffff81b1ddfa: e8 6f ba 53 ff       	callq	0xffffffff8105986e <.text+0x5986e>
ffffffff81b1ddff: 85 c0                	testl	%eax, %eax
ffffffff81b1de01: 74 15                	je	0xffffffff81b1de18 <.init.text+0x1ee18>
ffffffff81b1de03: 89 c3                	movl	%eax, %ebx
ffffffff81b1de05: 48 c7 c7 19 2c 81 81 	movq	$-0x7e7ed3e7, %rdi      # imm = 0x81812C19
ffffffff81b1de0c: 31 c0                	xorl	%eax, %eax
ffffffff81b1de0e: e8 02 e3 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1de13: e9 ef 01 00 00       	jmp	0xffffffff81b1e007 <.init.text+0x1f007>
ffffffff81b1de18: 83 7d e4 00          	cmpl	$0x0, -0x1c(%rbp)
ffffffff81b1de1c: 74 0d                	je	0xffffffff81b1de2b <.init.text+0x1ee2b>
ffffffff81b1de1e: 8b 7d e0             	movl	-0x20(%rbp), %edi
ffffffff81b1de21: 8d 47 ff             	leal	-0x1(%rdi), %eax
ffffffff81b1de24: 3d ff ff ff 03       	cmpl	$0x3ffffff, %eax        # imm = 0x3FFFFFF
ffffffff81b1de29: 76 18                	jbe	0xffffffff81b1de43 <.init.text+0x1ee43>
ffffffff81b1de2b: 48 c7 c7 4b 2c 81 81 	movq	$-0x7e7ed3b5, %rdi      # imm = 0x81812C4B
ffffffff81b1de32: 31 c0                	xorl	%eax, %eax
ffffffff81b1de34: bb ea ff ff ff       	movl	$0xffffffea, %ebx       # imm = 0xFFFFFFEA
ffffffff81b1de39: e8 d7 e2 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1de3e: e9 c4 01 00 00       	jmp	0xffffffff81b1e007 <.init.text+0x1f007>
ffffffff81b1de43: be d0 00 00 00       	movl	$0xd0, %esi
ffffffff81b1de48: bb f4 ff ff ff       	movl	$0xfffffff4, %ebx       # imm = 0xFFFFFFF4
ffffffff81b1de4d: e8 08 88 5e ff       	callq	0xffffffff8110665a <.text+0x10665a>
ffffffff81b1de52: 48 85 c0             	testq	%rax, %rax
ffffffff81b1de55: 48 89 05 8c d4 10 00 	movq	%rax, 0x10d48c(%rip)    # 0xffffffff81c2b2e8
ffffffff81b1de5c: 0f 84 a5 01 00 00    	je	0xffffffff81b1e007 <.init.text+0x1f007>
ffffffff81b1de62: 8b 55 e0             	movl	-0x20(%rbp), %edx
ffffffff81b1de65: 8b 75 e4             	movl	-0x1c(%rbp), %esi
ffffffff81b1de68: 48 89 c7             	movq	%rax, %rdi
ffffffff81b1de6b: e8 80 f3 6a ff       	callq	0xffffffff811cd1f0 <.text+0x1cd1f0>
ffffffff81b1de70: 85 c0                	testl	%eax, %eax
ffffffff81b1de72: 89 c3                	movl	%eax, %ebx
ffffffff81b1de74: 79 15                	jns	0xffffffff81b1de8b <.init.text+0x1ee8b>
ffffffff81b1de76: 89 c6                	movl	%eax, %esi
ffffffff81b1de78: 48 c7 c7 7d 2c 81 81 	movq	$-0x7e7ed383, %rdi      # imm = 0x81812C7D
ffffffff81b1de7f: 31 c0                	xorl	%eax, %eax
ffffffff81b1de81: e8 8f e2 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1de86: e9 70 01 00 00       	jmp	0xffffffff81b1dffb <.init.text+0x1effb>
ffffffff81b1de8b: 48 8b 0d 56 d4 10 00 	movq	0x10d456(%rip), %rcx    # 0xffffffff81c2b2e8
ffffffff81b1de92: 8b 45 e0             	movl	-0x20(%rbp), %eax
ffffffff81b1de95: 89 05 45 d4 10 00    	movl	%eax, 0x10d445(%rip)    # 0xffffffff81c2b2e0
ffffffff81b1de9b: 48 8d 41 24          	leaq	0x24(%rcx), %rax
ffffffff81b1de9f: 48 89 0d 9a cd 10 00 	movq	%rcx, 0x10cd9a(%rip)    # 0xffffffff81c2ac40
ffffffff81b1dea6: 48 89 05 3b d4 10 00 	movq	%rax, 0x10d43b(%rip)    # 0xffffffff81c2b2e8
ffffffff81b1dead: 8b 71 04             	movl	0x4(%rcx), %esi
ffffffff81b1deb0: 48 01 ce             	addq	%rcx, %rsi
ffffffff81b1deb3: 48 85 c9             	testq	%rcx, %rcx
ffffffff81b1deb6: 0f 84 61 01 00 00    	je	0xffffffff81b1e01d <.init.text+0x1f01d>
ffffffff81b1debc: 8b 11                	movl	(%rcx), %edx
ffffffff81b1debe: 83 fa 0e             	cmpl	$0xe, %edx
ffffffff81b1dec1: 74 15                	je	0xffffffff81b1ded8 <.init.text+0x1eed8>
ffffffff81b1dec3: be 0e 00 00 00       	movl	$0xe, %esi
ffffffff81b1dec8: 48 c7 c7 be 2c 81 81 	movq	$-0x7e7ed342, %rdi      # imm = 0x81812CBE
ffffffff81b1decf: 31 c0                	xorl	%eax, %eax
ffffffff81b1ded1: e8 3f e2 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1ded6: eb 2e                	jmp	0xffffffff81b1df06 <.init.text+0x1ef06>
ffffffff81b1ded8: 80 79 13 00          	cmpb	$0x0, 0x13(%rcx)
ffffffff81b1dedc: 75 1a                	jne	0xffffffff81b1def8 <.init.text+0x1eef8>
ffffffff81b1dede: 83 79 14 00          	cmpl	$0x0, 0x14(%rcx)
ffffffff81b1dee2: 75 14                	jne	0xffffffff81b1def8 <.init.text+0x1eef8>
ffffffff81b1dee4: 83 79 18 00          	cmpl	$0x0, 0x18(%rcx)
ffffffff81b1dee8: 75 0e                	jne	0xffffffff81b1def8 <.init.text+0x1eef8>
ffffffff81b1deea: 48 c7 c2 40 ac c2 81 	movq	$-0x7e3d53c0, %rdx      # imm = 0x81C2AC40
ffffffff81b1def1: 31 c9                	xorl	%ecx, %ecx
ffffffff81b1def3: 45 31 e4             	xorl	%r12d, %r12d
ffffffff81b1def6: eb 3a                	jmp	0xffffffff81b1df32 <.init.text+0x1ef32>
ffffffff81b1def8: 48 c7 c7 f7 2c 81 81 	movq	$-0x7e7ed309, %rdi      # imm = 0x81812CF7
ffffffff81b1deff: 31 c0                	xorl	%eax, %eax
ffffffff81b1df01: e8 0f e2 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1df06: bb ac ff ff ff       	movl	$0xffffffac, %ebx       # imm = 0xFFFFFFAC
ffffffff81b1df0b: e9 12 01 00 00       	jmp	0xffffffff81b1e022 <.init.text+0x1f022>
ffffffff81b1df10: 48 83 c2 10          	addq	$0x10, %rdx
ffffffff81b1df14: 41 83 fc 65          	cmpl	$0x65, %r12d
ffffffff81b1df18: 74 1f                	je	0xffffffff81b1df39 <.init.text+0x1ef39>
ffffffff81b1df1a: 48 8d 48 24          	leaq	0x24(%rax), %rcx
ffffffff81b1df1e: 48 89 42 fc          	movq	%rax, -0x4(%rdx)
ffffffff81b1df22: 41 ff c4             	incl	%r12d
ffffffff81b1df25: 48 89 4a 04          	movq	%rcx, 0x4(%rdx)
ffffffff81b1df29: 0f b7 40 22          	movzwl	0x22(%rax), %eax
ffffffff81b1df2d: 48 01 c8             	addq	%rcx, %rax
ffffffff81b1df30: b1 01                	movb	$0x1, %cl
ffffffff81b1df32: 48 39 c6             	cmpq	%rax, %rsi
ffffffff81b1df35: 77 d9                	ja	0xffffffff81b1df10 <.init.text+0x1ef10>
ffffffff81b1df37: eb 20                	jmp	0xffffffff81b1df59 <.init.text+0x1ef59>
ffffffff81b1df39: 84 c9                	testb	%cl, %cl
ffffffff81b1df3b: 74 07                	je	0xffffffff81b1df44 <.init.text+0x1ef44>
ffffffff81b1df3d: 48 89 05 a4 d3 10 00 	movq	%rax, 0x10d3a4(%rip)    # 0xffffffff81c2b2e8
ffffffff81b1df44: 48 c7 c7 1e 2d 81 81 	movq	$-0x7e7ed2e2, %rdi      # imm = 0x81812D1E
ffffffff81b1df4b: 31 c0                	xorl	%eax, %eax
ffffffff81b1df4d: bb f4 ff ff ff       	movl	$0xfffffff4, %ebx       # imm = 0xFFFFFFF4
ffffffff81b1df52: e8 be e1 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1df57: eb 0d                	jmp	0xffffffff81b1df66 <.init.text+0x1ef66>
ffffffff81b1df59: 84 c9                	testb	%cl, %cl
ffffffff81b1df5b: 74 07                	je	0xffffffff81b1df64 <.init.text+0x1ef64>
ffffffff81b1df5d: 48 89 05 84 d3 10 00 	movq	%rax, 0x10d384(%rip)    # 0xffffffff81c2b2e8
ffffffff81b1df64: 31 db                	xorl	%ebx, %ebx
ffffffff81b1df66: 85 db                	testl	%ebx, %ebx
ffffffff81b1df68: 44 89 25 d9 cc 10 00 	movl	%r12d, 0x10ccd9(%rip)   # 0xffffffff81c2ac48
ffffffff81b1df6f: 74 19                	je	0xffffffff81b1df8a <.init.text+0x1ef8a>
ffffffff81b1df71: 48 c7 c2 d0 60 62 81 	movq	$-0x7e9d9f30, %rdx      # imm = 0x816260D0
ffffffff81b1df78: 89 de                	movl	%ebx, %esi
ffffffff81b1df7a: 48 c7 c7 51 2d 81 81 	movq	$-0x7e7ed2af, %rdi      # imm = 0x81812D51
ffffffff81b1df81: 31 c0                	xorl	%eax, %eax
ffffffff81b1df83: e8 8d e1 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1df88: eb 71                	jmp	0xffffffff81b1dffb <.init.text+0x1effb>
ffffffff81b1df8a: 31 ff                	xorl	%edi, %edi
ffffffff81b1df8c: e8 7c 53 55 ff       	callq	0xffffffff8107330d <.text+0x7330d>
ffffffff81b1df91: 48 85 c0             	testq	%rax, %rax
ffffffff81b1df94: 49 89 c4             	movq	%rax, %r12
ffffffff81b1df97: 74 5d                	je	0xffffffff81b1dff6 <.init.text+0x1eff6>
ffffffff81b1df99: 50                   	pushq	%rax
ffffffff81b1df9a: 6a 00                	pushq	$0x0
ffffffff81b1df9c: 31 d2                	xorl	%edx, %edx
ffffffff81b1df9e: 4c 89 e1             	movq	%r12, %rcx
ffffffff81b1dfa1: 31 f6                	xorl	%esi, %esi
ffffffff81b1dfa3: 41 b9 02 00 00 00    	movl	$0x2, %r9d
ffffffff81b1dfa9: 41 b8 00 00 0f 1f    	movl	$0x1f0f0000, %r8d       # imm = 0x1F0F0000
ffffffff81b1dfaf: 48 c7 c7 7e 2d 81 81 	movq	$-0x7e7ed282, %rdi      # imm = 0x81812D7E
ffffffff81b1dfb6: e8 ec 58 69 ff       	callq	0xffffffff811b38a7 <.text+0x1b38a7>
ffffffff81b1dfbb: 48 3d 00 f0 ff ff    	cmpq	$-0x1000, %rax          # imm = 0xF000
ffffffff81b1dfc1: 5a                   	popq	%rdx
ffffffff81b1dfc2: 59                   	popq	%rcx
ffffffff81b1dfc3: 76 0c                	jbe	0xffffffff81b1dfd1 <.init.text+0x1efd1>
ffffffff81b1dfc5: 4c 89 e7             	movq	%r12, %rdi
ffffffff81b1dfc8: 89 c3                	movl	%eax, %ebx
ffffffff81b1dfca: e8 60 ed a3 ff       	callq	0xffffffff8155cd2f <.text+0x55cd2f>
ffffffff81b1dfcf: eb 2a                	jmp	0xffffffff81b1dffb <.init.text+0x1effb>
ffffffff81b1dfd1: f0                   	lock
ffffffff81b1dfd2: 80 48 79 02          	orb	$0x2, 0x79(%rax)
ffffffff81b1dfd6: 48 c7 c7 90 2d 81 81 	movq	$-0x7e7ed270, %rdi      # imm = 0x81812D90
ffffffff81b1dfdd: 48 89 05 ec d2 10 00 	movq	%rax, 0x10d2ec(%rip)    # 0xffffffff81c2b2d0
ffffffff81b1dfe4: 31 c0                	xorl	%eax, %eax
ffffffff81b1dfe6: 4c 89 25 eb d2 10 00 	movq	%r12, 0x10d2eb(%rip)    # 0xffffffff81c2b2d8
ffffffff81b1dfed: 31 db                	xorl	%ebx, %ebx
ffffffff81b1dfef: e8 21 e1 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1dff4: eb 11                	jmp	0xffffffff81b1e007 <.init.text+0x1f007>
ffffffff81b1dff6: bb f4 ff ff ff       	movl	$0xfffffff4, %ebx       # imm = 0xFFFFFFF4
ffffffff81b1dffb: 48 8b 3d e6 d2 10 00 	movq	0x10d2e6(%rip), %rdi    # 0xffffffff81c2b2e8
ffffffff81b1e002: e8 b7 90 5e ff       	callq	0xffffffff811070be <.text+0x1070be>
ffffffff81b1e007: 48 8b 75 e8          	movq	-0x18(%rbp), %rsi
ffffffff81b1e00b: 65 48 33 34 25 28 00 00 00   	xorq	%gs:0x28, %rsi
ffffffff81b1e014: 89 d8                	movl	%ebx, %eax
ffffffff81b1e016: 74 1d                	je	0xffffffff81b1e035 <.init.text+0x1f035>
ffffffff81b1e018: e8 11 e1 53 ff       	callq	0xffffffff8105c12e <.text+0x5c12e>
ffffffff81b1e01d: bb ea ff ff ff       	movl	$0xffffffea, %ebx       # imm = 0xFFFFFFEA
ffffffff81b1e022: 48 c7 c7 b9 2d 81 81 	movq	$-0x7e7ed247, %rdi      # imm = 0x81812DB9
ffffffff81b1e029: 31 c0                	xorl	%eax, %eax
ffffffff81b1e02b: e8 e5 e0 a3 ff       	callq	0xffffffff8155c115 <.text+0x55c115>
ffffffff81b1e030: e9 3c ff ff ff       	jmp	0xffffffff81b1df71 <.init.text+0x1ef71>
ffffffff81b1e035: 48 8d 65 f0          	leaq	-0x10(%rbp), %rsp
ffffffff81b1e039: 5b                   	popq	%rbx
ffffffff81b1e03a: 41 5c                	popq	%r12
ffffffff81b1e03c: 5d                   	popq	%rbp
ffffffff81b1e03d: c3                   	retq
