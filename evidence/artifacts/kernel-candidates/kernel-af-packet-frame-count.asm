# Exact AF_PACKET frame-count consumer evidence
# module sha256: c810265b3c22f95d2b90494cc206abd6b4e67b7710bff2adcb177ee4867f467b
# module ranges are section-relative half-open .text addresses


# ---- free_pg_vec [0x4b7,0x53c) ----

work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko:	file format elf64-x86-64

Disassembly of section .text:

00000000000004b7 <free_pg_vec>:
     4b7:      	pushq	%rbp
     4b8:      	movl	%edx, %eax
     4ba:      	movq	%rsp, %rbp
     4bd:      	pushq	%r15
     4bf:      	pushq	%r14
     4c1:      	pushq	%r13
     4c3:      	pushq	%r12
     4c5:      	movl	%esi, %r14d
     4c8:      	pushq	%rbx
     4c9:      	movq	%rdi, %r12
     4cc:      	xorl	%ebx, %ebx
     4ce:      	movabsq	$0x370000000000, %r15   # imm = 0x370000000000
     4d8:      	subq	$0x18, %rsp
     4dc:      	movq	%rax, -0x38(%rbp)
     4e0:      	cmpq	-0x38(%rbp), %rbx
     4e4:      	je	0x525 <free_pg_vec+0x6e>
     4e6:      	movslq	%ebx, %rax
     4e9:      	leaq	(%r12,%rax,8), %r13
     4ed:      	movq	(%r13), %rdi
     4f1:      	testq	%rdi, %rdi
     4f4:      	je	0x520 <free_pg_vec+0x69>
     4f6:      	leaq	(%rdi,%r15), %rdx
     4fa:      	movabsq	$0x1ffffffffffe, %rax   # imm = 0x1FFFFFFFFFFE
     504:      	cmpq	%rax, %rdx
     507:      	ja	0x510 <free_pg_vec+0x59>
     509:      	callq	0x50e <free_pg_vec+0x57>
		000000000000050a:  R_X86_64_PC32	vfree-0x4
     50e:      	jmp	0x518 <free_pg_vec+0x61>
     510:      	movl	%r14d, %esi
     513:      	callq	0x518 <free_pg_vec+0x61>
		0000000000000514:  R_X86_64_PC32	free_pages-0x4
     518:      	movq	$0x0, (%r13)
     520:      	incq	%rbx
     523:      	jmp	0x4e0 <free_pg_vec+0x29>
     525:      	movq	%r12, %rdi
     528:      	callq	0x52d <free_pg_vec+0x76>
		0000000000000529:  R_X86_64_PC32	kfree-0x4
     52d:      	addq	$0x18, %rsp
     531:      	popq	%rbx
     532:      	popq	%r12
     534:      	popq	%r13
     536:      	popq	%r14
     538:      	popq	%r15
     53a:      	popq	%rbp
     53b:      	retq

# ---- packet_mmap [0x596,0x6ef) ----

work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko:	file format elf64-x86-64

Disassembly of section .text:

0000000000000596 <packet_mmap>:
     596:      	pushq	%rbp
     597:      	movl	$0xffffffea, %eax       # imm = 0xFFFFFFEA
     59c:      	movq	%rsp, %rbp
     59f:      	pushq	%r15
     5a1:      	pushq	%r14
     5a3:      	pushq	%r13
     5a5:      	pushq	%r12
     5a7:      	pushq	%rbx
     5a8:      	subq	$0x28, %rsp
     5ac:      	cmpq	$0x0, 0x98(%rdx)
     5b4:      	movq	0x20(%rsi), %r14
     5b8:      	jne	0x6e0 <packet_mmap+0x14a>
     5be:      	leaq	0x470(%r14), %rax
     5c5:      	leaq	0x2c8(%r14), %rbx
     5cc:      	movq	%rdx, %r13
     5cf:      	movq	%rax, %rdi
     5d2:      	movq	%rax, -0x38(%rbp)
     5d6:      	callq	0x5db <packet_mmap+0x45>
		00000000000005d7:  R_X86_64_PC32	mutex_lock-0x4
     5db:      	leaq	0x398(%r14), %r11
     5e2:      	movq	%rbx, %rax
     5e5:      	xorl	%esi, %esi
     5e7:      	cmpq	%r11, %rax
     5ea:      	ja	0x608 <packet_mmap+0x72>
     5ec:      	cmpq	$0x0, (%rax)
     5f0:      	je	0x600 <packet_mmap+0x6a>
     5f2:      	movl	0x20(%rax), %edx
     5f5:      	imull	0x1c(%rax), %edx
     5f9:      	shlq	$0xc, %rdx
     5fd:      	addq	%rdx, %rsi
     600:      	addq	$0xd0, %rax
     606:      	jmp	0x5e7 <packet_mmap+0x51>
     608:      	testq	%rsi, %rsi
     60b:      	movl	$0xffffffea, %r12d      # imm = 0xFFFFFFEA
     611:      	je	0x6d4 <packet_mmap+0x13e>
     617:      	movq	(%r13), %r15
     61b:      	movq	0x8(%r13), %rax
     61f:      	subq	%r15, %rax
     622:      	cmpq	%rax, %rsi
     625:      	jne	0x6d4 <packet_mmap+0x13e>
     62b:      	cmpq	%r11, %rbx
     62e:      	ja	0x6ba <packet_mmap+0x124>
     634:      	xorl	%r9d, %r9d
     637:      	cmpq	$0x0, (%rbx)
     63b:      	je	0x6ae <packet_mmap+0x118>
     63d:      	cmpl	%r9d, 0x20(%rbx)
     641:      	jbe	0x6ae <packet_mmap+0x118>
     643:      	movq	(%rbx), %rdx
     646:      	movslq	%r9d, %rax
     649:      	xorl	%r10d, %r10d
     64c:      	movq	(%rdx,%rax,8), %r8
     650:      	subq	%r8, %r15
     653:      	cmpl	%r10d, 0x1c(%rbx)
     657:      	leaq	(%r8,%r15), %r12
     65b:      	jbe	0x6a6 <packet_mmap+0x110>
     65d:      	movq	%r8, %rdi
     660:      	movq	%r11, -0x50(%rbp)
     664:      	movl	%r10d, -0x48(%rbp)
     668:      	movl	%r9d, -0x44(%rbp)
     66c:      	movq	%r8, -0x40(%rbp)
     670:      	callq	0x53c <pgv_to_page>
     675:      	movq	%r12, %rsi
     678:      	movq	%rax, %rdx
     67b:      	movq	%r13, %rdi
     67e:      	callq	0x683 <packet_mmap+0xed>
		000000000000067f:  R_X86_64_PC32	vm_insert_page-0x4
     683:      	testl	%eax, %eax
     685:      	movl	%eax, %r12d
     688:      	jne	0x6d4 <packet_mmap+0x13e>
     68a:      	movq	-0x40(%rbp), %r8
     68e:      	movl	-0x48(%rbp), %r10d
     692:      	movq	-0x50(%rbp), %r11
     696:      	movl	-0x44(%rbp), %r9d
     69a:      	addq	$0x1000, %r8            # imm = 0x1000
     6a1:      	incl	%r10d
     6a4:      	jmp	0x653 <packet_mmap+0xbd>
     6a6:      	incl	%r9d
     6a9:      	movq	%r12, %r15
     6ac:      	jmp	0x63d <packet_mmap+0xa7>
     6ae:      	addq	$0xd0, %rbx
     6b5:      	jmp	0x62b <packet_mmap+0x95>
     6ba:      	leaq	0x4b0(%r14), %rdi
     6c1:      	xorl	%r12d, %r12d
     6c4:      	callq	0x0 <atomic_inc>
     6c9:      	movq	$0x0, 0x90(%r13)
		00000000000006d0:  R_X86_64_32S	.rodata+0x260
     6d4:      	movq	-0x38(%rbp), %rdi
     6d8:      	callq	0x6dd <packet_mmap+0x147>
		00000000000006d9:  R_X86_64_PC32	mutex_unlock-0x4
     6dd:      	movl	%r12d, %eax
     6e0:      	addq	$0x28, %rsp
     6e4:      	popq	%rbx
     6e5:      	popq	%r12
     6e7:      	popq	%r13
     6e9:      	popq	%r14
     6eb:      	popq	%r15
     6ed:      	popq	%rbp
     6ee:      	retq

# ---- packet_lookup_frame [0x19bb,0x19f7) ----

work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko:	file format elf64-x86-64

Disassembly of section .text:

00000000000019bb <packet_lookup_frame>:
    19bb:      	movl	%edx, %eax
    19bd:      	xorl	%edx, %edx
    19bf:      	movq	(%rsi), %r8
    19c2:      	divl	0xc(%rsi)
    19c5:      	imull	0x10(%rsi), %edx
    19c9:      	movl	%eax, %eax
    19cb:      	addq	(%r8,%rax,8), %rdx
    19cf:      	movq	%rdx, %rax
    19d2:      	movl	0x4b4(%rdi), %edx
    19d8:      	testl	%edx, %edx
    19da:      	je	0x19e9 <packet_lookup_frame+0x2e>
    19dc:      	decl	%edx
    19de:      	je	0x19e9 <packet_lookup_frame+0x2e>
    19e0:      	pushq	%rbp
    19e1:      	movq	%rsp, %rbp
    19e4:      	callq	0xb85 <__packet_get_status.part.44>
    19e9:      	movl	(%rax), %edx
    19eb:      	cmpl	%edx, %ecx
    19ed:      	movl	$0x0, %edx
    19f2:      	cmovneq	%rdx, %rax
    19f6:      	retq

# ---- packet_rcv_has_room [0x19f7,0x1a64) ----

work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko:	file format elf64-x86-64

Disassembly of section .text:

00000000000019f7 <packet_rcv_has_room.isra.45.part.46>:
    19f7:      	pushq	%rbp
    19f8:      	movq	%rsp, %rbp
    19fb:      	pushq	%r12
    19fd:      	leaq	0xac(%rdi), %r12
    1a04:      	pushq	%rbx
    1a05:      	movq	%rdi, %rbx
    1a08:      	movq	%r12, %rdi
    1a0b:      	callq	0x1a10 <packet_rcv_has_room.isra.45.part.46+0x19>
		0000000000001a0c:  R_X86_64_PC32	_raw_spin_lock-0x4
    1a10:      	cmpl	$0x2, 0x4b4(%rbx)
    1a17:      	jne	0x1a3a <packet_rcv_has_room.isra.45.part.46+0x43>
    1a19:      	movzwl	0x30a(%rbx), %edx
    1a20:      	movq	0x2f8(%rbx), %rax
    1a27:      	movq	(%rax,%rdx,8), %rax
    1a2b:      	movl	$0x0, %edx
    1a30:      	cmpl	$0x0, 0x8(%rax)
    1a34:      	cmovneq	%rdx, %rax
    1a38:      	jmp	0x1a51 <packet_rcv_has_room.isra.45.part.46+0x5a>
    1a3a:      	movl	0x2d0(%rbx), %edx
    1a40:      	leaq	0x2c8(%rbx), %rsi
    1a47:      	xorl	%ecx, %ecx
    1a49:      	movq	%rbx, %rdi
    1a4c:      	callq	0x19bb <packet_lookup_frame>
    1a51:      	testq	%rax, %rax
    1a54:      	movq	%r12, %rdi
    1a57:      	setne	%al
    1a5a:      	callq	0x26 <__raw_spin_unlock>
    1a5f:      	popq	%rbx
    1a60:      	popq	%r12
    1a62:      	popq	%rbp
    1a63:      	retq

# ---- packet_poll [0x1c82,0x1d6c) ----

work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko:	file format elf64-x86-64

Disassembly of section .text:

0000000000001c82 <packet_poll>:
    1c82:      	pushq	%rbp
    1c83:      	movq	%rsp, %rbp
    1c86:      	pushq	%r13
    1c88:      	pushq	%r12
    1c8a:      	pushq	%rbx
    1c8b:      	pushq	%rcx
    1c8c:      	movq	0x20(%rsi), %rbx
    1c90:      	callq	0x1c95 <packet_poll+0x13>
		0000000000001c91:  R_X86_64_PC32	datagram_poll-0x4
    1c95:      	movl	%eax, %r12d
    1c98:      	leaq	0xac(%rbx), %r13
    1c9f:      	movq	%r13, %rdi
    1ca2:      	callq	0x1ca7 <packet_poll+0x25>
		0000000000001ca3:  R_X86_64_PC32	_raw_spin_lock_bh-0x4
    1ca7:      	cmpq	$0x0, 0x2c8(%rbx)
    1caf:      	je	0x1d11 <packet_poll+0x8f>
    1cb1:      	cmpl	$0x1, 0x4b4(%rbx)
    1cb8:      	ja	0x1ce1 <packet_poll+0x5f>
    1cba:      	movl	0x2d0(%rbx), %edx
    1cc0:      	testl	%edx, %edx
    1cc2:      	je	0x1cc8 <packet_poll+0x46>
    1cc4:      	decl	%edx
    1cc6:      	jmp	0x1cce <packet_poll+0x4c>
    1cc8:      	movl	0x2dc(%rbx), %edx
    1cce:      	leaq	0x2c8(%rbx), %rsi
    1cd5:      	xorl	%ecx, %ecx
    1cd7:      	movq	%rbx, %rdi
    1cda:      	callq	0x19bb <packet_lookup_frame>
    1cdf:      	jmp	0x1d0c <packet_poll+0x8a>
    1ce1:      	movzwl	0x30a(%rbx), %eax
    1ce8:      	testw	%ax, %ax
    1ceb:      	jne	0x1cf3 <packet_poll+0x71>
    1ced:      	movl	0x328(%rbx), %eax
    1cf3:      	movq	0x2f8(%rbx), %rdx
    1cfa:      	decl	%eax
    1cfc:      	movq	(%rdx,%rax,8), %rax
    1d00:      	cmpl	$0x0, 0x8(%rax)
    1d04:      	je	0x1d0c <packet_poll+0x8a>
    1d06:      	orl	$0x41, %r12d
    1d0a:      	jmp	0x1d11 <packet_poll+0x8f>
    1d0c:      	testq	%rax, %rax
    1d0f:      	je	0x1d06 <packet_poll+0x84>
    1d11:      	movq	%r13, %rdi
    1d14:      	leaq	0x144(%rbx), %r13
    1d1b:      	callq	0x1d20 <packet_poll+0x9e>
		0000000000001d1c:  R_X86_64_PC32	_raw_spin_unlock_bh-0x4
    1d20:      	movq	%r13, %rdi
    1d23:      	callq	0x1d28 <packet_poll+0xa6>
		0000000000001d24:  R_X86_64_PC32	_raw_spin_lock_bh-0x4
    1d28:      	cmpq	$0x0, 0x398(%rbx)
    1d30:      	je	0x1d59 <packet_poll+0xd7>
    1d32:      	movl	0x3a0(%rbx), %edx
    1d38:      	leaq	0x398(%rbx), %rsi
    1d3f:      	xorl	%ecx, %ecx
    1d41:      	movq	%rbx, %rdi
    1d44:      	callq	0x19bb <packet_lookup_frame>
    1d49:      	movl	%r12d, %edx
    1d4c:      	orl	$0x104, %edx            # imm = 0x104
    1d52:      	testq	%rax, %rax
    1d55:      	cmovnel	%edx, %r12d
    1d59:      	movq	%r13, %rdi
    1d5c:      	callq	0x1d61 <packet_poll+0xdf>
		0000000000001d5d:  R_X86_64_PC32	_raw_spin_unlock_bh-0x4
    1d61:      	popq	%rdx
    1d62:      	movl	%r12d, %eax
    1d65:      	popq	%rbx
    1d66:      	popq	%r12
    1d68:      	popq	%r13
    1d6a:      	popq	%rbp
    1d6b:      	retq

# ---- packet_set_ring [0x1f5d,0x25aa) ----

work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko:	file format elf64-x86-64

Disassembly of section .text:

0000000000001f5d <packet_set_ring>:
    1f5d:      	pushq	%rbp
    1f5e:      	movq	%rsp, %rbp
    1f61:      	pushq	%r15
    1f63:      	pushq	%r14
    1f65:      	pushq	%r13
    1f67:      	pushq	%r12
    1f69:      	movq	%rsi, %r12
    1f6c:      	pushq	%rbx
    1f6d:      	xorl	%esi, %esi
    1f6f:      	movq	%rdi, %rbx
    1f72:      	subq	$0x88, %rsp
    1f79:      	movl	%edx, -0x8c(%rbp)
    1f7f:      	movl	%ecx, -0x80(%rbp)
    1f82:      	movq	%gs:0x28, %rax
    1f8b:      	movq	%rax, -0x38(%rbp)
    1f8f:      	xorl	%eax, %eax
    1f91:      	callq	0x1f96 <packet_set_ring+0x39>
		0000000000001f92:  R_X86_64_PC32	lock_sock_nested-0x4
    1f96:      	cmpl	$0x0, -0x8c(%rbp)
    1f9d:      	jne	0x1fcd <packet_set_ring+0x70>
    1f9f:      	cmpl	$0x0, -0x80(%rbp)
    1fa3:      	je	0x1fcd <packet_set_ring+0x70>
    1fa5:      	cmpl	$0x1, 0x4b4(%rbx)
    1fac:      	jbe	0x1fe8 <packet_set_ring+0x8b>
    1fae:      	movq	$0x0, %rdx
		0000000000001fb1:  R_X86_64_32S	.rodata.str1.1+0x265
    1fb5:      	movl	$0xf02, %esi            # imm = 0xF02
    1fba:      	movq	$0x0, %rdi
		0000000000001fbd:  R_X86_64_32S	.rodata.str1.1+0xad
    1fc1:      	xorl	%eax, %eax
    1fc3:      	callq	0x1fc8 <packet_set_ring+0x6b>
		0000000000001fc4:  R_X86_64_PC32	warn_slowpath_fmt-0x4
    1fc8:      	jmp	0x206d <packet_set_ring+0x110>
    1fcd:      	cmpl	$0x0, -0x80(%rbp)
    1fd1:      	leaq	0x98(%rbx), %rax
    1fd8:      	leaq	0x2c8(%rbx), %r14
    1fdf:      	movq	%rax, -0x88(%rbp)
    1fe6:      	je	0x1ffd <packet_set_ring+0xa0>
    1fe8:      	leaq	0x130(%rbx), %rax
    1fef:      	leaq	0x398(%rbx), %r14
    1ff6:      	movq	%rax, -0x88(%rbp)
    1ffd:      	cmpl	$0x0, -0x8c(%rbp)
    2004:      	je	0x2013 <packet_set_ring+0xb6>
    2006:      	cmpl	$0x0, 0x4(%r12)
    200c:      	jne	0x2037 <packet_set_ring+0xda>
    200e:      	jmp	0x2195 <packet_set_ring+0x238>
    2013:      	movl	0x4b0(%rbx), %eax
    2019:      	testl	%eax, %eax
    201b:      	je	0x2028 <packet_set_ring+0xcb>
    201d:      	movl	$0xfffffff0, %r13d      # imm = 0xFFFFFFF0
    2023:      	jmp	0x2396 <packet_set_ring+0x439>
    2028:      	leaq	0x28(%r14), %rdi
    202c:      	callq	0xbde <packet_read_pending.isra.51>
    2031:      	testl	%eax, %eax
    2033:      	je	0x2006 <packet_set_ring+0xa9>
    2035:      	jmp	0x201d <packet_set_ring+0xc0>
    2037:      	cmpq	$0x0, (%r14)
    203b:      	jne	0x201d <packet_set_ring+0xc0>
    203d:      	movl	0x4b4(%rbx), %edx
    2043:      	cmpl	$0x1, %edx
    2046:      	je	0x205b <packet_set_ring+0xfe>
    2048:      	jb	0x205b <packet_set_ring+0xfe>
    204a:      	cmpl	$0x2, %edx
    204d:      	jne	0x2065 <packet_set_ring+0x108>
    204f:      	movl	$0x44, 0x4b8(%rbx)
    2059:      	jmp	0x2065 <packet_set_ring+0x108>
    205b:      	movl	$0x34, 0x4b8(%rbx)
    2065:      	movl	(%r12), %eax
    2069:      	testl	%eax, %eax
    206b:      	jg	0x2078 <packet_set_ring+0x11b>
    206d:      	movl	$0xffffffea, %r13d      # imm = 0xFFFFFFEA
    2073:      	jmp	0x2396 <packet_set_ring+0x439>
    2078:      	testl	$0xfff, %eax            # imm = 0xFFF
    207d:      	jne	0x206d <packet_set_ring+0x110>
    207f:      	cmpl	$0x1, %edx
    2082:      	jbe	0x209c <packet_set_ring+0x13f>
    2084:      	movl	0x14(%r12), %edx
    2089:      	movl	%eax, %ecx
    208b:      	addq	$0x7, %rdx
    208f:      	andq	$-0x8, %rdx
    2093:      	addq	$0x30, %rdx
    2097:      	cmpq	%rdx, %rcx
    209a:      	jbe	0x206d <packet_set_ring+0x110>
    209c:      	movl	0x4bc(%rbx), %edx
    20a2:      	addl	0x4b8(%rbx), %edx
    20a8:      	movl	0x8(%r12), %ecx
    20ad:      	cmpl	%edx, %ecx
    20af:      	jb	0x206d <packet_set_ring+0x110>
    20b1:      	testb	$0xf, %cl
    20b4:      	jne	0x206d <packet_set_ring+0x110>
    20b6:      	xorl	%edx, %edx
    20b8:      	divl	%ecx
    20ba:      	testl	%eax, %eax
    20bc:      	movl	%eax, 0xc(%r14)
    20c0:      	je	0x206d <packet_set_ring+0x110>
    20c2:      	movl	0x4(%r12), %r13d
    20c7:      	imull	%r13d, %eax
    20cb:      	cmpl	0xc(%r12), %eax
    20d0:      	jne	0x206d <packet_set_ring+0x110>
    20d2:      	movl	(%r12), %eax
    20d6:      	orl	$-0x1, %edx
    20d9:      	movl	%r13d, %edi
    20dc:      	shlq	$0x3, %rdi
    20e0:      	movl	$0x80d0, %esi           # imm = 0x80D0
    20e5:      	decq	%rax
    20e8:      	shrq	$0xc, %rax
    20ec:      	bsrq	%rax, %rdx
    20f0:      	leal	0x1(%rdx), %eax
    20f3:      	movl	%eax, -0x7c(%rbp)
    20f6:      	callq	0x20fb <packet_set_ring+0x19e>
		00000000000020f7:  R_X86_64_PC32	__kmalloc-0x4
    20fb:      	testq	%rax, %rax
    20fe:      	movq	%rax, -0x78(%rbp)
    2102:      	je	0x23b9 <packet_set_ring+0x45c>
    2108:      	movb	-0x7c(%rbp), %cl
    210b:      	movl	$0x1, %eax
    2110:      	xorl	%r15d, %r15d
    2113:      	shll	%cl, %eax
    2115:      	cltq
    2117:      	shlq	$0xc, %rax
    211b:      	movq	%rax, -0xa0(%rbp)
    2122:      	cmpl	%r15d, %r13d
    2125:      	je	0x23c1 <packet_set_ring+0x464>
    212b:      	movq	-0x78(%rbp), %rsi
    212f:      	movslq	%r15d, %rax
    2132:      	movl	$0xd2d0, %edi           # imm = 0xD2D0
    2137:      	leaq	(%rsi,%rax,8), %rax
    213b:      	movl	-0x7c(%rbp), %esi
    213e:      	movq	%rax, -0x98(%rbp)
    2145:      	callq	0x214a <packet_set_ring+0x1ed>
		0000000000002146:  R_X86_64_PC32	__get_free_pages-0x4
    214a:      	testq	%rax, %rax
    214d:      	jne	0x216d <packet_set_ring+0x210>
    214f:      	movq	-0xa0(%rbp), %rdi
    2156:      	callq	0x215b <packet_set_ring+0x1fe>
		0000000000002157:  R_X86_64_PC32	vzalloc-0x4
    215b:      	testq	%rax, %rax
    215e:      	jne	0x216d <packet_set_ring+0x210>
    2160:      	movl	-0x7c(%rbp), %esi
    2163:      	movl	$0xc2d0, %edi           # imm = 0xC2D0
    2168:      	callq	0x216d <packet_set_ring+0x210>
		0000000000002169:  R_X86_64_PC32	__get_free_pages-0x4
    216d:      	movq	-0x98(%rbp), %rsi
    2174:      	testq	%rax, %rax
    2177:      	movq	%rax, (%rsi)
    217a:      	je	0x2181 <packet_set_ring+0x224>
    217c:      	incl	%r15d
    217f:      	jmp	0x2122 <packet_set_ring+0x1c5>
    2181:      	movl	-0x7c(%rbp), %esi
    2184:      	movq	-0x78(%rbp), %rdi
    2188:      	movl	%r13d, %edx
    218b:      	callq	0x4b7 <free_pg_vec>
    2190:      	jmp	0x23b9 <packet_set_ring+0x45c>
    2195:      	cmpl	$0x0, 0xc(%r12)
    219b:      	jne	0x206d <packet_set_ring+0x110>
    21a1:      	movl	$0x0, -0x7c(%rbp)
    21a8:      	movq	$0x0, -0x78(%rbp)
    21b0:      	leaq	0x46c(%rbx), %rax
    21b7:      	movq	%rax, %rdi
    21ba:      	movq	%rax, -0x98(%rbp)
    21c1:      	callq	0x21c6 <packet_set_ring+0x269>
		00000000000021c2:  R_X86_64_PC32	_raw_spin_lock-0x4
    21c6:      	movb	0x498(%rbx), %al
    21cc:      	movl	0x4a0(%rbx), %esi
    21d2:      	andl	$0x1, %eax
    21d5:      	movw	%si, -0xa0(%rbp)
    21dc:      	movl	%eax, -0x98(%rbp)
    21e2:      	je	0x21f7 <packet_set_ring+0x29a>
    21e4:      	movw	$0x0, 0x4a0(%rbx)
    21ed:      	xorl	%esi, %esi
    21ef:      	movq	%rbx, %rdi
    21f2:      	callq	0xa65 <__unregister_prot_hook>
    21f7:      	leaq	0x46c(%rbx), %rdi
    21fe:      	callq	0x26 <__raw_spin_unlock>
    2203:      	callq	0x2208 <packet_set_ring+0x2ab>
		0000000000002204:  R_X86_64_PC32	synchronize_net-0x4
    2208:      	leaq	0x470(%rbx), %rax
    220f:      	movq	%rax, %rdi
    2212:      	movq	%rax, -0xa8(%rbp)
    2219:      	callq	0x221e <packet_set_ring+0x2c1>
		000000000000221a:  R_X86_64_PC32	mutex_lock-0x4
    221e:      	cmpl	$0x0, -0x8c(%rbp)
    2225:      	jne	0x223f <packet_set_ring+0x2e2>
    2227:      	movl	0x4b0(%rbx), %eax
    222d:      	movq	-0x78(%rbp), %r15
    2231:      	movl	$0xfffffff0, %r13d      # imm = 0xFFFFFFF0
    2237:      	testl	%eax, %eax
    2239:      	jne	0x22f9 <packet_set_ring+0x39c>
    223f:      	movq	-0x88(%rbp), %rax
    2246:      	leaq	0x14(%rax), %r13
    224a:      	movq	%r13, %rdi
    224d:      	callq	0x2252 <packet_set_ring+0x2f5>
		000000000000224e:  R_X86_64_PC32	_raw_spin_lock_bh-0x4
    2252:      	movq	-0x78(%rbp), %rax
    2256:      	movq	(%r14), %r15
    2259:      	movq	%r13, %rdi
    225c:      	movq	%rax, (%r14)
    225f:      	movl	0xc(%r12), %eax
    2264:      	movl	$0x0, 0x8(%r14)
    226c:      	decl	%eax
    226e:      	movl	%eax, 0x14(%r14)
    2272:      	movl	0x8(%r12), %eax
    2277:      	movl	%eax, 0x10(%r14)
    227b:      	callq	0x2280 <packet_set_ring+0x323>
		000000000000227c:  R_X86_64_PC32	_raw_spin_unlock_bh-0x4
    2280:      	movl	0x18(%r14), %eax
    2284:      	movl	-0x7c(%rbp), %ecx
    2287:      	movq	-0x88(%rbp), %rdi
    228e:      	movl	%ecx, 0x18(%r14)
    2292:      	movl	%eax, -0x7c(%rbp)
    2295:      	movl	0x4(%r12), %edx
    229a:      	movl	0x20(%r14), %eax
    229e:      	movl	%edx, 0x20(%r14)
    22a2:      	movl	%eax, 0x4(%r12)
    22a7:      	movq	$0x0, %rdx
		00000000000022aa:  R_X86_64_32S	.text+0x35c3
    22ae:      	movl	(%r12), %eax
    22b2:      	shrl	$0xc, %eax
    22b5:      	movl	%eax, 0x1c(%r14)
    22b9:      	cmpq	$0x0, 0x2c8(%rbx)
    22c1:      	movq	$0x0, %rax
		00000000000022c4:  R_X86_64_32S	.text+0x2e92
    22c8:      	cmoveq	%rdx, %rax
    22cc:      	xorl	%r13d, %r13d
    22cf:      	movq	%rax, 0x510(%rbx)
    22d6:      	callq	0x22db <packet_set_ring+0x37e>
		00000000000022d7:  R_X86_64_PC32	skb_queue_purge-0x4
    22db:      	movl	0x4b0(%rbx), %eax
    22e1:      	testl	%eax, %eax
    22e3:      	je	0x22f9 <packet_set_ring+0x39c>
    22e5:      	movl	0x4b0(%rbx), %esi
    22eb:      	movq	$0x0, %rdi
		00000000000022ee:  R_X86_64_32S	.rodata.str1.1+0x280
    22f2:      	xorl	%eax, %eax
    22f4:      	callq	0x22f9 <packet_set_ring+0x39c>
		00000000000022f5:  R_X86_64_PC32	printk-0x4
    22f9:      	leaq	0x470(%rbx), %rdi
    2300:      	callq	0x2305 <packet_set_ring+0x3a8>
		0000000000002301:  R_X86_64_PC32	mutex_unlock-0x4
    2305:      	leaq	0x46c(%rbx), %rdi
    230c:      	callq	0x2311 <packet_set_ring+0x3b4>
		000000000000230d:  R_X86_64_PC32	_raw_spin_lock-0x4
    2311:      	cmpl	$0x0, -0x98(%rbp)
    2318:      	je	0x232f <packet_set_ring+0x3d2>
    231a:      	movl	-0xa0(%rbp), %eax
    2320:      	movq	%rbx, %rdi
    2323:      	movw	%ax, 0x4a0(%rbx)
    232a:      	callq	0xb13 <register_prot_hook>
    232f:      	leaq	0x46c(%rbx), %rdi
    2336:      	callq	0x26 <__raw_spin_unlock>
    233b:      	cmpl	$0x0, -0x8c(%rbp)
    2342:      	je	0x2381 <packet_set_ring+0x424>
    2344:      	cmpl	$0x1, 0x4b4(%rbx)
    234b:      	jbe	0x2381 <packet_set_ring+0x424>
    234d:      	cmpl	$0x0, -0x80(%rbp)
    2351:      	jne	0x2381 <packet_set_ring+0x424>
    2353:      	movq	-0x88(%rbp), %r14
    235a:      	addq	$0x14, %r14
    235e:      	movq	%r14, %rdi
    2361:      	callq	0x2366 <packet_set_ring+0x409>
		0000000000002362:  R_X86_64_PC32	_raw_spin_lock_bh-0x4
    2366:      	movq	%r14, %rdi
    2369:      	movb	$0x1, 0x309(%rbx)
    2370:      	callq	0x2375 <packet_set_ring+0x418>
		0000000000002371:  R_X86_64_PC32	_raw_spin_unlock_bh-0x4
    2375:      	leaq	0x360(%rbx), %rdi
    237c:      	callq	0x2381 <packet_set_ring+0x424>
		000000000000237d:  R_X86_64_PC32	del_timer_sync-0x4
    2381:      	testq	%r15, %r15
    2384:      	je	0x2396 <packet_set_ring+0x439>
    2386:      	movl	0x4(%r12), %edx
    238b:      	movl	-0x7c(%rbp), %esi
    238e:      	movq	%r15, %rdi
    2391:      	callq	0x4b7 <free_pg_vec>
    2396:      	movq	%rbx, %rdi
    2399:      	callq	0x239e <packet_set_ring+0x441>
		000000000000239a:  R_X86_64_PC32	release_sock-0x4
    239e:      	movq	-0x38(%rbp), %rsi
    23a2:      	xorq	%gs:0x28, %rsi
    23ab:      	movl	%r13d, %eax
    23ae:      	je	0x2598 <packet_set_ring+0x63b>
    23b4:      	callq	0x23b9 <packet_set_ring+0x45c>
		00000000000023b5:  R_X86_64_PC32	__stack_chk_fail-0x4
    23b9:      	movl	$0xfffffff4, %r13d      # imm = 0xFFFFFFF4
    23bf:      	jmp	0x2396 <packet_set_ring+0x439>
    23c1:      	cmpl	$0x2, 0x4b4(%rbx)
    23c8:      	jne	0x21b0 <packet_set_ring+0x253>
    23ce:      	cmpl	$0x0, -0x80(%rbp)
    23d2:      	jne	0x21b0 <packet_set_ring+0x253>
    23d8:      	leaq	0x30(%r14), %rax
    23dc:      	movl	$0x28, %ecx
    23e1:      	movq	%rax, %rdi
    23e4:      	movl	-0x80(%rbp), %eax
    23e7:      	rep		stosl	%eax, %es:(%rdi)
    23e9:      	movq	-0x78(%rbp), %rax
    23ed:      	movq	$0x1, 0x68(%r14)
    23f5:      	movq	%rax, 0x30(%r14)
    23f9:      	movq	(%rax), %rax
    23fc:      	movq	%rax, 0x48(%r14)
    2400:      	movq	%rax, -0x98(%rbp)
    2407:      	movl	(%r12), %eax
    240b:      	movl	%eax, 0x58(%r14)
    240f:      	movl	0x4(%r12), %eax
    2414:      	movl	%eax, 0x60(%r14)
    2418:      	movl	0x4b8(%rbx), %eax
    241e:      	movl	%eax, 0x3c(%r14)
    2422:      	movl	0x4b4(%rbx), %eax
    2428:      	movw	$0x0, 0x46(%r14)
    242f:      	movw	%ax, 0x8e(%r14)
    2437:      	movl	$0x0, 0x2c0(%rbx)
    2441:      	movl	0x10(%r12), %eax
    2446:      	testl	%eax, %eax
    2448:      	je	0x2457 <packet_set_ring+0x4fa>
    244a:      	movw	%ax, 0x8c(%r14)
    2452:      	jmp	0x2514 <packet_set_ring+0x5b7>
    2457:      	movl	(%r12), %eax
    245b:      	movl	%eax, -0xa0(%rbp)
    2461:      	callq	0x2466 <packet_set_ring+0x509>
		0000000000002462:  R_X86_64_PC32	rtnl_lock-0x4
    2466:      	movl	0x49c(%rbx), %esi
    246c:      	movq	0x30(%rbx), %rdi
    2470:      	callq	0x2475 <packet_set_ring+0x518>
		0000000000002471:  R_X86_64_PC32	__dev_get_by_index-0x4
    2475:      	testq	%rax, %rax
    2478:      	jne	0x2489 <packet_set_ring+0x52c>
    247a:      	callq	0x247f <packet_set_ring+0x522>
		000000000000247b:  R_X86_64_PC32	rtnl_unlock-0x4
    247f:      	movl	$0x8, %ecx
    2484:      	jmp	0x250c <packet_set_ring+0x5af>
    2489:      	leaq	-0x64(%rbp), %rsi
    248d:      	movq	%rax, %rdi
    2490:      	callq	0x2495 <packet_set_ring+0x538>
		0000000000002491:  R_X86_64_PC32	__ethtool_get_settings-0x4
    2495:      	movzwl	-0x58(%rbp), %r15d
    249a:      	movl	%eax, -0xa8(%rbp)
    24a0:      	movl	-0x48(%rbp), %r13d
    24a4:      	callq	0x24a9 <packet_set_ring+0x54c>
		00000000000024a5:  R_X86_64_PC32	rtnl_unlock-0x4
    24a9:      	movl	-0xa8(%rbp), %eax
    24af:      	testl	%eax, %eax
    24b1:      	jne	0x24e2 <packet_set_ring+0x585>
    24b3:      	movl	%r13d, %eax
    24b6:      	movl	$0x8, %ecx
    24bb:      	shll	$0x10, %eax
    24be:      	orl	%r15d, %eax
    24c1:      	leal	-0x3e8(%rax), %edx
    24c7:      	cmpl	$0xfffffc16, %edx       # imm = 0xFFFFFC16
    24cd:      	ja	0x250c <packet_set_ring+0x5af>
    24cf:      	movl	$0x3e8, %ecx            # imm = 0x3E8
    24d4:      	xorl	%edx, %edx
    24d6:      	divl	%ecx
    24d8:      	movl	$0x1, %ecx
    24dd:      	movl	%eax, %r13d
    24e0:      	jmp	0x24e7 <packet_set_ring+0x58a>
    24e2:      	xorl	%r13d, %r13d
    24e5:      	xorl	%ecx, %ecx
    24e7:      	movl	-0xa0(%rbp), %eax
    24ed:      	movl	$0x100000, %esi         # imm = 0x100000
    24f2:      	shll	$0x3, %eax
    24f5:      	cltd
    24f6:      	idivl	%esi
    24f8:      	testl	%r13d, %r13d
    24fb:      	je	0x2502 <packet_set_ring+0x5a5>
    24fd:      	xorl	%edx, %edx
    24ff:      	divl	%r13d
    2502:      	imull	%eax, %ecx
    2505:      	cmpl	$0x1, %r13d
    2509:      	sbbl	$-0x1, %ecx
    250c:      	movw	%cx, 0x8c(%r14)
    2514:      	movzwl	0x8c(%r14), %edi
    251c:      	callq	0x2521 <packet_set_ring+0x5c4>
		000000000000251d:  R_X86_64_PC32	msecs_to_jiffies-0x4
    2521:      	movq	%rax, 0x90(%r14)
    2528:      	movl	0x14(%r12), %eax
    252d:      	leaq	0x360(%rbx), %rdi
    2534:      	movl	0x58(%r14), %ecx
    2538:      	xorl	%esi, %esi
    253a:      	movw	%ax, 0x44(%r14)
    253f:      	movzwl	%ax, %eax
    2542:      	leal	-0x30(%rcx), %edx
    2545:      	addl	$0x7, %eax
    2548:      	xorl	%ecx, %ecx
    254a:      	andl	$-0x8, %eax
    254d:      	subl	%eax, %edx
    254f:      	movl	%edx, 0x5c(%r14)
    2553:      	movl	0x18(%r12), %eax
    2558:      	xorl	%edx, %edx
    255a:      	movl	%eax, 0x38(%r14)
    255e:      	callq	0x2563 <packet_set_ring+0x606>
		000000000000255f:  R_X86_64_PC32	init_timer_key-0x4
    2563:      	movq	(%rip), %rax            # 0x256a <packet_set_ring+0x60d>
		0000000000002566:  R_X86_64_PC32	jiffies-0x4
    256a:      	movq	-0x98(%rbp), %rsi
    2571:      	leaq	0x30(%r14), %rdi
    2575:      	movq	%rbx, 0x388(%rbx)
    257c:      	movq	$0x0, 0x380(%rbx)
		0000000000002583:  R_X86_64_32S	.text+0x1e52
    2587:      	movq	%rax, 0x370(%rbx)
    258e:      	callq	0x1d6c <prb_open_block>
    2593:      	jmp	0x21b0 <packet_set_ring+0x253>
    2598:      	addq	$0x88, %rsp
    259f:      	popq	%rbx
    25a0:      	popq	%r12
    25a2:      	popq	%r13
    25a4:      	popq	%r14
    25a6:      	popq	%r15
    25a8:      	popq	%rbp
    25a9:      	retq

# ---- tpacket_rcv [0x2e92,0x35c3) ----

work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko:	file format elf64-x86-64

Disassembly of section .text:

0000000000002e92 <tpacket_rcv>:
    2e92:      	pushq	%rbp
    2e93:      	movq	%rsp, %rbp
    2e96:      	pushq	%r15
    2e98:      	pushq	%r14
    2e9a:      	pushq	%r13
    2e9c:      	pushq	%r12
    2e9e:      	pushq	%rbx
    2e9f:      	movq	%rdi, %rbx
    2ea2:      	subq	$0x58, %rsp
    2ea6:      	movq	%rsi, -0x70(%rbp)
    2eaa:      	movq	%rcx, -0x78(%rbp)
    2eae:      	movq	%gs:0x28, %rax
    2eb7:      	movq	%rax, -0x38(%rbp)
    2ebb:      	xorl	%eax, %eax
    2ebd:      	movb	0x90(%rdi), %al
    2ec3:      	andl	$0x7, %eax
    2ec6:      	cmpb	$0x5, %al
    2ec8:      	je	0x356f <tpacket_rcv+0x6dd>
    2ece:      	movq	0x20(%rdx), %r13
    2ed2:      	movq	0x430(%rsi), %rcx
    2ed9:      	cmpq	%rcx, 0x30(%r13)
    2edd:      	jne	0x356f <tpacket_rcv+0x6dd>
    2ee3:      	cmpq	$0x0, 0x200(%rsi)
    2eeb:      	movq	0xd8(%rbx), %rdi
    2ef2:      	movl	0x80(%rbx), %ecx
    2ef8:      	movq	%rdi, -0x60(%rbp)
    2efc:      	movl	%ecx, -0x68(%rbp)
    2eff:      	je	0x2f49 <tpacket_rcv+0xb7>
    2f01:      	cmpw	$0x2, 0x14a(%r13)
    2f0a:      	je	0x2f2b <tpacket_rcv+0x99>
    2f0c:      	movzwl	0xc2(%rbx), %eax
    2f13:      	movq	-0x60(%rbp), %rsi
    2f17:      	movq	%rbx, %rdi
    2f1a:      	addq	0xd0(%rbx), %rax
    2f21:      	subq	%rax, %rsi
    2f24:      	callq	0x2f29 <tpacket_rcv+0x97>
		0000000000002f25:  R_X86_64_PC32	skb_push-0x4
    2f29:      	jmp	0x2f49 <tpacket_rcv+0xb7>
    2f2b:      	cmpb	$0x4, %al
    2f2d:      	jne	0x2f49 <tpacket_rcv+0xb7>
    2f2f:      	movzwl	0xc0(%rbx), %esi
    2f36:      	movq	%rbx, %rdi
    2f39:      	addq	0xd0(%rbx), %rsi
    2f40:      	subq	-0x60(%rbp), %rsi
    2f44:      	callq	0x2f49 <tpacket_rcv+0xb7>
		0000000000002f45:  R_X86_64_PC32	skb_pull-0x4
    2f49:      	movl	0x80(%rbx), %r12d
    2f50:      	incl	%gs:(%rip)
		0000000000002f53:  R_X86_64_PC32	__preempt_count-0x4
    2f57:      	movq	0xe8(%r13), %rax
    2f5e:      	movl	%r12d, %r15d
    2f61:      	testq	%rax, %rax
    2f64:      	je	0x2f77 <tpacket_rcv+0xe5>
    2f66:      	movq	0x18(%rax), %rax
    2f6a:      	movq	%rbx, %rdi
    2f6d:      	leaq	0x28(%rax), %rsi
    2f71:      	callq	*0x20(%rax)
    2f74:      	movl	%eax, %r15d
    2f77:      	decl	%gs:(%rip)
		0000000000002f7a:  R_X86_64_PC32	__preempt_count-0x4
    2f7e:      	testl	%r15d, %r15d
    2f81:      	je	0x3544 <tpacket_rcv+0x6b2>
    2f87:      	movb	0x91(%rbx), %al
    2f8d:      	movl	$0x9, %r14d
    2f93:      	andl	$0x6, %eax
    2f96:      	cmpb	$0x6, %al
    2f98:      	je	0x2fd1 <tpacket_rcv+0x13f>
    2f9a:      	movb	0x90(%rbx), %dl
    2fa0:      	movl	$0x1, %r14d
    2fa6:      	andl	$0x7, %edx
    2fa9:      	cmpb	$0x4, %dl
    2fac:      	je	0x2fd1 <tpacket_rcv+0x13f>
    2fae:      	cmpb	$0x4, %al
    2fb0:      	movl	$0x81, %r14d
    2fb6:      	je	0x2fd1 <tpacket_rcv+0x13f>
    2fb8:      	movq	%rbx, %rdi
    2fbb:      	callq	0x1193 <skb_csum_unnecessary>
    2fc0:      	cmpl	$0x1, %eax
    2fc3:      	sbbq	%r14, %r14
    2fc6:      	andq	$-0x80, %r14
    2fca:      	addq	$0x81, %r14
    2fd1:      	cmpl	%r15d, %r12d
    2fd4:      	movl	0x4b8(%r13), %eax
    2fdb:      	movl	0x4bc(%r13), %esi
    2fe2:      	cmoval	%r15d, %r12d
    2fe6:      	cmpw	$0x2, 0x14a(%r13)
    2fef:      	jne	0x3005 <tpacket_rcv+0x173>
    2ff1:      	addl	$0xf, %eax
    2ff4:      	andl	$-0x10, %eax
    2ff7:      	leal	0x10(%rax,%rsi), %eax
    2ffb:      	movw	%ax, -0x58(%rbp)
    2fff:      	movw	%ax, -0x62(%rbp)
    3003:      	jmp	0x3038 <tpacket_rcv+0x1a6>
    3005:      	movzwl	0xc0(%rbx), %edx
    300c:      	movl	$0x10, %ecx
    3011:      	addq	0xd0(%rbx), %rdx
    3018:      	subq	0xd8(%rbx), %rdx
    301f:      	cmpl	$0x10, %edx
    3022:      	cmovael	%edx, %ecx
    3025:      	leal	0xf(%rax,%rcx), %eax
    3029:      	andl	$-0x10, %eax
    302c:      	addl	%esi, %eax
    302e:      	movw	%ax, -0x62(%rbp)
    3032:      	subl	%edx, %eax
    3034:      	movw	%ax, -0x58(%rbp)
    3038:      	cmpl	$0x1, 0x4b4(%r13)
    3040:      	movzwl	-0x58(%rbp), %ecx
    3044:      	ja	0x30df <tpacket_rcv+0x24d>
    304a:      	leal	(%r12,%rcx), %eax
    304e:      	xorl	%r15d, %r15d
    3051:      	cmpl	0x2d8(%r13), %eax
    3058:      	jbe	0x3132 <tpacket_rcv+0x2a0>
    305e:      	cmpl	$0x0, 0x468(%r13)
    3066:      	je	0x30ca <tpacket_rcv+0x238>
    3068:      	movl	0xb0(%r13), %eax
    306f:      	cmpl	%eax, 0xe4(%r13)
    3076:      	jle	0x30ca <tpacket_rcv+0x238>
    3078:      	movl	0xe4(%rbx), %eax
    307e:      	movl	%ecx, -0x80(%rbp)
    3081:      	decl	%eax
    3083:      	je	0x3097 <tpacket_rcv+0x205>
    3085:      	movl	$0x20, %esi
    308a:      	movq	%rbx, %rdi
    308d:      	callq	0x3092 <tpacket_rcv+0x200>
		000000000000308e:  R_X86_64_PC32	skb_clone-0x4
    3092:      	movq	%rax, %r15
    3095:      	jmp	0x30b1 <tpacket_rcv+0x21f>
    3097:      	leaq	0xe4(%rbx), %rdi
    309e:      	movq	%rbx, %r15
    30a1:      	callq	0x0 <atomic_inc>
    30a6:      	movq	0xd8(%rbx), %rax
    30ad:      	movq	%rax, -0x60(%rbp)
    30b1:      	testq	%r15, %r15
    30b4:      	movl	-0x80(%rbp), %ecx
    30b7:      	je	0x30ca <tpacket_rcv+0x238>
    30b9:      	movq	%r13, %rsi
    30bc:      	movq	%r15, %rdi
    30bf:      	movl	%ecx, -0x80(%rbp)
    30c2:      	callq	0x1527 <skb_set_owner_r>
    30c7:      	movl	-0x80(%rbp), %ecx
    30ca:      	movl	0x2d8(%r13), %r12d
    30d1:      	movl	$0x0, %eax
    30d6:      	subl	%ecx, %r12d
    30d9:      	cmovsl	%eax, %r12d
    30dd:      	jmp	0x3132 <tpacket_rcv+0x2a0>
    30df:      	movl	0x324(%r13), %eax
    30e6:      	leal	(%r12,%rcx), %edx
    30ea:      	xorl	%r15d, %r15d
    30ed:      	cmpl	%eax, %edx
    30ef:      	jbe	0x3132 <tpacket_rcv+0x2a0>
    30f1:      	subl	%ecx, %eax
    30f3:      	cmpb	$0x0, (%rip)            # 0x30fa <tpacket_rcv+0x268>
		00000000000030f5:  R_X86_64_PC32	.data..read_mostly-0x5
    30fa:      	movl	%eax, %r15d
    30fd:      	jne	0x3119 <tpacket_rcv+0x287>
    30ff:      	movl	%eax, %edx
    3101:      	movl	%r12d, %esi
    3104:      	movq	$0x0, %rdi
		0000000000003107:  R_X86_64_32S	.rodata.str1.1+0x33c
    310b:      	xorl	%eax, %eax
    310d:      	movb	$0x1, (%rip)            # 0x3114 <tpacket_rcv+0x282>
		000000000000310f:  R_X86_64_PC32	.data..read_mostly-0x5
    3114:      	callq	0x3119 <tpacket_rcv+0x287>
		0000000000003115:  R_X86_64_PC32	printk-0x4
    3119:      	movl	%r15d, %r12d
    311c:      	xorl	%r15d, %r15d
    311f:      	testl	%r12d, %r12d
    3122:      	jns	0x3132 <tpacket_rcv+0x2a0>
    3124:      	movl	0x324(%r13), %eax
    312b:      	xorl	%r12d, %r12d
    312e:      	movw	%ax, -0x58(%rbp)
    3132:      	leaq	0xac(%r13), %rax
    3139:      	movq	%rax, %rdi
    313c:      	movq	%rax, -0x80(%rbp)
    3140:      	callq	0x3145 <tpacket_rcv+0x2b3>
		0000000000003141:  R_X86_64_PC32	_raw_spin_lock-0x4
    3145:      	movl	0x4b4(%r13), %eax
    314c:      	cmpl	$0x1, %eax
    314f:      	jbe	0x315b <tpacket_rcv+0x2c9>
    3151:      	cmpl	$0x2, %eax
    3154:      	je	0x317b <tpacket_rcv+0x2e9>
    3156:      	jmp	0x32a2 <tpacket_rcv+0x410>
    315b:      	movl	0x2d0(%r13), %edx
    3162:      	leaq	0x2c8(%r13), %rsi
    3169:      	xorl	%ecx, %ecx
    316b:      	movq	%r13, %rdi
    316e:      	callq	0x19bb <packet_lookup_frame>
    3173:      	movq	%rax, %r9
    3176:      	jmp	0x32be <tpacket_rcv+0x42c>
    317b:      	leaq	0x2f8(%r13), %rax
    3182:      	movzwl	0x30a(%r13), %edx
    318a:      	cmpb	$0x0, 0x308(%r13)
    3192:      	movq	%rax, -0x80(%rbp)
    3196:      	movq	0x2f8(%r13), %rax
    319d:      	movq	(%rax,%rdx,8), %rdx
    31a1:      	je	0x31c4 <tpacket_rcv+0x332>
    31a3:      	testb	$0x1, 0x8(%rdx)
    31a7:      	jne	0x358d <tpacket_rcv+0x6fb>
    31ad:      	leaq	0x2f8(%r13), %rdi
    31b4:      	movq	%rdx, %rsi
    31b7:      	movq	%rdx, -0x80(%rbp)
    31bb:      	callq	0x1d6c <prb_open_block>
    31c0:      	movq	-0x80(%rbp), %rdx
    31c4:      	movzwl	-0x58(%rbp), %ecx
    31c8:      	addl	%r12d, %ecx
    31cb:      	mfence
    31ce:      	movslq	0x320(%r13), %rsi
    31d5:      	movq	0x340(%r13), %r9
    31dc:      	leal	0x7(%rcx), %eax
    31df:      	movq	%rbx, 0x348(%r13)
    31e6:      	andl	$-0x8, %eax
    31e9:      	addq	%r9, %rax
    31ec:      	addq	%rdx, %rsi
    31ef:      	cmpq	%rax, %rsi
    31f2:      	jbe	0x3210 <tpacket_rcv+0x37e>
    31f4:      	leaq	0x2f8(%r13), %rsi
    31fb:      	movq	%r9, %rdi
    31fe:      	movq	%r9, -0x80(%rbp)
    3202:      	callq	0x12aa <prb_fill_curr_block>
    3207:      	movq	-0x80(%rbp), %r9
    320b:      	jmp	0x32be <tpacket_rcv+0x42c>
    3210:      	leaq	0x2f8(%r13), %rdi
    3217:      	xorl	%edx, %edx
    3219:      	movq	%r13, %rsi
    321c:      	movl	%ecx, -0x80(%rbp)
    321f:      	callq	0x10ac <prb_retire_current_block>
    3224:      	movzwl	0x30a(%r13), %edx
    322c:      	movq	0x2f8(%r13), %rax
    3233:      	movl	-0x80(%rbp), %ecx
    3236:      	movq	(%rax,%rdx,8), %rsi
    323a:      	testb	$0x1, 0x8(%rsi)
    323e:      	je	0x3254 <tpacket_rcv+0x3c2>
    3240:      	movb	$0x1, 0x308(%r13)
    3248:      	incl	0x2c0(%r13)
    324f:      	jmp	0x358d <tpacket_rcv+0x6fb>
    3254:      	leaq	0x2f8(%r13), %rdi
    325b:      	movl	%ecx, -0x80(%rbp)
    325e:      	callq	0x1d6c <prb_open_block>
    3263:      	movq	0x340(%r13), %r9
    326a:      	testq	%r9, %r9
    326d:      	je	0x358d <tpacket_rcv+0x6fb>
    3273:      	movzwl	0x30a(%r13), %edx
    327b:      	movq	0x2f8(%r13), %rax
    3282:      	leaq	0x2f8(%r13), %rsi
    3289:      	movl	-0x80(%rbp), %ecx
    328c:      	movq	%r9, %rdi
    328f:      	movq	%r9, -0x80(%rbp)
    3293:      	movq	(%rax,%rdx,8), %rdx
    3297:      	callq	0x12aa <prb_fill_curr_block>
    329c:      	movq	-0x80(%rbp), %r9
    32a0:      	jmp	0x32c7 <tpacket_rcv+0x435>
    32a2:      	movq	$0x0, %rdx
		00000000000032a5:  R_X86_64_32S	.rodata.str1.1+0x37d
    32a9:      	movl	$0x460, %esi            # imm = 0x460
    32ae:      	movq	$0x0, %rdi
		00000000000032b1:  R_X86_64_32S	.rodata.str1.1+0xad
    32b5:      	xorl	%eax, %eax
    32b7:      	callq	0x32bc <tpacket_rcv+0x42a>
		00000000000032b8:  R_X86_64_PC32	warn_slowpath_fmt-0x4
    32bc:      	ud2
    32be:      	testq	%r9, %r9
    32c1:      	je	0x358d <tpacket_rcv+0x6fb>
    32c7:      	cmpl	$0x1, 0x4b4(%r13)
    32cf:      	ja	0x3304 <tpacket_rcv+0x472>
    32d1:      	movl	0x2d0(%r13), %edx
    32d8:      	cmpl	0x2dc(%r13), %edx
    32df:      	leal	0x1(%rdx), %eax
    32e2:      	movl	$0x0, %edx
    32e7:      	cmovel	%edx, %eax
    32ea:      	movl	%eax, 0x2d0(%r13)
    32f1:      	movq	%r14, %rax
    32f4:      	orq	$0x4, %rax
    32f8:      	cmpl	$0x0, 0x2bc(%r13)
    3300:      	cmovneq	%rax, %r14
    3304:      	incl	0x2b8(%r13)
    330b:      	testq	%r15, %r15
    330e:      	je	0x333a <tpacket_rcv+0x4a8>
    3310:      	movq	0xa0(%r13), %rax
    3317:      	leaq	0x98(%r13), %rdx
    331e:      	orq	$0x2, %r14
    3322:      	movq	%rdx, (%r15)
    3325:      	movq	%rax, 0x8(%r15)
    3329:      	movq	%r15, (%rax)
    332c:      	incl	0xa8(%r13)
    3333:      	movq	%r15, 0xa0(%r13)
    333a:      	leaq	0xac(%r13), %rdi
    3341:      	movq	%r9, -0x80(%rbp)
    3345:      	callq	0x26 <__raw_spin_unlock>
    334a:      	movzwl	-0x58(%rbp), %edx
    334e:      	xorl	%esi, %esi
    3350:      	movl	%r12d, %ecx
    3353:      	movq	-0x80(%rbp), %r9
    3357:      	movq	%rbx, %rdi
    335a:      	addq	%r9, %rdx
    335d:      	callq	0x3362 <tpacket_rcv+0x4d0>
		000000000000335e:  R_X86_64_PC32	skb_copy_bits-0x4
    3362:      	movl	0x4c4(%r13), %edx
    3369:      	leaq	-0x48(%rbp), %rsi
    336d:      	movq	%rbx, %rdi
    3370:      	callq	0x1357 <tpacket_get_timestamp>
    3375:      	movl	%eax, %r15d
    3378:      	movq	-0x80(%rbp), %r9
    337c:      	testl	%r15d, %r15d
    337f:      	jne	0x338e <tpacket_rcv+0x4fc>
    3381:      	leaq	-0x48(%rbp), %rdi
    3385:      	callq	0x338a <tpacket_rcv+0x4f8>
		0000000000003386:  R_X86_64_PC32	getnstimeofday64-0x4
    338a:      	movq	-0x80(%rbp), %r9
    338e:      	movl	0x4b4(%r13), %edx
    3395:      	orq	%r15, %r14
    3398:      	cmpl	$0x1, %edx
    339b:      	je	0x3429 <tpacket_rcv+0x597>
    33a1:      	movq	-0x48(%rbp), %rax
    33a5:      	jb	0x33f2 <tpacket_rcv+0x560>
    33a7:      	cmpl	$0x2, %edx
    33aa:      	jne	0x349e <tpacket_rcv+0x60c>
    33b0:      	orl	%r14d, 0x14(%r9)
    33b4:      	movl	-0x58(%rbp), %edi
    33b7:      	movl	0x80(%rbx), %edx
    33bd:      	movw	-0x62(%rbp), %cx
    33c1:      	movl	%r12d, 0xc(%r9)
    33c5:      	movl	%eax, 0x4(%r9)
    33c9:      	movl	$0x30, %r12d
    33cf:      	movq	-0x40(%rbp), %rax
    33d3:      	movl	%edx, 0x10(%r9)
    33d7:      	movw	%di, 0x18(%r9)
    33dc:      	movw	%cx, 0x1a(%r9)
    33e1:      	movl	%eax, 0x8(%r9)
    33e5:      	movq	$0x0, 0x28(%r9)
    33ed:      	jmp	0x34a0 <tpacket_rcv+0x60e>
    33f2:      	movl	0x80(%rbx), %edx
    33f8:      	movl	-0x58(%rbp), %ecx
    33fb:      	movl	%r12d, 0xc(%r9)
    33ff:      	movl	%eax, 0x14(%r9)
    3403:      	movl	%edx, 0x8(%r9)
    3407:      	movw	%cx, 0x10(%r9)
    340c:      	movq	-0x40(%rbp), %rax
    3410:      	movw	-0x62(%rbp), %cx
    3414:      	cqto
    3416:      	movw	%cx, 0x12(%r9)
    341b:      	movl	$0x3e8, %ecx            # imm = 0x3E8
    3420:      	idivq	%rcx
    3423:      	movl	%eax, 0x18(%r9)
    3427:      	jmp	0x3496 <tpacket_rcv+0x604>
    3429:      	movl	0x80(%rbx), %eax
    342f:      	movl	%r12d, 0x8(%r9)
    3433:      	movl	%eax, 0x4(%r9)
    3437:      	movl	-0x58(%rbp), %eax
    343a:      	movw	%ax, 0xc(%r9)
    343f:      	movw	-0x62(%rbp), %ax
    3443:      	movw	%ax, 0xe(%r9)
    3448:      	movq	-0x48(%rbp), %rax
    344c:      	movl	%eax, 0x10(%r9)
    3450:      	movq	-0x40(%rbp), %rax
    3454:      	movl	%eax, 0x14(%r9)
    3458:      	movw	0xaa(%rbx), %ax
    345f:      	testb	$0x10, %ah
    3462:      	je	0x3480 <tpacket_rcv+0x5ee>
    3464:      	andb	$-0x11, %ah
    3467:      	orq	$0x50, %r14
    346b:      	movw	%ax, 0x18(%r9)
    3470:      	movzwl	0xa8(%rbx), %eax
    3477:      	xchgb	%al, %ah
    3479:      	movw	%ax, 0x1a(%r9)
    347e:      	jmp	0x348e <tpacket_rcv+0x5fc>
    3480:      	movw	$0x0, 0x18(%r9)
    3487:      	movw	$0x0, 0x1a(%r9)
    348e:      	movl	$0x0, 0x1c(%r9)
    3496:      	movl	$0x20, %r12d
    349c:      	jmp	0x34a0 <tpacket_rcv+0x60e>
    349e:      	ud2
    34a0:      	andl	$0x30, %r12d
    34a4:      	movq	%rbx, %rdi
    34a7:      	movq	%r9, -0x58(%rbp)
    34ab:      	addq	%r9, %r12
    34ae:      	leaq	0xc(%r12), %rsi
    34b3:      	callq	0x36 <dev_parse_header>
    34b8:      	movb	%al, 0xb(%r12)
    34bd:      	movq	-0x70(%rbp), %rax
    34c1:      	movw	$0x11, (%r12)
    34c8:      	movq	-0x58(%rbp), %r9
    34cc:      	movl	0x21c(%rax), %eax
    34d2:      	movw	%ax, 0x8(%r12)
    34d8:      	movl	0xbc(%rbx), %eax
    34de:      	movw	%ax, 0x2(%r12)
    34e4:      	movb	0x90(%rbx), %al
    34ea:      	andl	$0x7, %eax
    34ed:      	movb	%al, 0xa(%r12)
    34f2:      	testb	$0x4, 0x498(%r13)
    34fa:      	je	0x3502 <tpacket_rcv+0x670>
    34fc:      	movq	-0x78(%rbp), %rax
    3500:      	jmp	0x3506 <tpacket_rcv+0x674>
    3502:      	movq	-0x70(%rbp), %rax
    3506:      	movl	0x120(%rax), %eax
    350c:      	movl	%eax, 0x4(%r12)
    3511:      	mfence
    3514:      	cmpl	$0x1, 0x4b4(%r13)
    351c:      	ja	0x3538 <tpacket_rcv+0x6a6>
    351e:      	movq	%r13, %rdi
    3521:      	movl	%r14d, %edx
    3524:      	movq	%r9, %rsi
    3527:      	callq	0xba5 <__packet_set_status>
    352c:      	movq	%r13, %rdi
    352f:      	callq	*0x288(%r13)
    3536:      	jmp	0x3544 <tpacket_rcv+0x6b2>
    3538:      	leaq	0x350(%r13), %rdi
    353f:      	callq	0x9 <atomic_dec>
    3544:      	movq	-0x60(%rbp), %rax
    3548:      	cmpq	0xd8(%rbx), %rax
    354f:      	je	0x356f <tpacket_rcv+0x6dd>
    3551:      	movl	0xe4(%rbx), %eax
    3557:      	decl	%eax
    3559:      	je	0x356f <tpacket_rcv+0x6dd>
    355b:      	movq	-0x60(%rbp), %rax
    355f:      	movq	%rax, 0xd8(%rbx)
    3566:      	movl	-0x68(%rbp), %eax
    3569:      	movl	%eax, 0x80(%rbx)
    356f:      	movq	%rbx, %rdi
    3572:      	callq	0x3577 <tpacket_rcv+0x6e5>
		0000000000003573:  R_X86_64_PC32	kfree_skb-0x4
    3577:      	xorl	%eax, %eax
    3579:      	movq	-0x38(%rbp), %rbx
    357d:      	xorq	%gs:0x28, %rbx
    3586:      	je	0x35b4 <tpacket_rcv+0x722>
    3588:      	callq	0x358d <tpacket_rcv+0x6fb>
		0000000000003589:  R_X86_64_PC32	__stack_chk_fail-0x4
    358d:      	incl	0x2bc(%r13)
    3594:      	leaq	0xac(%r13), %rdi
    359b:      	callq	0x26 <__raw_spin_unlock>
    35a0:      	movq	%r13, %rdi
    35a3:      	callq	*0x288(%r13)
    35aa:      	movq	%r15, %rdi
    35ad:      	callq	0x35b2 <tpacket_rcv+0x720>
		00000000000035ae:  R_X86_64_PC32	kfree_skb-0x4
    35b2:      	jmp	0x3544 <tpacket_rcv+0x6b2>
    35b4:      	addq	$0x58, %rsp
    35b8:      	popq	%rbx
    35b9:      	popq	%r12
    35bb:      	popq	%r13
    35bd:      	popq	%r14
    35bf:      	popq	%r15
    35c1:      	popq	%rbp
    35c2:      	retq

# ---- packet_sendmsg [0x414d,0x4e60) ----

work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/modules/4.1.27-abl/kernel/net/packet/af_packet.ko:	file format elf64-x86-64

Disassembly of section .text:

000000000000414d <packet_sendmsg>:
    414d:      	pushq	%rbp
    414e:      	movq	%rsp, %rbp
    4151:      	pushq	%r15
    4153:      	pushq	%r14
    4155:      	pushq	%r13
    4157:      	pushq	%r12
    4159:      	movq	%rsi, %r14
    415c:      	pushq	%rbx
    415d:      	subq	$0x98, %rsp
    4164:      	movq	0x20(%rdi), %r15
    4168:      	movq	%rdi, -0x70(%rbp)
    416c:      	movq	%gs:0x28, %rax
    4175:      	movq	%rax, -0x38(%rbp)
    4179:      	xorl	%eax, %eax
    417b:      	movq	%rdx, -0x58(%rbp)
    417f:      	movq	(%rsi), %r13
    4182:      	cmpq	$0x0, 0x398(%r15)
    418a:      	je	0x4817 <packet_sendmsg+0x6ca>
    4190:      	leaq	0x470(%r15), %rax
    4197:      	movl	0x48(%rsi), %r12d
    419b:      	movq	%rax, %rdi
    419e:      	movq	%rax, -0x98(%rbp)
    41a5:      	callq	0x41aa <packet_sendmsg+0x5d>
		00000000000041a6:  R_X86_64_PC32	mutex_lock-0x4
    41aa:      	testq	%r13, %r13
    41ad:      	jne	0x41eb <packet_sendmsg+0x9e>
    41af:      	incl	%gs:(%rip)
		00000000000041b2:  R_X86_64_PC32	__preempt_count-0x4
    41b6:      	movq	0x4c8(%r15), %rbx
    41bd:      	testq	%rbx, %rbx
    41c0:      	je	0x41cc <packet_sendmsg+0x7f>
    41c2:      	movq	0x3f0(%rbx), %rax
    41c9:      	incl	%gs:(%rax)
    41cc:      	movl	0x4a0(%r15), %eax
    41d3:      	movq	$0x0, -0x90(%rbp)
    41de:      	decl	%gs:(%rip)
		00000000000041e1:  R_X86_64_PC32	__preempt_count-0x4
    41e5:      	movw	%ax, -0x78(%rbp)
    41e9:      	jmp	0x4235 <packet_sendmsg+0xe8>
    41eb:      	movslq	0x8(%r14), %rax
    41ef:      	movl	$0xffffffea, -0x44(%rbp) # imm = 0xFFFFFFEA
    41f6:      	cmpl	$0x13, %eax
    41f9:      	jbe	0x4803 <packet_sendmsg+0x6b6>
    41ff:      	movzbl	0xb(%r13), %edx
    4204:      	addq	$0xc, %rdx
    4208:      	cmpq	%rdx, %rax
    420b:      	jb	0x4803 <packet_sendmsg+0x6b6>
    4211:      	movw	0x2(%r13), %ax
    4216:      	movl	0x4(%r13), %esi
    421a:      	movq	0x30(%r15), %rdi
    421e:      	movw	%ax, -0x78(%rbp)
    4222:      	leaq	0xc(%r13), %rax
    4226:      	movq	%rax, -0x90(%rbp)
    422d:      	callq	0x4232 <packet_sendmsg+0xe5>
		000000000000422e:  R_X86_64_PC32	dev_get_by_index-0x4
    4232:      	movq	%rax, %rbx
    4235:      	testq	%rbx, %rbx
    4238:      	jne	0x4246 <packet_sendmsg+0xf9>
    423a:      	movl	$0xfffffffa, -0x44(%rbp) # imm = 0xFFFFFFFA
    4241:      	jmp	0x4803 <packet_sendmsg+0x6b6>
    4246:      	movl	$0xffffff9c, -0x44(%rbp) # imm = 0xFFFFFF9C
    424d:      	testb	$0x1, 0x208(%rbx)
    4254:      	je	0x47f9 <packet_sendmsg+0x6ac>
    425a:      	movq	0x238(%r15), %rax
    4261:      	movl	$0x0, -0x70(%rbp)
    4268:      	cmpw	$0x3, 0x4(%rax)
    426d:      	jne	0x4279 <packet_sendmsg+0x12c>
    426f:      	movzwl	0x21e(%rbx), %eax
    4276:      	movl	%eax, -0x70(%rbp)
    4279:      	movl	0x3a8(%r15), %eax
    4280:      	movl	0x218(%rbx), %edx
    4286:      	movl	-0x70(%rbp), %ecx
    4289:      	movl	$0x0, -0x5c(%rbp)
    4290:      	addl	$0x14, %eax
    4293:      	subl	0x4b8(%r15), %eax
    429a:      	leal	0x4(%rcx,%rdx), %edx
    429e:      	cmpl	%edx, %eax
    42a0:      	cmoval	%edx, %eax
    42a3:      	andl	$0x40, %r12d
    42a7:      	movl	%eax, -0x88(%rbp)
    42ad:      	movl	%r12d, -0x84(%rbp)
    42b4:      	movq	%gs:0x0, %rax
		00000000000042b9:  R_X86_64_32S	current_task
    42bd:      	movq	%rax, -0xa8(%rbp)
    42c4:      	movl	-0x78(%rbp), %eax
    42c7:      	xchgb	%al, %ah
    42c9:      	movzwl	%ax, %eax
    42cc:      	movl	%eax, -0xa0(%rbp)
    42d2:      	movq	%gs:0x0, %rax
		00000000000042d7:  R_X86_64_32S	cpu_tss+0x4
    42db:      	movq	%rax, -0xb0(%rbp)
    42e2:      	movl	0x3a0(%r15), %edx
    42e9:      	leaq	0x398(%r15), %rsi
    42f0:      	movl	$0x1, %ecx
    42f5:      	movq	%r15, %rdi
    42f8:      	callq	0x19bb <packet_lookup_frame>
    42fd:      	testq	%rax, %rax
    4300:      	movq	%rax, %r13
    4303:      	jne	0x4332 <packet_sendmsg+0x1e5>
    4305:      	cmpl	$0x0, -0x84(%rbp)
    430c:      	jne	0x4e43 <packet_sendmsg+0xcf6>
    4312:      	movq	-0xb0(%rbp), %rax
    4319:      	movq	-0x3ff8(%rax), %rax
    4320:      	testb	$0x8, %al
    4322:      	je	0x4e2f <packet_sendmsg+0xce2>
    4328:      	callq	0x432d <packet_sendmsg+0x1e0>
		0000000000004329:  R_X86_64_PC32	schedule-0x4
    432d:      	jmp	0x4e2f <packet_sendmsg+0xce2>
    4332:      	movzwl	0x21e(%rbx), %edx
    4339:      	movzwl	0x220(%rbx), %eax
    4340:      	leaq	-0x44(%rbp), %rcx
    4344:      	movzwl	0x222(%rbx), %esi
    434b:      	movq	%r15, %rdi
    434e:      	addl	%edx, %eax
    4350:      	xorl	%edx, %edx
    4352:      	andl	$-0x10, %eax
    4355:      	addl	$0x10, %eax
    4358:      	cmpl	$0x0, -0x84(%rbp)
    435f:      	movl	%eax, -0x58(%rbp)
    4362:      	setne	%dl
    4365:      	addl	%eax, %esi
    4367:      	movslq	%esi, %rsi
    436a:      	addq	$0x14, %rsi
    436e:      	callq	0x4373 <packet_sendmsg+0x226>
		000000000000436f:  R_X86_64_PC32	sock_alloc_send_skb-0x4
    4373:      	testq	%rax, %rax
    4376:      	movq	%rax, %r14
    4379:      	jne	0x4395 <packet_sendmsg+0x248>
    437b:      	cmpl	$0x0, -0x5c(%rbp)
    437f:      	je	0x47de <packet_sendmsg+0x691>
    4385:      	movl	-0x5c(%rbp), %eax
    4388:      	movl	$0x1, %edx
    438d:      	movl	%eax, -0x44(%rbp)
    4390:      	jmp	0x47e6 <packet_sendmsg+0x699>
    4395:      	movl	-0x78(%rbp), %eax
    4398:      	movq	0x238(%r15), %r8
    439f:      	movq	%r15, %rdi
    43a2:      	movq	%rbx, 0x20(%r14)
    43a6:      	movl	0xc8(%r14), %esi
    43ad:      	addq	0xd0(%r14), %rsi
    43b4:      	movw	%ax, 0xbc(%r14)
    43bc:      	movl	0x1c0(%r15), %eax
    43c3:      	movq	%r8, -0x68(%rbp)
    43c7:      	movl	%eax, 0x9c(%r14)
    43ce:      	movl	0x270(%r15), %eax
    43d5:      	incq	%rsi
    43d8:      	movl	%eax, 0xb0(%r14)
    43df:      	callq	0x11d8 <sock_tx_timestamp>
    43e4:      	movl	0xc8(%r14), %eax
    43eb:      	movq	0xd0(%r14), %rdx
    43f2:      	movq	-0x68(%rbp), %r8
    43f6:      	movq	%r13, 0x28(%rdx,%rax)
    43fb:      	cmpl	$0x1, 0x4b4(%r15)
    4403:      	jne	0x440b <packet_sendmsg+0x2be>
    4405:      	movl	0x4(%r13), %r12d
    4409:      	jmp	0x440f <packet_sendmsg+0x2c2>
    440b:      	movl	0x8(%r13), %r12d
    440f:      	cmpl	%r12d, -0x88(%rbp)
    4416:      	jge	0x4434 <packet_sendmsg+0x2e7>
    4418:      	movl	-0x88(%rbp), %edx
    441e:      	movl	%r12d, %esi
    4421:      	movq	$0x0, %rdi
		0000000000004424:  R_X86_64_32S	.rodata.str1.1+0x39c
    4428:      	xorl	%eax, %eax
    442a:      	callq	0x442f <packet_sendmsg+0x2e2>
		000000000000442b:  R_X86_64_PC32	printk-0x4
    442f:      	jmp	0x475b <packet_sendmsg+0x60e>
    4434:      	movslq	-0x58(%rbp), %rax
    4438:      	movl	-0x58(%rbp), %edi
    443b:      	addq	0xd8(%r14), %rax
    4442:      	addl	%edi, 0xc4(%r14)
    4449:      	movq	%rax, 0xd8(%r14)
    4450:      	subq	0xd0(%r14), %rax
    4457:      	movw	%ax, 0xc0(%r14)
    445f:      	testb	$0x2, 0x4c0(%r15)
    4467:      	je	0x44c3 <packet_sendmsg+0x376>
    4469:      	movl	0x3a8(%r15), %edx
    4470:      	movl	0x4b8(%r15), %eax
    4477:      	subl	%r12d, %edx
    447a:      	cmpw	$0x2, 0x4(%r8)
    4480:      	leal	-0x14(%rax), %ecx
    4483:      	movl	0x4b4(%r15), %eax
    448a:      	jne	0x449e <packet_sendmsg+0x351>
    448c:      	decl	%eax
    448e:      	jne	0x4497 <packet_sendmsg+0x34a>
    4490:      	movzwl	0xe(%r13), %eax
    4495:      	jmp	0x44ae <packet_sendmsg+0x361>
    4497:      	movzwl	0x12(%r13), %eax
    449c:      	jmp	0x44ae <packet_sendmsg+0x361>
    449e:      	decl	%eax
    44a0:      	jne	0x44a9 <packet_sendmsg+0x35c>
    44a2:      	movzwl	0xc(%r13), %eax
    44a7:      	jmp	0x44ae <packet_sendmsg+0x361>
    44a9:      	movzwl	0x10(%r13), %eax
    44ae:      	cmpl	%eax, %ecx
    44b0:      	jg	0x4d96 <packet_sendmsg+0xc49>
    44b6:      	cmpl	%eax, %edx
    44b8:      	jl	0x4d96 <packet_sendmsg+0xc49>
    44be:      	addq	%r13, %rax
    44c1:      	jmp	0x44cf <packet_sendmsg+0x382>
    44c3:      	movl	0x4b8(%r15), %eax
    44ca:      	leaq	-0x14(%r13,%rax), %rax
    44cf:      	cmpw	$0x2, 0x4(%r8)
    44d5:      	movq	%rax, -0x58(%rbp)
    44d9:      	jne	0x4513 <packet_sendmsg+0x3c6>
    44db:      	movq	0x200(%rbx), %rax
    44e2:      	testq	%rax, %rax
    44e5:      	je	0x4563 <packet_sendmsg+0x416>
    44e7:      	movq	(%rax), %rax
    44ea:      	testq	%rax, %rax
    44ed:      	je	0x4563 <packet_sendmsg+0x416>
    44ef:      	xorl	%r8d, %r8d
    44f2:      	movl	%r12d, %r9d
    44f5:      	movq	-0x90(%rbp), %rcx
    44fc:      	movl	-0xa0(%rbp), %edx
    4502:      	movq	%rbx, %rsi
    4505:      	movq	%r14, %rdi
    4508:      	callq	*%rax
    450a:      	testl	%eax, %eax
    450c:      	jns	0x4563 <packet_sendmsg+0x416>
    450e:      	jmp	0x4d96 <packet_sendmsg+0xc49>
    4513:      	movzwl	0x21e(%rbx), %esi
    451a:      	movl	%r12d, %edx
    451d:      	testw	%si, %si
    4520:      	je	0x4566 <packet_sendmsg+0x419>
    4522:      	cmpl	%esi, %r12d
    4525:      	jg	0x4709 <packet_sendmsg+0x5bc>
    452b:      	callq	0x4530 <packet_sendmsg+0x3e3>
		000000000000452c:  R_X86_64_PC32	net_ratelimit-0x4
    4530:      	testl	%eax, %eax
    4532:      	je	0x4d96 <packet_sendmsg+0xc49>
    4538:      	movq	-0xa8(%rbp), %rax
    453f:      	movzwl	0x21e(%rbx), %ecx
    4546:      	movl	%r12d, %edx
    4549:      	movq	$0x0, %rdi
		000000000000454c:  R_X86_64_32S	.rodata.str1.1+0x3c1
    4550:      	leaq	0x4a0(%rax), %rsi
    4557:      	xorl	%eax, %eax
    4559:      	callq	0x455e <packet_sendmsg+0x411>
		000000000000455a:  R_X86_64_PC32	printk-0x4
    455e:      	jmp	0x4d96 <packet_sendmsg+0xc49>
    4563:      	movl	%r12d, %edx
    4566:      	movl	-0x58(%rbp), %eax
    4569:      	movl	%edx, 0x84(%r14)
    4570:      	andl	$0xfff, %eax            # imm = 0xFFF
    4575:      	movl	%eax, -0x80(%rbp)
    4578:      	movl	$0x1000, %eax           # imm = 0x1000
    457d:      	subl	-0x80(%rbp), %eax
    4580:      	cmpl	%edx, %eax
    4582:      	cmovgl	%edx, %eax
    4585:      	addl	%edx, 0x80(%r14)
    458c:      	addl	%edx, 0xe0(%r14)
    4593:      	movl	%eax, -0x60(%rbp)
    4596:      	lock
    4597:      	addl	%edx, 0x124(%r15)
    459e:      	testl	%edx, %edx
    45a0:      	je	0x46f2 <packet_sendmsg+0x5a5>
    45a6:      	movl	0xc8(%r14), %eax
    45ad:      	movq	0xd0(%r14), %rcx
    45b4:      	movzbl	(%rcx,%rax), %eax
    45b8:      	movb	%al, -0x68(%rbp)
    45bb:      	cmpb	$0x10, -0x68(%rbp)
    45bf:      	movl	%eax, -0x9c(%rbp)
    45c5:      	jbe	0x45e5 <packet_sendmsg+0x498>
    45c7:      	movl	$0x11, %esi
    45cc:      	movq	$0x0, %rdi
		00000000000045cf:  R_X86_64_32S	.rodata.str1.1+0x3ec
    45d3:      	xorl	%eax, %eax
    45d5:      	callq	0x45da <packet_sendmsg+0x48d>
		00000000000045d6:  R_X86_64_PC32	printk-0x4
    45da:      	movl	$0xfffffff2, %r12d      # imm = 0xFFFFFFF2
    45e0:      	jmp	0x4ddd <packet_sendmsg+0xc90>
    45e5:      	movq	-0x58(%rbp), %rdi
    45e9:      	movl	%edx, -0xb8(%rbp)
    45ef:      	callq	0x53c <pgv_to_page>
    45f4:      	movq	%rax, %rcx
    45f7:      	movslq	-0x60(%rbp), %rax
    45fb:      	movl	-0xb8(%rbp), %edx
    4601:      	addq	%rax, -0x58(%rbp)
    4605:      	movq	(%rcx), %rax
    4608:      	testb	$-0x80, %ah
    460b:      	jne	0x4632 <packet_sendmsg+0x4e5>
    460d:      	leaq	0x1c(%rcx), %rdi
    4611:      	movl	%edx, -0xbc(%rbp)
    4617:      	movq	%rcx, -0xb8(%rbp)
    461e:      	callq	0x0 <atomic_inc>
    4623:      	movq	-0xb8(%rbp), %rcx
    462a:      	movl	-0xbc(%rbp), %edx
    4630:      	jmp	0x4658 <packet_sendmsg+0x50b>
    4632:      	movq	%rcx, %rdi
    4635:      	movl	%edx, -0xbc(%rbp)
    463b:      	movq	%rcx, -0xb8(%rbp)
    4642:      	callq	0x4647 <packet_sendmsg+0x4fa>
		0000000000004643:  R_X86_64_PC32	__get_page_tail-0x4
    4647:      	testb	%al, %al
    4649:      	movq	-0xb8(%rbp), %rcx
    4650:      	movl	-0xbc(%rbp), %edx
    4656:      	je	0x460d <packet_sendmsg+0x4c0>
    4658:      	movl	0xc8(%r14), %esi
    465f:      	movzbl	-0x68(%rbp), %eax
    4663:      	addq	0xd0(%r14), %rsi
    466a:      	movl	-0x80(%rbp), %edi
    466d:      	shlq	$0x4, %rax
    4671:      	addq	%rsi, %rax
    4674:      	movl	%edi, 0x38(%rax)
    4677:      	movq	%rcx, 0x30(%rax)
    467b:      	movslq	-0x9c(%rbp), %rax
    4682:      	movl	-0x60(%rbp), %edi
    4685:      	addq	$0x3, %rax
    4689:      	shlq	$0x4, %rax
    468d:      	movl	%edi, 0xc(%rsi,%rax)
    4691:      	movq	(%rcx), %rsi
    4694:      	movq	%rcx, %rax
    4697:      	testl	$0x8000, %esi           # imm = 0x8000
    469d:      	je	0x46ad <packet_sendmsg+0x560>
    469f:      	movq	0x30(%rcx), %rsi
    46a3:      	movq	(%rcx), %rcx
    46a6:      	andb	$-0x80, %ch
    46a9:      	cmovneq	%rsi, %rax
    46ad:      	cmpq	$-0x1, 0x10(%rax)
    46b2:      	jne	0x46bc <packet_sendmsg+0x56f>
    46b4:      	orb	$0x8, 0x90(%r14)
    46bc:      	subl	-0x60(%rbp), %edx
    46bf:      	movl	0xc8(%r14), %eax
    46c6:      	movb	-0x68(%rbp), %cl
    46c9:      	movq	0xd0(%r14), %rsi
    46d0:      	movl	$0x0, -0x80(%rbp)
    46d7:      	incl	%ecx
    46d9:      	cmpl	$0x1000, %edx           # imm = 0x1000
    46df:      	movb	%cl, (%rsi,%rax)
    46e2:      	movl	$0x1000, %eax           # imm = 0x1000
    46e7:      	cmovlel	%edx, %eax
    46ea:      	movl	%eax, -0x60(%rbp)
    46ed:      	jmp	0x459e <packet_sendmsg+0x451>
    46f2:      	cmpw	$-0x1, 0xbe(%r14)
    46fb:      	jne	0x4731 <packet_sendmsg+0x5e4>
    46fd:      	xorl	%esi, %esi
    46ff:      	movq	%r14, %rdi
    4702:      	callq	0x14af <skb_probe_transport_header.part.42>
    4707:      	jmp	0x4731 <packet_sendmsg+0x5e4>
    4709:      	movq	%r14, %rdi
    470c:      	callq	0x4711 <packet_sendmsg+0x5c4>
		000000000000470d:  R_X86_64_PC32	skb_push-0x4
    4711:      	movzwl	0x21e(%rbx), %ecx
    4718:      	movq	-0x58(%rbp), %rdx
    471c:      	xorl	%esi, %esi
    471e:      	movq	%r14, %rdi
    4721:      	callq	0x4726 <packet_sendmsg+0x5d9>
		0000000000004722:  R_X86_64_PC32	skb_store_bits-0x4
    4726:      	testl	%eax, %eax
    4728:      	je	0x4d40 <packet_sendmsg+0xbf3>
    472e:      	movl	%eax, %r12d
    4731:      	testl	%r12d, %r12d
    4734:      	js	0x4ddd <packet_sendmsg+0xc90>
    473a:      	movl	-0x70(%rbp), %eax
    473d:      	addl	0x218(%rbx), %eax
    4743:      	cmpl	%r12d, %eax
    4746:      	jae	0x4766 <packet_sendmsg+0x619>
    4748:      	movw	0x21c(%rbx), %di
    474f:      	movq	%r14, %rsi
    4752:      	callq	0x120b <packet_extra_vlan_len_allowed.isra.37>
    4757:      	testb	%al, %al
    4759:      	jne	0x4766 <packet_sendmsg+0x619>
    475b:      	movl	$0xffffffa6, %r12d      # imm = 0xFFFFFFA6
    4761:      	jmp	0x4ddd <packet_sendmsg+0xc90>
    4766:      	movq	%r14, %rsi
    4769:      	movq	%rbx, %rdi
    476c:      	callq	0x6ef <packet_pick_tx_queue>
    4771:      	movl	$0x2, %edx
    4776:      	movq	%r13, %rsi
    4779:      	movq	%r15, %rdi
    477c:      	movq	$0x0, 0x60(%r14)
		0000000000004780:  R_X86_64_32S	.text+0x13b7
    4784:      	callq	0xba5 <__packet_set_status>
    4789:      	movq	0x3c0(%r15), %rax
    4790:      	movq	%r14, %rdi
    4793:      	incl	%gs:(%rax)
    4796:      	callq	*0x4d0(%r15)
    479d:      	testl	%eax, %eax
    479f:      	movl	%eax, -0x44(%rbp)
    47a2:      	jle	0x4db4 <packet_sendmsg+0xc67>
    47a8:      	cmpl	$0x2, %eax
    47ab:      	movl	$0x0, %edx
    47b0:      	movl	$0xffffff97, %eax       # imm = 0xFFFFFF97
    47b5:      	cmovel	%edx, %eax
    47b8:      	testl	%eax, %eax
    47ba:      	movl	%eax, -0x44(%rbp)
    47bd:      	je	0x4d9e <packet_sendmsg+0xc51>
    47c3:      	movl	0x4b4(%r15), %eax
    47ca:      	testl	%eax, %eax
    47cc:      	jne	0x4da7 <packet_sendmsg+0xc5a>
    47d2:      	movl	(%r13), %eax
    47d6:      	testl	%eax, %eax
    47d8:      	jne	0x4d9e <packet_sendmsg+0xc51>
    47de:      	movl	$0x1, %edx
    47e3:      	xorl	%r14d, %r14d
    47e6:      	movq	%r15, %rdi
    47e9:      	movq	%r13, %rsi
    47ec:      	callq	0xba5 <__packet_set_status>
    47f1:      	movq	%r14, %rdi
    47f4:      	callq	0x47f9 <packet_sendmsg+0x6ac>
		00000000000047f5:  R_X86_64_PC32	kfree_skb-0x4
    47f9:      	movq	0x3f0(%rbx), %rax
    4800:      	decl	%gs:(%rax)
    4803:      	movq	-0x98(%rbp), %rdi
    480a:      	callq	0x480f <packet_sendmsg+0x6c2>
		000000000000480b:  R_X86_64_PC32	mutex_unlock-0x4
    480f:      	movl	-0x44(%rbp), %eax
    4812:      	jmp	0x4d28 <packet_sendmsg+0xbdb>
    4817:      	leaq	-0x44(%rbp), %rdi
    481b:      	xorl	%eax, %eax
    481d:      	movl	$0xa, %ecx
    4822:      	testq	%r13, %r13
    4825:      	rep		stosb	%al, %es:(%rdi)
    4827:      	jne	0x4863 <packet_sendmsg+0x716>
    4829:      	incl	%gs:(%rip)
		000000000000482c:  R_X86_64_PC32	__preempt_count-0x4
    4830:      	movq	0x4c8(%r15), %r12
    4837:      	testq	%r12, %r12
    483a:      	je	0x4847 <packet_sendmsg+0x6fa>
    483c:      	movq	0x3f0(%r12), %rax
    4844:      	incl	%gs:(%rax)
    4847:      	movl	0x4a0(%r15), %eax
    484e:      	movq	$0x0, -0x78(%rbp)
    4856:      	decl	%gs:(%rip)
		0000000000004859:  R_X86_64_PC32	__preempt_count-0x4
    485d:      	movw	%ax, -0x60(%rbp)
    4861:      	jmp	0x48aa <packet_sendmsg+0x75d>
    4863:      	movslq	0x8(%rsi), %rax
    4867:      	movl	$0xffffffea, -0x48(%rbp) # imm = 0xFFFFFFEA
    486e:      	cmpl	$0x13, %eax
    4871:      	jbe	0x4d25 <packet_sendmsg+0xbd8>
    4877:      	movzbl	0xb(%r13), %edx
    487c:      	addq	$0xc, %rdx
    4880:      	cmpq	%rdx, %rax
    4883:      	jb	0x4d25 <packet_sendmsg+0xbd8>
    4889:      	movw	0x2(%r13), %ax
    488e:      	movl	0x4(%r13), %esi
    4892:      	movq	0x30(%r15), %rdi
    4896:      	movw	%ax, -0x60(%rbp)
    489a:      	leaq	0xc(%r13), %rax
    489e:      	movq	%rax, -0x78(%rbp)
    48a2:      	callq	0x48a7 <packet_sendmsg+0x75a>
		00000000000048a3:  R_X86_64_PC32	dev_get_by_index-0x4
    48a7:      	movq	%rax, %r12
    48aa:      	testq	%r12, %r12
    48ad:      	jne	0x48bb <packet_sendmsg+0x76e>
    48af:      	movl	$0xfffffffa, -0x48(%rbp) # imm = 0xFFFFFFFA
    48b6:      	jmp	0x4d25 <packet_sendmsg+0xbd8>
    48bb:      	testb	$0x1, 0x208(%r12)
    48c4:      	movl	$0xffffff9c, -0x48(%rbp) # imm = 0xFFFFFF9C
    48cb:      	je	0x4d1a <packet_sendmsg+0xbcd>
    48d1:      	movq	-0x70(%rbp), %rax
    48d5:      	movl	$0x0, -0x5c(%rbp)
    48dc:      	cmpw	$0x3, 0x4(%rax)
    48e1:      	jne	0x48ef <packet_sendmsg+0x7a2>
    48e3:      	movzwl	0x21e(%r12), %eax
    48ec:      	movl	%eax, -0x5c(%rbp)
    48ef:      	testb	$0x8, 0x498(%r15)
    48f7:      	je	0x49c0 <packet_sendmsg+0x873>
    48fd:      	cmpq	$0x9, -0x58(%rbp)
    4902:      	ja	0x4910 <packet_sendmsg+0x7c3>
    4904:      	movl	$0xffffffea, -0x48(%rbp) # imm = 0xFFFFFFEA
    490b:      	jmp	0x4d1a <packet_sendmsg+0xbcd>
    4910:      	leaq	0x10(%r14), %rdx
    4914:      	leaq	-0x44(%rbp), %rdi
    4918:      	movl	$0xa, %esi
    491d:      	movl	$0xfffffff2, -0x48(%rbp) # imm = 0xFFFFFFF2
    4924:      	callq	0x4929 <packet_sendmsg+0x7dc>
		0000000000004925:  R_X86_64_PC32	copy_from_iter-0x4
    4929:      	cmpq	$0xa, %rax
    492d:      	jne	0x4d1a <packet_sendmsg+0xbcd>
    4933:      	testb	$0x1, -0x44(%rbp)
    4937:      	je	0x4959 <packet_sendmsg+0x80c>
    4939:      	movzwl	-0x3c(%rbp), %ecx
    493d:      	movzwl	-0x3e(%rbp), %esi
    4941:      	movl	%ecx, %edx
    4943:      	movl	%esi, %eax
    4945:      	leal	0x2(%rsi,%rcx), %esi
    4949:      	movzwl	-0x42(%rbp), %ecx
    494d:      	cmpl	%ecx, %esi
    494f:      	jle	0x4959 <packet_sendmsg+0x80c>
    4951:      	leal	0x2(%rax,%rdx), %eax
    4955:      	movw	%ax, -0x42(%rbp)
    4959:      	subq	$0xa, -0x58(%rbp)
    495e:      	movzwl	-0x42(%rbp), %eax
    4962:      	cmpq	%rax, -0x58(%rbp)
    4966:      	movl	$0xffffffea, -0x48(%rbp) # imm = 0xFFFFFFEA
    496d:      	jb	0x4d1a <packet_sendmsg+0xbcd>
    4973:      	movb	-0x43(%rbp), %al
    4976:      	testb	%al, %al
    4978:      	je	0x49c0 <packet_sendmsg+0x873>
    497a:      	movl	%eax, %edx
    497c:      	andl	$0x7f, %edx
    497f:      	cmpl	$0x3, %edx
    4982:      	je	0x49a1 <packet_sendmsg+0x854>
    4984:      	cmpl	$0x4, %edx
    4987:      	je	0x4999 <packet_sendmsg+0x84c>
    4989:      	decl	%edx
    498b:      	jne	0x4d1a <packet_sendmsg+0xbcd>
    4991:      	movl	$0x1, %r13d
    4997:      	jmp	0x49a7 <packet_sendmsg+0x85a>
    4999:      	movl	$0x10, %r13d
    499f:      	jmp	0x49a7 <packet_sendmsg+0x85a>
    49a1:      	movl	$0x2, %r13d
    49a7:      	movl	%r13d, %edx
    49aa:      	orl	$0x8, %edx
    49ad:      	testb	%al, %al
    49af:      	cmovsl	%edx, %r13d
    49b3:      	cmpw	$0x0, -0x40(%rbp)
    49b8:      	je	0x4d1a <packet_sendmsg+0xbcd>
    49be:      	jmp	0x49c3 <packet_sendmsg+0x876>
    49c0:      	xorl	%r13d, %r13d
    49c3:      	movq	0x108(%r15), %rax
    49ca:      	movl	$0x0, -0x68(%rbp)
    49d1:      	testl	$0x200000, %eax         # imm = 0x200000
    49d6:      	je	0x49f6 <packet_sendmsg+0x8a9>
    49d8:      	testb	$0x8, 0x20e(%r12)
    49e1:      	jne	0x49ef <packet_sendmsg+0x8a2>
    49e3:      	movl	$0xffffffa3, -0x48(%rbp) # imm = 0xFFFFFFA3
    49ea:      	jmp	0x4d1a <packet_sendmsg+0xbcd>
    49ef:      	movl	$0x4, -0x68(%rbp)
    49f6:      	testw	%r13w, %r13w
    49fa:      	movl	$0xffffffa6, -0x48(%rbp) # imm = 0xFFFFFFA6
    4a01:      	jne	0x4a1f <packet_sendmsg+0x8d2>
    4a03:      	movl	-0x5c(%rbp), %eax
    4a06:      	addl	0x218(%r12), %eax
    4a0e:      	movl	-0x68(%rbp), %ebx
    4a11:      	leal	0x4(%rbx,%rax), %eax
    4a15:      	cmpq	-0x58(%rbp), %rax
    4a19:      	jb	0x4d1a <packet_sendmsg+0xbcd>
    4a1f:      	movzwl	0x21e(%r12), %edx
    4a28:      	movzwl	0x220(%r12), %eax
    4a31:      	movzwl	0x222(%r12), %esi
    4a3a:      	movl	0x48(%r14), %ecx
    4a3e:      	movl	$0xffffff97, -0x48(%rbp) # imm = 0xFFFFFF97
    4a45:      	movzwl	-0x42(%rbp), %r11d
    4a4a:      	addl	%edx, %eax
    4a4c:      	andl	$0x40, %ecx
    4a4f:      	andl	$-0x10, %eax
    4a52:      	leal	0x10(%rax), %r10d
    4a56:      	movq	-0x58(%rbp), %rax
    4a5a:      	addl	%r10d, %esi
    4a5d:      	movslq	%esi, %rsi
    4a60:      	addq	%rsi, %rax
    4a63:      	cmpq	$0xfff, %rax            # imm = 0xFFF
    4a69:      	jbe	0x4a70 <packet_sendmsg+0x923>
    4a6b:      	testq	%r11, %r11
    4a6e:      	jne	0x4a74 <packet_sendmsg+0x927>
    4a70:      	movq	-0x58(%rbp), %r11
    4a74:      	movq	-0x58(%rbp), %rdx
    4a78:      	leaq	-0x48(%rbp), %r8
    4a7c:      	addq	%r11, %rsi
    4a7f:      	xorl	%r9d, %r9d
    4a82:      	movq	%r15, %rdi
    4a85:      	movl	%r10d, -0x84(%rbp)
    4a8c:      	movq	%r11, -0x80(%rbp)
    4a90:      	subq	%r11, %rdx
    4a93:      	callq	0x4a98 <packet_sendmsg+0x94b>
		0000000000004a94:  R_X86_64_PC32	sock_alloc_send_pskb-0x4
    4a98:      	testq	%rax, %rax
    4a9b:      	movq	%rax, %rbx
    4a9e:      	je	0x4d1a <packet_sendmsg+0xbcd>
    4aa4:      	movslq	-0x84(%rbp), %rax
    4aab:      	movq	-0x80(%rbp), %r11
    4aaf:      	movq	%rbx, %rdi
    4ab2:      	addq	%rax, 0xd8(%rbx)
    4ab9:      	addl	%eax, 0xc4(%rbx)
    4abf:      	movl	%r11d, %esi
    4ac2:      	callq	0x4ac7 <packet_sendmsg+0x97a>
		0000000000004ac3:  R_X86_64_PC32	skb_put-0x4
    4ac7:      	movl	-0x58(%rbp), %eax
    4aca:      	movq	-0x80(%rbp), %r11
    4ace:      	movl	$0xffffffea, -0x48(%rbp) # imm = 0xFFFFFFEA
    4ad5:      	subl	%r11d, %eax
    4ad8:      	addl	%eax, 0x80(%rbx)
    4ade:      	movl	%eax, 0x84(%rbx)
    4ae4:      	movq	0xd8(%rbx), %rax
    4aeb:      	subq	0xd0(%rbx), %rax
    4af2:      	addl	-0x5c(%rbp), %eax
    4af5:      	movw	%ax, 0xc0(%rbx)
    4afc:      	movq	-0x70(%rbp), %rax
    4b00:      	cmpw	$0x2, 0x4(%rax)
    4b05:      	jne	0x4b40 <packet_sendmsg+0x9f3>
    4b07:      	movl	-0x60(%rbp), %edx
    4b0a:      	movq	0x200(%r12), %rax
    4b12:      	xchgb	%dl, %dh
    4b14:      	testq	%rax, %rax
    4b17:      	je	0x4b8c <packet_sendmsg+0xa3f>
    4b19:      	movq	(%rax), %rax
    4b1c:      	testq	%rax, %rax
    4b1f:      	je	0x4b8c <packet_sendmsg+0xa3f>
    4b21:      	xorl	%r8d, %r8d
    4b24:      	movzwl	%dx, %edx
    4b27:      	movl	-0x58(%rbp), %r9d
    4b2b:      	movq	-0x78(%rbp), %rcx
    4b2f:      	movq	%r12, %rsi
    4b32:      	movq	%rbx, %rdi
    4b35:      	callq	*%rax
    4b37:      	testl	%eax, %eax
    4b39:      	jns	0x4b8e <packet_sendmsg+0xa41>
    4b3b:      	jmp	0x4d12 <packet_sendmsg+0xbc5>
    4b40:      	movzwl	0x21e(%r12), %edx
    4b49:      	xorl	%eax, %eax
    4b4b:      	cmpl	%edx, -0x58(%rbp)
    4b4e:      	jg	0x4b8e <packet_sendmsg+0xa41>
    4b50:      	callq	0x4b55 <packet_sendmsg+0xa08>
		0000000000004b51:  R_X86_64_PC32	net_ratelimit-0x4
    4b55:      	testl	%eax, %eax
    4b57:      	je	0x4d12 <packet_sendmsg+0xbc5>
    4b5d:      	movzwl	0x21e(%r12), %ecx
    4b66:      	movl	-0x58(%rbp), %edx
    4b69:      	movq	$0x0, %rdi
		0000000000004b6c:  R_X86_64_32S	.rodata.str1.1+0x3c1
    4b70:      	movq	%gs:0x0, %rsi
		0000000000004b75:  R_X86_64_32S	current_task
    4b79:      	xorl	%eax, %eax
    4b7b:      	addq	$0x4a0, %rsi            # imm = 0x4A0
    4b82:      	callq	0x4b87 <packet_sendmsg+0xa3a>
		0000000000004b83:  R_X86_64_PC32	printk-0x4
    4b87:      	jmp	0x4d12 <packet_sendmsg+0xbc5>
    4b8c:      	xorl	%eax, %eax
    4b8e:      	movl	-0x58(%rbp), %ecx
    4b91:      	leaq	0x10(%r14), %rdx
    4b95:      	movl	%eax, %esi
    4b97:      	movq	%rbx, %rdi
    4b9a:      	callq	0x4b9f <packet_sendmsg+0xa52>
		0000000000004b9b:  R_X86_64_PC32	skb_copy_datagram_from_iter-0x4
    4b9f:      	testl	%eax, %eax
    4ba1:      	movl	%eax, %r14d
    4ba4:      	movl	%eax, -0x48(%rbp)
    4ba7:      	jne	0x4d12 <packet_sendmsg+0xbc5>
    4bad:      	movl	0xc8(%rbx), %esi
    4bb3:      	movq	%r15, %rdi
    4bb6:      	addq	0xd0(%rbx), %rsi
    4bbd:      	incq	%rsi
    4bc0:      	callq	0x11d8 <sock_tx_timestamp>
    4bc5:      	testw	%r13w, %r13w
    4bc9:      	jne	0x4c02 <packet_sendmsg+0xab5>
    4bcb:      	movl	-0x5c(%rbp), %eax
    4bce:      	addl	0x218(%r12), %eax
    4bd6:      	movl	-0x68(%rbp), %ecx
    4bd9:      	addl	%ecx, %eax
    4bdb:      	cmpq	%rax, -0x58(%rbp)
    4bdf:      	jbe	0x4c02 <packet_sendmsg+0xab5>
    4be1:      	movw	0x21c(%r12), %di
    4bea:      	movq	%rbx, %rsi
    4bed:      	callq	0x120b <packet_extra_vlan_len_allowed.isra.37>
    4bf2:      	testb	%al, %al
    4bf4:      	jne	0x4c02 <packet_sendmsg+0xab5>
    4bf6:      	movl	$0xffffffa6, -0x48(%rbp) # imm = 0xFFFFFFA6
    4bfd:      	jmp	0x4d12 <packet_sendmsg+0xbc5>
    4c02:      	movl	-0x60(%rbp), %eax
    4c05:      	movq	%r12, 0x20(%rbx)
    4c09:      	movq	%rbx, %rsi
    4c0c:      	movq	%r12, %rdi
    4c0f:      	movw	%ax, 0xbc(%rbx)
    4c16:      	movl	0x1c0(%r15), %eax
    4c1d:      	movl	%eax, 0x9c(%rbx)
    4c23:      	movl	0x270(%r15), %eax
    4c2a:      	movl	%eax, 0xb0(%rbx)
    4c30:      	callq	0x6ef <packet_pick_tx_queue>
    4c35:      	testb	$0x8, 0x498(%r15)
    4c3d:      	je	0x4cb8 <packet_sendmsg+0xb6b>
    4c3f:      	testb	$0x1, -0x44(%rbp)
    4c43:      	je	0x4c65 <packet_sendmsg+0xb18>
    4c45:      	movzwl	-0x3c(%rbp), %edx
    4c49:      	movzwl	-0x3e(%rbp), %esi
    4c4d:      	movq	%rbx, %rdi
    4c50:      	callq	0x4c55 <packet_sendmsg+0xb08>
		0000000000004c51:  R_X86_64_PC32	skb_partial_csum_set-0x4
    4c55:      	testb	%al, %al
    4c57:      	jne	0x4c65 <packet_sendmsg+0xb18>
    4c59:      	movl	$0xffffffea, -0x48(%rbp) # imm = 0xFFFFFFEA
    4c60:      	jmp	0x4d12 <packet_sendmsg+0xbc5>
    4c65:      	movl	0xc8(%rbx), %eax
    4c6b:      	movq	0xd0(%rbx), %rdx
    4c72:      	movl	-0x40(%rbp), %ecx
    4c75:      	addq	$0xa, -0x58(%rbp)
    4c7a:      	movw	%cx, 0x2(%rdx,%rax)
    4c7f:      	movl	0xc8(%rbx), %eax
    4c85:      	movq	0xd0(%rbx), %rdx
    4c8c:      	movw	%r13w, 0x6(%rdx,%rax)
    4c92:      	movl	0xc8(%rbx), %eax
    4c98:      	addq	0xd0(%rbx), %rax
    4c9f:      	orw	$0x4, 0x6(%rax)
    4ca4:      	movl	0xc8(%rbx), %eax
    4caa:      	movq	0xd0(%rbx), %rdx
    4cb1:      	movw	$0x0, 0x4(%rdx,%rax)
    4cb8:      	cmpw	$-0x1, 0xbe(%rbx)
    4cc0:      	jne	0x4ccd <packet_sendmsg+0xb80>
    4cc2:      	movl	-0x5c(%rbp), %esi
    4cc5:      	movq	%rbx, %rdi
    4cc8:      	callq	0x14af <skb_probe_transport_header.part.42>
    4ccd:      	cmpl	$0x4, -0x68(%rbp)
    4cd1:      	jne	0x4cda <packet_sendmsg+0xb8d>
    4cd3:      	orb	$0x1, 0x92(%rbx)
    4cda:      	movq	%rbx, %rdi
    4cdd:      	callq	*0x4d0(%r15)
    4ce4:      	testl	%eax, %eax
    4ce6:      	jg	0x4cfb <packet_sendmsg+0xbae>
    4ce8:      	movl	%eax, -0x48(%rbp)
    4ceb:      	movq	0x3f0(%r12), %rax
    4cf3:      	decl	%gs:(%rax)
    4cf6:      	movl	-0x58(%rbp), %eax
    4cf9:      	jmp	0x4d28 <packet_sendmsg+0xbdb>
    4cfb:      	cmpl	$0x2, %eax
    4cfe:      	movl	$0xffffff97, %eax       # imm = 0xFFFFFF97
    4d03:      	cmovnel	%eax, %r14d
    4d07:      	testl	%r14d, %r14d
    4d0a:      	movl	%r14d, -0x48(%rbp)
    4d0e:      	jne	0x4d1a <packet_sendmsg+0xbcd>
    4d10:      	jmp	0x4ceb <packet_sendmsg+0xb9e>
    4d12:      	movq	%rbx, %rdi
    4d15:      	callq	0x4d1a <packet_sendmsg+0xbcd>
		0000000000004d16:  R_X86_64_PC32	kfree_skb-0x4
    4d1a:      	movq	0x3f0(%r12), %rax
    4d22:      	decl	%gs:(%rax)
    4d25:      	movl	-0x48(%rbp), %eax
    4d28:      	movq	-0x38(%rbp), %rbx
    4d2c:      	xorq	%gs:0x28, %rbx
    4d35:      	je	0x4e4e <packet_sendmsg+0xd01>
    4d3b:      	callq	0x4d40 <packet_sendmsg+0xbf3>
		0000000000004d3c:  R_X86_64_PC32	__stack_chk_fail-0x4
    4d40:      	cmpw	$0x0, 0xbc(%r14)
    4d49:      	jne	0x4d7e <packet_sendmsg+0xc31>
    4d4b:      	cmpw	$0x1, 0x21c(%rbx)
    4d53:      	jne	0x4d7e <packet_sendmsg+0xc31>
    4d55:      	movq	0xd0(%r14), %rdx
    4d5c:      	movq	0xd8(%r14), %rax
    4d63:      	subq	%rdx, %rax
    4d66:      	movw	%ax, 0xc2(%r14)
    4d6e:      	movzwl	%ax, %eax
    4d71:      	movw	0xc(%rdx,%rax), %ax
    4d76:      	movw	%ax, 0xbc(%r14)
    4d7e:      	movzwl	0x21e(%rbx), %edx
    4d85:      	addq	%rdx, -0x58(%rbp)
    4d89:      	movq	%rdx, %rax
    4d8c:      	movl	%r12d, %edx
    4d8f:      	subl	%eax, %edx
    4d91:      	jmp	0x4566 <packet_sendmsg+0x419>
    4d96:      	movl	$0xffffffea, %r12d      # imm = 0xFFFFFFEA
    4d9c:      	jmp	0x4ddd <packet_sendmsg+0xc90>
    4d9e:      	movl	$0x0, -0x44(%rbp)
    4da5:      	jmp	0x4db4 <packet_sendmsg+0xc67>
    4da7:      	decl	%eax
    4da9:      	je	0x47d2 <packet_sendmsg+0x685>
    4daf:      	callq	0xb85 <__packet_get_status.part.44>
    4db4:      	movl	0x3a0(%r15), %edx
    4dbb:      	cmpl	0x3ac(%r15), %edx
    4dc2:      	leal	0x1(%rdx), %eax
    4dc5:      	movl	$0x0, %edx
    4dca:      	cmovel	%edx, %eax
    4dcd:      	addl	%r12d, -0x5c(%rbp)
    4dd1:      	movl	%eax, 0x3a0(%r15)
    4dd8:      	jmp	0x42e2 <packet_sendmsg+0x195>
    4ddd:      	testb	$0x1, 0x4c0(%r15)
    4de5:      	je	0x4e21 <packet_sendmsg+0xcd4>
    4de7:      	xorl	%edx, %edx
    4de9:      	movq	%r15, %rdi
    4dec:      	movq	%r13, %rsi
    4def:      	callq	0xba5 <__packet_set_status>
    4df4:      	movl	0x3a0(%r15), %edx
    4dfb:      	cmpl	0x3ac(%r15), %edx
    4e02:      	movq	%r14, %rdi
    4e05:      	leal	0x1(%rdx), %eax
    4e08:      	movl	$0x0, %edx
    4e0d:      	cmovel	%edx, %eax
    4e10:      	movl	%eax, 0x3a0(%r15)
    4e17:      	callq	0x4e1c <packet_sendmsg+0xccf>
		0000000000004e18:  R_X86_64_PC32	kfree_skb-0x4
    4e1c:      	jmp	0x42e2 <packet_sendmsg+0x195>
    4e21:      	movl	%r12d, -0x44(%rbp)
    4e25:      	movl	$0x4, %edx
    4e2a:      	jmp	0x47e6 <packet_sendmsg+0x699>
    4e2f:      	leaq	0x3c0(%r15), %rdi
    4e36:      	callq	0xbde <packet_read_pending.isra.51>
    4e3b:      	testl	%eax, %eax
    4e3d:      	jne	0x42e2 <packet_sendmsg+0x195>
    4e43:      	movl	-0x5c(%rbp), %eax
    4e46:      	movl	%eax, -0x44(%rbp)
    4e49:      	jmp	0x47f9 <packet_sendmsg+0x6ac>
    4e4e:      	addq	$0x98, %rsp
    4e55:      	popq	%rbx
    4e56:      	popq	%r12
    4e58:      	popq	%r13
    4e5a:      	popq	%r14
    4e5c:      	popq	%r15
    4e5e:      	popq	%rbp
    4e5f:      	retq

# ---- vmlinux absolute VA vm_insert_page [0xffffffff810ee3bd,0xffffffff810ee50e) ----
# vmlinux sha256: f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff810ee3bd:      	pushq	%rbp
ffffffff810ee3be:      	movq	%rsp, %rbp
ffffffff810ee3c1:      	pushq	%r14
ffffffff810ee3c3:      	pushq	%r13
ffffffff810ee3c5:      	pushq	%r12
ffffffff810ee3c7:      	pushq	%rbx
ffffffff810ee3c8:      	subq	$0x20, %rsp
ffffffff810ee3cc:      	movq	%gs:0x28, %rax
ffffffff810ee3d5:      	movq	%rax, -0x28(%rbp)
ffffffff810ee3d9:      	xorl	%eax, %eax
ffffffff810ee3db:      	cmpq	%rsi, (%rdi)
ffffffff810ee3de:      	ja	0xffffffff810ee4e1 <.text+0xee4e1>
ffffffff810ee3e4:      	cmpq	0x8(%rdi), %rsi
ffffffff810ee3e8:      	movq	%rdi, %r12
ffffffff810ee3eb:      	jae	0xffffffff810ee4e1 <.text+0xee4e1>
ffffffff810ee3f1:      	movq	(%rdx), %rax
ffffffff810ee3f4:      	movq	%rdx, %rbx
ffffffff810ee3f7:      	testb	$-0x80, %ah
ffffffff810ee3fa:      	je	0xffffffff810ee408 <.text+0xee408>
ffffffff810ee3fc:      	movq	0x30(%rdx), %rax
ffffffff810ee400:      	movq	(%rdx), %rdx
ffffffff810ee403:      	andb	$-0x80, %dh
ffffffff810ee406:      	jne	0xffffffff810ee40b <.text+0xee40b>
ffffffff810ee408:      	movq	%rbx, %rax
ffffffff810ee40b:      	movl	0x1c(%rax), %eax
ffffffff810ee40e:      	testl	%eax, %eax
ffffffff810ee410:      	je	0xffffffff810ee4e8 <.text+0xee4e8>
ffffffff810ee416:      	testb	$0x10, 0x53(%r12)
ffffffff810ee41c:      	jne	0xffffffff810ee451 <.text+0xee451>
ffffffff810ee41e:      	movq	0x40(%r12), %rax
ffffffff810ee423:      	movq	%rsi, -0x38(%rbp)
ffffffff810ee427:      	leaq	0x68(%rax), %rdi
ffffffff810ee42b:      	callq	0xffffffff81085223 <.text+0x85223>
ffffffff810ee430:      	testl	%eax, %eax
ffffffff810ee432:      	movq	-0x38(%rbp), %rsi
ffffffff810ee436:      	je	0xffffffff810ee43a <.text+0xee43a>
ffffffff810ee438:      	ud2
ffffffff810ee43a:      	movq	0x50(%r12), %rax
ffffffff810ee43f:      	testb	$0x4, %ah
ffffffff810ee442:      	je	0xffffffff810ee446 <.text+0xee446>
ffffffff810ee444:      	ud2
ffffffff810ee446:      	orq	$0x10000000, %rax # imm = 0x10000000
ffffffff810ee44c:      	movq	%rax, 0x50(%r12)
ffffffff810ee451:      	testb	$0x1, 0x8(%rbx)
ffffffff810ee455:      	movq	0x40(%r12), %r13
ffffffff810ee45a:      	movl	$0xffffffea, %eax # imm = 0xFFFFFFEA
ffffffff810ee45f:      	movq	0x48(%r12), %r12
ffffffff810ee464:      	jne	0xffffffff810ee4ed <.text+0xee4ed>
ffffffff810ee46a:      	leaq	-0x30(%rbp), %rdx
ffffffff810ee46e:      	movq	%r13, %rdi
ffffffff810ee471:      	callq	0xffffffff810ee326 <.text+0xee326>
ffffffff810ee476:      	movq	%rax, %r14
ffffffff810ee479:      	movl	$0xfffffff4, %eax # imm = 0xFFFFFFF4
ffffffff810ee47e:      	testq	%r14, %r14
ffffffff810ee481:      	je	0xffffffff810ee4ed <.text+0xee4ed>
ffffffff810ee483:      	cmpq	$0x0, (%r14)
ffffffff810ee487:      	jne	0xffffffff810ee4d1 <.text+0xee4d1>
ffffffff810ee489:      	movq	%rbx, %rdi
ffffffff810ee48c:      	callq	0xffffffff810ec3b0 <.text+0xec3b0>
ffffffff810ee491:      	movl	$0x1, %edx
ffffffff810ee496:      	xorl	%esi, %esi
ffffffff810ee498:      	movq	%r13, %rdi
ffffffff810ee49b:      	callq	0xffffffff810eb9ac <.text+0xeb9ac>
ffffffff810ee4a0:      	movq	%rbx, %rdi
ffffffff810ee4a3:      	callq	0xffffffff810f65c2 <.text+0xf65c2>
ffffffff810ee4a8:      	movabsq	$0x160000000000, %rdi # imm = 0x160000000000
ffffffff810ee4b2:      	movq	%r12, %rsi
ffffffff810ee4b5:      	addq	%rbx, %rdi
ffffffff810ee4b8:      	sarq	$0x6, %rdi
ffffffff810ee4bc:      	callq	0xffffffff810eb87a <.text+0xeb87a>
ffffffff810ee4c1:      	movq	%rax, (%r14)
ffffffff810ee4c4:      	movq	-0x30(%rbp), %rdi
ffffffff810ee4c8:      	callq	0xffffffff810eb82c <.text+0xeb82c>
ffffffff810ee4cd:      	xorl	%eax, %eax
ffffffff810ee4cf:      	jmp	0xffffffff810ee4ed <.text+0xee4ed>
ffffffff810ee4d1:      	movq	-0x30(%rbp), %rdi
ffffffff810ee4d5:      	callq	0xffffffff810eb82c <.text+0xeb82c>
ffffffff810ee4da:      	movl	$0xfffffff0, %eax # imm = 0xFFFFFFF0
ffffffff810ee4df:      	jmp	0xffffffff810ee4ed <.text+0xee4ed>
ffffffff810ee4e1:      	movl	$0xfffffff2, %eax # imm = 0xFFFFFFF2
ffffffff810ee4e6:      	jmp	0xffffffff810ee4ed <.text+0xee4ed>
ffffffff810ee4e8:      	movl	$0xffffffea, %eax # imm = 0xFFFFFFEA
ffffffff810ee4ed:      	movq	-0x28(%rbp), %rcx
ffffffff810ee4f1:      	xorq	%gs:0x28, %rcx
ffffffff810ee4fa:      	je	0xffffffff810ee501 <.text+0xee501>
ffffffff810ee4fc:      	callq	0xffffffff8105c12e <.text+0x5c12e>
ffffffff810ee501:      	addq	$0x20, %rsp
ffffffff810ee505:      	popq	%rbx
ffffffff810ee506:      	popq	%r12
ffffffff810ee508:      	popq	%r13
ffffffff810ee50a:      	popq	%r14
ffffffff810ee50c:      	popq	%rbp
ffffffff810ee50d:      	retq

# ---- vmlinux absolute VA __get_order [0xffffffff81103c70,0xffffffff81103c86) ----

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff81103c70:      	pushq	%rbp
ffffffff81103c71:      	decq	%rdi
ffffffff81103c74:      	orl	$-0x1, %eax
ffffffff81103c77:      	shrq	$0xc, %rdi
ffffffff81103c7b:      	movq	%rsp, %rbp
ffffffff81103c7e:      	bsrq	%rdi, %rax
ffffffff81103c82:      	popq	%rbp
ffffffff81103c83:      	incl	%eax
ffffffff81103c85:      	retq

# ---- vmlinux absolute VA __kmalloc [0xffffffff8110665a,0xffffffff81106746) ----

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff8110665a:      	pushq	%rbp
ffffffff8110665b:      	cmpq	$0x2000, %rdi   # imm = 0x2000
ffffffff81106662:      	movq	%rdi, %rcx
ffffffff81106665:      	movq	%rsp, %rbp
ffffffff81106668:      	pushq	%r14
ffffffff8110666a:      	pushq	%r13
ffffffff8110666c:      	pushq	%r12
ffffffff8110666e:      	movl	%esi, %r12d
ffffffff81106671:      	pushq	%rbx
ffffffff81106672:      	jbe	0xffffffff8110668b <.text+0x10668b>
ffffffff81106674:      	callq	0xffffffff81103c70 <.text+0x103c70>
ffffffff81106679:      	movl	%eax, %edx
ffffffff8110667b:      	movq	%rcx, %rdi
ffffffff8110667e:      	callq	0xffffffff810e78ba <.text+0xe78ba>
ffffffff81106683:      	movq	%rax, %rdx
ffffffff81106686:      	jmp	0xffffffff8110673a <.text+0x10673a>
ffffffff8110668b:      	callq	0xffffffff810e7e92 <.text+0xe7e92>
ffffffff81106690:      	cmpq	$0x10, %rax
ffffffff81106694:      	movq	%rax, %r14
ffffffff81106697:      	movq	%rax, %rdx
ffffffff8110669a:      	jbe	0xffffffff8110673a <.text+0x10673a>
ffffffff811066a0:      	movl	0x9d9f1e(%rip), %eax # 0xffffffff81ae05c4
ffffffff811066a6:      	movq	0x8(%rbp), %r13
ffffffff811066aa:      	andl	%r12d, %eax
ffffffff811066ad:      	testb	$0x10, %al
ffffffff811066af:      	je	0xffffffff811066c9 <.text+0x1066c9>
ffffffff811066b1:      	xorl	%edx, %edx
ffffffff811066b3:      	movl	$0x4f2, %esi    # imm = 0x4F2
ffffffff811066b8:      	movq	$-0x7e803029, %rdi # imm = 0x817FCFD7
ffffffff811066bf:      	callq	0xffffffff8107585f <.text+0x7585f>
ffffffff811066c4:      	callq	0xffffffff8155ee3b <.text+0x55ee3b>
ffffffff811066c9:      	xorl	%edx, %edx
ffffffff811066cb:      	testq	%r14, %r14
ffffffff811066ce:      	je	0xffffffff8110673a <.text+0x10673a>
ffffffff811066d0:      	movq	(%r14), %rcx
ffffffff811066d3:      	movq	%gs:0x8(%rcx), %rdx
ffffffff811066d8:      	addq	%gs:0x7ef03a38(%rip), %rcx
ffffffff811066e0:      	movq	(%rcx), %rdi
ffffffff811066e3:      	testq	%rdi, %rdi
ffffffff811066e6:      	jne	0xffffffff811066fb <.text+0x1066fb>
ffffffff811066e8:      	movq	%r14, %rdi
ffffffff811066eb:      	movq	%r13, %rdx
ffffffff811066ee:      	movl	%r12d, %esi
ffffffff811066f1:      	callq	0xffffffff811062a0 <.text+0x1062a0>
ffffffff811066f6:      	movq	%rax, %rdi
ffffffff811066f9:      	jmp	0xffffffff81106721 <.text+0x106721>
ffffffff811066fb:      	movslq	0x20(%r14), %rax
ffffffff811066ff:      	leaq	0x1(%rdx), %rcx
ffffffff81106703:      	movq	(%r14), %r8
ffffffff81106706:      	movq	(%rdi,%rax), %rbx
ffffffff8110670a:      	movq	%rdi, %rax
ffffffff8110670d:      	leaq	(%r8), %rsi
ffffffff81106710:      	callq	0xffffffff81207ff0 <.text+0x207ff0>
ffffffff81106715:      	testb	%al, %al
ffffffff81106717:      	je	0xffffffff811066d0 <.text+0x1066d0>
ffffffff81106719:      	movslq	0x20(%r14), %rax
ffffffff8110671d:      	prefetcht0	(%rbx,%rax)
ffffffff81106721:      	andl	$0x8000, %r12d  # imm = 0x8000
ffffffff81106728:      	movq	%rdi, %rdx
ffffffff8110672b:      	je	0xffffffff8110673a <.text+0x10673a>
ffffffff8110672d:      	testq	%rdi, %rdi
ffffffff81106730:      	je	0xffffffff8110673a <.text+0x10673a>
ffffffff81106732:      	movslq	0x1c(%r14), %rcx
ffffffff81106736:      	xorl	%eax, %eax
ffffffff81106738:      	rep		stosb	%al, %es:(%rdi)
ffffffff8110673a:      	popq	%rbx
ffffffff8110673b:      	movq	%rdx, %rax
ffffffff8110673e:      	popq	%r12
ffffffff81106740:      	popq	%r13
ffffffff81106742:      	popq	%r14
ffffffff81106744:      	popq	%rbp
ffffffff81106745:      	retq

# ---- vmlinux absolute VA kmalloc_order [0xffffffff810e78ba,0xffffffff810e78fb) ----

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff810e78ba:      	pushq	%rbp
ffffffff810e78bb:      	movl	%esi, %edi
ffffffff810e78bd:      	movl	%edx, %esi
ffffffff810e78bf:      	orl	$0x4000, %edi   # imm = 0x4000
ffffffff810e78c5:      	movq	%rsp, %rbp
ffffffff810e78c8:      	callq	0xffffffff810d6e3d <.text+0xd6e3d>
ffffffff810e78cd:      	xorl	%edx, %edx
ffffffff810e78cf:      	testq	%rax, %rax
ffffffff810e78d2:      	je	0xffffffff810e78f6 <.text+0xe78f6>
ffffffff810e78d4:      	movabsq	$0x160000000000, %rdx # imm = 0x160000000000
ffffffff810e78de:      	addq	%rdx, %rax
ffffffff810e78e1:      	movabsq	$-0x780000000000, %rdx # imm = 0xFFFF880000000000
ffffffff810e78eb:      	sarq	$0x6, %rax
ffffffff810e78ef:      	shlq	$0xc, %rax
ffffffff810e78f3:      	addq	%rax, %rdx
ffffffff810e78f6:      	movq	%rdx, %rax
ffffffff810e78f9:      	popq	%rbp
ffffffff810e78fa:      	retq

# ---- vmlinux absolute VA alloc_kmem_pages [0xffffffff810d6e3d,0xffffffff810d6e51) ----

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff810d6e3d:      	pushq	%rbp
ffffffff810d6e3e:      	xorl	%ecx, %ecx
ffffffff810d6e40:      	movq	$-0x7e536000, %rdx # imm = 0x81ACA000
ffffffff810d6e47:      	movq	%rsp, %rbp
ffffffff810d6e4a:      	callq	0xffffffff810d674c <.text+0xd674c>
ffffffff810d6e4f:      	popq	%rbp
ffffffff810d6e50:      	retq

# ---- vmlinux absolute VA __alloc_pages_nodemask [0xffffffff810d674c,0xffffffff810d6e3d) ----

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff810d674c:      	pushq	%rbp
ffffffff810d674d:      	movq	%rsp, %rbp
ffffffff810d6750:      	pushq	%r15
ffffffff810d6752:      	pushq	%r14
ffffffff810d6754:      	pushq	%r13
ffffffff810d6756:      	pushq	%r12
ffffffff810d6758:      	movl	%esi, %r12d
ffffffff810d675b:      	pushq	%rbx
ffffffff810d675c:      	movl	%edi, %ebx
ffffffff810d675e:      	leaq	-0x60(%rbp), %rdi
ffffffff810d6762:      	subq	$0xb8, %rsp
ffffffff810d6769:      	movq	%rdx, -0x90(%rbp)
ffffffff810d6770:      	movq	%rcx, %rdx
ffffffff810d6773:      	movq	%gs:0x28, %rax
ffffffff810d677c:      	movq	%rax, -0x38(%rbp)
ffffffff810d6780:      	xorl	%eax, %eax
ffffffff810d6782:      	movl	$0xa, %ecx
ffffffff810d6787:      	rep		stosl	%eax, %es:(%rdi)
ffffffff810d6789:      	movl	%ebx, %eax
ffffffff810d678b:      	movq	%rdx, -0x58(%rbp)
ffffffff810d678f:      	andl	$0x80008, %eax  # imm = 0x80008
ffffffff810d6794:      	cmpl	$0x80008, %eax  # imm = 0x80008
ffffffff810d6799:      	jne	0xffffffff810d67ac <.text+0xd67ac>
ffffffff810d679b:      	movl	$0x98, %esi
ffffffff810d67a0:      	movq	$-0x7e806ea6, %rdi # imm = 0x817F915A
ffffffff810d67a7:      	callq	0xffffffff8105c38d <.text+0x5c38d>
ffffffff810d67ac:      	movl	0xa09e0e(%rip), %edx # 0xffffffff81ae05c0
ffffffff810d67b2:      	xorl	%eax, %eax
ffffffff810d67b4:      	testl	%edx, %edx
ffffffff810d67b6:      	jne	0xffffffff810d67cd <.text+0xd67cd>
ffffffff810d67b8:      	testb	$0x8, %bl
ffffffff810d67bb:      	movl	$0x2, %eax
ffffffff810d67c0:      	cmovnel	%eax, %edx
ffffffff810d67c3:      	movl	%ebx, %eax
ffffffff810d67c5:      	shrl	$0x13, %eax
ffffffff810d67c8:      	andl	$0x1, %eax
ffffffff810d67cb:      	orl	%edx, %eax
ffffffff810d67cd:      	movl	%ebx, %ecx
ffffffff810d67cf:      	andl	0xa09def(%rip), %ebx # 0xffffffff81ae05c4
ffffffff810d67d5:      	movl	%eax, -0x44(%rbp)
ffffffff810d67d8:      	andl	$0xf, %ecx
ffffffff810d67db:      	movl	$0x1320122, %eax # imm = 0x1320122
ffffffff810d67e0:      	addl	%ecx, %ecx
ffffffff810d67e2:      	sarl	%cl, %eax
ffffffff810d67e4:      	andl	$0x3, %eax
ffffffff810d67e7:      	movl	%ebx, -0x7c(%rbp)
ffffffff810d67ea:      	andb	$0x10, %bl
ffffffff810d67ed:      	movl	%eax, -0x40(%rbp)
ffffffff810d67f0:      	je	0xffffffff810d680a <.text+0xd680a>
ffffffff810d67f2:      	xorl	%edx, %edx
ffffffff810d67f4:      	movl	$0xb47, %esi    # imm = 0xB47
ffffffff810d67f9:      	movq	$-0x7e8073d9, %rdi # imm = 0x817F8C27
ffffffff810d6800:      	callq	0xffffffff8107585f <.text+0x7585f>
ffffffff810d6805:      	callq	0xffffffff8155ee3b <.text+0x55ee3b>
ffffffff810d680a:      	movq	-0x90(%rbp), %rax
ffffffff810d6811:      	cmpq	$0x0, 0x8(%rax)
ffffffff810d6816:      	jne	0xffffffff810d681f <.text+0xd681f>
ffffffff810d6818:      	xorl	%eax, %eax
ffffffff810d681a:      	jmp	0xffffffff810d6d3d <.text+0xd6d3d>
ffffffff810d681f:      	movl	$0x1, %eax
ffffffff810d6824:      	movb	%r12b, %cl
ffffffff810d6827:      	shll	%cl, %eax
ffffffff810d6829:      	cltq
ffffffff810d682b:      	movq	%rax, -0xb0(%rbp)
ffffffff810d6832:      	movq	%gs:0xa980, %rax
ffffffff810d683b:      	movq	%rax, -0x88(%rbp)
ffffffff810d6842:      	movq	%rax, -0xc8(%rbp)
ffffffff810d6849:      	movq	%rax, -0xd0(%rbp)
ffffffff810d6850:      	movq	%rax, -0xd8(%rbp)
ffffffff810d6857:      	movq	-0x88(%rbp), %rax
ffffffff810d685e:      	movl	0x698(%rax), %eax
ffffffff810d6864:      	testb	$0x1, %al
ffffffff810d6866:      	movl	%eax, -0x80(%rbp)
ffffffff810d6869:      	je	0xffffffff810d686f <.text+0xd686f>
ffffffff810d686b:      	pause
ffffffff810d686d:      	jmp	0xffffffff810d6857 <.text+0xd6857>
ffffffff810d686f:      	movq	-0x90(%rbp), %rax
ffffffff810d6876:      	movq	-0x58(%rbp), %rdx
ffffffff810d687a:      	movl	-0x40(%rbp), %esi
ffffffff810d687d:      	movq	%rax, -0x60(%rbp)
ffffffff810d6881:      	movq	-0xc8(%rbp), %rax
ffffffff810d6888:      	addq	$0x690, %rax    # imm = 0x690
ffffffff810d688e:      	testq	%rdx, %rdx
ffffffff810d6891:      	cmoveq	%rax, %rdx
ffffffff810d6895:      	movq	-0x90(%rbp), %rax
ffffffff810d689c:      	leaq	0x8(%rax), %rdi
ffffffff810d68a0:      	callq	0xffffffff810e3d27 <.text+0xe3d27>
ffffffff810d68a5:      	movq	(%rax), %rdx
ffffffff810d68a8:      	testq	%rdx, %rdx
ffffffff810d68ab:      	movq	%rdx, -0x50(%rbp)
ffffffff810d68af:      	jne	0xffffffff810d68cb <.text+0xd68cb>
ffffffff810d68b1:      	movq	%gs:0xa980, %rax
ffffffff810d68ba:      	movl	-0x80(%rbp), %ecx
ffffffff810d68bd:      	cmpl	0x698(%rax), %ecx
ffffffff810d68c3:      	je	0xffffffff810d6818 <.text+0xd6818>
ffffffff810d68c9:      	jmp	0xffffffff810d6857 <.text+0xd6857>
ffffffff810d68cb:      	movl	-0x7c(%rbp), %edi
ffffffff810d68ce:      	movl	0x8(%rax), %eax
ffffffff810d68d1:      	leaq	-0x60(%rbp), %rcx
ffffffff810d68d5:      	movl	$0x141, %edx    # imm = 0x141
ffffffff810d68da:      	movl	%r12d, %esi
ffffffff810d68dd:      	orl	$0x20000, %edi  # imm = 0x20000
ffffffff810d68e3:      	movl	%eax, -0x48(%rbp)
ffffffff810d68e6:      	callq	0xffffffff810d6114 <.text+0xd6114>
ffffffff810d68eb:      	testq	%rax, %rax
ffffffff810d68ee:      	jne	0xffffffff810d6d3d <.text+0xd6d3d>
ffffffff810d68f4:      	movq	-0xd0(%rbp), %rax
ffffffff810d68fb:      	movl	-0x7c(%rbp), %ebx
ffffffff810d68fe:      	movb	$0x0, -0x6d(%rbp)
ffffffff810d6902:      	movl	$0x0, -0x6c(%rbp)
ffffffff810d6909:      	andb	$0x3f, %bl
ffffffff810d690c:      	testb	$0x8, 0x16(%rax)
ffffffff810d6910:      	cmovel	-0x7c(%rbp), %ebx
ffffffff810d6914:      	movl	%ebx, %eax
ffffffff810d6916:      	andl	$0x10, %eax
ffffffff810d6919:      	cmpl	$0xa, %r12d
ffffffff810d691d:      	movl	%eax, -0x98(%rbp)
ffffffff810d6923:      	ja	0xffffffff810d695f <.text+0xd695f>
ffffffff810d6925:      	movq	%gs:0x10e84, %rax
ffffffff810d692e:      	xorl	%r14d, %r14d
ffffffff810d6931:      	movq	%rax, -0xb8(%rbp)
ffffffff810d6938:      	movq	$0x0, -0xa0(%rbp)
ffffffff810d6943:      	movq	%gs:0xa980, %rax
ffffffff810d694c:      	movq	%rax, -0xa8(%rbp)
ffffffff810d6953:      	movq	%rax, -0xc0(%rbp)
ffffffff810d695a:      	jmp	0xffffffff810d6b22 <.text+0xd6b22>
ffffffff810d695f:      	andb	$0x2, %bh
ffffffff810d6962:      	jne	0xffffffff810d68b1 <.text+0xd68b1>
ffffffff810d6968:      	cmpb	$0x0, 0x9f4b22(%rip) # 0xffffffff81acb491
ffffffff810d696f:      	jne	0xffffffff810d68b1 <.text+0xd68b1>
ffffffff810d6975:      	movl	$0xa85, %esi    # imm = 0xA85
ffffffff810d697a:      	movq	$-0x7e8073d9, %rdi # imm = 0x817F8C27
ffffffff810d6981:      	callq	0xffffffff8105c38d <.text+0x5c38d>
ffffffff810d6986:      	movb	$0x1, 0x9f4b04(%rip) # 0xffffffff81acb491
ffffffff810d698d:      	jmp	0xffffffff810d68b1 <.text+0xd68b1>
ffffffff810d6992:      	cmpl	$0x0, -0x98(%rbp)
ffffffff810d6999:      	je	0xffffffff810d6c2e <.text+0xd6c2e>
ffffffff810d699f:      	movq	-0xd8(%rbp), %rax
ffffffff810d69a6:      	testb	$0x8, 0x15(%rax)
ffffffff810d69aa:      	jne	0xffffffff810d6d1e <.text+0xd6d1e>
ffffffff810d69b0:      	movq	-0xb8(%rbp), %rax
ffffffff810d69b7:      	movq	-0x3ff8(%rax), %rax
ffffffff810d69be:      	testl	$0x100000, %eax # imm = 0x100000
ffffffff810d69c3:      	jne	0xffffffff810d6c61 <.text+0xd6c61>
ffffffff810d69c9:      	leaq	-0x6d(%rbp), %rax
ffffffff810d69cd:      	movl	-0x78(%rbp), %edx
ffffffff810d69d0:      	leaq	-0x6c(%rbp), %r9
ffffffff810d69d4:      	pushq	%rsi
ffffffff810d69d5:      	leaq	-0x60(%rbp), %rcx
ffffffff810d69d9:      	movl	%r14d, %r8d
ffffffff810d69dc:      	pushq	%rax
ffffffff810d69dd:      	movl	%ebx, %edi
ffffffff810d69df:      	movl	%r12d, %esi
ffffffff810d69e2:      	callq	0xffffffff810d6663 <.text+0xd6663>
ffffffff810d69e7:      	testq	%rax, %rax
ffffffff810d69ea:      	popq	%rdi
ffffffff810d69eb:      	popq	%r8
ffffffff810d69ed:      	jne	0xffffffff810d6d34 <.text+0xd6d34>
ffffffff810d69f3:      	movl	%ebx, %eax
ffffffff810d69f5:      	andl	$0x4352da, %eax # imm = 0x4352DA
ffffffff810d69fa:      	cmpl	$0x4352da, %eax # imm = 0x4352DA
ffffffff810d69ff:      	jne	0xffffffff810d6c85 <.text+0xd6c85>
ffffffff810d6a05:      	cmpb	$0x0, -0x6d(%rbp)
ffffffff810d6a09:      	jne	0xffffffff810d6d1e <.text+0xd6d1e>
ffffffff810d6a0f:      	movl	-0x6c(%rbp), %eax
ffffffff810d6a12:      	cmpl	$0x2, %eax
ffffffff810d6a15:      	je	0xffffffff810d6d1e <.text+0xd6d1e>
ffffffff810d6a1b:      	decl	%eax
ffffffff810d6a1d:      	je	0xffffffff810d6c6f <.text+0xd6c6f>
ffffffff810d6a23:      	movq	-0xa8(%rbp), %rax
ffffffff810d6a2a:      	testb	$0x20, 0x16(%rax)
ffffffff810d6a2e:      	movl	$0x1, %eax
ffffffff810d6a33:      	cmovnel	%eax, %r14d
ffffffff810d6a37:      	xorl	%edx, %edx
ffffffff810d6a39:      	movl	$0x9e4, %esi    # imm = 0x9E4
ffffffff810d6a3e:      	movq	$-0x7e8073d9, %rdi # imm = 0x817F8C27
ffffffff810d6a45:      	callq	0xffffffff81075756 <.text+0x75756>
ffffffff810d6a4a:      	callq	0xffffffff8155ee3b <.text+0x55ee3b>
ffffffff810d6a4f:      	cmpl	$0x0, 0xa09aca(%rip) # 0xffffffff81ae0520
ffffffff810d6a56:      	je	0xffffffff810d6a5d <.text+0xd6a5d>
ffffffff810d6a58:      	callq	0xffffffff810b463f <.text+0xb463f>
ffffffff810d6a5d:      	movq	%gs:0xa980, %r15
ffffffff810d6a66:      	orl	$0x800, 0x14(%r15) # imm = 0x800
ffffffff810d6a6e:      	movq	-0x58(%rbp), %rcx
ffffffff810d6a72:      	leaq	-0x68(%rbp), %rax
ffffffff810d6a76:      	movq	-0x60(%rbp), %rdi
ffffffff810d6a7a:      	movl	%ebx, %edx
ffffffff810d6a7c:      	movl	%r12d, %esi
ffffffff810d6a7f:      	movq	%rax, 0x668(%r15)
ffffffff810d6a86:      	movq	$0x0, -0x68(%rbp)
ffffffff810d6a8e:      	callq	0xffffffff810de807 <.text+0xde807>
ffffffff810d6a93:      	andl	$0xfffff7ff, 0x14(%r15) # imm = 0xFFFFF7FF
ffffffff810d6a9b:      	movq	%rax, %r13
ffffffff810d6a9e:      	xorl	%edx, %edx
ffffffff810d6aa0:      	movq	$0x0, 0x668(%r15)
ffffffff810d6aab:      	movl	$0x9f4, %esi    # imm = 0x9F4
ffffffff810d6ab0:      	movq	$-0x7e8073d9, %rdi # imm = 0x817F8C27
ffffffff810d6ab7:      	movslq	%r13d, %r13
ffffffff810d6aba:      	xorl	%r15d, %r15d
ffffffff810d6abd:      	callq	0xffffffff81075756 <.text+0x75756>
ffffffff810d6ac2:      	callq	0xffffffff8155ee3b <.text+0x55ee3b>
ffffffff810d6ac7:      	testq	%r13, %r13
ffffffff810d6aca:      	jne	0xffffffff810d6c90 <.text+0xd6c90>
ffffffff810d6ad0:      	testb	$0x10, %bh
ffffffff810d6ad3:      	jne	0xffffffff810d6ddf <.text+0xd6ddf>
ffffffff810d6ad9:      	movl	%ebx, %r15d
ffffffff810d6adc:      	addq	%r13, -0xa0(%rbp)
ffffffff810d6ae3:      	andl	$0x800, %r15d   # imm = 0x800
ffffffff810d6aea:      	je	0xffffffff810d6cc6 <.text+0xd6cc6>
ffffffff810d6af0:      	testq	%r13, %r13
ffffffff810d6af3:      	jne	0xffffffff810d6b12 <.text+0xd6b12>
ffffffff810d6af5:      	movq	-0x60(%rbp), %rdi
ffffffff810d6af9:      	movl	%ebx, %esi
ffffffff810d6afb:      	callq	0xffffffff810d3abd <.text+0xd3abd>
ffffffff810d6b00:      	testb	%al, %al
ffffffff810d6b02:      	jne	0xffffffff810d6ce1 <.text+0xd6ce1>
ffffffff810d6b08:      	movl	$0x1, %edi
ffffffff810d6b0d:      	callq	0xffffffff81560da2 <.text+0x560da2>
ffffffff810d6b12:      	movq	-0x50(%rbp), %rdi
ffffffff810d6b16:      	movl	$0x14, %edx
ffffffff810d6b1b:      	xorl	%esi, %esi
ffffffff810d6b1d:      	callq	0xffffffff810e589a <.text+0xe589a>
ffffffff810d6b22:      	testl	$0x400000, %ebx # imm = 0x400000
ffffffff810d6b28:      	je	0xffffffff810d6b3d <.text+0xd6b3d>
ffffffff810d6b2a:      	movl	%ebx, %edi
ffffffff810d6b2c:      	callq	0xffffffff810d4972 <.text+0xd4972>
ffffffff810d6b31:      	testb	$0x40, %al
ffffffff810d6b33:      	movl	%eax, -0x78(%rbp)
ffffffff810d6b36:      	je	0xffffffff810d6b98 <.text+0xd6b98>
ffffffff810d6b38:      	jmp	0xffffffff810d6bbe <.text+0xd6bbe>
ffffffff810d6b3d:      	movq	-0x60(%rbp), %rax
ffffffff810d6b41:      	movq	-0x58(%rbp), %rdx
ffffffff810d6b45:      	movabsq	$-0x5555555555555555, %r13 # imm = 0xAAAAAAAAAAAAAAAB
ffffffff810d6b4f:      	movl	-0x40(%rbp), %esi
ffffffff810d6b52:      	leaq	0x8(%rax), %rdi
ffffffff810d6b56:      	callq	0xffffffff810e3d27 <.text+0xe3d27>
ffffffff810d6b5b:      	movq	(%rax), %rdi
ffffffff810d6b5e:      	testq	%rdi, %rdi
ffffffff810d6b61:      	je	0xffffffff810d6b2a <.text+0xd6b2a>
ffffffff810d6b63:      	movq	-0x50(%rbp), %rdx
ffffffff810d6b67:      	movl	%r12d, %esi
ffffffff810d6b6a:      	movq	%rax, -0x78(%rbp)
ffffffff810d6b6e:      	subq	0x40(%rdx), %rdx
ffffffff810d6b72:      	sarq	$0x9, %rdx
ffffffff810d6b76:      	imulq	%r13, %rdx
ffffffff810d6b7a:      	callq	0xffffffff810dc7f5 <.text+0xdc7f5>
ffffffff810d6b7f:      	movq	-0x78(%rbp), %rax
ffffffff810d6b83:      	movq	-0x58(%rbp), %rdx
ffffffff810d6b87:      	movl	-0x40(%rbp), %esi
ffffffff810d6b8a:      	leaq	0x10(%rax), %rdi
ffffffff810d6b8e:      	callq	0xffffffff810e3d27 <.text+0xe3d27>
ffffffff810d6b93:      	movq	(%rax), %rdi
ffffffff810d6b96:      	jmp	0xffffffff810d6b5e <.text+0xd6b5e>
ffffffff810d6b98:      	cmpq	$0x0, -0x58(%rbp)
ffffffff810d6b9d:      	jne	0xffffffff810d6bbe <.text+0xd6bbe>
ffffffff810d6b9f:      	movq	-0x60(%rbp), %rax
ffffffff810d6ba3:      	movl	-0x40(%rbp), %esi
ffffffff810d6ba6:      	xorl	%edx, %edx
ffffffff810d6ba8:      	leaq	0x8(%rax), %rdi
ffffffff810d6bac:      	callq	0xffffffff810e3d27 <.text+0xe3d27>
ffffffff810d6bb1:      	movq	(%rax), %rdx
ffffffff810d6bb4:      	movq	%rdx, -0x50(%rbp)
ffffffff810d6bb8:      	movl	0x8(%rax), %eax
ffffffff810d6bbb:      	movl	%eax, -0x48(%rbp)
ffffffff810d6bbe:      	movl	-0x78(%rbp), %eax
ffffffff810d6bc1:      	leaq	-0x60(%rbp), %r15
ffffffff810d6bc5:      	movl	%r12d, %esi
ffffffff810d6bc8:      	movl	%ebx, %edi
ffffffff810d6bca:      	movq	%r15, %rcx
ffffffff810d6bcd:      	andl	$-0x5, %eax
ffffffff810d6bd0:      	movl	%eax, %edx
ffffffff810d6bd2:      	movl	%eax, -0x94(%rbp)
ffffffff810d6bd8:      	callq	0xffffffff810d6114 <.text+0xd6114>
ffffffff810d6bdd:      	testq	%rax, %rax
ffffffff810d6be0:      	jne	0xffffffff810d6d34 <.text+0xd6d34>
ffffffff810d6be6:      	testb	$0x4, -0x78(%rbp)
ffffffff810d6bea:      	je	0xffffffff810d6992 <.text+0xd6992>
ffffffff810d6bf0:      	movq	$-0x7e536000, -0x60(%rbp) # imm = 0x81ACA000
ffffffff810d6bf8:      	movq	%r15, %rcx
ffffffff810d6bfb:      	movl	$0x4, %edx
ffffffff810d6c00:      	movl	%r12d, %esi
ffffffff810d6c03:      	movl	%ebx, %edi
ffffffff810d6c05:      	callq	0xffffffff810d6114 <.text+0xd6114>
ffffffff810d6c0a:      	testq	%rax, %rax
ffffffff810d6c0d:      	jne	0xffffffff810d6d34 <.text+0xd6d34>
ffffffff810d6c13:      	testb	$0x8, %bh
ffffffff810d6c16:      	je	0xffffffff810d6992 <.text+0xd6992>
ffffffff810d6c1c:      	movq	-0x50(%rbp), %rdi
ffffffff810d6c20:      	movl	$0x14, %edx
ffffffff810d6c25:      	xorl	%esi, %esi
ffffffff810d6c27:      	callq	0xffffffff810e589a <.text+0xe589a>
ffffffff810d6c2c:      	jmp	0xffffffff810d6bf8 <.text+0xd6bf8>
ffffffff810d6c2e:      	testb	$0x8, %bh
ffffffff810d6c31:      	je	0xffffffff810d6d1e <.text+0xd6d1e>
ffffffff810d6c37:      	cmpb	$0x0, 0x9f4852(%rip) # 0xffffffff81acb490
ffffffff810d6c3e:      	jne	0xffffffff810d6d1e <.text+0xd6d1e>
ffffffff810d6c44:      	movl	$0xac4, %esi    # imm = 0xAC4
ffffffff810d6c49:      	movq	$-0x7e8073d9, %rdi # imm = 0x817F8C27
ffffffff810d6c50:      	callq	0xffffffff8105c38d <.text+0x5c38d>
ffffffff810d6c55:      	movb	$0x1, 0x9f4834(%rip) # 0xffffffff81acb490
ffffffff810d6c5c:      	jmp	0xffffffff810d6d1e <.text+0xd6d1e>
ffffffff810d6c61:      	testb	$0x8, %bh
ffffffff810d6c64:      	jne	0xffffffff810d69c9 <.text+0xd69c9>
ffffffff810d6c6a:      	jmp	0xffffffff810d6d1e <.text+0xd6d1e>
ffffffff810d6c6f:      	movq	-0xc0(%rbp), %rax
ffffffff810d6c76:      	testb	$0x20, 0x16(%rax)
ffffffff810d6c7a:      	jne	0xffffffff810d6a23 <.text+0xd6a23>
ffffffff810d6c80:      	jmp	0xffffffff810d6d1e <.text+0xd6d1e>
ffffffff810d6c85:      	movl	$0x1, %r14d
ffffffff810d6c8b:      	jmp	0xffffffff810d6a37 <.text+0xd6a37>
ffffffff810d6c90:      	movl	-0x94(%rbp), %edx
ffffffff810d6c96:      	leaq	-0x60(%rbp), %rcx
ffffffff810d6c9a:      	movl	%r12d, %esi
ffffffff810d6c9d:      	movl	%ebx, %edi
ffffffff810d6c9f:      	callq	0xffffffff810d6114 <.text+0xd6114>
ffffffff810d6ca4:      	testq	%rax, %rax
ffffffff810d6ca7:      	sete	%dl
ffffffff810d6caa:      	cmpb	%r15b, %dl
ffffffff810d6cad:      	jbe	0xffffffff810d6cbb <.text+0xd6cbb>
ffffffff810d6caf:      	xorl	%edi, %edi
ffffffff810d6cb1:      	movb	$0x1, %r15b
ffffffff810d6cb4:      	callq	0xffffffff810d4c6f <.text+0xd4c6f>
ffffffff810d6cb9:      	jmp	0xffffffff810d6c90 <.text+0xd6c90>
ffffffff810d6cbb:      	testq	%rax, %rax
ffffffff810d6cbe:      	je	0xffffffff810d6ad0 <.text+0xd6ad0>
ffffffff810d6cc4:      	jmp	0xffffffff810d6d34 <.text+0xd6d34>
ffffffff810d6cc6:      	testq	%r13, %r13
ffffffff810d6cc9:      	jne	0xffffffff810d6dd0 <.text+0xd6dd0>
ffffffff810d6ccf:      	callq	0xffffffff810d4aaf <.text+0xd4aaf>
ffffffff810d6cd4:      	testb	%al, %al
ffffffff810d6cd6:      	je	0xffffffff810d6e22 <.text+0xd6e22>
ffffffff810d6cdc:      	jmp	0xffffffff810d6ddf <.text+0xd6ddf>
ffffffff810d6ce1:      	movl	%ebx, %edi
ffffffff810d6ce3:      	leaq	-0x60(%rbp), %rcx
ffffffff810d6ce7:      	movl	$0x42, %edx
ffffffff810d6cec:      	orl	$0x20000, %edi  # imm = 0x20000
ffffffff810d6cf2:      	movl	%r12d, %esi
ffffffff810d6cf5:      	callq	0xffffffff810d6114 <.text+0xd6114>
ffffffff810d6cfa:      	testq	%rax, %rax
ffffffff810d6cfd:      	movq	%rax, %r13
ffffffff810d6d00:      	je	0xffffffff810d6d55 <.text+0xd6d55>
ffffffff810d6d02:      	xorl	%r15d, %r15d
ffffffff810d6d05:      	movq	-0x60(%rbp), %rdi
ffffffff810d6d09:      	movl	%ebx, %esi
ffffffff810d6d0b:      	callq	0xffffffff810d3b4e <.text+0xd3b4e>
ffffffff810d6d10:      	testq	%r13, %r13
ffffffff810d6d13:      	jne	0xffffffff810d6d31 <.text+0xd6d31>
ffffffff810d6d15:      	testq	%r15, %r15
ffffffff810d6d18:      	jne	0xffffffff810d6b12 <.text+0xd6b12>
ffffffff810d6d1e:      	xorl	%edx, %edx
ffffffff810d6d20:      	movl	%r12d, %esi
ffffffff810d6d23:      	movl	%ebx, %edi
ffffffff810d6d25:      	xorl	%eax, %eax
ffffffff810d6d27:      	callq	0xffffffff810d4df1 <.text+0xd4df1>
ffffffff810d6d2c:      	jmp	0xffffffff810d68b1 <.text+0xd68b1>
ffffffff810d6d31:      	movq	%r13, %rax
ffffffff810d6d34:      	testq	%rax, %rax
ffffffff810d6d37:      	je	0xffffffff810d68b1 <.text+0xd68b1>
ffffffff810d6d3d:      	movq	-0x38(%rbp), %rsi
ffffffff810d6d41:      	xorq	%gs:0x28, %rsi
ffffffff810d6d4a:      	je	0xffffffff810d6e2e <.text+0xd6e2e>
ffffffff810d6d50:      	callq	0xffffffff8105c12e <.text+0x5c12e>
ffffffff810d6d55:      	testl	%r15d, %r15d
ffffffff810d6d58:      	jne	0xffffffff810d6d82 <.text+0xd6d82>
ffffffff810d6d5a:      	movq	%gs:0xa980, %rax
ffffffff810d6d63:      	testb	$0x2, 0x15(%rax)
ffffffff810d6d67:      	jne	0xffffffff810d6d02 <.text+0xd6d02>
ffffffff810d6d69:      	cmpl	$0x3, %r12d
ffffffff810d6d6d:      	ja	0xffffffff810d6d02 <.text+0xd6d02>
ffffffff810d6d6f:      	cmpl	$0x1, -0x40(%rbp)
ffffffff810d6d73:      	jbe	0xffffffff810d6d02 <.text+0xd6d02>
ffffffff810d6d75:      	testb	$-0x80, %bl
ffffffff810d6d78:      	je	0xffffffff810d6dc5 <.text+0xd6dc5>
ffffffff810d6d7a:      	testl	$0x40000, %ebx  # imm = 0x40000
ffffffff810d6d80:      	jne	0xffffffff810d6d02 <.text+0xd6d02>
ffffffff810d6d82:      	movq	-0x58(%rbp), %rcx
ffffffff810d6d86:      	movq	-0x60(%rbp), %rdi
ffffffff810d6d8a:      	xorl	%r8d, %r8d
ffffffff810d6d8d:      	movl	%r12d, %edx
ffffffff810d6d90:      	movl	%ebx, %esi
ffffffff810d6d92:      	callq	0xffffffff810d3bab <.text+0xd3bab>
ffffffff810d6d97:      	testb	%al, %al
ffffffff810d6d99:      	jne	0xffffffff810d6dc5 <.text+0xd6dc5>
ffffffff810d6d9b:      	testl	%r15d, %r15d
ffffffff810d6d9e:      	je	0xffffffff810d6d02 <.text+0xd6d02>
ffffffff810d6da4:      	cmpb	$0x0, 0x9f46e7(%rip) # 0xffffffff81acb492
ffffffff810d6dab:      	jne	0xffffffff810d6dc5 <.text+0xd6dc5>
ffffffff810d6dad:      	movl	$0x991, %esi    # imm = 0x991
ffffffff810d6db2:      	movq	$-0x7e8073d9, %rdi # imm = 0x817F8C27
ffffffff810d6db9:      	callq	0xffffffff8105c38d <.text+0x5c38d>
ffffffff810d6dbe:      	movb	$0x1, 0x9f46cd(%rip) # 0xffffffff81acb492
ffffffff810d6dc5:      	movl	$0x1, %r15d
ffffffff810d6dcb:      	jmp	0xffffffff810d6d05 <.text+0xd6d05>
ffffffff810d6dd0:      	cmpl	$0x3, %r12d
ffffffff810d6dd4:      	jbe	0xffffffff810d6b12 <.text+0xd6b12>
ffffffff810d6dda:      	testb	$0x4, %bh
ffffffff810d6ddd:      	jne	0xffffffff810d6e0d <.text+0xd6e0d>
ffffffff810d6ddf:      	pushq	%rax
ffffffff810d6de0:      	leaq	-0x6d(%rbp), %rax
ffffffff810d6de4:      	movl	-0x78(%rbp), %edx
ffffffff810d6de7:      	leaq	-0x60(%rbp), %rcx
ffffffff810d6deb:      	leaq	-0x6c(%rbp), %r9
ffffffff810d6def:      	movl	%r14d, %r8d
ffffffff810d6df2:      	pushq	%rax
ffffffff810d6df3:      	movl	%r12d, %esi
ffffffff810d6df6:      	movl	%ebx, %edi
ffffffff810d6df8:      	callq	0xffffffff810d6663 <.text+0xd6663>
ffffffff810d6dfd:      	testq	%rax, %rax
ffffffff810d6e00:      	popq	%rdx
ffffffff810d6e01:      	popq	%rcx
ffffffff810d6e02:      	jne	0xffffffff810d6d34 <.text+0xd6d34>
ffffffff810d6e08:      	jmp	0xffffffff810d6d1e <.text+0xd6d1e>
ffffffff810d6e0d:      	movq	-0xb0(%rbp), %rsi
ffffffff810d6e14:      	cmpq	%rsi, -0xa0(%rbp)
ffffffff810d6e1b:      	jae	0xffffffff810d6ddf <.text+0xd6ddf>
ffffffff810d6e1d:      	jmp	0xffffffff810d6af0 <.text+0xd6af0>
ffffffff810d6e22:      	cmpl	$0x3, %r12d
ffffffff810d6e26:      	jbe	0xffffffff810d6af5 <.text+0xd6af5>
ffffffff810d6e2c:      	jmp	0xffffffff810d6dda <.text+0xd6dda>
ffffffff810d6e2e:      	leaq	-0x28(%rbp), %rsp
ffffffff810d6e32:      	popq	%rbx
ffffffff810d6e33:      	popq	%r12
ffffffff810d6e35:      	popq	%r13
ffffffff810d6e37:      	popq	%r14
ffffffff810d6e39:      	popq	%r15
ffffffff810d6e3b:      	popq	%rbp
ffffffff810d6e3c:      	retq

# ---- vmlinux absolute VA __rmqueue [0xffffffff810d5f25,0xffffffff810d6114) ----

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff810d5f25:      	pushq	%rbp
ffffffff810d5f26:      	movq	%rsp, %rbp
ffffffff810d5f29:      	pushq	%r15
ffffffff810d5f2b:      	pushq	%r14
ffffffff810d5f2d:      	pushq	%r13
ffffffff810d5f2f:      	pushq	%r12
ffffffff810d5f31:      	movq	%rdi, %r13
ffffffff810d5f34:      	pushq	%rbx
ffffffff810d5f35:      	movslq	%edx, %rbx
ffffffff810d5f38:      	subq	$0x38, %rsp
ffffffff810d5f3c:      	movl	%esi, -0x44(%rbp)
ffffffff810d5f3f:      	movq	%gs:0x28, %rax
ffffffff810d5f48:      	movq	%rax, -0x38(%rbp)
ffffffff810d5f4c:      	xorl	%eax, %eax
ffffffff810d5f4e:      	movslq	%ebx, %r15
ffffffff810d5f51:      	movl	-0x44(%rbp), %esi
ffffffff810d5f54:      	movq	%r15, %rdx
ffffffff810d5f57:      	shlq	$0x4, %rdx
ffffffff810d5f5b:      	cmpl	$0xa, %esi
ffffffff810d5f5e:      	ja	0xffffffff810d5fcc <.text+0xd5fcc>
ffffffff810d5f60:      	movl	%esi, %ecx
ffffffff810d5f62:      	imulq	$0x48, %rcx, %rcx
ffffffff810d5f66:      	leaq	(%rdx,%rcx), %rax
ffffffff810d5f6a:      	movq	0xc0(%r13,%rax), %r14
ffffffff810d5f72:      	leaq	0xc0(%r13,%rax), %rax
ffffffff810d5f7a:      	cmpq	%rax, %r14
ffffffff810d5f7d:      	jne	0xffffffff810d5f83 <.text+0xd5f83>
ffffffff810d5f7f:      	incl	%esi
ffffffff810d5f81:      	jmp	0xffffffff810d5f5b <.text+0xd5f5b>
ffffffff810d5f83:      	movq	%r14, %rdi
ffffffff810d5f86:      	leaq	-0x20(%r14), %r12
ffffffff810d5f8a:      	callq	0xffffffff810d3da6 <.text+0xd3da6>
ffffffff810d5f8f:      	movl	$0xffffffff, -0x8(%r14) # imm = 0xFFFFFFFF
ffffffff810d5f97:      	movq	$0x0, 0x10(%r14)
ffffffff810d5f9f:      	movl	%esi, %edx
ffffffff810d5fa1:      	decq	0x100(%r13,%rcx)
ffffffff810d5fa9:      	movl	-0x44(%rbp), %esi
ffffffff810d5fac:      	leaq	0xc0(%r13,%rcx), %rcx
ffffffff810d5fb4:      	movl	%ebx, %r8d
ffffffff810d5fb7:      	movq	%r12, %rdi
ffffffff810d5fba:      	callq	0xffffffff810d4358 <.text+0xd4358>
ffffffff810d5fbf:      	testq	%r12, %r12
ffffffff810d5fc2:      	movq	%r15, -0x10(%r14)
ffffffff810d5fc6:      	jne	0xffffffff810d60ee <.text+0xd60ee>
ffffffff810d5fcc:      	cmpl	$0x3, %ebx
ffffffff810d5fcf:      	je	0xffffffff810d60eb <.text+0xd60eb>
ffffffff810d5fd5:      	movl	$0xa, %r14d
ffffffff810d5fdb:      	cmpl	%r14d, -0x44(%rbp)
ffffffff810d5fdf:      	ja	0xffffffff810d60d8 <.text+0xd60d8>
ffffffff810d5fe5:      	cmpl	$0xa, %r14d
ffffffff810d5fe9:      	ja	0xffffffff810d60d8 <.text+0xd60d8>
ffffffff810d5fef:      	movl	%r14d, %eax
ffffffff810d5ff2:      	leaq	-0x39(%rbp), %r8
ffffffff810d5ff6:      	xorl	%ecx, %ecx
ffffffff810d5ff8:      	imulq	$0x48, %rax, %r12
ffffffff810d5ffc:      	movq	%rax, -0x50(%rbp)
ffffffff810d6000:      	movl	%ebx, %edx
ffffffff810d6002:      	movl	%r14d, %esi
ffffffff810d6005:      	leaq	0xc0(%r13,%r12), %rax
ffffffff810d600d:      	movq	%rax, %rdi
ffffffff810d6010:      	movq	%rax, -0x58(%rbp)
ffffffff810d6014:      	callq	0xffffffff810d4c0b <.text+0xd4c0b>
ffffffff810d6019:      	cmpl	$-0x1, %eax
ffffffff810d601c:      	jne	0xffffffff810d6023 <.text+0xd6023>
ffffffff810d601e:      	decl	%r14d
ffffffff810d6021:      	jmp	0xffffffff810d5fdb <.text+0xd5fdb>
ffffffff810d6023:      	cltq
ffffffff810d6025:      	shlq	$0x4, %rax
ffffffff810d6029:      	addq	%r12, %rax
ffffffff810d602c:      	cmpb	$0x0, -0x39(%rbp)
ffffffff810d6030:      	movq	0xc0(%r13,%rax), %r15
ffffffff810d6038:      	leaq	-0x20(%r15), %r12
ffffffff810d603c:      	je	0xffffffff810d6098 <.text+0xd6098>
ffffffff810d603e:      	movq	0x10(%r15), %rcx
ffffffff810d6042:      	cmpl	$0x8, %ecx
ffffffff810d6045:      	jbe	0xffffffff810d6071 <.text+0xd6071>
ffffffff810d6047:      	subl	$0x9, %ecx
ffffffff810d604a:      	movl	$0x1, %r9d
ffffffff810d6050:      	movq	%r12, %r10
ffffffff810d6053:      	shll	%cl, %r9d
ffffffff810d6056:      	testl	%r9d, %r9d
ffffffff810d6059:      	je	0xffffffff810d6098 <.text+0xd6098>
ffffffff810d605b:      	movq	%r10, %rdi
ffffffff810d605e:      	movl	%ebx, %esi
ffffffff810d6060:      	callq	0xffffffff810d5dbf <.text+0xd5dbf>
ffffffff810d6065:      	addq	$0x8000, %r10   # imm = 0x8000
ffffffff810d606c:      	decl	%r9d
ffffffff810d606f:      	jmp	0xffffffff810d6056 <.text+0xd6056>
ffffffff810d6071:      	movl	%ebx, %edx
ffffffff810d6073:      	movq	%r12, %rsi
ffffffff810d6076:      	movq	%r13, %rdi
ffffffff810d6079:      	callq	0xffffffff810d4ba4 <.text+0xd4ba4>
ffffffff810d607e:      	cmpl	$0xff, %eax
ffffffff810d6083:      	jg	0xffffffff810d608e <.text+0xd608e>
ffffffff810d6085:      	cmpl	$0x0, 0xa0a534(%rip) # 0xffffffff81ae05c0
ffffffff810d608c:      	je	0xffffffff810d6098 <.text+0xd6098>
ffffffff810d608e:      	movl	%ebx, %esi
ffffffff810d6090:      	movq	%r12, %rdi
ffffffff810d6093:      	callq	0xffffffff810d5dbf <.text+0xd5dbf>
ffffffff810d6098:      	imulq	$0x48, -0x50(%rbp), %rax
ffffffff810d609d:      	movq	%r15, %rdi
ffffffff810d60a0:      	decq	0x100(%r13,%rax)
ffffffff810d60a8:      	callq	0xffffffff810d3da6 <.text+0xd3da6>
ffffffff810d60ad:      	movq	-0x58(%rbp), %rcx
ffffffff810d60b1:      	movl	-0x44(%rbp), %esi
ffffffff810d60b4:      	movl	%ebx, %r8d
ffffffff810d60b7:      	movl	$0xffffffff, -0x8(%r15) # imm = 0xFFFFFFFF
ffffffff810d60bf:      	movq	$0x0, 0x10(%r15)
ffffffff810d60c7:      	movl	%r14d, %edx
ffffffff810d60ca:      	movq	%r12, %rdi
ffffffff810d60cd:      	callq	0xffffffff810d4358 <.text+0xd4358>
ffffffff810d60d2:      	movq	%rbx, -0x10(%r15)
ffffffff810d60d6:      	jmp	0xffffffff810d60db <.text+0xd60db>
ffffffff810d60d8:      	xorl	%r12d, %r12d
ffffffff810d60db:      	testq	%r12, %r12
ffffffff810d60de:      	movl	$0x3, %ebx
ffffffff810d60e3:      	je	0xffffffff810d5f4e <.text+0xd5f4e>
ffffffff810d60e9:      	jmp	0xffffffff810d60ee <.text+0xd60ee>
ffffffff810d60eb:      	xorl	%r12d, %r12d
ffffffff810d60ee:      	movq	-0x38(%rbp), %rdi
ffffffff810d60f2:      	xorq	%gs:0x28, %rdi
ffffffff810d60fb:      	movq	%r12, %rax
ffffffff810d60fe:      	je	0xffffffff810d6105 <.text+0xd6105>
ffffffff810d6100:      	callq	0xffffffff8105c12e <.text+0x5c12e>
ffffffff810d6105:      	addq	$0x38, %rsp
ffffffff810d6109:      	popq	%rbx
ffffffff810d610a:      	popq	%r12
ffffffff810d610c:      	popq	%r13
ffffffff810d610e:      	popq	%r14
ffffffff810d6110:      	popq	%r15
ffffffff810d6112:      	popq	%rbp
ffffffff810d6113:      	retq

# ---- vmlinux absolute VA get_page_from_freelist [0xffffffff810d6114,0xffffffff810d6663) ----

work/eu-260128/vmlinux:	file format elf64-x86-64

Disassembly of section .text:

ffffffff81000000 <.text>:
ffffffff810d6114:      	pushq	%rbp
ffffffff810d6115:      	movq	%rsp, %rbp
ffffffff810d6118:      	pushq	%r15
ffffffff810d611a:      	pushq	%r14
ffffffff810d611c:      	pushq	%r13
ffffffff810d611e:      	pushq	%r12
ffffffff810d6120:      	movl	%edx, %r15d
ffffffff810d6123:      	pushq	%rbx
ffffffff810d6124:      	movq	%rcx, %r13
ffffffff810d6127:      	subq	$0x88, %rsp
ffffffff810d612e:      	movq	(%rcx), %rax
ffffffff810d6131:      	movl	%edi, -0x38(%rbp)
ffffffff810d6134:      	movl	%esi, -0x34(%rbp)
ffffffff810d6137:      	movq	%rax, -0x70(%rbp)
ffffffff810d613b:      	movl	%edx, %eax
ffffffff810d613d:      	andl	$0x1, %eax
ffffffff810d6140:      	movl	%eax, -0x60(%rbp)
ffffffff810d6143:      	je	0xffffffff810d6150 <.text+0xd6150>
ffffffff810d6145:      	movl	%edi, %eax
ffffffff810d6147:      	shrl	$0x18, %eax
ffffffff810d614a:      	andl	$0x1, %eax
ffffffff810d614d:      	movl	%eax, -0x60(%rbp)
ffffffff810d6150:      	movb	-0x34(%rbp), %cl
ffffffff810d6153:      	movl	$0x1, %eax
ffffffff810d6158:      	movl	$0x0, -0x5c(%rbp)
ffffffff810d615f:      	shll	%cl, %eax
ffffffff810d6161:      	movl	%eax, -0x44(%rbp)
ffffffff810d6164:      	negl	%eax
ffffffff810d6166:      	movl	%eax, -0x68(%rbp)
ffffffff810d6169:      	movslq	-0x44(%rbp), %rax
ffffffff810d616d:      	movq	%rax, -0x80(%rbp)
ffffffff810d6171:      	movl	-0x38(%rbp), %eax
ffffffff810d6174:      	shrl	$0xb, %eax
ffffffff810d6177:      	movl	%eax, -0x98(%rbp)
ffffffff810d617d:      	movq	-0x70(%rbp), %rax
ffffffff810d6181:      	movq	0x8(%r13), %rdx
ffffffff810d6185:      	movl	0x20(%r13), %esi
ffffffff810d6189:      	leaq	0x8(%rax), %rdi
ffffffff810d618d:      	callq	0xffffffff810e3d27 <.text+0xe3d27>
ffffffff810d6192:      	movq	%rax, -0x40(%rbp)
ffffffff810d6196:      	movq	(%rax), %rbx
ffffffff810d6199:      	movl	%r15d, %eax
ffffffff810d619c:      	andl	$0x3, %eax
ffffffff810d619f:      	movq	%rax, -0x90(%rbp)
ffffffff810d61a6:      	movb	-0x98(%rbp), %al
ffffffff810d61ac:      	andl	$0x1, %eax
ffffffff810d61af:      	movb	%al, -0x91(%rbp)
ffffffff810d61b5:      	testq	%rbx, %rbx
ffffffff810d61b8:      	je	0xffffffff810d61ca <.text+0xd61ca>
ffffffff810d61ba:      	movl	0xa0a364(%rip), %eax # 0xffffffff81ae0524
ffffffff810d61c0:      	testl	%eax, %eax
ffffffff810d61c2:      	jle	0xffffffff810d624d <.text+0xd624d>
ffffffff810d61c8:      	jmp	0xffffffff810d622d <.text+0xd622d>
ffffffff810d61ca:      	testl	$0x100, %r15d   # imm = 0x100
ffffffff810d61d1:      	je	0xffffffff810d6226 <.text+0xd6226>
ffffffff810d61d3:      	andl	$0xfffffeff, %r15d # imm = 0xFFFFFEFF
ffffffff810d61da:      	cmpl	$0x0, -0x5c(%rbp)
ffffffff810d61de:      	je	0xffffffff810d6226 <.text+0xd6226>
ffffffff810d61e0:      	movq	0x10(%r13), %r12
ffffffff810d61e4:      	movq	0x40(%r12), %rbx
ffffffff810d61e9:      	movq	0x10(%rbx), %rdx
ffffffff810d61ed:      	subl	0x8(%rbx), %edx
ffffffff810d61f0:      	movl	$0x1, %esi
ffffffff810d61f5:      	movq	0x4c8(%rbx), %rax
ffffffff810d61fc:      	movq	%rbx, %rdi
ffffffff810d61ff:      	subl	%eax, %edx
ffffffff810d6201:      	callq	0xffffffff810e4ac5 <.text+0xe4ac5>
ffffffff810d6206:      	lock
ffffffff810d6207:      	andb	$-0x21, 0x3d8(%rbx)
ffffffff810d620e:      	addq	$0x600, %rbx    # imm = 0x600
ffffffff810d6215:      	leaq	-0x600(%rbx), %rax
ffffffff810d621c:      	cmpq	%rax, %r12
ffffffff810d621f:      	jne	0xffffffff810d61e9 <.text+0xd61e9>
ffffffff810d6221:      	jmp	0xffffffff810d617d <.text+0xd617d>
ffffffff810d6226:      	xorl	%eax, %eax
ffffffff810d6228:      	jmp	0xffffffff810d6651 <.text+0xd6651>
ffffffff810d622d:      	testb	$0x40, %r15b
ffffffff810d6231:      	je	0xffffffff810d624d <.text+0xd624d>
ffffffff810d6233:      	movl	0xa0a2eb(%rip), %eax # 0xffffffff81ae0524
ffffffff810d6239:      	incl	%eax
ffffffff810d623b:      	decl	%eax
ffffffff810d623d:      	jle	0xffffffff810d624d <.text+0xd624d>
ffffffff810d623f:      	movl	-0x38(%rbp), %esi
ffffffff810d6242:      	xorl	%edi, %edi
ffffffff810d6244:      	callq	0xffffffff810b44b2 <.text+0xb44b2>
ffffffff810d6249:      	testl	%eax, %eax
ffffffff810d624b:      	je	0xffffffff810d6264 <.text+0xd6264>
ffffffff810d624d:      	testl	$0x100, %r15d   # imm = 0x100
ffffffff810d6254:      	je	0xffffffff810d6285 <.text+0xd6285>
ffffffff810d6256:      	movq	0x3d8(%rbx), %rax
ffffffff810d625d:      	testb	$0x20, %al
ffffffff810d625f:      	je	0xffffffff810d6285 <.text+0xd6285>
ffffffff810d6261:      	incl	-0x5c(%rbp)
ffffffff810d6264:      	movq	-0x40(%rbp), %rdi
ffffffff810d6268:      	movq	0x8(%r13), %rdx
ffffffff810d626c:      	movl	0x20(%r13), %esi
ffffffff810d6270:      	addq	$0x10, %rdi
ffffffff810d6274:      	callq	0xffffffff810e3d27 <.text+0xe3d27>
ffffffff810d6279:      	movq	%rax, -0x40(%rbp)
ffffffff810d627d:      	movq	(%rax), %rbx
ffffffff810d6280:      	jmp	0xffffffff810d61b5 <.text+0xd61b5>
ffffffff810d6285:      	cmpl	$0x0, -0x60(%rbp)
ffffffff810d6289:      	jne	0xffffffff810d62ae <.text+0xd62ae>
ffffffff810d628b:      	movq	-0x90(%rbp), %rax
ffffffff810d6292:      	movl	0x18(%r13), %ecx
ffffffff810d6296:      	movl	%r15d, %r8d
ffffffff810d6299:      	movl	-0x34(%rbp), %esi
ffffffff810d629c:      	movq	%rbx, %rdi
ffffffff810d629f:      	movq	(%rbx,%rax,8), %rdx
ffffffff810d62a3:      	callq	0xffffffff810d4d27 <.text+0xd4d27>
ffffffff810d62a8:      	testb	%al, %al
ffffffff810d62aa:      	jne	0xffffffff810d62c2 <.text+0xd62c2>
ffffffff810d62ac:      	jmp	0xffffffff810d62bc <.text+0xd62bc>
ffffffff810d62ae:      	movq	%rbx, %rdi
ffffffff810d62b1:      	callq	0xffffffff810d82d8 <.text+0xd82d8>
ffffffff810d62b6:      	testb	%al, %al
ffffffff810d62b8:      	jne	0xffffffff810d628b <.text+0xd628b>
ffffffff810d62ba:      	jmp	0xffffffff810d6264 <.text+0xd6264>
ffffffff810d62bc:      	testb	$0x4, %r15b
ffffffff810d62c0:      	je	0xffffffff810d6264 <.text+0xd6264>
ffffffff810d62c2:      	movl	0x1c(%r13), %eax
ffffffff810d62c6:      	movl	%eax, -0x48(%rbp)
ffffffff810d62c9:      	movl	-0x38(%rbp), %eax
ffffffff810d62cc:      	andl	$0x100, %eax    # imm = 0x100
ffffffff810d62d1:      	cmpl	$0x0, -0x34(%rbp)
ffffffff810d62d5:      	movl	%eax, -0x64(%rbp)
ffffffff810d62d8:      	jne	0xffffffff810d6419 <.text+0xd6419>
ffffffff810d62de:      	callq	0xffffffff810d3dd5 <.text+0xd3dd5>
ffffffff810d62e3:      	movq	0x48(%rbx), %r14
ffffffff810d62e7:      	movq	%rax, -0x50(%rbp)
ffffffff810d62eb:      	addq	%gs:0x7ef33e25(%rip), %r14
ffffffff810d62f3:      	movslq	-0x48(%rbp), %r12
ffffffff810d62f7:      	leaq	0x1(%r12), %rax
ffffffff810d62fc:      	shlq	$0x4, %r12
ffffffff810d6300:      	addq	%r14, %r12
ffffffff810d6303:      	shlq	$0x4, %rax
ffffffff810d6307:      	addq	%r14, %rax
ffffffff810d630a:      	cmpq	0x10(%r12), %rax
ffffffff810d630f:      	movq	%rax, -0x58(%rbp)
ffffffff810d6313:      	je	0xffffffff810d6329 <.text+0xd6329>
ffffffff810d6315:      	cmpl	$0x0, -0x64(%rbp)
ffffffff810d6319:      	je	0xffffffff810d6401 <.text+0xd6401>
ffffffff810d631f:      	movq	0x18(%r12), %r12
ffffffff810d6324:      	jmp	0xffffffff810d6406 <.text+0xd6406>
ffffffff810d6329:      	movslq	0x8(%r14), %rax
ffffffff810d632d:      	movq	%rax, -0x78(%rbp)
ffffffff810d6331:      	leaq	0x3e0(%rbx), %rax
ffffffff810d6338:      	movq	%rax, %rdi
ffffffff810d633b:      	movq	%rax, -0x88(%rbp)
ffffffff810d6342:      	callq	0xffffffff81561583 <.text+0x561583>
ffffffff810d6347:      	movq	-0x58(%rbp), %r8
ffffffff810d634b:      	xorl	%r9d, %r9d
ffffffff810d634e:      	movslq	%r9d, %rax
ffffffff810d6351:      	cmpq	%rax, -0x78(%rbp)
ffffffff810d6355:      	jbe	0xffffffff810d6385 <.text+0xd6385>
ffffffff810d6357:      	movl	-0x48(%rbp), %edx
ffffffff810d635a:      	xorl	%esi, %esi
ffffffff810d635c:      	movq	%rbx, %rdi
ffffffff810d635f:      	movl	%r9d, -0xa4(%rbp)
ffffffff810d6366:      	movq	%r8, -0xa0(%rbp)
ffffffff810d636d:      	callq	0xffffffff810d5f25 <.text+0xd5f25>
ffffffff810d6372:      	testq	%rax, %rax
ffffffff810d6375:      	movq	-0xa0(%rbp), %r8
ffffffff810d637c:      	movl	-0xa4(%rbp), %r9d
ffffffff810d6383:      	jne	0xffffffff810d63c4 <.text+0xd63c4>
ffffffff810d6385:      	movl	%r9d, %edx
ffffffff810d6388:      	xorl	%esi, %esi
ffffffff810d638a:      	movq	%rbx, %rdi
ffffffff810d638d:      	negl	%edx
ffffffff810d638f:      	movl	%r9d, -0x48(%rbp)
ffffffff810d6393:      	callq	0xffffffff810e4b21 <.text+0xe4b21>
ffffffff810d6398:      	movq	-0x88(%rbp), %rax
ffffffff810d639f:      	addb	$0x1, (%rax)
ffffffff810d63a2:      	decl	%gs:0x7ef3456f(%rip)
ffffffff810d63a9:      	movl	-0x48(%rbp), %r9d
ffffffff810d63ad:      	addl	%r9d, (%r14)
ffffffff810d63b0:      	movq	-0x58(%rbp), %rax
ffffffff810d63b4:      	cmpq	0x10(%r12), %rax
ffffffff810d63b9:      	jne	0xffffffff810d6315 <.text+0xd6315>
ffffffff810d63bf:      	jmp	0xffffffff810d6507 <.text+0xd6507>
ffffffff810d63c4:      	cmpl	$0x0, -0x64(%rbp)
ffffffff810d63c8:      	leaq	0x20(%rax), %rdx
ffffffff810d63cc:      	jne	0xffffffff810d63e2 <.text+0xd63e2>
ffffffff810d63ce:      	movq	(%r8), %rsi
ffffffff810d63d1:      	movq	%rdx, 0x8(%rsi)
ffffffff810d63d5:      	movq	%rsi, 0x20(%rax)
ffffffff810d63d9:      	movq	%r8, 0x28(%rax)
ffffffff810d63dd:      	movq	%rdx, (%r8)
ffffffff810d63e0:      	jmp	0xffffffff810d63f5 <.text+0xd63f5>
ffffffff810d63e2:      	movq	0x8(%r8), %rsi
ffffffff810d63e6:      	movq	%rdx, 0x8(%r8)
ffffffff810d63ea:      	movq	%r8, 0x20(%rax)
ffffffff810d63ee:      	movq	%rsi, 0x28(%rax)
ffffffff810d63f2:      	movq	%rdx, (%rsi)
ffffffff810d63f5:      	leaq	0x20(%rax), %r8
ffffffff810d63f9:      	incl	%r9d
ffffffff810d63fc:      	jmp	0xffffffff810d634e <.text+0xd634e>
ffffffff810d6401:      	movq	0x10(%r12), %r12
ffffffff810d6406:      	subq	$0x20, %r12
ffffffff810d640a:      	leaq	0x20(%r12), %rdi
ffffffff810d640f:      	callq	0xffffffff810d3da6 <.text+0xd3da6>
ffffffff810d6414:      	decl	(%r14)
ffffffff810d6417:      	jmp	0xffffffff810d648e <.text+0xd648e>
ffffffff810d6419:      	cmpb	$0x0, -0x91(%rbp)
ffffffff810d6420:      	je	0xffffffff810d6449 <.text+0xd6449>
ffffffff810d6422:      	cmpl	$0x1, -0x34(%rbp)
ffffffff810d6426:      	jbe	0xffffffff810d6449 <.text+0xd6449>
ffffffff810d6428:      	cmpb	$0x0, 0x9f5064(%rip) # 0xffffffff81acb493
ffffffff810d642f:      	jne	0xffffffff810d6449 <.text+0xd6449>
ffffffff810d6431:      	movl	$0x6e8, %esi    # imm = 0x6E8
ffffffff810d6436:      	movq	$-0x7e8073d9, %rdi # imm = 0x817F8C27
ffffffff810d643d:      	callq	0xffffffff8105c38d <.text+0x5c38d>
ffffffff810d6442:      	movb	$0x1, 0x9f504a(%rip) # 0xffffffff81acb493
ffffffff810d6449:      	leaq	0x3e0(%rbx), %rdi
ffffffff810d6450:      	callq	0xffffffff815616a2 <.text+0x5616a2>
ffffffff810d6455:      	movl	-0x48(%rbp), %edx
ffffffff810d6458:      	movl	-0x34(%rbp), %esi
ffffffff810d645b:      	movq	%rbx, %rdi
ffffffff810d645e:      	movq	%rax, -0x50(%rbp)
ffffffff810d6462:      	callq	0xffffffff810d5f25 <.text+0xd5f25>
ffffffff810d6467:      	movq	%rax, %r12
ffffffff810d646a:      	addb	$0x1, 0x3e0(%rbx)
ffffffff810d6471:      	decl	%gs:0x7ef344a0(%rip)
ffffffff810d6478:      	testq	%rax, %rax
ffffffff810d647b:      	je	0xffffffff810d6507 <.text+0xd6507>
ffffffff810d6481:      	movl	-0x68(%rbp), %edx
ffffffff810d6484:      	xorl	%esi, %esi
ffffffff810d6486:      	movq	%rbx, %rdi
ffffffff810d6489:      	callq	0xffffffff810e4b21 <.text+0xe4b21>
ffffffff810d648e:      	movl	-0x68(%rbp), %edx
ffffffff810d6491:      	movl	$0x1, %esi
ffffffff810d6496:      	movq	%rbx, %rdi
ffffffff810d6499:      	callq	0xffffffff810e4b21 <.text+0xe4b21>
ffffffff810d649e:      	movq	0x4c8(%rbx), %rax
ffffffff810d64a5:      	testq	%rax, %rax
ffffffff810d64a8:      	jg	0xffffffff810d64bd <.text+0xd64bd>
ffffffff810d64aa:      	movq	0x3d8(%rbx), %rax
ffffffff810d64b1:      	testb	$0x20, %al
ffffffff810d64b3:      	jne	0xffffffff810d64bd <.text+0xd64bd>
ffffffff810d64b5:      	lock
ffffffff810d64b6:      	orb	$0x20, 0x3d8(%rbx)
ffffffff810d64bd:      	movq	%rbx, %rax
ffffffff810d64c0:      	subq	0x40(%rbx), %rax
ffffffff810d64c4:      	movq	-0x80(%rbp), %rsi
ffffffff810d64c8:      	sarq	$0x9, %rax
ffffffff810d64cc:      	imull	$0xaaaaaaab, %eax, %eax # imm = 0xAAAAAAAB
ffffffff810d64d2:      	leal	0x4(%rax), %edi
ffffffff810d64d5:      	callq	0xffffffff810d3f8e <.text+0xd3f8e>
ffffffff810d64da:      	pushq	-0x50(%rbp)
ffffffff810d64dd:      	popfq
ffffffff810d64de:      	testq	%r12, %r12
ffffffff810d64e1:      	je	0xffffffff810d6264 <.text+0xd6264>
ffffffff810d64e7:      	movq	%r12, %rax
ffffffff810d64ea:      	xorl	%r8d, %r8d
ffffffff810d64ed:      	movq	$-0x7e807489, %r9 # imm = 0x817F8B77
ffffffff810d64f4:      	xorl	%r10d, %r10d
ffffffff810d64f7:      	movq	$-0x7e807478, %r11 # imm = 0x817F8B88
ffffffff810d64fe:      	movq	$-0x7e807467, %r14 # imm = 0x817F8B99
ffffffff810d6505:      	jmp	0xffffffff810d656b <.text+0xd656b>
ffffffff810d6507:      	pushq	-0x50(%rbp)
ffffffff810d650a:      	popfq
ffffffff810d650b:      	jmp	0xffffffff810d6264 <.text+0xd6264>
ffffffff810d6510:      	movl	0x18(%rax), %edx
ffffffff810d6513:      	movq	%r10, %rsi
ffffffff810d6516:      	movq	(%rax), %rcx
ffffffff810d6519:      	movq	%rax, %rdi
ffffffff810d651c:      	incl	%edx
ffffffff810d651e:      	movl	0x1c(%rax), %edx
ffffffff810d6521:      	cmovneq	%r9, %rsi
ffffffff810d6525:      	cmpq	$0x0, 0x8(%rax)
ffffffff810d652a:      	cmovneq	%r11, %rsi
ffffffff810d652e:      	testl	%edx, %edx
ffffffff810d6530:      	cmovneq	%r14, %rsi
ffffffff810d6534:      	andl	$0x7fffff, %ecx # imm = 0x7FFFFF
ffffffff810d653a:      	cmpq	$0x1, %rcx
ffffffff810d653e:      	sbbq	%rdx, %rdx
ffffffff810d6541:      	notq	%rdx
ffffffff810d6544:      	andl	$0x7fffff, %edx # imm = 0x7FFFFF
ffffffff810d654a:      	testq	%rcx, %rcx
ffffffff810d654d:      	movq	$-0x7e806ec8, %rcx # imm = 0x817F9138
ffffffff810d6554:      	cmovneq	%rcx, %rsi
ffffffff810d6558:      	cmpq	$0x0, 0x38(%rax)
ffffffff810d655d:      	jne	0xffffffff810d6573 <.text+0xd6573>
ffffffff810d655f:      	addq	$0x40, %rax
ffffffff810d6563:      	testq	%rsi, %rsi
ffffffff810d6566:      	jne	0xffffffff810d657a <.text+0xd657a>
ffffffff810d6568:      	incl	%r8d
ffffffff810d656b:      	cmpl	%r8d, -0x44(%rbp)
ffffffff810d656f:      	jg	0xffffffff810d6510 <.text+0xd6510>
ffffffff810d6571:      	jmp	0xffffffff810d6584 <.text+0xd6584>
ffffffff810d6573:      	movq	$-0x7e807433, %rsi # imm = 0x817F8BCD
ffffffff810d657a:      	callq	0xffffffff810d40ae <.text+0xd40ae>
ffffffff810d657f:      	jmp	0xffffffff810d62c2 <.text+0xd62c2>
ffffffff810d6584:      	testl	$0x8000, -0x38(%rbp) # imm = 0x8000
ffffffff810d658b:      	movq	$0x0, 0x30(%r12)
ffffffff810d6594:      	movl	$0x1, 0x1c(%r12)
ffffffff810d659d:      	jne	0xffffffff810d65ae <.text+0xd65ae>
ffffffff810d659f:      	cmpl	$0x0, -0x34(%rbp)
ffffffff810d65a3:      	jne	0xffffffff810d662a <.text+0xd662a>
ffffffff810d65a9:      	jmp	0xffffffff810d663e <.text+0xd663e>
ffffffff810d65ae:      	movabsq	$0x160000000000, %rbx # imm = 0x160000000000
ffffffff810d65b8:      	xorl	%r13d, %r13d
ffffffff810d65bb:      	addq	%r12, %rbx
ffffffff810d65be:      	movq	%gs:0xa980, %r14
ffffffff810d65c7:      	cmpl	%r13d, -0x44(%rbp)
ffffffff810d65cb:      	jle	0xffffffff810d659f <.text+0xd659f>
ffffffff810d65cd:      	incl	%gs:0x7ef34344(%rip)
ffffffff810d65d4:      	incl	0x790(%r14)
ffffffff810d65db:      	movq	%rbx, %rdi
ffffffff810d65de:      	movabsq	$-0x780000000000, %rax # imm = 0xFFFF880000000000
ffffffff810d65e8:      	sarq	$0x6, %rdi
ffffffff810d65ec:      	shlq	$0xc, %rdi
ffffffff810d65f0:      	addq	%rax, %rdi
ffffffff810d65f3:      	callq	0xffffffff81207f90 <.text+0x207f90>
ffffffff810d65f8:      	decl	0x790(%r14)
ffffffff810d65ff:      	cmpl	$0x0, 0x790(%r14)
ffffffff810d6607:      	jns	0xffffffff810d661a <.text+0xd661a>
ffffffff810d6609:      	movl	$0x10, %esi
ffffffff810d660e:      	movq	$-0x7e81f0d6, %rdi # imm = 0x817E0F2A
ffffffff810d6615:      	callq	0xffffffff8105c38d <.text+0x5c38d>
ffffffff810d661a:      	decl	%gs:0x7ef342f7(%rip)
ffffffff810d6621:      	incl	%r13d
ffffffff810d6624:      	addq	$0x40, %rbx
ffffffff810d6628:      	jmp	0xffffffff810d65c7 <.text+0xd65c7>
ffffffff810d662a:      	testl	$0x4000, -0x38(%rbp) # imm = 0x4000
ffffffff810d6631:      	je	0xffffffff810d663e <.text+0xd663e>
ffffffff810d6633:      	movl	-0x34(%rbp), %esi
ffffffff810d6636:      	movq	%r12, %rdi
ffffffff810d6639:      	callq	0xffffffff810d4ac8 <.text+0xd4ac8>
ffffffff810d663e:      	movq	%r15, %rax
ffffffff810d6641:      	shlq	$0x3d, %rax
ffffffff810d6645:      	sarq	$0x3f, %rax
ffffffff810d6649:      	movq	%rax, 0x10(%r12)
ffffffff810d664e:      	movq	%r12, %rax
ffffffff810d6651:      	addq	$0x88, %rsp
ffffffff810d6658:      	popq	%rbx
ffffffff810d6659:      	popq	%r12
ffffffff810d665b:      	popq	%r13
ffffffff810d665d:      	popq	%r14
ffffffff810d665f:      	popq	%r15
ffffffff810d6661:      	popq	%rbp
ffffffff810d6662:      	retq
