# Exact-static AppUpgrade parameterized-verifier provenance
# ELF size: 5,066,264
# ELF SHA-256: 464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7
# GNU Build ID: 863a8730e66a1c5245a1bf458fe2554adee0351a
# Instruction authority: Homebrew LLVM 23.1.3 llvm-objdump.
# FDE authority: Homebrew LLVM 23.1.3 llvm-readelf --unwind.
# No raw instruction bytes are retained. Addresses are image-base-zero ELF VAs.

## Exact .eh_frame ranges
verifier                    [0x45820, 0x45d75)
resource route               [0x9cbc0, 0x9e260)
resource-route caller        [0xf28e0, 0xf3ddf)
navigation transform         [0x140030, 0x1405da)
command helper               [0x1397c0, 0x1398fb)

## Resource-route caller and archive/base-name producer [0xf28e0,0xf3066)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   f28e0:      	pushq	%r15
   f28e2:      	pushq	%r14
   f28e4:      	movq	%rdi, %r14
   f28e7:      	pushq	%r13
   f28e9:      	pushq	%r12
   f28eb:      	pushq	%rbp
   f28ec:      	pushq	%rbx
   f28ed:      	subq	$0x2b8, %rsp            # imm = 0x2B8
   f28f4:      	movq	%fs:0x28, %rax
   f28fd:      	movq	%rax, 0x2a8(%rsp)
   f2905:      	xorl	%eax, %eax
   f2907:      	callq	0x55c60 <.text+0x31430>
   f290c:      	leaq	0x136855(%rip), %rdx    # 0x229168
   f2913:      	leaq	0x12c873(%rip), %rsi    # 0x21f18d
   f291a:      	movq	%rax, %rdi
   f291d:      	xorl	%eax, %eax
   f291f:      	callq	0x137430 <.text+0x112c00>
   f2924:      	leaq	0x5e1d75(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
   f292b:      	movl	0x5e26b7(%rip), %ebx    # 0x6d4fe8 <_ZN9QListData11shared_nullE+0x788>
   f2931:      	movq	%rax, 0x50(%rsp)
   f2936:      	movq	%rax, 0x60(%rsp)
   f293b:      	movq	%rax, 0x70(%rsp)
   f2940:      	movq	%rax, 0x80(%rsp)
   f2948:      	leaq	0x80(%rsp), %rax
   f2950:      	movq	%rax, 0x30(%rsp)
   f2955:      	callq	0x55c60 <.text+0x31430>
   f295a:      	leaq	0x80(%rsp), %rcx
   f2962:      	movq	%rax, %rdi
   f2965:      	xorl	%eax, %eax
   f2967:      	movq	%rcx, 0x30(%rsp)
   f296c:      	leaq	0x1367f5(%rip), %rdx    # 0x229168
   f2973:      	movl	%ebx, %ecx
   f2975:      	leaq	0x12c81d(%rip), %rsi    # 0x21f199
   f297c:      	callq	0x137430 <.text+0x112c00>
   f2981:      	movl	0x5e2661(%rip), %ebx    # 0x6d4fe8 <_ZN9QListData11shared_nullE+0x788>
   f2987:      	cmpl	$0x1d, %ebx
   f298a:      	je	0xf2a30 <.text+0xce200>
   f2990:      	leaq	0x80(%rsp), %rax
   f2998:      	movq	%rax, 0x30(%rsp)
   f299d:      	callq	0x55c60 <.text+0x31430>
   f29a2:      	leaq	0x80(%rsp), %rcx
   f29aa:      	movq	%rax, %rdi
   f29ad:      	xorl	%eax, %eax
   f29af:      	movq	%rcx, 0x30(%rsp)
   f29b4:      	leaq	0x1367ad(%rip), %rdx    # 0x229168
   f29bb:      	movl	%ebx, %ecx
   f29bd:      	leaq	0x12f82c(%rip), %rsi    # 0x2221f0
   f29c4:      	callq	0x137430 <.text+0x112c00>
   f29c9:      	leaq	0x80(%rsp), %rax
   f29d1:      	xorl	%ebx, %ebx
   f29d3:      	movq	%rax, 0x30(%rsp)
   f29d8:      	movq	0x30(%rsp), %rdi
   f29dd:      	callq	0x4b960 <.text+0x27130>
   f29e2:      	leaq	0x70(%rsp), %rdi
   f29e7:      	callq	0x4b960 <.text+0x27130>
   f29ec:      	leaq	0x60(%rsp), %rdi
   f29f1:      	callq	0x4b960 <.text+0x27130>
   f29f6:      	leaq	0x50(%rsp), %rdi
   f29fb:      	callq	0x4b960 <.text+0x27130>
   f2a00:      	movl	%ebx, %eax
   f2a02:      	movq	0x2a8(%rsp), %rbx
   f2a0a:      	xorq	%fs:0x28, %rbx
   f2a13:      	jne	0xf3cf6 <.text+0xcf4c6>
   f2a19:      	addq	$0x2b8, %rsp            # imm = 0x2B8
   f2a20:      	popq	%rbx
   f2a21:      	popq	%rbp
   f2a22:      	popq	%r12
   f2a24:      	popq	%r13
   f2a26:      	popq	%r14
   f2a28:      	popq	%r15
   f2a2a:      	retq
   f2a2b:      	nopl	(%rax,%rax)
   f2a30:      	movq	0x40(%r14), %rsi
   f2a34:      	testq	%rsi, %rsi
   f2a37:      	je	0xf3b5e <.text+0xcf32e>
   f2a3d:      	leaq	0xc0(%rsp), %rax
   f2a45:      	leaq	0x80(%rsp), %rbx
   f2a4d:      	movq	%rax, %rdi
   f2a50:      	movq	%rax, %r15
   f2a53:      	movq	%rax, (%rsp)
   f2a57:      	movq	%rbx, 0x30(%rsp)
   f2a5c:      	callq	0x95420 <.text+0x70bf0>
   f2a61:      	movq	0xc0(%rsp), %rax
   f2a69:      	movq	%r15, %rdi
   f2a6c:      	movl	0x4(%rax), %ebx
   f2a6f:      	callq	0x4b960 <.text+0x27130>
   f2a74:      	testl	%ebx, %ebx
   f2a76:      	jne	0xf2ac0 <.text+0xce290>
   f2a78:      	leaq	0x80(%rsp), %rax
   f2a80:      	movq	%rax, 0x30(%rsp)
   f2a85:      	callq	0x55c60 <.text+0x31430>
   f2a8a:      	leaq	0x80(%rsp), %rbx
   f2a92:      	movl	$0x3716, %ecx           # imm = 0x3716
   f2a97:      	movq	%rbx, 0x30(%rsp)
   f2a9c:      	leaq	0x1366c5(%rip), %rdx    # 0x229168
   f2aa3:      	movq	%rax, %rdi
   f2aa6:      	xorl	%eax, %eax
   f2aa8:      	leaq	0x12c708(%rip), %rsi    # 0x21f1b7
   f2aaf:      	callq	0x137430 <.text+0x112c00>
   f2ab4:      	jmp	0xf29c9 <.text+0xce199>
   f2ab9:      	nopl	(%rax)
   f2ac0:      	movq	0x40(%r14), %rsi
   f2ac4:      	leaq	0xd0(%rsp), %rax
   f2acc:      	leaq	0x80(%rsp), %rbx
   f2ad4:      	movq	%rax, %rdi
   f2ad7:      	movq	%rax, 0x8(%rsp)
   f2adc:      	movq	%rbx, 0x30(%rsp)
   f2ae1:      	movq	%rax, %rbx
   f2ae4:      	callq	0x95420 <.text+0x70bf0>
   f2ae9:      	movq	0x80(%rsp), %rax
   f2af1:      	movq	%rbx, %rdi
   f2af4:      	movq	0xd0(%rsp), %rdx
   f2afc:      	movq	%rax, 0xd0(%rsp)
   f2b04:      	movq	%rdx, 0x80(%rsp)
   f2b0c:      	callq	0x4b960 <.text+0x27130>
   f2b11:      	leaq	0x80(%rsp), %rax
   f2b19:      	leaq	0x13a14b(%rip), %rsi    # 0x22cc6b
   f2b20:      	movq	%rax, %rdi
   f2b23:      	movq	%rax, 0x30(%rsp)
   f2b28:      	callq	0x131d40 <.text+0x10d510>
   f2b2d:      	leaq	0x90(%rsp), %rbx
   f2b35:      	movq	%rax, %rsi
   f2b38:      	movq	%rbx, %rdi
   f2b3b:      	movq	%rbx, 0x40(%rsp)
   f2b40:      	callq	0x24320 <_ZN4QDirC1ERK7QString@plt>
   f2b45:      	leaq	0xa0(%rsp), %rax
   f2b4d:      	movl	$0xffffffff, %ecx       # imm = 0xFFFFFFFF
   f2b52:      	movl	$0x6402, %edx           # imm = 0x6402
   f2b57:      	movq	%rbx, %rsi
   f2b5a:      	movq	%rax, %rdi
   f2b5d:      	movq	%rax, 0x48(%rsp)
   f2b62:      	callq	0x22420 <_ZNK4QDir13entryInfoListE6QFlagsINS_6FilterEES0_INS_8SortFlagEE@plt>
   f2b67:      	movq	0xa0(%rsp), %rdx
   f2b6f:      	movslq	0x8(%rdx), %rax
   f2b73:      	movl	0xc(%rdx), %ecx
   f2b76:      	subl	%eax, %ecx
   f2b78:      	testl	%ecx, %ecx
   f2b7a:      	jle	0xf3b9f <.text+0xcf36f>
   f2b80:      	leaq	0xe0(%rsp), %rcx
   f2b88:      	xorl	%r13d, %r13d
   f2b8b:      	xorl	%r15d, %r15d
   f2b8e:      	movq	%rcx, 0x18(%rsp)
   f2b93:      	leaq	0x100(%rsp), %rcx
   f2b9b:      	movq	%rcx, 0x10(%rsp)
   f2ba0:      	leaq	0xf0(%rsp), %rcx
   f2ba8:      	movq	%rcx, 0x20(%rsp)
   f2bad:      	leaq	0x260(%rsp), %rcx
   f2bb5:      	leaq	0xb0(%rsp), %rbx
   f2bbd:      	movq	%rcx, 0x38(%rsp)
   f2bc2:      	jmp	0xf2de8 <.text+0xce5b8>
   f2bc7:      	nopw	(%rax,%rax)
   f2bd0:      	movl	$0x8, %edx
   f2bd5:      	movl	$0x2, %esi
   f2bda:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f2bdf:      	movq	0xd0(%rsp), %rsi
   f2be7:      	movl	(%rsi), %eax
   f2be9:      	movq	%rsi, 0x2a0(%rsp)
   f2bf1:      	addl	$0x1, %eax
   f2bf4:      	cmpl	$0x1, %eax
   f2bf7:      	jbe	0xf2c08 <.text+0xce3d8>
   f2bf9:      	lock
   f2bfa:      	addl	$0x1, (%rsi)
   f2bfd:      	setne	%al
   f2c00:      	movq	0x2a0(%rsp), %rsi
   f2c08:      	movl	0x4(%rsi), %edx
   f2c0b:      	movq	0x10(%rsi), %rax
   f2c0f:      	testl	%edx, %edx
   f2c11:      	je	0xf2c1d <.text+0xce3ed>
   f2c13:      	cmpq	$0x17, %rax
   f2c17:      	jbe	0xf3b87 <.text+0xcf357>
   f2c1d:      	movq	0x10(%rsp), %rdi
   f2c22:      	addq	%rax, %rsi
   f2c25:      	callq	0x22470 <_ZN7QString18toLocal8Bit_helperEPK5QChari@plt>
   f2c2a:      	movq	0x100(%rsp), %rax
   f2c32:      	movl	0x4(%rax), %ecx
   f2c35:      	movq	0x10(%rax), %rbp
   f2c39:      	testl	%ecx, %ecx
   f2c3b:      	je	0xf2c47 <.text+0xce417>
   f2c3d:      	cmpq	$0x17, %rbp
   f2c41:      	jbe	0xf3b87 <.text+0xcf357>
   f2c47:      	movq	0xc0(%rsp), %rsi
   f2c4f:      	addq	%rax, %rbp
   f2c52:      	movl	(%rsi), %eax
   f2c54:      	movq	%rsi, 0x290(%rsp)
   f2c5c:      	addl	$0x1, %eax
   f2c5f:      	cmpl	$0x1, %eax
   f2c62:      	jbe	0xf2c73 <.text+0xce443>
   f2c64:      	lock
   f2c65:      	addl	$0x1, (%rsi)
   f2c68:      	setne	%al
   f2c6b:      	movq	0x290(%rsp), %rsi
   f2c73:      	movl	0x4(%rsi), %edx
   f2c76:      	movq	0x10(%rsi), %rax
   f2c7a:      	testl	%edx, %edx
   f2c7c:      	je	0xf2c88 <.text+0xce458>
   f2c7e:      	cmpq	$0x17, %rax
   f2c82:      	jbe	0xf3b87 <.text+0xcf357>
   f2c88:      	movq	0x20(%rsp), %rdi
   f2c8d:      	addq	%rax, %rsi
   f2c90:      	callq	0x22470 <_ZN7QString18toLocal8Bit_helperEPK5QChari@plt>
   f2c95:      	movq	0xf0(%rsp), %rax
   f2c9d:      	movl	0x4(%rax), %edx
   f2ca0:      	movq	0x10(%rax), %r12
   f2ca4:      	testl	%edx, %edx
   f2ca6:      	je	0xf2cb2 <.text+0xce482>
   f2ca8:      	cmpq	$0x17, %r12
   f2cac:      	jbe	0xf3b87 <.text+0xcf357>
   f2cb2:      	movq	0x5e312f(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   f2cb9:      	addq	%rax, %r12
   f2cbc:      	testq	%rdi, %rdi
   f2cbf:      	je	0xf38b8 <.text+0xcf088>
   f2cc5:      	movq	%rbp, %rcx
   f2cc8:      	movq	%r12, %rdx
   f2ccb:      	xorl	%eax, %eax
   f2ccd:      	leaq	0x12f56c(%rip), %rsi    # 0x222240
   f2cd4:      	callq	0x137430 <.text+0x112c00>
   f2cd9:      	movq	0xf0(%rsp), %rdi
   f2ce1:      	movl	(%rdi), %eax
   f2ce3:      	testl	%eax, %eax
   f2ce5:      	jne	0xf2ee8 <.text+0xce6b8>
   f2ceb:      	movl	$0x8, %edx
   f2cf0:      	movl	$0x1, %esi
   f2cf5:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f2cfa:      	movq	0x290(%rsp), %rdi
   f2d02:      	movl	(%rdi), %eax
   f2d04:      	testl	%eax, %eax
   f2d06:      	jne	0xf2ec0 <.text+0xce690>
   f2d0c:      	movl	$0x8, %edx
   f2d11:      	movl	$0x2, %esi
   f2d16:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f2d1b:      	movq	0x100(%rsp), %rdi
   f2d23:      	movl	(%rdi), %eax
   f2d25:      	testl	%eax, %eax
   f2d27:      	jne	0xf2e98 <.text+0xce668>
   f2d2d:      	movl	$0x8, %edx
   f2d32:      	movl	$0x1, %esi
   f2d37:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f2d3c:      	movq	0x2a0(%rsp), %rdi
   f2d44:      	movl	(%rdi), %eax
   f2d46:      	testl	%eax, %eax
   f2d48:      	jne	0xf2e70 <.text+0xce640>
   f2d4e:      	movl	$0x8, %edx
   f2d53:      	movl	$0x2, %esi
   f2d58:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f2d5d:      	movq	%rbx, %rdi
   f2d60:      	callq	0x23c60 <_ZNK9QFileInfo6isFileEv@plt>
   f2d65:      	testb	%al, %al
   f2d67:      	jne	0xf2f60 <.text+0xce730>
   f2d6d:      	movq	%rbx, %rdi
   f2d70:      	callq	0x230a0 <_ZNK9QFileInfo5isDirEv@plt>
   f2d75:      	testb	%al, %al
   f2d77:      	jne	0xf38a0 <.text+0xcf070>
   f2d7d:      	movq	0xd0(%rsp), %rdi
   f2d85:      	movl	(%rdi), %eax
   f2d87:      	testl	%eax, %eax
   f2d89:      	jne	0xf2f10 <.text+0xce6e0>
   f2d8f:      	movl	$0x8, %edx
   f2d94:      	movl	$0x2, %esi
   f2d99:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f2d9e:      	movq	0xc0(%rsp), %rdi
   f2da6:      	movl	(%rdi), %eax
   f2da8:      	testl	%eax, %eax
   f2daa:      	jne	0xf2f38 <.text+0xce708>
   f2db0:      	movl	$0x8, %edx
   f2db5:      	movl	$0x2, %esi
   f2dba:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f2dbf:      	movq	%rbx, %rdi
   f2dc2:      	callq	0x230e0 <_ZN9QFileInfoD1Ev@plt>
   f2dc7:      	movq	0xa0(%rsp), %rdx
   f2dcf:      	leal	0x1(%r13), %esi
   f2dd3:      	addq	$0x1, %r13
   f2dd7:      	movslq	0x8(%rdx), %rax
   f2ddb:      	movl	0xc(%rdx), %ecx
   f2dde:      	subl	%eax, %ecx
   f2de0:      	cmpl	%esi, %ecx
   f2de2:      	jle	0xf3b08 <.text+0xcf2d8>
   f2de8:      	addq	%r13, %rax
   f2deb:      	movq	%rbx, %rdi
   f2dee:      	movl	%r13d, 0x28(%rsp)
   f2df3:      	leaq	0x10(%rdx,%rax,8), %rsi
   f2df8:      	callq	0x245b0 <_ZN9QFileInfoC1ERKS_@plt>
   f2dfd:      	movq	(%rsp), %rdi
   f2e01:      	movq	%rbx, %rsi
   f2e04:      	callq	0x22e00 <_ZNK9QFileInfo8baseNameEv@plt>
   f2e09:      	movq	0x8(%rsp), %rdi
   f2e0e:      	movq	%rbx, %rsi
   f2e11:      	callq	0x227f0 <_ZNK9QFileInfo8filePathEv@plt>
   f2e16:      	movq	0x18(%rsp), %rdi
   f2e1b:      	movq	%rbx, %rsi
   f2e1e:      	callq	0x22ed0 <_ZNK9QFileInfo16absoluteFilePathEv@plt>
   f2e23:      	movq	0x60(%rsp), %rdi
   f2e28:      	movq	0xe0(%rsp), %rax
   f2e30:      	movq	%rdi, 0xe0(%rsp)
   f2e38:      	movq	%rax, 0x60(%rsp)
   f2e3d:      	movl	(%rdi), %eax
   f2e3f:      	testl	%eax, %eax
   f2e41:      	je	0xf2bd0 <.text+0xce3a0>
   f2e47:      	cmpl	$-0x1, %eax
   f2e4a:      	je	0xf2bdf <.text+0xce3af>
   f2e50:      	lock
   f2e51:      	subl	$0x1, (%rdi)
   f2e54:      	setne	%al
   f2e57:      	testb	%al, %al
   f2e59:      	jne	0xf2bdf <.text+0xce3af>
   f2e5f:      	movq	0xe0(%rsp), %rdi
   f2e67:      	jmp	0xf2bd0 <.text+0xce3a0>
   f2e6c:      	nopl	(%rax)
   f2e70:      	cmpl	$-0x1, %eax
   f2e73:      	je	0xf2d5d <.text+0xce52d>
   f2e79:      	lock
   f2e7a:      	subl	$0x1, (%rdi)
   f2e7d:      	setne	%al
   f2e80:      	testb	%al, %al
   f2e82:      	jne	0xf2d5d <.text+0xce52d>
   f2e88:      	movq	0x2a0(%rsp), %rdi
   f2e90:      	jmp	0xf2d4e <.text+0xce51e>
   f2e95:      	nopl	(%rax)
   f2e98:      	cmpl	$-0x1, %eax
   f2e9b:      	je	0xf2d3c <.text+0xce50c>
   f2ea1:      	lock
   f2ea2:      	subl	$0x1, (%rdi)
   f2ea5:      	setne	%al
   f2ea8:      	testb	%al, %al
   f2eaa:      	jne	0xf2d3c <.text+0xce50c>
   f2eb0:      	movq	0x100(%rsp), %rdi
   f2eb8:      	jmp	0xf2d2d <.text+0xce4fd>
   f2ebd:      	nopl	(%rax)
   f2ec0:      	cmpl	$-0x1, %eax
   f2ec3:      	je	0xf2d1b <.text+0xce4eb>
   f2ec9:      	lock
   f2eca:      	subl	$0x1, (%rdi)
   f2ecd:      	setne	%al
   f2ed0:      	testb	%al, %al
   f2ed2:      	jne	0xf2d1b <.text+0xce4eb>
   f2ed8:      	movq	0x290(%rsp), %rdi
   f2ee0:      	jmp	0xf2d0c <.text+0xce4dc>
   f2ee5:      	nopl	(%rax)
   f2ee8:      	cmpl	$-0x1, %eax
   f2eeb:      	je	0xf2cfa <.text+0xce4ca>
   f2ef1:      	lock
   f2ef2:      	subl	$0x1, (%rdi)
   f2ef5:      	setne	%al
   f2ef8:      	testb	%al, %al
   f2efa:      	jne	0xf2cfa <.text+0xce4ca>
   f2f00:      	movq	0xf0(%rsp), %rdi
   f2f08:      	jmp	0xf2ceb <.text+0xce4bb>
   f2f0d:      	nopl	(%rax)
   f2f10:      	cmpl	$-0x1, %eax
   f2f13:      	je	0xf2d9e <.text+0xce56e>
   f2f19:      	lock
   f2f1a:      	subl	$0x1, (%rdi)
   f2f1d:      	setne	%al
   f2f20:      	testb	%al, %al
   f2f22:      	jne	0xf2d9e <.text+0xce56e>
   f2f28:      	movq	0xd0(%rsp), %rdi
   f2f30:      	jmp	0xf2d8f <.text+0xce55f>
   f2f35:      	nopl	(%rax)
   f2f38:      	cmpl	$-0x1, %eax
   f2f3b:      	je	0xf2dbf <.text+0xce58f>
   f2f41:      	lock
   f2f42:      	subl	$0x1, (%rdi)
   f2f45:      	setne	%al
   f2f48:      	testb	%al, %al
   f2f4a:      	jne	0xf2dbf <.text+0xce58f>
   f2f50:      	movq	0xc0(%rsp), %rdi
   f2f58:      	jmp	0xf2db0 <.text+0xce580>
   f2f5d:      	nopl	(%rax)
   f2f60:      	leaq	0x110(%rsp), %rbp
   f2f68:      	movq	%rbx, %rsi
   f2f6b:      	movq	%rbp, %rdi
   f2f6e:      	callq	0x22740 <_ZNK9QFileInfo14completeSuffixEv@plt>
   f2f73:      	movq	0x110(%rsp), %rax
   f2f7b:      	movl	0x4(%rax), %esi
   f2f7e:      	movq	0x10(%rax), %rdi
   f2f82:      	testl	%esi, %esi
   f2f84:      	je	0xf2f90 <.text+0xce760>
   f2f86:      	cmpq	$0x17, %rdi
   f2f8a:      	jbe	0xf3b87 <.text+0xcf357>
   f2f90:      	addq	%rax, %rdi
   f2f93:      	movl	$0x1, %r8d
   f2f99:      	movl	$0xffffffff, %ecx       # imm = 0xFFFFFFFF
   f2f9e:      	leaq	0x12db87(%rip), %rdx    # 0x220b2c
   f2fa5:      	callq	0x23630 <_ZN7QString14compare_helperEPK5QChariPKciN2Qt15CaseSensitivityE@plt>
   f2faa:      	movl	%eax, %r12d
   f2fad:      	movq	%rbp, %rdi
   f2fb0:      	callq	0x4b960 <.text+0x27130>
   f2fb5:      	testl	%r12d, %r12d
   f2fb8:      	jne	0xf2d6d <.text+0xce53d>
   f2fbe:      	movq	(%rsp), %rsi
   f2fc2:      	leaq	0x120(%rsp), %rbp
   f2fca:      	movl	$0xa, %edx
   f2fcf:      	movq	%rbp, %rdi
   f2fd2:      	callq	0x24080 <_ZNK7QString4leftEi@plt>
   f2fd7:      	movq	0x50(%rsp), %rax
   f2fdc:      	movq	%rbp, %rdi
   f2fdf:      	movq	0x120(%rsp), %rdx
   f2fe7:      	movq	%rax, 0x120(%rsp)
   f2fef:      	movq	%rdx, 0x50(%rsp)
   f2ff4:      	callq	0x4b960 <.text+0x27130>
   f2ff9:      	movq	0x50(%rsp), %rax
   f2ffe:      	movl	0x4(%rax), %esi
   f3001:      	movq	0x10(%rax), %rdi
   f3005:      	testl	%esi, %esi
   f3007:      	je	0xf3013 <.text+0xce7e3>
   f3009:      	cmpq	$0x17, %rdi
   f300d:      	jbe	0xf3b87 <.text+0xcf357>
   f3013:      	addq	%rax, %rdi
   f3016:      	movl	$0x1, %r8d
   f301c:      	movl	$0xffffffff, %ecx       # imm = 0xFFFFFFFF
   f3021:      	leaq	0x122585(%rip), %rdx    # 0x2155ad
   f3028:      	callq	0x23630 <_ZN7QString14compare_helperEPK5QChariPKciN2Qt15CaseSensitivityE@plt>
   f302d:      	testl	%eax, %eax
   f302f:      	jne	0xf3350 <.text+0xceb20>
   f3035:      	movq	0x5e2dac(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   f303c:      	testq	%rdi, %rdi
   f303f:      	je	0xf3a90 <.text+0xcf260>
   f3045:      	leaq	0x13610c(%rip), %r8     # 0x229158
   f304c:      	movl	$0x3737, %ecx           # imm = 0x3737
   f3051:      	xorl	%eax, %eax
   f3053:      	leaq	0x12bacc(%rip), %rdx    # 0x21eb26
   f305a:      	leaq	0x12f207(%rip), %rsi    # 0x222268
   f3061:      	callq	0x137430 <.text+0x112c00>

## Resource-route caller edge [0xf31e9,0xf35b1)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   f31e9:      	leaq	0x12c02e(%rip), %rdi    # 0x21f21e
   f31f0:      	movl	$0xc, %esi
   f31f5:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   f31fa:      	movq	0x38(%rsp), %r15
   f31ff:      	leaq	0x2a0(%rsp), %rbp
   f3207:      	movl	$0x20, %r8d
   f320d:      	xorl	%ecx, %ecx
   f320f:      	leaq	0x60(%rsp), %rdx
   f3214:      	movq	%rbp, %rsi
   f3217:      	movq	%rax, 0x2a0(%rsp)
   f321f:      	movq	%r15, %rdi
   f3222:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   f3227:      	leaq	0x270(%rsp), %r12
   f322f:      	movl	$0x20, %r8d
   f3235:      	xorl	%ecx, %ecx
   f3237:      	leaq	0x70(%rsp), %rdx
   f323c:      	movq	%r15, %rsi
   f323f:      	movq	%r12, %rdi
   f3242:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   f3247:      	movq	%r12, %rdi
   f324a:      	callq	0x23900 <_ZN8QProcess7executeERK7QString@plt>
   f324f:      	movq	0x270(%rsp), %rdi
   f3257:      	movl	(%rdi), %eax
   f3259:      	testl	%eax, %eax
   f325b:      	jne	0xf3530 <.text+0xced00>
   f3261:      	movl	$0x8, %edx
   f3266:      	movl	$0x2, %esi
   f326b:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f3270:      	movq	0x260(%rsp), %rdi
   f3278:      	movl	(%rdi), %eax
   f327a:      	testl	%eax, %eax
   f327c:      	jne	0xf3508 <.text+0xcecd8>
   f3282:      	movl	$0x8, %edx
   f3287:      	movl	$0x2, %esi
   f328c:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f3291:      	movq	0x2a0(%rsp), %rdi
   f3299:      	movl	(%rdi), %eax
   f329b:      	testl	%eax, %eax
   f329d:      	jne	0xf34e0 <.text+0xcecb0>
   f32a3:      	movl	$0x8, %edx
   f32a8:      	movl	$0x2, %esi
   f32ad:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f32b2:      	movl	$0x1, %edi
   f32b7:      	callq	0x24390 <sleep@plt>
   f32bc:      	movq	0xc0(%rsp), %rax
   f32c4:      	movl	(%rax), %ecx
   f32c6:      	movq	%rax, 0x2a0(%rsp)
   f32ce:      	leal	0x1(%rcx), %edx
   f32d1:      	cmpl	$0x1, %edx
   f32d4:      	jbe	0xf32dd <.text+0xceaad>
   f32d6:      	lock
   f32d7:      	addl	$0x1, (%rax)
   f32da:      	setne	%dl
   f32dd:      	movq	0x40(%r14), %rdi
   f32e1:      	movq	%rbp, %rsi
   f32e4:      	callq	0x97d20 <.text+0x734f0>
   f32e9:      	movq	0x2a0(%rsp), %rdi
   f32f1:      	movl	%eax, %r12d
   f32f4:      	movl	(%rdi), %edx
   f32f6:      	testl	%edx, %edx
   f32f8:      	jne	0xf35e0 <.text+0xcedb0>
   f32fe:      	movl	$0x8, %edx
   f3303:      	movl	$0x2, %esi
   f3308:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   f330d:      	movq	0x5e2ad4(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   f3314:      	testb	%r12b, %r12b
   f3317:      	jne	0xf3558 <.text+0xced28>
   f331d:      	testq	%rdi, %rdi
   f3320:      	je	0xf3ae0 <.text+0xcf2b0>
   f3326:      	leaq	0x135e3b(%rip), %rdx    # 0x229168
   f332d:      	movl	%r13d, %ecx
   f3330:      	xorl	%eax, %eax
   f3332:      	leaq	0x12ef67(%rip), %rsi    # 0x2222a0
   f3339:      	callq	0x137430 <.text+0x112c00>
   f333e:      	movl	$0x1, %r15d
   f3344:      	jmp	0xf2d7d <.text+0xce54d>
   f3349:      	nopl	(%rax)
   f3350:      	movq	0x50(%rsp), %rax
   f3355:      	movl	0x4(%rax), %esi
   f3358:      	movq	0x10(%rax), %rdi
   f335c:      	testl	%esi, %esi
   f335e:      	je	0xf336a <.text+0xceb3a>
   f3360:      	cmpq	$0x17, %rdi
   f3364:      	jbe	0xf3b87 <.text+0xcf357>
   f336a:      	addq	%rax, %rdi
   f336d:      	movl	$0x1, %r8d
   f3373:      	movl	$0xffffffff, %ecx       # imm = 0xFFFFFFFF
   f3378:      	leaq	0x122239(%rip), %rdx    # 0x2155b8
   f337f:      	callq	0x23630 <_ZN7QString14compare_helperEPK5QChariPKciN2Qt15CaseSensitivityE@plt>
   f3384:      	testl	%eax, %eax
   f3386:      	jne	0xf3608 <.text+0xcedd8>
   f338c:      	leaq	0x1216c5(%rip), %rdi    # 0x214a58
   f3393:      	movl	$0x1f, %esi
   f3398:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   f339d:      	leaq	0x2a0(%rsp), %rbp
   f33a5:      	movq	%rax, 0x2a0(%rsp)
   f33ad:      	leaq	0x160(%rsp), %r12
   f33b5:      	movq	%rbp, %rsi
   f33b8:      	movq	%r12, %rdi
   f33bb:      	callq	0x24320 <_ZN4QDirC1ERK7QString@plt>
   f33c0:      	movq	%r12, %rdi
   f33c3:      	callq	0x23aa0 <_ZNK4QDir6existsEv@plt>
   f33c8:      	movq	%r12, %rdi
   f33cb:      	movl	%eax, %r15d
   f33ce:      	callq	0x22580 <_ZN4QDirD1Ev@plt>
   f33d3:      	movq	%rbp, %rdi
   f33d6:      	callq	0x4b960 <.text+0x27130>
   f33db:      	testb	%r15b, %r15b
   f33de:      	jne	0xf34c8 <.text+0xcec98>
   f33e4:      	leaq	0x12166d(%rip), %rdi    # 0x214a58
   f33eb:      	movl	$0x1f, %esi
   f33f0:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   f33f5:      	leaq	0x170(%rsp), %r12
   f33fd:      	movq	%rbp, %rsi
   f3400:      	movq	%rax, 0x2a0(%rsp)
   f3408:      	movq	%r12, %rdi
   f340b:      	callq	0x55b20 <.text+0x312f0>
   f3410:      	movq	0x170(%rsp), %rdi
   f3418:      	callq	0x55ac0 <.text+0x31290>
   f341d:      	movq	%rax, %r15
   f3420:      	callq	0x55c60 <.text+0x31430>
   f3425:      	leaq	0x135d3c(%rip), %rdx    # 0x229168
   f342c:      	movq	%rax, %rdi
   f342f:      	movq	%r15, %rcx
   f3432:      	leaq	0x12bda3(%rip), %rsi    # 0x21f1dc
   f3439:      	xorl	%eax, %eax
   f343b:      	callq	0x137430 <.text+0x112c00>
   f3440:      	movq	%r12, %rdi
   f3443:      	callq	0x4b8e0 <.text+0x270b0>
   f3448:      	movq	%rbp, %rdi
   f344b:      	callq	0x4b960 <.text+0x27130>
   f3450:      	movl	$0x1f, %esi
   f3455:      	leaq	0x1215fc(%rip), %rdi    # 0x214a58
   f345c:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   f3461:      	movl	$0xb, %esi
   f3466:      	movq	%rax, 0x2a0(%rsp)
   f346e:      	leaq	0x122243(%rip), %rdi    # 0x2156b8
   f3475:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   f347a:      	leaq	0x180(%rsp), %r15
   f3482:      	xorl	%ecx, %ecx
   f3484:      	movq	%rbp, %rdx
   f3487:      	movq	%rax, 0x290(%rsp)
   f348f:      	leaq	0x290(%rsp), %r12
   f3497:      	movl	$0x20, %r8d
   f349d:      	movq	%r15, %rdi
   f34a0:      	movq	%r12, %rsi
   f34a3:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   f34a8:      	movq	%r15, %rdi
   f34ab:      	callq	0x23900 <_ZN8QProcess7executeERK7QString@plt>
   f34b0:      	movq	%r15, %rdi
   f34b3:      	callq	0x4b960 <.text+0x27130>
   f34b8:      	movq	%r12, %rdi
   f34bb:      	callq	0x4b960 <.text+0x27130>
   f34c0:      	movq	%rbp, %rdi
   f34c3:      	callq	0x4b960 <.text+0x27130>
   f34c8:      	leaq	0x70(%rsp), %rdi
   f34cd:      	leaq	0x121584(%rip), %rsi    # 0x214a58
   f34d4:      	callq	0x783e0 <.text+0x53bb0>
   f34d9:      	jmp	0xf31e9 <.text+0xce9b9>
   f34de:      	nop
   f34e0:      	cmpl	$-0x1, %eax
   f34e3:      	je	0xf32b2 <.text+0xcea82>
   f34e9:      	lock
   f34ea:      	subl	$0x1, (%rdi)
   f34ed:      	setne	%al
   f34f0:      	testb	%al, %al
   f34f2:      	jne	0xf32b2 <.text+0xcea82>
   f34f8:      	movq	0x2a0(%rsp), %rdi
   f3500:      	jmp	0xf32a3 <.text+0xcea73>
   f3505:      	nopl	(%rax)
   f3508:      	cmpl	$-0x1, %eax
   f350b:      	je	0xf3291 <.text+0xcea61>
   f3511:      	lock
   f3512:      	subl	$0x1, (%rdi)
   f3515:      	setne	%al
   f3518:      	testb	%al, %al
   f351a:      	jne	0xf3291 <.text+0xcea61>
   f3520:      	movq	0x260(%rsp), %rdi
   f3528:      	jmp	0xf3282 <.text+0xcea52>
   f352d:      	nopl	(%rax)
   f3530:      	cmpl	$-0x1, %eax
   f3533:      	je	0xf3270 <.text+0xcea40>
   f3539:      	lock
   f353a:      	subl	$0x1, (%rdi)
   f353d:      	setne	%al
   f3540:      	testb	%al, %al
   f3542:      	jne	0xf3270 <.text+0xcea40>
   f3548:      	movq	0x270(%rsp), %rdi
   f3550:      	jmp	0xf3261 <.text+0xcea31>
   f3555:      	nopl	(%rax)
   f3558:      	testq	%rdi, %rdi
   f355b:      	je	0xf3ab8 <.text+0xcf288>
   f3561:      	leaq	0x135c00(%rip), %rdx    # 0x229168
   f3568:      	xorl	%eax, %eax
   f356a:      	leaq	0x12bcba(%rip), %rsi    # 0x21f22b
   f3571:      	callq	0x137430 <.text+0x112c00>
   f3576:      	movq	0xc0(%rsp), %rax
   f357e:      	movl	(%rax), %ecx
   f3580:      	movq	%rax, 0x2a0(%rsp)
   f3588:      	leal	0x1(%rcx), %edx
   f358b:      	cmpl	$0x1, %edx
   f358e:      	jbe	0xf3597 <.text+0xced67>
   f3590:      	lock
   f3591:      	addl	$0x1, (%rax)
   f3594:      	setne	%dl
   f3597:      	movq	0x40(%r14), %rdi
   f359b:      	movq	%rbp, %rsi
   f359e:      	callq	0x9cbc0 <.text+0x78390>
   f35a3:      	movl	%eax, %r12d
   f35a6:      	movq	%rbp, %rdi
   f35a9:      	callq	0x4b960 <.text+0x27130>
   f35ae:      	testb	%r12b, %r12b

## Resource selector, fixed trees, encrypted enumeration, first verifier, and transform [0x9cbc0,0x9d650)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   9cbc0:      	pushq	%r15
   9cbc2:      	pushq	%r14
   9cbc4:      	pushq	%r13
   9cbc6:      	pushq	%r12
   9cbc8:      	pushq	%rbp
   9cbc9:      	pushq	%rbx
   9cbca:      	movq	%rsi, %rbx
   9cbcd:      	subq	$0x2a8, %rsp            # imm = 0x2A8
   9cbd4:      	movq	%fs:0x28, %rax
   9cbdd:      	movq	%rax, 0x298(%rsp)
   9cbe5:      	xorl	%eax, %eax
   9cbe7:      	callq	0x55c60 <.text+0x31430>
   9cbec:      	leaq	0x1789af(%rip), %rsi    # 0x2155a2
   9cbf3:      	leaq	0x178ec6(%rip), %rdx    # 0x215ac0
   9cbfa:      	movq	%rax, %rdi
   9cbfd:      	xorl	%eax, %eax
   9cbff:      	callq	0x137430 <.text+0x112c00>
   9cc04:      	leaq	0x637a95(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
   9cc0b:      	movq	%rbx, %rdi
   9cc0e:      	movq	%rax, 0x60(%rsp)
   9cc13:      	leaq	0x178993(%rip), %rsi    # 0x2155ad
   9cc1a:      	movq	%rax, 0x70(%rsp)
   9cc1f:      	leaq	0x60(%rsp), %rax
   9cc24:      	movq	%rax, 0x28(%rsp)
   9cc29:      	callq	0x7f830 <.text+0x5b000>
   9cc2e:      	testb	%al, %al
   9cc30:      	je	0x9ddab <.text+0x7957b>
   9cc36:      	leaq	0x60(%rsp), %rdi
   9cc3b:      	leaq	0x177dee(%rip), %rsi    # 0x214a30
   9cc42:      	movq	%rdi, 0x28(%rsp)
   9cc47:      	callq	0x783e0 <.text+0x53bb0>
   9cc4c:      	leaq	0x70(%rsp), %rdi
   9cc51:      	leaq	0x178248(%rip), %rsi    # 0x214ea0
   9cc58:      	callq	0x783e0 <.text+0x53bb0>
   9cc5d:      	movq	0x28(%rsp), %rsi
   9cc62:      	leaq	0x80(%rsp), %rax
   9cc6a:      	movq	%rax, %rdi
   9cc6d:      	movq	%rax, 0x50(%rsp)
   9cc72:      	callq	0x24320 <_ZN4QDirC1ERK7QString@plt>
   9cc77:      	movq	0x50(%rsp), %rsi
   9cc7c:      	leaq	0xd0(%rsp), %rax
   9cc84:      	movl	$0xffffffff, %ecx       # imm = 0xFFFFFFFF
   9cc89:      	movl	%ecx, %edx
   9cc8b:      	movq	%rax, %rdi
   9cc8e:      	movq	%rax, %rbx
   9cc91:      	movq	%rax, (%rsp)
   9cc95:      	callq	0x22420 <_ZNK4QDir13entryInfoListE6QFlagsINS_6FilterEES0_INS_8SortFlagEE@plt>
   9cc9a:      	leaq	0x250(%rsp), %rax
   9cca2:      	movq	%rbx, %rsi
   9cca5:      	movq	%rax, %rdi
   9cca8:      	movq	%rax, 0x58(%rsp)
   9ccad:      	callq	0x55e90 <.text+0x31660>
   9ccb2:      	movq	0x250(%rsp), %rax
   9ccba:      	movq	%rbx, %rdi
   9ccbd:      	movslq	0x8(%rax), %rcx
   9ccc1:      	leaq	0x10(%rax), %rdx
   9ccc5:      	movslq	0xc(%rax), %rax
   9ccc9:      	movl	$0x1, 0x268(%rsp)
   9ccd4:      	leaq	(%rdx,%rcx,8), %rcx
   9ccd8:      	leaq	(%rdx,%rax,8), %rax
   9ccdc:      	movq	%rcx, 0x258(%rsp)
   9cce4:      	movq	%rax, 0x260(%rsp)
   9ccec:      	callq	0x4ba50 <.text+0x27220>
   9ccf1:      	movl	0x268(%rsp), %ebx
   9ccf8:      	testl	%ebx, %ebx
   9ccfa:      	je	0x9dd35 <.text+0x79505>
   9cd00:      	movq	0x258(%rsp), %rax
   9cd08:      	xorl	%ebx, %ebx
   9cd0a:      	xorl	%r12d, %r12d
   9cd0d:      	cmpq	0x260(%rsp), %rax
   9cd15:      	je	0x9dd38 <.text+0x79508>
   9cd1b:      	movq	%rax, %rsi
   9cd1e:      	xorl	%r12d, %r12d
   9cd21:      	leaq	0x90(%rsp), %rax
   9cd29:      	movq	%rax, 0x20(%rsp)
   9cd2e:      	leaq	0x270(%rsp), %rax
   9cd36:      	movq	%rax, 0x40(%rsp)
   9cd3b:      	leaq	0xa0(%rsp), %rax
   9cd43:      	movq	%rax, 0x48(%rsp)
   9cd48:      	leaq	0xe0(%rsp), %rax
   9cd50:      	movq	%rax, 0x10(%rsp)
   9cd55:      	leaq	0xb0(%rsp), %r14
   9cd5d:      	movq	0x20(%rsp), %rdi
   9cd62:      	callq	0x245b0 <_ZN9QFileInfoC1ERKS_@plt>
   9cd67:      	movl	0x268(%rsp), %edx
   9cd6e:      	testl	%edx, %edx
   9cd70:      	je	0x9cd8b <.text+0x7855b>
   9cd72:      	movq	0x20(%rsp), %rdi
   9cd77:      	callq	0x230a0 <_ZNK9QFileInfo5isDirEv@plt>
   9cd7c:      	testb	%al, %al
   9cd7e:      	jne	0x9cdca <.text+0x7859a>
   9cd80:      	movl	$0x0, 0x268(%rsp)
   9cd8b:      	movq	0x20(%rsp), %rdi
   9cd90:      	callq	0x230e0 <_ZN9QFileInfoD1Ev@plt>
   9cd95:      	movq	0x258(%rsp), %rax
   9cd9d:      	addq	$0x8, %rax
   9cda1:      	xorl	$0x1, 0x268(%rsp)
   9cda9:      	movq	%rax, 0x258(%rsp)
   9cdb1:      	je	0x9de0c <.text+0x795dc>
   9cdb7:      	cmpq	%rax, 0x260(%rsp)
   9cdbf:      	je	0x9de0c <.text+0x795dc>
   9cdc5:      	movq	%rax, %rsi
   9cdc8:      	jmp	0x9cd5d <.text+0x7852d>
   9cdca:      	movq	0x40(%rsp), %rbx
   9cdcf:      	movq	0x20(%rsp), %rsi
   9cdd4:      	movq	%rbx, %rdi
   9cdd7:      	callq	0x22ed0 <_ZNK9QFileInfo16absoluteFilePathEv@plt>
   9cddc:      	movq	0x48(%rsp), %r15
   9cde1:      	movq	%rbx, %rsi
   9cde4:      	movq	%r15, %rdi
   9cde7:      	callq	0x24320 <_ZN4QDirC1ERK7QString@plt>
   9cdec:      	movq	%rbx, %rdi
   9cdef:      	callq	0x4b960 <.text+0x27130>
   9cdf4:      	movq	%r15, %rsi
   9cdf7:      	movq	0x10(%rsp), %r15
   9cdfc:      	movl	$0xffffffff, %ecx       # imm = 0xFFFFFFFF
   9ce01:      	movl	%ecx, %edx
   9ce03:      	movq	%r15, %rdi
   9ce06:      	callq	0x22420 <_ZNK4QDir13entryInfoListE6QFlagsINS_6FilterEES0_INS_8SortFlagEE@plt>
   9ce0b:      	movq	%r15, %rsi
   9ce0e:      	movq	%rbx, %rdi
   9ce11:      	callq	0x55e90 <.text+0x31660>
   9ce16:      	movq	0x270(%rsp), %rax
   9ce1e:      	movq	%r15, %rdi
   9ce21:      	movslq	0x8(%rax), %rcx
   9ce25:      	leaq	0x10(%rax), %rdx
   9ce29:      	movslq	0xc(%rax), %rax
   9ce2d:      	movl	$0x1, 0x288(%rsp)
   9ce38:      	leaq	(%rdx,%rcx,8), %rcx
   9ce3c:      	leaq	(%rdx,%rax,8), %rax
   9ce40:      	movq	%rcx, 0x278(%rsp)
   9ce48:      	movq	%rax, 0x280(%rsp)
   9ce50:      	callq	0x4ba50 <.text+0x27220>
   9ce55:      	movl	0x288(%rsp), %r11d
   9ce5d:      	testl	%r11d, %r11d
   9ce60:      	je	0x9cf50 <.text+0x78720>
   9ce66:      	movq	0x278(%rsp), %rsi
   9ce6e:      	cmpq	0x280(%rsp), %rsi
   9ce76:      	je	0x9cf50 <.text+0x78720>
   9ce7c:      	leaq	0xf0(%rsp), %rax
   9ce84:      	movq	%rax, 0x18(%rsp)
   9ce89:      	leaq	0x220(%rsp), %rax
   9ce91:      	leaq	0xc0(%rsp), %r15
   9ce99:      	movq	%rax, 0x30(%rsp)
   9ce9e:      	leaq	0x240(%rsp), %rbx
   9cea6:      	movq	%r14, %rdi
   9cea9:      	callq	0x245b0 <_ZN9QFileInfoC1ERKS_@plt>
   9ceae:      	movl	0x288(%rsp), %eax
   9ceb5:      	testl	%eax, %eax
   9ceb7:      	je	0x9cf14 <.text+0x786e4>
   9ceb9:      	movq	%r14, %rsi
   9cebc:      	movq	%r15, %rdi
   9cebf:      	callq	0x222f0 <_ZNK9QFileInfo6suffixEv@plt>
   9cec4:      	movq	0xc0(%rsp), %rax
   9cecc:      	movl	0x4(%rax), %esi
   9cecf:      	movq	0x10(%rax), %rdi
   9ced3:      	testl	%esi, %esi
   9ced5:      	je	0x9cee1 <.text+0x786b1>
   9ced7:      	cmpq	$0x17, %rdi
   9cedb:      	jbe	0x9ddf4 <.text+0x795c4>
   9cee1:      	addq	%rax, %rdi
   9cee4:      	movl	$0x1, %r8d
   9ceea:      	movl	$0xffffffff, %ecx       # imm = 0xFFFFFFFF
   9ceef:      	leaq	0x183c3b(%rip), %rdx    # 0x220b31
   9cef6:      	callq	0x23630 <_ZN7QString14compare_helperEPK5QChariPKciN2Qt15CaseSensitivityE@plt>
   9cefb:      	movl	%eax, %ebp
   9cefd:      	movq	%r15, %rdi
   9cf00:      	callq	0x4b960 <.text+0x27130>
   9cf05:      	testl	%ebp, %ebp
   9cf07:      	je	0x9cf70 <.text+0x78740>
   9cf09:      	movl	$0x0, 0x288(%rsp)
   9cf14:      	movq	%r14, %rdi
   9cf17:      	callq	0x230e0 <_ZN9QFileInfoD1Ev@plt>
   9cf1c:      	movq	0x278(%rsp), %rax
   9cf24:      	xorl	$0x1, 0x288(%rsp)
   9cf2c:      	leaq	0x8(%rax), %rsi
   9cf30:      	movq	%rsi, 0x278(%rsp)
   9cf38:      	je	0x9cf50 <.text+0x78720>
   9cf3a:      	cmpq	%rsi, 0x280(%rsp)
   9cf42:      	jne	0x9cea6 <.text+0x78676>
   9cf48:      	nopl	(%rax,%rax)
   9cf50:      	movq	0x40(%rsp), %rdi
   9cf55:      	callq	0x4ba50 <.text+0x27220>
   9cf5a:      	movq	0x48(%rsp), %rdi
   9cf5f:      	callq	0x22580 <_ZN4QDirD1Ev@plt>
   9cf64:      	jmp	0x9cd80 <.text+0x78550>
   9cf69:      	nopl	(%rax)
   9cf70:      	movq	(%rsp), %rdi
   9cf74:      	movq	%r14, %rsi
   9cf77:      	callq	0x22ed0 <_ZNK9QFileInfo16absoluteFilePathEv@plt>
   9cf7c:      	leaq	0x3cbd59(%rip), %rdi    # 0x468cdc
   9cf83:      	xorl	%esi, %esi
   9cf85:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   9cf8a:      	movl	$0xb, %esi
   9cf8f:      	movq	%rax, 0xe0(%rsp)
   9cf97:      	leaq	0x1788a2(%rip), %rdi    # 0x215840
   9cf9e:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   9cfa3:      	movq	0x18(%rsp), %r13
   9cfa8:      	movq	%r14, %rsi
   9cfab:      	movq	%rax, 0x240(%rsp)
   9cfb3:      	movq	%r13, %rdi
   9cfb6:      	callq	0x22e00 <_ZNK9QFileInfo8baseNameEv@plt>
   9cfbb:      	movl	$0x1, %ecx
   9cfc0:      	xorl	%edx, %edx
   9cfc2:      	movq	%rbx, %rsi
   9cfc5:      	movq	%r13, %rdi
   9cfc8:      	movq	%rbx, %rbp
   9cfcb:      	callq	0x22210 <_ZNK7QString7indexOfERKS_iN2Qt15CaseSensitivityE@plt>
   9cfd0:      	movq	%r13, %rdi
   9cfd3:      	movl	%eax, %ebp
   9cfd5:      	callq	0x4b960 <.text+0x27130>
   9cfda:      	movq	%rbx, %rdi
   9cfdd:      	callq	0x4b960 <.text+0x27130>
   9cfe2:      	cmpl	$-0x1, %ebp
   9cfe5:      	je	0x9d7c0 <.text+0x78f90>
   9cfeb:      	leaq	0x182fe4(%rip), %rdi    # 0x21ffd6
   9cff2:      	movl	$0x1, %esi
   9cff7:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   9cffc:      	movq	0x20(%rsp), %r13
   9d001:      	leaq	0x100(%rsp), %rbp
   9d009:      	movq	%rax, 0x240(%rsp)
   9d011:      	movq	%rbp, %rdi
   9d014:      	movq	%r13, %rsi
   9d017:      	callq	0x22e00 <_ZNK9QFileInfo8baseNameEv@plt>
   9d01c:      	movl	$0x1, %ecx
   9d021:      	xorl	%edx, %edx
   9d023:      	movq	%rbx, %rsi
   9d026:      	movq	%rbp, %rdi
   9d029:      	callq	0x22210 <_ZNK7QString7indexOfERKS_iN2Qt15CaseSensitivityE@plt>
   9d02e:      	movq	%rbp, %rdi
   9d031:      	movl	%eax, %r12d
   9d034:      	callq	0x4b960 <.text+0x27130>
   9d039:      	movq	%rbx, %rdi
   9d03c:      	callq	0x4b960 <.text+0x27130>
   9d041:      	cmpl	$-0x1, %r12d
   9d045:      	je	0x9da98 <.text+0x79268>
   9d04b:      	leaq	0x182f84(%rip), %rdi    # 0x21ffd6
   9d052:      	movl	$0x1, %esi
   9d057:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   9d05c:      	leaq	0x110(%rsp), %r12
   9d064:      	movq	%r13, %rsi
   9d067:      	movq	%rax, 0x240(%rsp)
   9d06f:      	movq	%r12, %rdi
   9d072:      	callq	0x22e00 <_ZNK9QFileInfo8baseNameEv@plt>
   9d077:      	leaq	0x230(%rsp), %rbp
   9d07f:      	movl	$0x1, %r8d
   9d085:      	xorl	%ecx, %ecx
   9d087:      	movq	%rbx, %rdx
   9d08a:      	movq	%r12, %rsi
   9d08d:      	movq	%rbp, %rdi
   9d090:      	callq	0x23480 <_ZNK7QString5splitERKS_NS_13SplitBehaviorEN2Qt15CaseSensitivityE@plt>
   9d095:      	movq	%r12, %rdi
   9d098:      	callq	0x4b960 <.text+0x27130>
   9d09d:      	movq	%rbx, %rdi
   9d0a0:      	callq	0x4b960 <.text+0x27130>
   9d0a5:      	movq	0x230(%rsp), %rax
   9d0ad:      	movslq	0x8(%rax), %rdx
   9d0b1:      	movl	0xc(%rax), %ecx
   9d0b4:      	subl	%edx, %ecx
   9d0b6:      	cmpl	$0x1, %ecx
   9d0b9:      	jle	0x9de5e <.text+0x7962e>
   9d0bf:      	cmpl	$0x1, (%rax)
   9d0c2:      	jbe	0x9d0db <.text+0x788ab>
   9d0c4:      	movl	0x4(%rax), %esi
   9d0c7:      	movq	%rbp, %rdi
   9d0ca:      	callq	0x4c130 <.text+0x27900>
   9d0cf:      	movq	0x230(%rsp), %rax
   9d0d7:      	movslq	0x8(%rax), %rdx
   9d0db:      	leaq	0x120(%rsp), %r12
   9d0e3:      	movq	%r14, %rsi
   9d0e6:      	leaq	0x18(%rax,%rdx,8), %rax
   9d0eb:      	movq	%r12, %rdi
   9d0ee:      	movq	%rax, 0x8(%rsp)
   9d0f3:      	callq	0x24190 <_ZNK9QFileInfo12absolutePathEv@plt>
   9d0f8:      	leaq	0x17874d(%rip), %rdi    # 0x21584c
   9d0ff:      	movl	$0x14, %esi
   9d104:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   9d109:      	xorl	%ecx, %ecx
   9d10b:      	movq	%r12, %rdx
   9d10e:      	movq	%rbx, %rsi
   9d111:      	movq	%rax, 0x240(%rsp)
   9d119:      	leaq	0x130(%rsp), %r13
   9d121:      	movl	$0x20, %r8d
   9d127:      	movq	%r13, %rdi
   9d12a:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   9d12f:      	movq	0x8(%rsp), %rdx
   9d134:      	movl	$0x20, %r8d
   9d13a:      	xorl	%ecx, %ecx
   9d13c:      	movq	%r13, %rsi
   9d13f:      	leaq	0x140(%rsp), %rax
   9d147:      	movq	%rax, %rdi
   9d14a:      	movq	%rax, 0x8(%rsp)
   9d14f:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   9d154:      	movq	0xe0(%rsp), %rax
   9d15c:      	movq	0x140(%rsp), %rdx
   9d164:      	movq	0x8(%rsp), %rdi
   9d169:      	movq	%rax, 0x140(%rsp)
   9d171:      	movq	%rdx, 0xe0(%rsp)
   9d179:      	callq	0x4b960 <.text+0x27130>
   9d17e:      	movq	%r13, %rdi
   9d181:      	callq	0x4b960 <.text+0x27130>
   9d186:      	movq	%rbx, %rdi
   9d189:      	callq	0x4b960 <.text+0x27130>
   9d18e:      	movq	%r12, %rdi
   9d191:      	callq	0x4b960 <.text+0x27130>
   9d196:      	movq	%rbp, %rdi
   9d199:      	callq	0x55ce0 <.text+0x314b0>
   9d19e:      	movq	0xd0(%rsp), %rax
   9d1a6:      	movl	(%rax), %ecx
   9d1a8:      	movq	%rax, 0x240(%rsp)
   9d1b0:      	leal	0x1(%rcx), %edx
   9d1b3:      	cmpl	$0x1, %edx
   9d1b6:      	jbe	0x9d1bf <.text+0x7898f>
   9d1b8:      	lock
   9d1b9:      	addl	$0x1, (%rax)
   9d1bc:      	setne	%dl
   9d1bf:      	movq	0x6376c2(%rip), %rdi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
   9d1c6:      	testq	%rdi, %rdi
   9d1c9:      	je	0x9dbb8 <.text+0x79388>
   9d1cf:      	movq	%rbx, %rsi
   9d1d2:      	callq	0x45820 <.text+0x20ff0>
   9d1d7:      	movq	0x240(%rsp), %rdi
   9d1df:      	movl	%eax, %r12d
   9d1e2:      	movl	(%rdi), %eax
   9d1e4:      	testl	%eax, %eax
   9d1e6:      	jne	0x9d798 <.text+0x78f68>
   9d1ec:      	movl	$0x8, %edx
   9d1f1:      	movl	$0x2, %esi
   9d1f6:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   9d1fb:      	movq	0x638be6(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9d202:      	testq	%rdi, %rdi
   9d205:      	je	0x9dbe0 <.text+0x793b0>
   9d20b:      	leaq	0x1788ae(%rip), %rdx    # 0x215ac0
   9d212:      	movl	%r12d, %ecx
   9d215:      	xorl	%eax, %eax
   9d217:      	leaq	0x177d52(%rip), %rsi    # 0x214f70
   9d21e:      	callq	0x137430 <.text+0x112c00>
   9d223:      	movq	0xd0(%rsp), %rsi
   9d22b:      	testl	%r12d, %r12d
   9d22e:      	jne	0x9d670 <.text+0x78e40>
   9d234:      	movl	(%rsi), %eax
   9d236:      	movq	%rsi, 0x180(%rsp)
   9d23e:      	addl	$0x1, %eax
   9d241:      	cmpl	$0x1, %eax
   9d244:      	jbe	0x9d255 <.text+0x78a25>
   9d246:      	lock
   9d247:      	addl	$0x1, (%rsi)
   9d24a:      	setne	%al
   9d24d:      	movq	0x180(%rsp), %rsi
   9d255:      	movl	0x4(%rsi), %edx
   9d258:      	movq	0x10(%rsi), %rax
   9d25c:      	testl	%edx, %edx
   9d25e:      	je	0x9d26a <.text+0x78a3a>
   9d260:      	cmpq	$0x17, %rax
   9d264:      	jbe	0x9ddf4 <.text+0x795c4>
   9d26a:      	leaq	0x190(%rsp), %r13
   9d272:      	addq	%rax, %rsi
   9d275:      	movq	%r13, %rdi
   9d278:      	callq	0x22470 <_ZN7QString18toLocal8Bit_helperEPK5QChari@plt>
   9d27d:      	movq	0x190(%rsp), %rax
   9d285:      	movl	0x4(%rax), %r10d
   9d289:      	movq	0x10(%rax), %rbp
   9d28d:      	testl	%r10d, %r10d
   9d290:      	je	0x9d29c <.text+0x78a6c>
   9d292:      	cmpq	$0x17, %rbp
   9d296:      	jbe	0x9ddf4 <.text+0x795c4>
   9d29c:      	movq	0x638b45(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9d2a3:      	addq	%rax, %rbp
   9d2a6:      	testq	%rdi, %rdi
   9d2a9:      	je	0x9dc40 <.text+0x79410>
   9d2af:      	leaq	0x17880a(%rip), %rdx    # 0x215ac0
   9d2b6:      	movq	%rbp, %rcx
   9d2b9:      	xorl	%eax, %eax
   9d2bb:      	leaq	0x1785c6(%rip), %rsi    # 0x215888
   9d2c2:      	callq	0x137430 <.text+0x112c00>
   9d2c7:      	movq	0x190(%rsp), %rdi
   9d2cf:      	movl	(%rdi), %eax
   9d2d1:      	testl	%eax, %eax
   9d2d3:      	jne	0x9d9a8 <.text+0x79178>
   9d2d9:      	movl	$0x8, %edx
   9d2de:      	movl	$0x1, %esi
   9d2e3:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   9d2e8:      	movq	0x180(%rsp), %rdi
   9d2f0:      	movl	(%rdi), %eax
   9d2f2:      	testl	%eax, %eax
   9d2f4:      	jne	0x9d980 <.text+0x79150>
   9d2fa:      	movl	$0x8, %edx
   9d2ff:      	movl	$0x2, %esi
   9d304:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   9d309:      	movq	0xe0(%rsp), %rsi
   9d311:      	movl	(%rsi), %eax
   9d313:      	movq	%rsi, 0x1c0(%rsp)
   9d31b:      	addl	$0x1, %eax
   9d31e:      	cmpl	$0x1, %eax
   9d321:      	jbe	0x9d332 <.text+0x78b02>
   9d323:      	lock
   9d324:      	addl	$0x1, (%rsi)
   9d327:      	setne	%al
   9d32a:      	movq	0x1c0(%rsp), %rsi
   9d332:      	movl	0x4(%rsi), %edx
   9d335:      	movq	0x10(%rsi), %rax
   9d339:      	testl	%edx, %edx
   9d33b:      	je	0x9d347 <.text+0x78b17>
   9d33d:      	cmpq	$0x17, %rax
   9d341:      	jbe	0x9ddf4 <.text+0x795c4>
   9d347:      	leaq	0x1d0(%rsp), %r13
   9d34f:      	addq	%rax, %rsi
   9d352:      	movq	%r13, %rdi
   9d355:      	callq	0x22470 <_ZN7QString18toLocal8Bit_helperEPK5QChari@plt>
   9d35a:      	movq	0x1d0(%rsp), %rax
   9d362:      	movl	0x4(%rax), %r9d
   9d366:      	movq	0x10(%rax), %r12
   9d36a:      	testl	%r9d, %r9d
   9d36d:      	je	0x9d379 <.text+0x78b49>
   9d36f:      	cmpq	$0x17, %r12
   9d373:      	jbe	0x9ddf4 <.text+0x795c4>
   9d379:      	movq	0xd0(%rsp), %rsi
   9d381:      	addq	%r12, %rax
   9d384:      	movq	%rax, 0x8(%rsp)
   9d389:      	movl	(%rsi), %eax
   9d38b:      	movq	%rsi, 0x1a0(%rsp)
   9d393:      	addl	$0x1, %eax
   9d396:      	cmpl	$0x1, %eax
   9d399:      	jbe	0x9d3aa <.text+0x78b7a>
   9d39b:      	lock
   9d39c:      	addl	$0x1, (%rsi)
   9d39f:      	setne	%al
   9d3a2:      	movq	0x1a0(%rsp), %rsi
   9d3aa:      	movl	0x4(%rsi), %edx
   9d3ad:      	movq	0x10(%rsi), %rax
   9d3b1:      	testl	%edx, %edx
   9d3b3:      	je	0x9d3bf <.text+0x78b8f>
   9d3b5:      	cmpq	$0x17, %rax
   9d3b9:      	jbe	0x9ddf4 <.text+0x795c4>
   9d3bf:      	leaq	0x1b0(%rsp), %r12
   9d3c7:      	addq	%rax, %rsi
   9d3ca:      	movq	%r12, %rdi
   9d3cd:      	callq	0x22470 <_ZN7QString18toLocal8Bit_helperEPK5QChari@plt>
   9d3d2:      	movq	0x1b0(%rsp), %rax
   9d3da:      	movl	0x4(%rax), %r8d
   9d3de:      	movq	0x10(%rax), %rbp
   9d3e2:      	testl	%r8d, %r8d
   9d3e5:      	je	0x9d3f1 <.text+0x78bc1>
   9d3e7:      	cmpq	$0x17, %rbp
   9d3eb:      	jbe	0x9ddf4 <.text+0x795c4>
   9d3f1:      	movq	0x6389f0(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9d3f8:      	addq	%rax, %rbp
   9d3fb:      	testq	%rdi, %rdi
   9d3fe:      	je	0x9dc90 <.text+0x79460>
   9d404:      	movq	0x8(%rsp), %r8
   9d409:      	movq	%rbp, %rcx
   9d40c:      	xorl	%eax, %eax
   9d40e:      	leaq	0x1786ab(%rip), %rdx    # 0x215ac0
   9d415:      	leaq	0x177b7c(%rip), %rsi    # 0x214f98
   9d41c:      	callq	0x137430 <.text+0x112c00>
   9d421:      	movq	0x1b0(%rsp), %rdi
   9d429:      	movl	(%rdi), %eax
   9d42b:      	testl	%eax, %eax
   9d42d:      	jne	0x9d958 <.text+0x79128>
   9d433:      	movl	$0x8, %edx
   9d438:      	movl	$0x1, %esi
   9d43d:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   9d442:      	leaq	0x1a0(%rsp), %rdi
   9d44a:      	callq	0x4b960 <.text+0x27130>
   9d44f:      	movq	0x1d0(%rsp), %rdi
   9d457:      	movl	(%rdi), %eax
   9d459:      	testl	%eax, %eax
   9d45b:      	jne	0x9d930 <.text+0x79100>
   9d461:      	movl	$0x8, %edx
   9d466:      	movl	$0x1, %esi
   9d46b:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   9d470:      	leaq	0x1c0(%rsp), %rdi
   9d478:      	callq	0x4b960 <.text+0x27130>
   9d47d:      	leaq	0x3cb858(%rip), %rdi    # 0x468cdc
   9d484:      	xorl	%esi, %esi
   9d486:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   9d48b:      	movq	%rax, 0x1e0(%rsp)
   9d493:      	movq	0xe0(%rsp), %rax
   9d49b:      	movl	(%rax), %ecx
   9d49d:      	movq	%rax, 0x240(%rsp)
   9d4a5:      	leal	0x1(%rcx), %edx
   9d4a8:      	cmpl	$0x1, %edx
   9d4ab:      	jbe	0x9d4b4 <.text+0x78c84>
   9d4ad:      	lock
   9d4ae:      	addl	$0x1, (%rax)
   9d4b1:      	setne	%dl
   9d4b4:      	movq	0xd0(%rsp), %rax
   9d4bc:      	movl	(%rax), %ecx
   9d4be:      	movq	%rax, 0x230(%rsp)
   9d4c6:      	leal	0x1(%rcx), %edx
   9d4c9:      	cmpl	$0x1, %edx
   9d4cc:      	jbe	0x9d4d5 <.text+0x78ca5>
   9d4ce:      	lock
   9d4cf:      	addl	$0x1, (%rax)
   9d4d2:      	setne	%dl
   9d4d5:      	leaq	0x230(%rsp), %rbp
   9d4dd:      	callq	0x66460 <.text+0x41c30>
   9d4e2:      	leaq	0x1f0(%rsp), %r12
   9d4ea:      	movq	%rbx, %rcx
   9d4ed:      	movq	%rax, %rsi
   9d4f0:      	leaq	0x230(%rsp), %rbp
   9d4f8:      	movq	%r12, %rdi
   9d4fb:      	movq	%rbp, %rdx
   9d4fe:      	callq	0x140030 <.text+0x11b800>
   9d503:      	movq	0x1e0(%rsp), %rax
   9d50b:      	movq	%r12, %rdi
   9d50e:      	movq	0x1f0(%rsp), %rdx
   9d516:      	movq	%rax, 0x1f0(%rsp)
   9d51e:      	movq	%rdx, 0x1e0(%rsp)
   9d526:      	callq	0x4b960 <.text+0x27130>
   9d52b:      	movq	%rbp, %rdi
   9d52e:      	callq	0x4b960 <.text+0x27130>
   9d533:      	movq	%rbx, %rdi
   9d536:      	callq	0x4b960 <.text+0x27130>
   9d53b:      	movq	0x1e0(%rsp), %rax
   9d543:      	movl	0x4(%rax), %esi
   9d546:      	movq	0x10(%rax), %rdi
   9d54a:      	testl	%esi, %esi
   9d54c:      	je	0x9d558 <.text+0x78d28>
   9d54e:      	cmpq	$0x17, %rdi
   9d552:      	jbe	0x9ddf4 <.text+0x795c4>
   9d558:      	addq	%rax, %rdi
   9d55b:      	movl	$0x1, %r8d
   9d561:      	movl	$0xffffffff, %ecx       # imm = 0xFFFFFFFF
   9d566:      	leaq	0x3cb76f(%rip), %rdx    # 0x468cdc
   9d56d:      	callq	0x23630 <_ZN7QString14compare_helperEPK5QChariPKciN2Qt15CaseSensitivityE@plt>
   9d572:      	movq	0xe0(%rsp), %rsi
   9d57a:      	testl	%eax, %eax
   9d57c:      	je	0x9d9d0 <.text+0x791a0>
   9d582:      	movl	(%rsi), %eax
   9d584:      	movq	%rsi, 0x1f0(%rsp)
   9d58c:      	addl	$0x1, %eax
   9d58f:      	cmpl	$0x1, %eax
   9d592:      	jbe	0x9d5a3 <.text+0x78d73>
   9d594:      	lock
   9d595:      	addl	$0x1, (%rsi)
   9d598:      	setne	%al
   9d59b:      	movq	0x1f0(%rsp), %rsi
   9d5a3:      	movl	0x4(%rsi), %edx
   9d5a6:      	movq	0x10(%rsi), %rax
   9d5aa:      	testl	%edx, %edx
   9d5ac:      	je	0x9d5b8 <.text+0x78d88>
   9d5ae:      	cmpq	$0x17, %rax
   9d5b2:      	jbe	0x9ddf4 <.text+0x795c4>
   9d5b8:      	leaq	0x200(%rsp), %r13
   9d5c0:      	addq	%rax, %rsi
   9d5c3:      	movq	%r13, %rdi
   9d5c6:      	callq	0x22470 <_ZN7QString18toLocal8Bit_helperEPK5QChari@plt>
   9d5cb:      	movq	0x200(%rsp), %rax
   9d5d3:      	movl	0x4(%rax), %edi
   9d5d6:      	movq	0x10(%rax), %rbp
   9d5da:      	testl	%edi, %edi
   9d5dc:      	je	0x9d5e8 <.text+0x78db8>
   9d5de:      	cmpq	$0x17, %rbp
   9d5e2:      	jbe	0x9ddf4 <.text+0x795c4>
   9d5e8:      	movq	0x6387f9(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9d5ef:      	addq	%rax, %rbp
   9d5f2:      	testq	%rdi, %rdi
   9d5f5:      	je	0x9dcbb <.text+0x7948b>
   9d5fb:      	leaq	0x1784be(%rip), %rdx    # 0x215ac0
   9d602:      	movq	%rbp, %rcx
   9d605:      	xorl	%eax, %eax
   9d607:      	leaq	0x178298(%rip), %rsi    # 0x2158a6
   9d60e:      	callq	0x137430 <.text+0x112c00>
   9d613:      	movq	0x200(%rsp), %rdi
   9d61b:      	movl	(%rdi), %eax
   9d61d:      	testl	%eax, %eax
   9d61f:      	jne	0x9db68 <.text+0x79338>
   9d625:      	movl	$0x8, %edx
   9d62a:      	movl	$0x1, %esi
   9d62f:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   9d634:      	movq	%r12, %rdi
   9d637:      	movl	$0x1, %r12d
   9d63d:      	callq	0x4b960 <.text+0x27130>
   9d642:      	leaq	0x1e0(%rsp), %rdi
   9d64a:      	callq	0x4b960 <.text+0x27130>
   9d64f:      	movq	0x10(%rsp), %rdi

## Alternate destination construction and fixed producer classes [0x9d7c0,0x9dec5)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
   9d7c0:      	leaq	0x1780ac(%rip), %rdi    # 0x215873
   9d7c7:      	movl	$0xa, %esi
   9d7cc:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   9d7d1:      	leaq	0x170(%rsp), %rbp
   9d7d9:      	movq	%r14, %rsi
   9d7dc:      	movq	%rax, 0x240(%rsp)
   9d7e4:      	movq	%rbp, %rdi
   9d7e7:      	callq	0x22e00 <_ZNK9QFileInfo8baseNameEv@plt>
   9d7ec:      	movl	$0x1, %ecx
   9d7f1:      	xorl	%edx, %edx
   9d7f3:      	movq	%rbx, %rsi
   9d7f6:      	movq	%rbp, %rdi
   9d7f9:      	callq	0x22210 <_ZNK7QString7indexOfERKS_iN2Qt15CaseSensitivityE@plt>
   9d7fe:      	movq	%rbp, %rdi
   9d801:      	movl	%eax, %r13d
   9d804:      	callq	0x4b960 <.text+0x27130>
   9d809:      	movq	%rbx, %rdi
   9d80c:      	callq	0x4b960 <.text+0x27130>
   9d811:      	cmpl	$-0x1, %r13d
   9d815:      	je	0x9dc08 <.text+0x793d8>
   9d81b:      	leaq	0x1c0(%rsp), %r13
   9d823:      	movq	%r14, %rsi
   9d826:      	movq	%r13, %rdi
   9d829:      	callq	0x22e00 <_ZNK9QFileInfo8baseNameEv@plt>
   9d82e:      	leaq	0x180(%rsp), %rbp
   9d836:      	movq	%r14, %rsi
   9d839:      	movq	%rbp, %rdi
   9d83c:      	callq	0x24190 <_ZNK9QFileInfo12absolutePathEv@plt>
   9d841:      	leaq	0x178036(%rip), %rdi    # 0x21587e
   9d848:      	movl	$0x9, %esi
   9d84d:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   9d852:      	xorl	%ecx, %ecx
   9d854:      	movq	%rbp, %rdx
   9d857:      	movq	%rbx, %rsi
   9d85a:      	movq	%rax, 0x240(%rsp)
   9d862:      	leaq	0x1a0(%rsp), %r12
   9d86a:      	movl	$0x20, %r8d
   9d870:      	movq	%r12, %rdi
   9d873:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   9d878:      	leaq	0x1e0(%rsp), %rax
   9d880:      	movl	$0x20, %r8d
   9d886:      	xorl	%ecx, %ecx
   9d888:      	movq	%r13, %rdx
   9d88b:      	movq	%r12, %rsi
   9d88e:      	movq	%rax, %rdi
   9d891:      	movq	%rax, 0x8(%rsp)
   9d896:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   9d89b:      	movq	0xe0(%rsp), %rax
   9d8a3:      	movq	0x1e0(%rsp), %rdx
   9d8ab:      	movq	0x8(%rsp), %rdi
   9d8b0:      	movq	%rax, 0x1e0(%rsp)
   9d8b8:      	movq	%rdx, 0xe0(%rsp)
   9d8c0:      	callq	0x4b960 <.text+0x27130>
   9d8c5:      	movq	%r12, %rdi
   9d8c8:      	callq	0x4b960 <.text+0x27130>
   9d8cd:      	movq	%rbx, %rdi
   9d8d0:      	callq	0x4b960 <.text+0x27130>
   9d8d5:      	movq	%rbp, %rdi
   9d8d8:      	callq	0x4b960 <.text+0x27130>
   9d8dd:      	movq	0x1c0(%rsp), %rdi
   9d8e5:      	movl	(%rdi), %eax
   9d8e7:      	testl	%eax, %eax
   9d8e9:      	jne	0x9db90 <.text+0x79360>
   9d8ef:      	movl	$0x8, %edx
   9d8f4:      	movl	$0x2, %esi
   9d8f9:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   9d8fe:      	jmp	0x9d19e <.text+0x7896e>
   9d903:      	nopl	(%rax,%rax)
   9d908:      	cmpl	$-0x1, %eax
   9d90b:      	je	0x9d71c <.text+0x78eec>
   9d911:      	lock
   9d912:      	subl	$0x1, (%rdi)
   9d915:      	setne	%al
   9d918:      	testb	%al, %al
   9d91a:      	jne	0x9d71c <.text+0x78eec>
   9d920:      	movq	0x220(%rsp), %rdi
   9d928:      	jmp	0x9d70d <.text+0x78edd>
   9d92d:      	nopl	(%rax)
   9d930:      	cmpl	$-0x1, %eax
   9d933:      	je	0x9d470 <.text+0x78c40>
   9d939:      	lock
   9d93a:      	subl	$0x1, (%rdi)
   9d93d:      	setne	%al
   9d940:      	testb	%al, %al
   9d942:      	jne	0x9d470 <.text+0x78c40>
   9d948:      	movq	0x1d0(%rsp), %rdi
   9d950:      	jmp	0x9d461 <.text+0x78c31>
   9d955:      	nopl	(%rax)
   9d958:      	cmpl	$-0x1, %eax
   9d95b:      	je	0x9d442 <.text+0x78c12>
   9d961:      	lock
   9d962:      	subl	$0x1, (%rdi)
   9d965:      	setne	%al
   9d968:      	testb	%al, %al
   9d96a:      	jne	0x9d442 <.text+0x78c12>
   9d970:      	movq	0x1b0(%rsp), %rdi
   9d978:      	jmp	0x9d433 <.text+0x78c03>
   9d97d:      	nopl	(%rax)
   9d980:      	cmpl	$-0x1, %eax
   9d983:      	je	0x9d309 <.text+0x78ad9>
   9d989:      	lock
   9d98a:      	subl	$0x1, (%rdi)
   9d98d:      	setne	%al
   9d990:      	testb	%al, %al
   9d992:      	jne	0x9d309 <.text+0x78ad9>
   9d998:      	movq	0x180(%rsp), %rdi
   9d9a0:      	jmp	0x9d2fa <.text+0x78aca>
   9d9a5:      	nopl	(%rax)
   9d9a8:      	cmpl	$-0x1, %eax
   9d9ab:      	je	0x9d2e8 <.text+0x78ab8>
   9d9b1:      	lock
   9d9b2:      	subl	$0x1, (%rdi)
   9d9b5:      	setne	%al
   9d9b8:      	testb	%al, %al
   9d9ba:      	jne	0x9d2e8 <.text+0x78ab8>
   9d9c0:      	movq	0x190(%rsp), %rdi
   9d9c8:      	jmp	0x9d2d9 <.text+0x78aa9>
   9d9cd:      	nopl	(%rax)
   9d9d0:      	movl	(%rsi), %eax
   9d9d2:      	movq	%rsi, 0x230(%rsp)
   9d9da:      	addl	$0x1, %eax
   9d9dd:      	cmpl	$0x1, %eax
   9d9e0:      	jbe	0x9d9f1 <.text+0x791c1>
   9d9e2:      	lock
   9d9e3:      	addl	$0x1, (%rsi)
   9d9e6:      	setne	%al
   9d9e9:      	movq	0x230(%rsp), %rsi
   9d9f1:      	movl	0x4(%rsi), %edx
   9d9f4:      	movq	0x10(%rsi), %rax
   9d9f8:      	testl	%edx, %edx
   9d9fa:      	je	0x9da06 <.text+0x791d6>
   9d9fc:      	cmpq	$0x17, %rax
   9da00:      	jbe	0x9ddf4 <.text+0x795c4>
   9da06:      	leaq	0x210(%rsp), %r13
   9da0e:      	addq	%rax, %rsi
   9da11:      	movq	%r13, %rdi
   9da14:      	callq	0x22470 <_ZN7QString18toLocal8Bit_helperEPK5QChari@plt>
   9da19:      	movq	0x210(%rsp), %rax
   9da21:      	movl	0x4(%rax), %esi
   9da24:      	movq	0x10(%rax), %r12
   9da28:      	testl	%esi, %esi
   9da2a:      	je	0x9da36 <.text+0x79206>
   9da2c:      	cmpq	$0x17, %r12
   9da30:      	jbe	0x9ddf4 <.text+0x795c4>
   9da36:      	movq	0x6383ab(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9da3d:      	addq	%rax, %r12
   9da40:      	testq	%rdi, %rdi
   9da43:      	je	0x9dce6 <.text+0x794b6>
   9da49:      	leaq	0x178070(%rip), %rdx    # 0x215ac0
   9da50:      	movq	%r12, %rcx
   9da53:      	xorl	%eax, %eax
   9da55:      	leaq	0x177e67(%rip), %rsi    # 0x2158c3
   9da5c:      	callq	0x137430 <.text+0x112c00>
   9da61:      	movq	0x210(%rsp), %rdi
   9da69:      	movl	(%rdi), %eax
   9da6b:      	testl	%eax, %eax
   9da6d:      	jne	0x9db40 <.text+0x79310>
   9da73:      	movl	$0x8, %edx
   9da78:      	movl	$0x1, %esi
   9da7d:      	callq	0x23ee0 <_ZN10QArrayData10deallocateEPS_mm@plt>
   9da82:      	movq	%rbp, %rdi
   9da85:      	xorl	%r12d, %r12d
   9da88:      	callq	0x4b960 <.text+0x27130>
   9da8d:      	jmp	0x9d642 <.text+0x78e12>
   9da92:      	nopw	(%rax,%rax)
   9da98:      	leaq	0x150(%rsp), %rbp
   9daa0:      	movq	%r14, %rsi
   9daa3:      	movq	%rbp, %rdi
   9daa6:      	callq	0x24190 <_ZNK9QFileInfo12absolutePathEv@plt>
   9daab:      	leaq	0x177daf(%rip), %rdi    # 0x215861
   9dab2:      	movl	$0x11, %esi
   9dab7:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
   9dabc:      	xorl	%ecx, %ecx
   9dabe:      	movq	%rbp, %rdx
   9dac1:      	movq	%rbx, %rsi
   9dac4:      	movq	%rax, 0x240(%rsp)
   9dacc:      	leaq	0x160(%rsp), %r12
   9dad4:      	movl	$0x20, %r8d
   9dada:      	movq	%r12, %rdi
   9dadd:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
   9dae2:      	movq	0xe0(%rsp), %rax
   9daea:      	movq	%r12, %rdi
   9daed:      	movq	0x160(%rsp), %rdx
   9daf5:      	movq	%rax, 0x160(%rsp)
   9dafd:      	movq	%rdx, 0xe0(%rsp)
   9db05:      	callq	0x4b960 <.text+0x27130>
   9db0a:      	movq	%rbx, %rdi
   9db0d:      	callq	0x4b960 <.text+0x27130>
   9db12:      	movq	%rbp, %rdi
   9db15:      	callq	0x4b960 <.text+0x27130>
   9db1a:      	jmp	0x9d19e <.text+0x7896e>
   9db1f:      	nop
   9db20:      	callq	0x66460 <.text+0x41c30>
   9db25:      	leaq	0x70(%rsp), %rsi
   9db2a:      	movq	%rax, %rdi
   9db2d:      	callq	0x13feb0 <.text+0x11b680>
   9db32:      	jmp	0x9d78b <.text+0x78f5b>
   9db37:      	nopw	(%rax,%rax)
   9db40:      	cmpl	$-0x1, %eax
   9db43:      	je	0x9da82 <.text+0x79252>
   9db49:      	lock
   9db4a:      	subl	$0x1, (%rdi)
   9db4d:      	setne	%al
   9db50:      	testb	%al, %al
   9db52:      	jne	0x9da82 <.text+0x79252>
   9db58:      	movq	0x210(%rsp), %rdi
   9db60:      	jmp	0x9da73 <.text+0x79243>
   9db65:      	nopl	(%rax)
   9db68:      	cmpl	$-0x1, %eax
   9db6b:      	je	0x9d634 <.text+0x78e04>
   9db71:      	lock
   9db72:      	subl	$0x1, (%rdi)
   9db75:      	setne	%al
   9db78:      	testb	%al, %al
   9db7a:      	jne	0x9d634 <.text+0x78e04>
   9db80:      	movq	0x200(%rsp), %rdi
   9db88:      	jmp	0x9d625 <.text+0x78df5>
   9db8d:      	nopl	(%rax)
   9db90:      	cmpl	$-0x1, %eax
   9db93:      	je	0x9d19e <.text+0x7896e>
   9db99:      	lock
   9db9a:      	subl	$0x1, (%rdi)
   9db9d:      	setne	%al
   9dba0:      	testb	%al, %al
   9dba2:      	jne	0x9d19e <.text+0x7896e>
   9dba8:      	movq	0x1c0(%rsp), %rdi
   9dbb0:      	jmp	0x9d8ef <.text+0x790bf>
   9dbb5:      	nopl	(%rax)
   9dbb8:      	movl	$0x8, %edi
   9dbbd:      	callq	0x221f0 <_Znwm@plt>
   9dbc2:      	movq	%rax, %rdi
   9dbc5:      	movq	%rax, %rbp
   9dbc8:      	callq	0x45370 <.text+0x20b40>
   9dbcd:      	movq	%rbp, 0x636cb4(%rip)    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
   9dbd4:      	movq	%rbp, %rdi
   9dbd7:      	jmp	0x9d1cf <.text+0x7899f>
   9dbdc:      	nopl	(%rax)
   9dbe0:      	movl	$0x8, %edi
   9dbe5:      	callq	0x221f0 <_Znwm@plt>
   9dbea:      	movq	%rax, %rdi
   9dbed:      	movq	%rax, %rbp
   9dbf0:      	callq	0x1376a0 <.text+0x112e70>
   9dbf5:      	movq	%rbp, 0x6381ec(%rip)    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9dbfc:      	movq	%rbp, %rdi
   9dbff:      	jmp	0x9d20b <.text+0x789db>
   9dc04:      	nopl	(%rax)
   9dc08:      	movq	0x6381d9(%rip), %rdi    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9dc0f:      	testq	%rdi, %rdi
   9dc12:      	je	0x9dd11 <.text+0x794e1>
   9dc18:      	leaq	0x177e81(%rip), %r8     # 0x215aa0
   9dc1f:      	movl	$0xb75, %ecx            # imm = 0xB75
   9dc24:      	xorl	%eax, %eax
   9dc26:      	leaq	0x177a50(%rip), %rdx    # 0x21567d
   9dc2d:      	leaq	0x17730c(%rip), %rsi    # 0x214f40
   9dc34:      	callq	0x137430 <.text+0x112c00>
   9dc39:      	jmp	0x9d64f <.text+0x78e1f>
   9dc3e:      	nop
   9dc40:      	movl	$0x8, %edi
   9dc45:      	callq	0x221f0 <_Znwm@plt>
   9dc4a:      	movq	%rax, %rdi
   9dc4d:      	movq	%rax, %r12
   9dc50:      	callq	0x1376a0 <.text+0x112e70>
   9dc55:      	movq	%r12, 0x63818c(%rip)    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9dc5c:      	movq	%r12, %rdi
   9dc5f:      	jmp	0x9d2af <.text+0x78a7f>
   9dc64:      	nopl	(%rax)
   9dc68:      	movl	$0x8, %edi
   9dc6d:      	callq	0x221f0 <_Znwm@plt>
   9dc72:      	movq	%rax, %rdi
   9dc75:      	movq	%rax, %r12
   9dc78:      	callq	0x1376a0 <.text+0x112e70>
   9dc7d:      	movq	%r12, 0x638164(%rip)    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9dc84:      	movq	%r12, %rdi
   9dc87:      	jmp	0x9d6e3 <.text+0x78eb3>
   9dc8c:      	nopl	(%rax)
   9dc90:      	movl	$0x8, %edi
   9dc95:      	callq	0x221f0 <_Znwm@plt>
   9dc9a:      	movq	%rax, %rdi
   9dc9d:      	movq	%rax, 0x38(%rsp)
   9dca2:      	callq	0x1376a0 <.text+0x112e70>
   9dca7:      	movq	0x38(%rsp), %rax
   9dcac:      	movq	%rax, 0x638135(%rip)    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9dcb3:      	movq	%rax, %rdi
   9dcb6:      	jmp	0x9d404 <.text+0x78bd4>
   9dcbb:      	movl	$0x8, %edi
   9dcc0:      	callq	0x221f0 <_Znwm@plt>
   9dcc5:      	movq	%rax, %rdi
   9dcc8:      	movq	%rax, 0x8(%rsp)
   9dccd:      	callq	0x1376a0 <.text+0x112e70>
   9dcd2:      	movq	0x8(%rsp), %rax
   9dcd7:      	movq	%rax, 0x63810a(%rip)    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9dcde:      	movq	%rax, %rdi
   9dce1:      	jmp	0x9d5fb <.text+0x78dcb>
   9dce6:      	movl	$0x8, %edi
   9dceb:      	callq	0x221f0 <_Znwm@plt>
   9dcf0:      	movq	%rax, %rdi
   9dcf3:      	movq	%rax, 0x8(%rsp)
   9dcf8:      	callq	0x1376a0 <.text+0x112e70>
   9dcfd:      	movq	0x8(%rsp), %rax
   9dd02:      	movq	%rax, 0x6380df(%rip)    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9dd09:      	movq	%rax, %rdi
   9dd0c:      	jmp	0x9da49 <.text+0x79219>
   9dd11:      	movl	$0x8, %edi
   9dd16:      	callq	0x221f0 <_Znwm@plt>
   9dd1b:      	movq	%rax, %rdi
   9dd1e:      	movq	%rax, %rbp
   9dd21:      	callq	0x1376a0 <.text+0x112e70>
   9dd26:      	movq	%rbp, 0x6380bb(%rip)    # 0x6d5de8 <_ZN9QListData11shared_nullE+0x1588>
   9dd2d:      	movq	%rbp, %rdi
   9dd30:      	jmp	0x9dc18 <.text+0x793e8>
   9dd35:      	xorl	%r12d, %r12d
   9dd38:      	movq	0x58(%rsp), %rdi
   9dd3d:      	callq	0x4ba50 <.text+0x27220>
   9dd42:      	callq	0x55c60 <.text+0x31430>
   9dd47:      	leaq	0x177d72(%rip), %rdx    # 0x215ac0
   9dd4e:      	movq	%rax, %rdi
   9dd51:      	movl	%ebx, %ecx
   9dd53:      	leaq	0x1778b1(%rip), %rsi    # 0x21560b
   9dd5a:      	xorl	%eax, %eax
   9dd5c:      	callq	0x137430 <.text+0x112c00>
   9dd61:      	movq	0x50(%rsp), %rdi
   9dd66:      	callq	0x22580 <_ZN4QDirD1Ev@plt>
   9dd6b:      	leaq	0x70(%rsp), %rdi
   9dd70:      	callq	0x4b960 <.text+0x27130>
   9dd75:      	movq	0x28(%rsp), %rdi
   9dd7a:      	callq	0x4b960 <.text+0x27130>
   9dd7f:      	movl	%r12d, %eax
   9dd82:      	movq	0x298(%rsp), %rbx
   9dd8a:      	xorq	%fs:0x28, %rbx
   9dd93:      	jne	0x9e242 <.text+0x79a12>
   9dd99:      	addq	$0x2a8, %rsp            # imm = 0x2A8
   9dda0:      	popq	%rbx
   9dda1:      	popq	%rbp
   9dda2:      	popq	%r12
   9dda4:      	popq	%r13
   9dda6:      	popq	%r14
   9dda8:      	popq	%r15
   9ddaa:      	retq
   9ddab:      	leaq	0x60(%rsp), %rax
   9ddb0:      	movq	%rbx, %rdi
   9ddb3:      	leaq	0x1777fe(%rip), %rsi    # 0x2155b8
   9ddba:      	movq	%rax, 0x28(%rsp)
   9ddbf:      	callq	0x7f830 <.text+0x5b000>
   9ddc4:      	testb	%al, %al
   9ddc6:      	je	0x9de15 <.text+0x795e5>
   9ddc8:      	leaq	0x60(%rsp), %rdi
   9ddcd:      	leaq	0x176c84(%rip), %rsi    # 0x214a58
   9ddd4:      	movq	%rdi, 0x28(%rsp)
   9ddd9:      	callq	0x783e0 <.text+0x53bb0>
   9ddde:      	leaq	0x70(%rsp), %rdi
   9dde3:      	leaq	0x1770de(%rip), %rsi    # 0x214ec8
   9ddea:      	callq	0x783e0 <.text+0x53bb0>
   9ddef:      	jmp	0x9cc5d <.text+0x7842d>
   9ddf4:      	leaq	0x16bc9d(%rip), %rsi    # 0x209a98
   9ddfb:      	movl	$0x36, %edx
   9de00:      	leaq	0x16bd31(%rip), %rdi    # 0x209b38
   9de07:      	callq	0x22900 <_Z9qt_assertPKcS0_i@plt>
   9de0c:      	movzbl	%r12b, %ebx
   9de10:      	jmp	0x9dd38 <.text+0x79508>
   9de15:      	leaq	0x60(%rsp), %rax
   9de1a:      	movq	%rbx, %rdi
   9de1d:      	leaq	0x17779f(%rip), %rsi    # 0x2155c3
   9de24:      	movq	%rax, 0x28(%rsp)
   9de29:      	callq	0x7f830 <.text+0x5b000>
   9de2e:      	testb	%al, %al
   9de30:      	je	0x9de7d <.text+0x7964d>
   9de32:      	leaq	0x60(%rsp), %rdi
   9de37:      	leaq	0x176c3a(%rip), %rsi    # 0x214a78
   9de3e:      	movq	%rdi, 0x28(%rsp)
   9de43:      	callq	0x783e0 <.text+0x53bb0>
   9de48:      	leaq	0x70(%rsp), %rdi
   9de4d:      	leaq	0x17709c(%rip), %rsi    # 0x214ef0
   9de54:      	callq	0x783e0 <.text+0x53bb0>
   9de59:      	jmp	0x9cc5d <.text+0x7842d>
   9de5e:      	leaq	0x16bdb3(%rip), %rdx    # 0x209c18
   9de65:      	movl	$0x1e6, %ecx            # imm = 0x1E6
   9de6a:      	leaq	0x16be94(%rip), %rsi    # 0x209d05
   9de71:      	leaq	0x1752ca(%rip), %rdi    # 0x213142
   9de78:      	callq	0x227d0 <_Z11qt_assert_xPKcS0_S0_i@plt>
   9de7d:      	leaq	0x60(%rsp), %rax
   9de82:      	movq	%rbx, %rdi
   9de85:      	leaq	0x177742(%rip), %rsi    # 0x2155ce
   9de8c:      	movq	%rax, 0x28(%rsp)
   9de91:      	callq	0x7f830 <.text+0x5b000>
   9de96:      	leaq	0x60(%rsp), %rdi
   9de9b:      	movq	%rdi, 0x28(%rsp)
   9dea0:      	testb	%al, %al
   9dea2:      	je	0x9e24f <.text+0x79a1f>
   9dea8:      	leaq	0x176be9(%rip), %rsi    # 0x214a98
   9deaf:      	callq	0x783e0 <.text+0x53bb0>
   9deb4:      	leaq	0x70(%rsp), %rdi
   9deb9:      	leaq	0x177058(%rip), %rsi    # 0x214f18
   9dec0:      	callq	0x783e0 <.text+0x53bb0>

## Navigation verifier and pathname transform core [0x140030,0x1403c3)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  140030:      	pushq	%r15
  140032:      	movq	%rdx, %rsi
  140035:      	pushq	%r14
  140037:      	pushq	%r13
  140039:      	movq	%rdi, %r13
  14003c:      	pushq	%r12
  14003e:      	pushq	%rbp
  14003f:      	pushq	%rbx
  140040:      	subq	$0x118, %rsp            # imm = 0x118
  140047:      	movq	%fs:0x28, %rax
  140050:      	movq	%rax, 0x108(%rsp)
  140058:      	xorl	%eax, %eax
  14005a:      	leaq	0x40(%rsp), %rbp
  14005f:      	movq	%rcx, 0x10(%rsp)
  140064:      	leaq	0xf0(%rsp), %rbx
  14006c:      	movq	%rbp, %rdi
  14006f:      	callq	0x55bf0 <.text+0x313c0>
  140074:      	movq	%rbx, %rdi
  140077:      	movq	%rbp, %rsi
  14007a:      	callq	0x55bf0 <.text+0x313c0>
  14007f:      	movq	0x594802(%rip), %rdi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
  140086:      	testq	%rdi, %rdi
  140089:      	je	0x140418 <.text+0x11bbe8>
  14008f:      	movq	%rbx, %rsi
  140092:      	callq	0x45820 <.text+0x20ff0>
  140097:      	movl	%eax, %r12d
  14009a:      	movq	%rbx, %rdi
  14009d:      	callq	0x4b960 <.text+0x27130>
  1400a2:      	testl	%r12d, %r12d
  1400a5:      	jne	0x140340 <.text+0x11bb10>
  1400ab:      	leaq	0x80(%rsp), %r12
  1400b3:      	leaq	0xc9cea(%rip), %rsi     # 0x209da4
  1400ba:      	movq	%r12, %rdi
  1400bd:      	callq	0x55b90 <.text+0x31360>
  1400c2:      	movq	0x5947bf(%rip), %rsi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
  1400c9:      	testq	%rsi, %rsi
  1400cc:      	je	0x1403f0 <.text+0x11bbc0>
  1400d2:      	leaq	0x50(%rsp), %rax
  1400d7:      	movq	%r12, %rdx
  1400da:      	movq	%rax, %rdi
  1400dd:      	movq	%rax, 0x8(%rsp)
  1400e2:      	callq	0x44010 <.text+0x1f7e0>
  1400e7:      	movq	%r12, %rdi
  1400ea:      	callq	0x4b960 <.text+0x27130>
  1400ef:      	movq	0x8(%rsp), %rsi
  1400f4:      	movq	%rbx, %rdi
  1400f7:      	callq	0x55bf0 <.text+0x313c0>
  1400fc:      	movq	0x594785(%rip), %rdi    # 0x6d4888 <_ZN9QListData11shared_nullE+0x28>
  140103:      	movl	0x594ee2(%rip), %r15d   # 0x6d4fec <_ZN9QListData11shared_nullE+0x78c>
  14010a:      	testq	%rdi, %rdi
  14010d:      	je	0x1403c8 <.text+0x11bb98>
  140113:      	movq	%rbx, %rcx
  140116:      	movl	$0x1, %edx
  14011b:      	movl	%r15d, %esi
  14011e:      	callq	0x47ae0 <.text+0x232b0>
  140123:      	movl	%eax, %r14d
  140126:      	movq	%rbx, %rdi
  140129:      	callq	0x4b960 <.text+0x27130>
  14012e:      	testl	%r14d, %r14d
  140131:      	jne	0x140388 <.text+0x11bb58>
  140137:      	leaq	0x60(%rsp), %rax
  14013c:      	leaq	0xd2154(%rip), %rsi     # 0x212297
  140143:      	movq	%rax, %rdi
  140146:      	movq	%rax, %r15
  140149:      	movq	%rax, 0x38(%rsp)
  14014e:      	callq	0x55b90 <.text+0x31360>
  140153:      	leaq	0x70(%rsp), %rax
  140158:      	leaq	0xd2146(%rip), %rsi     # 0x2122a5
  14015f:      	movq	%rax, %rdi
  140162:      	movq	%rax, 0x28(%rsp)
  140167:      	callq	0x55b90 <.text+0x31360>
  14016c:      	movq	0x10(%rsp), %rdx
  140171:      	leaq	0xd0(%rsp), %r14
  140179:      	movl	$0x20, %r8d
  14017f:      	xorl	%ecx, %ecx
  140181:      	movq	0x28(%rsp), %rsi
  140186:      	movq	%r14, %rdi
  140189:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  14018e:      	leaq	0x90(%rsp), %rax
  140196:      	leaq	0xcb33b(%rip), %rsi     # 0x20b4d8
  14019d:      	movq	%rax, %rdi
  1401a0:      	movq	%rax, 0x18(%rsp)
  1401a5:      	callq	0x55b90 <.text+0x31360>
  1401aa:      	movq	0x18(%rsp), %rdx
  1401af:      	leaq	0xa0(%rsp), %rcx
  1401b7:      	movl	$0x20, %r8d
  1401bd:      	movq	%r15, %rsi
  1401c0:      	movq	%rcx, %rdi
  1401c3:      	xorl	%ecx, %ecx
  1401c5:      	movq	%rdi, 0x20(%rsp)
  1401ca:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  1401cf:      	movq	0x8(%rsp), %rdx
  1401d4:      	leaq	0xb0(%rsp), %r15
  1401dc:      	movl	$0x20, %r8d
  1401e2:      	xorl	%ecx, %ecx
  1401e4:      	movq	0x20(%rsp), %rsi
  1401e9:      	movq	%r15, %rdi
  1401ec:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  1401f1:      	leaq	0xc0(%rsp), %rax
  1401f9:      	movl	$0x20, %r8d
  1401ff:      	xorl	%ecx, %ecx
  140201:      	movq	%rbp, %rdx
  140204:      	movq	%r15, %rsi
  140207:      	movq	%rax, %rdi
  14020a:      	movq	%rax, 0x30(%rsp)
  14020f:      	callq	0x22c30 <_ZNK7QString3argERKS_i5QChar@plt>
  140214:      	movq	0xc0(%rsp), %rax
  14021c:      	movl	(%rax), %ecx
  14021e:      	movq	%rax, 0x80(%rsp)
  140226:      	leal	0x1(%rcx), %edx
  140229:      	cmpl	$0x1, %edx
  14022c:      	jbe	0x140235 <.text+0x11ba05>
  14022e:      	lock
  14022f:      	addl	$0x1, (%rax)
  140232:      	setne	%dl
  140235:      	movq	%r14, %rsi
  140238:      	movq	%r12, %rdi
  14023b:      	callq	0x23f10 <_ZN7QString6appendERKS_@plt>
  140240:      	movq	0x30(%rsp), %rdi
  140245:      	callq	0x4b960 <.text+0x27130>
  14024a:      	movq	%r15, %rdi
  14024d:      	callq	0x4b960 <.text+0x27130>
  140252:      	movq	0x20(%rsp), %rdi
  140257:      	callq	0x4b960 <.text+0x27130>
  14025c:      	movq	0x18(%rsp), %rdi
  140261:      	callq	0x4b960 <.text+0x27130>
  140266:      	movq	%r14, %rdi
  140269:      	callq	0x4b960 <.text+0x27130>
  14026e:      	leaq	0xe0(%rsp), %r14
  140276:      	movq	%r12, %rsi
  140279:      	movq	%rbx, %rdi
  14027c:      	callq	0x55bf0 <.text+0x313c0>
  140281:      	movq	%rbx, %rsi
  140284:      	movq	%r14, %rdi
  140287:      	callq	0x55b20 <.text+0x312f0>
  14028c:      	movq	0xe0(%rsp), %rdi
  140294:      	callq	0x55ac0 <.text+0x31290>
  140299:      	movq	%rax, %r15
  14029c:      	callq	0x55c60 <.text+0x31430>
  1402a1:      	leaq	0xecf60(%rip), %rdx     # 0x22d208
  1402a8:      	movq	%rax, %rdi
  1402ab:      	movq	%r15, %rcx
  1402ae:      	leaq	0xdf6fc(%rip), %rsi     # 0x21f9b1
  1402b5:      	xorl	%eax, %eax
  1402b7:      	callq	0x137430 <.text+0x112c00>
  1402bc:      	movq	%r14, %rdi
  1402bf:      	callq	0x4b8e0 <.text+0x270b0>
  1402c4:      	movq	%rbx, %rdi
  1402c7:      	callq	0x4b960 <.text+0x27130>
  1402cc:      	movq	0x595c2d(%rip), %rdi    # 0x6d5f00 <_ZN9QListData11shared_nullE+0x16a0>
  1402d3:      	testq	%rdi, %rdi
  1402d6:      	je	0x140440 <.text+0x11bc10>
  1402dc:      	movq	%r12, %rsi
  1402df:      	callq	0x1397c0 <.text+0x114f90>
  1402e4:      	movq	0x8(%rsp), %rsi
  1402e9:      	movq	%rbx, %rdi
  1402ec:      	callq	0x22d00 <_ZN5QFileC1ERK7QString@plt>
  1402f1:      	movq	%rbx, %rdi
  1402f4:      	callq	0x237c0 <_ZN5QFile6removeEv@plt>
  1402f9:      	movq	%rbx, %rdi
  1402fc:      	callq	0x22c70 <_ZN5QFileD1Ev@plt>
  140301:      	callq	0x23420 <sync@plt>
  140306:      	movq	0x10(%rsp), %rcx
  14030b:      	movq	%r12, %rdi
  14030e:      	movq	(%rcx), %rax
  140311:      	movq	%rax, (%r13)
  140315:      	movq	%rcx, %rax
  140318:      	leaq	0x594381(%rip), %rcx    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
  14031f:      	movq	%rcx, (%rax)
  140322:      	callq	0x4b960 <.text+0x27130>
  140327:      	movq	0x28(%rsp), %rdi
  14032c:      	callq	0x4b960 <.text+0x27130>
  140331:      	movq	0x38(%rsp), %rdi
  140336:      	callq	0x4b960 <.text+0x27130>
  14033b:      	jmp	0x1403b7 <.text+0x11bb87>
  14033d:      	nopl	(%rax)
  140340:      	leaq	0xd18d0(%rip), %rsi     # 0x211c17
  140347:      	movq	%r13, %rdi
  14034a:      	callq	0x55b90 <.text+0x31360>
  14034f:      	movq	%rbp, %rdi
  140352:      	callq	0x4b960 <.text+0x27130>
  140357:      	movq	%r13, %rax
  14035a:      	movq	0x108(%rsp), %rcx
  140362:      	xorq	%fs:0x28, %rcx
  14036b:      	jne	0x140499 <.text+0x11bc69>
  140371:      	addq	$0x118, %rsp            # imm = 0x118
  140378:      	popq	%rbx
  140379:      	popq	%rbp
  14037a:      	popq	%r12
  14037c:      	popq	%r13
  14037e:      	popq	%r14
  140380:      	popq	%r15
  140382:      	retq
  140383:      	nopl	(%rax,%rax)
  140388:      	callq	0x55c60 <.text+0x31430>
  14038d:      	leaq	0xece74(%rip), %rdx     # 0x22d208
  140394:      	movq	%rax, %rdi
  140397:      	movl	%r14d, %ecx
  14039a:      	leaq	0xcb10f(%rip), %rsi     # 0x20b4b0
  1403a1:      	xorl	%eax, %eax
  1403a3:      	callq	0x137430 <.text+0x112c00>
  1403a8:      	leaq	0xd1868(%rip), %rsi     # 0x211c17
  1403af:      	movq	%r13, %rdi
  1403b2:      	callq	0x55b90 <.text+0x31360>
  1403b7:      	movq	0x8(%rsp), %rdi
  1403bc:      	callq	0x4b960 <.text+0x27130>
  1403c1:      	jmp	0x14034f <.text+0x11bb1f>

## Shared command helper complete FDE [0x1397c0,0x1398fb)

work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf:	file format elf64-x86-64

Disassembly of section .text:

0000000000024830 <.text>:
  1397c0:      	pushq	%r13
  1397c2:      	pushq	%r12
  1397c4:      	pushq	%rbp
  1397c5:      	pushq	%rbx
  1397c6:      	subq	$0x248, %rsp            # imm = 0x248
  1397cd:      	movq	%fs:0x28, %rax
  1397d6:      	movq	%rax, 0x238(%rsp)
  1397de:      	xorl	%eax, %eax
  1397e0:      	movq	(%rsi), %rax
  1397e3:      	movl	0x4(%rax), %eax
  1397e6:      	testl	%eax, %eax
  1397e8:      	jne	0x139810 <.text+0x114fe0>
  1397ea:      	movq	0x238(%rsp), %rax
  1397f2:      	xorq	%fs:0x28, %rax
  1397fb:      	jne	0x1398ba <.text+0x11508a>
  139801:      	addq	$0x248, %rsp            # imm = 0x248
  139808:      	popq	%rbx
  139809:      	popq	%rbp
  13980a:      	popq	%r12
  13980c:      	popq	%r13
  13980e:      	retq
  13980f:      	nop
  139810:      	leaq	0xd2005(%rip), %rdi     # 0x20b81c
  139817:      	movq	%rsi, %rbx
  13981a:      	movl	$0x5, %esi
  13981f:      	callq	0x22db0 <_ZN7QString16fromAscii_helperEPKci@plt>
  139824:      	leaq	0x10(%rsp), %rbp
  139829:      	movq	%rbx, %rsi
  13982c:      	movq	%rax, (%rsp)
  139830:      	movq	%rbp, %rdi
  139833:      	callq	0x55bf0 <.text+0x313c0>
  139838:      	movq	%rsp, %rsi
  13983b:      	movq	%rbp, %rdi
  13983e:      	callq	0x23f10 <_ZN7QString6appendERKS_@plt>
  139843:      	leaq	0x20(%rsp), %r12
  139848:      	movq	%rbp, %rsi
  13984b:      	movq	%r12, %rdi
  13984e:      	callq	0x55b20 <.text+0x312f0>
  139853:      	movq	0x20(%rsp), %rdi
  139858:      	callq	0x55ac0 <.text+0x31290>
  13985d:      	leaq	0xd8427(%rip), %rsi     # 0x211c8b
  139864:      	movq	%rax, %rdi
  139867:      	callq	0x23800 <popen@plt>
  13986c:      	movq	%r12, %rdi
  13986f:      	movq	%rax, %rbx
  139872:      	callq	0x4b8e0 <.text+0x270b0>
  139877:      	movq	%rbp, %rdi
  13987a:      	callq	0x4b960 <.text+0x27130>
  13987f:      	movq	%rsp, %rdi
  139882:      	callq	0x4b960 <.text+0x27130>
  139887:      	testq	%rbx, %rbx
  13988a:      	je	0x1397ea <.text+0x114fba>
  139890:      	leaq	0x30(%rsp), %rbp
  139895:      	nopl	(%rax)
  139898:      	movq	%rbx, %rdx
  13989b:      	movl	$0x200, %esi            # imm = 0x200
  1398a0:      	movq	%rbp, %rdi
  1398a3:      	callq	0x23130 <fgets@plt>
  1398a8:      	testq	%rax, %rax
  1398ab:      	jne	0x139898 <.text+0x115068>
  1398ad:      	movq	%rbx, %rdi
  1398b0:      	callq	0x21fe0 <pclose@plt>
  1398b5:      	jmp	0x1397ea <.text+0x114fba>
  1398ba:      	callq	0x226b0 <__stack_chk_fail@plt>
  1398bf:      	movq	%rax, %rbx
  1398c2:      	movq	%rbx, %rdi
  1398c5:      	callq	0x23190 <_Unwind_Resume@plt>
  1398ca:      	movq	%rbp, %rdi
  1398cd:      	movq	%rax, %rbx
  1398d0:      	callq	0x4b960 <.text+0x27130>
  1398d5:      	movq	%rsp, %rdi
  1398d8:      	callq	0x4b960 <.text+0x27130>
  1398dd:      	jmp	0x1398c2 <.text+0x115092>
  1398df:      	movq	%rax, %rbx
  1398e2:      	leaq	0x10(%rsp), %rdi
  1398e7:      	callq	0x4b960 <.text+0x27130>
  1398ec:      	jmp	0x1398d5 <.text+0x1150a5>
  1398ee:      	movq	%r12, %rdi
  1398f1:      	movq	%rax, %rbx
  1398f4:      	callq	0x4b8e0 <.text+0x270b0>
  1398f9:      	jmp	0x1398e2 <.text+0x1150b2>
