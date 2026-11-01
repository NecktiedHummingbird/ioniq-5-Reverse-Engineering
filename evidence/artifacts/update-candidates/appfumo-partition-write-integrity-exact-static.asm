# AppFUMO PartitionUpdater exact-static selected evidence
# No raw instruction bytes; no target pathname or command text.
# ELF SHA-256 464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7
# Build ID 863a8730e66a1c5245a1bf458fe2554adee0351a
# Homebrew LLVM version 23.1.3
# Complete instructions 470739 SHA-256 693dce0d89faabeea30512fe0a696a733e9bdd64fd7be7379dba98a44d2dc0c8
# Complete FDEs 3789 SHA-256 2c71813a3f098f8f949c6acee1080c0147df182e589f8b8b576798ce4807eb07

[selected-fdes]
active-partition-name	0xa0e10-0xa14b2
inactive-partition-name	0xa14c0-0xa1b64
partition-map-population	0xa1b70-0xa247e
primary-image-selector	0xa2480-0xa2c17
partition-record-lookup	0xbfb20-0xbfe67
partition-updater-constructor	0xc0130-0xc0518
source-integrity-gate	0xc1ff0-0xc255d
partition-write-starter	0xc53d0-0xcc479
process-counter	0xcc480-0xcc6b4
post-hash-write-starter	0xcd560-0xcd637
slot-hash-check	0xcd640-0xce067
mode-orchestrator	0xce070-0xce217
process-completion-handler	0xcf9b0-0xd0c79
fstab-state-update	0xd0c80-0xd1e6c
finalization	0xd1e70-0xd327f
public-key-source-verifier	0x45d80-0x461e8
signed-trailer-parser	0x18e520-0x18e9ee
record-key-verification	0x18f5a0-0x18f6fc
process-thread-starter	0x145250-0x1458bd
partition-updater-meta-dispatch	0x16b910-0x16bac6

[complete-direct-transfers]
0x45820	calls=0x7be3a,0x80095,0x802f0,0x9d1d2,0x100bb0,0x140092	jumps=none
0x45d80	calls=0x5c21b,0xc22eb	jumps=none
0x18f700	calls=0x45f68,0x4b4ee,0x18f797	jumps=none
0x140f50	calls=0x1432f6,0x15170c	jumps=none
0xa0e10	calls=0xb1a4e,0xd0dbf,0xd0f0c	jumps=none
0xa14c0	calls=0xa1c2a,0xa1d07,0xa1de3,0xa1ee6,0xa1fda,0xa20ce,0xb2971,0xd0dfb,0xd0f48,0xd1f47	jumps=none
0xa1b70	calls=0xa075b	jumps=none
0xa2480	calls=0xa30b5,0xa9951,0xcd692,0x148fa2	jumps=none
0xbfb20	calls=0xc54ca	jumps=none
0xc1ff0	calls=0xcd6fa,0xcdbae	jumps=none
0xc53d0	calls=0xcc646	jumps=0xcd5db,0xce110
0xcc480	calls=0xcfa2e	jumps=0x16b9e0
0xcd560	calls=0xcdea7	jumps=none
0xcd640	calls=none	jumps=0x16ba9c
0xce070	calls=none	jumps=none
0xcf9b0	calls=none	jumps=0x16ba28
0xd0c80	calls=0xd2400	jumps=none
0xd1e70	calls=none	jumps=none

[literal-and-blob-identities]
public-key-directory	va=0x209d43	length=22	sha256=99c31169875a3478b5a0bf4ef49d2f3848176e14d4cdd7627f96ec40193300ff
public-key-basename	va=0x209d5a	length=16	sha256=938fe66045604ba5121110f6c9a98a0a40d92e23d11b341680ac348e8cd797de
mode-marker	va=0x2119f0	length=31	sha256=256835f02a090e6e026917e9594e914f51f6e2fe7dd5b3576801e7a361377077
integrity-slot-signature	va=0x21a9e0	length=16	sha256=64ee9193f512cf992472c800a08b54a16270bd1bba3d10499025b5a19ade5518
integrity-signal-signature	va=0x21aa20	length=15	sha256=5c4fd065b20c907a9d1a7f3a69f94f1ccfbe5992469a1bf9e14021c90a6ffda0
primary-selector-0	va=0x2163a0	length=8	sha256=b631f67a287e8250ba085f508909a53772229c66caa5a1f6ad85da6de95e85da
primary-selector-1	va=0x2163a9	length=13	sha256=cc6bc985f7846782712f9bd3a13152360ae9a738d8c4c6c6d6d19734537852bc
primary-selector-2	va=0x2163b7	length=16	sha256=d0ace5154fa5dfc8254665a11176225366806a45bac9a464754de914d7fa9898
primary-selector-3	va=0x2163c8	length=11	sha256=3ead2280ba83d31de0aebcadb620974423330f79eae9d64c7ccec9472df99e92
primary-selector-4	va=0x2163d4	length=16	sha256=01887aa06dbe98ba2ccd3b9f0fd3d928f34f8abd12d2d6ab048be6a2dac5dc5a
primary-selector-5	va=0x2163e5	length=19	sha256=a982aa336f3d2e9f5ff8dd0df7a2e32e961247a0f86983fe7b1c24f5dd6746a4
primary-selector-6	va=0x2163f9	length=11	sha256=d75c180592fbfefbe7f42677dc90c153c172fd9460839949293009aaad6ab7ac
primary-selector-7	va=0x216405	length=16	sha256=466f17e1907c2de49a6349b22a9383d54fd1e264ca0775bd4edfade7b8df9218
primary-selector-8	va=0x216416	length=19	sha256=d888ac6356279a8c5f55c5e8ecd1ea1957c9f5b3f86c0e7f33d98ebf1ce4eee9
static-partition-map	va=0x6c51a0	length=160	sha256=26a0c82e3dcef110631d6102e044a90b088c19abc02a7484e6ebdcba2c579702
mode-byte-initializer	va=0x6d20b4	length=1	sha256=4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a

[selected-instructions-no-bytes]
45d82	leaq	0x1c3fd1(%rip), %rdi    # 0x209d5a
45db7	leaq	0x1c3f85(%rip), %rdi    # 0x209d43
45ea4	callq	0x22d00 <_ZN5QFileC1ERK7QString@plt>
45f68	callq	0x18f700 <.text+0x16aed0>
a1509	leaq	0x623c90(%rip), %rsi    # 0x6c51a0
a1518	callq	0x22010 <memcpy@plt>
a1c2a	callq	0xa14c0 <.text+0x7cc90>
a1c7c	movl	$0x10, %edx
a1d07	callq	0xa14c0 <.text+0x7cc90>
a1d57	movl	$0x10, %edx
a1de3	callq	0xa14c0 <.text+0x7cc90>
a1e39	movl	$0x10, %edx
a1ee6	callq	0xa14c0 <.text+0x7cc90>
a1f44	callq	0x221e0 <strncpy@plt>
a1fda	callq	0xa14c0 <.text+0x7cc90>
a2038	callq	0x221e0 <strncpy@plt>
a20ce	callq	0xa14c0 <.text+0x7cc90>
a212c	callq	0x221e0 <strncpy@plt>
a24af	leaq	0x6321ea(%rip), %rax    # 0x6d46a0 <_ZN10QArrayData11shared_nullE>
a2593	movl	0x62fb17(%rip), %eax    # 0x6d20b0
bfb73	cmpl	$0xa, %ebx
bfbe3	callq	0x229e0 <_ZeqRK7QStringS1_@plt>
bfd27	movl	$0xffffffff, %eax       # imm = 0xFFFFFFFF
bfd90	movl	%ebx, %eax
c0155	movb	$0x0, 0x38(%rbx)
c018e	movq	%rax, 0x28(%rbx)
c01b5	movl	$0x0, 0x90(%rbx)
c01d3	movb	$0x0, 0x3b(%rbx)
c0339	movb	$0x0, 0x9c(%rbx)
c036d	callq	0x232e0 <_ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE@plt>
c20a7	movq	%r14, %rsi
c20b2	callq	0x239a0 <_ZNK5QFile6existsEv@plt>
c2150	callq	0x4a0a0 <.text+0x25870>
c22eb	callq	0x45d80 <.text+0x21550>
c2307	callq	0x43b20 <.text+0x1f2f0>
c5421	leaq	0x28(%r15), %rax
c543a	addq	$0x20, %rsi
c54ca	callq	0xbfb20 <.text+0x9b2f0>
c5637	movq	(%rax), %rsi
c564b	addq	$0x10, %rsi
c57af	callq	0x22d00 <_ZN5QFileC1ERK7QString@plt>
c57bc	callq	0x22690 <_ZN5QFile4openE6QFlagsIN9QIODevice12OpenModeFlagEE@plt>
c67cc	leaq	-0x5493(%rip), %rax     # 0xc1340 <.text+0x9cb10>
c683b	callq	0x220b0 <_ZN7QObject11connectImplEPKS_PPvS1_S3_PN9QtPrivate15QSlotObjectBaseEN2Qt14ConnectionTypeEPKiPK11QMetaObject@plt>
c684f	leaq	0x915a(%rip), %rbx      # 0xcf9b0 <.text+0xab180>
c6c69	callq	0x145250 <.text+0x120a20>
c7400	addq	$0x28, %rsi
c7423	callq	0xd3600 <.text+0xaedd0>
cd5db	jmp	0xc53d0 <.text+0xa0ba0>
cd692	callq	0xa2480 <.text+0x7dc50>
cd6fa	callq	0xc1ff0 <.text+0x9d7c0>
cd709	testl	%ebp, %ebp
cdb76	addq	%r12, %rax
cdb7e	movq	0x10(%rax), %rdx
cdba8	movq	%r15, %rsi
cdbae	callq	0xc1ff0 <.text+0x9d7c0>
cdbd7	testl	%r13d, %r13d
cdbda	je	0xcd788 <.text+0xa8f58>
cdea7	callq	0xcd560 <.text+0xa8d30>
ce09b	cmpb	$0x0, 0x604012(%rip)    # 0x6d20b4
ce110	jmp	0xc53d0 <.text+0xa0ba0>
ce134	jmp	0x16b850 <.text+0x147020>
cfa2e	callq	0xcc480 <.text+0xa7c50>
d2400	callq	0xd0c80 <.text+0xac450>
d2514	callq	0x23670 <_ZN8QProcess5startERK7QStringRK11QStringList6QFlagsIN9QIODevice12OpenModeFlagEE@plt>
d2541	callq	0x22e90 <_ZN8QProcess15waitForFinishedEi@plt>
d2920	callq	0x245e0 <umount@plt>
16ba9c	jmp	0xcd640 <.text+0xa8e10>
18e5a5	cmpq	$0x4024, %rax           # imm = 0x4024
18e5ad	leaq	-0x4024(%rax), %rsi
18e5fd	movl	$0x4024, %esi           # imm = 0x4024
18e610	cmpb	$0x54, (%rbp)
18e680	cmpb	$0x45, 0x1(%rbp)
18e686	movzbl	0x2(%rbp), %eax
18e68a	cmpb	$0x52, %al
18e68c	je	0x18e996 <.text+0x16a166>
18e69a	cmpb	$0x32, %al
18f610	leaq	0x2c9889(%rip), %rsi    # 0x458ea0
18f66e	callq	0x24290 <memcmp@plt>
cd70b	jne	0xcda20 <.text+0xa91f0>
cdbda	je	0xcd788 <.text+0xa8f58>

[bounded-negative]
No direct transfer from the selected process-completion, fstab-state, or finalization FDEs to targets 0x45820, 0x45d80, 0x18f700, 0x140f50, or 0xc1ff0.
Indirect, virtual, external, inlined, loader, boot-stage, and dynamic invocation remain outside this negative.
