# AppFUMO exact shell-boundary evidence (bounded excerpts)
# Static evidence only; no recovered code was executed.
# ELF: work/public-vuln-research-20261101/appupgrade-exact-extract/AppUpgrade.embedded-5721c8.elf
# size: 5066264
# SHA-256: 464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7
# GNU Build ID: 863a8730e66a1c5245a1bf458fe2554adee0351a
# tool: Homebrew LLVM 23.1.3 llvm-objdump / llvm-dwarfdump
# addresses: image-base-zero link-time virtual addresses

# .eh_frame exact ranges
# FDE pc=00100b30...0010110c  (AppUpgradeEngine::decryptionFile binding from prior Qt metadata)
# FDE pc=00044010...0004454c  (transient key-path helper)
# FDE pc=00060ac0...0006178f  (separate four-placeholder template consumer)
# FDE pc=001397c0...001398fb  (void command-draining helper called at 0x100e0c)
# FDE pc=00139900...00139b46  (distinct neighboring output-returning helper)

# Exact null-terminated literal bytes
# 0x209cd4: "%1/%2"
# 0x209da4: "/tmp"
# 0x20b4d8: "/app/share/AppUpgrade/DecryptToPIPE"
# 0x20b500: "%1 -d %2 %3 0 | pv -q -L 8m | dd of=%4 bs=512"
# 0x20b530: "%1 -d %2 %3 0 | dd of=%4 bs=512"
# 0x20b81c: " 2>&1"
# 0x211c17: "fail"
# 0x211c8b: "r"
# 0x212297: "%1 -d %2 %3 0"
# 0x2122a5: " | dd of=%1 bs=512"

# decryptionFile entry: hidden QString return=%rdi, encFile=%rdx,
# destPath=%rcx. destPath is retained in %r13; encFile QString data is copied.
  100b30: 41 57                         pushq   %r15
  100b34: 41 55                         pushq   %r13
  100b36: 49 89 cd                      movq    %rcx, %r13
  100b3c: 48 89 fd                      movq    %rdi, %rbp
  100b5a: 48 8b 02                      movq    (%rdx), %rax
  100b5f: 48 89 44 24 30                movq    %rax, 0x30(%rsp)

# Input verifier: nonzero returns fixed "fail" before command construction.
  100bad: 48 89 de                      movq    %rbx, %rsi
  100bb0: e8 6b 4c f4 ff                callq   0x45820
  100bb5: 41 89 c4                      movl    %eax, %r12d
  100bc0: 45 85 e4                      testl   %r12d, %r12d
  100bc3: 0f 85 a7 02 00 00             jne     0x100e70
  100e70: 48 8d 3d a0 0d 11 00          leaq    0x110da0(%rip), %rdi # 0x211c17
  100e7c: e8 2f 1f f2 ff                callq   QString::fromAscii_helper
  100e81: 48 89 45 00                   movq    %rax, (%rbp)

# Transient path: /tmp is passed to FDE [0x44010,0x4454c).
  100bc9: 48 8d 3d d4 91 10 00          leaq    0x1091d4(%rip), %rdi # 0x209da4
  100bd5: e8 d6 21 f2 ff                callq   QString::fromAscii_helper
  100bf7: 48 89 da                      movq    %rbx, %rdx
  100bfa: 4c 89 f7                      movq    %r14, %rdi
  100bfd: e8 0e 34 f4 ff                callq   0x44010

# Key-path helper: QUuid::createUuid -> toString, "%1/%2" substitution,
# then case-sensitive replacement of "{", "}", and "-" with empty strings.
   4403f: e8 3c fc fd ff                callq   QUuid::createUuid
   4405f: e8 fc f8 fd ff                callq   QUuid::toString
   44069: 48 8d 3d 64 5c 1c 00          leaq    0x1c5c64(%rip), %rdi # 0x209cd4
   44095: e8 96 eb fd ff                callq   QString::arg
   440b0: e8 7b eb fd ff                callq   QString::arg
   441b0: e8 2b f0 fd ff                callq   QString::replace
   441c8: e8 13 f0 fd ff                callq   QString::replace
   441db: e8 00 f0 fd ff                callq   QString::replace

# Key-file operation result: nonzero reaches the same fixed failure return.
  100c3f: 48 89 d9                      movq    %rbx, %rcx
  100c42: ba 01 00 00 00                movl    $1, %edx
  100c47: 44 89 e6                      movl    %r12d, %esi
  100c4a: e8 91 6e f4 ff                callq   0x47ae0
  100c5a: 45 85 e4                      testl   %r12d, %r12d
  100c5d: 0f 85 5d 02 00 00             jne     0x100ec0
  100ee0: 48 8d 3d 30 0d 11 00          leaq    0x110d30(%rip), %rdi # 0x211c17
  100ef1: 48 89 45 00                   movq    %rax, (%rbp)

# Exact decryptionFile command chain. The first split template receives:
# %1=fixed helper, %2=transient key pathname, %3=encFile.
# The second split template receives %1=destPath. The two results concatenate.
  100c63: 48 8d 3d 2d 16 11 00          leaq    0x11162d(%rip), %rdi # 0x212297
  100c74: be 12 00 00 00                movl    $0x12, %esi
  100c7e: 48 8d 3d 20 16 11 00          leaq    0x111620(%rip), %rdi # 0x2122a5
  100c8f: 48 8d 74 24 60                leaq    0x60(%rsp), %rsi
  100c96: 4c 89 ea                      movq    %r13, %rdx
  100cb3: e8 78 1f f2 ff                callq   QString::arg
  100cb8: 48 8d 3d 19 a8 10 00          leaq    0x10a819(%rip), %rdi # 0x20b4d8
  100cc4: e8 e7 20 f2 ff                callq   QString::fromAscii_helper
  100cf7: 4c 89 d6                      movq    %r10, %rsi
  100cfa: 4c 89 54 24 20                movq    %r10, 0x20(%rsp)
  100cff: e8 2c 1f f2 ff                callq   QString::arg
  100d0c: 4c 89 f2                      movq    %r14, %rdx
  100d0f: 4c 89 fe                      movq    %r15, %rsi
  100d2a: e8 01 1f f2 ff                callq   QString::arg
  100d44: 4c 8d 64 24 30                leaq    0x30(%rsp), %r12
  100d4c: 4c 89 e2                      movq    %r12, %rdx
  100d4f: e8 dc 1e f2 ff                callq   QString::arg
  100d54: 48 8b 14 24                   movq    (%rsp), %rdx
  100d5d: 4c 89 fe                      movq    %r15, %rsi
  100d68: e8 63 55 f6 ff                callq   0x662d0
# 0x662d0 copies the first QString and directly calls QString::append on the
# second. No quote, escape, validation, or shell-character filtering call occurs
# in this substitution/concatenation chain.

# Log formatting ends; direct call enters the exact void helper FDE.
  100dfc: e8 5f 56 f6 ff                callq   0x66460
  100e01: 4c 8b 7c 24 08                movq    0x8(%rsp), %r15
  100e06: 48 89 c7                      movq    %rax, %rdi
  100e09: 4c 89 fe                      movq    %r15, %rsi
  100e0c: e8 af 89 03 00                callq   0x1397c0

# [0x1397c0,0x1398fb): empty input returns. Nonempty input appends fixed
# stderr redirection, converts QString to local bytes, and calls popen in read
# mode. Under the libc contract, popen passes the command string to a shell.
  1397e0: 48 8b 06                      movq    (%rsi), %rax
  1397e3: 8b 40 04                      movl    0x4(%rax), %eax
  1397e6: 85 c0                         testl   %eax, %eax
  1397e8: 75 26                         jne     0x139810
  13980e: c3                            retq
  139810: 48 8d 3d 05 20 0d 00          leaq    0xd2005(%rip), %rdi # 0x20b81c
  13983e: e8 cd a6 ee ff                callq   QString::append
  13984e: e8 cd c2 f1 ff                callq   0x55b20
  139858: e8 63 c2 f1 ff                callq   0x55ac0
  13985d: 48 8d 35 27 84 0d 00          leaq    0xd8427(%rip), %rsi # 0x211c8b
  139867: e8 94 9f ee ff                callq   popen@plt

# popen failure returns void. Success drains at most 0x1ff data bytes per fgets
# call into the same stack buffer, discards every read, closes, and ignores the
# pclose return value in %eax.
  139887: 48 85 db                      testq   %rbx, %rbx
  13988a: 0f 84 5a ff ff ff             je      0x1397ea
  139898: 48 89 da                      movq    %rbx, %rdx
  13989b: be 00 02 00 00                movl    $0x200, %esi
  1398a3: e8 88 98 ee ff                callq   fgets@plt
  1398a8: 48 85 c0                      testq   %rax, %rax
  1398ab: 75 eb                         jne     0x139898
  1398ad: 48 89 df                      movq    %rbx, %rdi
  1398b0: e8 2b 87 ee ff                callq   pclose@plt
  1398b5: e9 30 ff ff ff                jmp     0x1397ea

# Distinct neighbor, not an alternate entry into 0x1397c0. It has its own FDE,
# prologue, popen at 0x1399cc, feof/fgets loop, QString::fromAscii and append.
  139900: 41 56                         pushq   %r14
  139917: 48 81 ec 50 02 00 00          subq    $0x250, %rsp
  1399cc: e8 2f 9e ee ff                callq   popen@plt
  139a53: e8 d8 96 ee ff                callq   fgets@plt
  139a60: e8 cb 84 ee ff                callq   feof@plt
  139a6c: e8 6f 85 ee ff                callq   pclose@plt
  139acb: e8 e0 92 ee ff                callq   QString::fromAscii_helper
  139adb: e8 30 a4 ee ff                callq   QString::append

# decryptionFile post-sink behavior: remove transient key, sync, then move
# destPath into the QString return object. There is no helper-status use and no
# destination existence/size check in [0x100b30,0x10110c).
  100e11: 4c 89 f6                      movq    %r14, %rsi
  100e17: e8 e4 1e f2 ff                callq   QFile::QFile
  100e1f: e8 9c 29 f2 ff                callq   QFile::remove
  100e2c: e8 ef 25 f2 ff                callq   sync@plt
  100e31: 49 8b 45 00                   movq    (%r13), %rax
  100e38: 48 89 45 00                   movq    %rax, (%rbp)
  100e3c: 48 8d 05 5d 38 5d 00          leaq    0x5d385d(%rip), %rax # 0x6d46a0
  100e43: 49 89 45 00                   movq    %rax, (%r13)
  100ebd: c3                            retq

# Literal provenance correction: 0x20b500 and 0x20b530 are not referenced by
# decryptionFile. They are selected in separate FDE [0x60ac0,0x6178f).
# Object byte +0x22 zero selects 0x20b500; nonzero branches to 0x20b530.
   60ecc: 41 80 7d 22 00                cmpb    $0, 0x22(%r13)
   60ed1: 0f 85 49 04 00 00             jne     0x61320
   60eef: 48 8d 35 e2 a5 1a 00          leaq    0x1aa5e2(%rip), %rsi # 0x20b4d8
   60f08: 48 8d 35 f1 a5 1a 00          leaq    0x1aa5f1(%rip), %rsi # 0x20b500
   60f41: e8 ea 1c fc ff                callq   QString::arg
   60f6b: e8 c0 1c fc ff                callq   QString::arg
   60f93: e8 98 1c fc ff                callq   QString::arg
   60fbb: e8 70 1c fc ff                callq   QString::arg
   6103b: e8 80 87 0d 00                callq   0x1397c0
   61338: 48 8d 35 99 a1 1a 00          leaq    0x1aa199(%rip), %rsi # 0x20b4d8
   61351: 48 8d 35 d8 a1 1a 00          leaq    0x1aa1d8(%rip), %rsi # 0x20b530
   6138a: e8 a1 18 fc ff                callq   QString::arg
   613b4: e8 77 18 fc ff                callq   QString::arg
   613dc: e8 4f 18 fc ff                callq   QString::arg
   61404: e8 27 18 fc ff                callq   QString::arg
# In both branches: %1=fixed helper, %2=transient key QString already at stack
# +0xc0, %3=source QString in %r14, %4=destination QString in %rbp.
# This separate function performs destination existence and size checks after
# its shared-helper call; those checks are not decryptionFile behavior.
   61058: e8 a3 1c fc ff                callq   QFile::QFile
   61060: e8 5b 27 fc ff                callq   QFile::remove
   6107b: e8 80 1c fc ff                callq   QFile::QFile
   61083: e8 18 29 fc ff                callq   QFile::exists
   610b7: e8 84 0e fc ff                callq   QFile::size
   610bc: 48 2d 24 40 00 00             subq    $0x4024, %rax
   610e5: e8 56 0e fc ff                callq   QFile::size
   610ff: 4c 39 74 24 20                cmpq    %r14, 0x20(%rsp)

# Whole-.text direct-call scan found 26 direct calls to 0x1397c0, including
# 0x100e0c. This is a shared helper, not a continuation of decryptionFile.
# Previously accepted producer-family bindings retained separately:
# direct calls 0x10281c, 0x102de9, 0x103398 are in copyWhatsNewFiles FDE
# [0x101110,0x104c1b); generated row-64 meta-call 0x16e030 remains separate.
