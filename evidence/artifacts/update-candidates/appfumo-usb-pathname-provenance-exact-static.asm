# AppFUMO USB pathname provenance — exact static excerpts
#
# Static/read-only evidence. This file is not an executable, command recipe,
# update package, trigger, or runtime observation. Virtual addresses are ELF
# virtual addresses. Excerpts were produced with a Homebrew LLVM objdump build;
# that generic tool description is intentionally retained without a workstation
# installation path.
#
# STOCK ARCHIVE BINDING
# mango-rootfs.tar.gz sha256:
#   423491fd8b86bd815d4e12f47054e08a589a5159f87213f08980fcc3a0e47c84
# ./app/bin/usb-automount sha256:
#   7db44d8e34fbece4d5b8ef4896a99239cb540a22d1d756335dde4bc219af3802
#   GNU Build ID 20748cf9928ba155ac4201a33bb1e29e64ae9139
# ./lib/systemd/systemd-udevd sha256:
#   f32f6296ea20d959ac046ae80724f39e317aaaf492a5c7eedd9270b5b2abab0d
#   GNU Build ID 91b0e9592a52274a97e185fed528d6af3557e49d
# ./lib/libblkid.so.1.1.0 sha256:
#   56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701
#   GNU Build ID c6f98d98cb2cbc2ff864167f37048233d90a8fef
# ./app/bin/AppDMClient sha256:
#   9a1fb796d7ac24fcce71c16e3dbee9306c888f43e705ee081f41b7d473978bd0
# ./etc/usb-automount.conf sha256:
#   559674d4469dc44611d77e175a27a238712b9f538d59a1864da0d321be3e2b51
# ./lib/systemd/system/usb-automount.service sha256:
#   563c077b61119a4ef7577732382fa245d87364a6068ac4304a94d073fc9c76fd
# AppUpgrade sha256:
#   464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7
#   GNU Build ID 863a8730e66a1c5245a1bf458fe2554adee0351a
# Direct archive-member hashes equal the separately reviewed extracted copies.
#
# Package metadata binds systemd-udev 249.3-r0mango134 and
# util-linux/libblkid 2.27.1-r0. Version-matched public-source files and full
# working disassemblies remain only under ignored work/.

## usb-automount: event/property function FDE [0x3ef0,0x4836)
# Property names at 0x75e1..0x763c are, in call order:
# ID_FS_TYPE, ID_FS_LABEL, ID_FS_UUID, ID_MODEL, ID_SERIAL_SHORT,
# ID_ATA_SATA, ID_PART_ENTRY_NUMBER.
    40f6: 48 8d 35 e4 34 00 00          leaq 0x34e4(%rip), %rsi # 0x75e1 ID_FS_TYPE
    4105: e8 26 e2 ff ff                callq 0x2330
    410a: 48 8d 35 db 34 00 00          leaq 0x34db(%rip), %rsi # 0x75ec ID_FS_LABEL
    4114: 48 89 44 24 38                movq %rax,0x38(%rsp)    # type
    4119: e8 12 e2 ff ff                callq 0x2330
    411e: 48 8d 35 d3 34 00 00          leaq 0x34d3(%rip), %rsi # 0x75f8 ID_FS_UUID
    4128: 48 89 44 24 58                movq %rax,0x58(%rsp)    # label
    412d: e8 fe e1 ff ff                callq 0x2330
    4132: 48 8d 35 ca 34 00 00          leaq 0x34ca(%rip), %rsi # 0x7603 ID_MODEL
    413c: 48 89 44 24 48                movq %rax,0x48(%rsp)    # UUID
    4141: e8 ea e1 ff ff                callq 0x2330
    4146: 48 8d 35 bf 34 00 00          leaq 0x34bf(%rip), %rsi # 0x760c ID_SERIAL_SHORT
    4150: 48 89 44 24 50                movq %rax,0x50(%rsp)    # model
    4155: e8 d6 e1 ff ff                callq 0x2330
    415a: 48 8d 35 bb 34 00 00          leaq 0x34bb(%rip), %rsi # 0x761c ID_ATA_SATA
    4164: 48 89 44 24 60                movq %rax,0x60(%rsp)    # serial-short
    4169: e8 c2 e1 ff ff                callq 0x2330
    416e: 48 8d 35 b3 34 00 00          leaq 0x34b3(%rip), %rsi # 0x7628 PART_ENTRY_NUMBER
    4178: 48 89 44 24 40                movq %rax,0x40(%rsp)    # ATA flag
    417d: e8 ae e1 ff ff                callq 0x2330
    4186: 48 89 44 24 68                movq %rax,0x68(%rsp)    # partition number

## usb-automount: event caller into complete dispatcher
# The event caller supplies rcx=FS type, r8=label, r9=UUID/alternate and a
# seventh stack argument=model to dispatcher 0x3a50. These are dispatcher
# inputs, not the mount-function ABI.
    442d: 48 83 ec 08                   subq $0x8,%rsp
    4431: ff 74 24 58                   pushq 0x58(%rsp)        # ID_MODEL
    4435: 4c 8b 4c 24 58                movq 0x58(%rsp),%r9     # ID_FS_UUID/alternate
    443a: 4c 8b 44 24 68                movq 0x68(%rsp),%r8     # ID_FS_LABEL
    443f: 48 8b 4c 24 48                movq 0x48(%rsp),%rcx    # ID_FS_TYPE
    4444: 48 8b 54 24 40                movq 0x40(%rsp),%rdx    # devnode
    4449: 8b 74 24 14                   movl 0x14(%rsp),%esi    # port index
    4452: e8 f9 f5 ff ff                callq 0x3a50

## usb-automount: decisive dispatcher transfers [0x3a50,0x3b53)
# The dispatcher preserves original UUID/alternate in r13, label in r12, and
# seventh-argument model in r14. On the mount branch it then remaps:
#   rdx=FS type, rcx=label, r8=UUID/alternate, r9=model,
# and tail-jumps to 0x4c00. Following this complete transfer is decisive.
    3a59: 4d 89 cd                      movq %r9,%r13           # UUID/alternate
    3a5e: 4d 89 c4                      movq %r8,%r12           # label
    3a88: 48 89 4c 24 08                movq %rcx,0x8(%rsp)     # FS type
    3a8d: 4c 8b 74 24 60                movq 0x60(%rsp),%r14    # model
    3b28: 48 8b 54 24 08                movq 0x8(%rsp),%rdx     # FS type
    3b31: 4d 89 f1                      movq %r14,%r9           # model
    3b34: 4d 89 e8                      movq %r13,%r8           # UUID/alternate
    3b37: 4c 89 e1                      movq %r12,%rcx          # label
    3b49: e9 b2 10 00 00                jmp 0x4c00              # mount tail-call

## usb-automount: no-UUID alternate identity helper FDE [0x3e50,0x3eea)
# Format at 0x7595 is "%s_%s". The call inputs are ID_SERIAL_SHORT and
# ID_PART_ENTRY_NUMBER, not ID_MODEL and not ID_FS_LABEL. If partition number
# is absent while serial is present, 0x3e7f..0x3e85 copies bare serial.
    3e7f: 48 89 fe                      movq %rdi,%rsi
    3e82: 4c 89 d7                      movq %r10,%rdi
    3e85: e8 26 e3 ff ff                callq 0x21b0             # strcpy(serial)
    3ec0: 49 89 f1                      movq %rsi,%r9
    3ec3: 49 89 f8                      movq %rdi,%r8
    3ec8: 48 8d 0d c6 36 00 00          leaq 0x36c6(%rip),%rcx # 0x7595 "%s_%s"
    3ede: e8 ed e1 ff ff                callq 0x20d0             # __sprintf_chk
    4667: 48 8b 54 24 78                movq 0x78(%rsp),%rdx     # output
    466c: 48 8b 74 24 68                movq 0x68(%rsp),%rsi     # partition number
    4671: 48 8b 7c 24 60                movq 0x60(%rsp),%rdi     # serial-short
    4676: e8 d5 f7 ff ff                callq 0x3e50
    4683: 4c 8b 8c 24 88 00 00 00       movq 0x88(%rsp),%r9     # alternate UUID argument

## usb-automount: mount function FDE [0x4c00,0x508d)
# After dispatcher remapping: rdx/rbx=FS type, rcx/r15=label,
# r8/r13=UUID/alternate, and r9/stack+8=model. Format 0x78a6 is "%s/%d/%s";
# 0x4d16 pushes r13, so the final pathname component is UUID/alternate.
# The exact stock pathname class is /media/usb/<port>/<UUID-or-alternate>.
    4c0a: 48 89 d3                      movq %rdx,%rbx           # FS type
    4c2a: 4c 89 4c 24 08                movq %r9,0x8(%rsp)      # model
    4c5c: 49 89 cf                      movq %rcx,%r15          # label
    4c5f: 4d 89 c5                      movq %r8,%r13           # UUID/alternate
    4cf6: 4c 8b 05 bb 53 20 00          movq 0x2053bb(%rip),%r8 # mount root
    4d06: 41 89 e9                      movl %ebp,%r9d           # port index
    4d16: 41 55                         pushq %r13               # final %s = UUID/alternate
    4d1a: 48 8d 0d 85 2b 00 00          leaq 0x2b85(%rip),%rcx # 0x78a6 "%s/%d/%s"
    4d24: e8 a7 d3 ff ff                callq 0x20d0             # __sprintf_chk

## usb-automount: D-Bus signal field separation, helper FDE [0x4870,0x4b7c)
# Call 0x4870 receives path in rsi, port in edx, label in rcx, model in r8,
# FS type in r9, and mount flag on the stack. Thus label and model are separate
# D-Bus fields; UUID/alternate is carried inside the constructed mount path.
    4e15: 49 89 d9                      movq %rbx,%r9            # FS type
    4e18: 4c 89 f9                      movq %r15,%rcx           # label
    4e23: 4c 8b 44 24 18                movq 0x18(%rsp),%r8     # model
    4e2f: 89 ea                         movl %ebp,%edx           # port
    4e31: 4c 89 e6                      movq %r12,%rsi           # constructed mount path
    4e34: e8 37 fa ff ff                callq 0x4870
    488a: 48 89 74 24 28                movq %rsi,0x28(%rsp)     # path field
    4896: 48 89 4c 24 18                movq %rcx,0x18(%rsp)     # label field
    489b: 4c 89 44 24 10                movq %r8,0x10(%rsp)      # model field
    48b7: 4c 89 4c 24 08                movq %r9,0x8(%rsp)       # FS-type field
    493b: e8 00 da ff ff                callq 0x2340             # dbus_message_append_args

## usb-automount: exact port-index classifier
# FDE covering this helper is [0x3850,0x38f3). It returns 1,2,3,4 for matches
# against the four configured front1/front2/rear1/rear2 devpath substrings.
# In the stock configuration front1 and rear1 are active and map to 1 and 3;
# front2 and rear2 contain "disable".
    3858: 48 8b 35 21 68 20 00          movq 0x206821(%rip),%rsi # front1
    3874: ba 01 00 00 00                movl $0x1,%edx
    38a0: 48 8b 35 e1 67 20 00          movq 0x2067e1(%rip),%rsi # front2
    38af: ba 02 00 00 00                movl $0x2,%edx
    38b9: 48 8b 35 d8 67 20 00          movq 0x2067d8(%rip),%rsi # rear1
    38c8: ba 03 00 00 00                movl $0x3,%edx
    38d2: 48 8b 35 c7 67 20 00          movq 0x2067c7(%rip),%rsi # rear2
    38e9: 83 e2 04                      andl $0x4,%edx

## shipped systemd-udevd: builtin blkid FDE [0x3d210,0x3d69d)
# Version-matched systemd v249.3 print_property maps UUID and LABEL separately.
# Machine code confirms both call blkid_safe_string, but LABEL publishes
# ID_FS_LABEL at the 0x3d4c0 branch (following UUID at 0x3d420 and UUID_SUB at
# 0x3d470).
    3d420: 48 89 e6                      movq %rsp,%rsi
    3d42e: e8 3d c9 fc ff                callq 0x9d70 # blkid_safe_string (UUID)
    3d43b: 48 8d 15 fe 7c 01 00          leaq 0x17cfe(%rip),%rdx # ID_FS_UUID
    3d470: 48 89 e6                      movq %rsp,%rsi
    3d47e: e8 ed c8 fc ff                callq 0x9d70 # blkid_safe_string (UUID_SUB)
    3d4c0: 48 89 e6                      movq %rsp,%rsi
    3d4ce: e8 9d c8 fc ff                callq 0x9d70 # blkid_safe_string (LABEL)
    3d4db: 48 8d 15 a3 7c 01 00          leaq 0x17ca3(%rip),%rdx # ID_FS_LABEL

## shipped libblkid: exact identity and blkid_safe_string FDE [0xced0,0xd09c)
# Exact stock archive member ./lib/libblkid.so.1.1.0 has SHA-256
# 56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701
# and GNU Build ID c6f98d98cb2cbc2ff864167f37048233d90a8fef.
# Version-matched util-linux v2.27.1 iso9660.c SHA-256:
# 601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b
# Source provenance: util-linux v2.27.1, libblkid/src/superblocks/iso9660.c,
# probe_iso9660_set_uuid() lines 110-151; retained only under ignored work/.
# Version-matched util-linux 2.27.1 encode source defines the allowed input set
# as "/ $%?," in addition to alphanumerics and "#+-.:=@_", accepts valid UTF-8,
# and accepts the narrow literal backslash-x pair. Whitespace is normalized to
# underscore first. Exact machine code confirms whitespace replacement, the
# whitelist call with rodata 0x33c60, literal backslash-x handling, and unsafe
# replacement with underscore. In particular '$', '?', and '/' survive when
# supplied by a filesystem-label parser.
    cfc4: c6 44 3d 00 5f                movb $0x5f,(%rbp,%rdi)  # whitespace -> '_'
    cff5: 48 8d 35 64 6c 02 00          leaq 0x26c64(%rip),%rsi # 0x33c60 "/ $%?,"
    cfff: e8 0c fb ff ff                callq 0xcb10             # whitelist
    d008: 80 fb 5c                      cmpb $0x5c,%bl           # '\\'
    d060: 42 80 7c 2d 01 78             cmpb $0x78,0x1(%rbp,%r13) # 'x'
    d050: 41 c6 06 5f                   movb $0x5f,(%r14)       # unsafe -> '_'

## shipped libblkid: ISO9660 raw-date UUID producer [0x1c4c0,0x1c654)
# probe_iso9660_set_uuid copies the first 16 modified/created-date bytes without
# digit/range validation. Representative first/middle/final byte loads are
# retained below; exact-binary tests pin all listed rows.
    1c4c0: 41 57                         pushq %r15
    1c4d3: 44 0f b6 06                   movzbl (%rsi),%r8d      # byte 0
    1c4e7: 0f b6 46 02                   movzbl 0x2(%rsi),%eax   # byte 2
    1c4eb: 44 0f b6 4e 01                movzbl 0x1(%rsi),%r9d   # byte 1
    1c500: 0f b6 46 03                   movzbl 0x3(%rsi),%eax   # byte 3
    1c511: 0f b6 46 04                   movzbl 0x4(%rsi),%eax   # byte 4
    1c51d: 0f b6 46 05                   movzbl 0x5(%rsi),%eax   # byte 5
    1c529: 0f b6 46 06                   movzbl 0x6(%rsi),%eax   # byte 6
    1c535: 0f b6 46 07                   movzbl 0x7(%rsi),%eax   # byte 7
    1c541: 0f b6 46 08                   movzbl 0x8(%rsi),%eax   # byte 8
    1c54d: 0f b6 46 09                   movzbl 0x9(%rsi),%eax   # byte 9
    1c551: 0f b6 5e 0a                   movzbl 0xa(%rsi),%ebx   # byte 10
    1c555: 0f b6 6e 0b                   movzbl 0xb(%rsi),%ebp   # byte 11
    1c559: 44 0f b6 66 0c                movzbl 0xc(%rsi),%r12d  # byte 12
    1c55e: 44 0f b6 6e 0d                movzbl 0xd(%rsi),%r13d  # byte 13
    1c567: 44 0f b6 76 0e                movzbl 0xe(%rsi),%r14d  # byte 14
    1c570: 44 0f b6 7e 0f                movzbl 0xf(%rsi),%r15d  # byte 15
# The loop checks only whether all 16 copied bytes equal ASCII '0'. If all do,
# offset byte +0x10 is separately tested; otherwise formatting proceeds.
    1c5a8: 0f b6 08                      movzbl (%rax),%ecx
    1c5af: 80 f9 30                      cmpb $0x30,%cl          # ASCII '0' only
    1c5bf: 83 fa 10                      cmpl $0x10,%edx         # all 16?
    1c5c2: 74 7c                         je 0x1c640
# Format 0x35368 is the exact NUL-terminated string
# "%c%c%c%c-%c%c-%c%c-%c%c-%c%c-%c%c-%c%c". Raw copied bytes are passed as
# %c values with fixed hyphens; 0x1c60c calls the UUID formatter.
    1c5c6: 48 8d 0d 9b 8d 01 00          leaq 0x18d9b(%rip),%rcx # 0x35368
    1c5cd: ba 10 00 00 00                movl $0x10,%edx
    1c60c: e8 6f 36 00 00                callq 0x1fc80           # sprintf UUID
# ISO9660 probe first passes modified date (+0x33e), then falls back to created
# date (+0x32d) only when the helper returns zero.
    1c7eb: 48 8d b3 3e 03 00 00          leaq 0x33e(%rbx),%rsi  # modified
    1c7f5: e8 c6 fc ff ff                callq 0x1c4c0
    1c7fa: 85 c0                         testl %eax,%eax
    1ca10: 48 8d b3 2d 03 00 00          leaq 0x32d(%rbx),%rsi  # created fallback
    1ca1a: e8 a1 fa ff ff                callq 0x1c4c0
# builtin-blkid subsequently applies blkid_safe_string to UUID. Bytes accepted
# by its allow set (including '$', '?', and '/') survive. The dispatcher then
# places ID_FS_UUID in the mount-path component. This establishes a bounded
# static ISO9660 parser -> transformed UUID -> mount-path byte route, not source
# media acceptance, mount success, installed delivery, or command execution.

## shipped systemd-udevd: usb_id builtin and no-UUID inputs
# usb_id FDE begins 0x1bc60. ID_MODEL and ID_SERIAL_SHORT each pass through
# udev_replace_whitespace and udev_replace_chars(..., NULL). Machine-code call
# pairs include 0x1c23e/0x1c248, 0x1c2a6/0x1c2b0 and serial
# 0x1c334/0x1c33e. Their ordinary accepted set is alphanumerics plus
# "#+-.:=@_", valid UTF-8 and the narrow literal backslash-x exception.
# The no-UUID alternate uses ID_SERIAL_SHORT plus decimal
# ID_PART_ENTRY_NUMBER; ID_MODEL is not the mount pathname component. Raw USB
# serial acceptance is ASCII 0x20..0x7f excluding comma before whitespace and
# character replacement. With allow=NULL, shell operators/substitution,
# whitespace, globbing, slash, quotes and dollar are replaced. The ordinary
# retained alphabet is alphanumeric plus #+-.:=@_; a literal backslash-x pair
# is the narrow exception. In the already-prefixed path word, '#' is not a
# comment introducer and '=' is not an assignment. Backslash removal before x
# cannot create splitting, an operator, substitution or globbing; it can only
# alter/mismatch that pathname word. No shell-active no-UUID effect is thereby
# established.
    1c2a6: e8 75 68 00 00                callq 0x22b20 # replace whitespace
    1c2b0: e8 4b 67 00 00                callq 0x22a00 # replace chars
    1c334: e8 e7 67 00 00                callq 0x22b20 # serial whitespace
    1c33e: e8 bd 66 00 00                callq 0x22a00 # serial chars

## AppDMClient: mounted callback FDE begins 0x84700
# Incoming callback mount-path QString is r14. It is assigned to this+0x128,
# then a shared copy of that same QString is passed to the staging helper.
# This is an exact within-AppDMClient edge. No exact AppDMClient launch-argument
# -> inner AppUpgrade constructor/package-base bridge is asserted here.
    848dd: 4c 89 f6                      movq %r14,%rsi
    848e0: 48 8d b8 28 01 00 00          leaq 0x128(%rax),%rdi
    848ee: e8 3d 81 f9 ff                callq 0x1ca30 # QString::operator=
    84983: 49 8b 06                      movq (%r14),%rax
    84988: 48 89 84 24 80 00 00          movq %rax,0x80(%rsp)
    849a4: 4c 89 ee                      movq %r13,%rsi
    849a7: e8 b4 b5 ff ff                callq 0x7ff60 # staging helper

## AppUpgrade: exact direct-site roles and package-suffix producer
# copyWhatsNewFiles FDE [0x101110,0x104c1b). The decisive mapping is:
#   0x102de9 = top-level <package base>/.whatsnew.tar.gz
#   0x10281c = enumerated system-tree file
#   0x103398 = enumerated controls-tree file
# The top-level source is constructed from package-base stack slot +0x60,
# template "%1/%2" at 0x209cd4, and suffix ".whatsnew.tar.gz" at 0x20bb63;
# its QString is retained at stack slot +0x80.
    101563: 48 8d 35 f9 a5 10 00          leaq 0x10a5f9(%rip),%rsi # 0x20bb63 suffix
    10157a: 48 8d 35 53 87 10 00          leaq 0x108753(%rip),%rsi # 0x209cd4 "%1/%2"
    101589: 48 8b 54 24 60                movq 0x60(%rsp),%rdx     # package base
    1015a4: e8 87 16 f2 ff                callq 0x22c30             # first QString::arg
    1015b9: 48 89 da                      movq %rbx,%rdx            # fixed suffix
    1015c2: 48 89 84 24 80 00 00 00       movq %rax,0x80(%rsp)     # retained source
    1015cd: e8 5e 16 f2 ff                callq 0x22c30             # second QString::arg
# At the top-level call, +0x80 is copied into the encFile local passed in %rdx;
# the separately built fixed temp archive destination is passed in %rcx.
    102dbb: 4c 8b a4 24 80 00 00 00       movq 0x80(%rsp),%r12     # package archive
    102dc3: 48 89 ef                      movq %rbp,%rdi
    102dc6: 4c 89 e6                      movq %r12,%rsi
    102dc9: e8 22 2e f5 ff                callq 0x55bf0             # copy encFile QString
    102dd3: 4c 89 e9                      movq %r13,%rcx            # destPath
    102dd6: 48 89 ea                      movq %rbp,%rdx            # encFile
    102de9: e8 42 dd ff ff                callq 0x100b30             # top-level archive
# The system-tree site obtains QFileInfo::absoluteFilePath(), places it in %rdx,
# and places the paired destination in %rcx.
    1027f5: e8 d6 06 f2 ff                callq 0x22ed0             # absoluteFilePath
    102807: 48 89 da                      movq %rbx,%rdx            # enumerated source
    102819: 4c 89 f1                      movq %r14,%rcx            # paired destination
    10281c: e8 0f e3 ff ff                callq 0x100b30             # system-tree file
# The controls-tree site has the same absolute-source/paired-destination shape.
    10337b: e8 50 fb f1 ff                callq 0x22ed0             # absoluteFilePath
    10338d: 4c 89 fa                      movq %r15,%rdx            # enumerated source
    103395: 48 89 e9                      movq %rbp,%rcx            # paired destination
    103398: e8 93 d7 ff ff                callq 0x100b30             # controls-tree file

## AppUpgrade: verifier-before-sink and shell boundary
# decryptionFile FDE [0x100b30,0x10110c). Its exact retained sink artifact is
# appfumo-shell-boundary-exact-static.asm. The verifier call and zero-test
# precede decrypt-command construction and the popen helper call.
    100bb0: e8 6b 4c f4 ff                callq 0x45820 # signed-container verifier
    100bb5: 41 89 c4                      movl %eax,%r12d
    100bc0: 45 85 e4                      testl %r12d,%r12d
    100bc3: 0f 85 a7 02 00 00             jne 0x100e70  # fixed-failure branch
    100d14: ...                            # construct unquoted decrypt command
    100e0c: e8 af 89 03 00                callq 0x1397c0 # helper -> popen("r")

## AppUpgrade: separate post-decryption extraction/enumeration route
# The extraction command template is "tar xf %1 -C %2" at 0x20be5a. Its two
# substitutions are the fixed temporary decrypted archive pathname and fixed
# temporary extraction root; archive member names are not QProcess command
# arguments. QDir then enumerates names under extracted whatsnew directories;
# constructed system/control pathnames reach 0x10281c and 0x103398 respectively.
    101d2c: 48 8d 35 27 a1 10 00          leaq 0x10a127(%rip),%rsi # 0x20be5a
    101d36: e8 55 3e f5 ff                callq 0x55b90             # QString literal
    101d3b: 48 8b 54 24 08                movq 0x8(%rsp),%rdx      # temp archive
    101d56: e8 d5 0e f2 ff                callq 0x22c30             # first QString::arg
    101d6b: 4c 89 f2                      movq %r14,%rdx            # temp root
    101d74: e8 b7 0e f2 ff                callq 0x22c30             # second QString::arg
    101d7c: e8 7f 1b f2 ff                callq 0x23900             # QProcess::execute(QString)
# The top-level encrypted archive is verifier-accepted before this extraction,
# and each enumerated encrypted member is verifier-checked in decryptionFile
# before its own shell sink. This bounded static package does not prove the
# signed-container verifier's exact covered-byte relation to decrypted tar
# header names; that member-name authentication-binding question remains
# unknown rather than being inferred from call order.

## Version-matched public-source working hashes (ignored work only)
# systemd v249.3 udev-builtin-blkid.c:
#   a4a20635a654cc1b034a73559081169bd5abcbccdd1741a79e3eb34a2366d805
# systemd v249.3 udev-builtin-usb_id.c:
#   e7cd1e315a267f84e0c1f17309a6b2a57590b04bfa9b1e0a33db09afa0f3d33b
# util-linux v2.27.1 encode.c:
#   6f3c6af73a36f8ad82152c9e476b3b1a5351735e0d88d1f9451cb03d0371d4d0
# util-linux v2.27.1 source archive:
#   b1b80e5b74bf9d62e4cb2318cf5d0f77b69b00a7c7f43cc0e6c83c009d726b2c
# ext.c  0c806388950451b9455b83899fe7da580b36a79ca9a65e31b694cd98296b1ecd
# vfat.c a3e46021c1a0b3aa54913baf26165b79c25fb2e1517a2b5cfdd3025e85d3747a
# exfat.c 3c369ecf56443740c1ec3c9c2a7f8ee3459323816856a1f87a3e150b90fab910
# ntfs.c 01765b0dc482932427423eab2f40d0e6c3710dd8f6d0c5635f4cff94bdb40582
# udf.c  f541fec8dfff3792e6b6bc2e07c29887c66b2bf64c925cd8bcbd9e9ddb3e6a0c
# iso9660.c 601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b
# superblocks.c 62932658adaef2c0d27322d5d191afe17762a41583e8163b4223f0e2173daa41
#
# UUID parser split: VFAT/exFAT, NTFS, ext-family and reviewed UDF producers use
# constrained forms that do not establish shell-active bytes. ISO9660 is the
# exception: its UUID formatter consumes 16 raw date bytes after only an
# all-ASCII-'0' test, and safe_string preserves allowed shell/path-sensitive
# bytes. The dispatcher proves UUID/alternate—not label—is the path component.
# Label-path and no-UUID shell-active routes remain rejected, but a combined
# filesystem-metadata rejection is withdrawn. Physical ISO9660 media control,
# acceptance/mount, installed delivery, authentication, success and impact are
# separate unknowns.
