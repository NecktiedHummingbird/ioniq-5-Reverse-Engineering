# Recovered ALSA timer semantic-backport evidence
#
# Input: exact recovered snd-timer.ko
# SHA-256: 3b2fa4e722ff210c2643089b2035a4ba93134ad1624e0c520bafa6debac46a91
# GNU Build ID: 42457bdb4c6cd4911a707afac6912e23d735b68a
# ELF: x86-64 ET_REL; .text file offset 0x64, size 0x2d44
# Tool: Homebrew LLVM llvm-objdump 23.1.3, Intel syntax, relocations shown
#
# CVE-2016-2546: open initializes the mutex at snd_timer_user+0x90, then stores
# that same object in file+0xd0. Ioctl and release reload file+0xd0 and use the
# same +0x90 mutex. The only ioctl file-operations relocation points to 0x236d;
# the function has one return, and every returning route passes the unlock at
# section-relative 0x2cda (stack-check failure is non-returning).

0000000000001a4a <snd_timer_user_open>:
    1a9e: 48 8d bb 90 00 00 00          lea rdi, [rbx + 0x90]
    1ab3: e8 00 00 00 00                call 0x1ab8
        0000000000001ab4: R_X86_64_PC32 __mutex_init-0x4
    ...
    1af0: 49 89 9c 24 d0 00 00 00       mov qword ptr [r12 + 0xd0], rbx

000000000000236d <snd_timer_user_ioctl>:
    2398: 48 8b 87 d0 00 00 00          mov rax, qword ptr [rdi + 0xd0]
    239f: 4c 8d a8 90 00 00 00          lea r13, [rax + 0x90]
    23a6: 4c 89 ef                      mov rdi, r13
    23a9: e8 00 00 00 00                call 0x23ae
        00000000000023aa: R_X86_64_PC32 mutex_lock-0x4
    23ae: 81 fb 02 54 04 40             cmp ebx, 0x40045402
    ...
    2cd3: 48 c7 c3 e7 ff ff ff          mov rbx, -0x19
    2cda: 4c 89 ef                      mov rdi, r13
    2cdd: e8 00 00 00 00                call 0x2ce2
        0000000000002cde: R_X86_64_PC32 mutex_unlock-0x4
    2d32: 48 81 c4 b8 00 00 00          add rsp, 0xb8
    2d43: c3                            ret

00000000000017cc <snd_timer_user_release>:
    17df: 4c 8d a3 90 00 00 00          lea r12, [rbx + 0x90]
    17f1: 4c 89 e7                      mov rdi, r12
    17f4: e8 00 00 00 00                call 0x17f9
        00000000000017f5: R_X86_64_PC32 mutex_lock-0x4
    17f9: 48 8b 3b                      mov rdi, qword ptr [rbx]
    1801: e8 00 00 00 00                call 0x1806
        0000000000001802: R_X86_64_PC32 snd_timer_close-0x4
    1806: 4c 89 e7                      mov rdi, r12
    1809: e8 00 00 00 00                call 0x180e
        000000000000180a: R_X86_64_PC32 mutex_unlock-0x4

# CVE-2016-2545: [rbp-0x38] holds the current timeri derived from the timer's
# active list. rdi is derived from that same object as timeri+0x80, with no call
# or object substitution before the exact list_del_init. The non-auto expiry
# path clears RUNNING and decrements timer->running before the call; this is its
# only active-list deletion and dominates continuation of that expiry path.

000000000000111e <snd_timer_interrupt>:
    11a8: 48 8b 45 c8                   mov rax, qword ptr [rbp - 0x38]
    11ac: 48 8d b8 80 00 00 00          lea rdi, [rax + 0x80]
    ...
    121a: a8 08                         test al, 0x8
    121c: 74 0a                         je 0x1228
    ...
    1228: 48 8b 4d c8                   mov rcx, qword ptr [rbp - 0x38]
    122c: 83 e0 fd                      and eax, -0x3
    122f: 89 41 10                      mov dword ptr [rcx + 0x10], eax
    1232: ff 8b b4 00 00 00             dec dword ptr [rbx + 0xb4]
    1238: e8 06 fc ff ff                call 0xe43 <list_del_init>

# CVE-2016-2547: all global slave-active lock relocations below name the same
# singleton .bss+0x290. Every nested timer lock is derived as +0x130 from the
# exact timer object associated with the master. Attach, close, delayed start,
# and slave stop consistently acquire global-before-timer.
# Hunk 1: slave-active lock is followed by master timer lock; master/timer
# assignment and active-list insertion occur inside both locks.

0000000000001da9 <snd_timer_open>:
    209d: e8 5e df ff ff                call 0x0 <list_move_tail>
    20a9: e8 00 00 00 00                call 0x20ae
        00000000000020aa: R_X86_64_PC32 _raw_spin_lock_irq-0x4
    20ae: 48 8b 03                      mov rax, qword ptr [rbx]
    20b1: 48 8d b8 30 01 00 00          lea rdi, [rax + 0x130]
    20b8: e8 00 00 00 00                call 0x20bd
        00000000000020b9: R_X86_64_PC32 _raw_spin_lock-0x4
    20c3: 49 89 9c 24 c0 00 00 00       mov qword ptr [r12 + 0xc0], rbx
    20cb: 48 8b 03                      mov rax, qword ptr [rbx]
    20ce: 49 89 04 24                   mov qword ptr [r12], rax
    ...
    210e: e8 13 df ff ff                call 0x26 <__raw_spin_unlock>
    211a: e8 17 df ff ff                call 0x36 <__raw_spin_unlock_irq>

# CVE-2016-2547 hunk 2: close acquires the global slave-active lock and timer
# lock around slave unlinking, nulling, and ack/active list_del_init operations.

00000000000015ad <snd_timer_close>:
    16ea: e8 00 00 00 00                call 0x16ef
        00000000000016eb: R_X86_64_PC32 _raw_spin_lock_irq-0x4
    16ef: 4c 89 ef                      mov rdi, r13
    16f2: e8 00 00 00 00                call 0x16f7
        00000000000016f3: R_X86_64_PC32 _raw_spin_lock-0x4
    ...
    1720: e8 db e8 ff ff                call 0x0 <list_move_tail>
    1725: 48 8d b9 90 00 00 00          lea rdi, [rcx + 0x90]
    172c: 48 c7 81 c0 00 00 00 00 00 00 00  mov qword ptr [rcx + 0xc0], 0x0
    1737: 48 c7 01 00 00 00 00          mov qword ptr [rcx], 0x0
    173e: e8 00 f7 ff ff                call 0xe43 <list_del_init>
    1743: 48 8d b9 80 00 00 00          lea rdi, [rcx + 0x80]
    174a: e8 f4 f6 ff ff                call 0xe43 <list_del_init>
    ...
    175f: e8 c2 e8 ff ff                call 0x26 <__raw_spin_unlock>
    176b: e8 c6 e8 ff ff                call 0x36 <__raw_spin_unlock_irq>

# CVE-2016-2547 hunk 3: start_slave checks both master and timer, then nests the
# timer lock inside slave_active_lock around active-list insertion.

00000000000000d0 <snd_timer_start_slave>:
      e3: e8 00 00 00 00                call 0xe8
        00000000000000e4: R_X86_64_PC32 _raw_spin_lock_irqsave-0x4
     10c: 48 83 bb c0 00 00 00 00       cmp qword ptr [rbx + 0xc0], 0x0
     117: 74 5f                         je 0x178
     119: 48 8b 3b                      mov rdi, qword ptr [rbx]
     11c: 48 85 ff                      test rdi, rdi
     11f: 74 57                         je 0x178
     121: 48 81 c7 30 01 00 00          add rdi, 0x130
     12c: e8 00 00 00 00                call 0x131
        000000000000012d: R_X86_64_PC32 _raw_spin_lock-0x4
     131: 48 8b 93 c0 00 00 00          mov rdx, qword ptr [rbx + 0xc0]
     138: 48 8d 8b 80 00 00 00          lea rcx, [rbx + 0x80]
     ...
     16f: e8 b2 fe ff ff                call 0x26 <__raw_spin_unlock>
     17f: e8 00 00 00 00                call 0x184
        0000000000000180: R_X86_64_PC32 _raw_spin_unlock_irqrestore-0x4

# CVE-2016-2547 hunk 4: _snd_timer_stop's unlocked-master branch removes both
# ack and active links with list_del_init under slave_active_lock.

0000000000000f03 <_snd_timer_stop>:
     f33: e8 00 00 00 00                call 0xf38
        0000000000000f34: R_X86_64_PC32 _raw_spin_lock_irqsave-0x4
     ...
     f62: 48 8d 7b 90                   lea rdi, [rbx + 0x90]
     f6e: e8 d0 fe ff ff                call 0xe43 <list_del_init>
     f73: 48 8d 7b 80                   lea rdi, [rbx + 0x80]
     f7a: e8 c4 fe ff ff                call 0xe43 <list_del_init>
