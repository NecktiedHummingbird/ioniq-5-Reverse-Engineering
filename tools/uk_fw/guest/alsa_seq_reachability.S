/* Freestanding Linux/x86-64 ALSA sequencer reachability diagnostic.
 * Opens /dev/snd/seq read-only, obtains its client ID, creates one empty port,
 * deletes it, and exits. No race, heap grooming, payload, or privilege action.
 */
.text
.globl _start
_start:
    subq $512, %rsp
    movq %rsp, %r12

    leaq .Ldevice(%rip), %rdi
    movl $0x800, %esi              /* O_RDONLY | O_NONBLOCK */
    xorl %edx, %edx
    movl $2, %eax                  /* open */
    syscall
    testq %rax, %rax
    js .Lopen_fail
    movq %rax, %rbx
    leaq .Lopen_ok(%rip), %rsi
    movl $.Lopen_ok_end-.Lopen_ok, %edx
    call .Lwrite

    movl $0, (%r12)
    movq %rbx, %rdi
    movl $0x80045301, %esi         /* SNDRV_SEQ_IOCTL_CLIENT_ID */
    movq %r12, %rdx
    movl $16, %eax                 /* ioctl */
    syscall
    testq %rax, %rax
    js .Lclient_fail
    leaq .Lclient_ok(%rip), %rsi
    movl $.Lclient_ok_end-.Lclient_ok, %edx
    call .Lwrite

    /* struct snd_seq_port_info is 0xa8 bytes in this ABI. */
    leaq 32(%r12), %r13
    movq %r13, %rdi
    xorl %eax, %eax
    movl $21, %ecx
    rep stosq
    movl (%r12), %eax
    movb %al, 0(%r13)              /* addr.client */
    movl $1, 68(%r13)              /* SNDRV_SEQ_PORT_CAP_READ */
    movl $0x100000, 72(%r13)       /* SNDRV_SEQ_PORT_TYPE_APPLICATION */
    movabsq $0x000065626f727070, %rax /* "pprobe\0" */
    movq %rax, 2(%r13)

    movq %rbx, %rdi
    movl $0xc0a85320, %esi         /* SNDRV_SEQ_IOCTL_CREATE_PORT */
    movq %r13, %rdx
    movl $16, %eax
    syscall
    testq %rax, %rax
    js .Lcreate_fail
    leaq .Lcreate_ok(%rip), %rsi
    movl $.Lcreate_ok_end-.Lcreate_ok, %edx
    call .Lwrite

    movq %rbx, %rdi
    movl $0x40a85321, %esi         /* SNDRV_SEQ_IOCTL_DELETE_PORT */
    movq %r13, %rdx
    movl $16, %eax
    syscall
    testq %rax, %rax
    js .Ldelete_fail
    leaq .Ldelete_ok(%rip), %rsi
    movl $.Ldelete_ok_end-.Ldelete_ok, %edx
    call .Lwrite

    movq %rbx, %rdi
    movl $3, %eax                  /* close */
    syscall
    xorl %edi, %edi
    jmp .Lexit

.Lopen_fail:
    leaq .Lopen_bad(%rip), %rsi
    movl $.Lopen_bad_end-.Lopen_bad, %edx
    movl $10, %edi
    jmp .Lfail
.Lclient_fail:
    leaq .Lclient_bad(%rip), %rsi
    movl $.Lclient_bad_end-.Lclient_bad, %edx
    movl $11, %edi
    jmp .Lfail
.Lcreate_fail:
    leaq .Lcreate_bad(%rip), %rsi
    movl $.Lcreate_bad_end-.Lcreate_bad, %edx
    movl $12, %edi
    jmp .Lfail
.Ldelete_fail:
    leaq .Ldelete_bad(%rip), %rsi
    movl $.Ldelete_bad_end-.Ldelete_bad, %edx
    movl $13, %edi
.Lfail:
    pushq %rdi
    call .Lwrite
    popq %rdi
.Lexit:
    movl $60, %eax                 /* exit */
    syscall

.Lwrite:
    movl $1, %eax                  /* write stdout */
    movl $1, %edi
    syscall
    ret

.Ldevice: .asciz "/dev/snd/seq"
.Lopen_ok: .ascii "ALSA_SEQ_OPEN_OK\n"
.Lopen_ok_end:
.Lclient_ok: .ascii "ALSA_SEQ_CLIENT_ID_OK\n"
.Lclient_ok_end:
.Lcreate_ok: .ascii "ALSA_SEQ_CREATE_PORT_OK\n"
.Lcreate_ok_end:
.Ldelete_ok: .ascii "ALSA_SEQ_DELETE_PORT_OK\n"
.Ldelete_ok_end:
.Lopen_bad: .ascii "ALSA_SEQ_OPEN_FAIL\n"
.Lopen_bad_end:
.Lclient_bad: .ascii "ALSA_SEQ_CLIENT_ID_FAIL\n"
.Lclient_bad_end:
.Lcreate_bad: .ascii "ALSA_SEQ_CREATE_PORT_FAIL\n"
.Lcreate_bad_end:
.Ldelete_bad: .ascii "ALSA_SEQ_DELETE_PORT_FAIL\n"
.Ldelete_bad_end:
