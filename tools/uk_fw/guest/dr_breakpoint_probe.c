/*
 * dr_breakpoint_probe.c — VM-only capability probe for guest hardware
 * execution breakpoints under the recovered Gen5W kernel.
 *
 * It answers the question that gates the EC-02 mechanism: can a tracer arm
 * DR0/DR7 for an execute breakpoint on a peer thread, observe the trap, read
 * the DR6 status, then restore the registers and let the tracee finish
 * cleanly? It touches no vendor code and is not part of any observer.
 *
 * Tests:
 *   T1  no breakpoint armed        -> tracee must exit 0 with no trap
 *   T2  DR0/DR7 armed              -> trap at RIP == &probe_target, DR6.B0 set
 *   T3  after clearing DR7/DR0     -> tracee runs on and exits 0, no re-trap
 *   T4  PTRACE_SINGLESTEP          -> exactly one trap, RIP advances
 *
 * Exit status 0 only when T1..T4 all behave as required.
 *
 * Build:
 *   zig cc -target x86_64-linux-musl -static -O2 -Wall -Wextra -Werror \
 *       -o dr-breakpoint-probe dr_breakpoint_probe.c
 */

#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define DR_STATUS 6
#define DR_CONTROL 7

/* DR7: L0 enables local slot 0; RW0=LEN0=0 selects execute. */
#define DR7_L0 0x1UL
/* DR7 bits 10 and 11 read as 1 and must not be cleared on this arch. */
#define DR7_RESERVED 0x400UL
/* DR6: B0 reports slot 0 fired. */
#define DR6_B0 0x1UL

static void say(const char *fmt, ...)
{
    va_list ap;

    fputs("DR-PROBE ", stdout);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

static long dr_offset(int index)
{
    return (long)offsetof(struct user, u_debugreg) +
           (long)index * (long)sizeof(unsigned long long);
}

static int dr_read(pid_t pid, int index, unsigned long long *out)
{
    long v;

    errno = 0;
    v = ptrace(PTRACE_PEEKUSER, pid, (void *)dr_offset(index), NULL);
    if (v == -1 && errno != 0) {
        say("peek DR%d failed errno=%d (%s)", index, errno,
            strerror(errno));
        return -1;
    }
    *out = (unsigned long long)v;
    return 0;
}

static int dr_write(pid_t pid, int index, unsigned long long value)
{
    errno = 0;
    if (ptrace(PTRACE_POKEUSER, pid, (void *)dr_offset(index),
               (void *)(unsigned long)value) == -1) {
        say("poke DR%d=0x%llx failed errno=%d (%s)", index, value, errno,
            strerror(errno));
        return -1;
    }
    return 0;
}

__attribute__((noinline, used)) static void probe_target(void)
{
    __asm__ __volatile__("" ::: "memory");
}

__attribute__((noinline, used)) static void control_target(void)
{
    __asm__ __volatile__("" ::: "memory");
}

static void child_body(void)
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        _exit(10);
    }
    /* Stop before any user code so the tracer arms registers first. */
    if (raise(SIGSTOP) != 0) {
        _exit(11);
    }
    control_target();
    probe_target();
    _exit(0);
}

static pid_t spawn_tracee(int *status)
{
    pid_t pid = fork();

    if (pid == 0) {
        child_body();
    }
    if (pid < 0) {
        return -1;
    }
    if (waitpid(pid, status, 0) != pid || !WIFSTOPPED(*status)) {
        return -1;
    }
    return pid;
}

static int read_rip(pid_t pid, unsigned long long *rip)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        return -1;
    }
    *rip = (unsigned long long)regs.rip;
    return 0;
}

static int test_negative_control(void)
{
    int status = 0;
    pid_t pid = spawn_tracee(&status);

    if (pid < 0) {
        say("T1 FAIL cannot reach initial stop");
        return 1;
    }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        say("T1 FAIL cont errno=%d", errno);
        return 1;
    }
    if (waitpid(pid, &status, 0) != pid) {
        say("T1 FAIL waitpid");
        return 1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        say("T1 pass no-trap control exit=0");
        return 0;
    }
    if (WIFSTOPPED(status)) {
        say("T1 FAIL unexpected stop sig=%d", WSTOPSIG(status));
    } else {
        say("T1 FAIL unexpected termination status=0x%x", status);
    }
    return 1;
}

/* T2 + T3: arm, observe the trap, restore, then require a clean exit. */
static int test_execute_breakpoint(void)
{
    int status = 0;
    int rc = 1;
    unsigned long long dr7_before = 0, dr7_armed = 0, dr6 = 0, rip = 0;
    unsigned long addr = (unsigned long)(void (*)(void))probe_target;
    pid_t pid = spawn_tracee(&status);

    if (pid < 0) {
        say("T2 FAIL cannot reach initial stop");
        return 1;
    }
    if (dr_read(pid, DR_CONTROL, &dr7_before) != 0) {
        say("T2 FAIL cannot read DR7 baseline");
        return 1;
    }
    say("T2 DR7 baseline=0x%llx target=0x%lx", dr7_before, addr);

    if (dr_write(pid, 0, (unsigned long long)addr) != 0) {
        say("T2 FAIL cannot set DR0");
        return 1;
    }
    if (dr_write(pid, DR_CONTROL, dr7_before | DR7_RESERVED | DR7_L0) != 0) {
        say("T2 FAIL cannot enable DR7.L0");
        return 1;
    }
    if (dr_read(pid, DR_CONTROL, &dr7_armed) != 0) {
        say("T2 FAIL cannot read DR7 back");
        return 1;
    }
    if ((dr7_armed & DR7_L0) == 0) {
        say("T2 FAIL DR7.L0 did not stick readback=0x%llx", dr7_armed);
        return 1;
    }
    say("T2 DR7 armed=0x%llx L0=set", dr7_armed);

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        say("T2 FAIL cont errno=%d", errno);
        return 1;
    }
    if (waitpid(pid, &status, 0) != pid) {
        say("T2 FAIL waitpid after arming");
        return 1;
    }
    if (WIFEXITED(status)) {
        say("T2 FAIL tracee exited (%d) without trapping on 0x%lx",
            WEXITSTATUS(status), addr);
        return 1;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        say("T2 FAIL stop was not SIGTRAP status=0x%x", status);
        return 1;
    }
    if (read_rip(pid, &rip) != 0) {
        say("T2 FAIL GETREGS after trap");
        return 1;
    }
    if (dr_read(pid, DR_STATUS, &dr6) != 0) {
        dr6 = 0;
    }
    say("T2 trap sig=SIGTRAP rip=0x%llx expected=0x%lx DR6=0x%llx", rip, addr,
        dr6);

    if (rip != (unsigned long long)addr) {
        say("T2 FAIL trap RIP does not match the armed address");
        return 1;
    }
    if (dr6 != 0 && (dr6 & DR6_B0) == 0) {
        say("T2 note DR6 readable but B0 clear while RIP matched");
    }
    say("T2 pass execute breakpoint fired at the armed address");

    /* T3: disarm, then the tracee must continue and exit cleanly. */
    if (dr_write(pid, DR_CONTROL, dr7_before) != 0) {
        say("T3 FAIL cannot restore DR7");
        return 1;
    }
    if (dr_write(pid, 0, 0) != 0) {
        say("T3 FAIL cannot clear DR0");
        return 1;
    }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        say("T3 FAIL cont after disarm errno=%d", errno);
        return 1;
    }
    if (waitpid(pid, &status, 0) != pid) {
        say("T3 FAIL waitpid after disarm");
        return 1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        say("T3 pass restored and tracee exited 0 with no further trap");
        rc = 0;
    } else if (WIFSTOPPED(status)) {
        say("T3 FAIL re-trapped sig=%d after disarm", WSTOPSIG(status));
    } else {
        say("T3 FAIL unexpected termination status=0x%x", status);
    }
    return rc;
}

static int test_single_step(void)
{
    int status = 0;
    unsigned long long rip0 = 0, rip1 = 0;
    pid_t pid = spawn_tracee(&status);

    if (pid < 0) {
        say("T4 FAIL cannot reach initial stop");
        return 1;
    }
    if (read_rip(pid, &rip0) != 0) {
        say("T4 FAIL GETREGS");
        return 1;
    }
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        say("T4 FAIL singlestep errno=%d (%s)", errno, strerror(errno));
        return 1;
    }
    if (waitpid(pid, &status, 0) != pid) {
        say("T4 FAIL waitpid");
        return 1;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        say("T4 FAIL no single-step trap status=0x%x", status);
        return 1;
    }
    if (read_rip(pid, &rip1) != 0) {
        say("T4 FAIL GETREGS after step");
        return 1;
    }
    say("T4 step rip 0x%llx -> 0x%llx", rip0, rip1);
    if (rip1 == rip0) {
        say("T4 FAIL RIP did not advance");
        return 1;
    }

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);
    say("T4 pass single step advanced RIP");
    return 0;
}

int main(void)
{
    int failures = 0;

    if (test_negative_control() != 0) {
        failures++;
    }
    if (test_execute_breakpoint() != 0) {
        failures++;
    }
    if (test_single_step() != 0) {
        failures++;
    }

    if (failures == 0) {
        say("RESULT hardware-execute-breakpoint=SUPPORTED");
        return 0;
    }
    say("RESULT hardware-execute-breakpoint=UNSUPPORTED failures=%d", failures);
    return 1;
}
