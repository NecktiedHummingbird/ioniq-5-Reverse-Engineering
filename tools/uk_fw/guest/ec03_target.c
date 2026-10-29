/*
 * ec03_target.c — synthetic target for validating the minimal observer.
 *
 * Prints its pid and the address of the function to be instrumented, waits long
 * enough for a tracer to attach and arm, then calls that function three times.
 * The observer disarms a slot after its first hit, so a correct run shows exactly
 * one hit and a clean exit.
 *
 * Build:
 *   zig cc -target x86_64-linux-musl -static -O2 -Wall -Wextra -Werror \
 *       -o ec03-target ec03_target.c
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>

__attribute__((noinline, used)) static void probe_target(void)
{
    __asm__ __volatile__("" ::: "memory");
}

int main(void)
{
    int i;

    printf("PID %d ADDR 0x%lx\n", (int)getpid(),
           (unsigned long)(void (*)(void))probe_target);
    fflush(stdout);

    /* Give the tracer time to attach and arm before the first call. */
    sleep(3);
    for (i = 0; i < 3; i++) {
        probe_target();
    }
    printf("TARGET done calls=3\n");
    fflush(stdout);
    return 0;
}
