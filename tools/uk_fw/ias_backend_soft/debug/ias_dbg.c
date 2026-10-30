/* Diagnostic scaffolding for the ias-backend-soft crash hunt. Not shipped. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <execinfo.h>
#include <ucontext.h>

#include "ias_dbg.h"

static int g_fd = -1;

int
ias_dbg_fd(void)
{
	if (g_fd < 0)
		g_fd = open("/dev/console", O_WRONLY | O_NOCTTY);
	if (g_fd < 0)
		g_fd = 2;
	return g_fd;
}

void
ias_dbg(const char *fmt, ...)
{
	char buf[512];
	int n = 0, fd;
	va_list ap;

	n += snprintf(buf, sizeof buf, "[IAS] ");
	va_start(ap, fmt);
	n += vsnprintf(buf + n, sizeof buf - n, fmt, ap);
	va_end(ap);
	if (n > (int) sizeof buf - 2)
		n = (int) sizeof buf - 2;
	buf[n++] = '\n';
	fd = ias_dbg_fd();
	if (write(fd, buf, n) < 0)
		;
}

static void
ias_trap(int sig, siginfo_t *si, void *uc)
{
	void *bt[48];
	int n;

	ias_dbg("SIGNAL %d fault_addr=%p", sig, si ? si->si_addr : NULL);
#ifdef REG_RIP
	if (uc)
		ias_dbg("RIP=%#llx",
			(unsigned long long)
			((ucontext_t *) uc)->uc_mcontext.gregs[REG_RIP]);
#endif
	n = backtrace(bt, 48);
	backtrace_symbols_fd(bt, n, ias_dbg_fd());
	_exit(9);
}

void
ias_dbg_trap(void)
{
	static char altstack[65536];
	stack_t ss;
	struct sigaction sa;

	memset(&ss, 0, sizeof ss);
	ss.ss_sp = altstack;
	ss.ss_size = sizeof altstack;
	sigaltstack(&ss, NULL);

	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = ias_trap;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	ias_dbg("trap installed");
}
