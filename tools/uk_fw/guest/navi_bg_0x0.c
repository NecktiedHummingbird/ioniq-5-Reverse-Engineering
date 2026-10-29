/*
 * navi_bg_0x0.c — drive AppNavi's surface to a real 0x0 configure.
 *
 * Why this exists: ApplicationManager only latches its navigation window byte on
 * a background (BG) window notification, and the IVI compositor classifies a
 * surface as BG only when both its width and height are non-positive. AppNavi
 * never hides its surface, so the latch never sets.
 *
 * A single null-buffer attach is not enough. In weston_surface_commit_state the
 * size block at 0x40f470 stores the previous `width_from_buffer` before the
 * null-buffer branch at 0x40f813 zeroes that field, so the first null attach
 * keeps the old positive size. A *second* null attach enters the same block with
 * `width_from_buffer` already zero and therefore stores 0x0.
 *
 * So this interposer passes a NULL buffer on the first two commits of the first
 * surface the client touches, once the trigger file exists. It relies only on
 * the vendor compositor's own behaviour: it does not call ApplicationManager,
 * write the window byte, or synthesise any notification.
 *
 * Trigger: the file named by NAVI_BG_TRIGGER (default /tmp/navi-bg-trigger).
 *
 * Build:
 *   zig cc -target x86_64-linux-musl -shared -fPIC -O2 -Wall -Wextra -Werror \
 *       -o navi-bg-0x0.so navi_bg_0x0.c
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define DEFAULT_TRIGGER "/tmp/navi-bg-trigger"
/*
 * Behaviour when the trigger file exists: every attach on the target surface is
 * replaced with a NULL-buffer attach, i.e. the surface is held at 0x0 for as long
 * as the trigger exists. A short burst of two attaches was tried first and the
 * manager still reported no change; a single frame is likely too brief for the
 * compositor to act on, so the surface is held instead. Removing the trigger file
 * restores normal attaching.
 */
/* Probe the trigger file at most once per this many attach calls. */
#define PROBE_INTERVAL 64u

typedef struct wl_surface wl_surface;
typedef struct wl_buffer wl_buffer;

typedef void (*attach_fn)(wl_surface *, wl_buffer *, int, int);

static attach_fn real_attach;
static wl_surface *target_surface;
static int hits;
static unsigned int calls;
static int held;
static int logged_first;
static unsigned int hold_count;

/* Append a line to the audit log so a run can prove the interposer executed and
 * how often it suppressed an attach. Without this, "no manager change" is
 * indistinguishable from "adapter never fired". */
static void audit(const char *what, unsigned int n)
{
    FILE *f = fopen("/tmp/navi-bg.log", "a");

    if (f == NULL) {
        return;
    }
    fprintf(f, "%s n=%u\n", what, n);
    fflush(f);
    fclose(f);
}

/* True only inside the authentic AppNavi process. LD_PRELOAD is inherited by
 * every launcher child, so acting on the first attaching app would hide Home
 * instead of Navigation. The answer is cached: it cannot change per process. */
static int is_appnavi(void)
{
    static int cached = -1;
    char buf[300];
    int fd;
    ssize_t n;

    if (cached >= 0) {
        return cached;
    }
    cached = 0;
    fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) {
        return cached;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
        buf[n] = '\0';
        if (strstr(buf, "AppNavi") != NULL) {
            cached = 1;
        }
    }
    return cached;
}

static void ensure_real(void)
{
    if (real_attach == NULL) {
        real_attach = (attach_fn)dlsym(RTLD_NEXT, "wl_surface_attach");
    }
}

static int trigger_present(void)
{
    const char *path = getenv("NAVI_BG_TRIGGER");

    if (path == NULL || path[0] == '\0') {
        path = DEFAULT_TRIGGER;
    }
    return access(path, F_OK) == 0;
}

void wl_surface_attach(wl_surface *surface, wl_buffer *buffer, int x, int y)
{
    ensure_real();
    if (real_attach == NULL) {
        return;
    }
    if (!is_appnavi()) {
        real_attach(surface, buffer, x, y);
        return;
    }

    /*
     * Elect the first surface the client attaches to as the target. AppNavi has
     * a parent surface and a map-widget child; only the parent should collapse.
     */
    if (target_surface == NULL) {
        target_surface = surface;
    }
    if (surface != target_surface) {
        real_attach(surface, buffer, x, y);
        return;
    }

    /*
     * Probe the trigger on a sample of calls, then act on the cached answer so a
     * stat() does not run on every frame.
     */
    calls++;
    if ((calls % PROBE_INTERVAL) == 0u) {
        held = trigger_present();
    }

    if (held) {
        hits++;
        hold_count++;
        if (!logged_first) {
            logged_first = 1;
            audit("first-hold", hold_count);
        } else if ((hold_count % 64u) == 0u) {
            audit("hold", hold_count);
        }
        real_attach(surface, NULL, 0, 0);
        return;
    }
    if (logged_first && !held) {
        audit("released", hold_count);
        logged_first = 0;
    }

    real_attach(surface, buffer, x, y);
}
