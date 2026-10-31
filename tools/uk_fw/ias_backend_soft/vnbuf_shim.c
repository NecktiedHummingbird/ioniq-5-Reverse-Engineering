#include <dlfcn.h>
/* vnbuf_shim — research adaptor for a client that commits surfaces without
 * ever attaching a buffer.
 *
 * Measured on AppHomeScreen in this build: five wl_surface.commit calls and zero
 * wl_surface.attach calls of any kind, so the compositor has a view whose surface
 * has no contents and correctly renders black. Attaching is therefore intercepted
 * at commit, not at attach: on the first commit for a surface, a known shm buffer
 * is attached first.
 *
 * Purpose: prove the emulation stack end to end (backend, CRTC, IAS shell,
 * renderer, capture) and isolate the client's omission as the only remaining
 * defect. This is a shim, not vendor behaviour.
 */
#define _GNU_SOURCE
#include <wayland-client-core.h>
#include <wayland-util.h>

/* Every libwayland symbol is resolved at runtime. Linking against the guest's
 * libwayland-client is not possible from this cross build, and leaving them
 * undefined makes LD_PRELOAD fail eagerly at load time. */
struct wl_registry *(*p_wl_display_get_registry)(struct wl_display *);
int (*p_wl_registry_add_listener)(struct wl_registry *, const void *, void *);
void *(*p_wl_registry_bind)(struct wl_registry *, uint32_t, const struct wl_interface *, uint32_t);
int (*p_wl_display_roundtrip)(struct wl_display *);
struct wl_shm_pool *(*p_wl_shm_create_pool)(struct wl_shm *, int32_t, int32_t);
struct wl_buffer *(*p_wl_shm_pool_create_buffer)(struct wl_shm_pool *, int32_t, int32_t, int32_t, int32_t, uint32_t);
void (*p_wl_shm_pool_destroy)(struct wl_shm_pool *);

static void resolve(void)
{
	p_wl_display_get_registry = dlsym(RTLD_DEFAULT, "wl_display_get_registry");
	p_wl_registry_add_listener = dlsym(RTLD_DEFAULT, "wl_registry_add_listener");
	p_wl_registry_bind = dlsym(RTLD_DEFAULT, "wl_registry_bind");
	p_wl_display_roundtrip = dlsym(RTLD_DEFAULT, "wl_display_roundtrip");
	p_wl_shm_create_pool = dlsym(RTLD_DEFAULT, "wl_shm_create_pool");
	p_wl_shm_pool_create_buffer = dlsym(RTLD_DEFAULT, "wl_shm_pool_create_buffer");
	p_wl_shm_pool_destroy = dlsym(RTLD_DEFAULT, "wl_shm_pool_destroy");
}

struct wl_registry_listener { void (*global)(void *, struct wl_registry *, uint32_t, const char *, uint32_t); void (*global_remove)(void *, struct wl_registry *, uint32_t); };
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdarg.h>

#define WIDTH 1920
#define HEIGHT 720
#define LOG "/dev/ttyS0"
#ifndef WL_SHM_FORMAT_ARGB8888
#define WL_SHM_FORMAT_ARGB8888 0
#endif

static struct wl_display *g_display;
static struct wl_shm *g_shm;
static struct wl_buffer *g_dummy;
static struct wl_surface *seen[64];
static int seen_n;
static int attached_n;
static int log_fd = -1;

static void say(const char *fmt, ...)
{
	va_list ap;
	char buf[256];

	if (log_fd < 0)
		log_fd = open(LOG, O_WRONLY);
	if (log_fd < 0)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	dprintf(log_fd, "vnbuf: %s", buf);
}


static void reg_global(void *d, struct wl_registry *r, uint32_t name,
		       const char *iface, uint32_t ver)
{
	(void)d; (void)ver;
	if (strcmp(iface, "wl_shm") == 0) {
		/* Resolved at runtime: a data symbol in the preloaded object would
		 * otherwise have to be resolved eagerly and fails at load time. */
		const struct wl_interface *iface_ptr =
			(const struct wl_interface *) dlsym(RTLD_DEFAULT, "wl_shm_interface");
		if (!iface_ptr) {
			say("wl_shm_interface not found\n");
			return;
		}
		g_shm = p_wl_registry_bind(r, name, iface_ptr, 1);
		say("bound wl_shm\n");
	}
}
static void reg_remove(void *d, struct wl_registry *r, uint32_t n) { (void)d; (void)r; (void)n; }
static const struct wl_registry_listener reg_listener = { reg_global, reg_remove };

struct wl_display *wl_display_connect(const char *name)
{
	static struct wl_display *(*real)(const char *);
	struct wl_display *d;
	struct wl_registry *reg;

	if (!real)
		real = dlsym(RTLD_NEXT, "wl_display_connect");
	d = real(name);
	if (d && !g_display) {
		g_display = d;
		resolve();
		reg = p_wl_display_get_registry(d);
		p_wl_registry_add_listener(reg, &reg_listener, NULL);
		p_wl_display_roundtrip(d);
		say("connected, shm=%p\n", (void *) g_shm);
	}
	return d;
}

static int make_dummy(void)
{
	int stride = WIDTH * 4;
	int size = stride * HEIGHT;
	char tmpl[] = "/tmp/vnbuf-XXXXXX";
	int fd = mkstemp(tmpl);
	struct wl_shm_pool *pool;
	uint32_t *p;

	if (fd < 0)
		return -1;
	unlink(tmpl);
	if (ftruncate(fd, size) < 0) { close(fd); return -1; }
	p = mmap(NULL, (size_t) size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) { close(fd); return -1; }
	/* Solid, unmistakable colour: opaque magenta. */
	for (int i = 0; i < WIDTH * HEIGHT; i++)
		p[i] = 0xFFFF00FFu;
	munmap(p, (size_t) size);

	pool = p_wl_shm_create_pool(g_shm, fd, size);
	g_dummy = p_wl_shm_pool_create_buffer(pool, 0, WIDTH, HEIGHT, stride,
					    WL_SHM_FORMAT_ARGB8888);
	p_wl_shm_pool_destroy(pool);
	close(fd);
	say("created dummy buffer %p (%dx%d)\n", (void *) g_dummy, WIDTH, HEIGHT);
	return g_dummy ? 0 : -1;
}

void wl_surface_commit(struct wl_surface *surface)
{
	static void (*real_commit)(struct wl_surface *);
	static void (*real_attach)(struct wl_surface *, struct wl_buffer *, int32_t, int32_t);
	int known = 0;

	if (!real_commit)
		real_commit = dlsym(RTLD_NEXT, "wl_surface_commit");
	if (!real_attach)
		real_attach = dlsym(RTLD_NEXT, "wl_surface_attach");

	for (int i = 0; i < seen_n; i++)
		if (seen[i] == surface)
			known = 1;

	if (!known && g_shm) {
		if (seen_n < (int) (sizeof seen / sizeof seen[0]))
			seen[seen_n++] = surface;
		if (!g_dummy)
			make_dummy();
		if (g_dummy) {
			real_attach(surface, g_dummy, 0, 0);
			attached_n++;
			say("attached dummy to surface %p (n=%d)\n",
			    (void *) surface, attached_n);
		}
	}
	real_commit(surface);
}
