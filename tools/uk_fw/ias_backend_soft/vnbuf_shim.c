/* vnbuf_shim — research adaptor for a client that commits surfaces without ever
 * attaching a buffer.
 *
 * Measured on AppHomeScreen in this build: commits with zero wl_surface.attach
 * calls, so the compositor has a view whose surface has no contents and correctly
 * renders black.
 *
 * Interposition point: wl_proxy_marshal_array, NOT wl_surface_commit. The latter
 * is a static inline wrapper in wayland-client's generated header, so clients never
 * reference the exported symbol and hooking it does nothing (verified: the object was
 * mapped into a committing client and never called). All client requests funnel
 * through the array marshaller, which is non-variadic and therefore safe to wrap.
 *
 * On a wl_surface commit (opcode 6) that has not yet seen an attach, a known opaque
 * magenta ARGB8888 buffer is attached (opcode 1) first.
 *
 * This is a shim, not vendor behaviour: it proves the emulation stack end to end and
 * isolates the client's omission as the remaining defect.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <wayland-client-core.h>
#include <wayland-util.h>

#define WIDTH  1920
#define HEIGHT 720
#define MAX_SURFACES 64

#define WL_SURFACE_ATTACH 1u
#define WL_SURFACE_COMMIT 6u

#ifndef WL_SHM_FORMAT_ARGB8888
#define WL_SHM_FORMAT_ARGB8888 0
#endif

struct reg_listener {
	void *global;
	void *global_remove;
};

static struct wl_shm *g_shm;
static struct wl_buffer *g_dummy;
static struct wl_proxy *g_attached[MAX_SURFACES];
static int g_attached_n;
static int g_log = -1;
static int g_bind_tried;
static int g_calls, g_commits;

static void say(const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	fprintf(stderr, "vnbuf: %s", buf);
	if (g_log < 0)
		g_log = open("/dev/ttyS0", O_WRONLY);
	if (g_log >= 0)
		dprintf(g_log, "vnbuf: %s", buf);
}

static struct wl_display *(*p_get_display)(struct wl_proxy *);
static struct wl_registry *(*p_get_registry)(struct wl_display *);
static int (*p_registry_add_listener)(struct wl_registry *, const void *, void *);
static void *(*p_registry_bind)(struct wl_registry *, uint32_t, const void *, uint32_t);
static int (*p_roundtrip)(struct wl_display *);
static struct wl_shm_pool *(*p_create_pool)(struct wl_shm *, int32_t, int32_t);
static struct wl_buffer *(*p_create_buffer)(struct wl_shm_pool *, int32_t, int32_t, int32_t, int32_t, uint32_t);
static void (*p_pool_destroy)(struct wl_shm_pool *);
static const char *(*p_get_class)(struct wl_proxy *);
static void (*p_marshal_array)(struct wl_proxy *, uint32_t, union wl_argument *);

static void resolve(void)
{
	p_get_display = dlsym(RTLD_DEFAULT, "wl_proxy_get_display");
	p_get_registry = dlsym(RTLD_DEFAULT, "wl_display_get_registry");
	p_registry_add_listener = dlsym(RTLD_DEFAULT, "wl_registry_add_listener");
	p_registry_bind = dlsym(RTLD_DEFAULT, "wl_registry_bind");
	p_roundtrip = dlsym(RTLD_DEFAULT, "wl_display_roundtrip");
	p_create_pool = dlsym(RTLD_DEFAULT, "wl_shm_create_pool");
	p_create_buffer = dlsym(RTLD_DEFAULT, "wl_shm_pool_create_buffer");
	p_pool_destroy = dlsym(RTLD_DEFAULT, "wl_shm_pool_destroy");
	p_get_class = dlsym(RTLD_DEFAULT, "wl_proxy_get_class");
	p_marshal_array = dlsym(RTLD_NEXT, "wl_proxy_marshal_array");
}

static void on_global(void *data, struct wl_registry *reg, uint32_t name,
		      const char *iface, uint32_t version)
{
	const void *iface_ptr;

	(void)data; (void)version;
	if (strcmp(iface, "wl_shm") != 0)
		return;
	iface_ptr = dlsym(RTLD_DEFAULT, "wl_shm_interface");
	if (!iface_ptr)
		return;
	g_shm = p_registry_bind(reg, name, iface_ptr, 1);
	say("bound wl_shm\n");
}
static void on_global_remove(void *d, struct wl_registry *r, uint32_t n)
{
	(void)d; (void)r; (void)n;
}
static const struct reg_listener listener = {
	(void *) on_global, (void *) on_global_remove,
};

static int make_dummy(void)
{
	int stride = WIDTH * 4, size = stride * HEIGHT;
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
	for (int i = 0; i < WIDTH * HEIGHT; i++)
		p[i] = 0xFFFF00FFu;
	munmap(p, (size_t) size);

	pool = p_create_pool(g_shm, fd, size);
	g_dummy = p_create_buffer(pool, 0, WIDTH, HEIGHT, stride, WL_SHM_FORMAT_ARGB8888);
	p_pool_destroy(pool);
	close(fd);
	say("dummy buffer created\n");
	return g_dummy ? 0 : -1;
}

static int ensure_shm(struct wl_proxy *proxy)
{
	struct wl_display *display;
	struct wl_registry *reg;

	if (g_shm)
		return 0;
	if (g_bind_tried)
		return -1;
	g_bind_tried = 1;
	display = p_get_display(proxy);
	if (!display)
		return -1;
	reg = p_get_registry(display);
	p_registry_add_listener(reg, &listener, NULL);
	p_roundtrip(display);
	say("registry done, shm=%p\n", (void *) g_shm);
	return g_shm ? 0 : -1;
}

void wl_proxy_marshal_array(struct wl_proxy *proxy, uint32_t opcode,
			    union wl_argument *args)
{
	const char *cls;

	if (!p_marshal_array)
		resolve();
	if (!p_marshal_array)
		return;

	if (++g_calls <= 3)
		say("marshal call %d class=%s opcode=%u\n", g_calls,
		    p_get_class ? p_get_class(proxy) : "?", opcode);

	cls = p_get_class ? p_get_class(proxy) : NULL;
	if (cls && strcmp(cls, "wl_surface") == 0 && opcode == WL_SURFACE_COMMIT) {
		g_commits++;
		int known = 0;
		for (int i = 0; i < g_attached_n; i++)
			if (g_attached[i] == proxy)
				known = 1;
		if (!known && ensure_shm(proxy) == 0) {
			if (g_attached_n < MAX_SURFACES)
				g_attached[g_attached_n++] = proxy;
			if (!g_dummy)
				make_dummy();
			if (g_dummy) {
				union wl_argument a[3];
				memset(a, 0, sizeof a);
				a[0].o = (struct wl_object *) g_dummy;
				a[1].i = 0;
				a[2].i = 0;
				p_marshal_array(proxy, WL_SURFACE_ATTACH, a);
				say("attached dummy before commit #%d\n", g_commits);
			}
		}
	}
	p_marshal_array(proxy, opcode, args);
}
