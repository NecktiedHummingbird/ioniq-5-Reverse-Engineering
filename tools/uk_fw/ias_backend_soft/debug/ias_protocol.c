/* ias_crtc / ias_mode — interface tables recovered from ias-backend.so
 * (evidence/vm-bringup/ias-backend-soft-scope.md). Published as wl_globals so the
 * vendor ias-shell and wrandr can address an output on a backend with no DRM device. */
#include <stdlib.h>
#include <string.h>
#include <wayland-server.h>
#include "ias_dbg.h"

#define IAS_MAX_ARGS 4
static const struct wl_interface *ias_types[] = { NULL, NULL, NULL, NULL };

/* The single mode this backend offers; keep in sync with the output created in
 * ias-backend-soft.c (1920x720 @ 60Hz). */
#define IAS_CRTC_WIDTH   1920u
#define IAS_CRTC_HEIGHT   720u
#define IAS_CRTC_REFRESH 60000u

struct ias_crtc { uint32_t mode; };

/* methods: set_mode(u) set_gamma(uuu) set_contrast(uuu) set_brightness(uuu) set_fb_transparency(u)
 * events:  mode(uuuu) gamma(uuu) contrast(uuu) brightness(uuu) */
static void
crtc_set_mode(struct wl_client *c, struct wl_resource *r, uint32_t mode)
{
	struct ias_crtc *crtc = wl_resource_get_user_data(r);
	(void)c;
	ias_dbg("crtc_set_mode r=%p mode=%u", (void *)r, mode);
	crtc->mode = mode;
	/* echo the mode back: id, width, height, refresh (mHz) */
	wl_resource_post_event(r, 0, mode, IAS_CRTC_WIDTH, IAS_CRTC_HEIGHT,
			       IAS_CRTC_REFRESH);
	ias_dbg("crtc_set_mode posted mode event");
}
static void
crtc_triple(struct wl_client *c, struct wl_resource *r, uint32_t a, uint32_t b, uint32_t d, int ev)
{
	(void)c; (void)a; (void)b; (void)d;
	ias_dbg("crtc_triple r=%p ev=%d %u %u %u", (void *)r, ev, a, b, d);
	wl_resource_post_event(r, ev, a, b, d);
	ias_dbg("crtc_triple posted");
}
static void crtc_set_gamma(struct wl_client *c, struct wl_resource *r, uint32_t a, uint32_t b, uint32_t d)
{ crtc_triple(c, r, a, b, d, 1); }
static void crtc_set_contrast(struct wl_client *c, struct wl_resource *r, uint32_t a, uint32_t b, uint32_t d)
{ crtc_triple(c, r, a, b, d, 2); }
static void crtc_set_brightness(struct wl_client *c, struct wl_resource *r, uint32_t a, uint32_t b, uint32_t d)
{ crtc_triple(c, r, a, b, d, 3); }
static void crtc_set_fb_transparency(struct wl_client *c, struct wl_resource *r, uint32_t v)
{ ias_dbg("crtc_set_fb_transparency r=%p v=%u", (void *)r, v); (void)c; (void)r; (void)v; }

static const struct ias_crtc_listener {
	void (*set_mode)(struct wl_client *, struct wl_resource *, uint32_t);
	void (*set_gamma)(struct wl_client *, struct wl_resource *, uint32_t, uint32_t, uint32_t);
	void (*set_contrast)(struct wl_client *, struct wl_resource *, uint32_t, uint32_t, uint32_t);
	void (*set_brightness)(struct wl_client *, struct wl_resource *, uint32_t, uint32_t, uint32_t);
	void (*set_fb_transparency)(struct wl_client *, struct wl_resource *, uint32_t);
} crtc_impl = {
	crtc_set_mode, crtc_set_gamma, crtc_set_contrast, crtc_set_brightness, crtc_set_fb_transparency,
};

static const struct wl_message crtc_requests[] = {
	{ "set_mode", "u", ias_types },
	{ "set_gamma", "uuu", ias_types },
	{ "set_contrast", "uuu", ias_types },
	{ "set_brightness", "uuu", ias_types },
	{ "set_fb_transparency", "u", ias_types },
};
static const struct wl_message crtc_events[] = {
	{ "mode", "uuuu", ias_types },
	{ "gamma", "uuu", ias_types },
	{ "contrast", "uuu", ias_types },
	{ "brightness", "uuu", ias_types },
};
const struct wl_interface ias_crtc_interface = {
	"ias_crtc", 1, 5, crtc_requests, 4, crtc_events,
};

static void mode_add(struct wl_client *c, struct wl_resource *r) { ias_dbg("mode_add r=%p", (void *)r); (void)c; (void)r; }
static const struct ias_mode_listener { void (*add)(struct wl_client *, struct wl_resource *); }
	mode_impl = { mode_add };
static const struct wl_message mode_requests[] = { { "add", "", ias_types } };
const struct wl_interface ias_mode_interface = {
	"ias_mode", 1, 1, mode_requests, 0, NULL,
};

static void
crtc_destroy(struct wl_resource *r)
{
	ias_dbg("crtc_destroy r=%p", (void *)r);
	free(wl_resource_get_user_data(r));
}

static void
bind_crtc(struct wl_client *client, void *data, uint32_t version, uint32_t id)
{
	(void)data;
	struct wl_resource *r;
	ias_dbg("bind_crtc version=%u id=%u", version, id);
	r = wl_resource_create(client, &ias_crtc_interface, version, id);
	ias_dbg("bind_crtc resource=%p", (void *)r);
	if (!r) { wl_client_post_no_memory(client); return; }
	struct ias_crtc *crtc = calloc(1, sizeof(*crtc));
	if (!crtc) { wl_resource_destroy(r); wl_client_post_no_memory(client); return; }
	wl_resource_set_implementation(r, &crtc_impl, crtc, crtc_destroy);
	ias_dbg("bind_crtc set_implementation done");

	/* Report the current mode on bind, like the vendor CRTC does; without this
	 * wrandr shows a CRTC with an empty mode list. */
	wl_resource_post_event(r, 0, 0u, IAS_CRTC_WIDTH, IAS_CRTC_HEIGHT,
			       IAS_CRTC_REFRESH);
}
static void
bind_mode(struct wl_client *client, void *data, uint32_t version, uint32_t id)
{
	(void)data;
	struct wl_resource *r = wl_resource_create(client, &ias_mode_interface, version, id);
	if (!r) { wl_client_post_no_memory(client); return; }
	wl_resource_set_implementation(r, &mode_impl, NULL, NULL);
	ias_dbg("bind_mode done");
}

void
ias_publish(struct wl_display *display)
{
	void *g;
	ias_dbg("ias_publish display=%p", (void *)display);
	ias_dbg_trap();
	g = wl_global_create(display, &ias_crtc_interface, 1, NULL, bind_crtc);
	ias_dbg("ias_crtc global=%p", g);
	g = wl_global_create(display, &ias_mode_interface, 1, NULL, bind_mode);
	ias_dbg("ias_mode global=%p", g);
	ias_dbg("ias_publish done");
}
