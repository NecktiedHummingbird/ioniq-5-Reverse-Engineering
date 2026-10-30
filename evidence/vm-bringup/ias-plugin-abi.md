# IAS layout plugin ABI — extracted from vendor DWARF

Source: `usr/lib/weston/ias-shell.so` and `usr/lib/weston/ias_plugin_framework.so` in
`NE_E.EUR.S5W_L.001.001.260128`, both of which ship full DWARF (see V-012). Extracted with
`llvm-dwarfdump --debug-info`. **Verified** unless marked otherwise.

## Why this matters

`AppHomeScreen` speaks only the IAS protocol. With `ias-shell.so` the compositor logs **zero repaints**
because no surface is ever placed; with `fullscreen-shell.so` nothing changes, because the app never uses
`wl_shell`. The layout plugin that would place surfaces is referenced by `etc/xdg/weston/.config/ias.conf`
as `<plugin name='grid' lib='/usr/lib/ias/grid_layout.so' defer="1"/>` — and **`grid_layout.so` does not
exist anywhere in the image or the decrypted tree**. `usr/lib/ias/` is empty and `opt/ias/` is an empty OEM
mount point. A replacement plugin is therefore the last missing piece for a rendered HMI.

## How a plugin is discovered

Plugins export a data symbol named **`ias_plugin_info`** (layout) or **`ias_input_plugin_info`** (input).
The shell loads these by name, so a replacement is a shared object exporting `ias_plugin_info`.

## `struct ias_plugin_info` — the layout contract

| offset | member | type |
|---|---|---|
| `0x00` | `switch_to` | `ias_switchto_fn` = `void (*)(const spug_output_id)` |
| `0x08` | `switch_from` | `ias_switchfrom_fn` = `void (*)(const spug_output_id)` |
| `0x10` | `mouse_grab` | `weston_pointer_grab` |
| `0x20` | `key_grab` | `weston_keyboard_grab` |
| `0x30` | `touch_grab` | `weston_touch_grab` |
| `0x40` | `inforec_version` | `uint32_t` |
| `0x44` | `id` | `unsigned int` |
| `0x48` | `draw` | `ias_draw_fn` = `void (*)(spug_view_list)` |

## `struct ias_plugin` — the registration record (size `0x90`)

Declared in `src/ias-common.h:265`.

| offset | member | type |
|---|---|---|
| `0x00` | `version` | `unsigned int` |
| `0x08` | `libname` | `char *` |
| `0x10` | `name` | `char *` |
| `0x18` | *(anonymous union)* | `info` (`ias_plugin_info`) or `input_info` (`ias_input_plugin_info`), 0x50 bytes |
| `0x68` | `link` | `wl_list` |
| `0x78` | `init_mode` | enum: `INIT_NORMAL`, `INIT_DEFERRED` |
| `0x7c` | `init` | `int` |
| `0x80` | `activate_on` | `char *` |

`init_mode` explains `defer="1"` in the config: a deferred plugin is not activated at startup.

## Framework helpers a plugin calls

From `ias_plugin_framework.so` exports: `fetch_ias_surface`, `ias_assign_surface_to_scanout`,
`ias_assign_surface_to_sprite`, `ias_assign_zorder_to_sprite`, `ias_assign_constant_alpha_to_sprite`,
`ias_activate_plugin`, `ias_deactivate_plugin`, `ias_frame_events_enabled`.

## Minimal replacement, stated in one line

On `switch_to(output_id)`: fetch each IAS surface and assign it to that output's scanout. Nothing else is
required to get pixels on the compositor's output; the grab tables can be left empty and `draw` can be a
no-op.

## Still unextracted — the honest gap

- `spug_output_id` and `spug_view_list` representations. The framework has `spug_ids`,
  `spug_output_ids`, `spug_surface_ids`, `spug_view_ids`, `spug_plane_ids`, `spug_seat_ids` and
  `spug_hashtables` types, so these are ID-based lookups into framework tables rather than raw pointers.
- The exact `fetch_ias_surface` signature (it presumably takes an ID and returns an `ias_surface *`;
  `struct ias_surface` and its `ias_surface_interface` are present in `ias-shell.so`).
- Whether `switch_to` is called with a valid output ID before any surface exists, i.e. ordering.

Each of these is one DWARF query away; none is a blocker of principle.
