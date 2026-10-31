# Vendor kernel USB-MIDI assessment — CVE-2016-2384

Date: 2026-11-01
Target: recovered EU `260128` Linux `4.1.27-abl`

## Result

CVE-2016-2384 is **rejected for the exact recovered USB-MIDI module**. The
physical, pre-login probe surface exists: `CONFIG_SND_USB_AUDIO=m` and the image
ships both generic USB-audio and USB-MIDI modules. Exact post-registration
endpoint-failure branches nevertheless return without directly freeing the
USB-MIDI object. That is the semantic change in upstream fix
`07d86ca93db7e5cdf4743564d98292042ec21af7`.

## Provenance

- `snd-usbmidi-lib.ko` SHA-256:
  `ad2180bab3d7433287288c9b8255c8f70cefb6d4ee3c6b7d95ea4826d4b434be`;
- GNU Build ID: `562938f72dabe794bda6232618bf2e254997b2fe`;
- `snd-usb-audio.ko` SHA-256:
  `67590c6bada08fe0de790cd91d74df2be912bff1ac4df6c9f9fc1a0d3d37e373`;
- module type: x86-64 `ET_REL`;
- `.text`: section address `0`, file offset `0x64`, size `0x2893`;
- `snd_usbmidi_create`: `[0x2034,0x2893)`;
- `snd_usbmidi_rawmidi_free`: `[0x1b34,0x1b90)`;
- recovered kernel configuration SHA-256:
  `987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56`.

## Upstream ownership defect

After `snd_rawmidi_new()` succeeds, the raw-MIDI object owns the USB-MIDI state
through its `private_free` callback. Vulnerable `snd_usbmidi_create()` also
called `snd_usbmidi_free(umidi)` when later endpoint creation failed. Subsequent
raw-MIDI/card teardown then freed the same object again. The complete upstream
fix deletes that direct post-registration free while preserving the owner's
normal destructor.

Authoritative sources:

- upstream fix and metadata:
  <https://git.kernel.org/linus/07d86ca93db7e5cdf4743564d98292042ec21af7>;
- one-hunk diff:
  <https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/07d86ca93db7e5cdf4743564d98292042ec21af7%5E%21/>;
- vulnerable parent source:
  <https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/86c2ee16704522a546c0ee1e8238096e3c391468/sound/usb/midi.c>;
- CVE record:
  <https://nvd.nist.gov/vuln/detail/CVE-2016-2384>.

Tracked patch:
`evidence/artifacts/kernel-candidates/cve-2016-2384-fix.patch`.

## Exact target control flow

1. `snd_rawmidi_new` is called at `0x2404`. On success, the code initializes the
   raw-MIDI object and the relocation at `0x246b` installs
   `.text+0x1b34`, exact `snd_usbmidi_rawmidi_free`, as its private-free
   callback.
2. Generic endpoint helper failures at `0x2617`, `0x264d`, and `0x2690` join
   `0x2711`. A nonzero error is copied to `r12d` and branches at `0x2716`
   directly to error return block `0x2833`.
3. Alternate endpoint-loop failures at `0x2767` and `0x277d` branch directly to
   `0x2880`, preserve the error, and join the same epilogue.
4. These are all five calls to the two endpoint-create helpers within the exact
   `snd_usbmidi_create` range. Neither post-registration failure route calls or
   inlines the full USB-MIDI endpoint/object destructor; both return the
   endpoint error.
5. In this build, source-level `snd_usbmidi_free` is inlined into the private-free
   callback at `0x1b34`. That callback's endpoint loops and final object free
   remain for legitimate owner teardown. Its continued presence is expected and
   is not evidence of the CVE.
6. The endpoint helpers `[0x1be5,0x1d95)` and `[0x1d95,0x2034)` clean only the
   newly allocated endpoint object on their own failure paths: the input helper
   passes its allocation in `r15` to endpoint deletion, while the output helper
   clears/frees its allocation in `rbx`. Neither helper invokes the full
   USB-MIDI object destructor before returning an error.
7. Direct `kfree` calls at `0x241d` and `0x24a2` are pre-registration cleanup.
   Exact predecessors of `0x2417` are descriptor/raw-MIDI preparation failures;
   the sole branch to `0x249d` is the negative `snd_rawmidi_new` result at
   `0x240d`. The upstream fix does not remove those early cleanup paths.

Because this is an `ET_REL` module, addresses above are `.text` section-relative
until load-time relocation. Corresponding file offsets add `0x64`; for example,
`snd_usbmidi_create` begins at `0x2098`, the first endpoint helper call begins
at `0x2674`, error return begins at `0x2897`, and the private-free callback
begins at `0x1b98`.

Reviewed bytes and relocation records are retained in
`evidence/artifacts/kernel-candidates/snd-usbmidi-cve-2016-2384.asm`.

## Reachability and claim boundary

A genuinely vulnerable build could encounter this ownership defect during
USB Audio/MIDI interface probing before login or application-level
authentication. Practical reachability would still require an accessible host
port, module loading/autoload, driver binding, USB authorization, and a
descriptor-derived setup failure after ownership transfer.

Those gates were not exercised because the exact module already contains the
fix effect. No USB descriptor, emulated peripheral, endpoint failure, module
load, target kernel execution, double free, crash, corruption, privilege
transition, SMACK escape, or persistence mechanism was produced.

This conclusion rejects only CVE-2016-2384 for the recovered module identity. It
does not prove the USB-audio stack free of other defects, establish the owner's
installed module, or establish production port policy.
