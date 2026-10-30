# Media-candidate evidence excerpts

This directory contains only small, reviewed excerpts needed to support the
tracked media-parser conclusions. Full VM serial/DLT logs, generated ASF files,
recovered binaries, and the local runner remain under ignored `work/`.

## PlayerEngine / CVE-2026-2920

`playerengine-asf-service-evidence.txt` records:

- the exact nested PlayerEngine option contract;
- the stock `alsasink` / `media_mixer` negative control;
- the VM-only ALSA-null compatibility control;
- one-stream and 32-stream surviving controls;
- 33- and 34-stream service crashes;
- the service's `SIGSEGV` backtrace; and
- exact vendor-plugin offsets showing the 208-byte stream stride, the first
  out-of-range writes, and the first observed fatal use of the corrupted
  `flowcombiner` pointer.

The evidence establishes parser memory corruption and PlayerEngine process
death in the isolated VM. It does not establish instruction-pointer control,
arbitrary code execution, automatic removable-media invocation, persistence,
or behavior on the owner's installed head unit.

## LightMediaScanner route

`lightmediascanner-asf-evidence.txt` records the separate automatic indexing
route. Authentic startup scanning processed the 33-stream file under
`/media/usb` with LightMediaScanner's own direct-I/O `asf.so` metadata plugin.
That plugin has no GStreamer dependency; the scan completed with zero errors,
the daemon survived, and a full session-bus capture contained no PlayerEngine or
thumbnail call. This excludes LightMediaScanner's indexing step as the observed
V-012 trigger, but not later browser, playback, thumbnail, or media-manager
handoffs.

## Thumbnail request route

`thumbnail-extractor-asf-route-evidence.txt` records the exact session-bus
contract, MediaBrowser's public `requestThumbnails(as)` forwarding path,
`ThumbnailService::Start(as) → VideoContext`, and the exact
`uridecodebin ... appsink` pipeline in `libthumbnailextractor.so`. Its custom
autoplug callback does not exclude `asfdemux`.

`appmediaplayer-thumbnail-caller-evidence.txt` records the client-side follow-up:
exact generated sync/async method signatures, implementation and thunk offsets,
vtable placement, the `BrowserInterface -> MediaModeController` scan-event
chain, and the connection from `VideoPlaybackModel`'s inherited
`BasePlaybackModel::thumbnailChanged` signal to `VideoPlaybackController`. The
reviewed application bodies contain no direct `requestThumbnails` dispatch;
generated capability and a downstream thumbnail-property signal are not caller
evidence.

Together these establish a static, explicit client-request route to the
vulnerable plugin. The reviewed scan-handler and property-slot bodies contain no
direct call to it, and bounded VM attempts did not observe name acquisition, a
delivered `Start`, `libgstasf` mapping, or a natural crash. This is not an
exhaustive exclusion of indirect/QML dispatch and is not evidence of automatic
insertion/indexing, UI
behavior, RCE, or physical-unit reachability.
