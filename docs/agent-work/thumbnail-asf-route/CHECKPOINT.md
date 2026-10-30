# Checkpoint — exact thumbnail-to-ASF route

Date: 2026-11-01
Status: static route complete; bounded VM delivery remains unresolved.

## Established

- Exact component hashes are retained in
  `evidence/artifacts/media-candidates/thumbnail-extractor-asf-route-evidence.txt`.
- The internal session-bus contract is:
  - destination `com.lge.thumbnailextractor`;
  - object `/com/lge/thumbnailextractor/service`;
  - interface `com.lge.thumbnailextractor.service`;
  - method `Start(as)`.
- MediaBrowser's public/CommonAPI `requestThumbnails(as)` forwards to that
  contract.
- Exact extractor call sites show `Start(as)` always selects `VideoContext`; the
  separate audio/TagLib context serves cover-art work. This corrects the earlier
  extension-based assumption.
- Exact `libthumbnailextractor.so` constructs an
  `uridecodebin ... videoconvert ... videoscale ... appsink` pipeline.
- The custom autoplug callback skips only factory names beginning with `mfx`; it
  does not exclude the shipped `asfdemux`.
- The only reviewed direct caller of the thumbnail request path is the explicit
  public request handler. Scan-completed and media-file-found callbacks forward
  events without requesting extraction.
- Exact AppMediaPlayer review recovers both generated client signatures:
  synchronous `requestThumbnails(paths, status, info)` and asynchronous
  `requestThumbnailsAsync(paths, callback, info)`. Their implementations,
  thunks, and vtable slots prove capability, not invocation.
- AppMediaPlayer's reviewed `BrowserInterface -> MediaModeController` scan-event
  handlers do not directly dispatch that method family.
- `VideoPlaybackModel` emits its inherited
  `BasePlaybackModel::thumbnailChanged(QString)` signal to
  `VideoPlaybackController::onThumbnailChanged(QString)`. This is a downstream
  model notification; the slot contains no direct request dispatch.

## Bounded VM result

Exploratory no-NIC VM attempts under ignored `work/` observed lengthy GStreamer
plugin and SQLite/cache initialization, but not the expected well-known service
name. Consequently they did not establish a delivered `Start`, an ASF plugin
map, cache output, a natural process crash, or a 32/33 distinction.

Interpretation:

- `THUMB_ALIVE_*=0` means `kill -0` succeeded;
- `CALL_RC=0` from a no-reply send proves local send success only;
- `THUMB_WAIT_RC=1` followed harness termination and is not a crash result;
- absent `/dev/media0` and missing optional plugin dependencies are VM limits,
  not production-fix evidence.

## Claim boundary

The thumbnail route is exact and explicit but client-request driven. Automatic
USB insertion/indexing, an authentic UI caller, dynamic thumbnail selection of
`libgstasf`, thumbnail-process corruption, RCE, root, and physical-head-unit
behavior remain unproven. Manual uid-0 PlayerEngine is still the only dynamically
confirmed production-service V-012 route.

## Verification

- SHA-256 identities independently recomputed.
- Exported symbol offsets, generated method bodies, relocations, Qt connections,
  and direct call sites checked with `objdump` and `llvm-readelf`.
- AppMediaPlayer caller evidence is retained in
  `evidence/artifacts/media-candidates/appmediaplayer-thumbnail-caller-evidence.txt`
  (SHA-256
  `24b3929df85c19603df337654a592a8b9cb6cb164ccda5b148b06b45e7c7e967`).
- D-Bus and pipeline literals checked with terminated static strings.
- Independent read-only review agreed with the narrow static route and rejected
  the exploratory logs as dynamic delivery/crash evidence.

## Resume action

Continue outside the now-reviewed scan-event and thumbnail-property paths:
trace `BrowserDBusProxy` ownership into QML-facing objects and look for indirect
virtual, callback, or metadata dispatch of `requestThumbnails(as)`, or playback
after indexing. Separately diagnose the VM-only service-name acquisition
boundary with matched benign controls before re-running 32/33 thumbnail
requests.
