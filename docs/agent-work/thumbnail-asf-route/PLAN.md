# Plan — exact thumbnail-to-ASF route

Date: 2026-11-01
Scope: recovered EU `260128` userspace, offline static analysis and bounded
interpretation of existing no-NIC VM logs.

## Goal

Determine whether the post-index thumbnail path can select the exact vulnerable
GStreamer ASF plugin, while separating explicit client requests from automatic
scan-time behavior and dynamic parser reachability.

## Safety boundary

- Do not execute recovered binaries during static extraction.
- Any VM attempt remains NIC-free, snapshot-backed, bounded to the existing
  32/33-stream crash-only fixtures, and contains no execution payload.
- Do not infer delivery from a D-Bus send return code, wrapper success, or process
  existence.
- Do not claim RCE, root, automatic USB invocation, or physical behavior.
- Keep complete logs, generated media, and exploratory runners under ignored
  `work/`; track only reviewed excerpts.

## Phases

1. Pin `MediaBrowser`, `thumbnail_extractor`, `libthumbnailextractor.so`, the
   D-Bus activation file, and `libgstasf.so` by SHA-256.
2. Recover the exact destination, object, interface, methods, and signals.
3. Trace MediaBrowser `requestThumbnails(as)` to extractor `Start(as)`.
4. Trace `Start(as)` through its selected context and exact GStreamer pipeline.
5. Inspect the custom autoplug callback for ASF exclusion.
6. Distinguish the request edge from scan-completed/media-file-found callbacks.
7. Classify existing and bounded VM attempts using exact name-acquisition,
   delivery, plugin-map, cache, liveness, and natural-exit evidence.
8. Retain a small reviewed excerpt and update V-012 claims conservatively.

## Acceptance

- Exact hashes and symbol/string offsets are retained.
- The `.service` destination/interface ambiguity is resolved.
- The audio-versus-video context is resolved from exact call sites.
- Static eligibility is not presented as dynamic parser reachability.
- Automatic scan-time invocation is accepted only with an exact caller or
  matched runtime evidence.
