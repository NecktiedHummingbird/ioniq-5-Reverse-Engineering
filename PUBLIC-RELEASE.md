# Public release boundary

The public source tree intentionally excludes raw owner USB exports, imported third-party diagnostic dumps, compressed core dumps, raw driving/location traces, exact private manifests, private workflow and Council packets, and full-text third-party paper artifacts. The source material remains in the operator's local private archive. Local user paths have been anonymized.

The snapshot is prepared for public release, but GitHub may continue serving old imported raw commits by SHA after a force update. Verify server-side cleanup of those cached objects before changing visibility. The repository stays private until that verification succeeds.

Run `python3 tests/run_all.py` and the unit suite before any push. The integrated harness uses public mode when this file exists, checks all published text for secrets, personal paths and VIN-shaped tokens, and rejects raw evidence paths.
