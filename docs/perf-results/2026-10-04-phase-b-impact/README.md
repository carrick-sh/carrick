# Lifecycle Phase B impact — 2026-10-04

Single-variable A/B on the director's Mac. Base `5e23be1a2` (batch 2a, before
Phase B) against candidate `1e61be8e8` (Phase B), with native arm64 Docker as
the reference. `carrick-xtask impact`: 10 samples, one excluded warm-up, no
retries. Docker ran under the exclusive Docker host lease and carrick under the
exclusive gate lease. The `HEAD` fields in `report.md` name the measuring tree
(097559be9); each artifact is identified by its own sha256/CDHash in the JSON.

| workload | base | Phase B | Docker | Phase B / Docker (per op) |
|---|---|---|---|---|
| thread-spawn (1000) | 17.96 s | 17.00 s (−5%) | 31.13 s [13.8–33.7] | 0.56x |
| spawn-loop (1000) | 1.263 s | 1.362 s (+8%) | 0.440 s | 5.3x |
| fork-exec (200) | 0.723 s | 0.716 s | 0.232 s | 6.8x |

Status: suggestive, not confirmed. A worker's cargo builds, which do not take
the lease, may have overlapped these runs.
- thread-spawn improved about 5%. The Docker reference is suspect: its spread
  is 2.4x, and 30 ms per thread is implausible. Investigate the Docker side
  before claiming carrick is faster than native.
- spawn-loop regressed about 8%. The candidate's minimum (1.326 s) exceeds the
  base median (1.263 s). Suspect Phase B's first-entry clone admission on exec.
  Needs a controlled rerun.
- Process spawn and fork+exec stay at 3x Docker wall clock (5-7x per op),
  over the 2x objective. N2 (process creation in EL1) is the planned lever.
