# HVPatch at the K1 boundary — the first product-visible number

**Recorded 2026-08-13.** K1's gate requires no performance claim, and the
discipline requires that this must not persist past the K1 boundary. This is
that measurement, and it is also K2's baseline.

## Provenance

| Field | Value |
| --- | --- |
| Commit | `7b808b6cf` (K1 GO) |
| Signed binary SHA-256 | `ce951408709fc5c4231d697e23b6419c9a31fe89d4fc90466eb46399dc523257` |
| Signed binary LC_UUID | `C453BDAC-0F9F-343F-86D5-478AA8852A78` |
| Host | macOS 27.0 `26A5406e`, Darwin 27.0.0 arm64, Apple M4, 10 logical (4P + 6E) |
| Image | `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b` |
| Fixture | `scripts/perf/native_go_build.py` `guest_script()` verbatim, with the `WORKLOAD_NS` window |
| Docker platform | `linux/arm64` (native, not Rosetta) |

Carrick and Docker were **never run concurrently**; the carrick series
completed and no `carrick:` process remained before the Docker series began.
Three runs per engine, cold `GOCACHE` per run.

## Measured

| Metric | Carrick hvpatch | Docker arm64 | Ratio |
| --- | ---: | ---: | ---: |
| Guest workload window | **2.129 s** | 0.827 s | **2.574x** |
| Process wall | 2.830 s | 1.023 s | 2.766x |
| Carrick host CPU (user+sys) | **4.410 s** | n/a | — |

Per-run carrick CPU: 4.060 / 4.600 / 4.570 s. Per-run windows: 1.976 /
2.193 / 2.219 s. Per-run Docker windows: 0.870 / 0.800 / 0.812 s.

Docker's own CPU is not comparable from the host: the work happens inside the
LinuxKit VM, so host `time` sees only the client. The workload window is the
like-for-like metric, which is why this tree made it the primary one.

## Reading

**The window ratio is 2.57x.** For context, the shipped `native` default was
last measured at **10.1806x** Docker (2026-08-07). The one-VM hvpatch backend
is therefore roughly **4x better than the shipped default** on this workload —
though note this is a window-vs-window comparison against a
CPU-seconds-derived historical figure, so treat the 4x as an order-of-
magnitude statement rather than an exact speedup.

**Against the goal's own bar, this is not done.** The target is a cold
`go build` below **2.3 CPU-s**; carrick spends **4.410 CPU-s**, so **47.8% of
current CPU must still be removed.** That is the number K2 has to move.

The Phase-4 prototype's last figure was ~4.27 CPU-s (2026-08-09) and this
measures 4.410 CPU-s. Those are not meaningfully different, and nothing in
K1 targeted CPU — K1 was correctness and observability. Do not read the
K1 work as a performance regression or improvement; it is neither.

## What this is not

- Not a claim about CPython, Node.js or Rust workloads — unmeasured.
- Not a conformance statement; `baseline.hvpatch.jsonl` does not exist.
- Not traced attribution. This is untraced wall/CPU on the shipped signed
  binary, which is the clean authority for retention decisions. Where the CPU
  goes is a separate, traced question and is K2's opening move.
