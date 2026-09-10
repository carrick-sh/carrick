# Retired DTrace Scripts

The following scripts were retired on **2026-09-10** (base commit `0ec4e75e9`) as part of the removal of the retired native/DSR translation execution lane:

- `dsr-profile.d`: DSR execution profiling
- `dsr-indirect.d`: DSR indirect branch resolver tracing
- `dsr-fork.d`: DSR fork translation state tracing
- `native-wall.d`: Legacy native execution wall-time attribution
- `native-fault-attribution.d`: Legacy native fault attribution
- `guest-translation-census.d`: Guest translation census tracing

Relative symlinks remain in `scripts/dtrace/` to preserve consumer compatibility across the runtime fence.
