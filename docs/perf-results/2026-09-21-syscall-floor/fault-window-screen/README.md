# First-touch window sensitivity: no measured concurrency win

Same frozen signed discard-edges binary in both arms; no runtime source change.
A sets host CARRICK_FAULT_WINDOW_BYTES=65536, B=16384. The driver records the
host variable alongside every raw timing row. Each workload has one warm sample
per arm and two ABBA blocks, four measured samples per arm. All30 runs completed
with exact Node/group markers. No builds or traces during timings. No exclusions.

| Workload | 64 KiB mean ms | 16 KiB mean ms |
|---|---:|---:|
| Original Node |171.75|171.00|
| One background Node |168.75|179.00|
| Eight concurrent Node |709.00|709.00|

Separate one-wave eight-process trace per setting observed12001 materialization
request/acquire/release events at16KiB versus12759 at64KiB (about5.9% fewer).
Both traces passed marker/phase closure, root exit, cleanup and no-error/drop
checks. Source confirms trace sudo preserves CARRICK_* variables. These counts
support an exercised configuration difference, not a timing improvement.

The window is backed in16KiB chunks, each published separately. The runtime
resident-fault path protects only the faulting4KiB page. Smaller speculative
backing reduces some transactions but did not reduce this workload's wall time.
Do not tune the default based on these counts. No default or product change,
no promotion claim, no new Linux ratio or I/O subtraction. Raw existing Linux
comparisons remain in discard-edges/concurrency and cpu-affinity receipts.
