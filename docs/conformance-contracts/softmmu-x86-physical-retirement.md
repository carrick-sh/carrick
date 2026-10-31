# Software vCPU physical retirement (`softmmu.x86.physical-retirement`, #681 slice 2, #607)

Surface: `carrick-softmmu::retirement` (`SoftVcpu`, `SoftVcpuSeat`, `RunningSeat`,
`SeatAdmission`, `PendingRetirement`, `SoftRequester`), the `ExtentTable`
retirement edits, and the soft CPU's `RunningCpu`, `RunningContext`, block entry and
`HostAccess`-gated guest access in `carrick-softcpu-x86`. Authority: Intel SDM
Vol. 3 §4.10.4 and AMD APM Vol. 2 §5.5: a processor may keep using a cached
translation until it is invalidated, so software invalidates on every
processor that may hold it before the frames are reused.

The venue runs on the neutral invalidation domain
(`kernel.mm.invalidation-domain`); it replaces PR #678's bespoke coordinator.
`ExtentTable` owns one `ServedTable<64>` through an owning `SoftDomainHandle`.
Each soft vCPU holds a `SoftVcpuSeat`; physical retirement is a domain-wide
request (`stage_domain`) every seated member owes. The kick is the member's
exit flag, the safe point is block entry (own-line `has_debt` loads), and the
local invalidation is `SoftTlb::flush_all` or `flush_write_plane`. Running is
a scope: a CPU runs only inside a run guard whose drop parks it, host access
goes through a `HostAccess` whose drop parks a parked CPU again, and a CPU's
own thread waiting without itself as requester is refused. A pending
retirement holds its whole span, a replacement publishes its new owner only on
completion, a later completion recovers a dropped retirement, and an exhausted
domain stops every CPU. The protocol takes no lock per block; the carrier's
per-block `&mut M` still implies an embedder lock when CPUs share a memory,
which the soft carrier (#578) removes.

The red-first witness is the #607 shape: a running peer holding a translation
of a retired extent kept serving `Some(stale_host_address)` on main. Structural
budgets at 2, 16 and 64 seated members: zero shared RMWs plus stores per
debt-free block entry (`invalidation_steady_state_shared_writes`), one owed
raise per seated member per retirement, and at most one kick per running
member. Signed and Docker layers wait for the soft carrier.
