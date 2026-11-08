# Go startup ring mapping control (#1862)

`kernel.el1.anonymous-reservations` now includes a production native-process
entry control. It reserves three 64 GiB ranges, commits interior subranges,
and issues 1024 nil-hint 256 KiB private anonymous RW mappings from each of
two live thread members (2048 total). It uses an
expanded virtual layout to keep the high Go hints in ring. Production instead
forwards an out-of-layout hint for authenticated external placement; this
control does not model that carrier transaction, physical first touch, or Go
execution. Passing it is not a reproduction or fix of the signed failure.

The known-answer diagnostic call deliberately sets RLIMIT_DATA to zero. The
native mmap must return errno 12 and retain its arguments and `Limit` reason.
Before publication was connected, the test returned errno 12 but captured zero
records. This is red diagnostic evidence, not evidence that Go hit a data limit.

The census is carrier-scoped in the existing mapped `Counters`. Sixteen slots
are claimed once; a release publication follows fifteen scalar payload stores.
No slot is reused. Recording does not allocate, acquire another MM's lock, or
wait. Success makes no new atomic operation. Failure reads the existing root
charge aggregates once (constant work), independent of reserved bytes or VMA
population. Attempts beyond sixteen remain counted; incomplete publication and
truncation are explicit in LLDB. The ABI test drives simultaneous writers,
checks coherent identities, fixed capacity and independent successor carriers.

On the Mac set `CARRICK_EL1_CENSUS` to an absolute evidence directory for
the exact row run. The existing terminal publisher saves the bounded failure
snapshot before unmapping the counters; `carrick debug el1-census <directory>`
prints it. The census schema is now 3. This preserves fast-fatal evidence
without needing an attach before the Go process exits. Incomplete publication
and capacity truncation survive JSON serialization and debug aggregation.

On the Mac preserve the symbol-bearing signed binary and inspect the carrier
with `carrick debug lldb-run` / the LLDB plugin's `carrick el1-counters`. It now
prints anonymous-leave counts and `mmap_enomem` records. `reason=1` means the
reservation decoder returned `Limit`; arena bounds, root/external charges and
limits distinguish placement from accounting. Metadata/editor refusals are
anonymous leaves, not direct ENOMEM. A zero ENOMEM count does not exonerate
mmap: Go 1.24 `sysAllocOS` returns nil for errors other than its special
EACCES/EAGAIN cases, so persistentalloc's fatal text does not establish errno
12. Read the mmap refusal census and anonymous leaves too.

BSD semantic source:
[Go 1.24 mem_linux.go](https://github.com/golang/go/blob/go1.24.0/src/runtime/mem_linux.go#L19-L33).

The director retains paired, interleaved main/head `go-build` runs on the Mac,
using one signed artifact per head, exact row command/image and population
accounting. Capture the fatal and hang variants with the carrier's backtraces,
ring/counters and scoped cleanup. Signed acceptance and runtime ratios remain
open; this diagnostic slice changes no allocator or refusal policy.
