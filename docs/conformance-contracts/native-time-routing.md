# Native time routing (#1808): red-witness checkpoint

At admitted main `86651e125f36299c1b542d951bc93ab32b5a7b36`, the time
syscalls in this issue have no shared in-ring family. A fully published
native fork child can therefore receive ENOSYS without any publication race.
This checkpoint does not implement a fix or establish the cause of the
original signed pipeline failure.

| Call | Canonical ordinal | x86 ordinal | Shared family | ARM crossing |
|---|---:|---:|---|---|
| nanosleep | 101 | 35 | Unported | Permanent |
| clock_gettime | 113 | 228 | Unported | Permanent |
| clock_nanosleep | 115 | 230 | Unported | Permanent |
| adjtimex | 171 | 159 | Unported | None |
| clock_adjtime | 266 | 305 | Unported | None |

`carrick-personality-linux::dispatch::{route_aarch64,route_x86}` choose
`Unported` for these calls. `crossing.rs` permits the three listed ARM clock
crossings, but not their x86 counterparts. Strict x86 entry refuses them.
On ARM, `carrick-el1-linux::dispatch::native_unstaged_exit` refuses an
unserved syscall from `NativeThreadGroupOwner::ForkChild` before publishing
a carrier crossing. The root can still reach the legacy handlers in
`carrick-kernel::dispatch::time` through `RootOnly` compatibility. All five
ordinals remain in that compatibility census.

The four `native_fork_child_*_reaches_time_handler` witnesses create a root,
perform the production native fork, activate the child with a distinct MM,
keep both process bindings alive, and call `dispatch_syscall_with_native`.
A forwarded call then enters the production `native_unstaged_exit` decision.
The child classification comes from the admitted process entry, not an
invented second task. The MMU stock supplier is simulated, as in the existing
native-fork tests; no guest instructions execute.

These first witnesses use null output/input pointers. Native Linux x86_64
returns EFAULT (14) for all four calls with the zero argument vector. The
assertion requires that result and no refusal count; it must remain red
until the real time handlers are wired. This is deliberately narrower than
the issue's successful CLOCK_REALTIME read acceptance criterion. Returning
EFAULT from a new routing stub would not satisfy the issue.

## Required implementation and proof

There is no evidence here that waiting for route publication will help:
family selection is static, and the witness runs after fork publication.
Do not relax the child refusal policy, send a child to the root dispatcher,
or retry the syscall. Those changes would grant ambient root authority
without implementing the missing service.

The shared implementation needs a time owner usable by both ISA entries:

- Clock reads need an authenticated clock-domain sample, including virtual
  time policy, and exact-MM retained copyout. The existing host `ClockDomain`
  supports system, offset, frozen, scaled and deterministic policies; simply
  reading a hardware counter or the current MM's vvar is not a replacement.
- Sleeps need an owned deadline and input/output continuation that releases
  execution capacity, preserves signal interruption and remaining time, and
  observes clock changes. The existing signal timer supplies a counter and
  deadline mechanism, not the complete sleep semantics.
- `adjtimex` and `clock_adjtime` need the same container discipline state and
  exact caller credentials as the legacy handlers. Moving only routing or
  copying their logic into a second implementation would leave two answers.

An ABI/clock-publication design must identify the one shared authority and
its initialization before introducing a new carrier record or mapped ABI.
AGENTS.md requires a design review before ABI/wire-layout changes. A complete
port must preserve the existing vDSO/syscall calibration contract and cover
fork and exec successors with two live processes.

Still required: successful realtime-read witness, retained-copy refusal,
sleep completion/interruption, timex state sharing, both ISA entry bindings,
and a live syscall census of the original pipeline. Signed A/B populations
and the pipeline demo remain director work; this host-only reduction does
not prove them. No complexity or runtime-ratio acceptance is claimed.
