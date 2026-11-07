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

## Shared transition prerequisite

`carrick-time-core` now owns the existing `AdjtimexState`, timex output
serialization and bounded field-update transition. The host `ClockDomain`
and dispatcher consume that implementation. This is a move of existing
behavior, including its documented frequency/slew approximations; it does
not register an in-ring time route. Exact-MM output preparation, offset changes, locking and notification
retain their existing order in the host dispatcher. Validation and reply
formatting now use the shared borrowed `TimexRequest`; malformed singleshot
copyout remains distinct from an errno-only refusal. The container-clock
production-entry tests exercise the moved implementation. The four native-child witnesses remain red.

An independent design review supports a typed clock-resource operation,
without using the raw host syscall crossing or the host-file protocol.
`ServiceOperation` currently has no clock operation; adding a discriminator
requires publish/decode/completion validation even if the service-cell size
stays unchanged. The request must retain the exact native member/MM and a
run clock capability. The ring owns Linux validation, credentials and user
memory. The existing `ClockDomain` can remain the single clock-resource
authority, preserving calibrated realtime/vDSO agreement, virtual-clock
policies and clock-change notification.

For the remaining implementation:

- Supply physical/model clock samples through both ISA service adapters.
  CPU clocks must select guest task accounting, never carrier CPU time.
- Retain completed samples through exact-MM copyout. A memory-owner wait
  must not resample or restart the syscall.
- Timex validation now lives in the shared core. Preserve output preparation
  before mutation when introducing a ring consumer. State-dependent
  SETOFFSET interpretation and updates need one atomic authority operation;
  snapshot-and-replace would lose concurrent updates. The extracted field
  helper alone does not provide that transaction.
- Give sleeps an owned deadline, remaining-time output and signal policy,
  integrated with clock changes and deterministic advancement. The waiter
  must release execution capacity.
- Bind the routes only with working resource venues on both ISAs, and prove
  successful realtime reads, timex sharing, sleep completion/interruption
  and retained copyout before claiming the four null-pointer tests green.

This prerequisite must not be published as the completed #1808 fix.

## Transport prerequisite found in the continuation

The x86 native entry has no generic native-service consumer. In
`carrick-x86-cpl0/src/linux_personality.rs`, the `NativeService` completion
route explicitly counts a refusal and returns ENOSYS. The production host
adapter is `carrick-x86-cpl0-host/src/cpl0_boot.rs`; its ordinary and idle-peer
port handling both need service admission and completion. The fixture's
forward-port support is not that transport. A shared time family returning
`NativeService` would therefore remain broken on x86.

The existing x86 `native_execution` timer expiry and shared
`NativeProcessService` signal-clock methods can park and wake a task against
a physical counter. They do not provide the container's frozen, scaled or
deterministic policies, or notifications when guest realtime changes.
A sleep resource needs retained deadline/subscription custody, cancellation
acknowledgment and exact-member resumption. Blocking a host executor or
resampling on an output-memory wait is not an implementation of that owner.

The independent source review confirmed these prerequisites and found no
semantic change in the validation extraction. It did not approve a working
time route, transport or sleep implementation. These remain unimplemented;
the four native-child witnesses must stay red until those owners exist.

## Clock transaction witnesses

The resource transport must not compose independent state reads and writes.
Two production-dispatch schedules expose why:

- `clock_adjtime_notifies_after_discipline_publication` subscribes to a
  realtime change, then submits SETOFFSET, NANO and TICK together. The listener
  must observe the new offset and discipline together, and may reenter the
  clock snapshot API. Before the transaction fix it observes tick 10000
  instead of 10500, alongside the new offset.
- `clock_adjtime_reinterprets_units_after_output_preparation` admits a second
  clock_adjtime on the same domain during the first call's output preparation.
  That call changes the units to nanoseconds. The first call must derive its
  implicit SETOFFSET units under the mutation authority, not reuse a step
  computed before preparation. Both operations enter the production dispatcher;
  the memory fixture supplies only the deterministic interleaving.

The reviewed transaction order is clock-change lock, then discipline lock.
Guest output preparation takes neither. Preflight rejects invalid requests
before preparation, but its derived step is discarded. Execution recomputes
the step against the locked discipline, checks controlled-clock refusal before
effects, and publishes offset, discipline and reply before unlocking and
notifying listeners. A preflight error linearizes at its snapshot; execution
or revalidation error linearizes under the transaction locks. Memory preparation
refusals have no clock effects, and genuine output faults remain deferred to
copyout commit. This needs no syscall retry or extra clock sample.

These witnesses cover the clock authority prerequisite only. They do not
establish a working native clock transport or satisfy the child-read acceptance
criterion.
