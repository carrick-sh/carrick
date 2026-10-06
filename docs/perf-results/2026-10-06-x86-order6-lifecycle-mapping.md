# Order 6: lifecycle ownership and X5 comparison packet

Comparison base: `0f476ce7a` (order 5), on integrated N1 `56bf8c0ca`.
The exit-participant custody from `af7bda476` is an ancestor of this base.
This extraction consumes its current graph operations; it does not replace
terminal-clear, adoption, graph revision reservations or participant custody.
No wider Linux exit/robust-death semantics are claimed.

## Owners and retained layout

| Before | After | Responsibility |
| --- | --- | --- |
| EL1 ABI `thread_lifecycle::{EntryState,EntryRef,TransitionError,GateState}` | `carrick-core-abi::lifecycle` | Exact encoded incarnation/state and transition refusals |
| EL1 ABI page claim/gate/live/publication/exit/reap bodies | `carrick-core::lifecycle::Lifecycle` | CAS state transitions on retained storage; noncopyable `ClaimedEntry` and `ExitAdmission` |
| EL1 ABI Linux payload/control/page records | `carrick-personality-linux::abi::thread` | Visible tid/uid credit, clone flags, mask, alternate stack, robust head and clear-tid sidecars |
| EL1 lifecycle syscall bodies | `carrick-personality-linux::lifecycle` | Linux validation, outputs/rollback, refusal policy and completion selection |
| EL1 `thread_setup` robust registration body | `carrick-personality-linux::thread` | Shared robust length/result, setup admission and clear/wake policy constants |
| EL1 lifecycle native context operations | EL1 `LifecycleNative` adapter | Checked ARM mappings, real ARM SP/TLS/frame and scheduler custody |
| No executing x86 clone/exit binding | x86 `cpl0_lifecycle` native adapter | Real native register/FS/user-GS/XSAVE context; retained shared scheduler records/queues |
| Runtime prepared terminal clear/wake | Same runtime sequencer, Linux policy constants | Actual runtime completion/job/graph authority; clear-before-notification sequencing stays here |

`PendingFamilies` has no semantic lifecycle operation. Its native acquisition
method only lends ISA hooks to the Linux owner, which routes and completes the
family. ARM policy bodies are deleted in the extraction commit. The EL1 ABI
module is a re-export; it contains no retained ABI implementation or tests.
`AtomicEntry` is transparent over the original atomic state word; the pool,
page and control layouts and lifecycle protocol version 6 remain unchanged.
Independent base/current ABI observations both report hash `0x3ff0698f9f1a67f1`
and the same 24 lifecycle size/alignment/offset facts.

Linux also selects child result zero and the AArch64 vDSO tid packing.
The native hooks only install those selected values. Typed `UserVa` addresses
cross the lifecycle copy boundary. The FS/GS and XSAVE instruction bodies live
in the existing reviewed native scheduler leaf and are shared by both CPL0
bindings; displaced instruction bodies are deleted.

Native seams retain `ExecutionBinding`, `RecordRef` (id plus incarnation),
`ThreadIdentity`, `EntryRef` (index plus generation), `EntryMmKey`, `UserVa`
and `SyscallResult`. Raw register arguments are decoded by the Linux codec.
The core does not receive clone flags, signal masks, Linux errnos or visible
tids; Linux chooses the live-membership floor of one. Native allocation hooks
check an unpublished allocation's exact incarnation, since `live` correctly
refuses its initial Free claim. Published record release still authenticates
the live incarnation. No host pid is substituted for a guest identity.

## Refusal/result mapping

“Forward” below means the unchanged native request is handed to the existing
host authority, with no newly synthesized errno. All before/after outcomes
below are identical for the existing ARM binding. New x86 ordinals are decoded
by Linux; unsupported native/binding cases remain explicit refusals.

| Condition / boundary | Before | After |
| --- | --- | --- |
| Missing lifecycle venue, task binding or scheduler for clone/exit | Forward | Forward |
| Unissued/stale execution, MM/thread generation or Born record/claim | Existing exact entry admission rejects completion | Same shared entry admission; no lifecycle effects |
| Unknown ordinal / unavailable family | Forward | Forward, same audited completion owner |
| `gettid`, threads hatch enabled, immutable visible projection present | Visible tid | Same visible tid |
| `gettid` disabled or visible projection absent | Forward | Forward |
| Robust setup hatch disabled or terminal gate Closed | Forward; head unchanged | Forward; head unchanged |
| Robust length not 24 | `-22` (`EINVAL`); head unchanged | `-22`; head unchanged |
| Robust head valid length, including zero | 0; publish caller's head | 0; same caller-slot publication |
| Mask setup closed or sigset size not 8 | Forward | Forward |
| Mask input/output overlap, failed input copy, failed old-mask copyout | Forward; installed mask unchanged | Same |
| Non-null mask with how outside 0/1/2 | Forward | Forward |
| Null mask query (how ignored) | 0; copy old mask if requested | Same |
| Mask block/unblock/set | 0; strip bits `0x40100` (KILL/STOP) | Same |
| Pending signal deliverable or newly blocked | 0 with pending host work | Same one completion with work, no redispatch |
| Altstack setup closed, input/output overlap or transfer failure | Forward; installed stack unchanged | Same |
| Active altstack with unknown SP, overflowed top or caller on that stack | Forward | Forward |
| Unsupported altstack flags or enabled size below 2048 | Forward | Forward |
| Disabled altstack old-value serialization | `(sp=0, flags=2, size=0)`, result 0 | Same 24-byte output, result 0 |
| Enabled off-stack altstack query/replacement | 0, little-endian 24-byte layout, ONSTACK cleared | Same |
| Clone threads disabled, low exit-signal byte nonzero, missing required flags, unknown flag, null stack | Forward | Forward |
| Native x86 stack/TLS cannot satisfy its qualified 48-bit return convention | Unported ordinal forwards | Forward before copyout, pool claim or record allocation; ARM hook unchanged |
| Clone exact MM absent | Forward | Forward |
| Clone parent/child output preimage unavailable | Forward before pool claim | Same |
| Claim pool empty / gate closed / invalid state | Forward; empty-pool decline retained | Same |
| Missing exact issued identity or retained child slot | Unclaim; Forward | Same |
| Visible tid above signed 32-bit range or immutable projection publication rejected | Unclaim; Forward | Same |
| Shared scheduler records exhausted | Unclaim; Forward | Same |
| Parent output fails | Free exact new record, unclaim; Forward | Same |
| Child output fails after parent output | Restore parent preimage, free exact record, unclaim; Forward | Same |
| Live count overflow or birth publication failure | Restore written outputs, free exact record, unclaim and restore live count when acquired; Forward | Same |
| Clone succeeds | Return visible tid; child result 0, Linux-selected stack/TLS; then publish Born and queue | Same |
| Child mask/altstack/clear/robust initialization | Clone-instant mask; inherited ABI policy; exact new control incarnation | Same |
| Exit threads disabled / gate not Open / no entry / stale or non-Born/non-Published entry | Forward with same named decline | Same |
| Exit registered robust list / thread or process pending signals | Forward; no retirement or clear/wake | Same |
| Exit missing current record/MM, home record, not exact OnCpu claim | Forward with same decline | Same |
| Exit adopted host job | Forward; retained runtime owner completes it | Same; custody preserved |
| Exit host work, cancellation, object operation or wrong current tid | Forward with same decline | Same |
| Exit admission fails | Forward, no membership release | Same |
| Exit last live member | Forward; dropped admission restores state | Same; Linux calls neutral release with floor 1 |
| Nonfinal clear copyout fails | Restore live count, drop admission, Forward; same decline | Same |
| Clear succeeds but native wake admission fails | Restore saved result/live count, drop admission, Forward; host clear/wake remains idempotent | Same |
| Admitted clear/wake | Four zero bytes, then exact-MM futex mask `0xffffffff`, count 1 | Same shared Linux policy |
| Admitted retirement | Release exact current record; commit retained exit token; notify ledger | Same |
| Unexpected commit refusal after release | Mark pending host work | Same |
| Switch after exit | Successor's saved result; switched/work or suspended completion | Same; typed result preserves all 64 bits |
| ARM scheduler timed wake result | `-110` (`ETIMEDOUT`) as native two's-complement bits | Same typed result and native lowering |
| Runtime prepared clear's graph refusal | Drop/cancel prepared write; no clear, wake or terminal publication | Same runtime sequencer and N1 custody |
| Runtime committed clear | Zero write, one wake, then retained terminal publication | Same, consuming shared Linux constants |

The bounded x86 lifecycle fixture declines timed futex waits; it does not
claim a newly qualified timed-wait or runtime completion binding. Ordinary
futex wake hooks receive the decoded mask/count (clear-tid alone selects the
one-waiter policy).

### Neutral transition results

| Before EL1 ABI result | After core result | Effect |
| --- | --- | --- |
| `NoSuchEntry` | Same | Invalid pool index; no mutation |
| `StaleGeneration` | Same | Predecessor incarnation; no mutation |
| `WrongState(observed)` | Same | Preserve observed state and original CAS failure lowering |
| `GateClosed(observed)` | Same | Claim/exit backs out under the same SeqCst gate pairing |
| `PoolEmpty` | Same | Bounded scan of the same eight retained entries |
| Gate transition `Err(observed GateState)` | Same | No policy errno lowering in core |
| `thread_born` overflow `None` | Same | No count increment |
| `try_exit` `LastThread` | Linux maps neutral `MembershipFloor` to the same `LastThread` | No decrement at one |
| Exit admission drop from ExitingBorn | Born | Same rollback |
| Exit admission drop after concurrent publish to ExitingPublished | Published | Same rollback; never stale Born |
| Commit/reap/retire | Same exact state and retained ledger announcement | No sampled census or copyable token |
| Ledger completion underflow `Err(pending)` | Unchanged original authority | No decrement |

## Evidence and red controls

Pre-move AL commands on `0f476ce7a`: EL1 ABI `thread_lifecycle` 20 tests,
EL1 `personality::lifecycle` 20 tests, kernel `prepared_parent_exit_` 7 tests.
After movement, the 20 ABI assertions run under Linux `abi::thread`; the
20 ARM native-frame assertions remain local and execute the moved Linux
owner. The old ABI test path has zero tests because its bodies were deleted;
that zero-test run is not counted as verification.

The order-6 owner fence was RED on an isolated checkout of `0f476ce7a`:
`order 6 must remove lifecycle from PendingFamilies`. Production mutation
controls (restored before green verification) produce these specific reds:

- `ExitAdmission::drop`, ExitingPublished -> Born: X5 publication sees
  `Some((1, Born))`, expected `Some((1, Published))`.
- Linux `CHILD_TID_CLEAR = 1`: X5 Linux wake hook sees 1, expected 0,
  failing `clear before wake` in the production exit path.
- Native context qualifier forced to accept an unavailable stack/TLS: shared
  Linux dispatch returns Served, expected Forward with unchanged outputs/pool.
- Native child FS installation selects the wrong retained word: actual KVM
  child output is 0, expected 62720 (`0xf500`).
- Native successor XSAVE restore suppressed: actual child XMM words retain
  `0x5a`, but resumed parent words are zero; the KVM restoration assertion fails.

The neutral contract `core.lifecycle.publication` evaluates observations at
16/64/256 births with exactly 13 retained cell acquisitions per completed
claim/birth/publish/rollback/retire/reap window. The peer MM remains untouched.
The Linux X5 witness runs actual shared dispatch/policy with both ARM and x86
native frame hooks, parent/child copy failure rollback, host-job refusal,
exact record reuse and clear ordering. Existing ARM AL assertions retain the
real shared queue clear/wake and mask Dekker storms.

The KVM witness executes clone -> parent futex park -> actual native child ->
clear/wake/nonfinal exit -> parent resume in two live processes with private
backing at the same user VA. At 16/64/256 births **per MM**, it measures
96/384/1536 CPL0 semantic entries and exactly as many completions; semantic
host forwards are zero. Host stocks identities and folds completed retirements
while vCPUs stop; it never answers the tested syscalls. Every wait keeps the
existing five-second bound. Secondary-vCPU MP state is explicitly Runnable
because the irqchip's firmware AP startup state otherwise executes no entry.

The native context hooks retain FS, user GS and a qualified aligned complete
x87/SSE/AVX XSAVE image. The child inherits and overwrites XMM15; the parent
must resume with its own original XMM15. TLS is independently checked by an
actual child FS-relative read. Existing CPL0 progress witnesses independently
qualify x87/SSE/AVX switching geometry and native preemption.

## ARM production census

Physical Rust source lines under each crate's `src/`, including comments and
blank lines, excluding `#[cfg(test)]`/`#[test]` item spans and their out-of-line
module descendants, test-only fields/initializers and in-function test blocks. Integration tests are outside `src/`. Counts use `syn`
span locations, propagate test module context, and conservatively count other
cfg/feature branches. This is not the plan's all-source relocation metric.

The standalone Rust census is retained in `docs/perf-results/order6-census`.
Run it with `cargo run --locked --offline --manifest-path
docs/perf-results/order6-census/Cargo.toml -- <tree>`; the base tree is a
`git archive 0f476ce7a` extraction of the three crates' `src/` directories.
It uses the same parser for both snapshots; no source renames receive extra
credit.

| Crate | Before `0f476ce7a` | After | Net reduction |
| --- | ---: | ---: | ---: |
| carrick-el1 | 10,950 | 10,395 | 555 |
| carrick-el1-abi | 9,311 | 8,053 | 1,258 |
| carrick-aarch64 | 13,468 | 13,468 | 0 |
| **Production total** | **33,729** | **31,916** | **1,813** |

All `src/` lines (including tests) fall from 58,578 to 56,270: **2,308**.
That lies in the plan's 2,100–2,600 source-and-witness forecast, 92 below its
2,400 central estimate. The requested production-only reduction is 287 below
the lower forecast bound and 587 below the central estimate. The difference
is moved ABI assertions, retained ARM frame fixtures and the native hook seam;
no reduction credit is taken for runtime constants, new X5 witnesses or new
x86 bindings. The old ARM policy owner is not retained for those fixtures.

## Platform and acceptance limits

Grep audited `ThreadLifecyclePage`, lifecycle transition calls and native
trait consumers in `carrick-vmm-hvf` and runtime macOS paths. HVF has no direct
consumer of the changed page methods; similarly named carrier-VM lifecycle
states are a different owner. Runtime `thread_lifecycle` imports the shared
transition trait; kernel thread-control/exit/signal/ledger callers and tests
switch in this commit. Runtime terminal clear and wake consume Linux policy.
Linux platform runtime/kernel Clippy compiles portable callers; macOS-only
branches require the director's unchanged-ARM signed comparison packet.

The fixture is a bounded two-context native custody binding, **not** the
carrier's production executor-pool binding. Production default-pool exhaustion
and full adopted-job retirement remain unqualified; the retained signed
production witnesses remain required, as the plan explicitly specifies.
No Docker, HVF signed tests, `just accept` or `remote-accept` run on this worker.
The new core files contain no production panic/unwrap/expect/allow or Linux
policy. Unsafe native mappings/context instructions carry SAFETY arguments.

Runtime Linux `--all-targets` Clippy is a baseline blocker: 117 unused/dead-code
errors occur both here and in an isolated `0f476ce7a` checkout. The diagnostic
multisets are identical, with zero additions/removals. Focused shared/native
owner crates and kernel/kernel-example all-target Clippy pass. This does not
confer a macOS runtime all-target or signed result.

## Final worker gate result

Source commit `7d720ba614158bc55f0475605076a0f308f24dc5` passes the four A
commands, moved ABI AL (20), native ARM AL (20), participant AL (7), exact
VM-free X5 targets and exact KVM X5 after rebuilding the image. Retained
entry (3), Linux wave-2 (20), KVM entry (6), extended context (2), focused
all-target Clippy, `just clippy` and `just fmt-check` pass. The required
fixture metadata loop produces no output. No load generators or lifecycle
test processes remain.

The qualified image SHA-256 is
`ec8f072203c92b3f301ecc1371677d138701ffdc86cc1657b13c9abe85979f83`.
This ELF carries no GNU build-id; identity is its content hash. The structured
worker record is `2026-10-06-x86-order6-verification.json`; it is not an
acceptance receipt.

**`just lint-domains` is not green.** Its assembly and local structural
checks pass, but three authority artifact self-tests fail because the
committed Mac capture and seven moved inventory spans disagree. The
clean Linux reconciler cannot authoritatively update Mac spans. The guarded
`just remote-recapture --ref 7d720ba614158bc55f0475605076a0f308f24dc5`
attempt fails before remote contact: `cloudmac` does not resolve here.
A reachable Mac recapture and its reviewed patch are required. No capture
was fabricated and no gate exception was added.

The later source-boundary command also fails with nine `PendingSignals`
findings in unchanged `carrick-signal-core/src/policy.rs`. An isolated
`0f476ce7a` source scan reports the exact same nine diagnostics, with zero
additions/removals. The other remaining lint recipe checks (contracts,
locks, participants, aborts, K1 and serial-host inventory) pass separately.
The full lint result remains red; these supplementary checks do not confer
a gate pass.

PR #68 advanced to `3207564aa` during final verification. The director was
asked to supply the settled rebase target. This work retains its approved
`0f476ce7a` base pending that instruction; no later order-5 fixes are claimed
as integrated. A kept/ported/dropped audit remains required on that rebase.
