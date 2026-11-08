# Admission-release source timing for #1879

Recommend **A, at first carrier publication of each control address**. Host
birth may precede that point: a birth receipt alone cannot name a control for
pending-writer or registry admission. Provision the source before publishing
any address that can do so, including pool addresses. No bounded pre-birth
allocator for all elastic host controls is necessary.

`CarrierLifecycleMappings::publish` is the host-control hook, **not the only
hook**. Fork-stock loans already contain mapped controls and bypass it. A
patch limited to that function would leave ring-born members without sources.
S1a must use the same source transport for those loans and x86 bootstrap;
this is mapping-time attachment, not a second admission policy. If A means
literally that function alone, reject that narrower implementation.

This is a design decision, not evidence that sources exist today. Main still
clears the pending writer without notification. It also drops refused
preparations without publishing admission progress. The changes below remain
proposed. This note changes no production behavior or contract budget.

## Evidence and address reachability

Source references link to fetched GitHub main
`1bf98995a86002f2227e6fe07b243024a013c078`; paths start at `crates/`.
Read #1879's d1, d2 section 3, slice decision and round 1/2 outcomes.
The latest decision separates #887's cause fix from this release-source work;
S1a does not depend on importing #1875's diagnostic contention variant.

The round-2 citations remain valid: the allocator creates more slabs at
[thread_control.rs:73](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-kernel/src/kernel/objects/thread_control.rs#L73) and more control pages at [thread_control.rs:389](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-kernel/src/kernel/objects/thread_control.rs#L389).
`Task::allocate_thread_control` is now located in
[task.rs:863](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-kernel/src/kernel/objects/task.rs#L863); it writes the exact birth identity at line 869.
Host publication calls `publish_thread`, increments live membership and writes
the birth receipt at [thread.rs:508](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-kernel/src/kernel/operations/thread.rs#L508). None publishes the child's guest control
address. The host arena's receipt pin is separate from its pool-control pins
([thread_control.rs:456](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-kernel/src/kernel/objects/thread_control.rs#L456), [thread_control.rs:461](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-kernel/src/kernel/objects/thread_control.rs#L461)).

For host-loaded entry, mapping precedes `CurrentTask` publication:
[thread_lifecycle.rs:165](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-runtime/src/vcpu_loop/thread_lifecycle.rs#L165) maps the lifecycle and control, retains the control, then returns
the two guest addresses. [thread_lifecycle.rs:28](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-runtime/src/vcpu_loop/thread_lifecycle.rs#L28) clears the prior addresses first and
publishes only a resolved pair; Busy leaves the pair zero. The ring's
`lifecycle_refs` validates alignment and aperture containment before deriving
references ([carrick-el1-abi/src/lib.rs:1589](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-abi/src/lib.rs#L1589)). Fresh-root admission checks record identity against
that pair ([native_process_runtime.rs:3465](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L3465)); registration checks it too ([native_process_runtime.rs:2590](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2590)).
Neither check can resolve a host pointer from a numeric tid or birth receipt.
This is trusted runtime publication, not adversarial pointer validation.

Other reachable controls come from retained members or lifecycle pool
addresses: [native_process_runtime.rs:3023](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L3023), [native_process_runtime.rs:224](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L224). Import requires a Born/Published entry,
its control address and a matching retained scheduler record
([native_process_runtime.rs:3311](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L3311)). Host pool addresses are bound only after mapping **each born
control**, including when the slab mapping already exists ([thread_lifecycle.rs:189](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-runtime/src/vcpu_loop/thread_lifecycle.rs#L189)).
Thus binding a source only on a `state.pages` cache miss is insufficient.

An already-running peer can nevertheless observe an **unmapped host birth's
identity**: exit collection makes `HostBorn { identity, index }`, with no
control reference ([native_process_runtime.rs:6401](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L6401)). That receipt can participate in existing
terminal/host cancellation, but cannot acquire a native pending writer or
collide as an admitted registry member. Its completion notification belongs
to the existing lifecycle owner, outside this admission-source table. A host
thread that dies without ever mapping needs no admission source and consumes
no source slot; its host receipt and live-count obligations still must settle.

Ring fork stock is also bounded mapped storage. HVF allocates retained
aperture backing ([metadata_grant.rs:727](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-vmm-hvf/src/metadata_grant.rs#L727)), derives lifecycle loans and installs stock
([fork_stock.rs:290](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-vmm-hvf/src/fork_stock.rs#L290)). The shared layout places controls inside those loans
([fork_stock.rs:440](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-hal/src/fork_stock.rs#L440)). Both ISA adapters lend the mapped array to the shared runtime
([aarch64_process.rs:2546](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/aarch64_process.rs#L2546), [native_process.rs:691](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-x86-cpl0/src/native_process.rs#L691)). Stock publishes control pointers at
[thread_stock.rs:202](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime/thread_stock.rs#L202), and fork takes a pending writer at [native_process_runtime.rs:7382](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L7382), without calling
the host `publish` hook. Source storage must accompany the loan; source
activation for each new incarnation must precede stock/Born publication.
KVM also publishes bootstrap controls directly ([cpl0_boot.rs:2115](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-vmm-kvm/src/cpl0_boot.rs#L2115), [cpl0_boot.rs:2165](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-vmm-kvm/src/cpl0_boot.rs#L2165));
its metadata VA uses the x86 aperture base ([cpl0_boot.rs:113](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-x86-cpl0-host/src/cpl0_boot.rs#L113)).

## Origins, publishers and capacity

R = native registry lock; G = native graph lock; S = signal-resource lock;
Q = admission object queue; L = scheduler slot/run-queue lock.
The order column specifies the proposed source operations relative to actual
locks, detailed below. **C** means the carrier's mapped-control source pool,
charged to retained metadata backing; **W** means the admitted scheduler
record/operation arena for waiters. C bounds sources, W bounds parked work;
`ZONE_RECORDS` is not a control-allocation bound.

| Origin and real predicate | Waiter and source | Release publisher | Lock order; capacity owner |
|---|---|---|---|
| OldRecordRetained: old record still exists ([native_process_runtime.rs:1997](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L1997)) | Rehome checkpoint; old member's sidecar plus exact old RecordRef. Resume self-owned live work instead of parking on it. | Successful host-home release/discard and both final record-retirement paths ([carrick-sched-core/src/lib.rs:3945](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/lib.rs#L3945), [carrick-sched-core/src/lib.rs:3929](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/lib.rs#L3929), [carrick-sched-core/src/lib.rs:2777](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/lib.rs#L2777), [carrick-sched-core/src/lib.rs:2793](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/lib.rs#L2793)). Notify when the predicate actually changes, not on a refused retirement. | Probe R→G; retain notification through scheduler mutation, publish after all guards. C owns old source, W owns checkpoint. |
| ExecutionKeyCollision: destination member key occupied ([native_process_runtime.rs:2001](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2001)) | Rehome checkpoint; conflicting occupant's sidecar, not applicant's. Identical owner resumes. | Rehome removal ([native_process_runtime.rs:2068](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2068)), member/process unregister ([native_process_runtime.rs:2798](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2798), [native_process_runtime.rs:2828](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2828)) and completed-host cleanup ([native_process_runtime.rs:1743](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L1743)). | Mutate R→G→S where rehome needs S; publish after R/G/S. C retains occupant, W retains intended key/context. |
| RecordKeyCollision: destination record index occupied ([native_process_runtime.rs:2002](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2002)) | Same rehome entry, occupant source plus zone/RecordRef generation. | Same record-index removals; source survives scheduler record reuse. | Same R→G ordering; no Q under R/G. C owns occupant source, W owns exact intended record. |
| ThreadRegistrationCollision ([native_process_runtime.rs:2644](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2644)) | Registration checkpoint, occupant member/record source. Exact existing membership resumes. | Unregister/rehome/cleanup above, after index removal. | R→G at [native_process_runtime.rs:2634](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2634)/[native_process_runtime.rs:2657](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2657); publication after unlock. C owns occupant source, W keeps unconsumed adopted birth and prepared resources. |
| ThreadPendingCustody: exclusive writer CAS fails ([native_process_runtime.rs:2690](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2690)) | Prepared registration on that exact mapped control's source. Existing member reuses its projection; no second writer. | NativePendingCustody Drop, after Release-clear ([thread.rs:385](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-personality-linux/src/abi/thread.rs#L385)), including rollback before registration. | CAS under R→G; proposed publication after guards. C owns control source, W owns prepared admission. |
| FreshRootPendingCustody ([native_process_runtime.rs:3569](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L3569)) | Root checkpoint on exact leader/imported member source, only for an independent writer. Self-held projection transfers/resumes; zero enrollment. | Same writer-release hook, including partially prepared root teardown. | Fresh preparation has no R/G held at CAS; teardown may also occur under owners, so defer publication. C owns source independently of runtime creation, W owns unpublished home. |
| RootRegistrationCollision: member/record/group occupied ([native_process_runtime.rs:1886](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L1886)) | Unpublished root checkpoint on conflicting member/root sidecar. Group retains root source until group removal. | Root/member rehome/removal; final group removal at [native_process_runtime.rs:2845](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2845). | R acquisition at [native_process_runtime.rs:1883](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L1883) follows released graph snapshots; retain ticket and publish after R. C owns conflicting source, W owns applicant. |
| Pre-registration control, before mapping | No admission waiter can name an unmapped host control; only its receipt is visible. A mapped but unregistered control already has C's source. | No admission publication owed for a never-mapped control; mapped provisional owners use writer/rollback hooks. | Source bind before pointer publication, outside R/G/S/Q nesting; C excludes unmapped host controls. |
| Refused admission, then parked | Same retained operation, on refusing owner's source. Refusal itself is not the release event. | Eventual writer/index/record release above, even when that owner never registered. If Q itself refuses enrollment, its current holder drains deferred admission ([object_wait.rs:717](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L717), [object_wait.rs:1090](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L1090)). | Drop R/G/S/L before enrollment; Q-held recheck uses atomics only. C owns source; W's intrusive operation owns deferred admission, with no extra waiter allocation. |

A collision without a demonstrated independent releasing owner is not a
license to park. Authenticate same-owner handoff or retained retirement first;
only a proven impossible identity is an invariant. Contention cannot become
fatal, errno, polling, a host crossing or a timer-based retry.

## Lock-order analysis

Existing lock sites establish R→G in rehome
([native_process_runtime.rs:1947](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L1947), [native_process_runtime.rs:1953](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L1953)) and registration
([native_process_runtime.rs:2634](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2634), [native_process_runtime.rs:2657](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2657)). Rehome calls projection rehome while both are held
([native_process_runtime.rs:2063](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2063)); that takes S at [native_process_signals.rs:262](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_signals.rs#L262). Project creation also takes S
([native_process_signals.rs:358](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_signals.rs#L358)). Unregister takes R then G ([native_process_runtime.rs:2804](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2804), [native_process_runtime.rs:2829](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L2829)).
Final thread cleanup drops G before calling unregister ([native_process_runtime.rs:8391](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime.rs#L8391)).
Do not add an opposite G→R edge through a notification callback.

Existing native-service cancellation takes its object queue then G
([service.rs:463](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime/service.rs#L463), [service.rs:470](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime/service.rs#L470));
owner-wait enrollment nests its service queue and graph inside the outer
object-queue transaction ([service.rs:2067](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime/service.rs#L2067),
[service.rs:2078](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime/service.rs#L2078), [service.rs:2080](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime/service.rs#L2080)).
Preserve those domain-specific edges; do not introduce G→admission-Q or a
reverse nested-queue edge through projection destruction. Scheduler queue
handling can also acquire L while holding an object queue
([object_wait.rs:2303](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L2303),
L's actual CAS at [carrick-sched-core/src/lib.rs:3490](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/lib.rs#L3490)).
`ObjectNotificationTicket::publish` can drain synchronously
([object_wait.rs:878](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L878),
[object_wait.rs:1955](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L1955)),
despite its nonblocking admission. It is not a queue-lock-free callback.

For the new domain, reserve counted publication custody without taking Q
([object_wait.rs:596](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L596)) while R/G/S or scheduler ownership still authenticates the
subject. Change the predicate there, move removed members/projections into
owned cleanup, release all those guards, then publish. Writer Drop must clear
pending and the writer bit before notification, retaining control/source until
the ticket is handed back. It must not take R, G or S, and must not synchronously
publish under a caller's R/G/S/L or another object queue. Drop under those
locks transfers a pre-admitted publication obligation to their outer cleanup;
it does not allocate or attempt another lock. The existing stock callback
([thread_stock.rs:18](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime/thread_stock.rs#L18)) illustrates delivery, not proof that arbitrary Drop sites are safe.

Do not re-enter R/G/S from Q's `still_blocked` closure: it executes with Q
held, after linking ([object_wait.rs:1457](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L1457)). Proposed sidecars therefore carry an atomic
predicate revision in addition to the queue epoch. Record the revision with
the failed predicate under its authority; every relevant predicate change
advances it before releasing that authority. Under Q, recheck that revision,
exact incarnation and closure state once, plus the atomic writer flag where
applicable. Changed means rerun the full predicate after dropping Q. An
unchanged revision preserves the failed-predicate observation. A release in
the unlock-to-notify window is covered by the retained publication ticket.
This avoids Q→R/G and does not turn lock refusal into a false predicate.

The host mapping state lock ([thread_lifecycle.rs:166](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-runtime/src/vcpu_loop/thread_lifecycle.rs#L166)) and aperture lock
([metadata_grant.rs:1153](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-vmm-hvf/src/metadata_grant.rs#L1153)) must remain outside these ring locks. Bind sources during
metadata provisioning, then publish pointer bindings. Do not call back into
mapping or the host allocator from a contention consumer. Exact hooks must
return owned effects to the outer release boundary rather than invoke a
registry/graph closure from scheduler record retirement.

## Recommendation and S1a outline

A covers all five requested origin families with the hook coverage above;
B's global pre-birth host-control allocator is unnecessary. Replace d2's
“before guest-visible birth” with “before first publication of an admission-
reachable control address; before each subsequent incarnation is published”.
A mere change in wording, without fork-stock and reuse hooks, is insufficient.

Use a neutral mapped-control admission owner shared by both ISA lanes. It
retains one sidecar/source for `(carrier, retained extent identity, control
byte offset, control incarnation)`. Exact birth identity is task/birth/thread,
not host pid, namespace tid, mutable execution snapshot generation or raw VA.
For unused pool storage, reserve the source slot with the loan; activate its
fresh generation before birth. Do not transport Rust pointers/Arc callbacks
between host and ring address domains. Carry a typed key/identity in ABI
storage and reconstruct a borrowed source only through retained authority.

Provision a disjoint object-wait range after existing domains
([object_wait.rs:35](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L35)), never borrow member-stock keys. A conservative source-slot bound
is `floor(EL1_DYNAMIC_METADATA_SIZE / size_of::<ThreadControlSlot>())` per
carrier: currently 64 MiB ([carrick-el1-abi/src/lib.rs:640](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-abi/src/lib.rs#L640)) and 448-byte controls
([thread.rs:1582](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-personality-linux/src/abi/thread.rs#L1582)). Count distinct retained control storage, including unused
loan controls and closing sources; aliases share one admission. The metadata
owner must prevent overlapping claims. This is an upper bound, not a promise
that the aperture can contain that many controls alongside other metadata.
Derive constants from final layout, and account for queues, handback headers,
sidecars and checkpoints in both images' size/alignment/protocol hashes.
No new control allocation or source-table scan occurs on refusal. If binding
contends, keep metadata publication owned and await its existing holder's
release; never publish a source-less address or add a new fallback.

Retirement order is: close source admission; invalidate/revoke address
publication under the existing lifecycle owner; advance predicate revision;
publish wake/revalidation; drain waiter operations, callbacks and tickets;
release the durable source; then reset/rebind storage with a fresh generation
and finally permit unmap/reuse. Queue rebinding already rejects publishers or
linked waiters ([object_wait.rs:2067](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L2067)); dropping the durable source alone does not wake
anyone ([object_wait.rs:908](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L908)). Waiters must cancel/revalidate without deleting new
ownership. Keep source/control capacity charged until this drain completes.
Host reset/free-list reuse ([thread_control.rs:378](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-kernel/src/kernel/objects/thread_control.rs#L378), [thread_control.rs:432](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-kernel/src/kernel/objects/thread_control.rs#L432)), ring stock reset
([thread_stock.rs:178](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/native_process_runtime/thread_stock.rs#L178)) and fork-loan scrubbing ([fork_stock.rs:599](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-hal/src/fork_stock.rs#L599)) all need this custody.
Carrier shutdown currently closes pages, clears pins and attempts retirement
([thread_lifecycle.rs:213](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-runtime/src/vcpu_loop/thread_lifecycle.rs#L213)); insert source settlement before pin/backing release. Refused
unmap retains backing and the closed source owner until settlement, never
recycles either on Busy.

S1a should implement layout/key/source custody, all publication and retirement
hooks, atomic revision rechecks, and scheduler wake integration first. S1b
then replaces mixed admission errors with existing `Refusal::Contended` and
owned checkpoints; S1c retains signal delivery. Reserve checkpoint storage
before consuming birth. ARM AdmissionHome currently discards only an
untransferred free home without an object operation ([aarch64_process.rs:654](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-el1-linux/src/aarch64_process.rs#L654)); encode
that transfer for both ISAs rather than keeping a borrowed frame across park.

Red-first witnesses must drive production mapping, stock, registration,
rehome and entry paths with real held authorities: each of seven origins
Busy once then release/resume once; release before observation/enrollment,
after link and after park; failed preparation drops its writer before any
registry member exists; never-mapped host birth and peer exit receipt;
fork-stock member admission without host `publish`; cancellation/SIGKILL;
two live members with wrong-source and old-generation releases; same-address
reset and refused unmap; self-held fresh-root handoff with zero enrollment.
Assert no consumed adopted birth on refusal, no duplicate projection or
completion, no contention-to-fatal/errno, zero allocation on refusal, no
source/control scan and no reuse until all tickets drain. Stress source
capacity separately from waiter capacity. Existing object-release work is
bounded by retained records ([object_wait.rs:1124](https://github.com/carrick-sh/carrick/blob/1bf98995a86002f2227e6fe07b243024a013c078/crates/carrick-sched-core/src/object_wait.rs#L1124)); preserve that bound, do not add
retries or larger budgets.

Applicable families are `process.native.arm-admission`,
`kernel.el1.thread-lifecycle`, `kernel.el1.signal-delivery-owner` and
`process.native.short-lock`. Their Linux authorities are clone, signal and
exit/wait semantics; internal ownership waits must preserve those operations.
Add missing semantic/work bindings red-first before implementation. Estimate
S1a at 3–4k changed lines including witnesses; if the full hook census exceeds
the cap, split transport/layout from owner hooks, with neither claiming
admission recovery before both exist. Shared lifecycle/ABI lock-order review,
VM-free tests, CPL0 build and signed/KVM composition remain required.

## Verification limits

This is source analysis of main, not a working sidecar or a runtime proof.
No guest, Docker oracle, signed artifact, KVM population or timing run was
performed. No GPL implementation sources were consulted. Queue/source byte
cost, final layout fit, exhaustive record-predicate transition hooks (including
claim/home changes beyond final retirement), every callback/Drop context and
all backend bootstrap sites still need implementation review and witnesses.
The single `publish` hook is demonstrably insufficient coverage; no unseen
backend is assumed to call it. This design does not close #1879 or #887.
