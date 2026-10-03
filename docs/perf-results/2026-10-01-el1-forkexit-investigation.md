# EL1 fork and thread-lifecycle acceptance investigation

Source baseline: `16ed0cced`, branch `work/forkexit`.

This is an investigation receipt, not acceptance. No production lifecycle
integration or COW ownership change is included. Acceptance ceilings, slopes,
timeouts and workload concurrency are unchanged.

## Production lifecycle route

`carrick-el1/src/personality/dispatch.rs::dispatch_syscall` calls
`dispatch_syscall_with_ipc`, which passes `None` as the lifecycle venue to
`dispatch_syscall_with_lifecycle`. The only `LifecycleVenue` implementation
is in `personality/lifecycle/tests.rs`. Thus production cannot call the
existing EL1 clone/exit handlers, regardless of their unit-test results.

The missing integration has several authority prerequisites:

- `Thread::control` is embedded in a host-heap `Thread`, not guest-mapped
  metadata. Publishing a second copy would split signal-mask, alternate-stack
  and robust-list authority. The existing slot must become shared storage.
- `ThreadLifecyclePage` has no production owner or mapping. Its live count,
  pending-signal summary, identity entries and host registry membership must
  participate in one publication protocol.
- `ThreadIdentityPool` reserves tid and namespace identity, whereas the
  exact `ThreadKey` serial is assigned later in
  `ThreadCloneReservation::prepare`. An EL1-born record must already name
  the exact identity that host settlement and adoption will use.
- `ThreadLedger::settle` consumes host `PreparedThreadClone` values. It does
  not consume ABI `Born` or `ExitedInZone` entries. Settlement must precede
  context resolution and every membership observer; publishing only from
  the next syscall of the new thread is insufficient.
- Fork/exec, ptrace, seccomp, credentials and uid-limit changes must close
  guest admission before acquiring conflicting host authority. Teardown
  must settle or revoke entries and release their identities and backing.
- EL1 exit currently declines an executor's home record, pending signals,
  registered robust lists and the last thread. Production admission must
  preserve these conditions and account for host-adopted threads, not just
  the unit-test shape of an unadopted born thread.

These are the L4 integration obligations in
`docs/superpowers/plans/2026-09-30-el1-thread-lifecycle.md`. Passing a
non-`None` venue alone cannot safely implement them.

## Fork exit attribution

`validate_el1_memory_cow_report` still enforces
`exits <= forks * pages / 4 + 64`: 144 at 20 forks and 16 pages. The test also
requires zero completed host COW transactions and a host-exit slope below
0.125 per added page. A total-exit failure alone does not identify COW faults.

The witness now prints its existing exhaustive host-exit-class counters and
forwarded syscall counts before report validation. It adds no instrumentation
to production execution and changes no assertion. This distinguishes
forwarded thread lifecycle work from host fault exits in a red receipt.

## Separate ptrace witness

`el1_thread_lifecycle_fork_during_clone_storm` runs `fork-storm`.
`options_ok` belongs to the separate
`el1_thread_lifecycle_ptrace_traceclone` test and `ptrace-clone` fixture.

The HVPatch `ptrace` dispatcher in `dispatch/proc.rs` has no
`PTRACE_SETOPTIONS` arm; an unmatched request returns `LINUX_ENOSYS`.
There is also no `PTRACE_GETEVENTMSG` request handler or TRACECLONE event
publication in the kernel/runtime. Merely accepting SETOPTIONS would not
satisfy the witness's clone-event and initial-child-stop requirements.

The fixture now captures `options_errno` immediately after SETOPTIONS fails,
before PTRACE_CONT can overwrite errno. Its success predicate is unchanged.

## Verification

The first signed command (exit 1) was:

```sh
CARGO_BUILD_JOBS=3 CARRICK_RUN_ID=forkexit-cow-red-20261001-01 ./scripts/test-signed.sh carrick-embed el1_fork_cow_resolves_in_guest --nocapture
```

At 20 forks and 16 pages:

- Both processes verified all 320 pages; isolation was true.
- Total exits: **5391**, ceiling **144**.
- Guest lane selected: 0; refused: 1, for the census reason.
- Completed host COW transactions: **459** (439 stage-fault,
  20 privileged-internal); EL1 resolutions: 0.
- EL1 declines: 161 not-private, 277 pool-empty, 1 editor-busy.
- Exit classes: canceled 323, idle 383, kick 38, syscall 3961,
  maintenance 686, fault 0, metadata 0, other 0.
- Forwarded calls included exit 160, clone 180, sigprocmask 767,
  sigaltstack 483, gettid 160, mmap 347, munmap 322, mprotect 321.
- All 25 grants returned, 491520 bytes in each direction.
- Entitlement negative control passed. Both scoped cleanup IDs reported
  zero remaining processes.

Thus the zero *fault exit class* does not establish zero host COW: the
independent host-COW ledger is red too. Child anonymous-root admission is
owned by the other worker and must be integrated before final attribution.

The tested binary was `target/release/deps/el1_sched-76baf36c966ce982`,
SHA-256 `3c45112eca0cbc2723c9c48af2b828a98aedd089ab22efc64a62b6b1946b46de`.
The hypervisor entitlement and `__dof_carrick` section were inspected.
Its CDHash was not retained before the next scripted signing; this is red
diagnostic evidence, not a complete promotion receipt.

`CARGO_BUILD_JOBS=3 just fmt-check` passed. No green acceptance is claimed.

The separate ptrace command also exited 1:

```sh
CARGO_BUILD_JOBS=3 CARRICK_RUN_ID=forkexit-ptrace-red-20261001-01 ./scripts/test-signed.sh carrick-embed el1_thread_lifecycle_ptrace_traceclone --nocapture > /tmp/forkexit-ptrace-red-20261001-01.log 2>&1
```

Its exact semantic line was:

```text
ptrace-clone initial_stop=true options_ok=false options_errno=Some(38) clone_event=false new_tid=0 new_thread_stopped=[] exit=Some(0)  ok=false
```

Errno 38 is Linux ENOSYS, confirming the unsupported SETOPTIONS request.
The negative control passed and both scoped cleanup IDs reported zero.
The ptrace artifact had SHA-256
`b1dc0fd73813d3ef581aedf7c0742b9604afc8169db640d5b4ed838f5df368c9`,
CDHash `ab013fe08e9a443573a3f99b0ced9248ea5fe696`, and LC_UUID
`A4BF296B-2207-3969-9C2C-9BD102329EC5`. Each test-signed invocation re-signs
the artifact, so these identities do not carry over to subsequent runs.

The spawn-slope command exited 1:

```sh
CARGO_BUILD_JOBS=3 CARRICK_RUN_ID=forkexit-spawn-red-20261001-01 ./scripts/test-signed.sh carrick-embed el1_thread_lifecycle_spawn_slope --nocapture > /tmp/forkexit-spawn-red-20261001-01.log 2>&1
```

All guest semantic lines passed at 128, 512 and 2048 total threads.
Forwarded exits were 131, 518 and 2068; total exits were 2875, 11160 and
42667. The first exit slope was **1.0078**, against **<0.05**. All measured
clone, exit, sigprocmask, sigaltstack and gettid served counts were zero.
From 128 to 512 threads, forwarded slopes were clone 1.0, sigprocmask 4.0,
sigaltstack 3.0 and gettid 1.0. The negative control passed; scoped cleanup
reported zero for both IDs.

The signal-mask and altstack handlers exist in `lifecycle.rs`. They are not
refused by `setup_open` in these production runs: the missing venue prevents
`lifecycle::serve` from being called in the first place. The director
confirmed that L4 must enable one shared venue for clone, exit, signal masks
and altstack together. That supersedes the temporary report-only restriction
on setup serving. Cheap-layer signal inheritance/delivery contracts and the
full signed signal and EL1 gates remain required; ptrace stays report-only.

The director also confirmed that guest-lane refusal is expected on this
baseline: descriptor-lane default-on lands in landing I. Final acceptance
must be remeasured after that landing; the numbers here are not acceptance
of the integrated tree.

The fork-storm command **passed**, exit 0:

```sh
CARGO_BUILD_JOBS=3 CARRICK_RUN_ID=forkexit-storm-red-20261001-01 ./scripts/test-signed.sh carrick-embed el1_thread_lifecycle_fork_during_clone_storm --nocapture > /tmp/forkexit-storm-red-20261001-01.log 2>&1
```

It completed 16 forks while spawning 260 storm threads, with `bad=0` and
all 16 child thread counts equal to one. Negative control and scoped cleanup
passed. The run-id's `red` label describes the requested baseline attempt,
not its verdict. The script's receipt is retained alongside this note as
`2026-10-01-el1-forkexit-storm-receipt.jsonl`.

## Open work

No production fix or red-to-green acceptance is claimed. L4 shared storage,
publication/adoption, settlement and gates remain unimplemented. The
separate ptrace feature is diagnosed but not fixed. Landing I has not been
rebased into this investigation.

The requested `just test-kernel`, serial `carrick-vmm-hvf` lib tests,
`just clippy`, `just lint-domains`, full signed `el1_` batch and CLI
`hvpatch-exit-attribution` trace have not been run here. The focused signed
counters establish the reported reds, not completion of those gates.

## L4 contract checkpoint

The first kernel contracts reserve identities in two live processes and
prepare them in reverse order, and mutate each parent's mask and affinity
between reservation and preparation. They require identity and inheritance
to be fixed at claim time. A separate ABI contract requires only the exact
string `0` to disable lifecycle serving, including whitespace counterexamples.

These contracts are not yet observed red. The command
`CARGO_BUILD_JOBS=3 cargo test -p carrick-kernel --lib lifecycle_ -- --nocapture`
was interrupted with exit 130 during compilation when the director paused
all builds and tests for landing I. No test executed. Production code remains
unchanged. After resume, run the focused contracts, implement their fixes,
then continue shared backing, venue wiring, settlement and admission work.
Rebase onto landing I before signed acceptance, as directed.

### Resume on landing I

Rebased onto `work/land-i` at `31ba5ef44`. The focused kernel contracts
then failed with serials 21 and 17 in reverse adoption order, and an inherited
mask of zero instead of `0x400`. The ABI hatch contract failed on `" 0"`.
Both test commands exited 101, with actual assertion failures.

The identity reservation now owns its full `ThreadKey`, exposed before
preparation, and preparation retains that exact key. A detached clone seed
captures the blocked mask and affinity at claim instead of rereading the
caller at adoption; it does not copy non-inherited pending signal queues.
Hatch parsing compares the exact string without trimming.

The ledger module passed all 11 tests after these fixes, and all 107 ABI
tests passed. `CARGO_BUILD_JOBS=3 just test-kernel` and
`CARGO_BUILD_JOBS=3 cargo test -p carrick-el1 --lib` also exited zero (181
EL1 tests). The serial `carrick-vmm-hvf --lib` suite passed with 681 tests
and three ignored. These are L4 prerequisites, not a production venue: shared
control backing, EL1 venue wiring, birth/exit settlement and adoption,
admission gates, and teardown remain open. No signed acceptance is claimed
for the rebased tree.

### Control storage and adoption checkpoint

The two-live-process backing contract failed because the original control
slot was inside the host `Thread` allocation. Mapping it would also expose
host pointers and locks. Control slots now live in aligned, control-only
pages owned by a task's arena. `ThreadControlLease` pins the exact slot and
its `(TaskKey, ThreadKey)`; retaining a pin prevents reuse without retaining
the task or kernel graph. Released slots are reset before a new claim.

After introducing the pre-adoption lease, the adoption contract failed on
different slot addresses: the old preparation path allocated fresh storage.
Preparation now adopts the claim's lease without resetting mask, altstack
or robust-list state that EL1 may have changed before host adoption.

This is the storage/host-adoption foundation only. No stage-2 mapping or
production `LifecycleVenue` is installed yet. Process lifecycle pages,
identity-pool publication to EL1, settle-before-context, conflicting-authority
gates, exit settlement and carrier teardown still need integration. The
arena currently retains free pages until the task drops; guest mapping
retirement has not been implemented or verified. Signed acceptance and the
full clippy/domain gates remain outstanding for this checkpoint.

The storage/adoption checkpoint passed `CARGO_BUILD_JOBS=3 just test-kernel`.
Review then found that numeric task keys can repeat across kernel instances.
The equal-key arena contract failed under the original key comparison.
Adoption now checks the issuing arena's retained authority; a two-live-kernel
contract uses identical numeric task/thread keys and rejects both cross-owner
leases. The final `just test-kernel` run also exited zero, including 2,337
kernel-lib tests, one ignored, and the semantics suites. Logs are
`/tmp/forkexit-l4-control-test-kernel.log` and
`/tmp/forkexit-l4-control-owner-test-kernel.log`.
The final `CARGO_BUILD_JOBS=3 cargo test -p carrick-el1-abi -p carrick-el1 --lib`
also exited zero: 107 ABI tests and 181 EL1 tests. Its log is
`/tmp/forkexit-l4-control-el1-libs.log`.

### Retained metadata mapping and lifecycle-page storage

The metadata aperture previously accepted only backing it allocated itself.
`CarrierMetadataAccess::map_retained` now maps retained ABI-only storage
without copying it, through the existing carrier stage-2 publication and
inventory transaction. It returns a carrier-bound retirement authority;
metadata extent pins exclude retirement, guest metadata returns cannot free
retained backing, and a failed unmap preserves both backing and aperture
reservation. VM destruction removes the mapping while outstanding host pins
continue to retain its bytes. The existing fixed EL1-only stage-1 aperture is
reused; no anonymous mmap or MAP_FIXED serving path is changed.

Every task control arena now owns one granule-aligned lifecycle page, shared
by its control leases. The page contains only shared ABI bytes and padding;
the Arc header and host bookkeeping remain outside the mapped granule. The
hatches are read once using the existing exact-zero parser. Equal numeric
keys in two live arenas do not share their lifecycle gate or page.

Both new API contracts first failed to compile because these operations did
not exist; these were missing-API reds, not behavioral assertion failures.
The focused kernel contracts subsequently passed. The full `just test-kernel`
gate passed (2,337 library tests, one ignored, plus semantics suites). The
serial HVF library gate passed with 682 tests and three ignored. The mapping
contract populates equal aperture addresses in two live carriers and checks
exact tokens, failed publication rollback, guest-return rejection, pinned
retirement refusal, failed-unmap retention and independent owner release.

This is still a partial step 1. The runtime has not installed these mappings
for threads and `dispatch_syscall_with_ipc` still passes no lifecycle venue.
No guest lifecycle service has been activated by this slice. Next is the
runtime mapping owner and the exact thread/record binding used by the real
EL1 venue; then ABI birth/exit settlement before context and membership,
conflicting-authority admission, and process/carrier teardown. Pending-signal
summary and host-adopted live-thread accounting must be connected before
opening that venue. Signed acceptance remains unrun on this tree.

The retained mapper currently reserves aperture space in the existing
512 KiB allocation units even for a 16 KiB backing; it maps only the actual
backing bytes. This spends virtual aperture capacity, not extra RAM. A caller
that drops retirement authority without retiring keeps the backing in
carrier custody until VM destruction. Runtime ownership must explicitly
retire these mappings after revoking guest references.

The mapping slice is committed as `2ff87dafc`. `CARGO_BUILD_JOBS=3 just
clippy` passed on that source snapshot. The abort inventory then reported
three missing classifications from the prior control-ownership foundations:
`Thread::prepare_clone`, `ThreadControlArena::allocate`, and
`ThreadControlLease::allocation`. These are internal ownership/allocation
invariant failures, not guest resource refusals; explicit carrier-fault
rationales were added without changing a debt ceiling. The abort checker
subsequently passed all four shards. Additional process-level assertions
exercise page separation and gate isolation in two live forked tasks, equal
numeric keys in two live kernels, and shared process-page identity at clone
claim.
The strengthened `cargo test -p carrick-kernel --lib lifecycle_` run passed
all 21 selected tests (`/tmp/forkexit-l4-process-page-contracts.log`).

Before runtime publication, the existing Box/Arc-allocated kernel backing
also needs qualification against the host VM-object lifetime: the current
metadata allocator uses MAP_SHARED backing specifically to preserve the
host/HVF alias across host COW. Stable Rust addresses alone do not prove
that property. No unsafe retained-backing implementation for these kernel
leases has been installed by this slice.

### Final host-gate receipt for this partial slice

On the committed source through `0f874d06f`, all of these completed with
exit zero, with `CARGO_BUILD_JOBS=3` and builds serialized:

- `just test-kernel` (`/tmp/forkexit-l4-lifecycle-page-test-kernel.log`);
- `cargo test -p carrick-el1 --lib`: 181 passed
  (`/tmp/forkexit-l4-retained-mapping-el1.log`);
- `RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib`: 682 passed,
  three ignored (`/tmp/forkexit-l4-retained-mapping-hvf.log`), followed by
  the strengthened retained-mapping contract passing separately;
- `cargo test -p carrick-kernel --lib lifecycle_`: 21 passed after adding
  the process-scope assertions;
- `just clippy` (`/tmp/forkexit-l4-clippy-final.log`);
- `just lint-domains` (`/tmp/forkexit-l4-lint-domains-accepted.log`).

The full domain gate initially exposed the unclassified immutable
`LIFECYCLE_HATCHES` policy static, then stale K1 taxonomy positions. Both
were fixed explicitly and committed. The final run passed; its compiler
census remains the macOS subset, with off-host profiles reported pending.
The taxonomy correction changed 47 line positions only, with no new,
removed or reclassified authority sites.

These receipts do not close L4. Step 1 still lacks runtime publication and
an actual venue passed by `dispatch_syscall_with_ipc`; the shared host
VM-object backing requirement remains unqualified for the kernel heap
storage. ABI birth/exit settlement, conflicting-authority admission,
host-adopted accounting, pending-signal integration and lifecycle teardown
remain open. No signed acceptance was run, and no new fork-COW residual-exit
receipt for this tree is claimed.

### Shared host VM-object backing prerequisite (forkexit-sol)

The control-slot and lifecycle-page allocations now reuse
`carrick_host::host_mapping::OwnedHostMapping` with `MAP_SHARED` anonymous
backing. The mapping owner contains the aligned ABI value; Arc metadata,
allocator state and free-list bookkeeping remain outside the published
16 KiB granule. A module-private `AbiPage` bound permits only the control and
lifecycle layouts. Existing leases retain this exact allocation and continue
to delay slot reuse until the final pin drops. No snapshot or second signal
storage was introduced.

The cheapest capable reducer is
`kernel::objects::thread_control::tests::serial_host::lifecycle_backing_keeps_one_vm_object_across_host_fork`,
under `kernel.el1.thread-lifecycle`. It holds two live arenas with equal
numeric keys and forks the host. The child performs only atomic ABI writes
and async-signal-safe syscalls before `_exit`; the parent bounds publication
with a five-second poll, reaps its exact child and checks both shared writes
and isolation of the other arena. Before the fix the control mask assertion
failed: parent read 0 after child stored 1024. Red command (the initial test
was named directly under `tests`, before moving into `serial_host`):

```sh
CARGO_BUILD_JOBS=3 RUST_TEST_THREADS=1 cargo test -p carrick-kernel --lib serial_host_lifecycle_backing_keeps_one_vm_object_across_host_fork > /tmp/forkexit-sol-vm-object-red.log 2>&1
```

The focused green command selected all four backing contracts (all passed):

```sh
CARGO_BUILD_JOBS=3 RUST_TEST_THREADS=1 cargo test -p carrick-kernel --lib thread_control::tests > /tmp/forkexit-sol-vm-object-green.log 2>&1
```

This qualifies host-fork aliasing; it does not demonstrate a live HVF
publication of these leases. The allocation reserves 32 KiB host virtual
space to accommodate hosts with mmap alignment smaller than 16 KiB, using
one mapping per ABI page and touching only the aligned 16 KiB value. The
unused slack is not exposed to EL1. Mapping failure is currently a carrier
fault in the existing infallible constructors, like the replaced allocation
failure; guest-visible fallible admission is not implemented by this slice.
The existing refill abort fingerprint was explicitly rebound after reviewing
its unchanged invariant and the backing-constructor substitution.

Step 1 remains partial: runtime publication, mapping retirement ownership
and the production `LifecycleVenue` are still absent. ABI Born/ExitedInZone
settlement, settle-before-context/membership, conflicting-authority closing,
pending signals, host-adopted accounting and teardown remain outstanding.
No signed acceptance, spawn-slope improvement, fork-storm result or fork-COW
residual-exit result is claimed for this slice. No Docker was run.

The final typed backing passed `CARGO_BUILD_JOBS=3 just test-kernel`
(`/tmp/forkexit-sol-vm-object-test-kernel.log`), including 2,337 kernel library
tests, one ignored, and the semantics suites. The serial-host placement check
and runtime abort shard check passed. `CARGO_BUILD_JOBS=3 just test` failed
(`/tmp/forkexit-sol-vm-object-test.log`) in two unchanged MMU-core tests:
`debug_walk_host_pages_matches_the_per_page_walk` and
`debug_walk_host_pages_resolves_each_arena_once_however_many_pages`, each
unwrapping `UnresolvedArena(65536)`. `git diff --exit-code work/land-i --
crates/carrick-mmu-core` is empty; that crate has no kernel dependency (its
only dev dependency is `carrick-mem`). This is source/dependency attribution,
not a pre-change execution receipt or a waiver. The full host gate remains
red and was not retried. Its early failure also prevented the later kernel
serial-host recipe from running, so the backing witness is checked separately.

Director ruling after the failed host gate: both MMU-core failures are
pre-existing on `work/land-i`; landing I2 contains the isolation-fixture fix.
They are not a lifecycle-slice blocker. This confirmation does not turn the
recorded `just test` exit into a pass; no I2 merge was made here.

The final typed backing's separately selected serial host-fork contract
passed (one selected test):
`CARGO_BUILD_JOBS=3 RUST_TEST_THREADS=1 cargo test -p carrick-kernel --lib
lifecycle_backing_keeps_one_vm_object_across_host_fork`, with output in
`/tmp/forkexit-sol-vm-object-final-serial.log`.
The serial HVF library gate also passed: 682 tests, three ignored,
`CARGO_BUILD_JOBS=3 RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib`
(`/tmp/forkexit-sol-vm-object-hvf.log`). These are host-library receipts,
not signed guest service acceptance.

`CARGO_BUILD_JOBS=3 just clippy` passed on `bb3842530`
(`/tmp/forkexit-sol-vm-object-clippy.log`). Clean-tree inventory reconciliation
refused the K1 operation inventory because the new backing owner adds 11
mapping-keyword scanner hits (mapping count 1484 to 1495). Review compared
rows without positions: all 11 additions are in `thread_control.rs`, solely
the `SharedAbiPage` owner field, its initialization/dereference/drop access,
and accompanying mapping/alignment safety comments; zero rows were removed.
They are internal anonymous ABI backing, not file-description, fd-table,
stream or epoll authority. No K1 callsite taxonomy authority row changed.
The operation inventory was refreshed after that explicit classification;
the macOS compiler capture changed only its source-head receipt, with all
596 authority rows unchanged. This is an intentional mapping-site addition,
not a mechanical position-only refresh.

Final domain receipt: `CARGO_BUILD_JOBS=3 just lint-domains` exited zero on
`bfc22e05e` (`/tmp/forkexit-sol-vm-object-lint-domains.log`). All four abort
shards, MM/task authority, the 97 raw-lock sites, K1 inventories/taxonomy,
burndown and serial-host placement passed. The compiler authority census is
the macOS subset; Linux/FreeBSD/NetBSD profiles remain pending as reported by
the gate. The work is committed as `bb3842530` (backing prerequisite) and
`bfc22e05e` (explicit mapping-site inventory classification).

Resume at obligation 1's runtime retained-mapping owner/adapters and actual
venue publication. This checkpoint does not implement any guest lifecycle
service. Obligations 2–4 and all signed L4 acceptance remain uncompleted.

## Carrier venue wiring checkpoint (continuation after `6a3cad8db`)

The carrier factory now retains the process lifecycle page and actual control
backing through its metadata aperture. An executor publishes both addresses
before entering EL0; zone identity carries them across cross-process switches.
The mapping owner pins exact arena-qualified slots, independently of the kernel
object graph, and its executor reference drops after the vCPU fields. The real
EL1 venue reads those bindings. The existing exact `CARRICK_EL1_SIGMASK=0` and
`CARRICK_EL1_THREADS=0` hatches remain the only service opt-outs.

The thread pending summary moved onto its control slot. The process pending
summary moved onto the retained lifecycle page, with the process queue owning
publication; there is no second host hint. Process sender recipient-mask reads
and guest mask-store/pending reads use the same sequentially consistent ordering.
Nonblocking setup can complete once with pending host work and return
`ServedWithWork`; clone and exit still decline at that boundary.

The first requested signed diagnostic ran before the pending-work correction:
`CARGO_BUILD_JOBS=3 CARRICK_RUN_ID=forkexit-sol-venue-spawn-20261001-01
./scripts/test-signed.sh carrick-embed el1_thread_lifecycle_spawn_slope --nocapture`.
Log: `/tmp/forkexit-sol-venue-spawn-20261001-01.log`. Source HEAD was `6a3cad8db`
plus the uncommitted wiring slice. All three parent/child workloads completed,
but the test **failed** its exit-slope assertion, as expected with guest pool
publication and exit settlement still absent. Counts are served / forwarded:

| Added threads | clone | exit | mask | altstack |
|---:|---:|---:|---:|---:|
| 128 | 0 / 129 | 0 / 130 | 397 / 128 | 328 / 59 |
| 512 | 0 / 513 | 0 / 521 | 1612 / 449 | 1393 / 146 |
| 2048 | 0 / 2051 | 0 / 2079 | 6427 / 1778 | 5509 / 638 |

First interval forward slopes: exit 1.0182, mask 0.8359, altstack 0.2266.
The negative entitlement control passed and scoped cleanup found zero processes.
The failed script does not publish its JSON receipt: the existing canonical
receipt remains an older run and cannot be cited for this diagnostic. A later
read of the unchanged test executable (no subsequent signed build) found SHA256
`519930aa9a0a23b590eea3597f7870f393b6b8b17b39ab5f140f2b3ee4ed041e`, CDHash
`8a06a08a9c1761fb6e3a88cf65e382aa1e0386f2`, LC_UUID
`F589211C-6852-3408-A9ED-E30545D401DD`, hypervisor entitlement and DOF present.
This supplements the diagnostic; it is not an execution-time receipt or green
acceptance. I2 subsequently landed on main and the director requested a rebase
before any signed acceptance run.

Red-first contracts caught missing binding revocation, missing per-slot pending
storage, arena-qualified pin retention, a cross-process switch retaining A's
binding while running B, pending-work forwarding setup, and process-pending
unblock returning `Served` rather than `ServedWithWork`. Logs are under
`/tmp/forkexit-sol-{venue-binding,control-pending,venue-owner,venue-switch,
setup-work,process-pending,process-mask}-{red,green}.log` (individual names vary).
The ABI/scheduler/EL1 lib suite, hook instruction tests and focused owner test
passed. Final broader gates and post-rebase signed results remain outstanding.

This checkpoint enables per-thread setup, not guest births or exits. The real
venue's `born_slot` deliberately declines until the kernel pool entries and
ledger share their ABI authority. Mapping pins currently last until carrier
teardown; exact per-thread retirement and backing reclamation remain obligation
4. Admission closure for conflicting host authority remains obligation 3.

Final pre-rebase wiring validation: ABI 109, scheduler core 88 and EL1 184
lib tests passed; kernel signal-object tests 10 passed; hook instruction tests
12 passed; the runtime arena-owner contract passed. The targeted all-targets
clippy command for runtime, EL1, memory and kernel exited zero
(`/tmp/forkexit-sol-venue-clippy.log`). These are focused wiring receipts,
not closure of the signed lifecycle contract or the full requested gates.

Post-I2 rebase: wiring is `665a53f0f` atop main `d7548d894`. The first
`just reconcile-inventories` refused the mapping count change, as designed;
its follow-up regenerated the operation inventory. Reviewed additions are
the eight mapping rows in `vcpu_loop/thread_lifecycle.rs`: the retained mapping
type, page index, cached lookup/result, insertion, lifetime comment, draining
iteration and retirement call. These are private anonymous lifecycle metadata,
not file-description or host-fd authority. No existing row was retired or
reclassified. The compiler capture still has all 596 authority rows unchanged.

`CARGO_BUILD_JOBS=3 just reconcile-inventories` subsequently exited zero on
clean `399a6b9c6` (`/tmp/forkexit-sol-i2-reconcile-final.log`): 596 unchanged
compiler authority rows, zero inventory position changes, K1 taxonomy and
all four abort shards passed. Only the compiler source-head receipt changed.
No post-I2 signed test or full requested gate is claimed. Resume with the
ABI pool/ledger authority before enabling `born_slot`; then settle before
context resolution and membership observers, close admission, and implement
exact retirement. No build or guest is left running by this checkpoint.

## Phase A promotion attempt on I2

The director split L4 promotion: first land setup serving with exit forwarded,
then attribute residual setup forwards and finish guest exit. The current
checkpoint is **not review-ready**. The new MM-occupancy watchdog failure is
outside the director's known six and blocks promotion.

On clean `2cdaaaede`, the signed hatch run used both
`CARRICK_EL1_SIGMASK=0 CARRICK_EL1_THREADS=0`, run ID
`forkexit-sol-phase-a-hatch-20261001-01`. All three workloads passed their
guest semantic lines. Served lifecycle counts were zero. At 128/512/2048
threads, forwards were exit 128/514/2053, mask 525/2061/8205 and altstack
387/1539/6147. First-interval slopes were exit 1.0052, mask 4.0000 and
altstack 3.0000. The test exited 1 on the unchanged exit-slope assertion;
the director accepted pre-venue hatch shape. Negative control and scoped
cleanup passed. Log: `/tmp/forkexit-sol-phase-a-hatch.log`. An execution-time
partial receipt was saved at
`/tmp/forkexit-sol-phase-a-hatch-artifacts.snapshot.jsonl`: executable SHA256
`d51be72f679cde3f2b80b2ed81d30c1fc8982f3a6f6593a41aa08fb440fead45`,
CDHash `0f02b84145bf38cf21d1c2eb760010ce9a292092`, LC_UUID
`C219A5AA-4FD5-31B9-A4E9-FD61C53EE7FB`; entitlement and DOF were present.
This failed invocation does not publish a complete canonical receipt.

The default-on full `el1_` invocation, run ID
`forkexit-sol-phase-a-el1-20261001-01`, exited 1. Five tests first failed
before guest launch because Linux fixtures had not been built. The missing
prerequisite was subsequently repaired with
`CARGO_BUILD_JOBS=3 ./scripts/build-linux-fixtures.sh` (exit 0, no Docker).
Four known memory reds ran, then `el1_sched_mm_occupancy_two_processes`
hit its unchanged 240-second watchdog. Later lifecycle tests did not run.
This incomplete batch cannot establish known-six closure. Full log:
`/tmp/forkexit-sol-phase-a-el1.log`.

The director requested three isolated default-on and three isolated hatch-off
MM-occupancy attempts as attribution, not retries for acceptance. All six
hit the unchanged 240-second watchdog; negative controls passed and scoped
cleanup reported zero. Run IDs are
`forkexit-sol-phase-a-mm-{on,off}-20261001-{01,02,03}`, logs
`/tmp/forkexit-sol-phase-a-mm-{on,off}-{01,02,03}.log`. The third off attempt
included a bounded 60-second stage-2 inventory USDT trace and is instrumented.

Two live LLDB captures of the original full-run carrier found an executor in
Hypervisor `find_range_bounds_containing` through `hv_vm_map`, preparing a
sparse first-touch page. Other executors were parked. Logs and modified-memory
core are `/tmp/forkexit-sol-phase-a-mm-occupancy-{stacks,core}.log` and
`/tmp/forkexit-sol-phase-a-mm-occupancy.core`. Attach perturbation applies.
The saved core omits framework code pages, so core disassembly was unavailable.
Watchdog post-mortem reported kernel authority busy, not a coherent empty graph.

The third off carrier (PID 27162) emitted 123520 successful stage-2 maps and
123342 unmaps during the bounded trace, including 128 metadata-aperture maps.
Replaying exact `(IPA,length)` keys leaves 178 keys. This is an edge census,
not HVF's internal region count: partial overlaps and remaps require care.
No DTrace drops were reported. Raw trace:
`/tmp/forkexit-sol-phase-a-mm-off-03-stage2.raw`; durable source:
`scripts/dtrace/hvpatch-global-frame-stage2-inventory.d`. The director's
region-count-growth hypothesis remains unconfirmed.

The off attempts still published retained lifecycle/control mappings. The
director identified this as incomplete hatch scope and authorized a
no-publication comparison. A cheap runtime contract failed red with
`disabled venue reached carrier publication`, then passed after publication
was gated on the retained page's existing hatch bits. Both hatches off now
skip carrier access, mapping, pin retention and binding publication; an
enabled service still uses the authoritative backing. Focused logs:
`/tmp/forkexit-sol-phase-a-hatch-publication-{red,green}.log`.
Signed no-publication attribution and default-on root-cause repair remain
outstanding. No Phase A host-gate or both-libc semantics closure is claimed.

The signed no-publication comparison passed under trace in 1360 ms, then
passed uninstrumented in 1147 ms, both with 150 forks and eight writers in
each process and all semantic predicates true. Run IDs:
`forkexit-sol-phase-a-mm-no-publication-20261001-{01,02}`; logs:
`/tmp/forkexit-sol-phase-a-mm-no-publication{,-untraced}.log`; complete
script receipts were saved to the corresponding `/tmp/*-artifacts.jsonl`.
The trace emitted 1587 maps and 1571 unmaps (PID 62600), with peak 59 exact
range keys, versus peak 179 with publication. Raw trace:
`/tmp/forkexit-sol-phase-a-mm-no-publication-stage2.raw`.

A concrete capacity lead supersedes speculation about native lookup cost:
`install_retained_using` reserves a 512 KiB aperture slot for each retained
16 KiB granule. There are exactly 128 slots; the stalled capture emitted
exactly 128 metadata maps. A 600-granule retained population uses 9.375 MiB
of actual backing within the existing 64 MiB aperture, but the current
allocator cannot admit it. Red-first capacity proof and repair are next;
the publication-disabled passes do not confer default-on acceptance.

### Resume after landing J: slab capacity

Rebased onto `75111e814`; the retained checkpoint is `3ea3cda16`.
Conflicts were inventory counts/source-head receipts; product code merged.
Two new landing-J test identities needed zero lifecycle/control bindings to
compile against this branch's extended ABI.

The original VM-free mapping diagnostic failed at retained granule 128 with
`Busy` (`/tmp/forkexit-sol-j-capacity-red.log`). That diagnostic allocated
600 unrelated host mappings: those cannot become one physical slab without
splitting or copying authoritative storage. The architectural contract now
uses actual kernel fork ownership: 300 live children retain 600 distinct
lifecycle/control granules. It failed with **600 backing regions** against
the **19-slab** ceiling (`/tmp/forkexit-sol-j-slab-red.log`).

Authoritative ABI allocation now uses 512 KiB shared slabs with 32 claimed
16 KiB granules. Fork descendants share the storage pool, not lifecycle or
signal authority; independent roots retain independent pools. Granules are
released only with their final page owner and reused with fresh ABI values.
The carrier maps each slab once, publishes exact page/slot offsets, and keys
thread pins by lifecycle-page identity rather than shared backing identity.
There is no copied guest control view. The contract also drops one child and
requires reuse of both released addresses with an open gate and empty mask.

Focused green commands (all `CARGO_BUILD_JOBS=3`): kernel `--lib lifecycle_`
under `RUST_TEST_THREADS=1` (24 tests), kernel `--lib thread_control::tests`
under `RUST_TEST_THREADS=1` (4 tests), runtime `--lib thread_lifecycle::tests`
(2 tests). Logs: `/tmp/forkexit-sol-j-{capacity-kernel,control,owner}-green.log`.
The old distinct-backing assertion for fork siblings now requires distinct
page/slot addresses within the shared slab; gate, mask and final-owner
independence remain asserted. Exhaustion behavior and signed default-on
acceptance are not yet verified.

### Exhaustion must leave a host-served continuation

The publication-boundary contract forced `MetadataResolutionError::Busy`
and failed red with `Err(Busy)` instead of `Ok(HostServed)`
(`/tmp/forkexit-sol-j-exhaustion-red.log`). Propagating resource pressure
as an executor-load error could strand guest progress rather than decline
this optional venue.

Publication now revokes any previous page/slot binding before one resolution
attempt. `Busy` returns `HostServed` with both addresses zero, so the loaded
thread continues on the existing host syscall path. No retry, wait or poll
is introduced; stale-owner and invalid-extent failures still propagate.
Thread pins are retained only after both backing resolutions succeed.

The runtime owner suite passed all three tests, including the exact one-
attempt budget and zero-binding assertion
(`/tmp/forkexit-sol-j-exhaustion-green.log`). The VMM quota contract filled
all 128 slab slots, then required refusal of the next request before any
backend work and without changing the stage-2 inventory or occupancy bitmap
(`/tmp/forkexit-sol-j-quota-green.log`, one test passed). The selected outcome
is admission decline, not fork identity rollback: the thread remains owned
and runnable through its ordinary host continuation. Signed Phase A gates
remain outstanding.

### Phase A review checkpoint (2026-10-02)

Rebased onto landing J (`75111e814`). Capacity and bounded exhaustion are
committed as `56238b41e` and `ebdc9625f`; `6c696dab6` puts the slab's host
concurrency guarantee on its storage owner rather than the page wrapper.
Clippy first rejected the missing slab Send/Sync contract, then passed;
the lifecycle ownership suite passed all 24 tests after that correction.
Inventories were reconciled on clean source checkpoints, with 599 unchanged
host-authority rows. No probe counts or exclusions were edited.

The final signed source checkpoint is `26cfd5380`. Full EL1 command:
`CARGO_BUILD_JOBS=3 CARRICK_RUN_ID=forkexit-sol-j-final-el1-20261001-01
./scripts/test-signed.sh carrick-embed el1_ --nocapture`.
It completed with **74 passed and exactly the known six failures**:
anonymous reservations, concurrent delegated VMA operations, delegated
MAP_FIXED over COW, fork-COW, ptrace traceclone, and spawn-slope. This is
**not an all-green suite**. Raw log: `/tmp/forkexit-sol-j-final-el1.log`.
The entitlement negative control passed and both scoped process censuses
were zero. The preserved `2026-10-02-el1-forkexit-el1-partial-receipt.jsonl`
is an in-flight receipt snapshot through the scheduler executable, not a
complete or successful script receipt; the failing script removes its
temporary receipt. The raw log supplies the completed verdicts.

Default-on spawn, for 128 / 512 / 2048 added threads:

| call | served | forwarded |
| --- | --- | --- |
| mask | 525 / 2061 / 8205 | 0 / 0 / 0 |
| altstack | 387 / 1539 / 6147 | 0 / 0 / 0 |
| exit | 0 / 0 / 0 | 131 / 514 / 2074 |

The 128-to-512 slopes are mask **0.0000**, altstack **0.0000**, exit
**0.9974**. Exit intentionally remains forwarded for Phase B. Fork-storm
passed (16 forks, 251 storm spawns, bad=0, each child census=1). Default-on
two-process MM occupancy passed in **774 ms**, with eight writers and 150
forks per process, no edit/torn/snapshot/child/join failures, no mprotect
errors, and zero alias-retirement restarts. Earlier focused post-J MM
occupancy passed in 723 ms; the first full suite passed in 1036 ms. These
are separate runs, not a controlled performance comparison to main's 651 ms.

The final exact opt-outs (`CARRICK_EL1_SIGMASK=0 CARRICK_EL1_THREADS=0`)
were checked with the same signed spawn command, run ID
`forkexit-sol-j-final-hatch-20261001-01`. All three calls were served zero
times. Mask forwards were 525 / 2061 / 8207, altstack 387 / 1539 / 6147,
exit 130 / 515 / 2066. Slopes were **4.0000 / 3.0000 / 1.0026**, restoring
the old forwarding shape. All guest semantic predicates were true; the
existing exit budget assertion failed as expected. Raw log:
`/tmp/forkexit-sol-j-final-hatch.log`. Negative control and scoped cleanup
passed. Its failed script also did not publish a complete receipt.
Post-run identity supplement (before any further embed signing): SHA-256
`d9b49cef150f483a0c102d1e6b4e6a69a6aa002ce66bfde296765e35fd20df2e`,
CDHash `53e8a576a991a34d0a5ae35d4f798525072c4b59`; hypervisor entitlement
and `__dof_carrick` present. This supplements the raw result, not a complete
script execution receipt.

Fork-COW remains red: pages=16 had 3442 exits against ceiling 144.
Residual classes were canceled=256, idle=286, kick=96, syscall=2543,
metadata=0, maintenance=261, fault=0, other=0. Both parent and child verified
320 pages successfully. Exact forwarded syscall attribution is in the
final full-suite raw log; this is a residual-cost receipt, not COW closure.

Both libc executables for the 30 cached names matching
`sigaltstack|sigprocmask|sigmask|signal|thread` were freshly built locally.
Signed `generic_probe_shard_` with that derived filter completed **60 unique
rows (30 musl, 30 GNU), all MATCH**, with empty mismatch baselines, all
three shards green, negative control green, and scoped cleanup zero.
Final run ID: `forkexit-sol-j-final-probes-20261001-01`; raw log:
`/tmp/forkexit-sol-j-final-probes.log`; complete receipt:
`2026-10-02-el1-forkexit-probes-receipt.jsonl`. By the director's explicit
mailbox revision, **manythreads, execfromthread, vforkexecthread are
director-run**, excluded from this worker's acceptance; they still require
both-libc landing-oracle verification. No Docker was run by this worker.

Host commands passed with `CARGO_BUILD_JOBS=3`: `just test-kernel`,
`just test`, `RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib`
(684 passed, three existing ignored), `just clippy`, clean-tree
`just reconcile-inventories`, and `just lint-domains`. Logs are
`/tmp/forkexit-sol-j-{test-kernel,test,hvf-lib,clippy-green,reconcile-green,
lint-domains}.log`. The host-authority gate explicitly covers the macOS
subset; Linux/FreeBSD/NetBSD profiles remain pending, not silently green.
The first three host commands preceded the trait-only slab correction;
24 lifecycle contracts and clippy passed after it, and both signed gates
were rebuilt and rerun after it. Inventories and final lint followed the
clean corrected source. No budgets, retries, concurrency or deadlines
were changed.

Phase A is ready for review under the revised acceptance, with the known
six still red. Phase B settlement, admission closing and exact per-thread
teardown are not implemented or accepted by this checkpoint.

### Phase B kernel settlement checkpoint (2026-10-02)

Branch `work/lifecycle-phase-b` rebased on main `4c4d06b4c` before this work.
This is an incomplete kernel checkpoint, not signed Phase B acceptance.

- `828b888d5`: host and EL1 claims consume the same ABI pool CAS. The
  two-process contract failed red with `PoolEmpty` before the correction.
- `46cf43e6f`: ABI Born records publish through the canonical kernel thread
  publication body before context/membership resolution. A peer's unknown-tid
  lookup failed red before settlement; the exact slot and serial survive it.
- `285a81f14`: ABI exits use canonical graph retirement and retain numeric
  identity while captured contexts exist. The peer-observer red found the
  departed tid still live. Birth followed by exit is also consumed in one
  settlement pass.
- `1c0f464ce`: host births and nonfinal host exits update the ABI live census;
  EL1-accounted exits do not decrement twice. The two-process red saw one
  instead of two after a host clone. Runtime census projection is unfinished.
- `b5f18bfad`: a non-cloneable exit admission spans the bounded EL1 exit
  window. Closing sees in-flight exits; rollback preserves concurrent birth
  publication. The red allowed an exit through `ForkClosing`. Protocol is 4.

Final focused checks: 29 kernel lifecycle contracts, 111 ABI tests and 184
EL1 tests pass. `just test-kernel` passed after exit/census changes; `just
test` passed before the exit-admission protocol change (including serial
HVF library: 684 passed, three ignored). Clippy passed on protocol 4.
Logs: `/tmp/phaseb-live-count-{red,green}.log`,
`/tmp/phaseb-exit-admission-{red,abi-el1,kernel}.log`,
`/tmp/phaseb-settlement-{test-kernel,test,clippy}.log`.

Reconciliation captured 599 macOS host-authority rows and rebound K1
positions without changing classifications/counts. It refused runtime-abort
re-blessing. `just lint-domains` fails with **24 missing classifications**;
the new settlement paths include fallible preparation/retirement after the
guest birth has already succeeded, requiring reserve-before-birth or typed
failure review rather than a blanket carrier-fault classification. Logs:
`/tmp/phaseb-settlement-{reconcile,lint-domains}.log`.

Production `GuestLifecycleVenue::born_slot` still declines. An ABI birth
settles to an uninitialized execution record, so existing zone handback has
no execution generation or runtime binding. The director confirmed that
ABI and host origins must enter one adoption routine, owned by exact
`TaskKey`, leasing the binding at first host entry; it must never borrow the
driver process's job. This integration, conflicting-operation gate guards,
exact carrier metadata retirement, pending-birth kernel lifetime and
teardown proof remain open. Credentials/affinity at claim require those
guards before production admission. No signed tests, cached probes, hatch
comparison, or Docker ran on this checkpoint; spawn slope is not green.


### Phase B reserve-before-birth checkpoint (2026-10-02)

Four implementation commits reserve credential identity (`251355f17`),
retirement arena custody (`93fa75abc`), and exact-task revision headroom
(`cd7244e7d`) before a pool entry becomes claimable, then consume the same
retirement custody for a host-adopted ABI thread (`b1eb9b52c`). Resource
failure leaves no claimable entry; the existing host clone fallback remains.
This is not production birth admission or Phase B acceptance.

Red receipts: allocator exhaustion after stocking aborted birth preparation;
retirement increased capacity from zero to one after an ABI exit; ordinary
revision advances consumed reserved headroom; a host-adopted ABI exit failed
with `RevisionExhausted` despite its owned retirement credit. Their fixed
contracts pass, including two live processes, peer host retirement, captured
identity retention, and a before-publication failpoint. Latest lifecycle
suite: 33 passed. Revision-capacity suite: two passed.

`CARGO_BUILD_JOBS=3 just test-kernel`, `CARGO_BUILD_JOBS=3 just test`, and
`CARGO_BUILD_JOBS=3 just clippy` pass on the implementation above. The host
suite includes 155 serial kernel tests, 669 runtime tests (eight ignored),
and 684 serial HVF library tests (three ignored). Logs:
`/tmp/phaseb-reserved-custody-{test-kernel,test,clippy}.log`,
`/tmp/phaseb-revision-{red,final,lifecycle}.log`, and
`/tmp/phaseb-host-adopted-{red,final}.log`.

The reconciler retained the same 599 host-authority rows and digest.
`5c9ac7e4e` rebinds only positions/source head; normalized JSON preserves
all classifications and budgets. `31a83d7f8` gives individual rationales to
eleven true revision/retirement custody invariants. `just lint-domains`
failed with 35 missing classifications before that review; the final abort
checker still fails with 24. Remaining settlement errors have not been
blanket-classified. Logs:
`/tmp/phaseb-reserved-custody-{reconcile,lint-domains,aborts-final}.log`.

Production `GuestLifecycleVenue::born_slot` still returns `None`.
Runtime adoption capacity is not reserved: an ABI birth still lacks an
execution generation and binding at its first host entry. The next change
must factor the host/ABI origins through one exact-TaskKey process-owned
adoption routine and reserve its capacity before stocking. Do not borrow
the driver job or its mm projection. Conflicting-authority admission guards,
carrier metadata retirement, pending-birth KernelArc lifetime and teardown
remain open; credentials/affinity at claim are not yet protected by those
guards. No signed acceptance, cached libc probes, hatch comparison, or
Docker ran at this checkpoint. Spawn slope is not green. Main remained
`4c4d06b4c345550da68b4b8cd44dfd8f6e53457b`, so no rebase was needed.

### Phase B process adoption capacity checkpoint (2026-10-02)

The next three commits reserve exact-process adoption capacity
(`0d1be206d`), share the typed-origin runtime constructor with host clone
(`35012b995`), and reserve scheduler submission before birth (`c170a75dd`).
These are the rebased names of `8ac07311f`, `c78d00a70`, and `ef4694b17`.
Main moved to `e59eec4e4` during verification with four documentation-only
commits. Rebase completed cleanly; range-diff reports all nineteen branch
commits unchanged.

Pool stocking now obtains the process factory's non-cloneable ticket before
publishing a reserved identity. Capacity failure declines stocking. The
ticket owns a runtime cell, injected execution-lease slot, process lifetime
and exact first-generation submission grant. The shared constructor checks
exact task/thread and kernel ownership, then installs either the host clone
completion token or ABI-origin idle completion. Host clone consumes its own
pre-birth grant through the existing dormant-binding publication; it no
longer borrows a running sibling's submission grant.

Red-first contracts cover refusal before stocking in one of two live
processes and scheduler reservation before birth. Fixed scope contracts
also reject peer consumption and admission after scheduler closing. The
nine host clone/process lifecycle tests and runtime constructor scope test
pass. `just test-kernel`, `just test`, and workspace `just clippy` pass on
`ef4694b17`; host receipts include 670 runtime tests (eight ignored) and
684 serial HVF library tests (three ignored). An exploratory parallel
runtime invocation failed on carrier counts and a global vfork test hook;
both failures reproduced on its parent. The prescribed serial runtime
lane passed. No concurrency, timeout or budget was changed.

The full signed `carrick-embed el1_ --nocapture` run on `ef4694b17` reports
exactly the known six failures and no new reds. The scheduler executable
reports 46 passed and six failed. Two-process occupancy and fork-storm
pass. Spawn slope remains red: clone `0.9974`, exit `1.0026`, sigmask and
sigaltstack `0.0000`. Run id:
`phaseb-adoption-20261002-ef4694b17-el1`; both it and its `-cli` scope have
zero remaining processes. The signed scheduler artifact SHA-256 is
`256d87cf1837ba397af6287a55d40cdae6527dee4976ea530052c244a7bd6e71`,
CDHash `fa45cb25a65273d63c7369c484b4eadbb474aa95`; entitlement, UUID and
DOF commands are retained in `/tmp/phaseb-process-adoption-artifact.json`.
These are pre-rebase receipts, not post-rebase signed acceptance.
After rebase, the nine runtime lifecycle tests pass on `c170a75dd`;
log `/tmp/phaseb-process-adoption-post-rebase.log`.

Logs: `/tmp/phaseb-process-adoption-{test-kernel,host-test,clippy,
lint-domains,signed-el1,cleanup}.log` and
`/tmp/phaseb-process-submission-{red,green-final,runtime,scope,
callgraph,runtime-serial,parent-runtime-all,aborts}.log`.
Lint-domains and the abort checker still fail on 24 unclassified sites;
no blanket classifications were added.

This is still incomplete implementation, not Phase B acceptance. The
ticket is stored with published ABI custody and has an exact consume API,
but the first host-entry hook does not consume it yet. Its runtime state
has no lazy task-only backend binding or execution generation. Building
the process-owned MM/backend template is the next implementation task,
not an external blocker. Production `born_slot` still returns `None`.
Pending-ticket kernel lifetime, conflicting-authority admission guards,
exact carrier metadata retirement and teardown remain open. Cached libc
probes and the hatch comparison have not run; no Docker ran.

### Phase B: production birth checkpoint, 2026-10-02

Production `born_slot` is enabled behind the existing exact `=0` hatch.
`d2aee1082` adds an exact-TaskKey owned inactive backend template, CPU and
scheduler capacity, pre-issued COW identity, first-host-entry consumption,
and the bind/activate routine shared with host clone. Thread-bound runtime
state is constructed on the adopting executor; the driver job is not borrowed.
Two-live-process owner rejection was captured red, then green. Runtime adoption,
host lifecycle, EL1 lifecycle and ledger focused tests passed (3/9/17/24).
This is implementation progress, **not Phase B acceptance**.

The first signed run found premature scheduler service publication. A startup
contract reproduced it red; `afbfa8b56` stocks births only after the prepared
scheduler/wait-service pair publishes. Signed consumption then exposed the
omitted `CLONE_DETACHED` and `CLONE_SYSVSEM` typed flags. The two-live-process
birth contract reproduced each abort; `f21b5b38e` and `91b239e4f` represent
the complete admitted pthread topology and pass that contract.

Signed spawn on `91b239e4f` completed all workloads with zero thread failures:

| Threads | Clone served / forwarded | Exit served / forwarded |
|---|---|---|
| 128 | 93 / 36 | 0 / 128 |
| 512 | 374 / 140 | 0 / 512 |
| 2048 | 1439 / 610 | 0 / 2050 |

The reported 128→512 slopes are clone **0.2708**, exit **1.0000**. The
512→2048 counters give clone **0.3060**, exit **1.0013**; the test stops at
the first failed exit assertion before printing this second pair. Sigmask
and sigaltstack forward slopes remain zero. Adoption currently frees the born
record and runs the new job as an executor home thread. The required home-record
exit decline therefore remains effective; it must not be removed to hide this
ownership transition.

The full signed `el1_` pass is red and its census is incomplete. New observed
watchdogs: `el1_files_cross_process_readers_contract` (120 seconds) and
`el1_inotify09_probe` (60 seconds). The reader's saved carrier core exposes
executor failure `hypervisor operation failed: birth CPU template rejected a
foreign process`: pre-exec inactive capacity survived into a replacement MM.
Closing admission and retiring old capacity across exec remains required.
Watchdog cleanup's second pass also killed the following inotify and scheduler
executables under the suite's reused run ID; those kills are contaminated
results, not independent semantic verdicts. No budgets or timeouts changed.

Separate signed runs with unique IDs pass
`el1_sched_mm_occupancy_two_processes` and
`el1_thread_lifecycle_fork_during_clone_storm`. All run and `-cli` cleanup
counts are zero. Logs:
`/tmp/phaseb-born-signed-spawn-complete-mask.log`,
`/tmp/phaseb-born-signed-full-complete-mask.log`,
`/tmp/phaseb-born-signed-occupancy.log`,
`/tmp/phaseb-born-signed-forkstorm.log`.
Run IDs are `phaseb-born-91b239e4f-{spawn,full,occupancy,forkstorm}-20261002`.
The full-pass scheduler SHA-256 is
`4707695b48791ecf3f65535bef62c9adccbb63067a813ec68dd7fc4e3583ff25`;
CDHash, UUID, entitlement and DOF are retained in
`/tmp/phaseb-born-91b239-full-artifact.json`. Later focused scripts re-sign
artifacts and have their own receipts. Reader core/stacks and extracted failure:
`/tmp/phaseb-born-files-hang.core`, `/tmp/phaseb-born-files-hang.lldb.txt`,
`/tmp/phaseb-born-files-failure-deep.txt`.

Open: conflict admission/exec capacity invalidation, preservation of zone
execution ownership after adoption, exact retirement, abort classification,
current full host gates, cached libc probes and hatch comparison. No Docker ran.
A sibling worktree built concurrently during release linking; no quiet-host
performance claim is made. Forward counts are the recorded structural witness.

### Admission and watchdog checkpoint (2026-10-02)

Rebased Phase B onto main `839f92126`. `ab012b68a` owns an exact-process
birth admission close through exec preparation/commit, settles completed ABI
births before the sibling census, revokes unused identities and inactive
CPU/scheduler/backend custody, and clears the old executable factory before MM
replacement. A two-live-process held-claim exec contract was red before the
fix; the 14 exec contracts passed. The focused signed
`el1_files_cross_process_readers_contract` passed in 3.11 seconds on that
checkpoint (`/tmp/phaseb-exec-signed-readers.log`). This is not a new full-suite
receipt.

`641142102` extends exact-process admission custody to fork, credentials and
ptrace. Three two-live-process contracts failed before the fix, then passed;
all 28 ledger contracts passed. `869bd4a0d` separates the unbound post-exec
image (`AwaitingExecBinding`) from an operation-owned `ForkClosing` gate:
factory installation cannot reopen another operation's close, and a host fork
can proceed before the new image installs its first executable birth factory.
Unfinished lifecycle admission has a separate refusal from registry `TaskBusy`,
so it cannot wait for a reservation notification that will never arrive. The
factory-close scope contract was red; 28 ledger and 18 ABI contracts passed.

The inotify watchdog then exposed missing cold-executor adoption progress.
`7df8416a6` permits a pre-reserved unadopted birth to reach a cold executor;
`8cf20216d` also admits it through queued migration, which publishes the SGI
needed to wake an executor in WFI. Without the second fix, the two-process
migration contract moved zero records instead of one. All 91 scheduler-core
contracts pass with both fixes. Ordinary foreign-MM and home-record rules
remain enforced.

Signed `el1_inotify09_probe` on source `d3a3b2a74` passed: LTP TPASS,
exit 0, observed wall 3.04370125 seconds. The negative entitlement control
passed; both scoped cleanup counts were zero. Run ID:
`phaseb-wake-d3a3b2a74-inotify-20261002`; log:
`/tmp/phaseb-wake-signed-inotify.log`; retained artifact receipt:
`/tmp/phaseb-wake-d3a3b2a74-artifacts.jsonl`.
The probe executable SHA-256 is
`9ea9e13e5562d521c2aa74889dffb594f68f7ee4c57539a57a895b980f8b754f`,
CDHash `da9e82f1e9e5cc4a936e1bdead0976d59ff78a86`, UUID
`7C046B7E-2035-3ECC-9914-D8805ACBDC46`; entitlement and DOF present.
This is a watchdog/semantic receipt, not a controlled performance comparison.
Earlier watchdog/core diagnostics remain in `/tmp/phaseb-{exec,admission,rebind}-*`
and their exact-run `target/embed-post-mortem` directories.

`d3a3b2a74` makes the spawn witness print its collected host exit classes and
assert the accepted clone slope threshold as well as exit. No new signed
spawn numbers have been collected. The last measured slopes remain the earlier
0.2708 clone and 1.0000 exit; they do not constitute current-source acceptance.
Adopted births still become home threads, so serving their exits needs an owned
zone continuation and exact execution-binding retirement, while preserving
EL1's home, pending-signal, robust-list and last-thread declines.

The director requested a quiet window for memory-admission landing. The
already-started inotify run finished and `quiet` was posted after zero-process
cleanup. No further guest runs may start before `RELEASE`; rebase after the
admission landing notice. Still open: current full-suite reader/inotify
contracts and red census, spawn slopes and dominant clone-decline attribution,
remaining limit/seccomp admission and exact retirement, occupancy/fork-storm
refresh, cached libc probes, hatch comparison and the full host gates. Phase B
is not accepted; no budgets, concurrency or timeouts changed and no Docker ran.

Host validation found and fixed an admission-ordering regression.
`just test-kernel` initially failed
`credential_publication_waits_for_task_reservation_without_recapture`:
credential mutation tried to close a page already owned by a fork instead of
waiting for that task reservation. After moving the close after the wait, the
same test caught notification preceding birth-guard release. A deterministic
two-live-process reservation callback reproduced that second failure.
`dcfc77491` waits first, closes, settles and revalidates before credential COW,
and releases birth custody before reservation notifications on commit and
rollback. The expected refusal remains errno 11, not an invariant diagnostic.
`CARGO_BUILD_JOBS=3 just test-kernel` then exited zero: 2,376 kernel unit tests
passed (one ignored, 155 serial-host tests filtered), with the remaining recipe
ABI/FD and kernel-semantics suites green. Logs:
`/tmp/phaseb-admission-test-kernel.log` (red),
`/tmp/phaseb-credential-reservation-green.log` (second red),
`/tmp/phaseb-admission-release-red.log` (deterministic scope red),
`/tmp/phaseb-admission-test-kernel-green.log` (green).
The signed watchdog receipt above belongs to `d3a3b2a74`, before this change;
current-source signed acceptance still requires the released quiet window.

### 2026-10-02: typed gettid receipt, exit still unresolved

`5ac2f1f555ecd79d15d336294fbbf350316abb6a` publishes the immutable visible
TID in lifecycle control storage before Born and deletes the legacy
CONTEXTIDR identity shim and stamps/readers in the same change. The
director approved this single identity path and explicitly retained the
home-record exit decline: returning an adopted job to the zone is not an
authorized workaround.

The signed spawn run `phaseb-gettid-5ac2f1f55-spawn-20261002` failed Linux
semantics at its 512-thread scale (parent ran 255 of 256 threads, one
failure). The 2048 scale did not run. There are no accepted three-scale
slopes. At 128 threads, served/forwarded counts were clone 61/68, exit
0/128 and gettid 128/2; at 512, they were clone 290/222, exit 0/511 and
gettid 506/7. Sigmask and altstack forwards remained zero. Removing the
gettid host trip did not enable exit; exact decline attribution is next.
The negative entitlement control passed and both scoped cleanup IDs
reported zero processes. Log: `/tmp/phaseb-gettid-signed-spawn.log`.

The failed signed runner does not publish an acceptance receipt. The
tested executable's identity was captured separately before another
release build in `/tmp/phaseb-gettid-5ac2f1f55-artifact.txt`: SHA-256
`6b437d30ced32ba23e4c47710c37bafffaf3c6743661494e2afdcc46d3c1b6e4`,
CDHash `805d402281012cb89c2e14655ad282ed7f41b2a8`, LC_UUID
`32E03C1C-BD77-3E35-BD40-1591FCDE169B`; hypervisor entitlement and
`__dof_carrick` were present. This is failure provenance, not acceptance.

### 2026-10-02: exact decline census, budgets still red

Rebased source `315a494d1c5b961bf79461039e80f7dc6bad0a0d` adds exact
exit-decline counters, the fixture's numeric spawn errno witness, and
four typed host-clone EAGAIN producer markers. The original one-spawn
failure remains unresolved: the new signed focused run and one LLDB
producer diagnostic both completed all three semantic scales without it.
The producer breakpoint resolved but was never hit; this does not prove
that the intermittent failure is fixed.

Signed run `phaseb-producer-spawn-20261002-1630` measured:

| threads | clone served/forwarded | exit served/forwarded | exit declines |
| --- | --- | --- | --- |
| 128 | 92/37 | 0/128 | NoEntry 36, NoCurrent 92 |
| 512 | 336/177 | 0/512 | NoEntry 175, NoCurrent 334, dispatch host work 3 |
| 2048 | 1356/693 | 0/2050 | NoEntry 681, NoCurrent 1350, venue 2, dispatch host work 17 |

Clone slopes are 0.3646 and 0.3359; exit slopes are 1.0000 and 1.0013.
Sigmask and altstack forwarding remains zero. `ClonePoolEmpty` is zero
at all these scales, while clone dispatch host work is 3/12/27. Thus
pool exhaustion does not account for the remaining spawn forwards;
the other clone-decline fences still need attribution. Forwarded
munmap is 257/1027/4107, mmap 284/1122/4487 and mprotect 257/1025/4097.
Log: `/tmp/phaseb-producer-signed-spawn.log`. Both scoped cleanup IDs
report zero; negative entitlement control passes. The budget fails.

Full signed `el1_` run `phaseb-producer-full-20261002-1600` is incomplete
acceptance evidence. Occupancy passed (150 forks per process, eight
writers, 921 edits and no errors); exec storm passed four rounds. Fork
storm stalled with executors in HVF idle waits. A real core and matching
executable were retained as `/tmp/phaseb-producer-forkstorm-315a494d1.core`
and `/tmp/phaseb-producer-el1_sched-315a494d1`. Core capture left the
process stopped after detach; it was explicitly continued, then the
watchdog fired. Its wall timing is debugger-perturbed, not acceptance.
The post-mortem shows root blocked on ChildState (generation 767), and
draining tid 1052 blocked on HostWait (generation 2) without a continuation;
the scheduler has no queued work or residency. The teardown orphan is
unresolved. Later cleanup raced the inotify contract, so it cannot supply
a no-new-red census. The separate inotify09 probe completed TPASS in
5.85 s. Reader and spawn cases in the killed scheduler executable did not
run. Final scoped cleanup reports zero processes.

The failed runners publish no acceptance receipt. The focused tested
artifact was captured directly: SHA-256
`57bc02d3d28eb223144dfc35f7771bbbdc1f67157f20197a76e2f4547afbe7a2`,
CDHash `3aa1b20e329586fe13e1876eb28d7c5c7bc58772`, LC_UUID
`F0A56C7D-6C34-3351-B21B-5042CA929339`; hypervisor entitlement and
`__dof_carrick` are present. Re-signing changed identity from the saved
core executable (SHA-256
`8085ddd797131e2ab6c4b5d28039ee0691a7c22ba7c7229ec4ba44e8f7b14ef4`).
These are failure receipts, not lifecycle acceptance.

The retained core's directory was authenticated from the saved
`run_executor_loop` prologue (resolver ArcInner at frame SP + 0x120).
It contains exactly `(tid=1, serial=6, generation=767)` and
`(tid=1052, serial=5815, generation=2)`. The orphan binding remains active;
its job is suspended on BlockedContinuation, with runtime withdrawal
false. The matching dSYM's DWARF variant discriminant `0x0b` identifies
its production phase as ResumeZone. Thus its host logical job was still
parked when graph retirement removed its live thread. The ledger's
ExitedInZone path retires graph/pool custody but does not complete such
a host job.

The ownership guard retains exit on the host whenever a non-home record
has already acquired a host execution generation. This uses the existing
unadopted-birth identity predicate, preserves the home-record decline,
and leaves generation-zero Born/Published records eligible for EL1 exit.
A red-first paired-process-venue contract observed Served instead of
Forward for the migrated host job; with the guard, its Published entry,
CLEARTID and current record remain intact, while the other process's
unadopted birth exits in EL1. All 187 EL1 and 112 ABI unit tests pass.
Fresh signed watchdog and slope checks remain required; this guard does
not claim the exit budget is fixed.
