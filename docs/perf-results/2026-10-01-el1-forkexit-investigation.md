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
