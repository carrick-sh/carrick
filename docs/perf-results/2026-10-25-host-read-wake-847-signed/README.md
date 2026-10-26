# Issue #847 signed hardware evidence

## Rebase onto slice 3 main (2026-10-26)

After the signed smoke and post-mortem, this branch rebased from
`2da501dcf0cc81aae517e038bb72dbfee1e1a716` onto GitHub main
`bec60cc3a907002f79a3513e1d3c6d2be3f5075d` (the landed slice 3). The
pre/post `git range-diff` is `/tmp/847-rebase-range-diff.txt`.

- Kept: 89 of 92 commits replayed with equal patches.
- Ported: `3b803b2c5`, `67927d9a1`, and `a5d9b1682` retained their behavior
  while their historical EL1 ABI hash edits were superseded by slice 3's
  layout. The combined layout is asserted once as `0xb8c46a9b63469ce2`.
- Dropped: none.

The first rebased compile caught the two stale assertions. With the combined
hash installed, the production-path VM-free witness
`bootstrap_clean_exit_returns_extension_arena_for_next_bootstrap` passes
1/1 (806 filtered). This post-rebase VM-free result does not alter the failed
pre-rebase signed artifact verdict above.

## Exact `e6cfbc5ac` clean-exit arena smoke failure (2026-10-26)

The exact bundle for evidence head
`e6cfbc5ac3c04b8f3038ae576dca9caf27628bdc` verified, restored, and
verified again with 1,195 executables:

```text
/Volumes/carrick-build/fixtures/published/e6cfbc5ac3c04b8f3038ae576dca9caf27628bdc/3703bc004fb220b008d77ed6fe26bf1048a865105dd67b5474593ecc8969a2b5.tar.gz
bundle identity: 3703bc004fb220b008d77ed6fe26bf1048a865105dd67b5474593ecc8969a2b5
archive SHA-256: d0d94108140fe0a88c47af853e74ad41290fd71982a91195a64032430bc3a1bc
input identity: 1b0c6348ad4325add0c8937509ef4ee9965ed1d096c797116ef83f8990be63fb
```

Mandatory bootstrap smoke `847-e6-smoke-01` reached HVF and failed 0/1 in
0.33 seconds with the same root-slot refusal. This was a typed hypervisor
error, not a `carrick: FATAL` carrier abort:

```text
stage-1 extension arena IPA 0x9a00000000 is still held by the root-slot pool;
stage2=Some(CarrierStage2RecordSnapshot { record_id:
CarrierStage2RecordId(14), vm_generation: CarrierVmGeneration(1),
ipa: 661424963584, len: 2097152, host_addr: 4388225024, mapped: true,
backend_map_installed: false, release_ipa: false, perms: 3, logical_owner:
Some(CarrierLogicalOwner { id: 14, generation: 14 }), pin_count: 0,
retirement_requested: false, retry_eligible: false, retry_pending: None,
terminalized_by_vm_destroy: false, superseded_by_rebind: false,
release_in_flight: false, release_retry_pending: false })
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured;
90 filtered out; finished in 0.33s
```

The negative entitlement control passed. All scoped cleanup counts for
`847-e6-smoke-01`, `-b1`, `-neg`, and `-cli` were zero. There was no watchdog
census. Per the mandatory stop condition, the remaining population did not
start:

- bootstrap smoke: 0/1 (`847-e6-smoke-01`);
- host-blocked-read acceptance: 0/0 of 20;
- `native_root_exec_replaces_pid1_shell`: 0/0;
- `el1_ipc_pipe_blocking_roundtrips`: 0/0 of 3;
- `el1_fork_cow_resolves_in_guest`: 0/0 of 3.

The exact smoke executable was
`target/release/deps/el1_sched-d8a5a9a0d2511a83`:

```text
SHA-256: 8959879ebc5a9a60cb2b130e9e79e3e3bc7f0bb2b09b02ad95d4409c427477cc
CDHash: abe6729a7979e0e61e9327f3858ec4066ceeb731
LC_UUID: 490805C1-2069-3B9C-915E-254FC8E4F258
entitlement: com.apple.security.hypervisor=true
USDT: __TEXT,__dof_carrick present
```

Diagnostic run `847-e6-postmortem-06` stopped the same signed executable at
`sparse_materialization.rs:860` while the successor root was in
`publish_raw_stage1_arenas_into -> reserve_table_arena ->
publish_initial_table_root -> initialize_root_process`. Its complete
lifecycle ring (`errors=0`) proves the predecessor completed clean exit first:

```text
8375 HVPPEXIT pid=1 tid=1 exit=0 publication=begin
8377 HVPPEXIT pid=1 tid=1 exit=0 publication=complete
```

The 40 MiB modified-memory core is
`/tmp/847-e6-postmortem-06/carrier.core`; the all-thread backtrace and both
ring populations are in `/tmp/847-e6-postmortem-06/test.log`. Diagnostic
setup runs `-02` through `-05` either did not launch a guest or stopped at the
same site without saving a core; every one cleaned to zero and none is a
functional verdict.

## Root clean exit owns the primary-arena retirement request (2026-10-26)

Commit `784070b25dff47d41163d65dadc350c5e2c42c3e` fixes the exact
`847-e6-postmortem-06` sequence. The root clean-exit owner is responsible for
requesting retirement: runtime terminal publication calls
`begin_address_space_retirement`, the executor retires the resident task and
unpublishes stage 1, and detached whole-MM retirement reaches
`HvfVmState::retire_task_table_capacity`. Neither root-thread exit by itself,
carrier teardown, nor successor bootstrap owns this request; successor
bootstrap only exposed the leaked obligation.

The skipped condition was the optional host image in
`HvfVmState::retire_task_table_capacity`: the implementation added by
`c8a1a3e54` called the primary retirement only under
`if let Some(manager)`. A persistent root's exec transition can legitimately
leave `Stage1Authority::manager == None` while `published_arenas` still owns
primary IPA `0x9a00000000`. The hardware exit therefore completed without
calling `request_released_stage2_record_retirement`, which is why record 14
showed `retirement_requested=false`.

`Stage1Authority::retire_table_capacity` now consumes every base in its owned
`published_arenas` set independently of the optional manager. Each exact
record is enqueued and requested by the whole-MM transition, and its pooled
root release travels in the pending carrier retirement until that same record
becomes terminal. A terminal refusal quarantines the slot instead of making it
reusable; unrelated structural retirements do not release pooled roots.

The production-shape VM-free witness is
`bootstrap_exec_then_clean_exit_requests_primary_arena_retirement_before_reuse`.
It bootstraps the root from the primary pool slot, performs the exec handoff
that removes the host manager, pins the exact stage-2 record, drives the
production clean-exit retirement, and asserts `retirement_requested=true`.
After releasing the pin and driving the safe-point owner, it asserts both the
record and pool hold are gone, then bootstraps and retires a successor from the
same primary base. Red-first on the prior head, it failed at the request
assertion; on the fix it passes 1/1.

Portable verification:

- serialized `carrick-vmm-hvf --lib`: 804 passed, 0 failed, 3 ignored;
- `carrick-aarch64 --lib`: 124 passed, 0 failed;
- the new root-exit witness and three adjacent two-live-MM retirement
  witnesses passed individually;
- `just fmt-check`, `just clippy`, `just clippy-linux`, `just lint-domains`,
  and `just test-kernel`: passed;
- contract-change check against
  `bec60cc3a907002f79a3513e1d3c6d2be3f5075d`: passed;
- macOS all-target EL1 image: 1,120,112 / 1,572,864 bytes; maximum checked
  stack 11,758 / 12,288 bytes (`native backing reply`);
- Linux portable EL1 image: 1,116,032 / 1,572,864 bytes; maximum checked
  stack 11,758 / 12,288 bytes (`native backing reply`).

The first `just test-kernel` attempt reached kernel-semantics after the kernel
library passed, then its linker returned ENOSPC. The worktree's `target/` was
66 GiB, including 49 GiB of stale release output. `cargo clean --release`
removed only recoverable release artifacts; the complete clean retry passed.
No signed test was run because this source requires an exact fixture bundle.

## Clean-exit extension-arena retirement repair (2026-10-26)

Commit `58df7db5af223fa6993fcd1d1994e93a2a09a45e` closes the root-slot
retention shape exposed by `847-d5-smoke-01`. Host stage-1 edits published
extension backing through the HVF task owner but did not record that physical
publication in the owning `Stage1Authority`. Whole-MM retirement therefore
detached the arena from stage 1 while skipping its stage-2 record and pooled
slot. The next bootstrap collided with record 14 at `0x9a00000000`.

Host editors now publish extension arenas through an owned operation that
records the arena for terminal retirement. Live descriptor sync refuses a
grown arena that did not cross that operation, so stage 1 cannot be published
before committed backing. The check uses the MMU's nonallocating arena
iterator, preserving metadata-refusal behavior.

The VM-free production-path binding
`bootstrap_clean_exit_returns_extension_arena_for_next_bootstrap` was red on
the prior implementation: clean exit left the extension record live. It now
grows a bootstrap into the second root-slot-pool arena, retires the MM through
the production whole-MM path, observes the exact stage-2 record disappear,
and boots a successor from that same physical slot.

Portable verification on the repair:

- `carrick-aarch64 --lib`: 124 passed, 0 failed;
- serialized `carrick-vmm-hvf --lib`: 804 passed, 0 failed, 3 ignored;
- serialized `carrick-runtime --lib`: 823 passed, 0 failed, 9 ignored;
- `just fmt-check`, `just clippy`, `just clippy-linux`, `just lint-domains`,
  and `just test-kernel`: passed;
- contract-change check against `2da501dcf0cc81aae517e038bb72dbfee1e1a716`:
  passed;
- default EL1 image: 1,053,200 / 1,572,864 bytes; maximum checked stack
  11,503 / 12,288 bytes (`native wait copy`);
- all-target clippy EL1 image: 1,082,032 / 1,572,864 bytes; maximum checked
  stack 12,015 / 12,288 bytes (`signal terminal exit`).

The first `just fmt-check` attempt stopped before formatting with ENOSPC while
building `carrick-xtask` (441 MiB free). Removing only dev-profile build
artifacts recovered 11.7 GiB; the clean rerun and every later gate passed.
No signed test was attempted because this source change needs a new exact
fixture bundle.

## Exact `d5c77fa1e` root-slot retention failure and runtime-suite repair (2026-10-26)

The exact `d5c77fa1eca6e4f5f591613ed896fce49fb49f8e` fixture bundle
verified, restored, and verified again with 1,195 executables:

```text
/Volumes/carrick-build/fixtures/published/d5c77fa1eca6e4f5f591613ed896fce49fb49f8e/aa366be47ac5dca349946df666a2c440be99a79c27d1a12feeb49a6d1586f7bf.tar.gz
bundle identity: aa366be47ac5dca349946df666a2c440be99a79c27d1a12feeb49a6d1586f7
archive SHA-256: 68daa7823878e19e79ecdc46a90f33482acda30e6c9df620e7804cf690bbcfec
input identity: 2492797e6f21b47d83c36ca54d70c7d7a1953857010242670b5def177a0e218c
```

The mandatory bootstrap smoke `847-d5-smoke-01` (backend run
`847-d5-smoke-01-b1`) reached HVF and failed 0/1 in 0.33 seconds. This was a
typed hypervisor error rather than a `carrick: FATAL` abort:

```text
stage-1 extension arena IPA 0x9a00000000 is still held by the root-slot pool;
stage2=Some(CarrierStage2RecordSnapshot { record_id: CarrierStage2RecordId(14),
vm_generation: CarrierVmGeneration(1), ipa: 661424963584, len: 2097152,
host_addr: 5100273664, mapped: true, backend_map_installed: false,
release_ipa: false, perms: 3, logical_owner:
Some(CarrierLogicalOwner { id: 14, generation: 14 }), pin_count: 0,
retirement_requested: false, retry_eligible: false, retry_pending: None,
terminalized_by_vm_destroy: false, superseded_by_rebind: false,
release_in_flight: false, release_retry_pending: false })
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured;
90 filtered out; finished in 0.33s
```

The entitlement negative control passed. Run-scoped cleanup was complete:

```text
remaining carrick procs (run-id 847-d5-smoke-01-b1) = 0
remaining carrick procs (run-id 847-d5-smoke-01-b1-cli) = 0
remaining carrick procs (run-id 847-d5-smoke-01-neg) = 0
remaining carrick procs (run-id 847-d5-smoke-01) = 0
remaining carrick procs (run-id 847-d5-smoke-01-cli) = 0
```

There was no watchdog census. Per the stop-on-smoke-failure direction, the
requested population stopped here:

- bootstrap smoke: 0/1 (`847-d5-smoke-01`);
- host-blocked-read witness: not started (0/0 of 20);
- `native_root_exec_replaces_pid1_shell`: not started (0/0);
- `el1_ipc_pipe_blocking_roundtrips`: not started (0/0 of 3);
- `el1_fork_cow_resolves_in_guest`: not started (0/0 of 3).

Diagnostic run `847-d5-postmortem-02` stopped the signed executable at
`sparse_materialization.rs:860` and saved the carrier core. Its stopped thread
was bootstrapping `/opt/carrick/el1-sched sock-pingpong 6000` through
`publish_raw_stage1_arenas_into -> reserve_table_arena ->
publish_initial_table_root -> initialize_root_process`. The lifecycle ring
showed the predecessor image had completed its exit before the next bootstrap:

```text
# carrick event ring (lifecycle) pid=48151 total=8382 showing=1024
# start=7358 oldest=190 errors=0
8367 HVPPEXIT pid=1 tid=1 exit=0 publication=begin
8369 HVPPEXIT pid=1 tid=1 exit=0 publication=complete
# carrick event ring (high-rate) pid=48151 total=9562 showing=1024
# start=8538 oldest=1370 errors=0
```

The post-mortem is `/tmp/847-d5-postmortem-02/carrier.core`; full LLDB and
ring output is `/tmp/847-d5-postmortem-02/test.log`. This debugger run is not
a functional pass. Its exact signed diagnostic artifact was:

```text
target/release/deps/el1_sched-d8a5a9a0d2511a83
SHA-256: 5411f55dc55cff3eae6d1b27f9cbe041c58aea4531ae3e72e9e8cc7724182bc4
CDHash: c6b5256bdb2a129be0c0ac3ceef242982c5781e0
LC_UUID: 6054AE0F-20DD-35E1-8906-2C3F266D3185
entitlement: com.apple.security.hypervisor=true
USDT: __TEXT,__dof_carrick present
```

The uninstrumented smoke executable was re-signed before its identity was
preserved, so the identity above belongs to the exact diagnostic artifact
built from the same source and fixture inputs.

GitHub main `a12d88a7b0dca37fdf3fd3b38a7ad2f5e96fcc7e` passed its
`carrick-runtime --lib` population (810 passed, 0 failed, 9 ignored). The
candidate initially had 811 passed, 12 failed, and 9 ignored, so all twelve
were branch regressions:

1. `hvpatch::stage1_mm::tests::retirement_waits_for_a_borrowed_ttbr0_window_and_then_owes_its_invalidation`
2. `vcpu_loop::binding::tests::child_tid_write_without_an_editor_producer_skips_silently`
3. `vcpu_loop::exec::exec_image_verification_tests::no_return_arming_precedes_destructive_work_and_mm_publication_follows_it`
4. `vcpu_loop::executor::tests::exit_group_consumes_the_last_resident_entry_before_root_retirement`
5. `vcpu_loop::executor::tests::saved_replacement_returns_host_wait_slot_before_terminal_retirement`
6. `vcpu_loop::executor::tests::terminal_retirement_does_not_hold_topology_lock_across_detached_cleanup`
7. `vcpu_loop::memory::tests::native_buffers::current_read_window_rechecks_live_carrier_authorities`
8. `vcpu_loop::memory::tests::native_data_activation_rejects_changes_after_preparation`
9. `vcpu_loop::signal::guest_descriptor_lane_tests::fork_commit_and_syscall_entry_order_guest_descriptor_work`
10. `vcpu_loop::tests::serial_host_carrier_ipc_physical_owner_wait_cancellation_from_el0`
11. `vcpu_loop::tests::serial_host_munmap_retirement_races_blocking_read_with_one_executor`
12. `vcpu_loop::tests::serial_host_native_ipc_physical_owner_wait_cancellation_from_el0`

Commit `64a16d3bb` repairs the witnesses without weakening production
authentication. Test HVPatch roots now publish through real sched-core
address-space custody before retirement, synthetic page-table authorities bind
their exact Kernel MM, and structural order checks match the licensed
production call shapes. The retained no-producer witness now asserts the
design's exact-MM invariant SIGKILL rather than treating an impossible
stage-2 state as an ordinary `ChildTid` write failure.

Portable verification:

- `carrick-runtime --lib`: 823 passed, 0 failed, 9 ignored;
- serialized `carrick-vmm-hvf --lib`: 803 passed, 0 failed, 3 ignored;
- `just fmt-check`, `just clippy`, `just clippy-linux`, and
  `just lint-domains`: passed;
- `just test-kernel`: passed (kernel 2,639 passed, 0 failed, one ignored;
  every kernel-semantics target completed without failure);
- default EL1 image: 1,053,200 / 1,572,864 bytes; maximum checked stack
  11,503 / 12,288 bytes (`native wait copy`);
- all-target clippy EL1 image: 1,082,032 / 1,572,864 bytes; maximum checked
  stack 12,015 / 12,288 bytes (`signal terminal exit`).

No post-fix signed test was attempted because the source correction requires
a new exact-candidate fixture bundle.

## Exact `89d1a591a` empty-publication fatal and source correction (2026-10-26)

The fixture bundle for `89d1a591a77f8f6e9071040c13c44b305076ee68`
verified, restored, and verified again with 1,195 executables:

```text
/Volumes/carrick-build/fixtures/published/89d1a591a77f8f6e9071040c13c44b305076ee68/8afa7e3e8814d81fde0eee1ca9f3b97693f9741880fb6a5d8e7055bb0208da72.tar.gz
bundle identity: 8afa7e3e8814d81fde0eee1ca9f3b97693f9741880fb6a5d8e7055bb0208da72
archive SHA-256: 62dfd65d4a548f769735c42346864114ac5e37b8912245a2c421b249ec35828c
input identity: 2492797e6f21b47d83c36ca54d70c7d7a1953857010242670b5def177a0e218c
```

The mandatory bootstrap smoke `847-89d-smoke-01` (backend run
`847-89d-smoke-01-b1`) reached HVF and failed 0/1 in 2.29 seconds.  Four
completed guest arms each reported the same carrier fatal before the outer
cost witness rejected the corrupted population:

```text
carrick: FATAL: detached address-space retirement failed (the MM-authority drop abort that follows is a CONSEQUENCE of this, not the cause): hypervisor operation failed: publish detached terminal inventory retirement: frame inventory batch is empty
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 90 filtered out; finished in 2.29s
remaining carrick procs (run-id 847-89d-smoke-01-b1) = 0
remaining carrick procs (run-id 847-89d-smoke-01-b1-cli) = 0
remaining carrick procs (run-id 847-89d-smoke-01-neg) = 0
remaining carrick procs (run-id 847-89d-smoke-01) = 0
remaining carrick procs (run-id 847-89d-smoke-01-cli) = 0
```

The entitlement negative control passed.  There was no watchdog and therefore
no watchdog census.  Per the stop-on-smoke-failure direction, the requested
population stopped here:

- bootstrap smoke: 0/1 (`847-89d-smoke-01`);
- host-blocked-read acceptance population: not started (0/0 of 20);
- `native_root_exec_replaces_pid1_shell`: not started (0/0);
- `el1_ipc_pipe_blocking_roundtrips`: not started (0/0 of 3);
- `el1_fork_cow_resolves_in_guest`: not started (0/0 of 3).

Diagnostic run `847-89d-fatalring-03` stopped the signed executable at the
runtime publication boundary and saved the carrier core.  This run is a
debugger capture, not a functional pass; its LLDB wrapper terminates the guest
after collecting evidence.  The stopped thread and ring tail were:

```text
thread #11, name = 'carrick-executor-0', stop reason = breakpoint 1.14
HvpatchTaskQuantum::apply_detached_address_space_retirement(
    commit=FrameInventoryCommit<()> @ 0x00000001710ebd20)

# carrick event ring (lifecycle)  pid=5495  total=8258  showing=512  start=7746  oldest=66  errors=0
8256 HVPPEXIT pid=1 tid=1 exit=0 publication=begin
# carrick event ring (high-rate)  pid=5495  total=9534  showing=512  start=9022  oldest=1342  errors=0
```

The post-mortem is `/tmp/847-89d-fatalring-03/carrier.core`; full LLDB and
ring output is `/tmp/847-89d-fatalring-03/test.log`.  Its exact signed artifact
identity was:

```text
target/release/deps/el1_sched-d8a5a9a0d2511a83
SHA-256: 611fb9babd880ddc6a6dbbc382c11195cf2a1d254fb94f8ee5a68cd3c58fa475
CDHash: b82615e7633957c309468a6bb86f4c9411d88660
LC_UUID: BEEBD13F-3CD9-30B8-92B4-60FE5AC7E91E
entitlement: com.apple.security.hypervisor=true
USDT: __TEXT,__dof_carrick present
```

The smoke executable had already been re-signed by the time the post-mortem
receipt was captured, so its pre-debugger SHA/CDHash are not recoverable.  The
identity above is the exact diagnostic artifact built from the same source and
fixture inputs, not a claim that re-signing preserved the original identity.

The backend correction in `4a8872256` was valid: a never-registered task
closes its owned reservation with an empty commit.  The remaining defect was
the consumer.  The runtime unconditionally sent that commit to
`FrameInventory::apply`, whose public contract rejects an eventless batch.
Commit `1a502b2e9` consumes an empty detached commit after taking the exact
terminal authority without invoking the nonempty Kernel batch API.  A
receipt-bearing published inventory still fails closed if it somehow has no
retirement events.  The VM-free witness commits a real empty reservation and
proves the Kernel publication closure is not called.

The 12 `carrick-aarch64` failures reported on this branch were also real branch
regressions, not pre-existing main failures.  Nine behavioral fixtures used an
unbound `Stage1Authority` with an exact-MM Editor license; three structural
witnesses matched pre-refactor formatting or funnel names.  Commit
`1f0cec40c` binds test authorities to MM 1 and updates those witnesses without
weakening production authentication.  The full suite is now 124/124.

Portable verification at `1f0cec40c`:

- `cargo test -p carrick-aarch64 --lib`: 124 passed, 0 failed;
- `empty_detached_inventory_commit_skips_kernel_publication`: 1 passed;
- `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, and `just test-kernel`: passed;
- `just check-contract-change 2da501dcf0cc81aae517e038bb72dbfee1e1a716 HEAD`:
  passed;
- default EL1 image: 1,053,200 / 1,572,864 bytes; maximum checked stack
  11,503 / 12,288 bytes (`native wait copy`);
- allocator-test-control EL1 image: 1,057,376 / 1,572,864 bytes; maximum
  checked stack 11,503 / 12,288 bytes (`native wait copy`).

An additional serialized full `carrick-runtime --lib` diagnostic was not a
green gate: 811 passed, 12 failed, 9 ignored.  Those separate branch-level
fixture/structural failures do not invalidate the focused empty-consumer
witness, but they remain explicit follow-up work rather than being described as
pre-existing main failures.

No signed post-fix run was attempted because the two source commits require a
new exact-candidate fixture bundle.

## `2e26b934d` bootstrap root cause and source correction (2026-10-26)

The guest fault recorded below was not caused by a stage-1 leaf exposing zero
or misaligned content.  Live register and syscall captures on the exact signed
artifact identified an earlier anonymous-`mmap` refusal:

```text
847-2e26-fault-live9:
  PC=0x29e564 (__copy_tls: str x1, [x20], #8)
  x20=0x144 x23=0xfffffffffffffff4 (-ENOMEM)

847-2e26-mmap-refusal:
  mmap(addr=0, length=344, prot=3, flags=34, fd=-1, offset=0) = -1 errno 12
  reason: anonymous predecessor retirement failed

847-2e26-mmap-error3:
  guest stage-1 unmap: verified retirement did not bind its old leaves
```

Musl used the failed TLS allocation result in its pointer arithmetic and then
wrote through `0x144`.  The faulting instruction and bad pointer therefore
followed the `ENOMEM`; the page containing `__copy_tls` was intact.  The saved
core and rings remain at:

```text
/tmp/847-2e26-fatalring-14/carrier.core
/tmp/847-2e26-fatalring-14/carrier.lldb.txt
```

The rejected retirement was the inaccessible neighbour in a freshly prepared
sparse arena.  Its authenticated descriptor transaction correctly retired no
live stage-1 leaf.  `complete_guest_retirement_proof` nevertheless represented
both “verified and empty” and “verification failed” as `None`, so the engine
converted the former into `ENOMEM`.

Commit `d1a72f4d7` makes that state structural: proof validation is a typed
`Result`, while a successful retirement carries `Option<Stage1LeafRetired>`.
A live pre-image produces a proof; an invalid retained output produces
`Ok(None)` and cannot authorize stage-2 retirement.  The strengthened
`guest_owned_authority_refuses_host_live_stores_and_builds_guest_transactions`
witness runs the real prepare/apply/verify transaction over both a live leaf
and its prepared inaccessible neighbour.  This preserves the publication
invariant: no stage-1 leaf is exposed without committed backing, and an invalid
retained output cannot manufacture retirement authority.

The carrier fatal was a second defect.  The task died before carrier
registration, but still owned the Kernel's inventory reservation.  Commit
`4a8872256` makes detached retirement consume an already-staged commit when
present or commit that reservation with an empty event batch when the task
never registered.  Missing both is a typed `RetirementRefused`, not a generic
hypervisor failure.  The strengthened
`whole_mm_retirement_of_never_registered_detached_space_is_empty` production
witness retires a never-registered MM, consumes the returned commit, and
checks that its event batch is empty.

The same pass audited static missing-result failures at the fallible carrier
retirement/publication crossings.  The following are now typed
`RetirementRefused` or `PublicationRefused` results:

- carrier-exit custody and carrier-MM unpublished inventory;
- exec-predecessor carrier MM, root proof, inventory authority, and MM
  identity;
- task stage-1 unpublication and prepared-task rollback/custody/frame registry;
- task-only root owner and inventory reservation;
- process root proof, inventory authority/reservation/identity, and detached
  inventory completion;
- declined-remainder settlement and process-materialization inventory;
- every default AArch64 inventory publication/retirement method which has no
  backend implementation.

Direct `carrick_fatal!` checks left in constructors and infallible typed
accessors (for example, a published `PendingTransferGrant` without its owned
descriptor transaction) are not absence crossings: those values cannot be
returned as refusals without weakening the type's construction invariant.
They were enumerated separately during the audit and were not relabelled as
ordinary lifecycle refusals.

Fresh portable verification at `4a8872256`:

- `guest_owned_authority_refuses_host_live_stores_and_builds_guest_transactions`:
  1 passed;
- `whole_mm_retirement_of_never_registered_detached_space_is_empty`: 1 passed;
- serialized `carrick-vmm-hvf --lib`: 803 passed, 0 failed, 3 ignored;
- `just fmt-check`, `just clippy`, `just clippy-linux`, and
  `just lint-domains`: passed;
- `just test-kernel`: passed (kernel library 2,639 passed, 1 ignored, and all
  kernel-semantics targets completed without failure);
- `just check-contract-change 2da501dcf0cc81aae517e038bb72dbfee1e1a716 HEAD`:
  passed;
- default EL1 image: 1,053,200 / 1,572,864 bytes; maximum checked stack
  11,503 / 12,288 bytes (`native wait copy`);
- allocator-test-control EL1 image: 1,057,376 / 1,572,864 bytes; maximum
  checked stack 11,503 / 12,288 bytes (`native wait copy`);
- all-target clippy EL1 image: 1,082,032 / 1,572,864 bytes; maximum checked
  stack 12,015 / 12,288 bytes (`signal terminal exit`).

No signed post-fix run was attempted because these commits change source and
need an exact-candidate fixture bundle.

## Exact `2e26b934d` inventory-commit fatal (2026-10-26)

The exact bundle for `2e26b934d032924e61cf03e1546b054dedef6780`
verified, restored, and then verified again with 1,195 executables:

```text
/Volumes/carrick-build/fixtures/published/2e26b934d032924e61cf03e1546b054dedef6780/76be9ca2ad15bf3b16f7c24f1cbc268ed013bfb0ab861c5ff8d7430217a932e1.tar.gz
bundle identity: 76be9ca2ad15bf3b16f7c24f1cbc268ed013bfb0ab861c5ff8d7430217a932e1
archive SHA-256: 170bad970ac055cca69ab1cf1ad85b7e70750c15142974da8c129d8eac6bc46d
input identity: 2492797e6f21b47d83c36ca54d70c7d7a1953857010242670b5def177a0e218c
```

The first attempt, `847-2e26-smoke-01`, ran no guest: compiling the unsigned
debug harness filled the gate volume. `cargo clean --profile dev` removed
only generated debug artifacts, leaving the restored release fixtures
intact; the bundle was verified again before hardware execution.

The mandatory uninstrumented bootstrap smoke `847-2e26-smoke-02` (backend
run `847-2e26-smoke-02-b1`) reached HVF and failed 0/1 in 0.11 seconds:

```text
carrick: FATAL: detached address-space retirement failed (the MM-authority drop abort that follows is a CONSEQUENCE of this, not the cause): hypervisor operation failed: detached HVPatch task retirement produced no inventory commit
exit 139 signal Some(Signal(11)) stdout "" stderr ""
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 90 filtered out; finished in 0.11s
remaining carrick procs (run-id 847-2e26-smoke-02-b1) = 0
remaining carrick procs (run-id 847-2e26-smoke-02-b1-cli) = 0
remaining carrick procs (run-id 847-2e26-smoke-02-neg) = 0
remaining carrick procs (run-id 847-2e26-smoke-02) = 0
remaining carrick procs (run-id 847-2e26-smoke-02-cli) = 0
```

The entitlement negative control passed. This is a carrier-fatal/new-source
regression, so the requested acceptance population stopped immediately:

- bootstrap smoke: 0/1 (`847-2e26-smoke-02`);
- host-blocked-read acceptance population: not started (0/0 of 20);
- `native_root_exec_replaces_pid1_shell`: not started (0/0);
- `el1_ipc_pipe_blocking_roundtrips`: not started (0/0 of 3);
- `el1_fork_cow_resolves_in_guest`: not started (0/0 of 3).

Runs `847-2e26-fatal-03`, `847-2e26-fatalcap-04`, and
`847-2e26-fatalring-05` through `847-2e26-fatalring-10` reproduced the same
failure while qualifying a capture method; every signed-harness cleanup line
was zero. `847-2e26-fatalring-12` and `-13` did not launch a guest because the
diagnostic debugger invocation itself was refused. Final diagnostic run
`847-2e26-fatalring-14` launched the exact signed test under LLDB from the
signed harness, stopped at the failure before retirement unwound, saved a
34 MiB modified-memory core, dumped both event rings, and then reproduced the
same terminal result. Its host-local post-mortem is:

```text
/tmp/847-2e26-fatalring-14/carrier.core
/tmp/847-2e26-fatalring-14/carrier.lldb.txt
```

The exact diagnostic artifact was
`target/release/deps/el1_sched-d8a5a9a0d2511a83`:

```text
SHA-256: af95f8dc7586a1f16ac399e67283f040e40694eba6ee0222832918af406ebfdf
CDHash: 0b987df1110106a1c47d4e9fff00aa5e51b830ba
LC_UUID: 66D88277-F25C-3718-A34C-3D527C98028C
identifier: el1_sched-d8a5a9a0d2511a83.tmp.2281
entitlement: com.apple.security.hypervisor=true
USDT: __TEXT,__dof_carrick present
```

The lifecycle ring at the failure was, verbatim:

```text
# carrick event ring (lifecycle)  pid=5051  total=30  showing=30  start=0  oldest=0  errors=0
     0 SYSLOG_RECORD owner=1 seq=1 total_bytes=68
     1 SYSLOG_STATE owner=1 read_seq=1 clear_seq=1 unread=68
     2 SYSLOG_WAKE owner=1 type=1 wake_count=1 poll_fd=16385
     3 ALIAS    coordinator=0x600003ac2310 tid=0 begin=dispatch
     4 ALIAS    coordinator=0x600003ac2310 tid=0 end
     5 SYSLOG_RECORD owner=2 seq=1 total_bytes=52
     6 SYSLOG_STATE owner=2 read_seq=1 clear_seq=1 unread=52
     7 SYSLOG_WAKE owner=2 type=1 wake_count=1 poll_fd=16389
     8 HVPEXEC  pid=1 tid=1 executor=1 phase=claim
     9 HVPEXEC  pid=1 tid=1 executor=1 phase=load
    10 ALIAS    coordinator=0x600003ac2310 tid=1 begin=dispatch
    11 ALIAS    coordinator=0x600003ac2310 tid=1 end
    12 ALIAS    coordinator=0x600003ac2310 tid=1 begin=dispatch
    13 ALIAS    coordinator=0x600003ac2310 tid=1 end
    14 FAULTSIG tid=1 mm=1 signal=11 si_code=1 mutating=false walk=L3-invalid-denies access=write direct=false
    15 FAULTSIG_ADDR far=0x0000000000000144 esr=0x92000047
    16 FAULTSIG_PC tid=1 pc=0x000000000029e564
    17 FAULTSIG_LEAF tid=1 leaf=0x0000000000000000
    18 FAULTSIG_MBOXES tid=1 busy=0 own_slot=0 mask0_31=0x00000000
    19 HVPTHREAD pid=1 tid=1 phase=cleanup-start
    20 HVPTHREAD pid=1 tid=1 phase=registry-removed
    21 HVPTHREAD pid=1 tid=1 phase=kicker-unregistered
    22 HVPTHREAD pid=1 tid=1 phase=signal-forgotten
    23 HVPTHREAD pid=1 tid=1 phase=dispatcher-forgotten
    24 HVPEXEC  pid=1 tid=1 phase=boundary reason=yielded
    25 HVPEXEC  pid=1 tid=1 phase=settlement state=runnable
    26 HVPEXEC  pid=1 tid=1 executor=2 phase=claim
    27 HVPEXEC  pid=1 tid=1 executor=2 phase=load
    28 HVPPEXIT pid=1 tid=1 exit=139 publication=begin
    29 HVPEXEC  pid=1 tid=1 phase=boundary reason=exited
```

The high-rate ring was also complete and error-free:

```text
# carrick event ring (high-rate)  pid=5051  total=4  showing=4  start=0  oldest=0  errors=0
     0 SCHED_DISPATCH tid=2 executor=1 cpu=0
     1 SCHED_BUDGET executor=1 budget_ms=4 generation=1
     2 SCHED_DISPATCH tid=2 executor=2 cpu=1
     3 SCHED_BUDGET executor=2 budget_ms=4 generation=2
```

The stopped retirement frame carried `Stage1UnpublishedMm { mm: 1 }` and
returned the inventory-commit error quoted above. The ring shows the preceding
guest-visible event precisely: PID/TID 1 took a write `SIGSEGV/SEGV_MAPERR` at
VA `0x144` (PC `0x29e564`), began exit 139 publication, and then detached MM
retirement found no inventory commit. There was no watchdog and therefore no
watchdog census. Source was not changed.

## Exact `f990f2af5` whole-MM retirement fatal (2026-10-26)

The exact bundle for `f990f2af550881bfbbcf5d75afea942d95e9ec69`
verified and restored 1,195 executables:

```text
/Volumes/carrick-build/fixtures/published/f990f2af550881bfbbcf5d75afea942d95e9ec69/0cb8db16161f7635251780c296f8707b76b7ff2ee79228ba7ca42d5bbd0180ec.tar.gz
bundle identity: 0cb8db16161f7635251780c296f8707b76b7ff2ee79228ba7ca42d5bbd0180ec
archive SHA-256: 7df3dded13f8dcd7b07dba0611f285ffd0ae85c8d2e8e253ae6f5a32542778fe
input identity: 293074b237d1d1b0a2ec3ba5560927dc50a6b24526c35117811014c7003a78b2
```

The mandatory bootstrap smoke `847-f990-smoke-01` (backend run
`847-f990-smoke-01-b1`) reached HVF and failed in 0.11 seconds with this exact
carrier fatal:

```text
carrick: FATAL: detached address-space retirement failed (the MM-authority drop abort that follows is a CONSEQUENCE of this, not the cause): hypervisor operation failed: whole-MM retirement has no carrier registration for stage-1 proof
exit 139 signal Some(Signal(11)) stdout "" stderr ""
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 90 filtered out; finished in 0.11s
```

No watchdog census was emitted. The signed harness and explicit cleanup
reported zero remaining processes for `847-f990-smoke-01-b1`, its CLI scope,
the negative control, and the outer `847-f990-smoke-01` scope. The entitlement
negative control passed. Per the stop condition, the additional 20 host-read
runs and all nine companion runs were not started. The failure and cleanup
receipt are quoted verbatim above so this durable record does not depend on a
host-local log. No source change was made.

The signed executable was
`target/release/deps/el1_sched-a135647895e386e6`:

```text
SHA-256: b1ef112f1cd3c37d618c2401bb4a1232124ea13a2cb5c88c53b95b920e1ca5d2
CDHash: 91fb6fa330cce1ae2ab76fcde3a6afaa7371460e
LC_UUID: B935226E-EAB7-3840-AAFF-7204AB4D8288
identifier: el1_sched-a135647895e386e6.tmp.48463
entitlement: com.apple.security.hypervisor=true
USDT: __TEXT,__dof_carrick present
```

## Portable closure after the `f990f2af5` review (2026-10-26)

Source head `acd200cea` closes the bootstrap fatal and the review's ambient
license finding before another signed artifact is built:

- whole-MM retirement treats an MM with no carrier registration and no
  stage-2 references as an empty successful retirement; the VM-free detached
  and never-registered witnesses pass;
- `El1EditorExcluded` is non-cloneable and borrowed from the exclusion guard;
  every production stage-1 edit receives that borrow explicitly, while the
  exact-MM assertion returns a typed refusal and records
  `STAGE1_EDITOR_LICENSE_REFUSAL`;
- when no EL1 region exists at all, bootstrap and VM-free callers receive an
  exact-MM unpublished proof from an empty directory. Once the region exists,
  only its live published/unpublished directory can license an edit;
- stage-2 reference release compares the receipt's Editor authority and MM
  with the retiring extent owner, the guest-written COW self-termination
  boundary is documented, rollback removal outcomes are handled, and evidence
  needed for review is quoted here rather than delegated to `/tmp` paths.

Portable verification on `acd200cea`:

- serialized `carrick-vmm-hvf --lib`: 803 passed, 0 failed, 3 ignored;
- `just test-kernel`: passed (the first run exposed the missing no-EL1-region
  proof; the complete rerun passed after that proof was made explicit);
- `just fmt-check`, `just clippy`, `just clippy-linux`, `just lint-domains`,
  and the contract-change gate: passed;
- normal EL1 image: 1,053,200 / 1,572,864 bytes, maximum checked stack
  11,503 / 12,288 (`native wait copy`);
- Linux portable all-target EL1 image: 1,077,936 / 1,572,864 bytes, maximum
  checked stack 12,015 / 12,288 (`signal terminal exit`);
- embed EL1 image: 1,082,032 / 1,572,864 bytes, maximum checked stack
  12,015 / 12,288 (`signal terminal exit`).

No signed run has been made from this corrected source. The next required
evidence is one exact-bundle bootstrap smoke followed by the 20/20 host-read
population and requested companions.

## Exact `3e5abed72` bootstrap regression and review closure (2026-10-26)

The exact bundle for `3e5abed72a8e9e3c2cc0abf8af68f7fbd0b88b4c`
verified and restored 1,195 executables:

```text
/Volumes/carrick-build/fixtures/published/3e5abed72a8e9e3c2cc0abf8af68f7fbd0b88b4c/3ef30cb7418785d6e2396fe5d4bdc31a9e76fcda886ef3582e10b41fb3bf2d7a.tar.gz
bundle identity: 3ef30cb7418785d6e2396fe5d4bdc31a9e76fcda886ef3582e10b41fb3bf2d7a
archive SHA-256: d88dc8782a3d78767a14279fc5d2cfca0427673b8db2faabe3ea1eff669f9d75
input identity: 293074b237d1d1b0a2ec3ba5560927dc50a6b24526c35117811014c7003a78b2
```

The prerequisite-bearing smoke attempt `847-3e5-smoke-01` was rejected by
the disk guard at 13 GiB free and never executed a guest. The approved
no-prerequisite signed harness run `847-3e5-smoke-02` (backend run
`847-3e5-smoke-02-b1`) reached HVF and failed in 0.11 seconds before the
workload loop:

```text
configuration refused: exclude root EL1 Editor before HVPatch ASID setup
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 90 filtered out; finished in 0.11s
remaining carrick procs (run-id 847-3e5-smoke-02-b1) = 0
remaining carrick procs (run-id 847-3e5-smoke-02-b1-cli) = 0
remaining carrick procs (run-id 847-3e5-smoke-02) = 0
remaining carrick procs (run-id 847-3e5-smoke-02-cli) = 0
```

Classification: source bootstrap regression, not the #847 hang. There was no
guest EFAULT, watchdog, carrier fatal, or watchdog census. The negative
entitlement control passed and its scoped cleanup was zero. The full 20-run
population and companions stopped at the required smoke gate. The complete
failure and cleanup receipt is quoted verbatim above.

The signed executable was
`target/release/deps/el1_sched-a135647895e386e6`:

```text
SHA-256: 0cc68839acbdc5f5cf67395ce70c06640f82d270acd8da12fbd2ea31881e0ca3
CDHash: 5a35286ac32c664962fbfe8e22a967c0547ab94d
LC_UUID: DCA660B5-A90F-39C7-BE76-27E7AFE51047
identifier: el1_sched-a135647895e386e6.tmp.13414
entitlement: com.apple.security.hypervisor=true
USDT: __TEXT,__dof_carrick present
```

`a7e833024` fixes the bootstrap path by taking the already-installed raw zone
table rather than the policy-gated live scheduler view. The accompanying
audit enumerated every production `Stage1Authority::edit*` caller, including
boot, arena setup, AArch64 live edits, local COW, foreign COW, and sparse
materialization/import; each now takes the exact-MM owned edit license.

The three design-review P1s remain closed on this head: replacement
unpublication comes only from verified descriptor receipts after invalidation;
whole-MM proof is bound to the exact MM; and the edit license is an owned,
process-visible exact-MM capability rather than thread-local state. The final
review closure makes host `Stage1LeafRetired` unavailable until its TLBI
callback succeeds. Losing the consume-once rollback receipt leaves the extent
quarantined and emits `STAGE2_ROLLBACK_INVARIANT` through the terminal event
ring instead of silently leaking diagnostic evidence.

Portable verification on the post-review source:

- serialized `carrick-vmm-hvf --lib`: 801 passed, 0 failed, 3 ignored;
- focused TLBI-order, foreign-COW, host-repoint and terminal-invariant
  witnesses: passed;
- `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, `just test-kernel`, and the contract-change gate:
  passed;
- normal EL1 image: 1,053,104 / 1,572,864 bytes, maximum checked stack
  11,503 / 12,288 (`native wait copy`);
- all-target EL1 image: 1,081,920 / 1,572,864 bytes, maximum checked stack
  12,015 / 12,288 (`signal terminal exit`).

The source changed after the failed signed artifact. An exact bundle for the
new evidence head is required before the 20/20 host-read proof and companions.

## Exact `3e3e702d9` bootstrap regression and portable correction (2026-10-25)

The exact bundle for `3e3e702d9b7ccfb981527d4af36eab2d67a9f15e`
verified and restored 1,195 executables before the requested serial proof:

```text
/Volumes/carrick-build/fixtures/published/3e3e702d9b7ccfb981527d4af36eab2d67a9f15e/18f2a1a0d3ae419df8300441a1de62edee71fde625a6b750e00b1e1e5467e2f3.tar.gz
bundle identity: 18f2a1a0d3ae419df8300441a1de62edee71fde625a6b750e00b1e1e5467e2f3
archive SHA-256: c0363cd8fa14897a785b6854a1bab77706058e7a74b61cfdfb3db460744e6ff3
input identity: 293074b237d1d1b0a2ec3ba5560927dc50a6b24526c35117811014c7003a78b2
```

The first requested host-read repetition, `847-3e3-hostread-01`, failed in
0.11 seconds before the workload entered its loop:

```text
reserve sparse HVPatch root mmap arena: host mapping operation failed: stage-1 edit lacks its Editor exclusion
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 90 filtered out; finished in 0.11s
remaining carrick procs (run-id 847-3e3-hostread-01) = 0
remaining carrick procs (run-id 847-3e3-hostread-01-cli) = 0
```

Classification: source regression, not the #847 hang. There was no guest
EFAULT, watchdog, carrier fatal, or watchdog census. The matrix stopped on
that regression, so the remaining 19 host-read repetitions and all companion
populations were not run on this artifact. The complete failure and cleanup
receipt is quoted verbatim above.

The signed executable was
`target/release/deps/el1_sched-a135647895e386e6`:

```text
SHA-256: f4967796b6e3ff63aac1cf7c282060691ede501bf860fca7cdf37e4055888ff0
CDHash: 9d63aff64e2e94175228d8562f1c443b70cec94f
LC_UUID: 8B4F803F-A61E-3ABF-A853-61A888372A8C
identifier: el1_sched-a135647895e386e6.tmp.66718
entitlement: com.apple.security.hypervisor=true
USDT: __TEXT,__dof_carrick present
```

The portable correction is split into three reviewable commits. `2b58752be`
acquires the root MM's Editor exclusion across bootstrap ASID setup.
`a81a89199` accepts an authenticated EL1 COW settlement after a later admitted
owner has retired or re-armed the replacement, while still rejecting the old
output's reappearance. `62d74d6b8` gives relocated bootstrap primaries their
missing retirement owner: whole-MM, rootless-shared, and exec-predecessor
retirement consume the exact MM receipt, retain proof custody across pins, and
complete at the carrier safe point. The same change preserves declined and
republished inventory proofs instead of dropping or demanding them early.

Portable verification on `62d74d6b8`:

- `carrick-vmm-hvf --lib`, serial: 800 passed, 3 ignored;
- `carrick-vmm-hvf --lib`, default parallel: 800 passed, 3 ignored;
- focused later-owner settlement, parked-pin, rootless-shared,
  exec-successor, declined-retirement, and exact-root witnesses: passed;
- `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, and `just test-kernel`: passed;
- normal EL1 image: 1,053,104 / 1,572,864 bytes, maximum checked stack
  11,503 / 12,288 (`native wait copy`);
- all-target/Linux clippy EL1 image: 1,081,920 / 1,572,864 bytes, maximum
  checked stack 12,015 / 12,288 (`signal terminal exit`).

The source changed after the failed signed artifact. An exact bundle for the
new evidence head is required before the 20/20 host-read proof and companions.

## Exact `98e177408` bootstrap regression (2026-10-25)

The exact bundle for `98e177408103bc79ef5a79306b921a2c31dc2b94`
verified and restored 1,195 executables before the requested serial proof:

```text
/Volumes/carrick-build/fixtures/published/98e177408103bc79ef5a79306b921a2c31dc2b94/2c0eeb41b38f1d58d3cb69ccf0c6bed3305b05fdd40e4cd99d243e8c8c0f75d2.tar.gz
bundle identity: 2c0eeb41b38f1d58d3cb69ccf0c6bed3305b05fdd40e4cd99d243e8c8c0f75d2
archive SHA-256: 61a512d58226546980f6d2161151183fe848fae9528b649043a6a17cd4213de4
input identity: 6758fc7d7b8cb90a61068a28cb57ca3f8a0e5af38c46247e7bc268a75fff3651
```

The first host-read repetition, `847-98e-hostread-01`, failed before the
workload entered its loop:

```text
container run failed: runtime failure: filesystem backend error: failed to run ELF from dispatcher: trap engine failed: hypervisor operation failed: reserve sparse HVPatch root mmap arena: host mapping operation failed: stage-1 edit lacks its Editor exclusion
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 90 filtered out; finished in 0.11s
```

Classification: source regression, not the #847 hang. Pass count was 0/1;
there was no EFAULT, watchdog, carrier fatal, or watchdog census. The harness
and the explicit `scripts/sudo/kill.sh 847-98e-hostread-01` cleanup both
reported zero remaining scoped processes. Per the stop condition, the other
19 host-read repetitions, all three companion populations, and the signed
counterparts of the new witnesses were not run on this broken artifact. The
complete failure and cleanup receipt is quoted verbatim above.

The signed executable was
`target/release/deps/el1_sched-a135647895e386e6`:

```text
SHA-256: 036c9d5f7ddfd0f9cd9807b63219ce11b3e0fb5dd743c9665b318bf43fe2dded
CDHash: 96972583a6f131404147ba196501beea86f96e9a
LC_UUID: 220F1BCF-9B93-3879-9141-116C6A305475
entitlement: com.apple.security.hypervisor=true
USDT: __TEXT,__dof_carrick present
ad-hoc signing identity: .tmp.83334
```

The regression was the design's total-Editor revision being enforced on a
bootstrap stage-1 edit before that not-yet-published MM could acquire its
Editor exclusion. `b324a2fda` lets an unpublished MM acquire that exact
bootstrap exclusion and replaces thread-local proof with a process-visible,
exact-MM owned capability. It also closes the review findings found while
attributing the failure: real transaction-bound guest descriptor preimages,
exact-MM whole-inventory receipts, non-optional COW receipts, and total replay
predecessor handling. `b2a944d85` then propagates an exact-MM bind refusal as
`TrapError` through both engine layers instead of growing carrier-fatal
authority; `6c8b805bd` closes the feature-gated production harness caller.

Portable verification on `6c8b805bd`:

- focused exact-MM deferred-owner witness: 1 passed;
- metadata-retirement population: 17 passed;
- `carrick-vmm-hvf --lib --no-run`: passed;
- `just fmt-check`, `just clippy`, `just clippy-linux`, and
  `just lint-domains`: passed (1,222 authority counters);
- `just test-kernel`: passed, including 2,638 kernel tests and all
  kernel-semantics targets;
- normal EL1 image: 1,053,104 / 1,572,864 bytes, maximum checked stack
  11,503 / 12,288 (`native wait copy`);
- all-target clippy EL1 image: 1,081,920 / 1,572,864 bytes, maximum checked
  stack 12,015 / 12,288 (`signal terminal exit`).

No signed run was made after the source change. The requested 20/20 proof and
companions require an exact bundle for the new evidence head.

## Stage-1-first retirement candidate (2026-10-25)

The current candidate supersedes the producer-by-producer corrections recorded
later in this file. It makes the problematic state unrepresentable: a carrier
stage-2 retirement request requires a non-cloneable `Stage1Unpublished`
witness. Ordinary mapping retirement mints that witness only at its Editor
release boundary. Whole-MM exit and exec first close and retire the MM's
published stage-1 entry, then carry `Stage1UnpublishedMm` through detached
inventory cleanup. The predecessor carrier-MM authority remains retained until
that proof arrives, so exec replacement cannot drop it early.

Host copy now has three outcomes after SELECT: an advanced Editor revision
reselects immediately, a held Editor parks on its guaranteed release, and an
unchanged/free Editor with a current leaf records
`STAGE2_AUTHORITY_INVARIANT` and SIGKILLs only that MM. It never fabricates
`EFAULT` for a valid buffer and never aborts the carrier. Stage-2 publication
and rollback use one RAII publication guard. Terminal retirement refusal keeps
the physical extent quarantined; overlapping stage-2 registration is rejected
with `ExtentCollision`.

The VM-free production-path proof covers the issue's ten requested shapes:

1. `serial_host_editor_release_after_select_reselects_without_stranding`
   advances the Editor after SELECT and completes through immediate reselect.
2. The owner-wait population parks with an Editor held, enrolls before probing,
   and wakes whether release wins before or after enrollment. The typed whole-MM
   ordering witness confirms that Editor publication/source retirement precede
   the first global-frame free operation.
3. `stage2_publication_commit_guard_wakes_valid_leaf_and_rebinds_successor` and
   `stage2_publication_rollback_guard_wakes_enrolled_copy` cover both RAII
   outcomes.
4. The commit witness retains the inserted successor without another park.
5. The existing two-live-thread IPC owner-wait cancellation witness drives
   process exit while a sibling copy is parked; the executor ordering witness
   drives exec cleanup through the same typed unpublication crossing.
6. `terminal_stage2_retirement_is_invisible_and_quarantines_ipa` proves the
   copy cannot retain the refused record and the IPA cannot be registered
   again.
7. `retirement_request_signature_requires_stage1_unpublished_witness` fixes
   the request signature at compile time.
8. `serial_host_unchanged_selection_without_stage2_authority_kills_only_its_mm`
   drives the production park consumer and observes MM-local SIGKILL handling.
9. `two_mms_reselect_without_accumulating_retirement_state` drives 256
   selections across two MMs and observes no copy-side retirement state.
10. `host_read_retains_pooled_frame_across_concurrent_munmap` and the bounded
    production IPC owner-wait/executor witnesses cover the munmap/read and
    exhausted-capacity halves: the admitted copy either completes or follows
    its guest fault path, without losing its retained frame or polling.

There is deliberately no `OwedStage1Rewrite` token in the terminal witness.
The terminal record itself is the carrier quarantine: it remains in the
physical extent index, rejects reuse, and is invisible to correct copies after
stage-1 unpublication.

Portable verification on the stage-1-first candidate:

- the focused production-path witnesses listed above passed;
- `just fmt-check`, `just clippy`, `just clippy-linux`, `just lint-domains`,
  and `just test-kernel` passed;
- the normal EL1 image loads 1,053,104 of 1,572,864 bytes and its maximum
  checked stack is 11,503 of 12,288 bytes (`native wait copy`);
- the all-target EL1 image loads 1,077,712 of 1,572,864 bytes and its maximum
  checked stack is 11,951 of 12,288 bytes (`signal terminal exit`).

The exact candidate SHA is recorded in the worker handoff. No new signed run
was made because this source needs an exact fixture bundle; the requested
20/20 hardware proof remains the next step.

This receipt records the final cloudmac/HVF proof for PR #855 at source
`6c45f14f90cb22c5f1279fb0ab92b433c61f45f3`. The exact fixture archive was:

```text
/Volumes/carrick-build/fixtures/published/6c45f14f90cb22c5f1279fb0ab92b433c61f45f3/0433bf8b71d3b9322075f45100a4387ce048ccbb59675a513dd401a487d574f4.tar.gz
```

`just fixtures-verify` and `just fixtures-restore` both passed. The bundle
contained 1,195 executables, its input identity was
`51121dd5bd4ec2eec8fe50e254d8bfc363a302fe3c0a61f54b14fbf6d70c7e25`,
and its archive SHA-256 was
`879d123f4bd670a5f93c3bd39669d98178c7254e85361a619f772ec5b1c59e80`.

## Result

`el1_sched_host_blocked_read_resumes_by_guest_scheduling` completed all ten
requested repetitions without reproducing the #847 watchdog hang:

- Passed: `847-final-hostread-01` through `-05`, and `-07` through `-10`
  (9/10).
- Failed quickly: `847-final-hostread-06` (1/10). It exited in 1.42 seconds,
  signal `None`, after the guest reported
  `read(fd=5) iter=427 rc=-1 errno=14`; stdout was
  `sock-pingpong failed at 427`. This run emitted no watchdog census and no
  Carrick fatal.
- Hangs/watchdogs: 0/10.

## Run 06 EFAULT attribution and correction

The failed run exited normally, so it produced no watchdog census or event-ring
post-mortem. The only guest failure is the durable valid-buffer receipt
`read(fd=5) iter=427 rc=-1 errno=14` quoted above. The source path was exact:
physical retention reported a stale selected leaf as an Editor wait, the
editor revision was current while the editor word was free, and
`OwnerMemoryPark::NoProducer` fabricated `EFAULT` without asking EL1 to select
the guest address again. Thus a completed edit or transient stage-2
replacement could be mistaken for an unmapped guest VMA.

The VM-free production witness
`serial_host_stale_selection_without_editor_reselects_and_parks_on_physical_producer`
reproduced that path with a valid mapping. Red-first, the saved syscall
returned `EFAULT` immediately instead of blocking on the exact physical
producer. The correction gives a producer-free Editor observation one bounded
authoritative redispatch. EL1 selection now decides whether the guest address
is actually unmapped; a still-mapped address either completes against its
current leaf or returns an exact owner/physical producer. The witness then
parks without polling, wakes on physical-retirement completion, and commits
the copyout. The later publication-producer correction below replaces the
temporary repeated-receipt invariant error with a named producer.

Portable verification on the correction:

- focused witness: 1 passed;
- owner-wait population: 15 passed;
- serialized `carrick-runtime` library: 818 passed, 9 ignored;
- `just fmt-check`, `just lint-domains`, `just clippy`, and
  `just clippy-linux`: passed;
- `just test-kernel`: passed.

The required signed 20/20 proof must use the exact post-correction fixture
bundle and is intentionally deferred until that bundle is relayed.

## Stage-2 publication producer correction

Review of `ba1e7db9b` found that its bounded reselect still treated each new
Editor receipt as progress. SELECT itself advances that receipt, so a valid
stage-1 leaf whose stage-2 record stayed absent could synchronously cycle
through SELECT, stale selection, and producer-free redispatch forever.

The follow-up keeps the `kernel.memory.owner-wait` conformance contract:
Linux `read(2)` returns `EFAULT` only when the destination is inaccessible,
and a transient physical publication cannot become either EFAULT or executor
polling. Physical retention now distinguishes an absent record with no live
backing owner (authoritative EL1 reselect) from an absent or `NotMapped`
record whose live global-frame, structural, or carrier owner must publish a
successor. The latter returns an IPA-scoped physical wait. That wait enrolls
before probing and becomes ready only after the exact mapped record and its
backing-owner identity are both visible, or after the authority retires so
EL1 can reselect and deliver the real mapping fault. Registration, replay
rebind, VM terminalization, and retirement publish after their state locks
drop.

The red-first VM-free witness
`valid_leaf_with_absent_stage2_record_waits_for_physical_publication` first
failed because retention returned `StaleSelection`. Green, it holds a live
owner across a terminal record gap, proves that allocating the successor is
not yet readiness, enrolls the production physical wait, publishes the exact
successor owner, observes one wake, and retains the mapped bytes without
EFAULT. The existing
`serial_host_stale_selection_without_editor_reselects_and_parks_on_physical_producer`
witness drives the runtime park and wake. A separate receipt-churn witness
proves that neither new owner receipts nor physical-wait generations reset
the redrive budget: only committed bytes reset it; terminal dispatch results
leave the loop directly.

Portable verification on this follow-up:

- `carrick-vmm-hvf` library: 790 passed, 3 ignored;
- `carrick-runtime` library: 819 passed, 9 ignored;
- focused user-transfer population: 15 passed;
- focused owner-redrive population: 2 passed;
- `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, and `just test-kernel`: passed.

No signed test was run because the source changed. The exact-candidate fixture
bundle is required before the requested signed 20/20 proof.

## Removal publication and pending stage-1 rewrite correction

Review of `2efa83419` found two remaining producer gaps. First, readiness can
change when a global owner, structural backing, per-MM structural owner, or
carrier record is removed, but several removal sites did not publish the
stage-2 availability stream. This included cleanup of a dangling owner that
named an already missing record: readiness became true without waking an
enrolled waiter. All directory removals now go through shared helpers that
publish only after their directory lock drops. Terminal record removal uses a
scoped removal owner whose drop releases the record lock before publishing, so
the pin-release and terminal-release paths cannot omit the wake.

Second, a valid stage-1 leaf may outlive retirement of its stage-2 authority
until the promised stage-1 rewrite publishes. An authoritative reselect can
therefore observe the same producer-free Editor cause while the editor word is
momentarily free. The first such observation still performs the authoritative
reselect. A second observation for the same MM and cause now names the pending
stage-1 rewrite and parks on that exact MM's Editor publication stream. It no
longer returns a carrier error, and receipt churn still does not count as
forward progress.

Red-first evidence:

- `removing_dangling_stage2_authority_wakes_publication_wait` observed the
  waiter become ready after direct removal but received zero callbacks; it now
  receives exactly one wake through the shared removal helper.
- `serial_host_stale_selection_without_editor_parks_on_pending_stage1_rewrite`
  reached
  `Runtime(Configuration("authoritative owner reselect repeated without a producer"))`;
  it now parks the production continuation, wakes when a real editor publishes,
  and completes the saved copyout.
- `owner_redrive_receipt_churn_names_the_pending_stage1_rewrite` proves a new
  Editor receipt for the same MM cannot disguise the owed rewrite producer or
  reset the stalled-pass accounting.

Portable verification on the final tree:

- focused production park/wake, receipt-churn, and authority-removal
  witnesses: 1 passed each;
- serialized `carrick-vmm-hvf` library: 791 passed, 3 ignored;
- serialized `carrick-runtime` library: 819 passed, 9 ignored;
- `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, and `just test-kernel`: passed.

No signed test was run because this correction changes source. The requested
20/20 hardware proof remains gated on its exact-candidate fixture bundle.

The first companion `el1_ipc_two_processes_blocking` repetition,
`847-final-two-process-01`, hit its 60-second watchdog. Per the director's
stop condition, the remaining two repetitions and all requested
`el1_sched_pipe_pingpong_stays_in_guest` and
`el1_ipc_pipe_blocking_roundtrips` repetitions were not run. Every completed
outer run was followed by `scripts/sudo/kill.sh <run-id>` and reported zero
remaining scoped processes.

This two-process watchdog is recorded only as companion evidence. The director
also reproduced its missing-second-process shape on main and explicitly moved
it out of this fix's scope.

## Signed executable identities

The signing harness re-signs the test executable on every invocation, so its
SHA-256 and CDHash legitimately differ by run. The LC_UUID remained
`FD63A5AE-28A7-3A89-9947-6841B09A8B0D` throughout.

| run ID | SHA-256 | CDHash |
|---|---|---|
| `847-final-hostread-01` | `f945603f48d7f13d27c51b4907b745b451dee1606babc09b11652284e4cfcc65` | `df08ce88cc078da0df0baddec7a0fad36e3b2431` |
| `847-final-hostread-02` | `b9416418518d491c0c5b5751a838bda6e1c6803ffcb0eaafe90ddf7bda90a587` | `1417903cc26ed701a73a3066736831fb58fda8a7` |
| `847-final-hostread-03` | `f94a1d4c92143f34612e0e4a525a3f84009bd5dcd4131308e1fadacfb95da157` | `30c6b444d6b124a3e0e88a7aa2d0431527db2aaf` |
| `847-final-hostread-04` | `63645534d513711943bc224f6b4d13307fd0c9478c65ae430145c39a5d64fec2` | `f880ced6a43abd654e2a7e0ac7be8fc980fdc124` |
| `847-final-hostread-05` | `c637a66fee8de55551edd06764b69b838572ea095de2bf1124a4facd523e7f5d` | `5c42ad9d8a4a7bf85ae4622de351004ff59ece37` |
| `847-final-hostread-06` | `45d25e9d43ed739e312a6807f80bd62a9b1dbe62e80a1fc81ee3b6be5eb1f37c` | `94e40a2d9d639c2582da0557f4bb4516cdd571e7` |
| `847-final-hostread-07` | `c12010432e06171237c07efc3de90712a57ccf7209238a122ccb511ee4f24204` | `74c6b642ad0ed985363b43e33e076a462ec0f218` |
| `847-final-hostread-08` | `e10559479b1082017b4f00c15f076d87ff66f17c8a63e78e85a9aa7d7e4d23e5` | `9a452eea16c675c5a6e61a6d64ac9ceba1a7cd68` |
| `847-final-hostread-09` | `c24a56270aa84d71f3e267a8f56590c5951289ddb6ca7964c0a5e9d4c91e37b6` | `737304ed6603bd5575b16dc4c16a43448bb5d1a0` |
| `847-final-hostread-10` | `c480ecc27f77ef9a9b3d292f002ef23f717e685391d61cec907ab1d27faaaff9` | `393f270591f1746520de3e2c2b4d870415a23811` |
| `847-final-two-process-01` | `6f083241659df7d8c7a9d02f9bd98ff94318014c9f5771d631f0e101ea515413` | `6bed03750b623f95c1488e2982e7c72f7bb2d8fc` |

## Watchdog census (verbatim)

```text
test el1_ipc_two_processes_blocking ... WATCHDOG: timeout (60s) exceeded for CARRICK_RUN_ID=847-final-two-process-01-b1; reaping with scripts/sudo/kill.sh
WATCHDOG zone census:
zone slot 0: state=IdleWfi driver=2 away=false mm=0 installed=0 cpu+1=1 current=0 host_record=0 len=0 queue=[] resched=0 timer_cval=0
zone slot 1: state=IdleWfi driver=3 away=false mm=0 installed=0 cpu+1=2 current=0 host_record=0 len=0 queue=[] resched=0 timer_cval=0
zone slot 2: state=IdleWfi driver=4 away=false mm=0 installed=0 cpu+1=3 current=0 host_record=0 len=0 queue=[] resched=0 timer_cval=0
zone slot 3: state=IdleWfi driver=5 away=false mm=0 installed=0 cpu+1=4 current=0 host_record=0 len=0 queue=[] resched=0 timer_cval=0
zone counters: el1_wakes=28 host_wakes=0 el1_parks=30 host_parks=0 switches=29 steals=14 service_exits=0 host_service_placements=0 host_ready_placements=0 resched_kicks=0 service_adoptions=0 exit_adoptions=0 host_handbacks=0 lost_adoptions=0 stale_services=0 held_refusals=0 host_queue_claims=2 host_executor_parks=0 host_queue_takes=0 foreign_adoptions=0
zone spaces: idle_ttbr=0x2d001f8000 el1_space_switches=29 el1_space_refusals=0 el1_cow_invalidations=0
zone space 1: mm=1 gate=0x0
zone record 3: claim=Parked { seq: 1 } handback=None tid=1 serial=2 mm=1 gen=1 home=None last_slot=None wanted=false cancelled=false entries=1 deadline=None
zone record 3 owner: incarnation=1 resume=UserReturn lifecycle_page=0x2d08080000 control_slot=0x2d08087d80
zone record 3 parked: first_wait_mm=1 first_wait_address=0x6000208ad0 resume=UserReturn saved_pc=0x2a5a00
zone record 4: claim=Parked { seq: 1 } handback=None tid=2 serial=5 mm=1 gen=1 home=None last_slot=None wanted=false cancelled=false entries=0 deadline=None
zone record 4 owner: incarnation=1 resume=UserReturn lifecycle_page=0x2d08080000 control_slot=0x2d08087c00
zone record 4 parked: wait_key_and_pc=unavailable-busy-or-changed-or-unlinked
zone record 4 object wait: queue=3 generation=1 operation=1:2
zone object queue 3: generation=1 epoch=1 head=4 tail=4 waiters=1 locked=false
ipc object 1 (queue 3 Readable): kind=pipe generation=0 read_seq=0 write_seq=0 host_subscribers=0 host_wake_owed=0 unread=0 capacity=65536 readers=1 writers=1
ipc host-wake index: owed_without_target=0 summary=0x0
reservation root 1: mm=1 lock_word=0x8000000000000000 notification_required=true holder=None
```

The runner wrote the durable post-mortem to
`target/embed-post-mortem/847-final-two-process-01-b1`; the relevant census is
quoted verbatim above so the diagnosis does not depend on a temporary copy.

## Structural owed stage-1 rewrite producer

Review of `c7b097f36` found that the runtime's inferred
`PendingStage1Rewrite` wait still depended on a comment-only promise. Two
producer-free Editor passes could park on a free Editor word even when no
retirement transaction owed a later stage-1 publication, recreating the
original lost-wake shape.

The stage-2 retirement crossing now creates a typed, generation-bearing
`OwedStage1Rewrite` entry before it removes backend authority. The entry is
scoped to the retired IPA range and the exact carrier-record incarnation.
Host retention can obtain a physical wait only from an entry that covers its
selected IPA. The wait subscribes before probing. A successful stage-1 editor
release re-reads the authoritative translation and completes only waits whose
old VA-to-IPA selection was rewritten or unmapped. Failed retirement rolls
the entry back, while terminal retirement retains it until MM teardown; entry
drop publishes every remaining waiter. The runtime's coarse two-pass
inference and forced-true Editor predicate are removed.

VM-free production witnesses:

- `production_retirement_waits_for_owed_stage1_rewrite_commit` drives the
  shared stage-2 backend-retirement crossing, retains through the production
  transfer consumer at a sub-16-KiB VA offset, parks on the exact obligation,
  and observes one wake when a real stage-1 unmap commits.
- `terminal_retirement_owed_rewrite_wakes_at_mm_teardown` drives terminal
  retirement, parks the production transfer consumer on the retained
  obligation, and observes its exact teardown publication.

Portable verification on this follow-up:

- focused production retirement/rewrite and terminal teardown witnesses:
  1 passed each;
- serialized `carrick-vmm-hvf` library: 793 passed, 3 ignored;
- serialized `carrick-runtime` library: 818 passed, 9 ignored;
- `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, and `just test-kernel`: passed;
- EL1 clippy image: 1,077,712 bytes loaded; maximum checked stack 11,951 of
  12,288 bytes (`signal terminal exit`).

No signed test was run because this correction changes source. The exact
candidate bundle is required before the requested signed 20/20 proof.

## Owed-rewrite simplification after review of `0d9d7861c`

The private stage-1 publication observer and per-obligation physical wait are
gone. An owed rewrite now uses the MM's existing Editor publication queue.
Retention returns a typed `PendingStage1Rewrite` only when the exact selected
IPA is covered by a live retirement obligation; after the Editor wake, the
next authoritative SELECT settles obligations against the live stage-1 image.
An obligation is removed once every live `(VA, IPA)` selection it covered no
longer translates to that IPA, so settlement work is O(live obligations), not
O(all historical retirements).

`RetryPending` no longer rolls the obligation back. The witness
`retry_pending_and_terminal_retirement_keep_the_owed_rewrite_token` directly
asserts that the MM has exactly one token after the backend returns
`RetryPending`, still has exactly one token after terminalization, and that
production retention returns `PendingStage1Rewrite`. MM teardown then owns
disposal of that terminal token. The success witness performs a real
retirement, observes the pending token, commits a sub-16-KiB-offset stage-1
unmap, settles through the production custody hook, and asserts the token
count falls from one to zero; a later retention is the typed guest mapping
fault rather than a stale wait.

The owner-resume pass limit is now only a release-build guest-fault guard for
the typed-impossible producer-free state. It has a debug assertion and returns
guest `EFAULT` for that syscall; it never produces a carrier `RuntimeError`.

Portable verification on this correction:

- focused retirement success, RetryPending/terminal-token, production Editor
  park/wake, typed mapping-fault, redrive guard, retained ChildTid, and stale
  physical-producer witnesses: pass;
- serialized `carrick-vmm-hvf` library: 793 passed, 3 ignored;
- serialized `carrick-runtime` library: 820 passed, 9 ignored;
- `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, and `just test-kernel`: pass;
- normal EL1 image: 1,053,152 / 1,572,864 bytes; maximum checked stack
  11,503 / 12,288 bytes (`native wait copy`);
- all-target clippy EL1 image: 1,077,744 / 1,572,864 bytes; maximum checked
  stack 12,015 / 12,288 bytes (`signal terminal exit`).

This correction changes the EL1 ABI layout hash. No signed test was run; an
exact-candidate fixture bundle is required for the signed 20/20 proof.

## Stage-1-first retirement proof correction after `a5d9b1682`

The stage-2 retirement capability is no longer minted from an IPA identity.
The exact record witness is private to carrier custody and can be derived only
from a completed stage-1 editor receipt, the whole-MM inventory drain, an
unpublished inventory rollback, or the typed EL1 metadata teardown. Final
record request, unmap, terminal removal, and global-frame retirement all
require that witness. Whole-MM exit and exec publish their stage-1 drain before
the detached stage-2 inventory becomes eligible, while publication rollback
uses the still-unpublished inventory transaction.

Host copies also revalidate a sampled leaf against the authoritative stage-1
table before reporting `Stage2AuthorityInvariant`. A host-side replacement or
unmap therefore reselects immediately; closing an MM reads as an Editor change.
The record directory now maintains a `BTreeMap` extent index and checks only
the predecessor and successor on registration. Stage-2 publication/removal is
owned by an RAII guard which publishes after its directory lock drops, including
rollback. A refused terminal retirement remains indexed as quarantine and its
IPA cannot be reissued.

Exactly four tests were newly added in this correction:

- `serial_host_mm_exit_close_races_a_parked_sibling_copy_without_invariant_kill`
  drives the shared exit/exec MM-close path while a sibling host copy is parked;
- `serial_host_munmap_retirement_races_blocking_read_with_one_executor` drives
  the production owner-memory park with one executor;
- `host_stage1_unmap_of_selected_leaf_forces_ready_reselect` removes a selected
  leaf through the production stage-1 authority and proves ready reselection;
- `stage2_extent_index_checks_only_adjacent_intervals` proves neighbour-only
  overlap admission.

Two pre-existing tests were materially strengthened, not counted as new:

- `two_mms_by_n_real_retirements_leave_no_custody_growth` now performs 64 real
  stage-1 unmaps and typed stage-2 retirements across two MMs and checks the
  directory returns to its baseline size;
- `serial_host_global_owner_collision_refuses_before_custody_transfer` now
  asserts interval collision is refused before backend custody or rollback.

Fresh portable verification:

- the six focused filters above: 6 passed, 0 failed;
- `just fmt-check`, `just clippy`, `just clippy-linux`, and
  `just lint-domains`: passed;
- `just test-kernel`: passed (EL1 ABI 147/147, FD core 54/54,
  kernel 2,638 passed with one ignored, and every kernel-semantics target
  completed without a failure);
- default EL1 image: 1,053,104 / 1,572,864 bytes; maximum checked stack
  11,503 / 12,288 bytes (`native wait copy`);
- allocator-test-control EL1 image: 1,057,296 / 1,572,864 bytes; maximum
  checked stack 11,503 / 12,288 bytes (`native wait copy`);
- all-target clippy EL1 image: 1,077,712 / 1,572,864 bytes; maximum checked
  stack 11,951 / 12,288 bytes (`signal terminal exit`).

No signed test was run because this correction changes source and therefore
requires an exact-candidate fixture bundle.

## Exact `3e5abed72` bootstrap smoke and stage-1 edit audit

The exact `3e5abed72a8e9e3c2cc0abf8af68f7fbd0b88b4c` fixture bundle verified
and restored 1,195 executables. Signed run `847-3e5-smoke-02` reached HVF but
failed before the workload in 0.11 seconds:

```text
configuration refused: exclude root EL1 Editor before HVPatch ASID setup
```

There was no watchdog census, EFAULT, or carrier fatal. The signed harness's
negative entitlement control passed and run-scoped cleanup reported zero
remaining Carrick processes. (`847-3e5-smoke-01` never ran a guest: the 20 GiB
disk guard rejected its prerequisite build while 13 GiB was free.)

The root cause was policy/authority confusion in
`mm_occupancy::exclude_el1_editor`: it consulted `el1_zone::zone()`, which is
deliberately unavailable until guest scheduling is enabled, even though the
raw EL1 address-space table and its unpublished Editor proof already exist.
Editor exclusion and revision publication now use the raw installed zone
table, so bootstrap edits are licensed and their guard remains live until that
exact table is removed.

The same change audited every production `Stage1Authority::edit*` caller:

- the shared AArch64 live-edit funnel (`engine.rs`) receives the exact-MM
  `Stage1EditLicense` and passes it to both `edit` and `edit_unpublishing`;
- retained COW and COW replacement (`cow_engine.rs`) obtain the exact MM's
  exclusion before every edit, rollback, commit, and unpublishing edit;
- sparse materialisation/import (`sparse_materialization.rs`) does the same
  for publication, rollback, commit, journal begin, and final mapping;
- carrier bootstrap and arena setup reach those funnels only after acquiring
  the root MM exclusion; and
- the remaining direct calls are VM-free/test-support witnesses, each with an
  explicit ring `SpaceEditor` or exact-MM host license.

The focused `carrick-kernel` MM-occupancy population passed (21/21). A new
signed bundle is required before retrying the smoke or the requested 20-run
population.

## Total Editor order and consume-once retirement ownership

The implementation now follows the stage-1-first design recorded on issue
[#847](https://github.com/carrick-sh/carrick/issues/847) rather than deriving
stage-2 retirement authority from a cached absence observation. Host stage-1
edits require an exact edit license, mint `Stage1LeafRetired` only inside
`edit_unpublishing`, and publish the Editor revision before lowering host
exclusion. `InventoryFrameRegistry` alone converts a receipt naming the lease
into the non-cloneable `Stage1Unpublished` proof at the zero-reference
crossing. Pending retirement owns that proof until one exact claimant consumes
it or returns it unfinished.

Publication and rollback are one RAII transaction.
`Stage2PublicationAuthority::rollback` consumes the guard and yields the exact
`NeverPublishedRecord`; commit, rollback, record removal, and rebind publish
after their directory locks drop. Terminal refused retirements remain indexed
as quarantine and their IPA cannot be issued again. A malformed exclusive
retirement claim is handled as a typed local error rather than introducing a
new carrier-fatal authority cohort.

The thirteen design acceptance items are covered as follows:

1. `edit_unpublishing_binds_retired_leaf_to_old_ipa_and_image` checks the
   exact old `(VA, IPA)` receipt, including repointing.
2. `reference_ledger_mints_only_at_zero_for_a_receipt_naming_the_lease` and
   `two_mms_by_n_real_retirements_leave_no_custody_growth` exercise the real
   zero crossing and multi-MM cleanup.
3. `.semgrep/typed-domains.yml` permanently rejects every deleted derived
   proof/reselect spelling from DESIGN section 7.
4. `host_edit_release_advances_editor_before_lowering_gate` and
   `serial_host_editor_release_after_select_reselects_without_stranding`
   cover the total Editor order and production owner park.
5. The `carrick-aarch64` compile-fail doctest rejects an edit without a
   `Stage1EditLicense`.
6. `every_cause_refuses_release_before_enrollment_and_ignores_other_causes`
   and `release_after_enrollment_reprobes_before_park_for_every_cause` cover
   release-before-enrolment and release-after-enrolment.
7. `stage2_publication_commit_guard_wakes_valid_leaf_and_rebinds_successor`
   and `stage2_publication_rollback_guard_wakes_enrolled_copy` cover both RAII
   exits and rollback proof consumption.
8. The commit-guard successor test plus
   `replacement_completion_and_rollback_touch_the_right_owner` require rebind
   to consume the predecessor proof before the successor is retained.
9. `serial_host_mm_exit_close_races_a_parked_sibling_copy_without_invariant_kill`
   drives the common exit/exec terminal-close publication path with two live
   threads.
10. `serial_host_unchanged_selection_without_stage2_authority_kills_only_its_mm`
    checks the event-ring invariant record, exact-MM SIGKILL, and surviving
    carrier/sibling MM.
11. `serial_host_munmap_retirement_races_blocking_read_with_one_executor`
    drives the production blocking-read park through a real host munmap with
    executor capacity exhausted.
12. `terminal_stage2_retirement_is_invisible_and_quarantines_ipa` checks
    terminal invisibility and `ExtentCollision` on reuse.
13. `carrier_lease_batch_collision_publishes_nothing_and_retains_every_candidate`,
    `directory_failpoint_rolls_back_inventory_before_final_carrier_drop`, and
    the two replacement tests cover typed rollback failures without a silent
    proof-less skip.

Five test functions are entirely new relative to `a932c5ddc`:

- `edit_unpublishing_binds_retired_leaf_to_old_ipa_and_image`;
- `a_revision_change_buys_exactly_one_reselect`;
- `host_edit_release_advances_editor_before_lowering_gate`;
- `reference_ledger_mints_only_at_zero_for_a_receipt_naming_the_lease`;
- `pending_retirement_owns_one_proof_and_returns_an_unfinished_claim`.

The other acceptance witnesses above are strengthened pre-existing tests and
are not counted as new. In particular,
`bounded_idle_retry_rotates_past_persistent_prefix_and_services_detached_work`
now proves that the generic carrier sweep cannot steal an exact directory
claim after a backend refusal.

Portable verification:

- all thirteen focused design filters passed on `af62078db`; after the final
  fallible-claim change,
  `pending_retirement_owns_one_proof_and_returns_an_unfinished_claim` and
  `bounded_idle_retry_rotates_past_persistent_prefix_and_services_detached_work`
  passed again on `8aab9a297`;
- on `8aab9a297`, `just fmt-check`, `just clippy`, `just clippy-linux`,
  `just lint-domains`, and `just test-kernel` passed;
- default EL1 image: 1,053,104 / 1,572,864 bytes; maximum checked stack
  11,503 / 12,288 bytes (`native wait copy`);
- allocator-test-control EL1 image: 1,057,296 / 1,572,864 bytes; maximum
  checked stack 11,503 / 12,288 bytes (`native wait copy`);
- all-target clippy EL1 image: 1,081,920 / 1,572,864 bytes; maximum checked
  stack 12,015 / 12,288 bytes (`signal terminal exit`).

A diagnostic full `carrick-vmm-hvf --lib` run is not green: older foreign-COW
fixtures such as
`concurrent_foreign_cow_from_same_snapshot_allows_exactly_one_commit` and
`host_retained_reuse_repoints_through_the_host_editor` call host edits from
spawned threads without the now-required thread-bound Editor exclusion. The
design acceptance filters and requested portable gates are green, but this
broad-suite fixture migration remains explicit rather than being reported as
a pass.

No signed test was run on this source. Its exact fixture bundle is required
before the signed 20/20 proof and companion matrix.

## Exact stage-1 and rollback proofs after review of `055bf2354`

Editor retirement receipts now carry the exact VA-to-IPA translations removed
by their edit. Converting one into a stage-2 retirement witness checks that the
record's IPA occurs in that receipt; whole-arena retirement likewise checks the
retired physical bases. The proof and whole-MM inventory drain are consume-once
types. Tests obtain Editor receipts by performing real stage-1 unmaps.

The caller-constructed `AuthoritativeAbsence` escape hatch is gone. Frame-COW
and alias retirement use the kernel frame authority's VM-wide reverse-map
population. The shared COW inventory commit performs that check at the final
retirement point: if a racing fork peer still maps the frame, the carrier keeps
stage-2 authority instead of retiring it or aborting. The serialized HVF suite's
`concurrent_foreign_cow_from_same_snapshot_allows_exactly_one_commit` test
exercised this case with one remaining mapping.

Records which never reached stage 1 carry a typed `NeverPublishedRecord` from
registration through the exact publication transaction. Rollback consumes only
that transaction's receipts, so it cannot skip retirement or accidentally retry
an unrelated historical owner. Host retention treats a missing host-side table
view as unknown, not as a ready reselect, and permits only one reselect for a
given Editor revision.

Exactly two tests are new relative to `055bf2354`:

- `editor_receipt_cannot_retire_a_record_outside_its_removed_ipa_range`;
- `absent_host_stage1_view_is_unknown_not_ready_reselect`.

The review also materially strengthened or renamed these production-path
witnesses (they are not counted as new):

- `host_stage1_unmap_allows_one_reselect_per_host_edit_revision`;
- `serial_host_munmap_retirement_races_blocking_read_with_one_executor`;
- `serial_host_mm_exit_close_races_a_parked_sibling_copy_without_invariant_kill`;
- `two_mms_by_n_real_retirements_leave_no_custody_growth`;
- `serial_host_global_owner_collision_refuses_before_custody_transfer`;
- `serial_host_foreign_mm_failure_injection_at_composition_boundaries`;
- `concurrent_foreign_cow_from_same_snapshot_allows_exactly_one_commit`;
- the three `stage2_backend::ipc_window_tests` rollback/publication cases.

Fresh portable verification:

- serialized `carrick-vmm-hvf` library: 798 passed, 3 ignored;
- both production owner-park witnesses above: 1 passed each;
- `just test-kernel`: passed (kernel 2,638 passed with one ignored and every
  kernel-semantics target completed without a failure);
- `just fmt-check`, `just clippy`, `just clippy-linux`, and
  `just lint-domains`: passed;
- default EL1 image: 1,053,104 / 1,572,864 bytes; maximum checked stack
  11,503 / 12,288 bytes (`native wait copy`);
- allocator-test-control EL1 image: 1,057,296 / 1,572,864 bytes; maximum
  checked stack 11,503 / 12,288 bytes (`native wait copy`);
- all-target clippy EL1 image: 1,077,712 / 1,572,864 bytes; maximum checked
  stack 11,951 / 12,288 bytes (`signal terminal exit`).

No signed test was run because this correction changes source and therefore
requires an exact-candidate fixture bundle.
