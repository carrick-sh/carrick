# #1733 native fork witness triage, round 2 (2026-11-08)

Initial base: GitHub main `ac592c4b4`; rebased onto `c077f336f` before
reporting. Salvage: `fb9c9cd132`. The dropped-fixture observations below were
made on the initial base; the retained x86 red result was repeated after the
rebase with the same values. This is witness work only;
no kernel implementation changed. One VM-free x86 test now establishes that a
parent's first write to an inherited `PREPARED|COW` page is refused after its
forked child writes, exits, and is reaped by `wait4`. It does not establish
that the child's retirement caused the refusal or that CPython uses this path.

The CPL0 retirement experiment calls production `release_retired_child` on
synthetic child MMs. The pool remains full of their READY COW grants and fails
to publish at cycle 1017. The production CPL0 reclaim path calls that helper
without a matching `CowGrantPool::release_mm` call. This is evidence of a
separate grant-pool leak. The experiment does not fork a child, drive a child
COW write through fault supply, or show the child's retirement changing its
parent's memory. It therefore fails this round's explicit retention rule and
was removed. A future witness for the leak must exercise native fork, fault
supply, and the production reclaim entry before attributing a guest symptom.

| ISA / salvaged witness | Round-2 observation | Classification and disposition |
| --- | --- | --- |
| ARM `arm_fork_splits_2mib_private_block_into_cow_armed_l3_leaves` | Red: `copy_table` left parent L2 entry `0x60000008000fc1`, not an L3 table. | **(a)** Synthetic L2 block and direct inner-helper call. Production anonymous grants descend to L3 leaves; no production fork entry. Dropped. |
| ARM `serial_host_native_fork_coarse_2mib_private_block_splits_and_isolates_across_child_exit_wait4` | Red: child block write returned `Refused` after the base write resolved. | **(a)** Fixture installs a private L2 block by hand after `mmap`; production anonymous grant preparation descends to L3. The COW classifier accepts an L3 leaf, so the refusal is expected for the synthetic block. Dropped. |
| ARM `serial_host_native_fork_base_and_variants_isolate_parent_across_child_write_exit_wait4` | Original red: child write `0x40215000` returned `Refused`; diagnostic outcome was `Declined(Unmapped)` at the synthetic L2 block. Replacing it with an L3 anonymous grant let the child complete writes and exit. Inventory-backed COW grants removed the retirement receipt mismatch. The fixture then returned `Stale` on parent `wait4`, before any parent read. | **(a)** Original red came from the synthetic block; the repaired fixture still lacks a valid host-owned parent return after child exit. Its attempted scheduler switch found no queued parent record. No parent-state verdict; dropped. |
| x86 `write_publish_of_cow_armed_prepared_leaf_commits_read_only_cow_leaf` | Red: `DescriptorOp::Publish` for sibling frame `0x9000` did not return `Applied`. | **(a)** Direct descriptor-helper test; no native fork, fault supply, or retirement entry. Dropped. |
| x86 CPL0 `retired_fork_children_release_cow_pool_grants_across_pool_capacity` | Initial compile errors: stale module path and zone APIs. After fixture repair, red at cycle 1017: `COW grant pool exhausted at fork/exit cycle 1017: retired children leaked grants`. | **(b), separate resource leak.** Production `release_retired_child` does not return READY COW grants, but the test calls that helper with synthetic children. It proves none of the three allowed guest-visible outcomes. Dropped. |
| x86 `serial_host_x86_native_fork_base_and_2mib_pde_isolate_parent_across_child_write_exit_wait4` | Red: child write `0x50609000`, `present=true`, PTE `0x8010000010400c85`, returned `(Forward, Unavailable)`. Replacing the hand-installed huge PDE with a 4 KiB grant reached `wait4`, which returned `-14` on its unprepared status-page copy. | **(a)** The huge PDE was manually installed after reservation, whereas production anonymous grants use 4 KiB leaves. The `-14` was a fixture copy fault, not fork admission. This test was dropped; its distinct huge-PDE claim remains unproven. |
| x86 `serial_host_x86_native_fork_post_fork_first_touch_and_cow_refill_across_child_exit_wait4` | Original `-14` was **`wait4`**, not fork. The child had already written and exited; the fixture's direct status copy encountered a COW-protected page. Pre-faulting that page through production fault supply let `wait4` reap PID `2`. A later parent first-write to inherited sibling `0x60001000` returned `(Forward, Unavailable)`, PTE `0x8010000010201e04`; descriptor `Publish` refused `PermissionDenied`. A temporary child first-write diagnostic produced the same result before exit. | **(b)** The inherited 4 KiB leaf is `PREPARED|COW|MAY_WRITE|USER` without `WRITE`. Production `X86PreparedResolver` uses the same descriptor `Publish` operation; it refuses a write to this COW-armed prepared leaf, while translation-fault dispatch does not take the COW write branch. The parent loses usable write mapping after child write, exit, and `wait4`. Kept, ignored for CI. |
| runtime `serial_host_cow_fault_settles_used_grants_before_engine_refill` | Initial `ThreadedEngine` API drift and `Result`/`Option` mismatch repaired locally. Then red: first production poll returned `Yielded`, `injected_signals=[]`, rather than reaching the claimed refill assertion. | **(a)** A single synthetic poll with a fake engine never reaches the native-fork child or parent COW path. Dropped. |

`el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation_on_any_thread`
(#1857) is signed HVF and cannot run in this Linux VM. Its source runs two
threads on separate vCPUs while another CPU changes their shared MM with
`mprotect` and `munmap`; it checks for stale translations. The kept x86 test
exercises the parent's prepared COW fault after child reaping, not cross-vCPU invalidation;
their shapes do not match.

## Evidence and limits

Raw logs are in `/tmp/1733-round2/` on this worker. Focused test invocations
used `timeout`, `CARGO_BUILD_JOBS=3`, and `-j 3`. The direct red diagnostic run
of the subsequently removed CPL0 test was:

```text
timeout 120 env CARGO_BUILD_JOBS=3 cargo test --locked -j 3 -p carrick-x86-cpl0-host --lib retired_fork_children_release_cow_pool_grants_across_pool_capacity -- --ignored --nocapture
```

The test exited 101 with the cycle-1017 assertion above. The kept ignored x86
test exits 101 after `wait4` with parent write `0x60001000`, PTE
`0x8010000010201e04`, and `(Forward, Unavailable)`. A temporary diagnostic
in the fixture observed `DescriptorOutcome::Refused(PermissionDenied)` on that
parent leaf, and the same refusal on the child leaf before exit; those
diagnostic assertions were removed from the kept test. The signed HVF test
and CPython reproducer remain unrun here. Neither this prepared-page fault nor
the separate COW pool leak has an established causal link to the CPython crash.

```text
timeout 180 env CARGO_BUILD_JOBS=3 cargo test --locked -j 3 -p carrick-x86 --test native_fork_cow serial_host_x86_native_fork_post_fork_first_touch_and_cow_refill_across_child_exit_wait4 -- --ignored --nocapture
```
