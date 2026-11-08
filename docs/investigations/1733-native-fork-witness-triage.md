# #1733 native fork witness triage, round 2 (2026-11-08)

Base: GitHub main `ac592c4b4`. Salvage: `fb9c9cd132`. This is witness work only;
no kernel implementation changed. None of these VM-free runs establishes that a
parent loses its value, page, or mapping after a child write, exit, and `wait4`,
or that a child COW write after a production native fork is refused.

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
| x86 `serial_host_x86_native_fork_base_and_2mib_pde_isolate_parent_across_child_write_exit_wait4` | Red: child write `0x50609000`, `present=true`, PTE `0x8010000010400c85`, returned `(Forward, Unavailable)`. Replacing the hand-installed huge PDE with an L3 grant moved the failure to fork `-14`. | **(a)** The huge PDE was manually installed after reservation, whereas anonymous grant preparation supplies 4 KiB leaves. The alternative did not produce a parent-state verdict. Dropped. |
| x86 `serial_host_x86_native_fork_post_fork_first_touch_and_cow_refill_across_child_exit_wait4` | Red: fork returned `-14`, expected PID `2`. Removing the fixture's unbacked reservation let fork proceed to the now-unreserved page, which returned `(Forward, PolicyDeclined)`. Using a full 2 MiB grant did not change `-14`. | **(a)** The fixture's manually completed unbacked mapping is the distinguishing setup; its fork admission was not shown equivalent to production `mmap` publication. No child COW or parent-state verdict. Dropped. |
| runtime `serial_host_cow_fault_settles_used_grants_before_engine_refill` | Initial `ThreadedEngine` API drift and `Result`/`Option` mismatch repaired locally. Then red: first production poll returned `Yielded`, `injected_signals=[]`, rather than reaching the claimed refill assertion. | **(a)** A single synthetic poll with a fake engine never reaches the native-fork child or parent COW path. Dropped. |

`el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation_on_any_thread`
(#1857) is signed HVF and cannot run in this Linux VM. Its source runs two
threads on separate vCPUs while another CPU changes their shared MM with
`mprotect` and `munmap`; it checks for stale translations. That cross-vCPU
translation shape matches none of the salvaged fork/retirement experiments.

## Evidence and limits

Raw logs are in `/tmp/1733-round2/` on this worker. Focused test invocations
used `timeout`, `CARGO_BUILD_JOBS=3`, and `-j 3`. The direct red diagnostic run
of the subsequently removed CPL0 test was:

```text
timeout 120 env CARGO_BUILD_JOBS=3 cargo test --locked -j 3 -p carrick-x86-cpl0-host --lib retired_fork_children_release_cow_pool_grants_across_pool_capacity -- --ignored --nocapture
```

The test exited 101 with the cycle-1017 assertion above. The signed HVF test,
CPython reproducer, and any end-to-end parent-after-`wait4` verdict remain
unrun here. The separate COW pool leak has no established causal link to the
CPython crash.
