# #1733 native fork witness triage (2026-11-08)

This round tested every witness salvaged in `fb9c9cd132`, rebased onto GitHub
main `ac592c4b4`. None establishes the proposed failure: a parent losing its
value, page, or mapping **after** a forked child writes, exits, and is reaped.
The salvaged test code was removed from this branch. No kernel fix was made.

| ISA / witness | Result and observed value | Why it was removed |
| --- | --- | --- |
| ARM `arm_fork_splits_2mib_private_block_into_cow_armed_l3_leaves` | Red: parent L2 entry was `0x60000008000fc1`, not an L3 table. | Geometry-level `copy_table` test; no native child exit or parent read. |
| ARM `serial_host_native_fork_coarse_2mib_private_block_splits_and_isolates_across_child_exit_wait4` | Red: child COW resolution was `Refused`, expected `Resolved` (`native_fault_supply_tests.rs:5810` on WIP). | Stops at the child's write, before exit, `wait4`, or parent-state check. |
| ARM `serial_host_native_fork_base_and_variants_isolate_parent_across_child_write_exit_wait4` | Red: child COW write at `0x40215000` was `Refused`, expected `Resolved` (`native_fault_supply_tests.rs:6234` on WIP). | Stops at the child's write, before the parent-state check. |
| x86 `write_publish_of_cow_armed_prepared_leaf_commits_read_only_cow_leaf` | Red: `DescriptorOp::Publish` for sibling frame `0x9000` did not return `Applied`. | Descriptor helper test; does not drive native fork or parent retirement. |
| x86 CPL0 `retired_fork_children_release_cow_pool_grants_across_pool_capacity` | Did not compile: `E0583`, module declaration sought `src/cow_retirement_tests.rs`, but the file was under `src/cpl0_anonymous/`. | Salvaged module-path error; no verdict on the intended behavior. |
| x86 `serial_host_x86_native_fork_base_and_2mib_pde_isolate_parent_across_child_write_exit_wait4` | Red: child write fault at `0x50609000` (`present=true`, PTE `0x8010000010400c85`) returned `(Forward, Unavailable)`. | Stops at the child's write, before exit and parent-state assertions. |
| x86 `serial_host_x86_native_fork_post_fork_first_touch_and_cow_refill_across_child_exit_wait4` | Red: native fork returned `-14`, expected child PID `2` (`native_fork_cow.rs:1772` on WIP). | Stops at fork admission; no child or parent memory result. |
| runtime `serial_host_cow_fault_settles_used_grants_before_engine_refill` | Did not compile with `platform-linux`: `E0046` (two missing `ThreadedEngine` methods) and `E0308` (`Result` treated as `Option`). | Salvaged fixture API drift; no native fork or parent-state verdict. |

The ARM and x86 native witnesses reach production fork/fault paths but fail
before the proposed parent-after-`wait4` observation. Their early refusals
point first to child COW/fault-supply and fork-admission behavior. They do not
confirm the hypothesis that child retirement corrupts the parent. A new
parent-state witness must complete its child write, exit, and `wait4` first.

`el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation_on_any_thread` (#1857)
is a signed HVF test and is not runnable in this Linux VM (HVF does not nest).
Its reported threaded, cross-vCPU edit and no-output segfault resembles the
CPython symptom. There is no kept witness to compare with it.

## Commands and logs

All runs used `CARGO_BUILD_JOBS=3`, `-j 3`, and `timeout`. The raw logs are
under `/tmp/1733-witness/` on the worker VM. Commands:

```text
timeout 600 env CARGO_BUILD_JOBS=3 cargo test --locked -j 3 -p carrick-core --test aarch64_fork_geometry arm_fork_splits_2mib_private_block_into_cow_armed_l3_leaves -- --exact --nocapture
timeout 600 env CARGO_BUILD_JOBS=3 cargo test --locked -j 3 -p carrick-el1-linux --lib --features host-test serial_host_native_fork -- --nocapture
timeout 600 env CARGO_BUILD_JOBS=3 cargo test --locked -j 3 -p carrick-x86 --test native_fork_cow -- --nocapture
timeout 120 env CARGO_BUILD_JOBS=3 cargo test --locked -j 3 -p carrick-mmu-core --lib write_publish_of_cow_armed_prepared_leaf_commits_read_only_cow_leaf -- --nocapture
timeout 600 env CARGO_BUILD_JOBS=3 cargo test --locked -j 3 -p carrick-x86-cpl0-host --lib retired_fork_children_release_cow_pool_grants_across_pool_capacity -- --nocapture
timeout 600 env CARGO_BUILD_JOBS=3 cargo test --locked -j 3 -p carrick-runtime --no-default-features --features platform-linux --lib serial_host_cow_fault_settles_used_grants_before_engine_refill -- --nocapture
```

The first x86 descriptor invocation used `--exact` and ran zero tests; the
listed invocation removed that filter and produced the red result. The first
runtime invocation used its macOS-default feature closure on Linux and failed
to compile `carrick-vmm-hvf`; the listed Linux-feature invocation produced
the fixture errors above.
