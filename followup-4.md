# x86 CPL0: a fork child's exit_group with a second live member never completes cleanly

Labels: main-defect, x86, kvm, lifecycle (relates to #418)

**What happens.** A fork child clones a worker thread, and the child's main
thread calls `exit_group(5)` while the worker is live. The root's `wait4`
then never returns, and the run hits its 60 s bound:

- worker blocked in `FUTEX_WAIT_PRIVATE`: hangs on GitHub main 03055d691
  (run `r2-main-eg`) and on #2263;
- worker runnable, yielding in a `sched_yield` loop: hangs on #2263
  (runs `r2-ctl-1..3`);
- worker parked on a user fault after its COW supply (#2263): the program
  completes, but pool shutdown finds a CPU on the dead child's root:
  `x86 CPU image does not match its issued MM/context/root binding;
  expected root 0x4803000, actual CR3 0x480c000`, or `unregistered physical
  crossing CR3: root 0x480d000, port 0xcb` (9 of 10 runs, `r2-pop-*`).

The fixture is `crates/carrick-vmm-kvm/tests/fixtures/native_post_supply_busy.S`
(`-DPOST_SUPPLY_EXIT_GROUP`).

**What it means.** On x86 CPL0, `exit_group` with a second live member (the
AGENTS lifecycle case "exit_group with a running worker") is unwitnessed
and broken. #2263's witness
`production_cow_parked_after_supply_survives_exit_group` is
`#[ignore]`d against this issue.

Acceptance: that witness and a futex-blocked-worker twin pass 10/10 on KVM.
Both are red on main today.
