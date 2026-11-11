# Kernel landing batch, 2026-11-11

The owner approved this batch. It combines eight reviewed kernel PRs on
one branch, so that one CI run and one merge-group signed gate stand in for
eight. Each PR's own commits were cherry-picked with `git cherry-pick -x`,
in the order below. Authors and trailers are unchanged, and every picked
commit carries a `(cherry picked from commit …)` line naming its PR-branch
original.

**Base:** GitHub `main` at `715f3afd44153a3a495eae0c204f0779e8871458`.
`main` had not moved when the batch was built.

| # | PR | Head picked | Range picked | Commits | Issue |
|---|----|-------------|--------------|---------|-------|
| 1 | #2063 poll writes only `revents` | `cf8c93600d` | `7deba24e21..cf8c93600d` | 3 | #1897 |
| 2 | #2093 x86 pipe tests, unbound wakes | `467512578a` | `a88314ade2..467512578a` | 3 | #2082 |
| 3 | #2080 signal-frame contention parks | `1acd09eab2` | `118c67f525..1acd09eab2` | 5 | #2070 |
| 4 | #2065 x86 timed poll | `0f8fb5759f` | `7deba24e21..0f8fb5759f` | 7 | #2033 |
| 5 | #2079 per-member child waits | `f077b8cea5` | `a88314ade2..f077b8cea5` | 2 | #2071 |
| 6 | #1994 kill a non-leader tid | `b87b14946c` | `7af6927b8c..b87b14946c` | 11 | #1974 (part) |
| 7 | #2053 signals to unbound births | `a8aab77a7e` | `118c67f525..a8aab77a7e` | 4 | #1974 (part) |
| 8 | #2062 #1974 slice 2 | `e011ecf4fd` | `a8aab77a7e..e011ecf4fd` | 11 | #1974 (part) |

Each range starts at `git merge-base 715f3afd4 pr/N`, and that merge base
is an ancestor of `main`. #2062's branch contains #2053's commits, so only
`a8aab77a7e..e011ecf4fd` was picked for it.

**#2053 review head.** #2053's independent review approved
`9d3253da38`, and the PR head is now `a8aab77a7e`, a rebase of it.
`git range-diff` shows the production commit
(`fix(el1): resolve pre-requeue native births…`) is identical. The two
witness commits differ only in context lines and blank-line placement in
`born_thread_entry_tests.rs`, from rebasing onto a newer `main`.

## Textual conflicts

Each conflict below was between two purely additive sides. The resolution
keeps both, and no test, assertion or production line was dropped.

| # | File | Picking | Ours (already on the batch) | Theirs (being picked) | Kept |
|---|------|---------|-----------------------------|------------------------|------|
| T1 | `crates/carrick-vmm-kvm/tests/cpl0_initial_mm.rs`, after `zone_pipe_poll_zero_timeout_returns_immediately` | #2065 `4b54e43f8` (batch `d5034185e`) | #2063 added `run_poll_revents_only_fixture` and the two `x86_cpl0_poll_*` revents tests at that spot | #2065 added four `zone_pipe_{ppoll,poll}_finite_timeout_*` tests at the same spot | Both: #2063's helper and two tests, then #2065's four tests. The brief expected #2093 to be the other side here, but #2093's edits merged cleanly. The overlap was with #2063. |
| T2 | `crates/carrick-vmm-kvm/tests/cpl0_entry.rs`, after `production_pipe_metadata_stays_in_the_ring…` | #2079 `050860fd3` (batch `0287df622`) | #2080 added `run_production_signal_frame_contention_probe`, its two tests and `production_signal_frame_real_fault_delivers_sigsegv_si_kernel` | #2079 added `production_two_threads_blocking_wait4_reap_distinct_children` | Both: #2080's x86 signal-frame tests, then #2079's x86 `wait4` witness. |
| T3 | `crates/carrick-el1-linux/src/aarch64_process_tests/born_thread_entry_tests.rs`, after `arm_declined_fault_returns_a_quarantined_delivery_refusal` (two interleaved hunks that share a `native_scheduler` call) | #2053 `c3a0cb699` (batch `a92c0fbcd`) | #2079 added `ProductionProcessHarness` and its five `arm_*wait4*`/`msgrcv` witnesses | #2053 added `TGKILL_AFTER_CLONE_FLAGS`, `MultiSlotEnv`, harness helpers and the pre-entry tgkill/peer-kill witnesses | Both, in full: #2079's block, then #2053's block. Checked mechanically: against the batch's previous state the resolved file has no removed lines, and its added lines are exactly the lines `c3a0cb699` adds. |
| T4 | `crates/carrick-el1-linux/src/native_process_runtime.rs`, the member-retirement loop over `completed` (about line 2013) | #2062 `c6d7bb8d9` (batch `ef132ed01`) | #2079 widened `completed` to a 4-tuple `(_, record, _, control_addr)` and added `graph.pending.remove_member_child_waits(&process, *control_addr)` after `take_relative_futex_wait` | #2062 replaced `take_relative_futex_wait(record)` with `retire_member_retained(record)`, which is defined as `take_relative_futex_wait` plus `take_thread_stock_reply` | #2079's 4-tuple and `remove_member_child_waits`, with #2062's `retire_member_retained` in place of `take_relative_futex_wait`. Each side's effect is kept, and nothing is added. |

## Semantic conflicts (each compiled alone, failed combined)

`just clippy` found two after all the picks applied. Each fix has its own
commit after the picks, so it can be reviewed apart from the PRs.

| # | Commit | PRs | Failure | Fix |
|---|--------|-----|---------|-----|
| S1 | `853743768` `fix(el1): state the carrier-work demand at the signal-frame park site` | #2080 + #2062 | #2062 made `demand` a required field of `ServiceOperation::CarrierWork`. #2080 added a new `CarrierWork` site in `native_process_runtime/service.rs` (the signal-frame park), which #2062 never saw. Result: E0063 in the EL1 and CPL0 image builds. | One added line, `demand: CarrierDemand::Work`, at that site. This is #2062's own stated rule ("Every existing CarrierWork site states `Work`"). The signal-frame park is ordinary carrier work, not a thread-stock demand. |
| S2 | `b3b9cfbd2` `test(x86): give the nonleader-kill checkpoint injection its own ordinal` | #2065 + #1994 | Both PRs gave a new CPL0 test-support injection the ordinal `0xffff_ffff_ffff_fe1d`: #2065's `INJECT_REPLAY_SETTLEMENT_REFUSAL_ONCE` and #1994's `INJECT_BLOCK_SIGUSR1_AT_SECOND_CHECKPOINT`. The test CPL0 image failed `unreachable_patterns` and `match_overlapping_arm`. | #1994's injection moves to the unused ordinal `0xfe1e`, in `carrick-x86-cpl0/src/lib.rs` (`test_support`, behind `feature = "test-support"`) and in the `cpl0_entry.rs` witness that issues it. Production code is unchanged. |

Verification of the combined branch is posted on the batch PR.
