Independent review of the #1576 fix for PR #1589. Keep draft pending the director's signed verification. This review changes no production code.

The VM-free witness reproduces the proposed cause: main's entry admission returns `Stale` when the CPU slot carries the still-live parent's namespace PID and the selected newborn belongs to the native child. This supports the identity-projection diagnosis; it does not establish that every observed signed fatal has this cause.

Findings: no P0 or P1 code defect identified in the reviewed change. Signed acceptance remains outstanding.

### Red-first and failing lookup

Both changed production files were temporarily restored from admitted main `371d59eb8edd2b475da13b1fa63e57b488fa7ddc`, leaving the candidate witness in place. Exact command (with the runner's Cargo bin directory added to PATH):

```sh
cargo test -p carrick-el1-linux --lib native_child_thread_signal_at_first_user_return -- --nocapture
```

Exit 101: `native_fault_supply_tests.rs:1202:6`, `newborn signal checkpoint must own its process entry: Stale`. One test failed, 684 filtered out. An initial invocation before setting PATH exited 127 because `cargo` was not on PATH; it supplied no test evidence.

On admitted main, `aarch64_process.rs:583` calls `REGISTRY.group_address` with the CPU slot's `visible_pid`; line 590 converts the absent group to `Stale`. `native_process_runtime.rs:1750` defines the group key as zone, MM, root, lifecycle-page address and namespace PID. Here the selected thread has a Born lifecycle entry (`control.entry()` is present) but no registered execution entry (`registry.for_record` is absent). Its MM/page are the child's, while the stale PID is the parent's. `dispatch.rs:1785-1795` propagates that admission error to the reported `EntryBinding` fatal. This is a failed group lookup, rather than evidence that its lifecycle page has vanished.

### Authentication and lifetime

At candidate `native_process_runtime.rs:2396`, `newborn_visible_pid` authenticates the selected record's incarnation and native ownership, its presence on the specified CPU slot, the CurrentTask's lifecycle page and control slot, and the control's exact RecordRef. `prepare_handoff` additionally checks TID, execution generation, MM, thread serial, installed address space and the exact OnCpu/OnCpuRequested claim and slot (`carrick-core/src/entry.rs:220`).

`page.identity(control.entry())` validates the entry generation and refuses Vacant/Stocking entries (`carrick-personality-linux/src/abi/thread.rs:2089`). The helper compares birth TID and serial with the selected record. Saved-context authentication checks root, MM and root generation (`carrick-sched-core/src/aarch64_context.rs:78`). The bounded group-index range fixes zone/MM/root/page and refuses ambiguity. Finally the exact generation-bearing TaskKey is looked up under the graph lock, and full address, page identity and thread membership are checked before returning the row's namespace PID.

The group index omits root generation, but the final resources-address comparison includes it. A recycled record or lifecycle entry is rejected by incarnation/generation and birth-serial checks. Another process's page cannot match the group range and final page comparison. `page.control_address(entry)` and CLONE_THREAD are not rechecked by this projection helper; normal `register_thread` admission still authenticates both before registering delivery. The helper only restores the namespace projection and does not grant a process entry.

I found no newly introduced check/use gap that permits a foreign identity: the caller holds exclusive selected-record custody through restoration, lifecycle backing is retained for that execution, the group lookup retains an Arc, and the graph read uses the original TaskKey. The graph lock is dropped before the scalar PID is published, but concurrent closure cannot convert that TaskKey into a different process. Subsequent admission and signal gate checks remain authoritative for delivery. This reasoning depends on the existing exclusive-record/lifecycle-retention contract; the positive witness is not a concurrency proof of all lifecycle machinery.

### Shape and adjacent changes

Restoring namespace projection at unregistered resume is appropriate. A newborn has no registered entry yet, so it cannot enter `resume_selected`'s registered-entry path without first authenticating/admitting it. The new helper supplies only the missing projection; entry registration, signal import and signal delivery continue through the existing production path. It introduces no second signal consumer, retry loop or host fallback. Cancellation is handled before this restoration branch (`aarch64_process.rs:343-449`). Registered and newborn records still need distinct identity lookup sources; unifying their publication statements would be cleanup, not a correctness prerequisite.

The new witness drives production scheduler selection, `resume_production_with_service`, `with_process_entry` and the user-return delivery policy. It imports and consumes SIGPIPE once, exits the worker while its leader remains live, and then delivers to that leader. It does not execute the hardware `arm_signal_user_return` wrapper itself or a real carrier.

Composition was checked against the current GitHub descriptions of #1585, #1569 and #1586 and the relevant #1585/#1569 patch hunks. #1585 changes closed-gate service retirement in the native runtime, while this change restores a newborn's namespace before entry admission; they are distinct lifecycle seams. #1569 changes park/yield publication and host-request custody; this helper merely authenticates an existing selected claim with unchanged `prepare_handoff`. No duplicate park/yield mechanism is added. #1586 explicitly starts after #1576 and moves signal state to typed identities; this fix does not add a signal map. The runtime file is shared, so the director must rebase and verify their combined tree; no combined-stack signed result is claimed.

### Verification and remaining acceptance

After restoring both production files from the candidate commit, the same focused command exited 0: one passed, 684 filtered out. The admitted-main isolated suite (`just test-el1-native --skip native_child_thread_signal_at_first_user_return`) exited 0 with 683 passed and one ignored, including all 29 serial tests. The candidate `just test-el1-native` exited 0 with 684 passed and one ignored, again including all 29 serial tests. Name-by-name comparison: `NEW=[]`, `missing=[]`, no changed outcomes among baseline tests, and exactly the new witness added. Each selected test has a terminal result; both binaries completed. Source authority-debt and the contract-change check against the admitted main passed. `just cross-check-macos` passed, including check and clippy. The source-only authority ratchet against admitted main passed (1266 source counters). The extra full authority-discovery invocation was stopped; only source discovery is claimed. The full `just clippy` recipe exited 0. It emitted the existing clippy configuration warning for `libc::proc_listallpids` on Linux; no source lint failed.

The Linux x86_64 runner has `/dev/kvm`; no KVM test is needed for this AArch64 native-resume review, and none is claimed. Docker is unavailable and HVF cannot run on this host. The director must run the affected signed fork-COW, two-process, spawn-slope, seccomp clone-filter and allocator workloads on the exact signed artifact, show zero `EntryBinding at=1795` fatals, and retain signed smoke and artifact provenance. Whole-workspace `just lint-domains` and `just test-kernel` are left to CI. Nothing was pushed or posted.
