# follow-up: a ring-born member's other declined raw exits still leave for an executor with no host task

Refs #2109, PR #2182.

**What happens.** #2182 removes the robust-list decline, which glibc hits on every
thread exit. `serve_exit` (`crates/carrick-personality-linux/src/lifecycle.rs`) can
still decline a non-last thread's raw `exit` for other reasons: `ExitPending`,
`ExitGate`, `ExitHostWork`, `ExitCancelled`, `ExitObjectOperation`,
`ExitClearTidCopyout`/`ExitClearTidWake`, `ExitAdmission`, `ExitLast`,
`ExitIdentity` and `ExitClaim`. Every decline routes to `CompletionRoute::HostCustody`
(`invoke`, the `LifecycleCall::Exit` arm), and `Action::HostCustody` leaves through the
vector's syscall capture (`El1Exit::HostCustody`). `capture_native_service_exit`
(`crates/carrick-el1-linux/src/dispatch.rs`) captures only `Forward` and
`ServedWithWork`.

**What it means.** A ring-born member of a native fork child has no host thread. If one
of those declines happens while it runs from the zone on an executor waiting in the
guest (`wait_in_guest`, `crates/carrick-runtime/src/vcpu_loop/executor/backend.rs`),
the carrier dies with the #2109 fatal. A pending signal at thread exit
(`ExitPending`) is the likeliest real-world trigger.

**Acceptance.** For a ring-born member, a declined raw exit is either served in ring or
treated as "not now" (keep the owned exit, enrol on what it waits for, then rerun).
Make `HostCustody` unrepresentable for a record with no host owner on its slot: today
`LifecycleNative::route_host_thread_exit` returns a bare `bool`. Witness each decline
on the #2182 harness (`arm_pinned_glibc_member_raw_exit_on_an_idle_executor_retires_in_ring`).
