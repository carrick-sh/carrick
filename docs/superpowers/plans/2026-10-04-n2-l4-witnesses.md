# N2 L4 signal/timer red witnesses

Preparation only, on main `b1167c6e19811c5b3a601d979cedca844656454f`.
The controller is PR #25's N2 readiness plan. N1 has not landed and no
N2 driver API is assumed. No production code, registrations, inventories or
driver-reserved files change. No row is closed.

The auto-discovered target is
`crates/carrick-el1/tests/n2_readiness_signal.rs`. All four tests carry the
requested `N2 red witness` ignore reason. Normal execution is green with
four ignored tests; explicit ignored execution is red with four failures.

## Contract and fixture

Rows 10 and 12 belong to `kernel.el1.signal-delivery-owner` and the driver's
pending `kernel.el1.creation-native-path` binding. Linux semantic authorities
are signal(7), sigaction(2), tgkill(2) and setitimer(2), as named in the
existing contract and policy controls. The structural requirement is exactly
zero semantic forwards per operation at 1/8/32 targets. This document is a
binding request, not a second contract registry.

Each scale retains N target process identities **plus one live guard** in
distinct open address spaces. At scale 1 there are two simultaneous owners;
at scale 32 there are 33. These are production shared-ABI lifecycle/MM records,
not live EL0 tasks or host kernel-graph processes. The birth test creates one
thread in each target process through the real dispatcher; it does not expand
the ordinary eight-entry per-process pool. Every child uses stack VA
`0x40001000`. No host settlement occurs before tgkill. The birth assertions
(Served, child tid, Born state, live count, inherited blocked mask, queued
record and zero clone forwards) all pass before the signal-owner assertion.

The other tests supply valid host-backed ABI buffers to the synchronous
dispatcher. They do not prove same-VA UserTransfer or fault handling. The
injected CPU has a fixed clock; timer programming records a physical effect,
without implementing a Linux timer or delivering an expiration.

The measured counters are the production dispatcher's per-syscall
`Counters.forwarded/served`. No host syscall dispatcher is invoked. Therefore
nonzero forwarding proves the route deficit, but **host signal-selection work
is unmeasured**, not a fabricated zero. Driver-owned work instrumentation and
production owner binding remain necessary.

## Observed red and route needed

All vectors below are ordered by N = 1, 8, 32. Every listed serving count is
zero; expected forwards are zero. Every semantic predicate is false today.
All scales execute before the final assertion.

| Witness (exact test name) | Row and observed red | Production change needed for green |
| --- | --- | --- |
| `sigaction_keeps_live_process_actions_separate_at_1_8_32` | 10: `missing sigaction owner`; syscall 134 forwards **4/18/66**. Installed handler, SA_RESTART flag and mask are not returned by each owner's query. | Bind the one Linux action authority to EL1; install/query through exact process ownership and owner user-copy. No host action selection. |
| `tgkill_reaches_exact_born_target_before_host_settlement_at_1_8_32` | 10: `missing born-target signal owner`; syscall 131 forwards **2/16/64** after **1/8/32 successful births**. Blocked child pending bit is absent; wrong-group call fails to return ESRCH (3). | Publish signal identity with Born before runnable publication; route exact tgid/tid without host adoption, enqueue on the child and reject the foreign group without changing its pending state. Pending-summary checks here are necessary, not proof of payload custody. |
| `blocked_sigchld_is_observable_only_in_its_live_owner_at_1_8_32` | 10: `missing blocked-pending owner`; syscall 131 forwards **1/8/32**, syscall 136 **2/9/33**. Pending queries do not return the owner's blocked SIGCHLD or the guard's empty set. | Bind signal enqueue and pending-query policy to the same owner. This uses explicitly sent SIGCHLD; child-exit notification, wait status and autoreap are not tested. |
| `disarming_one_process_timer_preserves_the_live_guard_timer_at_1_8_32` | 12: `missing interval-timer owner`; syscall 103 forwards **3/17/65**, syscall 102 **2/9/33**. Prior value, disarmed value and independent guard value are not returned. | Bind set/get interval-timer operations to exact process ownership using the existing timer reducer and injected clock; cancellation must preserve other owners. This does not inject expiry. |

## Open bindings and existing controls

`cargo test -p carrick-signal-core` preserves the existing positive controls;
none was copied into a new test or relabeled as a production red:

- `clone_sighand_shares_actions_but_never_masks_or_pending_at_1_8_32_targets`
  and `fork_and_exec_reset_actions_pending_and_masks_in_their_own_domains`:
  shared/copied action edges and exec reset still need the production task
  transaction binding. The action witness above covers independent owners only.
- `interval_timer_arm_expire_cancel_and_duplicate_completion_use_injected_time`
  and `timer_rearm_stale_owner_fork_exec_and_coalescing_at_1_8_32_targets`:
  duplicate/stale expiry needs the driver's real completion input. The public
  dispatcher offers no such input today.
- `restart_class_readiness_and_partial_io_are_distinct_from_signal_delivery`
  and the temporary-mask tests: SA_RESTART execution, a readiness/enrollment
  race, and SIGPIPE after a partial write need L2/L3's production owned wait
  continuation plus the L4 signal binding. Storing SA_RESTART in an action
  does not test restart. No alternate wait/signal model was added.
- Cross-page frame copy, invalid sigreturn and handler activation require
  N1/P4's single codec through the eventual owner SignalFrame service, followed
  by signed execution. They are UnsupportedLayer here; no transport spy is
  substituted. Signal policy remains Linux-specific, not neutral substrate.

These missing interfaces limit this preparation to the four compiled route
witnesses. The driver must compose the existing reducers with the accepted N1
owner, update this fixture to that public binding, register it, and remove
ignores only when semantic and work assertions actually pass. Signed execution,
Docker semantics/timing and whole-N2 acceptance remain unperformed.

## Verification receipts

All commands ran on cloudmac after `source /Volumes/carrick/dev/env.sh`.
No Docker or guest execution occurred. Logs are host-local under `/tmp/`.

```sh
CARRICK_RUN_ID=n2-l4-red cargo test -p carrick-el1 --test n2_readiness_signal -- --ignored --nocapture --test-threads=1
CARRICK_RUN_ID=n2-l4-policy cargo test -p carrick-signal-core
CARRICK_RUN_ID=n2-l4-owner cargo test -p carrick-el1 --test n2_readiness_signal -- --nocapture
CARRICK_RUN_ID=n2-l4-clippy just clippy
CARRICK_RUN_ID=n2-l4-fmt just fmt-check
CARRICK_RUN_ID=n2-l4-domains just lint-domains
CARRICK_RUN_ID=n2-l4-ci just ci
```

- `/tmp/n2-l4-red.log`: exit 101, **0 passed; 4 failed; 0 ignored**;
  the four final owner assertions and scale counts above are the red evidence.
  An earlier fixture attempt rejected ordinary clone preemption-timer arming;
  that fixture failure was corrected and is not counted as owner red evidence.
- `/tmp/n2-l4-policy.log`: exit 0; 12 unit and 18 policy controls pass.
- `/tmp/n2-l4-owner.log`: exit 0, **0 passed; 0 failed; 4 ignored**.
- `/tmp/n2-l4-clippy.log`, `/tmp/n2-l4-fmt.log`,
  `/tmp/n2-l4-domains.log`: all exit 0, including the live macOS compiler
  census. That census explicitly leaves non-macOS profiles pending.
- `/tmp/n2-l4-ci.log`: exit 101 at `just doc`, after format, Clippy,
  domains, dependency, matrix, layering, portable-kernel and workspace build
  stages passed. Rustdoc rejects five links in the unchanged, out-of-fence
  `crates/carrick-mmu-core/src/aarch64.rs`: `[5:0]` (299),
  `publish_existing_invalid_private_pages` (826, 889, 949), and `AP[1]`
  (1831). Later CI test/integration stages were not reached. This is a
  broader CI blocker, not a green full-CI or acceptance receipt.
