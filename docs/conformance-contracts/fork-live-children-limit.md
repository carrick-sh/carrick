# Fork live-children limit (`kernel.fork.live-children-limit`)

Surface: `fork`/`vfork`/`clone` without `CLONE_VM` on the in-kernel fork
path (HVPATCH), on both carriers. Linux authority: fork(2) fails with
`EAGAIN` when a system-imposed limit is reached (`RLIMIT_NPROC`,
`threads-max`, `pid_max`). Carrick adds a narrower limit, a candid
divergence: each live fork child holds one carrier lifecycle record until
its MM is retired and reclaimed, and the stock is fixed at boot. x86 CPL0
has 8 records, AArch64 31 (see the
[fork stock design](../design/arm-fork-stock-crossing.md)). A workload with
more concurrently live children than that (`make -j16`, a long shell
pipeline) sees `EAGAIN` from the extra forks where Linux would succeed.
Zombies do not count: a child's record returns once it has exited and left
every slot, whether or not it was reaped.

Invariant: a fork beyond the limit is refused with a counted `Capacity`
refusal and returns `EAGAIN` (-11). It never hangs, never faults the
carrier, never strands a loan, and never returns another errno. The limit
counts live children, not forks: retiring one child admits the next fork.
A terminal receipt remains `Retiring` until exact member cancellation and
MM retirement have completed. A parent entering wait in that interval
parks through the existing wait continuation; it cannot reap and issue a
new fork against the retiring child's charged tables. Completion publishes
readiness and selects the current receipt parent in one graph projection
before notification/wakeup; an adopter owns the wake after reparenting. This adds one
acquire read per examined terminal receipt and no polling, retries, wider
stock, or wall-clock deadline. Autoreaped children retain the same pending
receipt, exact child edge and numeric claim. Each pending automatic removal
owns one preadmitted parent revision credit; adoption replaces it with an
admitted credit for the exact adopter. Retirement atomically removes that
receipt and edge without charging CPU usage, before the existing channel
wake. Dropping the exit publication leaves retirement pending. Admission itself
drains reclaimable stock once through the existing stopped crossing.

Every refusal is attributable in the run report's
`execution_witness.fork_stock_families` (`capacity_refusal`, and for a
withdrawn dirty record `inventory_refusal` with `withdrawn_lifecycle`).
The last exact capacity resource and all quarantined children at refusal
are retained in `execution_witness.fork_admission_refusal` and emitted by
`fork-admission-refusal` / `fork-quarantine-state` USDT probes. Their absence
means no recorded capacity refusal, not evidence of a dropped trace.

VM-free bindings:
- `process_owner::tests::exit_status_is_not_waitable_before_mm_retirement_completes`
  (carrick-el1): pause at owner publication, assert wait remains running,
  complete retirement and assert the same status is available. Red before
  the readiness publication gate, without load.
- `process_owner::tests::retirement_completion_notifies_the_adopter_of_a_pending_zombie`
  (carrick-el1): reparent while retirement is pending, then complete it;
  notification targets the adopter, not the exited original parent.
- `carrier_cpu::tests::child_owner_grant_on_root_executor_is_a_physical_boundary`
  (carrick-vmm-kvm): a registered child crosses for physical service while
  the executor retains its root-task custody. Select the live registered
  child root; an unregistered root still refuses. Red on the retirement-only
  selection policy. Physical service separately authenticates the CPL0
  binding and context incarnation.
- `fork_stock::tests::kvm_live_children_beyond_lifecycle_records_are_counted_refusals`
  (carrick-hal): eight live children, the ninth loan is one counted
  `Capacity` refusal, and after one child is retired and reclaimed the
  ninth loan is granted.
- `aarch64_process_tests::capacity_refused_loan_is_eagain_with_nothing_to_settle`
  (carrick-el1): the guest lowers the carrier's typed refusal to
  `Exhausted`, errno -11, with no loan to settle. It was red (`EFAULT`)
  while the guest trusted x0 over the typed reply.
- `aarch64_process_tests::failed_prepare_after_the_loan_aborts_it_and_a_later_fork_succeeds`:
  a refusal after the loan was granted aborts it, so later forks on the
  CPU are not refused for capacity.

Native lazy backing uses the same fixed table stock. Each descriptor supply
may preclaim the bounded eight-page grant record, but only the prefix named by
the authenticated EL1 receipt becomes live child custody. The unused suffix,
and every grant from a refused, rolled-back or unclaimed transaction, returns
before the service continuation releases. If child exit wins the service race,
reply application returns before settlement, or receipt settlement fails after
consumption, the neutral retirement owner absorbs every remaining grant for
that child into terminal table custody. Quarantine clears those possibly linked
pages before reclaim; retirement never refuses this ordinary race. Capacity
exhaustion is a counted `descriptor_capacity_refusal`; it refuses the fault
service without a carrier fatal and without changing stock. The VM-free bindings
`many_native_backing_supplies_return_unused_tables_across_two_children` and
`native_backing_table_exhaustion_is_counted_without_losing_stock` drive 512
alternating supplies across two live children and the exact exhaustion edge.
`child_exit_racing_native_supply_quarantines_pending_pages_with_peer_live` and
`early_fault_reply_return_quarantines_every_pending_supply_with_peer_live`
keep a second process live while proving unfinished grants clear through
quarantine rather than causing a terminal refusal or premature reuse.

The HAL exec replacement component transfers the same unfinished descriptor
supplies into predecessor retirement custody before withdrawing its live child
identity. `exec_replacement_absorbs_pending_descriptor_tables_with_peer_live`
was red when replacement left those grants stranded. It covers a live peer,
failed-clear retry without repeated physical release, and exact stock recovery.
`exec_replacement_rejects_stale_predecessor_incarnation` was red when a matching
root/MM admitted a stale context generation. These component bindings do not
claim production native exec adoption or signed execution.

ARM routing keeps root and native fork-child ownership distinct. Admitting the
root for its first fork does not move the root's own `execve` into the native
child owner: the root continues through the host exec boundary. Until native
child exec is implemented, only a fork child's `execve` is refused with
`ENOSYS`. `arm_unadmitted_thread_runs_ordinary_calls_and_refuses_owner_calls`
binds the owned-root case, while
`native_child_exec_refusal_parks_once_and_resumes_with_enosys` binds a real
registered child and the single park/resume boundary.

KVM binding:
`native_runtime_wait_wakes_once_only_after_real_mm_retirement` holds the
real CPL0 child-retire crossing pending. The parent observes WNOHANG zero,
successfully forks again, and enrolls its blocking wait through the native
runtime. The scheduler census remains parked with zero completion wakes
until MM retirement and slot absence publish; completion queues that exact
waiter with one wake and resumes it with the child's exit status. Reordering
runtime readiness before `retire_mm`, or omitting channel publication,
fails this witness. The existing carrier watchdog bounds guest execution;
the host census only observes atomic enrollment and never publishes readiness.

`native_nocldwait_blocks_until_every_child_mm_retires` and
`native_sigign_blocks_until_every_child_mm_retires` exercise real native
`rt_sigaction` and `wait4(-1)` with two autoreaped children. Linux authority:
[wait(2)](https://man7.org/linux/man-pages/man2/wait.2.html) and
[sigaction(2)](https://man7.org/linux/man-pages/man2/sigaction.2.html).
The parent admits a second fork with the first MM retirement held pending,
enrolls a real wait, and must enroll again after the first completion while
the second MM remains charged. Only the last completion may return errno
10 (`ECHILD`), followed by another successful fork. Each completion wakes
the enrolled waiter exactly once; no observer publishes readiness. The
VM-free binding `autoreap_keeps_wait_population_until_retirement` retains
the child edge and numeric claim even if the exit lane is abandoned.
`autoreap_completion_removes_only_the_retired_child` covers a new birth
between retirement publications, exact removal and zero CPU charging;
`pending_autoreap_moves_removal_credit_to_adopter` checks credit ownership
and numeric-claim release after adoption. Mounted fork-rounds reuse covers
normal waits, SA_NOCLDWAIT and SIG_IGN, each over twelve sequential rounds;
the autoreap children attest successful private-page verification through
the existing owned signal-wait protocol with a zero timeout, because their
exit status is unavailable.

`child_born_on_idle_peer_can_fault_and_retire_on_root_executor` forces a
fork loan and commit on the idle peer, then places that queued newborn on
CPU 0 through the real scheduler claim/run queues. The fixture does not
require the unported CPL0 sched_setaffinity syscall.
Its private first-touch and physical MM retirement must authenticate the
newborn's live binding while CPU 0 retains the root task's executor lease.
The carrier's CPUs share one child-binding authority; executor detach does
not retire a live child, and a conflicting live-root registration refuses.

`mounted_static_x86_fork_rounds_beyond_lifecycle_stock_reuse_retired_children`
(12 sequential fork/exit rounds, each child first-touching fresh private
pages that must read zero; native output and exit; `loan` 12,
`returned_child` at least 4, no refusal family). The live-concurrency
refusal itself has no mounted binding yet.

Budget: a refusal does one loan crossing and no reclaim retry; reclaim
visits each quarantined child once per loan. Signed HVF execution and
Docker timing are not claimed by these bindings; the signed ARM fork gate
records `withdrawn_lifecycle` and `retire_refusal` as zero.
