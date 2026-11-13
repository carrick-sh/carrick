title: finish ring-native root exec through the shared neutral transaction
parent: #2273

The selected design is (b): the root uses the existing native child exec
build/adopt/cancel/settle owner. Do not add an x86 RootExecVenue that builds a
second successor or commits a second copy of the neutral exec sequence.

Existing mechanisms, ARM first:
- ARM root: HvpatchExecVenue and kernel::exec_transaction::drive_root_exec.
- ARM/native child: begin_exec_service, complete_exec_prepared,
  commit_exec_successor, and the shared exec_successor slot/adopter.
- x86 child: stage_x86_exec, build_x86_successor, NATIVE_EXEC_PORT
  adopt/cancel/settle, and ForkStock predecessor custody.
- Root rebinding already on main: PendingExecReplacement::cpl0,
  Cpl0TaskBindingDirectory::replace_exec, retarget_loaded_task, and
  ProductionCpuLease::retarget_root_exec.

The recovered root patch is unfinished and must not land or enable the
crossing. It selects RootExecRoute::Ring and carries root image identity,
but the runtime never commits the host Kernel transition or retargets
the root. Initially both doorbell handlers silently discarded RootSettled;
the continuation makes that unexpected settlement an explicit invariant
error through one exhaustive child_rebind handler. This is not a root
transaction implementation.
The continuation therefore restores caller_access before service publication:
the root remains a counted ENOSYS until the full transaction can own it.
The existing access-refusal witness failed on the recovered WIP (1001 pass,
1 fail, 9 ignored); it is retained unchanged as the guard regression witness.
Before restoring the guard, real KVM passed the ENOENT/ENOEXEC cases but
failed successful root replacement with `unregistered forward CR3: root
0x480c000, rip 0xffffffff80005102` (run 2235r3-root).

The missing shared interface must retain the neutral transaction across
Exec preparation, the consuming adopt crossing, and settlement. Today
exec_transaction::run owns prepare, signal/proc state, arm, image replacement,
Kernel commit, CLOEXEC, exec identity publication and ptrace stop in one
synchronous call. Extract resumable phases there; do not copy these steps
into the CPL0 executor. Prepare before destructive replacement and preserve
rollback on loader/build refusal and cancellation.

MM authority must also agree before arm: the ring currently issues the
successor MM in begin_service, while Kernel::prepare_exec_after_reservation
allocates another MM. The runtime loader receives only origin and payload,
not the authenticated proposed successor. PendingExecReplacement::cpl0
correctly refuses mismatched committed/architectural MMs. Extend the owned
interface to carry/admit that issued successor rather than forging an ID or
weakening the check. The same requirement applies to execution generation
and the host successor thread key.

Exec service interface for #2269/Python subprocess: the ring stages an
ExecPayload (execve or execveat), retains the outstanding service ticket,
and parks on its object wait. The host loader resolves the caller's authority;
finish_native_exec seals the successor manifest or returns a pre-arm errno.
The CPL0 adopter builds it, adopts or cancels the sealed receipt, commits the
record, and settles the predecessor via NATIVE_EXEC_PORT. No host exec-status
pipe read is implemented here; #2269 owns that read and must use this service.

Executable identity belongs to #2084 native_host_file::admit_or_cross and
its retained executable object/backing custody. Do not add a path snapshot
registry. #1903 remains unproven until post-exec readlinkat has a live witness.

Still required: three production root witnesses, root exec with another live
task, parked-exec rerun and ring-cancel KVM witnesses, separate director-owned
crossing commit, all requested final-head gates, native-arm64 oracle, and the
main/head eight-row scoreboard off tmpfs. No budgets or ignores may change.
