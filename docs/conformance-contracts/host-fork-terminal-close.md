# Host fork versus terminal close (`kernel.el1.thread-lifecycle`, #441)

An admitted host fork either loses to terminal close before its commit gate
check, or holds a neutral publication claim until the new process is fully
published. Closing observes that claim through `claimed_count` and cannot
settle until publication or rollback finishes. The winning child is an
independent process and is reparented normally; it is never a member of the
parent's thread cancellation set. Seccomp/ptrace decline to `HostOnly`, which
permits host forks and cannot reopen a terminal `Closed` page.

The five `arm_exit_group_*host_fork*` VM-free bindings use production ARM
`arm_call` and host `PreparedFork::commit` on one exact KernelContext lifecycle
page/control, with a second live process. The admitted, prepared, and committing
losers retain parent status 7 and release the child record, MM, file table,
reservation and publication claim. The commit-wins binding keeps Closing parked
through backend publication and proves that the live child is subsequently
reparented. The backend-rollback binding retains the claim after kernel
rollback, and the real host Drop path wakes the ARM continuation. HVPatch keeps
the same owned publication scope through its backend transaction; terminal
refusal restores parent outputs and pidfd state before returning EAGAIN (11).
One page-local claim and one gate observation suffice; no population scan,
retry, polling or child cancellation is introduced. Signed HVF execution remains
the director's gate.
