# Live native stock crossing authentication (#1758)

The `process.native.arm-admission` fixture uses the same HAL
`GrantExecution::from_stopped_lane` authority as HVF's stopped-execution
reconstruction. Each loan, reservation, commit, abort and descriptor
settlement reads the current execution binding, installed MM, root and root
incarnation. The simulated CPU retains an atomic root register, updated at
scheduler root switches. The loan retains its original identity only in the
production stock owner, where a later
mismatch must refuse rather than authorize settlement.

The two-process witness first forks through the native runtime and retains
both real process bindings. A further child goes through production MM
preparation, physical custody reservation and MM commit. Moving the parent's
root incarnation before birth settlement must produce the production
`StaleExecution` verdict and retain custody for quarantine; the unchanged
control commits exactly once. This does not claim that generation movement
is the cause of #1742, or change production refusal policy.

The witness runs VM-free, without guest instructions or host processes.
Signed Go population evidence, hardware-root observation and end-to-end
performance remain director-owned. Existing semantic and work budgets are
unchanged; extracting the HVF check into HAL preserves its predicates.

The red control restores the old behavior at the commit crossing by passing
the pending stock owner's loan-time execution instead of the freshly observed
lane. The witness fails at `production refuses the stale loan: ()`: the stale
settlement was accepted. Restoring the live execution makes that schedule
refuse deterministically. Separate live-lane checks cover task, thread, MM,
root and generation changes; the two-process control also refuses a parent's
attempt to settle its child's descriptor receipt.
