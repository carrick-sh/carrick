# Bootstrap control layout and root admission (#1400)

`x86.mm.initial-image` requires stopped root admission to retain independent
control records for both bootstrap CPUs. The metadata arrays use the shared
CPL0 host coordinator's stride. Each record must fit that stride, remain
aligned, and end before the next array. A control's reset must not modify its
peer. These are fixed two-CPU layout bounds; no scan, retry, allocation growth
or guest syscall semantics change is introduced.

The VM-free binding
`bootstrap_metadata_records_are_disjoint_before_root_binding` checks the
production offsets and record sizes before making typed references, then
initializes both provisional controls in retained guest RAM and resets each
through `ThreadControlSlot::reset_for_host_birth`. Root identity publication
must preserve the peer, and resetting the peer must preserve the root.
The existing KVM initial-image and `cpl0_entry` fixtures supply execution
coverage through `bind_initial_task_identity` and the prepared pool runner.

## Onset attribution

Adjacent main push receipts bracket the first binding failure:

- [Run 40161698087](https://github.com/carrick-sh/carrick/actions/runs/40161698087)
  at `0fde9d2756551c7bf96b91638a11d9dc6016c88c`, artifact
  `kvm-logs-0fde9d2756551c7bf96b91638a11d9dc6016c88c-1`:
  `cpl0_entry` 46 passed, zero failed, zero occurrences of the binding error.
- [Run 40164238536](https://github.com/carrick-sh/carrick/actions/runs/40164238536)
  at `2da501dcf0cc81aae517e038bb72dbfee1e1a716`, artifact
  `kvm-logs-2da501dcf0cc81aae517e038bb72dbfee1e1a716-1`:
  `cpl0_entry` 44 passed, two failed; the full KVM test log contains 94
  occurrences of `control slot still owned by graph`.
- The following [run 40174732309](https://github.com/carrick-sh/carrick/actions/runs/40174732309)
  at `82409ffe871f41912334324e048e824ffca771a6` repeats those counts.

The first failing push carries `f2e2b7e7b`, which adds `ServiceCell` and
changes the asserted `ThreadControlSlot` size from 256 to 384 bytes. The
bootstrap stride remained 256. Initializing the second control consequently
overwrites the first control's tail, including service state. The error text
from root admission collapses reset failures to a graph-ownership message;
it does not prove that the graph actually retained the control. The fix
preserves the reset refusal and derives the stride from the control ABI,
with compile-time bounds for all three arrays.

On admitted main, the VM-free witness fails with
`record at 0xa000: 384 bytes exceed stride 256`. It passes after deriving the
stride. This proves the binding precondition; it does not claim a green KVM
lane, anonymous-memory execution, signed HVF acceptance, or a runtime ratio.
Those require the corresponding hardware receipts.
