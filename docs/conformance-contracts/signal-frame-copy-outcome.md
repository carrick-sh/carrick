# Signal-frame copy outcome migration (#1737)

The signal-frame push keeps `kernel.el1.signal-delivery-owner` semantics and
work unchanged. `SignalBackend::setup_signal_frame` accepts `CopyOutcome`;
ARM and x86 take the former true branch only for `Done`. `Fault` and `NotYet`
take the former false branch, including x86's first-copy short circuit.
Selection, mutation order, masks, terminal decisions and routing are unchanged.
No continuation, supply attempt, park or retry is added.

`signal_delivery::altstack_tests::production_signal_frame_refusal_keeps_main_fault_branch`
uses the production native entry, shared syscall-return delivery owner and ARM
codec. The physical test service injects the not-yet-backed supply refusal
(`Unsupported`, the existing `UnsupportedSupply` mapping) and address fault
(`Fault`) at the unchanged copy boundary. Each case requires one frame-sized
copy attempt at the selected stack address, no successful bytes, unchanged
registers and the existing terminal route. It reduces the service refusal;
it does not prove real stage-1 supply or signed guest execution. The existing
successful delivery witness covers `Done`. Baseline comparison uses the same
witness with the admitted main implementation, where both errors made
`copy_signal_frame(...).is_ok()` false.

The guest-copy census recognizes direct boolean copy methods and named copy
result collapses, but does not count boolean callbacks inside signal-frame
methods. This slice retires that callback without changing census ceilings.
The remaining `arm_signal.rs` collapse belongs to signal-frame restoration,
which is outside this slice. Exit cleanup, clone TIDs and identity copyouts
remain separate work. Signed ARM and real KVM execution retain their existing
higher-layer requirements.
