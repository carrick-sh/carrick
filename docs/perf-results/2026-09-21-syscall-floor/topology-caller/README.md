# Caller-qualified topology trace

One eight-process Node app-smoke wave on the frozen discard-edges CLI, SHA256
3e2521515cc0af0324dbd2f7639bd43ea27fc324dd84e1dbd69a4e508e780972.
All8 markers and GROUP_DONE, root exit, return0, cleanup0, balanced operation
phases and no reported errors/drops. This high-perturbation stack capture is not
comparable to untraced timing; its wait sums overlap and are not removable time.

Source qualification found two probe emitters: FrameRegistryGuard and kernel
MM transaction scopes. Nonzero acquisition durations come from the former;
MM transaction depth acquisition is nonblocking and explicitly emits zero.
The earlier warning about mixed hold scopes remains necessary, but nonzero
acquisition waits should not be attributed to an unidentified MM pause lock.

Raw stack addresses were resolved against the exact binary. USDT nop address
0x100d4f404 (otool) observed at0x10340f404 establishes slide0x26c0000 and image
load0x1026c0000. atos maps the first frame to hvpatch_topology_lock+36. Otool
also proves the otherwise generic core::mem::drop return0x100499ddc and terminal
return0x1004d62a4 call MmTransactionGuard::drop. All stack classes now resolved;
these address qualifications are specific to this artifact/capture.

In this perturbed capture, frame-registry hold totals were materialization140.8ms,
alias unmap121.4ms, COW25.6ms, exec1.0ms. Exec's separate MM transaction scope
was1174.8ms; counting that as exec holding the registry would be wrong. Do not
add the nested totals or use these durations as a predicted speedup.
The main materialization stacks are first-touch resolution -> protect_range ->
ensure_sparse_mmap_backing, not ordinary guest mprotect attribution. Unmap stacks
lead to guest munmap. Source/call sites plus a paired intervention are needed
before treating either as the causal longest pole.

The follow-up fault-window screen is in ../fault-window-screen. It reduced
materialization counts without reducing concurrent workload time. Next audit
private fresh-frame publication separately from shared-file deduplication:
InventoryBackingIdentity::Private and PrivateFileView are unique and never
looked up globally; stage_mapping_in reuses frames only for SharedFile or an
explicit inherited_frame. This is a hypothesis for independent publication,
not authorization to remove guards without exact-owner and retirement proof.
