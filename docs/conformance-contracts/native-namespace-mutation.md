# Native namespace mutation baseline (#1335, slice 1)

`kernel.native.namespace-mutation` binds the missing typed namespace service
before any behavior change. Linux owns the semantics; a forward allowlist
entry supplies neither child authority nor a host task.

The production ARM native entry fixture admits a root, forks live children
through real stock reservation/publication, and dispatches six ordinals from
both children. They retain distinct fork-time cwd, umask and file tables.
Each call must complete with errno 38, increment served/refused exactly once,
and publish no carrier service notice. This is a defect census, not a claim
that ENOSYS is correct Linux behavior. The existing unclaimed-call negative
control remains unchanged.

Shared boundaries retain their own contracts:
`process.native.arm-admission` owns admission and exact task binding;
`kernel.el1.thread-lifecycle` owns [fork-child admission](native-fork-child-admission.md);
`kernel.native.host-file-venue` owns existing typed file calls;
`kernel.fs.directory-copyout` owns getdents64 cursor and copyout authority.
The new contract does not weaken any of their budgets.

The fixture calls native syscall dispatch and the shipping unclaimed-capture
policy separately. It does not install a simulated guest IPC venue or host
reply. Slice 2 needs a typed capture/venue binding in this harness before a
successful namespace operation can be proved; changing an expected result to
zero alone cannot provide that binding.

The director's signed reference reports six missing calls (mkdirat, unlinkat,
renameat, symlinkat, readlinkat, fchmodat), with statx, getdents64, openat
O_CREAT and write working. VM-free routing alone cannot repeat those host
venue results. The existing successful child exec, adoption, exit, reap and
slot-reuse fixture now dispatches the same six calls after adoption, retaining one counted refusal
and no carrier notice per call. Its process context is the shared VM-free x86
owner with an ARM syscall frame; it does not execute an ELF or install ARM
hardware page tables. Signed population/venue attribution,
image/artifact identity and original CLI regression remain open evidence.

Slice 2 must settle wire layout review, both ISA bindings, VFS mutation
ownership and cross-crate lock order before changing routing. Its first
witness must require successful mkdirat here and fail on this baseline;
then prove caller umask/dirfd, directory identity and parent visibility,
EEXIST/EFAULT and both filesystem venues. No raw syscall fallback or carrier
ambient credentials are licensed. Cancellation after a committed mutation
must settle once without replay. Budgets for staging and resolution must be
chosen from the existing owner algorithm, before measuring a candidate.

The measured VM-free baseline is two attempts, two completions and two ring
refusals per ordinal in the two-child fixture; the exec successor adds one
attempt, completion and ring refusal per ordinal. Both require zero carrier
notices. This covers 18 completed calls, not a signed workload population.
No mutation, carrier venue success or runtime ratio was measured.

Red-first semantic check: temporarily requiring mkdirat success in the same
production-entry fixture fails at child 0, ordinal 34: actual -38, required 0.
The committed assertion restores the explicit defect baseline. This red result
is not a CLI witness and does not replace slice 4's process-boundary check.

The lineage assertion was separately red: the two-child fixture recorded two
total ring refusals but zero descendant refusals. Final unclaimed-child
capture now uses `Counters::record_refusal` with descendant origin and ring
venue. Both fixtures require all refusals in that descendant population and
zero carrier refusals. The existing unclaimed-ordinal negative control keeps
its errno and total count and now checks the lineage too. This diagnostic
correction changes neither routing nor the six missing namespace services.
