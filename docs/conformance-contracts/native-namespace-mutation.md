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
`kernel.native.host-file-venue` owns existing typed file calls;
`kernel.fs.directory-copyout` owns getdents64 cursor and copyout authority.
The new contract does not weaken any of their budgets.

The director's signed reference reports six missing calls (mkdirat, unlinkat,
renameat, symlinkat, readlinkat, fchmodat), with statx, getdents64, openat
O_CREAT and write working. VM-free routing alone cannot repeat those host
venue results. Successful child exec, signed population/venue attribution,
image/artifact identity and original CLI regression remain open evidence.

Slice 2 must settle wire layout review, both ISA bindings, VFS mutation
ownership and cross-crate lock order before changing routing. Its first
witness must require successful mkdirat here and fail on this baseline;
then prove caller umask/dirfd, directory identity and parent visibility,
EEXIST/EFAULT and both filesystem venues. No raw syscall fallback or carrier
ambient credentials are licensed. Cancellation after a committed mutation
must settle once without replay. Budgets for staging and resolution must be
chosen from the existing owner algorithm, before measuring a candidate.
