# Follow-up: x86 RootExecVenue publishes the CPL0 replacement (#2142 slice 4)

PR #2191 adds `PendingExecReplacement::cpl0`, `Cpl0TaskBindingDirectory::replace_exec`,
`Cpl0PersistentExecutor::retarget_loaded_task` and `ProductionCpuLease::retarget_root_exec`.
Nothing in production publishes a CPL0 replacement yet. The x86 `RootExecVenue` must:
- build the successor image and root (#1093 S4c slices b-c) before publishing;
- publish `PendingExecReplacement::cpl0(committed, successor_arch)` into the submission context's `exec_replacement`, with the successor's real new root GPA (the KVM witness reuses the predecessor root only because no successor build exists);
- retire the predecessor root, aliases and inventory (S4c slice d). `Cpl0HostCustody::initial_sources` stays keyed on the boot root context: after the rebind, `sources_mut` for the successor MM fails closed ("initial source incarnation changed") until slice d moves or retires those sources.
