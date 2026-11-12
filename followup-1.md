# Follow-up: x86 root exec is blocked on #1093 S4c slices b–d and #2142 design slice 2

The x86 `RootExecVenue` round (PR #2146) could not make root `execve` succeed without becoming a second owner of mechanisms the accepted designs assign elsewhere.

- **S4c b/c (the #2149 design):** the shared `build_x86_successor` CPL0 entry runs `install_initial_image` outside boot (`initial_boot.rs:154` is boot-only: boot extent, source root `0x60_0000`, one-shot `admit_tables`), plus the shared request validator and the host stage/reserve step (frame grants with inventory identities, image-row import).
- **S4c d:** the adopt/cancel/settle crossings (`native_process.rs:218`), including host `CarrierMemory::install_root` for the successor and retirement of the predecessor root, aliases and inventory.
- **#2142 slice 2:** a venue-typed `PendingExecReplacement` (today it holds the HVPatch `Stage1MmLease`) and `Cpl0TaskBindingDirectory::replace_exec`. `Cpl0PersistentExecutor` also needs `retarget_loaded_task` and `mark_exec_transferred`. `CarrierCpu::bind_root`, `Cpl0TaskBinding` and `ForwardVenue`'s `initial_task.mm` leader rule must accept the post-exec `MmId`, thread key and generation that `Kernel::prepare_exec` mints.

**Proposal:** sequence S4c b → c → d and #2142 slice 2 first. Then the x86 venue plus the crossing flip (rows 221/281) turns the three red witnesses in `cpl0_initial_mm.rs` green. The root's build should call the same `build_x86_successor` from its forward-return path, not a root-only copy.
