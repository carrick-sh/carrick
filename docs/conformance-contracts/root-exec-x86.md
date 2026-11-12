# Root exec on x86 CPL0 (#2142)

Contract: `process.exec.custody`. Linux authority: `execve(2)` replaces
the calling process image and does not return on success; a missing path
fails with ENOENT and an unrecognized format with ENOEXEC, both leaving the
caller on its old image. Three witnesses in
`carrick-vmm-kvm/tests/cpl0_initial_mm.rs` use the production CPL0
artifact, scheduler pool and dispatcher, and exit with the returned errno
if `execve` returns:

- `production_root_exec_replaces_image_and_runs_static_successor`: the
  successor writes `root-exec-ok\n` and exits zero;
- `production_root_exec_of_a_missing_path_is_enoent`: exit 2;
- `production_root_exec_of_a_non_elf_file_is_enoexec`: exit 8.

All three are intentionally red, `(38, [])` (ENOSYS), until the production
replacement transport is bound. On GitHub main `70604de41` they fail that
way under `just lease gate` with `CARRICK_REQUIRE_KVM=1`.

Red evidence against GitHub main `7799517754055c86c2c7c8d873aaeb82a2873fd3`:
`CARRICK_RUN_ID=2142-red CARRICK_REQUIRE_KVM=1 just lease gate cargo test -p carrick-vmm-kvm --test cpl0_initial_mm production_root_exec_replaces_image_and_runs_static_successor -- --exact --nocapture`
exited 101. The production guest returned `(38, [])` rather than exit zero
with the successor marker. One test ran, failed in 0.17 seconds, and none
were ignored. The durable worker log is `target/2142-evidence/red.log`.

## Existing mechanisms

- `carrick-el1-linux/src/dispatch.rs::native_exec_claimed` deliberately
  claims only fork children. ARM root exec keeps host custody, including
  its live cwd, credentials and descriptor table.
- `carrick-kernel/src/dispatch/proc.rs` decodes root exec and returns
  `DispatchOutcome::Execve`.
- `carrick-runtime/src/vcpu_loop/binding.rs` handles that outcome in the
  persistent production adapter, invoking
  `ThreadRuntimeState::prepare_execve` in `vcpu_loop/exec.rs`. That method
  uses the shared loader, closes clone admission, reserves MM replacement
  and transfers owned completion into the sibling-drain phase. The binding
  and preparation are currently compiled only on macOS/AArch64.
- `carrick-x86-cpl0/src/native_process.rs::ServiceExecMachine` still refuses
  adopt/cancel/settle crossings for fork-child exec (#1093 S4c). Routing
  the root into that service would neither install an image nor preserve
  the root's host resource custody.

## Remaining implementation

Bind x86 root execution to the existing shared runtime transaction, moving
any neutral code out of platform gates rather than copying it. Supply x86
register/entry and page-table mechanics behind the existing interfaces.
Preserve exact task/MM completion authority and predecessor rollback.
Changing `native_exec_claimed` to claim roots is not this binding.

The crossing table currently marks `Execve` and `Execveat` as ARM-only
permanent crossings. Any expansion of those entries is director-owned;
no allowlist change is included in this witness slice. PR #2138's staging
changes are not copied or required by this static witness.

The witness makes no structural-budget, signed ARM, Docker differential or
runtime-ratio claim. Existing custody budgets remain unchanged. Node's
container entrypoint is a separate acceptance layer, still required after
the static witness passes.

## Inventory at main `70604de41` (#2142 x86 venue round)

The shared driver and its ARM venue:

- `carrick-kernel/src/kernel/exec_transaction.rs:132` `RootExecVenue`, with
  `ImageReplacement` (`:115`) and `drive_root_exec` (`:239`).
- `carrick-runtime/src/vcpu_loop/exec.rs:1787` `HvpatchExecVenue`, the only
  venue. Its non-HVPatch arms already use the plain Kernel exec
  (`prepare_one_task_kernel_exec` / `commit_one_task_kernel_exec`,
  `carrick-kernel/src/dispatch/kernel_context.rs:229`, `:236`), which an
  x86 venue can share.
- `fail_past_no_return` still takes a cause string; the neutral
  `ExecPastNoReturn` verdict is #2171, which is open.

What an x86 venue would bind to, and what is missing:

- **Routing.** The x86 ring settles a root exec as a counted ring refusal
  (`carrick-el1-linux/src/dispatch.rs:1275` `settle_unwired_native_service`,
  called from `carrick-x86-cpl0/src/linux_personality.rs:1393`). The host
  side refuses it too (`carrick-runtime/src/prepare.rs:71`, because
  `Execve`/`Execveat` are `x86 = false` in
  `carrick-personality-linux/src/crossing.rs:255`, `:313`). The flip is
  approved to land only with its server.
- **Successor build.** `install_initial_image`
  (`carrick-el1/src/isa/x86/initial_mm.rs:356`) is generic, but its only
  caller, `carrick-x86-carrier/src/initial_boot.rs:154` `load`, is boot-only:
  the boot extent, source root `0x60_0000` and the one-shot
  `table_span::admit_tables`. #1093 S4c's accepted design (on #2149) owns
  the shared build entry (`build_x86_successor`), the shared request
  validator and the stage/reserve step. They are S4c slices b and c and are
  unstarted.
- **Host custody of a new root MM.** The successor needs a new
  `CarrierMemory::install_root`, frame-inventory grants and publication
  replay, and the predecessor's root, aliases and inventory retired. Today
  that exists only for boot (`carrick-vmm-kvm/src/cpl0_boot.rs:1135-1386`)
  and for fork-child birth and retirement (`cpl0_anonymous.rs:1380`,
  `:959`). The adopt/cancel/settle crossings
  (`carrick-x86-cpl0/src/native_process.rs:218` `ServiceExecMachine`) are
  S4c slice d.
- **Root execution identity.** `Kernel::prepare_exec` mints a new `MmId`,
  thread key and execution generation. Every host binding of the x86 root
  pins the boot values: `Cpl0TaskBinding` (`executor/cpl0.rs:1602`),
  `GuestArchBinding::validate_x86`, the carrier CPU's root binding
  (`bind_root`, boot-only), and `ForwardVenue`'s leader rule tied to
  `initial_task.mm`. The executor pool's retarget path
  (`Scheduler::retarget_running_exec`) is fed by an ARM-typed
  `PendingExecReplacement`, and `Cpl0PersistentExecutor` implements neither
  `retarget_loaded_task` nor `mark_exec_transferred`. This is #2142 design
  slice 2 (a venue-typed `PendingExecReplacement` plus
  `Cpl0TaskBindingDirectory::replace_exec`).

An x86 `RootExecVenue` written before S4c slices b to d would either copy
the successor build and crossings into a second path, or fail every
successful exec after the no-return arm. So this round adds only the errno
witnesses. The witnesses stay red; none is a known gap or ignored.
