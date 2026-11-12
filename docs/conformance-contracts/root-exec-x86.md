# Root exec on x86 CPL0 (#2142)

Contract: `process.exec.custody`. Linux authority: `execve(2)` replaces
the calling process image and does not return on success. The root witness
execs a static successor which writes `root-exec-ok\n` and exits zero. It
uses the production CPL0 artifact, scheduler pool and dispatcher. Returning
ENOSYS exits 38 and fails the assertion; the witness is intentionally red
until the production replacement transport is bound.

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
