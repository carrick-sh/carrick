# x86 host Exec service (#1093 S4c slice c)

Contract: `process.exec.custody`. Linux authority: `execve(2)`. A failed
preparation returns its errno and leaves the caller on its old image:
E2BIG (7) when argv and envp exceed the argument limit, ENOEXEC (8) for an
unrecognized format, ENOENT (2) for a missing file or interpreter. This
slice builds the host half of x86 native-child exec, on the design accepted
on #2149. Before the ring arms an exec, the host loads the successor and
reserves everything the CPL0 build after the arm consumes.

The ring does not route x86 exec to this service yet, and the adopt, cancel
and settle crossings stay refusals (slice d). So no x86 exec is
guest-reachable, `native_fork_child_execs_static_successor` (#2149) is still
red, and no work budget changes.

## What the service does

1. **Load** (`carrick-runtime/src/runtime/exec.rs:146`
   `prepare_native_x86_exec_image`). The staged payload goes through the
   shared request parse (`prepare_native_exec`, `:169`): execve or execveat,
   path or fexecve descriptor, and the caller's sealed access. It then goes
   through the shared resolver (`resolve_exec_target`, `:575`): resolution,
   execute permission, FAN_OPEN_EXEC and up to four `#!` interpreters.
   `load_x86_exec_image` (`:827`) charges the arguments that the `#!` chain
   left through the shared `ExecArgumentCharge`
   (`carrick-core-abi/src/service.rs:380`). That gives E2BIG before the image
   is read, in Linux's order. It then parses with the boot loader's own
   `ElfProgram::load`; `exec_image_errno` maps failures to ENOEXEC, ELIBBAD,
   ENOENT or EIO.
2. **Check** (`carrick-x86-cpl0-host/src/cpl0_exec.rs:83`
   `X86ExecImage::from_program`). `prepare_x86_elf` and slice b's
   `validate_image_rows` refuse with ENOEXEC. The sealed stack pointer comes
   from the editor's `build_initial_stack`, which places AT_RANDOM by
   position, so the build after the arm lands on it. Arguments that Linux
   accepts but the 64 KiB built stack cannot hold are unrouted (ENOSYS),
   never a false E2BIG.
3. **Reserve and import** (`cpl0_exec.rs:452` `stage_x86_exec`), under the
   exec lock order:
   - the preparations (one per closed successor);
   - the successor's root: `import_x86_image_rows` plus the built stack,
     left unadmitted because the adopter's `prepare_adoption` finishes the
     import;
   - the fork stock: exactly `image_frame_demand`'s tables, where the first
     table is the sealed root;
   - then the data frames under boot's `InitialInventory`.

   The preparation is retained in the carrier custody until slice d adopts
   or cancels it. `release_x86_exec` returns an unused one whole.
4. **Not now**. When the stock cannot grant the tables, the service aborts
   the import and keeps nothing reserved. `ParkedX86Exec` keeps the owned
   operation and the `StockRelease` it observed before the refusal. In the
   same fork-stock phase that refused, the caller's `StockReleaseWake` is
   enrolled on that release (`ForkStock::enrol_release`), and only then
   probed once: a return that already landed is delivered at enrolment.
   The holder's next table return delivers the wake exactly once, and one
   probe then hands the operation back to rerun. The parked exec holds no
   lock, no reservation and no errno; nothing polls. A
   Busy successor root is a broken invariant, not contention: the root is
   closed, and its only other owner (the ring's successor slot) is parked in
   this very call. Any other root refusal gives ENOMEM before the arm, which
   is how the AArch64 service answers it.

## Existing-mechanism inventory (no second loader)

- **Boot inventory transaction:** `InitialInventory`
  (`carrick-x86-cpl0-host/src/cpl0_boot.rs:655`) and its `stage` (`:678`).
  The exec frames reuse it unchanged (`CarrierExecFrames`, `cpl0_exec.rs`).
- **Fork stock:**
  - `FORK_STOCK_PORT` (`carrick-el1-abi/src/fork_stock.rs:25`; the guest
    crossing is at `carrick-x86-cpl0/src/native_process.rs:453`);
  - slice b's `take_successor_table_runs` and `reserve_successor_tables`
    (`carrick-hal/src/fork_stock.rs:881`, `:1945`);
  - this slice's `StockRelease` (`:944`), `table_release` (`:1912`), and
    the release's waiters: `StockReleaseWake` (`:952`), `enrol_release`
    (`:1927`) and the delivery on every table return (`:1002`).
- **Wait and wake (#2205 review):**
  - the ring's owner wait, `ServiceTicket::complete_wait`
    (`carrick-core-abi/src/service.rs:1987`, used by the x86 native
    service at `cpl0_native_service.rs:316`), acknowledges a service
    ticket with a `PortalWaitCause` (`carrick-core-abi/src/mm/transfer.rs:66`)
    and producer revision. The stock has no cause there yet, and routing
    one is ring work for slice d, which hands the ring continuation to
    this host wake;
  - the host-side enrol-then-probe shape is `PhysicalMemoryWait::enroll`
    (`carrick-guest-mem/src/prepared.rs:67`): an owned
    `Arc<dyn Fn() + Send + Sync>` wake, enrolled before the readiness
    probe. `StockReleaseWake` is that wake. The stock is exclusively owned
    by the carrier custody, not shared behind an `Arc`, so it enrols the
    wake itself instead of implementing that trait.
- **Image import:**
  - `import_x86_image_rows` and `x86_image_rows` (`cpl0_boot.rs:588`,
    `:562`) moved here from KVM boot
    (`carrick-vmm-kvm/src/cpl0_boot.rs:1466` now calls them), after #2149's
    `import_x86_image_regions`;
  - boot keeps its own `finish_import`.
- **Validator and frame runs:** slice b's `validate_image_rows` and
  `frame_runs` (`carrick-core-abi/src/successor_image.rs:95`, `:202`).
- **Editor:**
  - `install_initial_image`
    (`carrick-el1/src/isa/x86/initial_mm.rs:387`);
  - its demand, `image_frame_demand` (`:323`), which sits beside it;
  - `build_initial_stack` (`:114`);
  - slice b's `build_x86_successor`
    (`carrick-x86-carrier/src/initial_boot.rs:391`) and `X86PrepareCross`
    (`carrick-x86-cpl0/src/exec_successor.rs:75`), which slice d drives.
- **Closed successor slot:** `prepare_closed_exec_successor_slot` and
  `prepare_adoption` (`carrick-el1-linux/src/exec_successor.rs:152`, `:84`).
- **Lock order:** `ExecCrossingOrder` and the new `ExecPhaseOwner`
  (`carrick-hal/src/exec_lock_order.rs:163`; #2192).
- **The ARM host exec service this mirrors:**
  - `NativeService::prepare_exec` and `publish_exec_prepared`
    (`carrick-vmm-hvf/src/metadata_grant/native_service.rs:334`, `:377`);
  - `prepare_native_exec_successor`
    (`carrick-vmm-hvf/src/trap/execve_rebuild.rs:436`);
  - the loader `NativeExecHostService` impl
    (`carrick-runtime/src/runtime/exec.rs:284`), with
    `load_execve_image` (`:677`);
  - the row import `prepare_native_successor`
    (`carrick-kernel/src/dispatch/mem/native_successor.rs:206`).

  The ARM service answers no Busy: its failures are terminal codes. The
  x86 reservation from the shared fork stock is the new contention, and
  this slice parks it.
- **Root boot parse:** `ElfProgram::load(&bytes, 62, …)`
  (`carrick-runtime/src/prepare.rs:1510`). The exec loader uses the same
  call.
- **Still unwired:**
  - `cpl0_native_service.rs:305` refuses `ServiceOperation::Exec` as an
    unsupported operation;
  - the ring settles a child's exec as staged ENOSYS
    (`carrick-el1-linux/src/dispatch.rs:1292`).

  Both belong to slice d, with the crossings.

## Witnesses

The red evidence for each is on its own commit.

- `carrick-x86-cpl0-host::cpl0_boot::exec_service::tests::`
  - `exec_service_stages_a_static_successor`;
  - `exec_service_refuses_with_exact_execve_errnos`;
  - `a_pending_fork_parks_the_exec_until_its_release_wakes_it_then_stages`.
    This is Busy once, then success, behind a real pending fork loan. The
    loan's abort runs on another thread, and the test waits up to 5 s for
    the enrolled wake; nothing probes the parked exec before it is woken.

  All three are VM-free, over a real fork stock, a frame inventory, and the
  CPL0 zone and reservation table in `TestEl1Region`.
- `carrick-runtime::runtime::exec::tests::native_child_x86_exec_loads_its_successor_through_the_shared_loader`
  covers path, `#!` and fexecve, plus 2, 8 and post-`#!` 7. A `#!` script
  whose interpreter is executable non-ELF text gives 8 alone, and 7 with
  an oversized expansion, so E2BIG comes before the image is parsed.
- `carrick-hal::fork_stock::tests::{a_pending_fork_holds_the_stock_until_its_abort_releases_the_successor,only_returned_tables_advance_the_stock_release,an_enrolled_waiter_is_woken_once_by_the_holder_return}`.
- `carrick-el1::isa::x86_initial_mm::tests::image_frame_demand_is_exactly_what_the_editor_takes`.
  For each of four layouts, the demand builds and one table fewer is
  refused.
- `carrick-hal::exec_lock_order`: the static-mutex counterexample is a
  `compile_fail` doctest, and `mutex_owners_are_locked_only_for_their_own_phase`.
- KVM (under `just lease gate`, `CARRICK_REQUIRE_KVM=1`):
  `carrick-vmm-kvm::cpl0_initial_mm::production_exec_service_stages_parks_and_reruns_a_successor`.
  This runs on a booted production carrier's own fork stock, frame
  inventory, memory and CPL0 tables. The held tables return on another
  thread, and the parked exec's enrolled wake must arrive within 5 s before
  it is probed. It is a carrier fixture, not a signed result.

No runtime-ratio, signed-gate or Docker differential claim is made.
