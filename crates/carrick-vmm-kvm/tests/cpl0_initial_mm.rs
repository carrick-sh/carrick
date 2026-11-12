//! Live KVM witness: a static x86 ELF enters through the shared CPL0 MM owner.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used, clippy::panic)]

use carrick_mem::x86_initial_image::prepare_x86_elf;
use carrick_vmm_kvm::cpl0_boot::{Cpl0Carrier, InitialReservationLimits, InitialTaskBinding};
#[path = "common/kvm_pool_fixture.rs"]
mod kvm_pool_fixture;
use carrick_x86::cpl0_entry::OBSERVE_INITIAL_MM;
use kvm_pool_fixture::{physical_inventory, run_pool_fixture, run_pool_fixture_with};
use std::path::PathBuf;

/// Only CPU 0 (the loaded lane) may schedule the root and its inherited children.
const ROOT_AFFINITY_LOADED: u64 = 1;
/// Only the idle peer (CPU 1) may schedule the root once it leaves CPU 0;
/// its forked children inherit the mask, so EL1 queues them only there.
const ROOT_AFFINITY_IDLE_PEER: u64 = 2;

fn try_run_pool_fixture_with_root_affinity(
    elf: &[u8],
    max_exits: usize,
    affinity: u64,
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_kernel::run_result::RuntimeError,
> {
    let program = carrick_mem::elf::ElfProgram::load(elf, 62, &|_| None).expect("ELF program");
    kvm_pool_fixture::try_run_program_with_root_affinity(&program, max_exits, affinity, |_| {})
}

fn try_run_pool_fixture_with_loaded_pre_entry_hook(
    elf: &[u8],
    loaded_exits: usize,
    idle_exits: usize,
    affinity: u64,
    hook: impl Fn(&std::sync::atomic::AtomicBool, &carrick_vmm_kvm::KvmKickHandle)
    + Send
    + Sync
    + 'static,
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_kernel::run_result::RuntimeError,
> {
    let program = carrick_mem::elf::ElfProgram::load(elf, 62, &|_| None).expect("ELF program");
    let image = prepare_x86_elf(&program).expect("x86 ELF program");
    let extent =
        Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("bounded initial extent");
    // Boot and publish the root's ring descriptor table as production does
    // (`prepare.rs`), so a child's write stages on its own fd-core table.
    let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    let ipc = carrick_kernel::kernel::continuation::ipc::host_window_backing(&dispatcher);
    let mut carrier = Cpl0Carrier::boot_production(physical_inventory(), extent, ipc)
        .expect("production KVM image");
    let root = dispatcher.capture_one_task_context().expect("issued root");
    root.resources()
        .files()
        .publish_ipc(
            root.kernel().ipc().expect("IPC owner"),
            carrick_kernel::kernel::objects::IpcTableMapBinding::Retained(
                carrier.ipc_table_map().expect("retained descriptor map"),
            ),
        )
        .expect("publish exact table");
    root.kernel()
        .bind_initial_birth_source(
            carrier
                .birth_serial_source()
                .expect("stopped carrier source"),
        )
        .expect("bind initial carrier birth and MM source");
    carrier
        .bind_initial_task_identity(InitialTaskBinding {
            task: root.task().key(),
            mm: carrick_hal::MmGeneration::new(root.shared().mm().id().nonzero()),
            thread: carrick_sched_core::ThreadIdentity {
                tid: carrick_el1_abi::El1TaskId::from_linux_tid(root.thread().key().tid.raw())
                    .raw(),
                serial: root.thread().key().serial.raw(),
                mm: 0,
                file_table: root.resources().files().id().raw(),
                generation: carrick_kernel::kernel::objects::ExecutionGeneration::INITIAL.raw(),
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity,
                lifecycle_page: 0,
                control_slot: 0,
            },
        })
        .expect("bind issued root");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("initial guest MM");
    carrick_runtime::prepare::try_run_prepared_kvm_pool_with_loaded_pre_entry_hook(
        carrier,
        root,
        dispatcher,
        loaded_exits,
        idle_exits,
        std::sync::Arc::new(hook),
    )
    .map_err(|failure| failure.error)
}

fn try_run_pool_fixture_with_lane_exit_budgets(
    elf: &[u8],
    loaded_exits: usize,
    idle_exits: usize,
    affinity: u64,
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_kernel::run_result::RuntimeError,
> {
    try_run_pool_fixture_with_loaded_pre_entry_hook(
        elf,
        loaded_exits,
        idle_exits,
        affinity,
        |_, _| {},
    )
}

fn try_run_pool_fixture_with_typed_failure(
    elf: &[u8],
    max_exits: usize,
    affinity: u64,
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_runtime::prepare::PreparedKvmPoolFailure,
> {
    let program = carrick_mem::elf::ElfProgram::load(elf, 62, &|_| None).expect("ELF program");
    kvm_pool_fixture::try_run_program_with_root_affinity_typed(
        &program,
        max_exits,
        affinity,
        |_| {},
    )
}

const ELF_X86_64_MACHINE: u16 = 62;
const ELF_LOAD_VA: u64 = 0x400000;
const X86_SYS_WRITE: u8 = 1;
const X86_SYS_EXIT_GROUP: u8 = 231;

// Production child entropy service, including CPL0 entry and host completion.
#[test]
fn serial_host_native_child_getrandom_default_returns_eight_bytes() {
    native_child_entropy_witness(
        "serial_host_native_child_getrandom_default_returns_eight_bytes",
        &[],
    );
}

#[test]
fn serial_host_native_child_getrandom_nonblock_returns_eight_bytes() {
    native_child_entropy_witness(
        "serial_host_native_child_getrandom_nonblock_returns_eight_bytes",
        &["-DENTROPY_FLAGS=1"],
    );
}

#[test]
fn serial_host_native_root_getrandom_returns_eight_bytes() {
    native_child_entropy_witness(
        "serial_host_native_root_getrandom_returns_eight_bytes",
        &["-DENTROPY_ROOT=1"],
    );
}

#[test]
fn serial_host_native_child_getrandom_readonly_returns_efault() {
    native_child_entropy_witness(
        "serial_host_native_child_getrandom_readonly_returns_efault",
        &["-DENTROPY_READONLY=1"],
    );
}

#[test]
fn serial_host_native_child_getrandom_cow_preserves_parent() {
    native_child_entropy_witness(
        "serial_host_native_child_getrandom_cow_preserves_parent",
        &["-DENTROPY_COW=1"],
    );
}

#[test]
fn serial_host_native_child_getrandom_lazy_output_returns_eight_bytes() {
    native_child_entropy_witness(
        "serial_host_native_child_getrandom_lazy_output_returns_eight_bytes",
        &["-DENTROPY_LAZY=1"],
    );
}

#[test]
fn serial_host_native_child_getrandom_boundary_returns_accessible_prefix() {
    native_child_entropy_witness(
        "serial_host_native_child_getrandom_boundary_returns_accessible_prefix",
        &["-DENTROPY_PREFIX=1"],
    );
}

#[test]
fn serial_host_native_root_getrandom_lazy_output_returns_eight_bytes() {
    native_child_entropy_witness(
        "serial_host_native_root_getrandom_lazy_output_returns_eight_bytes",
        &["-DENTROPY_ROOT=1", "-DENTROPY_LAZY=1"],
    );
}

/// #1808: a production x86 fork child's relative nanosleep parks on the
/// shared sleep owner and its timer returns 0; it is never forwarded.
#[test]
fn serial_host_native_child_nanosleep_returns_zero() {
    native_child_sleep_witness("serial_host_native_child_nanosleep_returns_zero", &[]);
}

#[test]
fn serial_host_native_child_zero_nanosleep_returns_zero() {
    native_child_sleep_witness(
        "serial_host_native_child_zero_nanosleep_returns_zero",
        &["-DSLEEP_ZERO=1"],
    );
}

/// x86 CPL0 defines no guest-visible monotonic epoch (no vDSO, a raw RDTSC
/// counter), so even forkexecstorm's already expired absolute
/// CLOCK_MONOTONIC deadline keeps the counted ENOSYS refusal (#1808).
#[test]
fn serial_host_native_child_absolute_clock_nanosleep_is_refused() {
    native_child_sleep_witness_with_exit(
        "serial_host_native_child_absolute_clock_nanosleep_is_refused",
        "native_child_sleep.S",
        &["-DSLEEP_ABSOLUTE=1"],
        218,
    );
}

/// The routed x86 child `clock_nanosleep` answers each clock and flag class
/// with the errno number Linux gives (or the counted refusal where the ring
/// has no authority); the fixture's table lists the rows.
#[test]
fn serial_host_native_child_clock_nanosleep_clocks_and_flags_match_linux() {
    native_child_sleep_witness_with_exit(
        "serial_host_native_child_clock_nanosleep_clocks_and_flags_match_linux",
        "native_child_sleep_witness.S",
        &["-DSLEEP_CLOCK_TABLE=1"],
        8,
    );
}

fn native_child_sleep_witness(test: &str, flags: &[&str]) {
    native_child_sleep_witness_with_exit(test, "native_child_sleep.S", flags, 8);
}

fn native_child_sleep_witness_with_exit(test: &str, fixture: &str, flags: &[&str], exit: i32) {
    // Bounded in a child test process like the entropy witness: a lost timer
    // wake must fail, never hang CI.
    const CHILD: &str = "CARRICK_SLEEP_WITNESS_CHILD";
    if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new(test)) {
        let output = std::process::Command::new("timeout")
            .args(["--kill-after=1", "10"])
            .arg(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                test,
                "--include-ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, test)
            .output()
            .expect("bounded native sleep witness");
        // The child must have run exactly this witness, not filtered it out.
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed"),
            "bounded child witness: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }
    let elf = native_exit_fixture_with_flags(fixture, flags);
    let outcome = run_pool_fixture(&elf, 128);
    assert_eq!(
        outcome.run.exit_code, exit,
        "child sleep result (218 means ENOSYS; 100 + n is errno n or table row n)"
    );
    assert!(outcome.run.stdout.is_empty());
    assert!(outcome.run.stderr.is_empty());
}

fn native_child_entropy_witness(test: &str, flags: &[&str]) {
    // A parked guest need not consume the pool's exit budget. Bound the whole
    // fixture in a separate test process so a lost child wake cannot hang CI.
    // timeout owns that process group; KVM workers are threads in that process.
    const CHILD: &str = "CARRICK_ENTROPY_WITNESS_CHILD";
    if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new(test)) {
        let output = std::process::Command::new("timeout")
            .args(["--kill-after=1", "10"])
            .arg(std::env::current_exe().expect("current test executable"))
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CHILD, test)
            .output()
            .expect("bounded native entropy witness");
        assert!(
            output.status.success(),
            "bounded child witness: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }
    let elf = native_exit_fixture_with_flags("native_child_entropy.S", flags);
    let outcome = run_pool_fixture(&elf, 128);
    assert_eq!(
        outcome.run.exit_code, 8,
        "child getrandom result (218 means ENOSYS)"
    );
    assert!(outcome.run.stdout.is_empty());
    assert!(outcome.run.stderr.is_empty());
}

/// #1845 single-lane check for x86 `pipe2`. The production CPL0 lane serves
/// a native `pipe2` in ring, through the shared constructor in
/// `carrick-el1-linux`, and that constructor binds no readiness lane on x86
/// (the native dispatch has no scheduler zone). So the readiness-lane lock
/// whose contention #1952 turns into a retained host create is never taken
/// by x86 `pipe2`: a live host party of the recycled slot's previous
/// incarnation holds both of its lanes in the production native zone for
/// the whole run, and `pipe2` still returns the pair (3, 4) on the popped
/// slot without waiting for it. The fixture then closes both
/// ends: a release's wake for a lane never bound to the new incarnation
/// (#2082) takes no lock either, so the previous incarnation's holder cannot
/// stall it. Write/read on that pair is #1756.
#[test]
fn native_pipe2_takes_no_readiness_lane_lock_held_by_a_previous_incarnation() {
    use carrick_el1_abi::ipc::{IpcBacking, pipe::End};
    const HOLD_BOUND: std::time::Duration = std::time::Duration::from_secs(20);
    let elf = native_exit_fixture("native_pipe2.S");
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    let owner = dispatcher
        .capture_one_task_context()
        .expect("issued root")
        .kernel()
        .ipc()
        .expect("IPC owner");
    // Free one pipe so the guest's create pops its slot (LIFO) as the next
    // incarnation, exactly as a released pipe's slot is recycled.
    let old = owner.create_pipe(65536).expect("previous incarnation");
    for end in [End::Reader, End::Writer] {
        owner
            .release(IpcBacking::Pipe { object: old, end }.encode())
            .expect("release previous incarnation");
    }
    let hold = std::sync::Mutex::new(None);
    let started = std::time::Instant::now();
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        128,
        ROOT_AFFINITY_LOADED,
        |carrier| {
            *hold.lock().unwrap() = Some(
                carrier
                    .fixture_hold_ipc_readiness_lanes(old, HOLD_BOUND)
                    .expect("hold both lanes of the previous incarnation"),
            );
        },
        dispatcher,
    )
    .map_err(|failure| failure.error)
    .expect("native pipe2 run");
    let elapsed = started.elapsed();
    let hold = hold.lock().unwrap().take().expect("holder started");
    assert!(
        hold.release(),
        "the holder gave up at its {HOLD_BOUND:?} bound before pipe2 returned \
         (run took {elapsed:?}): x86 pipe2 waited on a held readiness-lane lock"
    );
    assert_eq!(
        outcome.run.exit_code, 7,
        "pipe2 fixture status (38 is ENOSYS, 90 a pair other than (3, 4))"
    );
    // The guest's pipe popped the recycled slot: closing both ends freed it
    // again, so the next create pops the same index two incarnations on.
    let next = owner.create_pipe(65536).expect("next incarnation");
    assert_eq!(
        (next.index(), next.generation()),
        (old.index(), old.generation().wrapping_add(2)),
        "the guest's pipe2 used the recycled slot whose lanes were held"
    );
}

fn native_exit_fixture(name: &str) -> Vec<u8> {
    native_exit_fixture_with_flags(name, &[])
}

fn native_exit_fixture_with_flags(name: &str, flags: &[&str]) -> Vec<u8> {
    kvm_pool_fixture::assemble_fixture(name, flags)
}

fn native_exit_workers(
    elf: &[u8],
) -> (
    carrick_vmm_kvm::cpl0_boot::ProductionWorkerParts,
    carrick_el1_abi::El1TaskId,
    carrick_kernel::dispatch::SyscallDispatcher,
) {
    let program = carrick_mem::elf::ElfProgram::load(elf, ELF_X86_64_MACHINE, &|_| None)
        .expect("ELF program");
    let image = prepare_x86_elf(&program).expect("static ELF");
    let extent = Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("extent");
    // Match production preparation: native descriptor owners require the
    // shared IPC window and this exact root table's publication.
    let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    let mut carrier = Cpl0Carrier::boot_production(
        physical_inventory(),
        extent,
        carrick_kernel::kernel::continuation::ipc::host_window_backing(&dispatcher),
    )
    .expect("real KVM");
    let issued = dispatcher.capture_one_task_context().expect("issued root");
    issued
        .resources()
        .files()
        .publish_ipc(
            issued.kernel().ipc().expect("IPC owner"),
            carrick_kernel::kernel::objects::IpcTableMapBinding::Retained(
                carrier.ipc_table_map().expect("retained descriptor map"),
            ),
        )
        .expect("publish exact root descriptor table");
    issued
        .kernel()
        .bind_initial_birth_source(
            carrier
                .birth_serial_source()
                .expect("stopped carrier source"),
        )
        .expect("bind initial carrier birth and MM source");
    carrier
        .bind_initial_task_identity(InitialTaskBinding {
            task: issued.task().key(),
            mm: carrick_guest_arch::MmGeneration::new(issued.shared().mm().id().nonzero()),
            thread: carrick_sched_core::ThreadIdentity {
                tid: issued.thread().key().tid.raw() as u64,
                serial: issued.thread().key().serial.raw(),
                mm: 0,
                file_table: issued.resources().files().id().raw(),
                generation: 77,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 3,
                lifecycle_page: 0,
                control_slot: 0,
            },
        })
        .expect("issued root binding");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("guest MM");
    assert!(
        carrier.initial_thread_custody(),
        "actual initial native record"
    );
    (
        carrier.into_worker_parts(128).expect("physical workers"),
        carrick_el1_abi::El1TaskId::from_linux_tid(issued.thread().key().tid.raw()),
        // Keep the issuing host owner alive until the stopped-worker fixture
        // finishes; dropping it withdraws the root's IPC table publication.
        dispatcher,
    )
}

/// A booted production carrier with its initial MM loaded and every vCPU
/// stopped, before any worker lane runs, with the issuing host owner.
fn booted_production_carrier(
    elf: &[u8],
) -> (Cpl0Carrier, carrick_kernel::dispatch::SyscallDispatcher) {
    let program = carrick_mem::elf::ElfProgram::load(elf, ELF_X86_64_MACHINE, &|_| None)
        .expect("ELF program");
    let image = prepare_x86_elf(&program).expect("static ELF");
    let extent = Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("extent");
    let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    let mut carrier = Cpl0Carrier::boot_production(
        physical_inventory(),
        extent,
        carrick_kernel::kernel::continuation::ipc::host_window_backing(&dispatcher),
    )
    .expect("real KVM");
    let issued = dispatcher.capture_one_task_context().expect("issued root");
    issued
        .kernel()
        .bind_initial_birth_source(
            carrier
                .birth_serial_source()
                .expect("stopped carrier source"),
        )
        .expect("bind initial carrier birth and MM source");
    carrier
        .bind_initial_task_identity(InitialTaskBinding {
            task: issued.task().key(),
            mm: carrick_guest_arch::MmGeneration::new(issued.shared().mm().id().nonzero()),
            thread: carrick_sched_core::ThreadIdentity {
                tid: issued.thread().key().tid.raw() as u64,
                serial: issued.thread().key().serial.raw(),
                mm: 0,
                file_table: issued.resources().files().id().raw(),
                generation: 77,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 3,
                lifecycle_page: 0,
                control_slot: 0,
            },
        })
        .expect("issued root binding");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("guest MM");
    (carrier, dispatcher)
}

/// #1093 S4c slice c: on a booted production carrier, the host Exec service
/// reserves a static successor from the carrier's own fork stock (the boot
/// table grants it left unused), stages its data frames in the carrier's
/// frame inventory and memory, and imports its rows into a closed successor
/// root in the guest's real CPL0 tables; an unused preparation returns
/// whole. While a holder has the stock it parks with nothing reserved and
/// no errno, stays parked when probed early, and stages after the release.
#[test]
fn production_exec_service_stages_parks_and_reruns_a_successor() {
    use carrick_x86_cpl0_host::cpl0_boot::exec_service::{
        X86ExecImage, X86ExecRequest, X86ExecStage,
    };
    let (mut carrier, _dispatcher) =
        booted_production_carrier(&native_exit_fixture("native_exit_order.S"));
    let successor = carrick_el1_abi::ReservationMm::new(900).expect("successor MM");
    let root_generation = carrier
        .fixture_publish_exec_successor(successor)
        .expect("closed successor root");
    let marker = native_exit_fixture("native_exec_marker.S");
    let program = carrick_mem::elf::ElfProgram::load(&marker, ELF_X86_64_MACHINE, &|_| None)
        .expect("successor ELF");
    let request = || X86ExecRequest {
        image: Box::new(
            X86ExecImage::from_program(&program, vec![b"/successor".to_vec()], vec![])
                .expect("checked successor"),
        ),
        successor,
        root_generation,
    };
    let demand = request().image.demand();
    let stock = carrier.fork_table_stock();
    assert!(stock >= demand.tables, "boot left the stock {stock} tables");

    let X86ExecStage::Staged(backing, entry) =
        carrier.stage_exec_successor(0, request()).expect("service")
    else {
        panic!("the stock grants the successor");
    };
    let (tables, data) = carrier.exec_reservation(successor).expect("retained");
    assert_eq!(tables.len(), demand.tables);
    assert_eq!(data.len(), demand.data);
    assert_eq!(backing.root, tables[0]);
    assert_eq!(entry.entry, request().image.entry().entry);
    assert_eq!(carrier.fork_table_stock(), stock - demand.tables);
    carrier
        .release_exec_successor(successor)
        .expect("unused preparation returns");
    assert_eq!(carrier.fork_table_stock(), stock);
    assert!(carrier.exec_reservation(successor).is_none());

    let held = carrier
        .fixture_hold_fork_stock(demand.tables - 1)
        .expect("hold stock");
    let X86ExecStage::Parked(parked) = carrier.stage_exec_successor(0, request()).expect("service")
    else {
        panic!("a holder has the stock: not now");
    };
    assert_eq!(carrier.fork_table_stock(), demand.tables - 1);
    assert!(carrier.exec_reservation(successor).is_none());
    let parked = carrier.probe_parked_exec(parked).expect_err("still held");
    carrier.fixture_release_fork_stock(held);
    let rerun = carrier.probe_parked_exec(parked).expect("released");
    assert!(matches!(
        carrier.stage_exec_successor(0, rerun).expect("service"),
        X86ExecStage::Staged(..)
    ));
    assert_eq!(carrier.fork_table_stock(), stock - demand.tables);
}

fn run_to_marker(
    cpu: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease,
    task: carrick_guest_arch::TaskIdentity,
    expected: u8,
    factory: &carrick_vmm_kvm::cpl0_boot::ProductionCpuFactory,
) {
    use carrick_guest_mem::GuestMemory;
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    for _ in 0..128 {
        let exit = cpu
            .fixture_run_loaded(task)
            .expect("native runtime progress")
            .exit;
        match exit {
            CarrierRunExit::SyscallTrap => {
                let ((bytes, fork_result), token) = cpu
                    .capture_forward(task, |venue, frame| {
                        assert_eq!(frame.rax, 1, "only the rendezvous write may cross");
                        assert_eq!((frame.rdi, frame.rdx), (1, 1));
                        Ok((
                            venue.read_bytes_raw(frame.rsi, 1).expect("marker byte"),
                            frame.r12 as i32,
                        ))
                    })
                    .expect("real write crossing");
                assert!(
                    expected == 0 || fork_result > 0,
                    "guest fork result: {fork_result}; refusal {:?}; stock {:?}",
                    factory.fork_admission_refusal(),
                    factory.fork_stock_counters()
                );
                assert_eq!(
                    bytes,
                    [expected],
                    "guest assertions must reach the next marker"
                );
                cpu.complete_forward(task, token, 1)
                    .expect("write completion");
                return;
            }
            CarrierRunExit::PhysicalDoorbell { .. } => {
                let outcome = cpu
                    .service_physical_doorbell(task, &exit, |_, _| {
                        panic!("unexpected completed host work before marker")
                    })
                    .expect("physical service");
                assert!(
                    outcome.is_none(),
                    "guest exited before marker {expected}: {outcome:?}"
                );
            }
            CarrierRunExit::Kick => {}
            other => panic!("unexpected native exit: {other:?}"),
        }
    }
    panic!("marker exit budget");
}

fn run_until_wait_enrolled(
    cpu: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease,
    task: carrick_guest_arch::TaskIdentity,
    factory: &carrick_vmm_kvm::cpl0_boot::ProductionCpuFactory,
    tid: carrick_el1_abi::El1TaskId,
    peer: bool,
) {
    run_until_wait_enrolled_with_boundary(cpu, task, factory, tid, peer, false);
}

fn run_until_wait_enrolled_with_boundary(
    cpu: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease,
    task: carrick_guest_arch::TaskIdentity,
    factory: &carrick_vmm_kvm::cpl0_boot::ProductionCpuFactory,
    tid: carrick_el1_abi::El1TaskId,
    peer: bool,
    idle_boundary: bool,
) {
    use carrick_hal::VcpuKick;
    use carrick_sched_core::Claim;
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    let kick = carrick_vmm_kvm::KvmKickHandle::for_current_thread();
    let stopped = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let claim = factory
                    .fixture_native_wait_state(tid)
                    .expect("native enrollment")
                    .0;
                if matches!(claim, Claim::Parked { .. })
                    && (!idle_boundary
                        || factory
                            .fixture_native_cpu_idle(carrick_guest_arch::CpuId::new(u32::from(
                                peer,
                            )))
                            .expect("idle enrollment boundary"))
                {
                    kick.kick();
                    return true;
                }
                if stopped.load(std::sync::atomic::Ordering::Acquire)
                    || std::time::Instant::now() >= deadline
                {
                    kick.kick();
                    return false;
                }
                std::thread::yield_now();
            }
        });
        let exit = if peer {
            cpu.fixture_run_idle_peer().expect("enroll peer wait")
        } else {
            cpu.fixture_run_until_native_kick(task)
                .expect("enroll actual wait")
        };
        stopped.store(true, std::sync::atomic::Ordering::Release);
        assert!(
            watcher.join().expect("bounded enrollment watcher"),
            "wait must enroll before retirement completes"
        );
        assert_eq!(exit, CarrierRunExit::Kick);
    });
}

fn run_idle_peer_until_kick(peer: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease) {
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    for _ in 0..128 {
        match peer.fixture_run_idle_peer().expect("idle peer progress") {
            CarrierRunExit::Kick => return,
            exit @ CarrierRunExit::PhysicalDoorbell { .. } => {
                assert!(
                    peer.service_idle_peer_doorbell(&exit, |_, _| {})
                        .expect("idle peer physical service")
                        .is_none()
                );
            }
            other => panic!("unexpected idle peer exit: {other:?}"),
        }
    }
    panic!("idle peer kick budget");
}

#[test]
fn native_runtime_wait_wakes_once_only_after_real_mm_retirement() {
    native_runtime_exit_wake(false);
}

/// #1961 review P0-1 (homed waiter), and the #1973 refactor guard: the
/// production native process owner's exit wake (`publish_signal_channel` ->
/// `native_process::Service::wake_effects`) finds the parent's home run
/// queue busy (the host holds CPU 0's queue lock, as a contending CPU
/// would). The wake waits for that lock and queues the parent at home,
/// never on the waker's slot: it used to queue it there `misplaced`, for a
/// host relocation no boundary performs, and `migrate_queued` never moves
/// a homed record. The exiting waker still leaves for the host at its exit
/// boundary with its doorbell rung (`begin_closing` rings it).
#[test]
fn native_exit_wake_to_a_busy_home_queues_the_parent_at_home() {
    native_runtime_exit_wake(true);
}

/// #1961 review P0-1 (homed waiter, non-exit production entry): a blocked,
/// nonfatal signal still publishes the process channel enrolled by wait4.
/// With CPU 0's home queue held, the child's native `kill` on CPU 1 waits
/// for that lock and queues the parent at home. It used to queue the parent,
/// homed on CPU 0, on CPU 1 `misplaced`, where CPU 1 would switch it in.
/// Neither task exits, so a wake placed at home owes the host nothing.
#[test]
fn native_kill_wake_to_a_busy_home_queues_the_parent_at_home() {
    use carrick_sched_core::Claim;
    let elf = native_exit_fixture("native_kill_wait.S");
    let (parts, root_tid, _dispatcher) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let child_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let mut parent = factory.claim(0).expect("root executor");
    let mut child = factory.claim(1).expect("sender executor");
    let task = root.binding().task();
    parent.cpu_mut().load(root).expect("load root");
    run_to_marker(&mut parent, task, 1, &factory);
    factory
        .fixture_place_native_thread(child_tid, carrick_guest_arch::CpuId::new(1))
        .expect("place sender on peer");
    run_until_wait_enrolled(&mut parent, task, &factory, root_tid, false);
    let (claim, _, wakes_before) = factory
        .fixture_native_wait_state(root_tid)
        .expect("wait4 record");
    assert!(matches!(claim, Claim::Parked { .. }));
    let peer = carrick_guest_arch::CpuId::new(1);
    let (misplaced_before, owed_before) =
        factory.fixture_native_wake_debt(peer).expect("before kill");
    assert!(!owed_before, "non-exit sender doorbell must start clear");
    let ((exit, owed), released_early) =
        with_slot_contended(&factory, carrick_guest_arch::CpuId::new(0), || {
            let exit = child
                .fixture_run_idle_peer()
                .expect("native kill from child");
            let owed = factory
                .fixture_native_wake_debt(peer)
                .expect("after kill")
                .1;
            (exit, owed)
        });
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("published parent");
    let (misplaced, _) = factory
        .fixture_native_wake_debt(peer)
        .expect("misplaced wake");
    assert_eq!(
        wakes,
        wakes_before + 1,
        "kill publishes one wait4 channel wake"
    );
    assert!(
        matches!(claim, Claim::Queued { slot, .. } if slot == carrick_sched_core::SlotId::new(0)),
        "the parent is queued at home, never on the sender's CPU: {claim:?}"
    );
    assert_eq!(misplaced, misplaced_before, "nothing misplaced");
    assert!(
        !released_early,
        "the sender waited for the parent's home queue: exit {exit:?}"
    );
    assert!(
        !owed,
        "a wake queued at home owes the host nothing: exit {exit:?}, claim {claim:?}"
    );
}

/// #1961 review P0-1, x86 production witness: a fork child's thread on
/// CPU 1 wakes the child's main thread with `FUTEX_WAKE_PRIVATE`; that
/// waiter may run only on CPU 0, whose run queue is busy (the host holds
/// its lock, as a contending CPU would). x86 CPL0 never leaves the guest
/// state, so a contended queue lock is how this lane meets a waiter no
/// guest CPU may take now. The wake must still queue the waiter on CPU 0,
/// once the lock is free, never on the waker's CPU 1: it used to fall back
/// to CPU 1, `misplaced`, for a host relocation no boundary performs, and
/// CPU 1 then ran the waiter, pinned to CPU 0, itself. The run completes.
/// (The fixture pins the waiter; the guest cannot, as a fork child's
/// `sched_setaffinity` answers ENOSYS on x86 today.)
#[test]
fn native_child_futex_wake_to_a_busy_pinned_cpu_queues_the_waiter_there() {
    use carrick_sched_core::Claim;
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    let elf = native_exit_fixture("native_child_futex_wake.S");
    let (parts, root_tid, dispatcher) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let child_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let (cpu0, cpu1) = (
        carrick_guest_arch::CpuId::new(0),
        carrick_guest_arch::CpuId::new(1),
    );
    let mut parent = factory.claim(0).expect("root executor");
    let mut peer = factory.claim(1).expect("idle peer executor");
    let task = root.binding().task();
    parent.cpu_mut().load(root).expect("load root");
    run_to_marker(&mut parent, task, 1, &factory);
    // CPU 1 runs the child's real thread birth. The new thread (the waker)
    // runs first and stops at its marker with the main thread queued.
    factory
        .fixture_pin_native_thread(child_tid, cpu1)
        .expect("child on CPU 1");
    let mut marker = false;
    for _ in 0..128 {
        let exit = peer.fixture_run_idle_peer().expect("thread birth on CPU 1");
        assert!(
            matches!(exit, CarrierRunExit::PhysicalDoorbell { .. }),
            "thread birth exit {exit:?}"
        );
        assert!(
            peer.service_idle_peer_doorbell_with_host_file(
                &exit,
                |_, _| {},
                &mut |origin, record| {
                    assert_eq!(origin, carrick_core_abi::service::ServiceOrigin::Descendant);
                    let served = dispatcher
                        .serve_native_host_file(record)
                        .map_err(|_| carrick_hal::fork_stock::NativeHostFileRefused)?;
                    marker = true;
                    Ok(served.retained_source)
                }
            )
            .expect("thread birth service")
            .is_none()
        );
        if marker {
            break;
        }
    }
    assert_eq!(dispatcher.stdout(), [2], "the waker stopped at its marker");
    // The waiter (the child's main thread) may run only on CPU 0. CPU 0
    // resumes the root into wait4, then runs the waiter into its futex wait.
    factory
        .fixture_pin_native_thread(child_tid, cpu0)
        .expect("pin the waiter to CPU 0");
    run_until_wait_enrolled_with_boundary(&mut parent, task, &factory, child_tid, false, true);
    assert!(matches!(
        factory
            .fixture_native_wait_state(child_tid)
            .expect("waiter wait")
            .0,
        Claim::Parked { .. }
    ));
    let bucket = parked_bucket(&factory, child_tid);
    let (misplaced_before, _) = factory.fixture_native_wake_debt(cpu1).expect("debt");
    // The host holds CPU 0's run queue while CPU 1 resumes the waker. It
    // lets go once the waker has waited on that lock far longer than a
    // bounded spin (the waker holds the futex bucket throughout), or once
    // the waiter left its park without it.
    let (locked, held) = std::sync::mpsc::channel();
    let waited = std::thread::scope(|scope| {
        let holder = scope.spawn(|| {
            factory
                .fixture_with_slot_locked(cpu0, || {
                    locked.send(()).expect("holder rendezvous");
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                    let mut held_since = None;
                    loop {
                        let now = std::time::Instant::now();
                        if factory.fixture_futex_bucket_held(bucket).expect("bucket") {
                            let since = *held_since.get_or_insert(now);
                            if now - since >= std::time::Duration::from_millis(50) {
                                return true;
                            }
                        } else {
                            held_since = None;
                            if !matches!(
                                factory
                                    .fixture_native_wait_state(child_tid)
                                    .expect("waiter")
                                    .0,
                                Claim::Parked { .. }
                            ) {
                                return false;
                            }
                        }
                        if now >= deadline {
                            return false;
                        }
                        std::thread::yield_now();
                    }
                })
                .expect("hold CPU 0's run queue")
        });
        held.recv().expect("CPU 0's run queue held");
        // CPU 1: the waker's wake and raw exit. The waiter must never run
        // here; CPU 1 idles once the waker is gone.
        run_until_idle(
            &factory,
            cpu1,
            || {
                let exit = peer.fixture_run_idle_peer().expect("waker on CPU 1");
                assert!(
                    !matches!(
                        exit,
                        CarrierRunExit::PhysicalDoorbell {
                            port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                            ..
                        }
                    ),
                    "the waiter, pinned to CPU 0, ran and exited the child on CPU 1"
                );
                if matches!(exit, CarrierRunExit::PhysicalDoorbell { .. }) {
                    assert!(
                        peer.service_idle_peer_doorbell(&exit, |_, _| {})
                            .expect("waker service")
                            .is_none()
                    );
                }
                exit
            },
            || false,
        );
        holder.join().expect("bounded holder")
    });
    let (claim, _, _) = factory
        .fixture_native_wait_state(child_tid)
        .expect("woken waiter");
    let (misplaced, _) = factory.fixture_native_wake_debt(cpu1).expect("debt");
    assert!(
        matches!(claim, Claim::Queued { slot, .. } if slot == carrick_sched_core::SlotId::new(0)),
        "the waiter is queued on CPU 0, the CPU it may run on: {claim:?}, \
         misplaced {misplaced_before} -> {misplaced}"
    );
    assert_eq!(misplaced, misplaced_before, "nothing left to relocate");
    assert!(waited, "the waker waited for CPU 0's run queue");
    // CPU 0 runs the waiter: it exits the child with 19 and stops at the
    // child's exit crossing. The exit reaches the waker thread's remains,
    // which CPU 1 retires; then the root reaps the child and exits 7.
    let run_cpu0 = |parent: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease| {
        let exit = parent
            .fixture_run_loaded(task)
            .expect("waiter and root on CPU 0")
            .exit;
        match exit {
            CarrierRunExit::PhysicalDoorbell { .. } => parent
                .service_physical_doorbell(task, &exit, |_, _| {})
                .expect("CPU 0 service"),
            other => panic!("unexpected exit on CPU 0: {other:?}"),
        }
    };
    assert_eq!(run_cpu0(&mut parent), None, "the waiter's exit crossing");
    run_until_idle(
        &factory,
        cpu1,
        || {
            let exit = peer.fixture_run_idle_peer().unwrap_or_else(|error| {
                panic!(
                    "CPU 1: {error:?}\n{}",
                    factory.capture_physical_state().zone_census
                )
            });
            if matches!(exit, CarrierRunExit::PhysicalDoorbell { .. }) {
                assert!(
                    peer.service_idle_peer_doorbell(&exit, |_, _| {})
                        .expect("CPU 1 service")
                        .is_none()
                );
            }
            exit
        },
        || false,
    );
    let status = (0..128)
        .find_map(|_| run_cpu0(&mut parent))
        .expect("root exit");
    assert_eq!(
        status,
        carrick_vmm_kvm::cpl0_boot::PhysicalProcessExit::Exited(
            carrick_sched_core::process::TerminationStatus::exited(7)
        ),
        "the root reaped the child's 19 and exited 7"
    );
    assert_eq!(dispatcher.stdout(), [2]);
}

/// Run `run` (a guest CPU's next entry) while the host holds `cpu`'s run
/// queue lock, as a contending CPU would, for a bounded interval. The
/// result pairs `run`'s value with whether `run` had returned while the
/// lock was still held: a waker that must queue its waiter on `cpu` waits
/// for the lock instead, so it returns only after the release.
fn with_slot_contended<R>(
    factory: &carrick_vmm_kvm::cpl0_boot::ProductionCpuFactory,
    cpu: carrick_guest_arch::CpuId,
    run: impl FnOnce() -> R,
) -> (R, bool) {
    let returned = std::sync::atomic::AtomicBool::new(false);
    let (locked, held) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let holder = scope.spawn(|| {
            factory
                .fixture_with_slot_locked(cpu, || {
                    locked.send(()).expect("holder rendezvous");
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_millis(300);
                    while std::time::Instant::now() < deadline
                        && !returned.load(std::sync::atomic::Ordering::Acquire)
                    {
                        std::thread::yield_now();
                    }
                    returned.load(std::sync::atomic::Ordering::Acquire)
                })
                .expect("hold the run queue")
        });
        held.recv().expect("run queue held");
        let value = run();
        returned.store(true, std::sync::atomic::Ordering::Release);
        (value, holder.join().expect("bounded holder"))
    })
}

/// The futex bucket `tid`'s parked record waits in, from the zone census.
fn parked_bucket(
    factory: &carrick_vmm_kvm::cpl0_boot::ProductionCpuFactory,
    tid: carrick_el1_abi::El1TaskId,
) -> usize {
    let census = factory.capture_physical_state().zone_census;
    let index = census
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("zone record ")?;
            let (index, fields) = rest.split_once(": ")?;
            fields
                .split(' ')
                .any(|field| field == format!("tid={}", tid.raw()))
                .then(|| index.to_owned())
        })
        .expect("parked record in the census");
    let parked = census
        .lines()
        .find_map(|line| line.strip_prefix(&format!("zone record {index} parked: ")))
        .expect("parked wait in the census");
    let field = |name: &str| {
        parked
            .split(' ')
            .find_map(|field| field.strip_prefix(name))
            .expect("census field")
            .to_owned()
    };
    let mm = field("first_wait_mm=").parse::<u64>().expect("mm");
    let address = u64::from_str_radix(field("first_wait_address=").trim_start_matches("0x"), 16)
        .expect("address");
    carrick_sched_core::ZoneTables::<carrick_sched_core::ParkedContextWords>::bucket_of_with_context(
        mm, address,
    )
}

/// Run the CPU `cpu` through `run` (one guest entry, its doorbell serviced)
/// until it idles with nothing to run, or `done`; a watcher kicks it at that
/// idle boundary.
fn run_until_idle(
    factory: &carrick_vmm_kvm::cpl0_boot::ProductionCpuFactory,
    cpu: carrick_guest_arch::CpuId,
    mut run: impl FnMut() -> carrick_vmm_kvm::carrier_cpu::CarrierRunExit,
    done: impl Fn() -> bool,
) {
    use carrick_hal::VcpuKick;
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    for _ in 0..128 {
        // Already idle with nothing queued (its work finished earlier): a
        // kick sent before the vCPU enters the guest would be lost.
        if factory.fixture_native_cpu_idle(cpu).expect("idle census") {
            return;
        }
        let kick = carrick_vmm_kvm::KvmKickHandle::for_current_thread();
        let stopped = std::sync::atomic::AtomicBool::new(false);
        let (exit, idle) = std::thread::scope(|scope| {
            let watcher = scope.spawn(|| {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                loop {
                    if factory.fixture_native_cpu_idle(cpu).expect("idle census") {
                        kick.kick();
                        return true;
                    }
                    if stopped.load(std::sync::atomic::Ordering::Acquire)
                        || std::time::Instant::now() >= deadline
                    {
                        return false;
                    }
                    std::thread::yield_now();
                }
            });
            let exit = run();
            stopped.store(true, std::sync::atomic::Ordering::Release);
            (exit, watcher.join().expect("bounded idle watcher"))
        });
        if done() {
            return;
        }
        match exit {
            CarrierRunExit::Kick if idle => return,
            CarrierRunExit::Kick | CarrierRunExit::PhysicalDoorbell { .. } => {}
            other => panic!("unexpected exit before idle: {other:?}"),
        }
    }
    panic!("idle budget");
}

fn native_runtime_exit_wake(hold_home: bool) {
    use carrick_sched_core::Claim;
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    let elf = native_exit_fixture("native_exit_order.S");
    let (parts, root_tid, _dispatcher) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let child_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let newborn_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 2);
    let mut parent = factory.claim(0).expect("root executor");
    let mut child = factory.claim(1).expect("idle peer executor");
    let task = root.binding().task();
    parent.cpu_mut().load(root).expect("load root");
    run_to_marker(&mut parent, task, 1, &factory);
    factory
        .fixture_place_native_thread(child_tid, carrick_guest_arch::CpuId::new(1))
        .expect("place child on peer");
    let retiring = (0..128)
        .find_map(|_| {
            let exit = child.fixture_run_idle_peer().expect("child on idle peer");
            if matches!(
                exit,
                CarrierRunExit::PhysicalDoorbell {
                    port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                    ..
                }
            ) {
                Some(exit)
            } else {
                assert!(
                    child
                        .service_idle_peer_doorbell(&exit, |_, _| {})
                        .expect("peer physical service")
                        .is_none()
                );
                None
            }
        })
        .expect("real retire_mm must cross before exit notification");
    let (_, _, wakes_before) = factory
        .fixture_native_wait_state(root_tid)
        .expect("parent record");
    // This marker follows actual wait4(WNOHANG)==0 and a successful fork.
    // Retirement is still held at its stopped physical crossing.
    run_to_marker(&mut parent, task, 2, &factory);
    factory
        .fixture_place_native_thread(newborn_tid, carrick_guest_arch::CpuId::new(1))
        .expect("place sibling on peer");
    assert!(
        factory
            .fork_admission_refusal()
            .expect("admission evidence")
            .is_none()
    );
    run_until_wait_enrolled(&mut parent, task, &factory, root_tid, false);
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("pending wait");
    assert!(matches!(claim, Claim::Parked { .. }));
    assert!(
        matches!(claim, Claim::Parked { seq: 1 }),
        "one wait enrollment: {claim:?}"
    );
    assert_eq!(
        wakes, wakes_before,
        "pending retirement cannot wake the waiter"
    );
    assert!(
        child
            .service_idle_peer_doorbell(&retiring, |_, _| {})
            .expect("retire physical MM")
            .is_none()
    );
    if hold_home {
        let peer_cpu = carrick_guest_arch::CpuId::new(1);
        let (misplaced_before, _) = factory
            .fixture_native_wake_debt(peer_cpu)
            .expect("waker debt before the exit wake");
        let ((exit, owed), released_early) =
            with_slot_contended(&factory, carrick_guest_arch::CpuId::new(0), || {
                let exit = child.fixture_run_idle_peer().expect("finish child exit");
                let owed = factory
                    .fixture_native_wake_debt(peer_cpu)
                    .expect("waker debt at its boundary")
                    .1;
                (exit, owed)
            });
        let (claim, _, wakes) = factory
            .fixture_native_wait_state(root_tid)
            .expect("woken wait");
        let (misplaced, _) = factory
            .fixture_native_wake_debt(peer_cpu)
            .expect("waker debt after the exit wake");
        assert_eq!(wakes, wakes_before + 1, "one exit publishes one wake");
        assert!(
            misplaced == misplaced_before
                && matches!(claim, Claim::Queued { slot, .. }
                    if slot == carrick_sched_core::SlotId::new(0)),
            "the waiter is queued at home, never on the waker's slot: {claim:?}, \
             misplaced {misplaced_before} -> {misplaced}"
        );
        assert!(
            !released_early,
            "the waker waited for the parent's home queue"
        );
        assert!(
            matches!(
                exit,
                CarrierRunExit::PhysicalDoorbell {
                    port: carrick_x86::cpl0_entry::WORK_PORT,
                    ..
                }
            ) && owed,
            "the exiting waker still owes its exit boundary: exit {exit:?}, doorbell {owed}"
        );
        return;
    }
    // Resume retire_mm to publish slot absence, then runtime readiness/channel.
    // Stop at the next sibling retirement, which has not published a wake.
    let next_retire = (0..128)
        .find_map(|_| {
            let exit = child.fixture_run_idle_peer().expect("finish child exit");
            if matches!(
                exit,
                CarrierRunExit::PhysicalDoorbell {
                    port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                    ..
                }
            ) {
                Some(exit)
            } else {
                assert!(
                    child
                        .service_idle_peer_doorbell(&exit, |_, _| {})
                        .expect("peer completion")
                        .is_none()
                );
                None
            }
        })
        .expect("sibling remains stopped at retirement");
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("completed wait");
    assert!(
        matches!(claim, Claim::Queued { .. }),
        "real waiter must be runnable: {claim:?}"
    );
    assert_eq!(
        wakes,
        wakes_before + 1,
        "one exit publishes exactly one wake"
    );
    run_to_marker(&mut parent, task, 3, &factory);
    assert_eq!(
        factory
            .fixture_native_wait_state(root_tid)
            .expect("resumed wait")
            .2,
        wakes_before + 1
    );
    drop(next_retire);
}

#[test]
fn work_port_services_bound_tasks_on_loaded_and_idle_peer_lanes() {
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    let elf = native_exit_fixture("native_exit_order.S");
    let (parts, root_tid, _dispatcher) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let child_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let mut parent = factory.claim(0).expect("root executor");
    let mut peer = factory.claim(1).expect("idle peer executor");
    let task = root.binding().task();
    parent.cpu_mut().load(root).expect("load root");
    run_to_marker(&mut parent, task, 1, &factory);

    factory
        .fixture_mark_current_host_work(carrick_guest_arch::CpuId::new(0))
        .expect("publish root work");
    let mut loaded_deliveries = Vec::new();
    for _ in 0..128 {
        let exit = parent
            .fixture_run_loaded(task)
            .expect("loaded boundary")
            .exit;
        if let CarrierRunExit::PhysicalDoorbell { port, .. } = exit {
            parent
                .service_physical_doorbell(task, &exit, |served, pending| {
                    loaded_deliveries.push((served, pending));
                })
                .expect("loaded service");
            if port == carrick_x86::cpl0_entry::WORK_PORT {
                break;
            }
        }
    }
    assert_eq!(loaded_deliveries.len(), 1);
    loaded_deliveries[0]
        .1
        .take()
        .expect("loaded task's host work delivered")
        .settled();

    factory
        .fixture_place_native_thread(child_tid, carrick_guest_arch::CpuId::new(1))
        .expect("place child on peer");
    // Enter once to bind the child, then publish a host wake against that
    // exact task while the vCPU is stopped at a real physical doorbell.
    let first = peer.fixture_run_idle_peer().expect("bind idle peer child");
    assert!(matches!(first, CarrierRunExit::PhysicalDoorbell { .. }));
    peer.service_idle_peer_doorbell(&first, |_, pending| {
        assert!(pending.is_none(), "no pending host work on first peer bind");
    })
    .expect("first peer service");
    factory
        .fixture_mark_current_host_work(carrick_guest_arch::CpuId::new(1))
        .expect("publish peer work");
    let mut idle_deliveries = Vec::new();
    for _ in 0..128 {
        let exit = peer.fixture_run_idle_peer().expect("idle peer boundary");
        if let CarrierRunExit::PhysicalDoorbell { port, .. } = exit {
            peer.service_idle_peer_doorbell(&exit, |served, pending| {
                idle_deliveries.push((served, pending));
            })
            .expect("idle peer service");
            if port == carrick_x86::cpl0_entry::WORK_PORT {
                break;
            }
        }
    }
    assert_eq!(idle_deliveries.len(), 1);
    idle_deliveries[0]
        .1
        .take()
        .expect("idle peer's host work delivered")
        .settled();
}

fn peer_retirement(
    peer: &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease,
) -> carrick_vmm_kvm::carrier_cpu::CarrierRunExit {
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    (0..128)
        .find_map(|_| {
            let exit = peer
                .fixture_run_idle_peer()
                .expect("child runtime progress");
            if matches!(
                exit,
                CarrierRunExit::PhysicalDoorbell {
                    port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                    ..
                }
            ) {
                Some(exit)
            } else {
                assert!(
                    peer.service_idle_peer_doorbell(&exit, |_, _| {})
                        .expect("physical service")
                        .is_none()
                );
                None
            }
        })
        .expect("child must reach actual MM retirement")
}

fn native_autoreap_waits_for_every_mm(flags: &[&str]) {
    use carrick_hal::VcpuKick;
    use carrick_sched_core::Claim;
    let elf = native_exit_fixture_with_flags("native_autoreap_exit.S", flags);
    let (parts, root_tid, _dispatcher) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let first_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let second_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 2);
    let mut parent = factory.claim(0).expect("root executor");
    let mut peer = factory.claim(1).expect("peer executor");
    let task = root.binding().task();
    parent.cpu_mut().load(root).expect("load parent");
    run_to_marker(&mut parent, task, 1, &factory);
    factory
        .fixture_pin_native_thread(first_tid, carrick_guest_arch::CpuId::new(1))
        .expect("first child on peer");
    let first_retire = peer_retirement(&mut peer);
    // The parent forks successfully while its first child is retiring.
    run_to_marker(&mut parent, task, 2, &factory);
    factory
        .fixture_pin_native_thread(second_tid, carrick_guest_arch::CpuId::new(1))
        .expect("second child on peer");
    assert!(
        factory
            .fork_admission_refusal()
            .expect("fork evidence")
            .is_none()
    );
    run_until_wait_enrolled_with_boundary(&mut parent, task, &factory, root_tid, false, true);
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("first wait");
    assert_eq!(claim, Claim::Parked { seq: 1 });
    assert_eq!(wakes, 0, "pending MM cannot wake wait");
    assert!(matches!(
        factory
            .fixture_native_wait_state(second_tid)
            .expect("peer-bound second child")
            .0,
        Claim::Queued { slot, .. } if slot == carrick_sched_core::SlotId::new(1)
    ));
    assert!(
        peer.service_idle_peer_doorbell(&first_retire, |_, _| {})
            .expect("first MM retirement")
            .is_none()
    );
    let second_retire = peer_retirement(&mut peer);
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("first completion");
    assert!(matches!(claim, Claim::Queued { .. }));
    assert_eq!(wakes, 1);
    // A wake for the first child is insufficient: wait(-1) must enroll again
    // instead of returning ECHILD while the second child's MM is still charged.
    run_until_wait_enrolled_with_boundary(&mut parent, task, &factory, root_tid, false, true);
    let (claim, _, wakes) = factory
        .fixture_native_wait_state(root_tid)
        .expect("remaining child");
    assert_eq!(claim, Claim::Parked { seq: 2 });
    assert_eq!(wakes, 1);
    assert!(
        peer.service_idle_peer_doorbell(&second_retire, |_, _| {})
            .expect("last MM retirement")
            .is_none()
    );
    // Stop only after the exit lane reaches idle, including its real wake IPI.
    // A queued claim alone precedes finish_wake and is not a safe stop boundary.
    // Neither observer changes the wait population or publishes a wake.
    let kick = carrick_vmm_kvm::KvmKickHandle::for_current_thread();
    let stopped = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let (claim, _, wakes) = factory
                    .fixture_native_wait_state(root_tid)
                    .expect("completion census");
                if matches!(claim, Claim::Queued { .. })
                    && wakes == 2
                    && factory
                        .fixture_native_cpu_idle(carrick_guest_arch::CpuId::new(1))
                        .expect("completed exit boundary")
                {
                    kick.kick();
                    return true;
                }
                if stopped.load(std::sync::atomic::Ordering::Acquire)
                    || std::time::Instant::now() >= deadline
                {
                    kick.kick();
                    return false;
                }
                std::thread::yield_now();
            }
        });
        run_idle_peer_until_kick(&mut peer);
        stopped.store(true, std::sync::atomic::Ordering::Release);
        assert!(watcher.join().expect("bounded completion observer"));
    });
    // Actual wait returns -10 only now, followed by another successful fork.
    run_to_marker(&mut parent, task, 3, &factory);
    run_to_marker(&mut parent, task, 4, &factory);
    assert!(
        factory
            .fork_admission_refusal()
            .expect("final fork evidence")
            .is_none()
    );
    let stock = factory.fork_stock_counters().expect("stock census");
    assert_eq!(stock.capacity_refusals, 0);
    assert_eq!(stock.retire_refusals, 0);
    assert_eq!(
        factory
            .fixture_native_wait_state(root_tid)
            .expect("resumed wait")
            .2,
        2
    );
}

#[test]
fn native_nocldwait_blocks_until_every_child_mm_retires() {
    native_autoreap_waits_for_every_mm(&[]);
}

#[test]
fn native_sigign_blocks_until_every_child_mm_retires() {
    native_autoreap_waits_for_every_mm(&["-DIGNORE_SIGCHLD"]);
}

#[test]
fn child_born_on_idle_peer_can_fault_and_retire_on_root_executor() {
    use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
    let elf = native_exit_fixture("native_peer_birth.S");
    let (parts, root_tid, dispatcher) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let child_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let newborn_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 2);
    let mut parent = factory.claim(0).expect("root executor");
    let mut peer = factory.claim(1).expect("idle peer");
    let task = root.binding().task();
    parent.cpu_mut().load(root).expect("load root");
    run_to_marker(&mut parent, task, 1, &factory);
    factory
        .fixture_place_native_thread(child_tid, carrick_guest_arch::CpuId::new(1))
        .expect("place child on peer");
    // CPU 1 runs the first child and performs the grandchild's real fork
    // loan and commit. CPU 0 stays stopped at the parent's marker.
    let mut stock_crossings = 0;
    for _ in 0..128 {
        let exit = peer.fixture_run_idle_peer().expect("fork on idle peer");
        if matches!(
            exit,
            CarrierRunExit::PhysicalDoorbell {
                port: carrick_el1_abi::FORK_STOCK_PORT,
                ..
            }
        ) {
            stock_crossings += 1;
        }
        assert!(
            peer.service_idle_peer_doorbell(&exit, |_, _| {})
                .expect("peer fork service")
                .is_none()
        );
        if stock_crossings == 2 {
            break;
        }
    }
    assert_eq!(
        stock_crossings, 2,
        "loan and commit must both occur on CPU 1"
    );
    let mut served_marker = false;
    for _ in 0..128 {
        let exit = peer.fixture_run_idle_peer().expect("peer fork completion");
        assert!(
            peer.service_idle_peer_doorbell_with_host_file(
                &exit,
                |_, _| {},
                &mut |origin, record| {
                    assert_eq!(origin, carrick_core_abi::service::ServiceOrigin::Descendant);
                    let served = dispatcher
                        .serve_native_host_file(record)
                        .map_err(|_| carrick_hal::fork_stock::NativeHostFileRefused)?;
                    served_marker = true;
                    Ok(served.retained_source)
                },
            )
            .expect("peer authenticated host-file completion")
            .is_none()
        );
        if served_marker {
            break;
        }
    }
    assert!(
        served_marker,
        "peer parent marker must use the host-file venue"
    );
    let peer_task = peer.idle_peer_task().expect("idle peer child task");
    assert_ne!(peer_task, task);
    assert!(
        peer.capture_forward(task, |_, _| Ok(())).is_err(),
        "idle peer forward must refuse a mismatched task generation"
    );
    assert_eq!(
        dispatcher.stdout(),
        [2],
        "marker reached its destination once"
    );
    factory
        .fixture_place_native_thread(newborn_tid, carrick_guest_arch::CpuId::new(0))
        .expect("migrate peer-born child to root executor");
    run_until_wait_enrolled(&mut peer, task, &factory, child_tid, true);
    // The newborn is queued on CPU 0; its parent enrolled wait4 on CPU 1.
    // CPU 0 retains its root task lease as it schedules the grandchild.
    let mut root_grants = 0;
    let grandchild_retire = (0..128)
        .find_map(|_| {
            let stopped = parent
                .fixture_run_loaded(task)
                .expect("peer-born child on root executor");
            let exit = stopped.exit;
            if matches!(
                exit,
                CarrierRunExit::PhysicalDoorbell {
                    port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                    ..
                }
            ) {
                assert_ne!(
                    stopped.state.as_ref().unwrap().binding().task(),
                    task,
                    "physical image must belong to the grandchild"
                );
                Some(exit)
            } else {
                if matches!(
                    exit,
                    CarrierRunExit::PhysicalDoorbell {
                        port: carrick_x86::cpl0_entry::OWNER_GRANT_PORT,
                        ..
                    }
                ) {
                    root_grants += 1;
                }
                assert!(
                    parent
                        .service_physical_doorbell(task, &exit, |_, _| {
                            panic!("unexpected completed host work during grandchild retirement")
                        })
                        .expect("registered migrated MM physical service")
                        .is_none()
                );
                None
            }
        })
        .expect("grandchild retirement on CPU 0");
    assert!(
        root_grants > 0,
        "grandchild private first-touch requires physical grant"
    );
    assert!(
        parent
            .service_physical_doorbell(task, &grandchild_retire, |_, _| {
                panic!("unexpected completed host work during grandchild retirement")
            })
            .expect("grandchild MM retirement")
            .is_none()
    );
    let stock = factory
        .fork_stock_counters()
        .expect("retired grandchild stock");
    assert_eq!(stock.quarantined_children, 1);
    assert_eq!(stock.retire_refusals, 0);
    // The binding witness ends at the authenticated physical retirement.
    // Both vCPUs are stopped; dropping the carrier reclaims the remaining graph.
}

#[test]
fn initial_root_uses_issued_thread_and_file_table_identity() {
    fn assert_send<T: Send>() {}
    assert_send::<carrick_vmm_kvm::cpl0_boot::ProductionWorkerParts>();
    let elf = tiny_elf();
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let image = prepare_x86_elf(&program).expect("static ELF");
    let extent =
        Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("initial grant extent");
    let mut carrier = Cpl0Carrier::boot_production(physical_inventory(), extent, None)
        .expect("production KVM boot");
    // These identities are fixture-supplied, with no host registry issuing
    // later MMs. The dispatcher-backed fixtures above bind the stopped source.
    carrier
        .bind_initial_task_identity(InitialTaskBinding {
            mm: carrick_guest_arch::MmGeneration::new(
                std::num::NonZeroU64::new(911).expect("issued fixture MM"),
            ),
            task: carrick_sched_core::process::TaskKey {
                id: carrick_personality_linux::identity::task_id_from_linux_pid(67)
                    .expect("fixture task id"),
                serial: carrick_sched_core::process::TaskSerial::from_registry_allocation(
                    std::num::NonZeroU64::new(700).expect("fixture task serial"),
                ),
            },
            thread: carrick_sched_core::ThreadIdentity {
                tid: 67,
                serial: 701,
                mm: 0,
                file_table: 702,
                generation: 1,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 3,
                lifecycle_page: 0,
                control_slot: 0,
            },
        })
        .expect("bind issued root");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("shared MM owner");
    assert!(carrier.initial_thread_custody());
    let workers = carrier.into_worker_parts(8).expect("worker handoff");
    assert_eq!(workers.root_state().binding().task().task.raw().get(), 700);
    assert_eq!(workers.root_state().state().mm_generation(), 911);
    let (root, factory) = workers.into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let factory = std::sync::Arc::new(factory);
    let root_factory = std::sync::Arc::clone(&factory);
    std::thread::spawn(move || {
        let mut lease = root_factory.claim(0).expect("root CPU claim");
        assert_eq!(lease.physical_slot().map(|slot| slot.raw()), Some(0));
        assert!(root_factory.claim(0).is_err());
        lease.cpu_mut().audit_idle().expect("stopped root CPU");
        lease
            .cpu_mut()
            .load(root.clone())
            .expect("load issued root");
        let mut wrong = root.binding().task();
        wrong.execution = carrick_guest_arch::ExecutionGeneration::new(
            std::num::NonZeroU64::new(2).expect("other execution"),
        );
        let unknown = carrick_vmm_kvm::carrier_cpu::CarrierRunExit::PhysicalDoorbell {
            port: 0xffff,
            data: vec![],
        };
        let wrong_error = lease
            .service_physical_doorbell(wrong, &unknown, |_, _| {
                panic!("unexpected completed host work for wrong task")
            })
            .expect_err("wrong task cannot enter physical service");
        assert!(wrong_error.to_string().contains("task generation"));
        let port_error = lease
            .service_physical_doorbell(root.binding().task(), &unknown, |_, _| {
                panic!("unexpected completed host work for unknown port")
            })
            .expect_err("unknown physical crossing must fail closed");
        assert!(port_error.to_string().contains("unexpected physical"));
        let saved = lease
            .cpu_mut()
            .save_and_detach(root.binding().task())
            .expect("save issued root");
        assert_eq!(saved.state(), root.state());
        lease.cpu_mut().audit_idle().expect("detached root CPU");
    })
    .join()
    .expect("root worker ownership transfer");
    std::thread::spawn(move || {
        let mut lease = factory.claim(1).expect("peer CPU claim");
        assert_eq!(lease.physical_slot().map(|slot| slot.raw()), Some(1));
        assert!(factory.claim(1).is_err());
        lease.cpu_mut().audit_idle().expect("stopped peer CPU");
    })
    .join()
    .expect("peer worker ownership transfer");
}

fn image() -> PathBuf {
    PathBuf::from(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE"))
}

#[test]
fn production_initial_image_spans_more_than_one_edit_table_budget() {
    // Sixteen MiB of zero BSS needs more than eight lower-level tables
    // once the independently placed bootstrap stack is included.
    let mut elf = tiny_elf();
    elf[104..112].copy_from_slice(&(16_u64 * 1024 * 1024).to_le_bytes());
    let outcome = run_pool_fixture(&elf, 32);
    assert_eq!(outcome.run.exit_code, 7);
    assert!(outcome.run.stdout.is_empty());
    assert!(outcome.run.stderr.is_empty());
}

fn tiny_elf() -> Vec<u8> {
    let mut bytes = vec![0; 0xc0];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&ELF_X86_64_MACHINE.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x0040_00b0_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
    bytes[80..88].copy_from_slice(&ELF_LOAD_VA.to_le_bytes());
    bytes[96..104].copy_from_slice(&0xc0u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    // mov eax,231; mov edi,7; syscall; ud2. No libc or host ELF loader.
    bytes[0xb0..0xbe].copy_from_slice(&[
        0xb8,
        X86_SYS_EXIT_GROUP,
        0,
        0,
        0,
        0xbf,
        7,
        0,
        0,
        0,
        0x0f,
        0x05,
        0x0f,
        0x0b,
    ]);
    bytes
}

fn write_then_exit_elf(pointer: u64, count: u32) -> Vec<u8> {
    let mut bytes = tiny_elf();
    let mut code = vec![0xb8, X86_SYS_WRITE, 0, 0, 0, 0xbf, 1, 0, 0, 0];
    code.extend_from_slice(&[0x48, 0xbe]); // movabs rsi, pointer
    code.extend_from_slice(&pointer.to_le_bytes());
    code.push(0xba); // mov edx, count
    code.extend_from_slice(&count.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x89, 0xc7]); // syscall; mov edi, eax
    code.extend_from_slice(&[0xb8, X86_SYS_EXIT_GROUP, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b]);
    let end = 0xb0 + code.len();
    bytes.resize(end, 0);
    bytes[96..104].copy_from_slice(&(end as u64).to_le_bytes());
    bytes[0xb0..end].copy_from_slice(&code);
    bytes
}

#[test]
fn initial_write_returns_prefix_or_efault_without_aborting_carrier() {
    for (pointer, count, expected_exit, expected_bytes) in [
        (0x400ff0, 0x10_0001, 16, 16),
        (0x7_0000, 32, 242, 0), // -EFAULT = -14, low exit byte 242
    ] {
        let elf = write_then_exit_elf(pointer, count);
        let outcome = run_pool_fixture(&elf, 8);
        assert_eq!(outcome.run.exit_code, expected_exit);
        assert_eq!(outcome.run.stdout.len(), expected_bytes);
    }
}

#[test]
fn explicit_initial_process_kick_preempts_and_resumes_under_pool() {
    let elf = tiny_elf();
    let outcome = run_pool_fixture_with(&elf, 8, |carrier| {
        carrier
            .fixture_cancel_next_run(0)
            .expect("cancel stopped vCPU");
    });
    assert_eq!(outcome.run.exit_code, 7);
}

#[test]
fn shared_guest_owner_loads_static_elf_and_exits_seven() {
    let elf = tiny_elf();
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let plan = prepare_x86_elf(&program).expect("shared ELF parser");
    assert_eq!(
        (plan.entry, plan.phdr, plan.phent, plan.phnum),
        (0x4000b0, 0x400040, 56, 1)
    );
    assert_eq!(plan.regions.len(), 1);
    assert!(plan.regions[0].perms.execute && !plan.regions[0].perms.write);
    let mut program = vec![0x48, 0xbf]; // mov rdi, staged ELF pointer
    program.extend_from_slice(&0x10100u64.to_le_bytes());
    program.extend_from_slice(&[0x48, 0xbe]); // mov rsi, ELF length
    program.extend_from_slice(&(elf.len() as u64).to_le_bytes());
    program.extend_from_slice(&[0x48, 0xb8]); // mov rax, owner request
    program.extend_from_slice(&OBSERVE_INITIAL_MM.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    program.resize(0x100, 0x90);
    program.extend_from_slice(&elf);
    let mut carrier = Cpl0Carrier::boot(physical_inventory(), &image(), [&program, &program])
        .expect("real KVM image");
    let observed = carrier.observe(0).expect("static ELF exit");
    assert_eq!(observed.result, 7);
    assert_eq!(observed.semantic_host_exits, 0);
}

#[test]
fn production_static_pie_loads_above_low_stack_and_exits_seven() {
    let mut elf = tiny_elf();
    elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN without PT_INTERP
    elf[24..32].copy_from_slice(&0xb0u64.to_le_bytes());
    elf[80..88].copy_from_slice(&0u64.to_le_bytes());
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let plan = prepare_x86_elf(&program).expect("static PIE parser");
    assert_eq!(plan.entry, carrick_mem::elf::LINUX_PIE_DEFAULT_BASE + 0xb0);
    let outcome = run_pool_fixture(&elf, 8);
    assert_eq!(outcome.run.exit_code, 7);
}

#[test]
fn production_enters_pt_interp_instead_of_executable_entry() {
    let mut elf = tiny_elf();
    elf.resize(0x200, 0);
    elf.copy_within(64..120, 120);
    elf[64..120].fill(0);
    elf[64..68].copy_from_slice(&3u32.to_le_bytes());
    elf[72..80].copy_from_slice(&0x180u64.to_le_bytes());
    let path = b"/lib/ld-test.so\0";
    elf[96..104].copy_from_slice(&(path.len() as u64).to_le_bytes());
    elf[0x180..0x180 + path.len()].copy_from_slice(path);
    elf[56..58].copy_from_slice(&2u16.to_le_bytes());
    elf[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
    elf[152..160].copy_from_slice(&0x200u64.to_le_bytes());
    elf[0x100..0x102].copy_from_slice(&[0x0f, 0x0b]); // Main must not enter ud2.

    let mut interpreter = tiny_elf();
    interpreter[16..18].copy_from_slice(&3u16.to_le_bytes());
    interpreter[24..32].copy_from_slice(&0xb0u64.to_le_bytes());
    interpreter[80..88].copy_from_slice(&0u64.to_le_bytes());
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|requested| {
        assert_eq!(requested, "/lib/ld-test.so");
        Some(interpreter.clone())
    })
    .expect("shared ELF loader");
    let outcome = kvm_pool_fixture::try_run_program_with(&program, 8, |_| {})
        .expect("PT_INTERP production entry");
    assert_eq!(outcome.run.exit_code, 7);
}

#[test]
fn production_bootstrap_stack_prefix_accepts_user_writes() {
    let mut elf = tiny_elf();
    let exit = elf[0xb0..0xbe].to_vec();
    elf.resize(0x100, 0);
    elf[96..104].copy_from_slice(&0x100u64.to_le_bytes());
    // sub rsp,8192; mov qword [rsp],0x5a; exit_group(7).
    let mut code = vec![
        0x48, 0x81, 0xec, 0, 0x20, 0, 0, 0x48, 0xc7, 0x04, 0x24, 0x5a, 0, 0, 0,
    ];
    code.extend_from_slice(&exit);
    elf[0xb0..0xb0 + code.len()].copy_from_slice(&code);
    assert_eq!(run_pool_fixture(&elf, 8).run.exit_code, 7);
}

#[test]
fn production_extent_cannot_alias_kernel_metadata() {
    use carrick_el1_abi::{EL1_DYNAMIC_METADATA_SIZE, X86_CPL0_DYNAMIC_METADATA_BASE};

    let extent_bytes = 192 * 1024 * 1024 + 4096;
    let mut carrier = Cpl0Carrier::boot_production(physical_inventory(), extent_bytes, None)
        .expect("production KVM image");
    let elf = tiny_elf();
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let image = prepare_x86_elf(&program).expect("static ELF");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("shared MM owner");

    let extent_va = carrick_core_abi::X86_CPL0_INITIAL_EXTENT_VA;
    let extent_end = extent_va + extent_bytes as u64;
    let metadata_end = X86_CPL0_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE;
    assert!(
        extent_end <= X86_CPL0_DYNAMIC_METADATA_BASE || extent_va >= metadata_end,
        "initial extent aliases the dynamic metadata aperture"
    );
}

#[test]
fn production_boot_binds_both_kvm_local_apics() {
    let carrier = Cpl0Carrier::boot_production(physical_inventory(), 0x20_000, None)
        .expect("production KVM boot");
    assert!(
        carrier
            .bootstrap_lapic_mapped()
            .expect("bootstrap LAPIC table walk"),
        "production CPL0 needs a writable supervisor mapping to xAPIC MMIO"
    );
    for slot in 0..2 {
        let version = carrier
            .lapic_register(slot, 0x30)
            .expect("production vCPU needs a live local APIC");
        assert_ne!(version & 0xff, 0, "missing LAPIC version on slot {slot}");
    }
}

#[test]
fn production_irq_entry_retains_each_native_vector_from_live_user_mode() {
    for (vector, bit) in [(0xe0, 1), (0xe1, 2), (0xe2, 4), (0xe3, 8)] {
        let elf = tiny_elf();
        let outcome = run_pool_fixture_with(&elf, 8, |carrier| {
            carrier
                .fixture_inject_irq(0, vector)
                .expect("native IRQ edge into stopped vCPU");
        });
        assert_eq!(outcome.run.exit_code, 7, "vector {vector:#x}");
        assert_eq!(
            outcome.physical.fixture_pending_irqs(0).unwrap() & bit,
            bit,
            "vector {vector:#x}"
        );
    }
}

#[test]
fn production_initial_mm_admits_one_shared_reservation_root() {
    let elf = tiny_elf();
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let plan = prepare_x86_elf(&program).expect("static ELF plan");
    let argv = vec!["/tiny".to_owned()];
    let extent =
        Cpl0Carrier::initial_extent_bytes_for(&plan, &argv, &[]).expect("typed initial extent");
    let mut carrier = Cpl0Carrier::boot_production(physical_inventory(), extent, None)
        .expect("production CPL0 image");
    carrier
        .load_guest_mm(&plan, &argv, &[], InitialReservationLimits::UNLIMITED)
        .expect("guest initial MM publication");
    let mappings = carrier.initial_reservation_census().expect("fork census");
    assert_eq!(
        mappings.len(),
        plan.regions.len() + 2,
        "fork must inherit every ELF region, the built stack top and the stack's growable rest"
    );
    let stack_top = carrick_vmm_kvm::cpl0_boot::INITIAL_STACK_TOP;
    assert!(mappings.iter().any(|mapping| {
        mapping.range.start() == stack_top - carrick_vmm_kvm::cpl0_boot::INITIAL_STACK_RESERVATION
            && mapping.range.end() == stack_top - carrick_vmm_kvm::cpl0_boot::INITIAL_STACK_SIZE
    }));
    for region in &plan.regions {
        assert!(
            mappings
                .iter()
                .any(|mapping| mapping.range.start() == region.start
                    && mapping.range.end() == region.end)
        );
    }
    assert!(mappings.iter().any(|mapping| {
        mapping.range.len() >= 4096
            && mapping
                .protection
                .permits(carrick_el1_abi::ReservationProtection::WRITE)
    }));
    assert!(carrier.initial_reservation_admitted());
    assert!(carrier.initial_inventory_custody());
    assert!(
        carrier.initial_thread_custody(),
        "initial x86 task must own one typed scheduler record"
    );
}

#[test]
fn production_user_page_fault_terminates_with_sigsegv_in_ring() {
    let elf = production_fault_elf();
    let outcome = run_pool_fixture(&elf, 32);
    assert!(outcome.fault_record.is_none(), "SIGSEGV stays in-ring");
    let exits = outcome.run.traps;
    assert_eq!(outcome.run.terminating_signal, Some(libc::SIGSEGV));
    assert_eq!(
        outcome.physical.user_fault_state(0).expect("fault custody"),
        (1, 0xdead000, 6, 0x4000b0 + 26, 0)
    );
    assert_eq!(exits, 2);
}

/// #1714: the run root's stack grows below the 64 KiB the carrier built, up
/// to Linux's default `RLIMIT_STACK`, as Linux grows the stack VMA. Before,
/// the first touch below the built stack was a SIGSEGV: CPython's compiler
/// died there compiling its startup modules.
#[test]
fn production_initial_stack_grows_below_the_built_pages() {
    let elf = native_exit_fixture("native_stack_growth.S");
    let outcome = try_run_pool_fixture_with_root_affinity(&elf, 64, ROOT_AFFINITY_LOADED)
        .expect("stack growth run");
    assert_eq!(
        (outcome.run.exit_code, outcome.run.terminating_signal),
        (0, None),
        "1 MiB of stack below the entry pointer: {:?}",
        outcome.run
    );
}

#[test]
fn block_then_user_page_fault_terminates_with_sigsegv_in_ring() {
    let elf = block_then_fault_elf();
    let outcome = run_pool_fixture(&elf, 32);
    assert!(outcome.fault_record.is_none(), "SIGSEGV stays in-ring");
    let exits = outcome.run.traps;
    assert_eq!(outcome.run.terminating_signal, Some(libc::SIGSEGV));
    assert_eq!(
        outcome.physical.user_fault_state(0).expect("fault custody"),
        (1, 0xdead000, 6, 0x4000b0 + 17, 0)
    );
    assert_eq!(exits, 1);
}

fn block_then_fault_elf() -> Vec<u8> {
    let mut elf = tiny_elf();
    let mut code = vec![0xb8, 24, 0, 0, 0, 0x0f, 0x05, 0x48, 0xb8];
    code.extend_from_slice(&0xdead000u64.to_le_bytes());
    code.extend_from_slice(&[0xc6, 0x00, 1, 0x0f, 0x0b]);
    elf.truncate(0xb0);
    elf.extend_from_slice(&code);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    elf
}

fn production_fault_elf() -> Vec<u8> {
    let mut elf = tiny_elf();
    let mut code = vec![
        0xbf, 1, 0, 0, 0, 0x31, 0xf6, 0x31, 0xd2, 0xb8, 1, 0, 0, 0, 0x0f, 0x05, 0x48, 0xb8,
    ];
    code.extend_from_slice(&0xdead000u64.to_le_bytes());
    code.extend_from_slice(&[0xc6, 0x00, 1, 0x0f, 0x0b]);
    elf.truncate(0xb0);
    elf.extend_from_slice(&code);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    elf
}

#[test]
fn file_region_guest_fork_dup_and_child_retirement_preserve_parent() {
    use carrick_el1_abi::fd_map_lookup;
    use carrick_hal::VcpuKick;
    use std::sync::atomic::Ordering;
    let elf = native_exit_fixture("native_file_fork.S");
    let (parts, root_tid, _dispatcher) = native_exit_workers(&elf);
    let (root, factory) = parts.into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let task = root.binding().task();
    let child_tid = carrick_el1_abi::El1TaskId::from_linux_tid(root_tid.raw() as i32 + 1);
    let mut parent = factory.claim(0).expect("root executor");
    let mut peer = factory.claim(1).expect("peer executor");
    parent.cpu_mut().load(root).expect("load issued root");
    run_to_marker(&mut parent, task, 0, &factory);
    let (stdout, incarnation) = factory
        .with_stopped_file_tables(|tables| {
            let slot = tables
                .fd_map()
                .iter()
                .find(|slot| {
                    slot.incarnation.load(Ordering::Acquire) != 0
                        && slot.fd.load(Ordering::Relaxed) == 1
                })
                .expect("initial stdout descriptor");
            let stdout = slot.handle.load(Ordering::Relaxed);
            let open = &tables.opens()[stdout as usize - 1];
            let incarnation = open.generation.load(Ordering::Acquire);
            assert_eq!(open.lifetime.ring_references(incarnation), Some(1));
            (stdout, incarnation)
        })
        .expect("pre-fork open lifetime");
    run_to_marker(&mut parent, task, 1, &factory);
    factory
        .fixture_pin_native_thread(child_tid, carrick_guest_arch::CpuId::new(1))
        .expect("child on independent physical lane");
    let retiring = peer_retirement(&mut peer); // real child dup then exit(3)
    let (parent_table, child_table, parent_slot, child_slot) = factory
        .with_stopped_file_tables(|tables| {
            let slots: Vec<_> = tables
                .fd_map()
                .iter()
                .enumerate()
                .filter(|(_, s)| {
                    s.incarnation.load(Ordering::Acquire) != 0 && s.fd.load(Ordering::Relaxed) == 3
                })
                .map(|(i, s)| (s.file_table.load(Ordering::Acquire), i))
                .collect();
            assert_eq!(
                slots.len(),
                2,
                "parent and child each published dup(stdout)"
            );
            let [(parent_table, parent_slot), (child_table, child_slot)] = slots[..] else {
                unreachable!()
            };
            assert_ne!(parent_table, child_table);
            assert_ne!(parent_slot, child_slot);
            let stdout = fd_map_lookup(tables.fd_map(), parent_table, 1)
                .expect("parent stdout")
                .0;
            for table in [parent_table, child_table] {
                assert_eq!(
                    fd_map_lookup(tables.fd_map(), table, 1)
                        .expect("inherited stdout")
                        .0,
                    stdout
                );
                assert_eq!(
                    fd_map_lookup(tables.fd_map(), table, 3)
                        .expect("independent dup reference")
                        .0,
                    stdout
                );
            }
            let open = &tables.opens()[stdout as usize - 1];
            assert_eq!(open.lifetime.ring_references(incarnation), Some(4));
            assert!(
                open.inode_handle.load(Ordering::Acquire) > 0,
                "stdout open must reside in the retained region"
            );
            assert!(open.is_bound_to(
                &tables.objects()[open.inode_handle.load(Ordering::Acquire) as usize - 1]
            ));
            (parent_table, child_table, parent_slot, child_slot)
        })
        .expect("both live tables in retained region");
    run_until_wait_enrolled(&mut parent, task, &factory, root_tid, false);
    assert!(
        peer.service_idle_peer_doorbell(&retiring, |_, _| {})
            .expect("real MM retirement")
            .is_none()
    );
    // Complete the real child's retirement and stop its now-idle executor.
    // The watcher only bounds the fixture; it does not complete guest exit.
    let kick = carrick_vmm_kvm::KvmKickHandle::for_current_thread();
    let stopped = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !factory
                .fixture_native_cpu_idle(carrick_guest_arch::CpuId::new(1))
                .expect("idle state")
            {
                if stopped.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                    kick.kick();
                    return false;
                }
                std::thread::yield_now();
            }
            kick.kick();
            true
        });
        run_idle_peer_until_kick(&mut peer);
        stopped.store(true, Ordering::Release);
        assert!(
            watcher.join().expect("idle watcher"),
            "child retirement deadline"
        );
    });
    run_to_marker(&mut parent, task, 2, &factory);
    factory
        .with_stopped_file_tables(|tables| {
            // The parent owns its issued file table (2) before and after
            // wait4; retiring the child table leaves only the parent's two
            // references (stdout and dup(stdout)).
            assert_eq!(parent_table, 2);
            assert_ne!(child_table, 2);
            assert_eq!(
                tables.opens()[stdout as usize - 1]
                    .lifetime
                    .ring_references(incarnation),
                Some(2)
            );
            assert_eq!(
                tables.fd_map()[child_slot]
                    .incarnation
                    .load(Ordering::Acquire),
                0
            );
            assert_eq!(
                tables.fd_map()[child_slot]
                    .file_table
                    .load(Ordering::Acquire),
                0
            );
            assert_eq!(
                tables.fd_map()[parent_slot]
                    .file_table
                    .load(Ordering::Acquire),
                parent_table
            );
            for fd in 0..=3 {
                assert!(
                    fd_map_lookup(tables.fd_map(), parent_table, fd).is_some(),
                    "parent fd {fd} survives"
                );
                assert!(
                    fd_map_lookup(tables.fd_map(), child_table, fd).is_none(),
                    "child fd {fd} retired"
                );
            }
        })
        .expect("parent survives child file-table retirement");
}

/// #143: the forked child's retained host-file write is served on CPU 1.
/// Root affinity 2 makes EL1 queue the inherited child only on CPU 1, so
/// the idle-peer lane, not a timing race, serves it.
#[test]
fn idle_peer_syscall_trap_hands_task_back_to_host_and_delivers_stdout() {
    let elf = native_exit_fixture("../../../carrick-cli/tests/fixtures/x86_forked_child_stdout.S");
    let outcome = try_run_pool_fixture_with_root_affinity(&elf, 32, ROOT_AFFINITY_IDLE_PEER)
        .expect("idle peer handback run");
    assert_eq!(outcome.run.exit_code, 7);
    assert_eq!(outcome.run.stdout, b"E");
    assert!(outcome.run.stderr.is_empty());
    assert_eq!(
        outcome
            .physical
            .idle_peer_host_file_witness()
            .expect("idle peer host-file witness"),
        1,
        "the child's write must be served from the idle peer"
    );
}

/// #143: when root affinity is 1 (CPU 0 only), the forked child inherits
/// affinity 1 and runs on CPU 0 after the parent enters CPL0 `wait4`. Its
/// `SyscallTrap` deterministically crosses the loaded-lane `SyscallTrap` arm
/// in `carrier_cpu.rs` and `with_forward_vcpu` (with zero idle-peer forwards).
#[test]
fn loaded_lane_child_syscall_trap_hands_task_back_to_host_and_delivers_stdout() {
    let elf = native_exit_fixture("../../../carrick-cli/tests/fixtures/x86_forked_child_stdout.S");
    let outcome = try_run_pool_fixture_with_root_affinity(&elf, 32, ROOT_AFFINITY_LOADED)
        .expect("loaded lane child handback run");
    assert_eq!(outcome.run.exit_code, 7);
    assert_eq!(outcome.run.stdout, b"E");
    assert!(outcome.run.stderr.is_empty());
    assert_eq!(
        outcome
            .physical
            .idle_peer_forward_witness()
            .expect("idle peer forward witness"),
        0,
        "affinity 1 must route the child's SyscallTrap through the loaded lane on CPU 0"
    );
}

/// Ruling 3 on #542: every idle-lane early return completes the run. With a
/// zero-exit budget is independent per lane, so the child's first carrier
/// exit (its `ppoll` host-readiness crossing; since #2157 a child's write is
/// served in ring and costs no exit) exhausts the idle budget while the
/// loaded root is parked in `wait4`;
/// before the single `settle_lane` path an idle
/// lane error skipped the `Err` completion and the run hung, and before the
/// shutdown kick the root vCPU stayed in `KVM_RUN` under the halted parent.
#[test]
fn idle_lane_exit_budget_failure_completes_the_run() {
    let elf = forward_authority_fixture("CHILD_POLL_WAIT");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result =
            try_run_pool_fixture_with_lane_exit_budgets(&elf, 64, 0, ROOT_AFFINITY_IDLE_PEER);
        let _ = tx.send(result);
    });
    let result = rx.recv_timeout(std::time::Duration::from_secs(30)).expect(
        "idle-lane exit-budget failure must complete within 30s deadline instead of hanging",
    );
    match result {
        Ok(outcome) => panic!(
            "a zero-exit idle budget cannot finish the forked run, got exit {}",
            outcome.run.exit_code
        ),
        Err(error) => assert!(
            error
                .to_string()
                .contains("idle KVM lane guest exit budget exceeded"),
            "expected the exit budget failure, got {error}"
        ),
    }
}

/// A shutdown arriving after the loaded lane's first reschedule check must be
/// retained by KVM's `immediate_exit` byte until the impending `KVM_RUN`.
#[test]
fn loaded_lane_shutdown_kick_between_check_and_entry_is_sticky() {
    use carrick_hal::VcpuKick;
    use std::sync::atomic::{AtomicBool, Ordering};

    let elf = native_exit_fixture("../../../carrick-cli/tests/fixtures/x86_forked_child_stdout.S");
    let injected = std::sync::Arc::new(AtomicBool::new(false));
    let observed = std::sync::Arc::clone(&injected);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = try_run_pool_fixture_with_loaded_pre_entry_hook(
            &elf,
            64,
            64,
            ROOT_AFFINITY_IDLE_PEER,
            move |need_resched, kick| {
                if !injected.swap(true, Ordering::AcqRel) {
                    need_resched.store(true, Ordering::Release);
                    kick.kick();
                    assert_eq!(
                        kick.fixture_run_exit_byte(),
                        Some(1),
                        "loaded entry must publish immediate_exit before the shutdown kick"
                    );
                }
            },
        );
        let _ = tx.send(result);
    });
    let outcome = rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("loaded pre-entry shutdown kick must complete the run")
        .expect("loaded pre-entry shutdown kick run");
    assert!(
        observed.load(Ordering::Acquire),
        "hook did not inject the kick"
    );
    assert_eq!(outcome.run.exit_code, 7);
}

fn forward_authority_fixture(variant: &str) -> Vec<u8> {
    native_exit_fixture_with_flags(
        "../../../carrick-cli/tests/fixtures/x86_forked_child_forward_authority.S",
        &[&format!("-D{variant}")],
    )
}

/// Ruling 2 on #542: a forked child's forward never borrows the root's host
/// `KernelContext`. The child's `read(0)` needs a host task context the
/// child does not own. Before the ruling the root's context served it; until
/// #2157 B0 the run failed with a typed `HostTaskContext` refusal. Now the
/// ring answers it like ARM: a counted ENOSYS (38) in ring, and the run
/// completes with the parent reaping that status.
#[test]
fn in_zone_child_host_read_is_counted_enosys_not_served_under_root_context() {
    let elf = forward_authority_fixture("CHILD_STDIN_READ");
    let outcome = try_run_pool_fixture_with_typed_failure(&elf, 64, ROOT_AFFINITY_IDLE_PEER)
        .unwrap_or_else(|failure| {
            panic!(
                "the child's read must be answered in ring: {:?} ({})",
                failure.authority_refusals, failure.error
            )
        });
    assert_eq!(
        outcome.run.exit_code, 7,
        "91 = the child's status was not ENOSYS: {:?}",
        outcome.run
    );
    let counters = outcome
        .physical
        .syscall_counters()
        .expect("stopped counters");
    assert_eq!(
        counters.refused_child[0].load(std::sync::atomic::Ordering::Acquire),
        1,
        "the child's read is a counted descendant refusal"
    );
}

/// #1756: x86 builds no IPC execution capability yet, so the shared transfer
/// engine never runs for an x86 `write` to an in-ring pipe. Since #1935/#1954
/// (`4c73badd1`) the native stage admits that write and keeps an in-zone fd
/// in ring (`native_stage::tests::write_to_in_zone_pipe_stays_in_ring`), so
/// the unserved write is answered in ring as a counted ENOSYS (-38) instead
/// of reaching the forward-authority check as a typed `HostTaskContext`
/// refusal. The child's `write` must therefore return ENOSYS: it must not
/// complete (exit 0), and it must not be served under another task's
/// authority. Slice 4 constructs the capability and turns this run green.
#[test]
fn in_zone_child_pipe_write_without_ipc_execution_is_counted_enosys_in_ring() {
    let elf = native_exit_fixture("native_pipe_child_write.S");
    let outcome = try_run_pool_fixture_with_typed_failure(&elf, 64, ROOT_AFFINITY_IDLE_PEER)
        .unwrap_or_else(|failure| {
            panic!(
                "the in-ring pipe write must be answered in ring, not refused at the \
                 forward-authority check: {:?} ({})",
                failure.authority_refusals, failure.error
            )
        });
    assert_eq!(
        outcome.run.exit_code, 38,
        "child write errno (0 means the write completed without an IPC execution \
         binding, 38 is ENOSYS, 90 pipe2 / 91 fork-wait failed)"
    );
    let counters = outcome
        .physical
        .syscall_counters()
        .expect("stopped counters");
    let write_nr = usize::from(X86_SYS_WRITE);
    assert_eq!(
        counters.refused[write_nr].load(std::sync::atomic::Ordering::Acquire),
        1,
        "x86 write (ordinal 1) must be recorded in ring refusal census"
    );
    assert_eq!(
        counters.refused_child[write_nr].load(std::sync::atomic::Ordering::Acquire),
        1,
        "child's in-ring pipe write refusal must credit descendant origin"
    );
    assert_eq!(
        counters.venue_refused[write_nr].load(std::sync::atomic::Ordering::Acquire),
        0,
        "in-ring refusal must not be recorded as a carrier venue refusal"
    );
    assert_eq!(
        counters.venue_refused_child[write_nr].load(std::sync::atomic::Ordering::Acquire),
        0,
        "in-ring refusal must not be recorded as a child carrier venue refusal"
    );
    let total_refusals: u64 = counters
        .refused
        .iter()
        .map(|counter| counter.load(std::sync::atomic::Ordering::Acquire))
        .sum();
    assert_eq!(
        total_refusals, 1,
        "only the child's x86 write (ordinal 1) may be recorded in ring refusal census"
    );
}

/// Ruling 2 on #542: a child's blocking wait never parks on another task's
/// lease. The child's `ppoll` on never-readable stdout must wait 50 ms; with
/// no lease of its own the run is refused before any forward token is taken.
/// Before the ruling the idle lane failed only after taking the token.
#[test]
fn in_zone_child_blocking_wait_is_refused_before_any_token() {
    let elf = forward_authority_fixture("CHILD_POLL_WAIT");
    let failure = match try_run_pool_fixture_with_typed_failure(&elf, 64, ROOT_AFFINITY_IDLE_PEER) {
        Ok(outcome) => panic!(
            "the child's wait parked on another task's lease: exit {}",
            outcome.run.exit_code
        ),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.authority_refusals,
        vec![carrick_runtime::prepare::ForwardAuthorityRefusal::BlockingWait],
        "unexpected refusal error: {}",
        failure.error
    );
}

/// Ruling 2 on #542: only the root's exit publishes the run's exit. The
/// child's `exit_group(3)` is reaped by the waiting parent as status 3<<8 and
/// the run exits with the parent's 7.
#[test]
fn in_zone_child_exit_is_reaped_by_parent_not_published_as_run_exit() {
    let elf = forward_authority_fixture("CHILD_EXIT_STATUS");
    let outcome = try_run_pool_fixture_with_root_affinity(&elf, 64, ROOT_AFFINITY_IDLE_PEER)
        .expect("child exit run");
    assert_eq!(outcome.run.exit_code, 7);
    assert!(outcome.run.stdout.is_empty());
}

/// Ruling 2 on #542 (director correction): a child's write to fd 1 is not
/// assumed to be host stdout. After `dup2(2, 1)` in the child, fd 1 resolves
/// through the child's own table to the stderr binding, so "P" reaches stderr
/// and stdout stays empty.
#[test]
fn in_zone_child_stdout_write_resolves_through_childs_own_table() {
    let elf = forward_authority_fixture("CHILD_STDOUT_REDIRECT");
    let outcome = try_run_pool_fixture_with_root_affinity(&elf, 64, ROOT_AFFINITY_IDLE_PEER)
        .expect("child redirect run");
    assert_eq!(outcome.run.exit_code, 7);
    assert!(outcome.run.stdout.is_empty(), "{:?}", outcome.run.stdout);
    assert_eq!(outcome.run.stderr, b"P");
}

/// Un-workarounded witness for #599/#586: in-guest `pipe2` (currently
/// `-ENOSYS`) and
/// parent `read(pipefd[0], buffer, 1)` into an unfaulted post-`fork` COW `.data`
/// page (currently `-EFAULT` in `ForwardVenue::write_bytes_raw`).
#[test]
#[ignore = "#599/#586"]
fn in_zone_child_pipe2_and_unfaulted_cow_read_matches_native_oracle() {
    let elf = native_exit_fixture_with_flags(
        "../../../carrick-cli/tests/fixtures/x86_forked_child_forward_authority.S",
        &["-DCHILD_PIPE_DUP2_STDOUT", "-DCHILD_PIPE_UNFAULTED_COW"],
    );
    let outcome = try_run_pool_fixture_with_root_affinity(&elf, 64, ROOT_AFFINITY_IDLE_PEER)
        .expect("child raw pipe2 and unfaulted COW read run");
    assert_eq!(outcome.run.exit_code, 7);
    assert_eq!(outcome.run.stdout, b"P");
    assert!(outcome.run.stderr.is_empty());
}

/// #1877 / #2019 on x86: the shared poll/select owner must park a blocked
/// `ppoll` or `poll` on a not-ready zone pipe and wake it when the last
/// writer closes (or on a peer write once #1756 lands). The parent must
/// return 1 with `revents == POLLHUP` (or `POLLIN`) and its `fd`/`events`
/// intact, then reap the child. The same source runs natively first as the
/// oracle. Exit codes name the failed stage (see `native_pipe_poll_wake.S`).
fn zone_pipe_poll_wake(flags: &[&str]) {
    zone_pipe_poll_wake_with_affinity(flags, ROOT_AFFINITY_IDLE_PEER);
}

fn zone_pipe_poll_wake_with_affinity(flags: &[&str], affinity: u64) {
    let elf = native_exit_fixture_with_flags("native_pipe_poll_wake.S", flags);
    let dir = tempfile::tempdir().expect("oracle directory");
    let oracle = dir.path().join("oracle");
    carrick_test_support::executable::write_executable_mode(&oracle, &elf, 0o700);
    let native = std::process::Command::new("timeout")
        .arg("10")
        .arg(&oracle)
        .status()
        .expect("bounded native oracle");
    assert_eq!(native.code(), Some(7), "native oracle: {native:?}");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(try_run_pool_fixture_with_root_affinity(&elf, 256, affinity));
    });
    let outcome = rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("blocked zone pipe poll must complete, not hang")
        .expect("zone pipe poll run");
    assert_eq!(
        outcome.run.exit_code, 7,
        "stdout {:?} stderr {:?}",
        outcome.run.stdout, outcome.run.stderr
    );
}

#[test]
#[ignore = "#1756: x86 has no ring IPC venue for the child's zone pipe write"]
fn zone_pipe_ppoll_blocks_until_peer_write_and_preserves_pollfd() {
    zone_pipe_poll_wake(&[]);
}

#[test]
#[ignore = "#1756: x86 has no ring IPC venue for the child's zone pipe write"]
fn zone_pipe_poll_blocks_until_peer_write_and_preserves_pollfd() {
    zone_pipe_poll_wake(&["-DUSE_POLL"]);
}

#[test]
fn zone_pipe_ppoll_blocks_until_last_writer_closes() {
    zone_pipe_poll_wake(&["-DWAKE_BY_CLOSE"]);
}

#[test]
fn zone_pipe_poll_blocks_until_last_writer_closes() {
    zone_pipe_poll_wake(&["-DUSE_POLL", "-DWAKE_BY_CLOSE"]);
}

/// Pinning parent and child to CPU 0 (`ROOT_AFFINITY_LOADED`) keeps the forked
/// child queued behind the running parent until the parent parks in `ppoll`,
/// deterministically forcing the parent-first interleaving without any sleep.
#[test]
fn zone_pipe_ppoll_loaded_affinity_parks_before_last_writer_closes() {
    zone_pipe_poll_wake_with_affinity(
        &["-DWAKE_BY_CLOSE", "-DNO_CHILD_SLEEP"],
        ROOT_AFFINITY_LOADED,
    );
}

#[test]
fn zone_pipe_poll_loaded_affinity_parks_before_last_writer_closes() {
    zone_pipe_poll_wake_with_affinity(
        &["-DUSE_POLL", "-DWAKE_BY_CLOSE", "-DNO_CHILD_SLEEP"],
        ROOT_AFFINITY_LOADED,
    );
}

#[test]
fn zone_pipe_ppoll_zero_timeout_returns_immediately() {
    zone_pipe_poll_wake(&["-DWAKE_BY_CLOSE", "-DZERO_TIMEOUT"]);
}

#[test]
fn zone_pipe_poll_zero_timeout_returns_immediately() {
    zone_pipe_poll_wake(&["-DUSE_POLL", "-DWAKE_BY_CLOSE", "-DZERO_TIMEOUT"]);
}

fn run_poll_revents_only_fixture(flags: &[&str]) {
    let elf = native_exit_fixture_with_flags("native_poll_revents_only.S", flags);
    let dir = tempfile::tempdir().expect("oracle directory");
    let oracle = dir.path().join("oracle");
    carrick_test_support::executable::write_executable_mode(&oracle, &elf, 0o755);
    let native = std::process::Command::new("timeout")
        .arg("10")
        .arg(&oracle)
        .output()
        .expect("run native oracle");
    assert_eq!(
        native.status.code(),
        Some(0),
        "native Linux oracle failed (flags={flags:?}): {:?}",
        native.status
    );

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(try_run_pool_fixture_with_root_affinity(
            &elf,
            512,
            kvm_pool_fixture::ROOT_AFFINITY_ANY,
        ));
    });
    let outcome = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("CPL0 poll revents witness hung past 10 s")
        .expect("CPL0 poll revents witness refused");
    assert_eq!(
        outcome.run.exit_code, 0,
        "CPL0 poll revents witness failed at stage {} (flags={flags:?}; see native_poll_revents_only.S)",
        outcome.run.exit_code
    );
}

#[test]
fn x86_cpl0_poll_and_ppoll_write_only_writable_revents_page() {
    run_poll_revents_only_fixture(&["-DREADONLY_INPUT_PAGE"]);
}

#[test]
fn x86_cpl0_poll_preserves_fields_changed_during_host_wait() {
    run_poll_revents_only_fixture(&[]);
}

#[test]
fn zone_pipe_ppoll_finite_timeout_expires() {
    zone_pipe_poll_wake(&["-DWAKE_BY_CLOSE", "-DFINITE_TIMEOUT"]);
}

#[test]
fn zone_pipe_poll_finite_timeout_expires() {
    zone_pipe_poll_wake(&["-DUSE_POLL", "-DWAKE_BY_CLOSE", "-DFINITE_TIMEOUT"]);
}

#[test]
fn zone_pipe_ppoll_finite_timeout_writer_close_wins() {
    zone_pipe_poll_wake(&[
        "-DWAKE_BY_CLOSE",
        "-DNO_CHILD_SLEEP",
        "-DFINITE_TIMEOUT_LONG",
    ]);
}

#[test]
fn zone_pipe_poll_finite_timeout_writer_close_wins() {
    zone_pipe_poll_wake(&[
        "-DUSE_POLL",
        "-DWAKE_BY_CLOSE",
        "-DNO_CHILD_SLEEP",
        "-DFINITE_TIMEOUT_LONG",
    ]);
}

fn private_file_fixture(cow: bool) {
    private_file_fixture_with(cow, &[], 0);
}

fn private_file_fixture_with(cow: bool, scenario: &[&str], open_flags: u64) {
    let dir = tempfile::tempdir().expect("private source directory");
    let path = dir.path().join("source");
    let mut bytes = vec![0x37; 4096];
    bytes[0] = 0x41;
    bytes[4095] = 0x5a;
    std::fs::write(&path, &bytes).expect("private source file");
    let define = format!("-DFILE_PATH=\"{}\"", path.display());
    let mut flags = vec![define.as_str()];
    flags.extend_from_slice(scenario);
    if cow {
        flags.push("-DCOW_WRITE");
    }
    let mut oracle_flags = flags.clone();
    if scenario.contains(&"-DEXPECT_SOURCE_LIMIT") {
        oracle_flags.push("-DNATIVE_SOURCE_LIMIT_CONTROL");
    }
    let elf = native_exit_fixture_with_flags("native_private_file.S", &oracle_flags);
    let oracle = dir.path().join("oracle");
    carrick_test_support::executable::write_executable_mode(&oracle, &elf, 0o700);
    let native = std::process::Command::new("timeout")
        .arg("10")
        .arg(&oracle)
        .output()
        .expect("bounded native oracle");
    let expects_bus = scenario.contains(&"-DEXPECT_BUS");
    if expects_bus {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(native.status.signal(), Some(7), "native SIGBUS control");
    } else {
        assert!(
            native.status.success(),
            "native oracle: {:?}",
            native.status
        );
    }
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    // File opening has a separate native-service binding. Seed this exact
    // task's real descriptor through production dispatch before guest entry,
    // so the witness isolates mmap and its physical fault service.
    let root = dispatcher.capture_one_task_context().expect("source task");
    let mut path_bytes = path.as_os_str().as_encoded_bytes().to_vec();
    path_bytes.push(0);
    let mut setup_memory = carrick_kernel::dispatch::LinearMemory::new(0x4000, path_bytes);
    let opened = dispatcher
        .dispatch(
            &root,
            carrick_kernel::dispatch::SyscallRequest::new(
                56,
                carrick_kernel::compat::SyscallArgs::from([
                    (-100_i64) as u64,
                    0x4000,
                    open_flags,
                    0,
                    0,
                    0,
                ]),
            ),
            &mut setup_memory,
            &carrick_kernel::compat::CompatReporter::default(),
        )
        .expect("production source open");
    let carrick_kernel::dispatch::DispatchOutcome::Returned { value: fd } = opened else {
        panic!("source open failed: {opened:?}");
    };
    assert_eq!(fd, 3);
    let preopened = format!("-DPREOPENED_FD={fd}");
    flags.push(&preopened);
    let elf = native_exit_fixture_with_flags("native_private_file.S", &flags);
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        if scenario.contains(&"-DEXPECT_SOURCE_LIMIT") {
            4096
        } else {
            128
        },
        ROOT_AFFINITY_LOADED,
        |_| {},
        dispatcher,
    )
    .expect("private mapping production runtime");
    assert_eq!(
        outcome.run.exit_code,
        if expects_bus { 135 } else { 0 },
        "31=open, 32=mmap, 33=bytes; run={:?}",
        outcome.run
    );
    if scenario.contains(&"-DEXPECT_SOURCE_LIMIT") {
        let witness = outcome
            .run
            .report
            .execution_witness
            .as_ref()
            .expect("source-bound execution population");
        let crossings = witness
            .host_forward_families
            .iter()
            .find(|row| row.family == "host-file")
            .expect("private-source host service");
        // 1,024 admitted sources, one errno-12 request, then one request
        // releasing the unmapped source and admitting its replacement.
        // Metadata growth must retain its original source, not stage again.
        assert_eq!(crossings.count, 1026);
        assert!(witness.guest_refusal_families.is_empty());
        assert!(!outcome.run.trap_limit_hit);
        assert!(outcome.run.stdout.is_empty());
        assert!(outcome.run.stderr.is_empty());
    }
    assert_eq!(std::fs::read(&path).expect("source after guest"), bytes);
}

#[test]
fn private_file_read_only_faults_in_source_bytes() {
    private_file_fixture(false);
}

#[test]
fn private_file_write_preserves_source_bytes() {
    private_file_fixture(true);
}

#[test]
fn private_file_write_only_mapping_returns_eacces() {
    private_file_fixture_with(
        false,
        &["-DEXPECT_ACCESS_FAILURE"],
        carrick_abi::LINUX_O_WRONLY,
    );
}

#[test]
fn private_file_path_only_mapping_returns_ebadf() {
    private_file_fixture_with(false, &["-DEXPECT_PATH_FAILURE"], carrick_abi::LINUX_O_PATH);
}

#[test]
fn private_file_child_first_touch_after_parent_unmap() {
    private_file_fixture_with(true, &["-DCHILD_FIRST_TOUCH"], 0);
}

#[test]
fn private_file_page_beyond_eof_delivers_sigbus() {
    private_file_fixture_with(false, &["-DEXPECT_BUS"], 0);
}

/// Reach the retained-source bound through production mmap admission, report
/// ENOMEM, then reclaim a source and admit another mapping. An earlier
/// metadata/admission failure must remain visible rather than skipping the bound.
#[test]
fn private_file_source_limit_returns_enomem() {
    private_file_fixture_with(false, &["-DEXPECT_SOURCE_LIMIT"], 0);
}

#[test]
fn serial_host_loader_open_close_reopen_uses_one_native_descriptor_namespace() {
    loader_reopen_with_publication(false);
}

#[test]
fn serial_host_loader_open_survives_colliding_publication() {
    loader_reopen_with_publication(true);
}

fn loader_reopen_with_publication(contended: bool) {
    let dir = tempfile::tempdir().expect("loader file directory");
    let path = dir.path().join("library");
    std::fs::write(&path, b"loader library").expect("loader source file");
    let define = format!("-DFILE_PATH=\"{}\"", path.display());
    let elf = native_exit_fixture_with_flags("native_loader_reopen.S", &[&define]);
    let oracle = dir.path().join("oracle");
    carrick_test_support::executable::write_executable_mode(&oracle, &elf, 0o700);
    let native = std::process::Command::new("timeout")
        .arg("10")
        .arg(&oracle)
        .output()
        .expect("bounded native loader control");
    assert!(native.status.success(), "native result: {native:?}");
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let key = dispatcher
        .capture_one_task_context()
        .expect("root")
        .resources()
        .files()
        .id()
        .raw();
    let (release, released) = std::sync::mpsc::channel();
    let outcome = std::thread::scope(|scope| {
        let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
            &program,
            128,
            ROOT_AFFINITY_LOADED,
            |carrier| {
                if !contended {
                    return;
                }
                let backing = carrier.ipc_table_map().expect("retained map");
                let map = backing.table_map();
                let home = |key: u64| {
                    (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize
                        % carrick_el1_abi::ipc_tables::IPC_TABLE_MAP_ENTRIES
                };
                let blocker = (1..u64::MAX)
                    .find(|other| *other != key && home(*other) == home(key))
                    .expect("collision");
                let raw = map.withdraw_table(key).expect("root binding");
                map.publish(blocker, raw).expect("blocker");
                map.publish(key, raw).expect("displaced root binding");
                let (ready, entered) = std::sync::mpsc::channel();
                scope.spawn(move || {
                    use carrick_el1_abi::ipc_tables::{
                        IPC_TABLE_MAP_ENTRIES, IpcTableMap, IpcTableMapEntry,
                    };
                    use std::sync::atomic::{AtomicU64, Ordering};
                    let map = backing.table_map();
                    // Test-only fault injection into repr(C) shared storage. The
                    // entries follow the aligned header; seq is each entry's
                    // first word. No guest runs until the odd sequence is visible.
                    let offset = std::mem::size_of::<IpcTableMap>()
                        - IPC_TABLE_MAP_ENTRIES * std::mem::size_of::<IpcTableMapEntry>()
                        + home(blocker) * std::mem::size_of::<IpcTableMapEntry>();
                    // SAFETY: retained backing keeps this aligned atomic live;
                    // the blocker has no other publisher during this schedule.
                    let seq = unsafe {
                        &*((map as *const IpcTableMap)
                            .cast::<u8>()
                            .add(offset)
                            .cast::<AtomicU64>())
                    };
                    seq.fetch_add(1, Ordering::Release);
                    ready.send(()).expect("reader alive");
                    let result = released.recv_timeout(std::time::Duration::from_secs(5));
                    seq.fetch_add(1, Ordering::Release);
                    map.withdraw_table(blocker).expect("remove blocker");
                    result.expect("guest completed while publisher held");
                });
                entered
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("publisher entered");
            },
            dispatcher,
        );
        if contended {
            release.send(()).expect("publisher alive");
        }
        outcome.expect("production loader runtime")
    });
    let counters = outcome
        .physical
        .syscall_counters()
        .expect("stopped counters");
    let refusals: u64 = counters
        .refused
        .iter()
        .map(|counter| counter.load(std::sync::atomic::Ordering::Acquire))
        .sum();
    assert_eq!(
        refusals, 0,
        "native syscall refusal counters; run={:?}",
        outcome.run
    );
    assert_eq!(
        outcome.run.exit_code, 0,
        "open returns its errno as the exit code; 42=close failure, 43=fd reuse failure: {:?}",
        outcome.run
    );
    assert!(!outcome.run.trap_limit_hit);
    let witness = outcome
        .run
        .report
        .execution_witness
        .expect("KVM execution population");
    assert_eq!(witness.backend, "kvm-x86-cpl0");
    assert_eq!(witness.guest_entries, 7, "three pairs and exit_group");
    assert!(witness.guest_refusal_families.is_empty());
}

/// #1714: glibc's dynamic loader as the run root, on the production CPL0
/// path. The root opens a library in its ring namespace, then reads, preads,
/// seeks, `fstat`s (x86's 144-byte record) and `AT_EMPTY_PATH`-stats that
/// descriptor there, reports through `writev`, and narrows a page of its own
/// ELF image with the RELRO `mprotect`. Before the fix every descriptor call
/// went to the host table (EBADF, exit 11), `writev` and the image
/// `mprotect` were counted ENOSYS (exit 18, 19), and every staged output came
/// back EFAULT.
#[test]
fn serial_host_root_loader_reads_stats_and_protects_through_the_ring() {
    let dir = tempfile::tempdir().expect("loader file directory");
    let path = dir.path().join("library");
    std::fs::write(&path, b"loader library").expect("loader source file");
    let define = format!("-DFILE_PATH=\"{}\"", path.display());
    let out = dir.path().join("written");
    let out_define = format!("-DOUT_PATH=\"{}\"", out.display());
    let elf = native_exit_fixture_with_flags("native_root_loader_io.S", &[&define, &out_define]);
    let oracle = dir.path().join("oracle");
    carrick_test_support::executable::write_executable_mode(&oracle, &elf, 0o700);
    let native = std::process::Command::new("timeout")
        .arg("10")
        .arg(&oracle)
        .output()
        .expect("bounded native loader control");
    assert!(native.status.success(), "native result: {native:?}");
    assert_eq!(native.stdout, b"wv-ok\n");
    std::fs::remove_file(&out).expect("native control output");
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        128,
        ROOT_AFFINITY_LOADED,
        |_| {},
        dispatcher,
    )
    .expect("production loader runtime");
    let counters = outcome
        .physical
        .syscall_counters()
        .expect("stopped counters");
    let refused: Vec<(usize, u64)> = counters
        .refused
        .iter()
        .enumerate()
        .map(|(nr, counter)| (nr, counter.load(std::sync::atomic::Ordering::Acquire)))
        .filter(|(_, count)| *count != 0)
        .collect();
    assert_eq!(
        (outcome.run.exit_code, refused.as_slice()),
        (0, &[][..]),
        "exit is the failed step (11 read, 15/16 fstat, 17 newfstatat, 18 writev, \
         19 mprotect, 22 write); refusals are (x86 nr, count): {:?}",
        outcome.run
    );
    assert_eq!(outcome.run.stdout, native.stdout);
    assert_eq!(std::fs::read(&out).expect("guest output"), b"data");
    assert!(!outcome.run.trap_limit_hit);
}

/// Run one `native_ring_descriptors.S` mode on the production CPL0 path,
/// after the native oracle exits 0 with it. Returns the guest's exit code
/// (the failed step) and its nonzero refusal counters as (x86 nr, count).
fn ring_descriptor_run(mode: &str) -> (i32, Vec<(usize, u64)>) {
    let dir = tempfile::tempdir().expect("ring descriptor directory");
    let path = dir.path().join("library");
    std::fs::write(&path, b"loader library").expect("ring descriptor file");
    let file = format!("-DFILE_PATH=\"{}\"", path.display());
    let directory = format!("-DDIR_PATH=\"{}\"", dir.path().display());
    let elf =
        native_exit_fixture_with_flags("native_ring_descriptors.S", &[mode, &file, &directory]);
    let oracle = dir.path().join("oracle");
    carrick_test_support::executable::write_executable_mode(&oracle, &elf, 0o700);
    let native = std::process::Command::new("timeout")
        .arg("10")
        .arg(&oracle)
        .output()
        .expect("bounded native ring descriptor control");
    assert!(native.status.success(), "{mode} native result: {native:?}");
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        128,
        ROOT_AFFINITY_LOADED,
        |_| {},
        dispatcher,
    )
    .expect("ring descriptor production runtime");
    assert!(!outcome.run.trap_limit_hit, "{mode}: {:?}", outcome.run);
    let counters = outcome
        .physical
        .syscall_counters()
        .expect("stopped counters");
    let refused = counters
        .refused
        .iter()
        .enumerate()
        .map(|(nr, counter)| (nr, counter.load(std::sync::atomic::Ordering::Acquire)))
        .filter(|(_, count)| *count != 0)
        .collect();
    (outcome.run.exit_code, refused)
}

/// #2138 P0-1: a bad descriptor on a ring-served call is the ring's EBADF.
/// The run root's `writev`, `getdents64` and `statx(AT_EMPTY_PATH)` on fd
/// -1 and on a closed descriptor each return -EBADF (9) with no refusal.
/// Red before the fix: an absent descriptor declined the stage, so these
/// calls, which have no x86 host crossing, were counted ENOSYS (exit 20).
#[test]
fn serial_host_root_bad_descriptor_on_ring_served_calls_is_ebadf() {
    assert_eq!(
        ring_descriptor_run("-DBAD_FD"),
        (0, vec![]),
        "exit is the failed step (20-22 fd -1, 30-32 closed fd: writev, getdents64, \
         statx); refusals are (x86 nr, count)"
    );
}

/// #2138 P0-2: the run root opens a directory in its ring namespace and
/// `getdents64` copies its `linux_dirent64` entries out, then reports the
/// end. Red on main: root `getdents64` was a counted ENOSYS (exit 31).
#[test]
fn serial_host_root_getdents64_lists_a_ring_directory() {
    assert_eq!(
        ring_descriptor_run("-DROOT_DIR"),
        (0, vec![]),
        "exit is the failed step (30 open, 31 getdents64, 32 no \"library\", 33 not at \
         the end); refusals are (x86 nr, count)"
    );
}

/// #2138 P0-2: a fork child's inherited ring descriptors are served in
/// ring. The run root opens a file and a directory in its ring namespace and
/// forks; the child reads, preads (keeping the cursor), seeks, `fstat`s (x86
/// layout) and `getdents64`s them. Red on main: the descendant's `read`
/// crossed with no host task context and was refused (exit 51).
#[test]
fn serial_host_fork_child_reads_its_inherited_ring_descriptors() {
    assert_eq!(
        ring_descriptor_run("-DCHILD"),
        (0, vec![]),
        "exit is the failed step (38/39 root opens, 40-42 fork and wait, 51 read, \
         52 pread64, 53/54 lseek, 55/56 fstat, 61-63 getdents64); refusals are \
         (x86 nr, count)"
    );
}

/// Run `test` in a separate `timeout`-bounded process: a parked guest need
/// not consume the pool's exit budget, so a lost wake must not hang CI.
fn bounded_witness(test: &str, witness: impl FnOnce()) {
    const CHILD: &str = "CARRICK_REDIRECT_WITNESS_CHILD";
    if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new(test)) {
        witness();
        return;
    }
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=1", "30"])
        .arg(std::env::current_exe().expect("current test executable"))
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, test)
        .output()
        .expect("bounded redirect witness");
    assert!(
        output.status.success(),
        "bounded child witness: {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Production x86 dispatch with fd 1 redirected to a real host file (seeded
/// through production dispatch like a shell's `>`), returning the guest exit
/// code and the destination file's bytes.
fn redirected_stdout_fixture(flags: &[&str]) -> (i32, Vec<u8>) {
    let dir = tempfile::tempdir().expect("redirect directory");
    let path = dir.path().join("stdout");
    let elf = native_exit_fixture_with_flags("native_redirect_write.S", flags);
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    let root = dispatcher
        .capture_one_task_context()
        .expect("redirect task");
    let mut path_bytes = path.as_os_str().as_encoded_bytes().to_vec();
    path_bytes.push(0);
    let mut memory = carrick_kernel::dispatch::LinearMemory::new(0x4000, path_bytes);
    let mut call = |nr: u64, args: [u64; 6]| {
        let outcome = dispatcher
            .dispatch(
                &root,
                carrick_kernel::dispatch::SyscallRequest::new(
                    nr,
                    carrick_kernel::compat::SyscallArgs::from(args),
                ),
                &mut memory,
                &carrick_kernel::compat::CompatReporter::default(),
            )
            .expect("production setup call");
        let carrick_kernel::dispatch::DispatchOutcome::Returned { value } = outcome else {
            panic!("setup call {nr} failed: {outcome:?}");
        };
        value
    };
    // openat(AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC, 0644), then
    // dup3(fd, 1, 0) and close(fd): canonical (aarch64) numbering.
    let fd = call(56, [(-100_i64) as u64, 0x4000, 0x241, 0o644, 0, 0]);
    assert_eq!(fd, 3);
    assert_eq!(call(24, [3, 1, 0, 0, 0, 0]), 1);
    assert_eq!(call(57, [3, 0, 0, 0, 0, 0]), 0);
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        128,
        ROOT_AFFINITY_LOADED,
        |_| {},
        dispatcher,
    )
    .expect("redirected stdout production runtime");
    assert!(!outcome.run.trap_limit_hit, "{:?}", outcome.run);
    assert!(outcome.run.stdout.is_empty(), "{:?}", outcome.run.stdout);
    (
        outcome.run.exit_code,
        std::fs::read(&path).expect("redirect destination"),
    )
}

/// #1954 P0-1: a native child's `writev` to a host-file stdout is staged on
/// the retained host-file venue ahead of the strict x86 crossing refusal.
/// Red before the fix: counted ENOSYS (exit 218) and an empty file.
#[test]
fn serial_host_native_child_writev_reaches_redirected_host_file() {
    bounded_witness(
        "serial_host_native_child_writev_reaches_redirected_host_file",
        || {
            let (exit, bytes) = redirected_stdout_fixture(&[]);
            assert_eq!(exit, 12, "writev result (218 = ENOSYS, 242 = EFAULT)");
            assert_eq!(bytes, b"hello world\n");
        },
    );
}

/// #1954 P0-3: an untouched readable anonymous page is a valid source. The
/// staged copy's fault is supplied through the owner fault path and the
/// syscall retried, so the file receives zeros instead of EFAULT (exit 242).
#[test]
fn serial_host_native_child_write_from_untouched_page_supplies_zeros() {
    bounded_witness(
        "serial_host_native_child_write_from_untouched_page_supplies_zeros",
        || {
            let (exit, bytes) = redirected_stdout_fixture(&["-DUNTOUCHED"]);
            assert_eq!(exit, 100, "write result (218 = ENOSYS, 242 = EFAULT)");
            assert_eq!(bytes, vec![0; 100]);
        },
    );
}

/// #1954: a native child's write whose buffer is readable for 16 bytes and
/// then unmapped returns that prefix and writes it, as Linux's short write;
/// a writev whose second vector starts on the unmapped page returns the
/// first vector's 5 bytes. The refused supply never discards the prefix.
#[test]
fn serial_host_native_child_write_prefix_before_unmapped_page_is_short() {
    bounded_witness(
        "serial_host_native_child_write_prefix_before_unmapped_page_is_short",
        || {
            let (exit, bytes) = redirected_stdout_fixture(&["-DPREFIX"]);
            assert_eq!(exit, 16, "write result (218 = ENOSYS, 242 = EFAULT)");
            assert_eq!(bytes, b"0123456789abcdef");
            let (exit, bytes) = redirected_stdout_fixture(&["-DPREFIXV"]);
            assert_eq!(exit, 5, "writev result (218 = ENOSYS, 242 = EFAULT)");
            assert_eq!(bytes, b"hello");
        },
    );
}

/// #1954 P0-2: with no ring descriptor table published for the initial task,
/// its stdout write keeps the existing route instead of counted ENOSYS (-38).
#[test]
fn serial_host_initial_write_without_ring_table_keeps_stdout_route() {
    bounded_witness(
        "serial_host_initial_write_without_ring_table_keeps_stdout_route",
        || {
            let elf = native_exit_fixture_with_flags("native_redirect_write.S", &["-DROOT_WRITE"]);
            let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
            let key = dispatcher
                .capture_one_task_context()
                .expect("root")
                .resources()
                .files()
                .id()
                .raw();
            let program =
                carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
            let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
                &program,
                64,
                ROOT_AFFINITY_LOADED,
                |carrier| {
                    carrier
                        .ipc_table_map()
                        .expect("retained map")
                        .table_map()
                        .withdraw_table(key)
                        .expect("root binding");
                },
                dispatcher,
            )
            .expect("unpublished-table production runtime");
            assert_eq!(
                outcome.run.exit_code, 12,
                "write result (218 = ENOSYS): {:?}",
                outcome.run
            );
            assert_eq!(outcome.run.stdout, b"hello world\n");
        },
    );
}

/// #2157 B0 T1: a fork child's x86-allowed crossing that no ring stage serves
/// is a counted ENOSYS in ring, as ARM answers a fork child's unclaimed
/// native call, never a carrier failure. Two children (A's `read(0, buf, 0)`,
/// B's `lseek(0, 0, SEEK_CUR)`) each report to the root by signal and then
/// block until their sibling has made its own call, so children that ran one
/// after another fail. The handshake, not a delay, proves both were live;
/// every wait is a bounded 5 s `rt_sigtimedwait`. Each child exits with errno
/// 38, and the root's own `read(0, buf, 0)` keeps its host route and returns
/// 0. Red on main: the run failed with a typed `HostTaskContext`.
#[test]
fn two_live_children_unstaged_crossings_are_counted_enosys_and_root_is_served() {
    let elf = native_exit_fixture("native_child_unstaged_crossing.S");
    let outcome = try_run_pool_fixture_with_typed_failure(&elf, 256, ROOT_AFFINITY_IDLE_PEER)
        .unwrap_or_else(|failure| {
            panic!(
                "a child's unstaged crossing must be answered in ring, not fail the run: \
                 {:?} ({})",
                failure.authority_refusals, failure.error
            )
        });
    assert_eq!(
        outcome.run.exit_code, 7,
        "81/82 root read, 83/84 child A/B result, 91 fork/wait/pipe, 92 report timeout, \
         95 child status: {:?}",
        outcome.run
    );
    let counters = outcome
        .physical
        .syscall_counters()
        .expect("stopped counters");
    let load = |counter: &[std::sync::atomic::AtomicU64], nr: usize| {
        counter[nr].load(std::sync::atomic::Ordering::Acquire)
    };
    const X86_SYS_READ: usize = 0;
    const X86_SYS_LSEEK: usize = 8;
    for (name, nr) in [("read", X86_SYS_READ), ("lseek", X86_SYS_LSEEK)] {
        assert_eq!(
            load(&counters.refused_child, nr),
            1,
            "child {name} refusal credits descendant origin"
        );
        assert_eq!(
            load(&counters.refused, nr),
            1,
            "only the child's {name} is refused; the root's read is served"
        );
        assert_eq!(
            load(&counters.venue_refused, nr),
            0,
            "child {name} is refused in ring, not by the carrier venue"
        );
    }
}

/// Assemble one `native_crossing_operand.S` variant, run it natively as the
/// Linux oracle, and return the ELF with the oracle's exit code.
fn crossing_operand_fixture(flags: &[&str]) -> (Vec<u8>, i32) {
    let elf = native_exit_fixture_with_flags("native_crossing_operand.S", flags);
    let dir = tempfile::tempdir().expect("oracle directory");
    let oracle = dir.path().join("oracle");
    carrick_test_support::executable::write_executable_mode(&oracle, &elf, 0o700);
    let native = std::process::Command::new("timeout")
        .arg("10")
        .arg(&oracle)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("bounded native oracle");
    (elf, native.status.code().expect("native oracle exit code"))
}

/// #2157 B0 T2, stdio host object: fd 5 names the stderr host object, so the
/// resolver sends the write as a host-object write and "S" reaches stderr.
#[test]
fn crossing_operand_stdio_host_object_writes_through_its_binding() {
    let (elf, oracle) = crossing_operand_fixture(&["-DSTDIO_OBJECT"]);
    assert_eq!(oracle, 1, "native oracle");
    let outcome = try_run_pool_fixture_with_root_affinity(&elf, 64, ROOT_AFFINITY_LOADED)
        .expect("stdio host object run");
    assert_eq!(outcome.run.exit_code, oracle, "{:?}", outcome.run);
    assert_eq!(outcome.run.stderr, b"S");
    assert!(outcome.run.stdout.is_empty(), "{:?}", outcome.run.stdout);
}

/// #2157 B0 T2, host-backed: a host file seeded before entry passes to the
/// host unchanged, and `pread64` returns its first four bytes.
#[test]
fn crossing_operand_host_backed_fd_passes_to_the_host() {
    let dir = tempfile::tempdir().expect("host-backed directory");
    let path = dir.path().join("source");
    std::fs::write(&path, b"ABCDEFGH").expect("host-backed source");
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    let root = dispatcher.capture_one_task_context().expect("source task");
    let mut path_bytes = path.as_os_str().as_encoded_bytes().to_vec();
    path_bytes.push(0);
    let mut memory = carrick_kernel::dispatch::LinearMemory::new(0x4000, path_bytes);
    let opened = dispatcher
        .dispatch(
            &root,
            carrick_kernel::dispatch::SyscallRequest::new(
                56,
                carrick_kernel::compat::SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &carrick_kernel::compat::CompatReporter::default(),
        )
        .expect("production source open");
    let carrick_kernel::dispatch::DispatchOutcome::Returned { value: fd } = opened else {
        panic!("source open failed: {opened:?}");
    };
    let preopened = format!("-DPREOPENED_FD={fd}");
    let elf =
        native_exit_fixture_with_flags("native_crossing_operand.S", &["-DHOST_BACKED", &preopened]);
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("ELF program");
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        64,
        ROOT_AFFINITY_LOADED,
        |_| {},
        dispatcher,
    )
    .expect("host-backed run");
    assert_eq!(
        outcome.run.exit_code, 4,
        "pread64 result (70 = wrong bytes, 9 = EBADF, 38 = ENOSYS): {:?}",
        outcome.run
    );
}

/// #2157 B0 T2, in-zone: a pipe is the ring's object, so its `lseek` is
/// answered in ring and never reaches the host under the guest's number.
#[test]
fn crossing_operand_in_zone_fd_is_answered_in_ring() {
    let (elf, oracle) = crossing_operand_fixture(&["-DIN_ZONE"]);
    assert_eq!(oracle, 29, "native oracle: ESPIPE");
    let outcome = try_run_pool_fixture_with_root_affinity(&elf, 64, ROOT_AFFINITY_LOADED)
        .expect("in-zone run");
    assert_eq!(
        outcome.run.exit_code, oracle,
        "lseek errno on a pipe (29 = ESPIPE, 38 = ENOSYS, 9 = EBADF): {:?}",
        outcome.run
    );
}

/// #2157 B0 T2, absent: a closed descriptor is EBADF (errno 9).
#[test]
fn crossing_operand_absent_fd_is_ebadf() {
    let (elf, oracle) = crossing_operand_fixture(&["-DABSENT"]);
    assert_eq!(oracle, 9, "native oracle: EBADF");
    let outcome = try_run_pool_fixture_with_root_affinity(&elf, 64, ROOT_AFFINITY_LOADED)
        .expect("absent run");
    assert_eq!(outcome.run.exit_code, oracle, "{:?}", outcome.run);
}

/// #2157 B0 T2: a stdio host object under a number outside 0..=2 resolves
/// through its binding for every fd-operand crossing, not only for a
/// hand-listed call and fd range. `dup2(0, 5); read(5, buf, 0)` reads the
/// stdin object (0, as Linux with stdin on /dev/null). Red on main: the
/// guest's fd 5 crossed to the host unchanged.
#[test]
fn crossing_operand_duplicated_stdin_reads_through_its_binding() {
    let (elf, oracle) = crossing_operand_fixture(&["-DDUP_STDIN"]);
    assert_eq!(oracle, 0, "native oracle");
    let outcome = try_run_pool_fixture_with_root_affinity(&elf, 64, ROOT_AFFINITY_LOADED)
        .expect("duplicated stdin run");
    assert_eq!(
        outcome.run.exit_code, oracle,
        "read(5) errno (9 = EBADF, 38 = ENOSYS): {:?}",
        outcome.run
    );
}

fn cwd_run(mode: &[&str]) {
    let dir = tempfile::tempdir().expect("cwd witness directory");
    let mut flags = mode.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    for (name, leaf) in [("BASE", "a"), ("PARENT", "b"), ("CHILD", "c")] {
        let path = dir.path().join(leaf);
        std::fs::create_dir(&path).expect("create cwd directory");
        std::fs::write(path.join("marker"), leaf.as_bytes())
            .expect("write directory-specific marker");
        flags.push(format!("-D{name}_PATH=\"{}\"", path.display()));
    }
    let flags = flags.iter().map(String::as_str).collect::<Vec<_>>();
    let elf = native_exit_fixture_with_flags("native_cwd.S", &flags);
    let oracle = dir.path().join("oracle");
    carrick_test_support::executable::write_executable_mode(&oracle, &elf, 0o700);
    let native = std::process::Command::new("timeout")
        .arg("10")
        .arg(&oracle)
        .output()
        .expect("bounded native cwd control");
    assert!(native.status.success(), "native: {native:?}");
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("cwd ELF program");
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        512,
        if mode.contains(&"-DCONCURRENT") {
            3
        } else {
            ROOT_AFFINITY_LOADED
        },
        |_| {},
        dispatcher,
    )
    .expect("cwd production runtime");
    assert_eq!(outcome.run.exit_code, 0, "{mode:?}: {:?}", outcome.run);
    assert!(!outcome.run.trap_limit_hit);
}

#[test]
fn serial_host_root_cwd_and_relative_open_agree() {
    bounded_witness("serial_host_root_cwd_and_relative_open_agree", || {
        cwd_run(&[])
    });
}
#[test]
fn serial_host_fork_cwd_is_inherited_and_isolated() {
    bounded_witness("serial_host_fork_cwd_is_inherited_and_isolated", || {
        cwd_run(&["-DCHILD"])
    });
}
#[test]
fn serial_host_two_live_processes_keep_distinct_cwds() {
    bounded_witness("serial_host_two_live_processes_keep_distinct_cwds", || {
        cwd_run(&["-DCHILD", "-DCONCURRENT"])
    });
}
