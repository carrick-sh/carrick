use carrick_mem::x86_initial_image::prepare_static_x86_elf;
use carrick_vmm_kvm::cpl0_boot::{Cpl0Carrier, InitialReservationLimits, InitialTaskBinding};

#[path = "physical_inventory.rs"]
mod physical_inventory;
use physical_inventory::physical_inventory;

pub fn run_pool_fixture(
    elf: &[u8],
    max_exits: usize,
) -> carrick_runtime::prepare::PreparedKvmPoolOutcome {
    run_pool_fixture_with(elf, max_exits, |_| {})
}

pub fn run_pool_fixture_with(
    elf: &[u8],
    max_exits: usize,
    configure: impl FnOnce(&mut Cpl0Carrier),
) -> carrick_runtime::prepare::PreparedKvmPoolOutcome {
    try_run_pool_fixture_with(elf, max_exits, configure).expect("shared pool fixture")
}

pub fn try_run_pool_fixture_with(
    elf: &[u8],
    max_exits: usize,
    configure: impl FnOnce(&mut Cpl0Carrier),
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_kernel::run_result::RuntimeError,
> {
    try_run_pool_fixture_inner(elf, max_exits, configure, None)
}

#[allow(dead_code)] // Only the fault fixture installs an exact mid-forward injection.
pub fn try_run_pool_fixture_with_first_forward_hook(
    elf: &[u8],
    max_exits: usize,
    hook: Box<
        dyn FnOnce(
                &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease,
            ) -> Result<(), carrick_hal::TrapError>
            + Send,
    >,
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_kernel::run_result::RuntimeError,
> {
    try_run_pool_fixture_inner(elf, max_exits, |_| {}, Some(hook))
}

fn try_run_pool_fixture_inner(
    elf: &[u8],
    max_exits: usize,
    configure: impl FnOnce(&mut Cpl0Carrier),
    hook: Option<
        Box<
            dyn FnOnce(
                    &mut carrick_vmm_kvm::cpl0_boot::ProductionCpuLease,
                ) -> Result<(), carrick_hal::TrapError>
                + Send,
        >,
    >,
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_kernel::run_result::RuntimeError,
> {
    let image = prepare_static_x86_elf(elf).expect("static x86 ELF");
    let extent =
        Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("bounded initial extent");
    let mut carrier =
        Cpl0Carrier::boot_production(physical_inventory(), extent).expect("production KVM image");
    let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    let root = dispatcher.capture_one_task_context().expect("issued root");
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
                affinity: 3,
                lifecycle_page: 0,
                control_slot: 0,
            },
        })
        .expect("bind issued root");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("initial guest MM");
    configure(&mut carrier);
    if let Some(hook) = hook {
        carrick_runtime::prepare::run_prepared_kvm_pool_with_first_forward_hook(
            carrier, root, dispatcher, max_exits, hook,
        )
    } else {
        carrick_runtime::prepare::run_prepared_kvm_pool(carrier, root, dispatcher, max_exits)
    }
}
