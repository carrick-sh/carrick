use carrick_mem::x86_initial_image::prepare_x86_elf;
use carrick_vmm_kvm::cpl0_boot::{Cpl0Carrier, InitialReservationLimits, InitialTaskBinding};

#[path = "physical_inventory.rs"]
mod physical_inventory;
pub(crate) use physical_inventory::physical_inventory;

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
    let program = carrick_mem::elf::ElfProgram::load(elf, 62, &|_| None).expect("ELF program");
    try_run_program_with(&program, max_exits, configure)
}

pub fn try_run_program_with(
    program: &carrick_mem::elf::ElfProgram<'_>,
    max_exits: usize,
    configure: impl FnOnce(&mut Cpl0Carrier),
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_kernel::run_result::RuntimeError,
> {
    try_run_program_with_root_affinity(program, max_exits, ROOT_AFFINITY_ANY, configure)
}

/// The root may run on either guest CPU.
pub const ROOT_AFFINITY_ANY: u64 = 3;
/// Only CPU 0 (the loaded lane) may schedule the root and its inherited children.
pub const ROOT_AFFINITY_LOADED: u64 = 1;
/// Only the idle peer (CPU 1) may schedule the root once it leaves CPU 0;
/// its forked children inherit the mask, so EL1 queues them only there.
pub const ROOT_AFFINITY_IDLE_PEER: u64 = 2;

pub fn try_run_pool_fixture_with_root_affinity(
    elf: &[u8],
    max_exits: usize,
    affinity: u64,
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_kernel::run_result::RuntimeError,
> {
    let program = carrick_mem::elf::ElfProgram::load(elf, 62, &|_| None).expect("ELF program");
    try_run_program_with_root_affinity(&program, max_exits, affinity, |_| {})
}

pub fn try_run_pool_fixture_with_typed_failure(
    elf: &[u8],
    max_exits: usize,
    affinity: u64,
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_runtime::prepare::PreparedKvmPoolFailure,
> {
    let program = carrick_mem::elf::ElfProgram::load(elf, 62, &|_| None).expect("ELF program");
    try_run_program_with_root_affinity_typed(&program, max_exits, affinity, |_| {})
}

pub fn try_run_pool_fixture_with_admitted_pipe(
    elf: &[u8],
    max_exits: usize,
    affinity: u64,
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_kernel::run_result::RuntimeError,
> {
    struct PipeFdScratch([u8; 8]);
    impl carrick_guest_mem::GuestMemory for PipeFdScratch {
        fn protections(&self) -> Option<carrick_guest_mem::LegacyProtectionRead<'_>> {
            None
        }
        fn read_bytes_raw(
            &self,
            address: u64,
            length: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            let offset = usize::try_from(address).unwrap_or(usize::MAX);
            self.0
                .get(offset..offset.saturating_add(length))
                .map(<[u8]>::to_vec)
                .ok_or(carrick_guest_mem::MemoryError::OutOfBounds { address, length })
        }
        fn write_bytes_raw(
            &mut self,
            address: u64,
            bytes: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            let offset = usize::try_from(address).unwrap_or(usize::MAX);
            let slot = self
                .0
                .get_mut(offset..offset.saturating_add(bytes.len()))
                .ok_or(carrick_guest_mem::MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                })?;
            slot.copy_from_slice(bytes);
            Ok(())
        }
    }
    impl carrick_guest_mem::CurrentMmMemory for PipeFdScratch {}

    let program = carrick_mem::elf::ElfProgram::load(elf, 62, &|_| None).expect("ELF program");
    let image = prepare_x86_elf(&program).expect("x86 ELF program");
    let extent =
        Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("bounded initial extent");
    let mut carrier =
        Cpl0Carrier::boot_production(physical_inventory(), extent).expect("production KVM image");
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    let root = dispatcher.capture_one_task_context().expect("issued root");
    let mut scratch = PipeFdScratch([0u8; 8]);
    let outcome = dispatcher
        .dispatch(
            &root,
            carrick_kernel::dispatch::SyscallRequest::new(
                59,
                carrick_kernel::compat::SyscallArgs::from([0, 0, 0, 0, 0, 0]),
            ),
            &mut scratch,
            &carrick_kernel::compat::CompatReporter::default(),
        )
        .expect("dispatch pipe2 for initial task");
    assert_eq!(
        outcome,
        carrick_kernel::dispatch::DispatchOutcome::Returned { value: 0 }
    );
    let read_fd = i32::from_le_bytes([scratch.0[0], scratch.0[1], scratch.0[2], scratch.0[3]]);
    let write_fd = i32::from_le_bytes([scratch.0[4], scratch.0[5], scratch.0[6], scratch.0[7]]);
    assert_eq!((read_fd, write_fd), (3, 4));
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
                affinity,
                lifecycle_page: 0,
                control_slot: 0,
            },
        })
        .expect("bind issued root");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("initial guest MM");
    carrier
        .admit_initial_pipe_fds(read_fd, write_fd)
        .expect("admit initial pipe fds");
    carrick_runtime::prepare::try_run_prepared_kvm_pool(carrier, root, dispatcher, max_exits)
        .map_err(|failure| failure.error)
}

pub fn try_run_program_with_root_affinity(
    program: &carrick_mem::elf::ElfProgram<'_>,
    max_exits: usize,
    affinity: u64,
    configure: impl FnOnce(&mut Cpl0Carrier),
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_kernel::run_result::RuntimeError,
> {
    try_run_program_with_root_affinity_typed(program, max_exits, affinity, configure)
        .map_err(|failure| failure.error)
}

pub fn try_run_program_with_root_affinity_typed(
    program: &carrick_mem::elf::ElfProgram<'_>,
    max_exits: usize,
    affinity: u64,
    configure: impl FnOnce(&mut Cpl0Carrier),
) -> Result<
    carrick_runtime::prepare::PreparedKvmPoolOutcome,
    carrick_runtime::prepare::PreparedKvmPoolFailure,
> {
    let image = prepare_x86_elf(program).expect("x86 ELF program");
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
                affinity,
                lifecycle_page: 0,
                control_slot: 0,
            },
        })
        .expect("bind issued root");
    carrier
        .load_guest_mm(&image, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("initial guest MM");
    configure(&mut carrier);
    carrick_runtime::prepare::try_run_prepared_kvm_pool(carrier, root, dispatcher, max_exits)
}
