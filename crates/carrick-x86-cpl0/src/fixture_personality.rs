//! Fixture OS personality implementation for synthetic observation tests.

#![cfg(all(target_os = "none", target_arch = "x86_64"))]

use crate::lifecycle;
use crate::progress;

use carrick_el1::isa::x86::context::native::{
    CpuBinding, DIRECT_VA, FATAL_PORT, NativeFrame, OBSERVE_ALLOCATOR,
    OBSERVE_CPL0_UACCESS_SHOOTDOWN, OBSERVE_DESCRIPTOR_PREPARE_PUBLISH, OBSERVE_DESCRIPTOR_PROTECT,
    OBSERVE_FORK_TABLE_WINDOW, OBSERVE_INITIAL_MM, OBSERVE_MMU_DRAIN, OBSERVE_MMU_ROOT,
    OBSERVE_NATIVE, OBSERVE_PORTAL_WINDOW, OBSERVE_RETIRE_REPOINT, OBSERVE_SHARED_COW_FAULT,
    OBSERVE_SHARED_PREPARED_FAULT,
};
use carrick_el1::isa::x86::context::scheduler::XsaveArea;
use carrick_el1::personality::{sched, thread_setup::GuestLifecycleVenue};
use carrick_el1_abi::{Counters, CurrentTask};
use carrick_guest_arch::{EntryArch, NativeReturnWord, UserVa};
use carrick_personality_linux::crossing::{HostCrossingSet, evaluate_host_crossing};
use carrick_personality_linux::dispatch::CompletionRoute;
use carrick_personality_linux::entry::{CanonicalCall, decode_x86_snapshot};
use carrick_x86_carrier::entry::{
    InitialWords, PageFaultStack, control_doorbell, fatal_error, forward_to_host, halt,
    notify_work, prepare_user_page_fault,
};
use carrick_x86_carrier::personality::{
    CallContext, ControlFlow, EntryDecodeError, ExecutionContext, OwnedContinuation, Personality,
    PersonalityAbi,
};
use core::sync::atomic::{AtomicU64, Ordering};

use carrick_x86_cpl0::linux_personality::{self, NativeDispatch};
use carrick_x86_cpl0::native_execution;
use carrick_x86_cpl0::{ProductionBoundary, production_boundary};

pub static SHARED_FAULT_MAILBOX: carrick_el1_abi::FrameGrantMailbox =
    carrick_el1_abi::FrameGrantMailbox::new();
pub static SHARED_COW_POOL: carrick_el1_abi::CowGrantPool = carrick_el1_abi::CowGrantPool::new();
pub static FORK_RESIDENCY_ADDRESS: AtomicU64 = AtomicU64::new(0);

pub fn lifecycle_invariant_error(reason: lifecycle::LifecycleInvariant) -> ! {
    // SAFETY: terminal kernel custody error; report the named stage
    // without replaying a partially committed syscall on the host.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") FATAL_PORT,
            in("rax") reason as u64, options(nostack, preserves_flags));
    }
    halt()
}

fn fixture_edit(
    va: u64,
    sequence: core::num::NonZeroU64,
    operation: carrick_guest_arch::EditOperation,
) -> Result<carrick_mmu_core::x86::descriptor_txn::DescriptorReceipt, carrick_el1::isa::ArchError> {
    use carrick_guest_arch::{
        EditIntent, EditOwner, FrameGpa, GuestLen, KernelVa, MmuEditArch, RootGpa, TableWindow,
        UserRange, UserVa,
    };
    let root = RootGpa::page_aligned(FrameGpa::new(0x60_0000))
        .ok_or(carrick_el1::isa::ArchError::Unbound)?;
    let mm_key = carrick_el1::isa::x86::context::current_cpu_binding()
        .and_then(|binding| {
            if binding.task_address == 0 {
                None
            } else {
                // SAFETY: the active CPU binding is retained from CPL0 bootstrap and
                // names this CPU's task until its final user return.
                let task =
                    unsafe { &*(binding.task_address as *const carrick_el1_abi::CurrentTask) };
                core::num::NonZeroU64::new(task.mm.key.load(Ordering::Acquire))
            }
        })
        .unwrap_or(core::num::NonZeroU64::MIN);
    // SAFETY: this fixture runs one vCPU at a time with the retained
    // root, so each sequential native descriptor edit is exclusive.
    let owner = unsafe { EditOwner::issue(root, mm_key, sequence) };
    let range = UserRange::checked(UserVa::new(va), GuestLen::new(4096))
        .ok_or(carrick_el1::isa::ArchError::Unbound)?;
    let intent = EditIntent::checked(owner, range, operation, &[])
        .ok_or(carrick_el1::isa::ArchError::Unbound)?;
    let mut arch = carrick_el1::isa::x86::Kernel::new(carrick_el1::isa::x86::X86Backend);
    // SAFETY: KVM retains and maps the 448-page PML4 window under the
    // upper-half supervisor direct window; the sibling vCPU is stopped here.
    let tables = unsafe {
        TableWindow::issue(
            root.address(),
            KernelVa::new(DIRECT_VA + root.address().raw()),
            GuestLen::new(carrick_el1_abi::X86_CPL0_TABLE_ARENA_BYTES),
        )
    }
    .ok_or(carrick_el1::isa::ArchError::Unbound)?;
    // SAFETY: the exact editor and mapped table window remain held until
    // the native transaction and its drain receipt have settled.
    unsafe { arch.execute_edit(intent, tables) }
}

pub const FIXTURE_TABLE_START: u64 = carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_GPA
    + carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_SIZE;
pub const FIXTURE_TABLE_END: u64 = 0xd4_0000;

pub fn fixture_initial_words() -> InitialWords {
    let root = carrick_el1::isa::x86::hardware_live_root()
        .unwrap_or_else(|_| carrick_el1::isa::x86::fatal_entry_binding());
    InitialWords::new(
        FIXTURE_TABLE_START,
        FIXTURE_TABLE_END,
        Some(root),
        None,
        None,
    )
}

pub struct InitialFrames {
    next_table: u64,
    next_data: u64,
}

impl InitialFrames {
    pub fn zeroed(pa: u64) {
        // SAFETY: these private fixture physical pages are mapped RW by
        // the one retained direct window and not reachable by user PTEs.
        unsafe { core::ptr::write_bytes((DIRECT_VA + pa) as *mut u8, 0, 4096) };
    }
}

impl carrick_el1::isa::x86::initial_mm::InitialFrameSource for InitialFrames {
    fn take_zeroed_table(&mut self) -> Option<carrick_guest_arch::RootGpa> {
        use carrick_guest_arch::{FrameGpa, RootGpa};
        if self.next_table >= FIXTURE_TABLE_END {
            return None;
        }
        let pa = self.next_table;
        self.next_table += 4096;
        Self::zeroed(pa);
        RootGpa::page_aligned(FrameGpa::new(pa))
    }
    fn take_zeroed_data(&mut self) -> Option<carrick_el1::isa::x86::initial_mm::InitialDataGrant> {
        use carrick_el1::isa::x86::initial_mm::InitialDataGrant;
        use carrick_guest_arch::{EditBacking, FrameGpa};
        if self.next_data >= 0xd1_0000 {
            return None;
        }
        let pa = self.next_data;
        self.next_data += 4096;
        Self::zeroed(pa);
        let identity = core::num::NonZeroU64::new(pa)?;
        Some(InitialDataGrant {
            frame: FrameGpa::new(pa),
            backing: EditBacking {
                frame_id: identity,
                mapping_id: identity,
                owner_generation: core::num::NonZeroU64::MIN,
                inventory_revision: core::num::NonZeroU64::MIN,
            },
        })
    }
    fn copy_guest_data(
        &mut self,
        grant: carrick_el1::isa::x86::initial_mm::InitialDataGrant,
        offset: u16,
        source: carrick_guest_arch::FrameGpa,
        len: u16,
    ) -> bool {
        let dest = grant.frame.raw();
        let from = source.raw();
        if !((0xd0_0000..0xd1_0000).contains(&dest) || (0x40_0000..0x41_0000).contains(&dest))
            || !(0x10_000..0x11_000).contains(&from)
            || from + u64::from(len) > 0x11_000
            || u64::from(offset) + u64::from(len) > 4096
        {
            return false;
        }
        // SAFETY: this stopped fixture identity-maps the staged user code
        // page and retains its disjoint private destination grant under
        // the supervisor direct window. The fixture has SMAP disabled.
        unsafe {
            core::ptr::copy_nonoverlapping(
                from as *const u8,
                (DIRECT_VA + dest + u64::from(offset)) as *mut u8,
                usize::from(len),
            );
        }
        true
    }
    fn write_data(
        &mut self,
        grant: carrick_el1::isa::x86::initial_mm::InitialDataGrant,
        offset: u16,
        bytes: &[u8],
    ) -> bool {
        let pa = grant.frame.raw();
        if !((0xd0_0000..0xd1_0000).contains(&pa) || (0x40_0000..0x41_0000).contains(&pa))
            || usize::from(offset)
                .checked_add(bytes.len())
                .is_none_or(|end| end > 4096)
        {
            return false;
        }
        // SAFETY: the source is the fixed RX fixture ELF and the private
        // destination grant is disjoint, writable and retained by KVM.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (DIRECT_VA + pa + u64::from(offset)) as *mut u8,
                bytes.len(),
            );
        }
        true
    }
}

fn fixture_handled(
    frame: &mut NativeFrame,
    xsave: &mut XsaveArea,
    binding: &CpuBinding,
    task: &CurrentTask,
    counters: &Counters,
    call: &CanonicalCall,
) -> bool {
    let lifecycle_address = binding.scheduler_witness.load(Ordering::Acquire);
    if lifecycle_address == lifecycle::LIFECYCLE_LANE
        || lifecycle_address == lifecycle::LIFECYCLE_LANE + lifecycle::LIFECYCLE_STRIDE
    {
        // SAFETY: stopped-host bootstrap published and retains the aligned
        // native lane/zone/page custody for this exact CPU binding.
        let Some(mut lane) = (unsafe {
            lifecycle::acquire(
                frame,
                xsave,
                binding,
                task,
                counters,
                call.args,
                carrick_el1::personality::native_run_failure::complete_native_run_failure,
            )
        }) else {
            fatal_error(frame);
        };
        match carrick_personality_linux::dispatch::dispatch(
            call.canonical.raw(),
            u64::MAX,
            &mut lane,
        ) {
            carrick_personality_linux::dispatch::CompletionRoute::Served => {}
            carrick_personality_linux::dispatch::CompletionRoute::WithWork => {
                notify_work(frame);
            }
            carrick_personality_linux::dispatch::CompletionRoute::Forward
            | carrick_personality_linux::dispatch::CompletionRoute::HostCustody => {
                forward_to_host(frame);
            }
            _ => {
                fatal_error(frame);
            }
        }
        true
    } else {
        false
    }
}

pub enum FixtureCall {
    Syscall(CanonicalCall),
    ObserveNative,
    ObserveInitialMm,
    ObserveMmuRoot,
    ObservePortalWindow,
    ObserveForkTableWindow,
    ObserveRetireRepoint,
    ObserveMmuDrain,
    ObserveDescriptorProtect,
    ObserveDescriptorPreparePublish,
    ObserveSharedPreparedFault,
    ObserveSharedCowFault,
    ObserveAllocator,
    ObserveUserAccessWitness,
    ObserveCpl0UaccessShootdown,
    ObserveTransportWitness,
    ObserveContextWitness,
    ObserveInterruptWitness,
    ObserveExitGroup,
}

#[derive(Default)]
pub struct FixturePersonality;

impl PersonalityAbi<carrick_el1::isa::x86::Kernel> for FixturePersonality {
    type Call = FixtureCall;

    fn decode(
        &self,
        cx: &mut CallContext<'_, carrick_el1::isa::x86::Kernel>,
    ) -> Result<Self::Call, EntryDecodeError> {
        let snapshot = cx.snapshot()?;
        let rax = cx.frame().rax;
        if rax == OBSERVE_NATIVE {
            return Ok(FixtureCall::ObserveNative);
        }
        if rax == OBSERVE_INITIAL_MM {
            return Ok(FixtureCall::ObserveInitialMm);
        }
        if rax == OBSERVE_MMU_ROOT {
            return Ok(FixtureCall::ObserveMmuRoot);
        }
        if rax == OBSERVE_PORTAL_WINDOW {
            return Ok(FixtureCall::ObservePortalWindow);
        }
        if rax == OBSERVE_FORK_TABLE_WINDOW {
            return Ok(FixtureCall::ObserveForkTableWindow);
        }
        if rax == OBSERVE_RETIRE_REPOINT {
            return Ok(FixtureCall::ObserveRetireRepoint);
        }
        if rax == OBSERVE_MMU_DRAIN {
            return Ok(FixtureCall::ObserveMmuDrain);
        }
        if rax == OBSERVE_DESCRIPTOR_PROTECT {
            return Ok(FixtureCall::ObserveDescriptorProtect);
        }
        if rax == OBSERVE_DESCRIPTOR_PREPARE_PUBLISH {
            return Ok(FixtureCall::ObserveDescriptorPreparePublish);
        }
        if rax == OBSERVE_SHARED_PREPARED_FAULT {
            return Ok(FixtureCall::ObserveSharedPreparedFault);
        }
        if rax == OBSERVE_SHARED_COW_FAULT {
            return Ok(FixtureCall::ObserveSharedCowFault);
        }
        if rax == OBSERVE_ALLOCATOR {
            return Ok(FixtureCall::ObserveAllocator);
        }
        if rax == carrick_el1::isa::x86::user_access::USER_ACCESS_WITNESS {
            return Ok(FixtureCall::ObserveUserAccessWitness);
        }
        if rax == OBSERVE_CPL0_UACCESS_SHOOTDOWN {
            return Ok(FixtureCall::ObserveCpl0UaccessShootdown);
        }
        if rax == carrick_el1::isa::x86::transport::TRANSPORT_WITNESS {
            return Ok(FixtureCall::ObserveTransportWitness);
        }
        if rax == carrick_el1::isa::x86::context::CONTEXT_WITNESS {
            return Ok(FixtureCall::ObserveContextWitness);
        }
        if rax == carrick_el1::isa::x86::interrupt::INTERRUPT_WITNESS {
            return Ok(FixtureCall::ObserveInterruptWitness);
        }
        if rax == 231
            && carrick_el1::isa::x86::hardware_live_root()
                .is_ok_and(|root| matches!(root.address().raw(), 0xd3_0000 | 0x30_0000))
        {
            return Ok(FixtureCall::ObserveExitGroup);
        }
        decode_x86_snapshot(snapshot)
            .map(FixtureCall::Syscall)
            .ok_or(EntryDecodeError::UnsupportedAbi)
    }

    fn encode_return(
        &self,
        result: NativeReturnWord,
        frame: &mut NativeFrame,
    ) -> Result<(), EntryDecodeError> {
        frame.rax = result.0;
        Ok(())
    }
}

impl Personality for FixturePersonality {
    type Return = ();
    type Continuation = OwnedContinuation;

    fn is_counted_call(&self, call: &Self::Call) -> bool {
        matches!(call, FixtureCall::Syscall(_))
    }

    fn call_stack(&self, call: &Self::Call) -> UserVa {
        match call {
            FixtureCall::Syscall(c) => c.stack,
            _ => UserVa::new(0),
        }
    }

    fn dispatch(
        &mut self,
        call: Self::Call,
        cx: &mut ExecutionContext<'_>,
    ) -> ControlFlow<Self::Return, Self::Continuation> {
        let frame = &mut *cx.frame;
        let binding = cx.binding;
        let task = cx.task;
        let counters = cx.counters;

        if binding.scheduler_witness.load(Ordering::Acquire) != 0 {
            let mut arch = carrick_el1::isa::x86::kernel_arch();
            let Ok(saved) = arch.save_context(frame) else {
                fatal_error(frame);
            };
            if arch.load_context(frame, &saved).is_err() {
                fatal_error(frame);
            }
        }

        match call {
            FixtureCall::ObserveNative => {
                control_doorbell(frame);
                frame.rax = 0;
                ControlFlow::Return(())
            }
            FixtureCall::ObserveInitialMm => {
                use carrick_el1::isa::x86::initial_mm::{
                    InitialImageRegion, InitialImageSpec, InitialSourceRange, InitialStackSpec,
                    install_initial_image,
                };
                use carrick_guest_arch::EditPermissions;
                if frame.rdi != 0x10100 || !(0xc0..=0xf00).contains(&frame.rsi) {
                    fatal_error(frame);
                }
                // SAFETY: this exact RX user fixture page remains mapped under
                // the still-live source root until the new MM has copied its bytes.
                let elf = unsafe {
                    core::slice::from_raw_parts(frame.rdi as *const u8, frame.rsi as usize)
                };
                if &elf[..4] != b"\x7fELF" {
                    fatal_error(frame);
                }
                let region = InitialImageRegion {
                    start: carrick_guest_arch::UserVa::new(0x400000),
                    len: carrick_guest_arch::GuestLen::new(4096),
                    initialized_offset: carrick_guest_arch::GuestLen::new(0),
                    initialized: InitialSourceRange {
                        start: carrick_guest_arch::FrameGpa::new(0x10100),
                        len: carrick_guest_arch::GuestLen::new(elf.len() as u64),
                    },
                    perms: EditPermissions {
                        readable: true,
                        writable: false,
                        executable: true,
                        user: true,
                    },
                };
                let image = InitialImageSpec {
                    regions: core::slice::from_ref(&region),
                    executable_region_count: 1,
                    entry: carrick_guest_arch::UserVa::new(0x4000b0),
                    stack: InitialStackSpec {
                        entry: 0x4000b0,
                        interpreter_base: 0,
                        phdr: 0x400040,
                        phent: 56,
                        phnum: 1,
                        argv: &[b"/tiny"],
                        envp: &[],
                        random: [0x5a; 16],
                        stack_top: 0x7fff_0000,
                        stack_size: 0x4000,
                    },
                };
                let Ok(source_root) = carrick_el1::isa::x86::hardware_live_root() else {
                    fatal_error(frame);
                };
                if source_root.address().raw() != 0x60_0000 {
                    fatal_error(frame);
                }
                let mut frames = if frame.rdx == 1 {
                    InitialFrames {
                        next_table: 0x30_0000,
                        next_data: 0x40_0000,
                    }
                } else {
                    InitialFrames {
                        next_table: 0xd3_0000,
                        next_data: 0xd0_0000,
                    }
                };
                // SAFETY: this stopped-carrier fixture owns the unpublished MM,
                // both disjoint zeroed frame ranges and the sole table editor.
                let loaded = unsafe {
                    install_initial_image(
                        &fixture_initial_words(),
                        &mut frames,
                        source_root,
                        core::num::NonZeroU64::MIN,
                        core::num::NonZeroU64::MIN,
                        &image,
                    )
                };
                let Ok(loaded) = loaded else {
                    fatal_error(frame);
                };
                // One text page plus all four configured bootstrap stack pages.
                if loaded.publications.len() != 5
                    || !loaded.context.authenticates(loaded.address)
                    || loaded.context.frame[15] != 0x4000b0
                    || loaded.context.frame[18] != loaded.stack_pointer
                {
                    fatal_error(frame);
                }
                use carrick_guest_arch::MmuBackend;
                let mut mmu = carrick_el1::isa::x86::X86Backend;
                if mmu.install_context(loaded.address).is_err() {
                    fatal_error(frame);
                }
                if frame.rdx == 1
                    && !crate::process::admit_initial(
                        binding,
                        loaded.stack_pointer,
                        loaded.address.root.address().raw(),
                    )
                {
                    fatal_error(frame);
                }
                frame.rcx = loaded.context.frame[15];
                frame.rsp = loaded.context.frame[18];
                frame.r11 = loaded.context.frame[17];
                frame.rax = 0;
                ControlFlow::Return(())
            }
            FixtureCall::ObserveMmuRoot => {
                use carrick_guest_arch::MmuBackend;
                let mut arch = carrick_el1::isa::x86::X86Backend;
                frame.rax = arch.live_root().map_or(0, |root| root.address().raw());
                ControlFlow::Return(())
            }
            FixtureCall::ObservePortalWindow => {
                let root = carrick_el1::isa::x86::hardware_live_root()
                    .map_or(0, |root| root.address().raw());
                frame.rax = u64::from(
                    carrick_el1::isa::x86::portal_root_is_live(root)
                        && !carrick_el1::isa::x86::portal_root_is_live(root + 4096),
                );
                ControlFlow::Return(())
            }
            FixtureCall::ObserveForkTableWindow => {
                use carrick_el1::isa::x86::ForkDescriptorWords;
                use carrick_el1_abi::PortalForkTableArena;
                use carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords;
                let root = carrick_el1::isa::x86::hardware_live_root()
                    .map_or(0, |root| root.address().raw());
                let (Some(child), Some(parent)) = (
                    PortalForkTableArena::new(0xd2_0000, 4096),
                    PortalForkTableArena::new(0xd2_1000, 4096),
                ) else {
                    frame.rax = 0;
                    return ControlFlow::Return(());
                };
                frame.rax = u64::from(
                    unsafe { ForkDescriptorWords::checked(root, child, parent) }.is_ok_and(
                        |words| {
                            words.load(child.base).is_ok()
                                && words.load(parent.base).is_ok()
                                && words.load(0xd2_2000).is_err()
                                && words.drain_succeeded()
                        },
                    ),
                );
                ControlFlow::Return(())
            }
            FixtureCall::ObserveRetireRepoint => {
                use carrick_guest_arch::{
                    EditBacking, EditCowAccess, EditOperation, EditPermissions, FrameGpa, GuestLen,
                    UserRange, UserVa,
                };
                use carrick_mmu_core::x86::descriptor_txn::{DescriptorOutcome, DescriptorReceipt};
                let one = core::num::NonZeroU64::MIN;
                let backing = EditBacking {
                    frame_id: one,
                    mapping_id: one,
                    owner_generation: one,
                    inventory_revision: one,
                };
                let applied = |receipt: Result<DescriptorReceipt, carrick_el1::isa::ArchError>| {
                    receipt.is_ok_and(|value| {
                        matches!(value.outcome, DescriptorOutcome::Applied { .. })
                    })
                };
                let Some(resident) = UserRange::checked(UserVa::new(0x3_7000), GuestLen::new(4096))
                else {
                    frame.rax = 0;
                    return ControlFlow::Return(());
                };
                if !matches!(frame.rdi, 0 | 2 | 3) {
                    frame.rax = 0;
                    return ControlFlow::Return(());
                }
                if frame.rdi == 3 {
                    let retired = applied(fixture_edit(0x3_7000, one, EditOperation::Unmap));
                    frame.rax = u64::from(retired);
                    return ControlFlow::Return(());
                }
                let mapped = fixture_edit(
                    0x3_7000,
                    one,
                    EditOperation::Prepare {
                        output: FrameGpa::new(0xd1_1000),
                        permissions: EditPermissions {
                            readable: true,
                            writable: true,
                            executable: false,
                            user: true,
                        },
                        resident,
                        backing,
                    },
                );
                if frame.rdi == 2 {
                    frame.rax = u64::from(applied(mapped));
                    return ControlFlow::Return(());
                }
                let retired =
                    applied(mapped) && applied(fixture_edit(0x3_7000, one, EditOperation::Unmap));
                let repointed = retired
                    && applied(fixture_edit(
                        0x3_7000,
                        one,
                        EditOperation::CowRepoint {
                            old: FrameGpa::new(0xd1_1000),
                            new: FrameGpa::new(0xd1_5000),
                            backing,
                            access: EditCowAccess::RecordedPrivate,
                        },
                    ));
                frame.rax = u64::from(repointed);
                ControlFlow::Return(())
            }
            FixtureCall::ObserveMmuDrain => {
                use carrick_guest_arch::{
                    AddressContext, ContextGeneration, FrameGpa, GuestLen, MmGeneration,
                    MmuBackend, RootGpa, UserRange, UserVa,
                };
                let mut arch = carrick_el1::isa::x86::X86Backend;
                frame.rax = arch
                    .live_root()
                    .and_then(|_| {
                        let root = RootGpa::page_aligned(FrameGpa::new(frame.rsi))
                            .ok_or(carrick_el1::isa::ArchError::Unbound)?;
                        let context = AddressContext {
                            root,
                            mm: MmGeneration::new(core::num::NonZeroU64::MIN),
                            generation: ContextGeneration::new(core::num::NonZeroU64::MIN),
                        };
                        let range = UserRange::checked(UserVa::new(frame.rdi), GuestLen::new(4096))
                            .ok_or(carrick_el1::isa::ArchError::Unbound)?;
                        arch.request_invalidation(context, range)
                            .and_then(|ticket| arch.ack_drain(ticket))
                    })
                    .map_or(u64::MAX, |receipt| receipt.root().address().raw());
                ControlFlow::Return(())
            }
            FixtureCall::ObserveDescriptorProtect => {
                use carrick_guest_arch::{
                    EditBacking, EditOperation, EditPermissions, FrameGpa, GuestLen, UserRange,
                    UserVa,
                };
                use carrick_mmu_core::x86::descriptor_txn::DescriptorOutcome;
                let one = core::num::NonZeroU64::MIN;
                let Some(resident) = UserRange::checked(UserVa::new(0x3_6000), GuestLen::new(4096))
                else {
                    frame.rax = 0;
                    return ControlFlow::Return(());
                };
                let prepared = fixture_edit(
                    0x3_6000,
                    one,
                    EditOperation::Prepare {
                        output: FrameGpa::new(0xd1_6000),
                        permissions: EditPermissions {
                            readable: true,
                            writable: true,
                            executable: false,
                            user: true,
                        },
                        resident,
                        backing: EditBacking {
                            frame_id: one,
                            mapping_id: one,
                            owner_generation: one,
                            inventory_revision: one,
                        },
                    },
                );
                if !matches!(prepared, Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }))
                {
                    frame.rax = 0;
                    return ControlFlow::Return(());
                }
                let receipt = fixture_edit(
                    0x3_6000,
                    one,
                    EditOperation::Protect {
                        permissions: EditPermissions {
                            readable: true,
                            writable: false,
                            executable: false,
                            user: true,
                        },
                    },
                );
                frame.rax = match receipt {
                    Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }) => {
                        1
                    }
                    Ok(_) => 0,
                    Err(_) => {
                        fatal_error(frame);
                    }
                };
                ControlFlow::Return(())
            }
            FixtureCall::ObserveDescriptorPreparePublish => {
                use carrick_core::mm::transfer::resolver::PreparedPageResolver;
                use carrick_guest_arch::{
                    EditBacking, EditLeafSize, EditOperation, EditPermissions, FrameGpa,
                };
                use carrick_mmu_core::aarch64::{GuestPreparedCommit, LeafAccess};
                use carrick_mmu_core::x86::descriptor_txn::DescriptorOutcome;
                let one = core::num::NonZeroU64::MIN;
                let backing = EditBacking {
                    frame_id: one,
                    mapping_id: one,
                    owner_generation: one,
                    inventory_revision: one,
                };
                let prepared = fixture_edit(
                    0x3_2000,
                    one,
                    EditOperation::Map {
                        output: FrameGpa::new(0x9_0000),
                        permissions: EditPermissions {
                            readable: true,
                            writable: false,
                            executable: false,
                            user: true,
                        },
                        size: EditLeafSize::Page,
                        resident: false,
                        backing,
                    },
                );
                match prepared {
                    Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }) => {
                    }
                    Ok(_) => {
                        frame.rax = 0;
                        return ControlFlow::Return(());
                    }
                    Err(_) => {
                        fatal_error(frame);
                    }
                }
                let words = fixture_initial_words();
                let mut resolver =
                    unsafe { carrick_el1::fault::X86PreparedResolver::under_editor(one, &words) };
                let published =
                    resolver.commit_prepared(0x60_0000, 0x3_2000, 0x9_0000, LeafAccess::Read);
                match published {
                    Ok(GuestPreparedCommit::Committed) => {}
                    Err(carrick_mmu_core::aarch64::GuestPreparedCommitError::RollbackFailed) => {
                        fatal_error(frame);
                    }
                    _ => {
                        frame.rax = 0;
                        return ControlFlow::Return(());
                    }
                }
                let retry =
                    resolver.commit_prepared(0x60_0000, 0x3_2000, 0x9_0000, LeafAccess::Read);
                frame.rax = match retry {
                    Ok(GuestPreparedCommit::AlreadyResident) => 1,
                    Err(carrick_mmu_core::aarch64::GuestPreparedCommitError::RollbackFailed) => {
                        fatal_error(frame);
                    }
                    _ => 0,
                };
                ControlFlow::Return(())
            }
            FixtureCall::ObserveSharedPreparedFault => {
                use carrick_core::mm::transfer::resolver::NoopCowResolver;
                use carrick_el1::fault::{
                    GrantMailboxes, PreparedFaultPath, X86PreparedResolver,
                    dispatch_x86_fault_with_prepared,
                };
                use carrick_el1_abi::{Action, FrameGrantResidencyIdentity};
                use carrick_guest_arch::{
                    Access, EditBacking, EditLeafSize, EditOperation, EditPermissions, FaultInfo,
                    FrameGpa, UserVa,
                };
                use carrick_mmu_core::x86::descriptor_txn::DescriptorOutcome;

                let one = core::num::NonZeroU64::MIN;
                let prepared = fixture_edit(
                    0x3_3000,
                    one,
                    EditOperation::Map {
                        output: FrameGpa::new(0x9_1000),
                        permissions: EditPermissions {
                            readable: true,
                            writable: false,
                            executable: false,
                            user: true,
                        },
                        size: EditLeafSize::Page,
                        resident: false,
                        backing: EditBacking {
                            frame_id: one,
                            mapping_id: one,
                            owner_generation: one,
                            inventory_revision: one,
                        },
                    },
                );
                if !matches!(
                    prepared,
                    Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. })
                ) {
                    fatal_error(frame);
                }
                // SAFETY: the boot owner published this supervisor-only zone and
                // retains it across the exact CPU's space-edit transaction.
                // SAFETY: the boot owner published this supervisor-only zone and
                // retains it across the exact CPU's space-edit transaction.
                let zone = unsafe {
                    &*(lifecycle::LIFECYCLE_ZONE as *const carrick_sched_core::ZoneTables)
                };
                let mm = task.mm.key.load(Ordering::Acquire);
                let Some(mm_key) = core::num::NonZeroU64::new(mm) else {
                    fatal_error(frame);
                };
                let layout =
                    core::alloc::Layout::new::<carrick_el1_abi::FrameGrantResidencyTable>();
                // SAFETY: the global allocator returns an aligned block of this layout;
                // this fixture owns it exclusively until deallocated below.
                let ptr = unsafe { rust_alloc::alloc::alloc(layout) };
                if ptr.is_null() {
                    fatal_error(frame);
                }
                // SAFETY: ptr is non-null, aligned and valid for FrameGrantResidencyTable.
                let residency = unsafe {
                    let table_ptr = ptr.cast::<carrick_el1_abi::FrameGrantResidencyTable>();
                    carrick_el1_abi::FrameGrantResidencyTable::init_in_place(table_ptr);
                    &*table_ptr
                };
                if residency
                    .publish(FrameGrantResidencyIdentity {
                        mm_key: mm,
                        semantic_base: 0x3_3000,
                        physical_ipa: 0x9_1000,
                        len: 4096,
                        mapping_id: 1,
                        frame_id: 1,
                        owner_generation: 1,
                        inventory_revision: 1,
                    })
                    .is_none()
                {
                    fatal_error(frame);
                }
                let words = fixture_initial_words();
                // SAFETY: the shared dispatcher acquires this MM's exact editor
                // before invoking the resolver, and the upper direct table window lives
                // for the whole KVM fixture.
                let mut resolver = unsafe { X86PreparedResolver::under_editor(mm_key, &words) };
                let action = dispatch_x86_fault_with_prepared(
                    carrick_guest_arch::CpuId::new(0),
                    FaultInfo {
                        address: UserVa::new(0x3_3000),
                        access: Access::Read,
                        present: false,
                    },
                    counters,
                    task,
                    carrick_el1::substrate::sched::object_wait::space_access(
                        zone,
                        carrick_sched_core::SlotId::new(0),
                    ),
                    GrantMailboxes::own(&SHARED_FAULT_MAILBOX),
                    Some(PreparedFaultPath::<_> {
                        residency,
                        resolver: &mut resolver,
                        roots: None,
                        file_slots: None,
                    }),
                    &mut NoopCowResolver,
                );
                frame.rax = u64::from(
                    action == Action::Served && residency.is_guest_committed(mm, 0x3_3000),
                );
                // SAFETY: ptr was returned for layout and has not escaped.
                unsafe { rust_alloc::alloc::dealloc(ptr, layout) };
                ControlFlow::Return(())
            }
            FixtureCall::ObserveSharedCowFault => {
                use carrick_core::mm::transfer::resolver::NoopPreparedResolver;
                use carrick_el1::fault::{
                    GrantMailboxes, X86CowResolver, dispatch_x86_fault_with_prepared,
                };
                use carrick_el1_abi::{Action, FrameGrantResidencyIdentity};
                use carrick_guest_arch::{
                    Access, EditBacking, EditOperation, EditPermissions, FaultInfo, FrameGpa,
                    GuestLen, UserVa,
                };
                use carrick_mmu_core::x86::descriptor_txn::{BackingIdentity, DescriptorOutcome};

                let one = core::num::NonZeroU64::MIN;
                let backing = BackingIdentity {
                    frame_id: one,
                    mapping_id: one,
                    owner_generation: one,
                    inventory_revision: one,
                };
                let map = fixture_edit(
                    0x3_4000,
                    one,
                    EditOperation::Map {
                        output: FrameGpa::new(0xd1_1000),
                        permissions: EditPermissions {
                            readable: true,
                            writable: true,
                            executable: false,
                            user: true,
                        },
                        size: carrick_guest_arch::EditLeafSize::Page,
                        resident: true,
                        backing: EditBacking {
                            frame_id: one,
                            mapping_id: one,
                            owner_generation: one,
                            inventory_revision: one,
                        },
                    },
                );
                let arm = fixture_edit(
                    0x3_4000,
                    core::num::NonZeroU64::new(2).unwrap_or(one),
                    EditOperation::ArmCow {
                        kernel_only: false,
                        executable: false,
                        adopt_private: false,
                        asid_scoped: false,
                        excluded_ipa: FrameGpa::new(0),
                        excluded_len: GuestLen::new(0),
                    },
                );
                if !matches!(map, Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }))
                    || !matches!(arm, Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }))
                {
                    fatal_error(frame);
                }
                // SAFETY: the bootstrap direct window maps both retained frame
                // pages and this fixture excludes the sibling vCPU.
                unsafe {
                    ((DIRECT_VA + 0xd1_1000) as *mut u8).write_volatile(0x5a);
                    ((DIRECT_VA + 0xd1_5000) as *mut u8).write_volatile(0);
                }
                // SAFETY: the boot owner published this supervisor-only zone and
                // retains it across the exact CPU's space-edit transaction.
                // SAFETY: the boot owner published this supervisor-only zone and
                // retains it across the exact CPU's space-edit transaction.
                let zone = unsafe {
                    &*(lifecycle::LIFECYCLE_ZONE as *const carrick_sched_core::ZoneTables)
                };
                let mm = task.mm.key.load(Ordering::Acquire);
                let layout =
                    core::alloc::Layout::new::<carrick_el1_abi::FrameGrantResidencyTable>();
                // SAFETY: the global allocator returns an aligned block of this layout;
                // this fixture owns it exclusively until deallocated below.
                let ptr = unsafe { rust_alloc::alloc::alloc(layout) };
                if ptr.is_null() {
                    fatal_error(frame);
                }
                // SAFETY: ptr is aligned, writable storage for the whole table.
                let residency = unsafe {
                    let table = ptr.cast::<carrick_el1_abi::FrameGrantResidencyTable>();
                    carrick_el1_abi::FrameGrantResidencyTable::init_in_place(table);
                    &*table
                };
                let Some(old_slot) = residency.publish(FrameGrantResidencyIdentity {
                    mm_key: mm,
                    semantic_base: 0x3_4000,
                    physical_ipa: 0xd1_1000,
                    len: 4096,
                    mapping_id: 1,
                    frame_id: 1,
                    owner_generation: 1,
                    inventory_revision: 1,
                }) else {
                    fatal_error(frame);
                };
                let _ = old_slot;
                let Some(old_page) = residency.lookup(mm, 0x3_4000) else {
                    fatal_error(frame);
                };
                if !residency.record_commit(old_page)
                    || SHARED_COW_POOL.publish(mm, 0xd1_4000, backing).is_none()
                {
                    fatal_error(frame);
                }
                let words = fixture_initial_words();
                let mut cow = X86CowResolver {
                    words: &words,
                    pool: &SHARED_COW_POOL,
                    residency,
                    completion: None,
                };
                let action = dispatch_x86_fault_with_prepared(
                    carrick_guest_arch::CpuId::new(0),
                    FaultInfo {
                        address: UserVa::new(0x3_4000),
                        access: Access::Write,
                        present: true,
                    },
                    counters,
                    task,
                    carrick_el1::substrate::sched::object_wait::space_access(
                        zone,
                        carrick_sched_core::SlotId::new(0),
                    ),
                    GrantMailboxes::own(&SHARED_FAULT_MAILBOX),
                    None::<carrick_el1::fault::PreparedFaultPath<'_, NoopPreparedResolver>>,
                    &mut cow,
                );
                // SAFETY: both pages remain mapped in the supervisor direct window.
                let copied = unsafe {
                    ((DIRECT_VA + 0xd1_1000) as *const u8).read_volatile() == 0x5a
                        && ((DIRECT_VA + 0xd1_5000) as *const u8).read_volatile() == 0x5a
                };
                frame.rax = u64::from(
                    action == Action::Served
                        && copied
                        && residency.is_guest_committed(mm, 0x3_4000)
                        && cow.completion.is_some(),
                );
                // SAFETY: the fixture's table is no longer borrowed and ptr came
                // from this exact allocation layout.
                unsafe { rust_alloc::alloc::dealloc(ptr, layout) };
                ControlFlow::Return(())
            }
            FixtureCall::ObserveAllocator => {
                let layout = match core::alloc::Layout::from_size_align(128, 64) {
                    Ok(layout) => layout,
                    Err(_) => {
                        frame.rax = 0;
                        return ControlFlow::Return(());
                    }
                };
                // SAFETY: the global allocator returns a block of this layout;
                // this fixture owns it exclusively until the matching dealloc.
                let ptr = core::hint::black_box(unsafe { rust_alloc::alloc::alloc(layout) });
                if ptr.is_null() {
                    frame.rax = 0;
                    return ControlFlow::Return(());
                }
                // SAFETY: byte 127 is inside this exclusively owned allocation.
                unsafe { core::ptr::write_volatile(ptr.add(127), 0xa5) };
                let valid = (ptr as usize & 63) == 0
                    && (ptr as u64)
                        .checked_sub(carrick_el1_abi::X86_CPL0_BOOTSTRAP_METADATA_BASE)
                        .is_some_and(|offset| {
                            offset < carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE
                        })
                    // SAFETY: the same byte remains allocated until dealloc below.
                    && unsafe { core::ptr::read_volatile(ptr.add(127)) } == 0xa5;
                // SAFETY: ptr was returned for layout and has not escaped.
                unsafe { rust_alloc::alloc::dealloc(ptr, layout) };
                frame.rax = u64::from(valid);
                ControlFlow::Return(())
            }
            FixtureCall::ObserveUserAccessWitness => {
                frame.rax = carrick_el1::isa::x86::user_access::witness(task, frame.rdi, frame.rsi);
                ControlFlow::Return(())
            }
            FixtureCall::ObserveCpl0UaccessShootdown => {
                let address = frame.rdi;
                let word1 = carrick_el1::isa::x86::user_access::witness(task, address, 6);
                if word1 as i64 == -14 {
                    frame.rax = 0xdead;
                    return ControlFlow::Return(());
                }
                frame.rbx = word1;
                forward_to_host(frame);
                let word2 = carrick_el1::isa::x86::user_access::witness(task, address, 6);
                frame.rax = word2;
                forward_to_host(frame);
                ControlFlow::Return(())
            }
            FixtureCall::ObserveTransportWitness => {
                frame.rax = carrick_el1::isa::x86::transport::witness(frame.rdi);
                ControlFlow::Return(())
            }
            FixtureCall::ObserveContextWitness => {
                frame.rax = carrick_el1::isa::x86::context::witness(frame.rdi);
                ControlFlow::Return(())
            }
            FixtureCall::ObserveInterruptWitness => {
                frame.rax = carrick_el1::isa::x86::interrupt::witness(frame.rdi, frame.rsi);
                ControlFlow::Return(())
            }
            FixtureCall::ObserveExitGroup => {
                control_doorbell(frame);
                halt();
            }
            FixtureCall::Syscall(call) => {
                if binding.scheduler_witness.load(Ordering::Acquire)
                    == carrick_el1::isa::x86::context::scheduler::PROGRESS_STATE
                {
                    progress::entry_boundary();
                }

                let handled_by_fixture =
                    fixture_handled(frame, cx.xsave, binding, task, counters, &call);
                if !handled_by_fixture {
                    let files = linux_personality::file_tables(binding);
                    linux_personality::admit_stdio_cached(binding, task, &files);
                    let file_table = task.linux.file_table.load(Ordering::Acquire).max(1);
                    let cache_lookup = |handle: u32| {
                        files
                            .cache(handle)
                            .map_or(core::ptr::null_mut(), |ptr| ptr.as_ptr())
                    };

                    let mut native = NativeDispatch {
                        frame,
                        fpstate: cx.xsave,
                        call,
                        publications: &binding.publications,
                        slot: carrick_guest_arch::SlotId::from_index(binding.cpu_slot as usize),
                        file_table,
                        files: &files,
                    };
                    let route =
                        match production_boundary(carrick_el1::dispatch_syscall_with_lifecycle(
                            &mut native,
                            counters,
                            core::slice::from_ref(task),
                            files.fd_map(),
                            files.objects(),
                            files.opens(),
                            &[],
                            files.names(),
                            None::<
                                carrick_el1::Zone<'_, sched::HardwareCpu, sched::HardwareUserWord>,
                            >,
                            None,
                            Some(&GuestLifecycleVenue),
                            None,
                            cache_lookup,
                        )) {
                            ProductionBoundary::Continue => CompletionRoute::Served,
                            ProductionBoundary::Work => CompletionRoute::WithWork,
                            ProductionBoundary::Forward => CompletionRoute::Forward,
                            ProductionBoundary::HostCustody => CompletionRoute::HostCustody,
                            ProductionBoundary::Invalid => CompletionRoute::InvalidCompletion,
                        };
                    match route {
                        CompletionRoute::Served => {}
                        CompletionRoute::WithWork => notify_work(frame),
                        CompletionRoute::Suspended => {
                            return ControlFlow::Suspend(OwnedContinuation::new(0));
                        }
                        CompletionRoute::InvalidCompletion => {
                            fatal_error(frame);
                        }
                        CompletionRoute::Forward | CompletionRoute::HostCustody => {
                            forward_to_host(frame);
                        }
                    }
                }
                ControlFlow::Return(())
            }
        }
    }

    fn on_user_return(&mut self, _frame: &mut NativeFrame, _xsave: &mut XsaveArea) {}

    fn has_pending_host_work(&mut self, task: &CurrentTask) -> bool {
        if task.linux.has_pending_host_work() {
            task.linux.record_completed_with_work();
            true
        } else {
            false
        }
    }

    fn handle_unrecognized_call(
        &mut self,
        frame: &mut NativeFrame,
        _task: &CurrentTask,
        _binding: &CpuBinding,
        counters: &Counters,
    ) {
        evaluate_host_crossing(
            HostCrossingSet::X86,
            true,
            None,
            None,
            Some(&counters.refused),
            |ret| frame.rax = ret.raw() as u64,
        );
    }

    fn schedule(slot: carrick_sched_core::SlotId) -> ! {
        native_execution::schedule(slot);
    }

    fn on_timer(&mut self, slot: carrick_sched_core::SlotId) {
        native_execution::expire_signal_timer(slot);
    }

    fn on_counted_completion(&mut self, binding: &CpuBinding) {
        if binding.scheduler_witness.load(Ordering::Acquire)
            == carrick_el1::isa::x86::context::scheduler::PROGRESS_STATE
        {
            progress::return_boundary();
        }
    }

    fn fixture_hold_check(
        &self,
        table: &carrick_el1::isa::x86::context::native::ShootdownTable,
        target_mode: u32,
    ) -> Result<(), carrick_el1::isa::ArchError> {
        if table.fixture_hold_ipi.load(Ordering::Acquire) == target_mode {
            // SAFETY: this fixture owns the identity-mapped control data page.
            // Release its running reader only after the edit reached this hold.
            unsafe {
                core::ptr::write_volatile(0x4_0008 as *mut u8, 1);
            }
            let Some(tsc_hz) = carrick_el1::isa::x86::interrupt::tsc_frequency() else {
                return Err(carrick_el1::isa::ArchError::Unbound);
            };
            let Some(limit) = tsc_hz.get().checked_mul(5) else {
                return Err(carrick_el1::isa::ArchError::Unbound);
            };
            let start = carrick_el1::isa::x86::interrupt::read_tsc();
            while table.fixture_hold_ipi.load(Ordering::Acquire) == target_mode {
                if carrick_el1::isa::x86::interrupt::read_tsc().wrapping_sub(start) > limit {
                    return Err(carrick_el1::isa::ArchError::Busy);
                }
                core::hint::spin_loop();
            }
        }
        Ok(())
    }

    fn handle_page_fault(frame: &mut PageFaultStack, fpstate: &XsaveArea) -> u64 {
        use carrick_core::mm::transfer::resolver::NoopPreparedResolver;
        use carrick_el1::fault::{
            GrantMailboxes, X86CowResolver, dispatch_x86_fault_with_prepared,
        };
        use carrick_el1_abi::Action;

        let prep = match prepare_user_page_fault(frame) {
            Ok(p) => p,
            Err(code) => return code,
        };
        let lane = prep.binding.scheduler_witness.load(Ordering::Acquire);
        if lane == lifecycle::LIFECYCLE_LANE
            || lane == lifecycle::LIFECYCLE_LANE + lifecycle::LIFECYCLE_STRIDE
        {
            let address = FORK_RESIDENCY_ADDRESS.load(Ordering::Acquire);
            if address == 0 {
                return 4;
            }
            // SAFETY: the fixture published and retains this aligned table.
            let residency =
                unsafe { &*(address as *const carrick_el1_abi::FrameGrantResidencyTable) };
            // SAFETY: the boot owner published this supervisor-only zone and
            // retains it across the exact CPU's space-edit transaction.
            let zone =
                unsafe { &*(lifecycle::LIFECYCLE_ZONE as *const carrick_sched_core::ZoneTables) };
            let words = fixture_initial_words();
            let mut cow = X86CowResolver {
                words: &words,
                pool: &SHARED_COW_POOL,
                residency,
                completion: None,
            };
            let result = dispatch_x86_fault_with_prepared(
                carrick_guest_arch::CpuId::new(0),
                prep.fault,
                prep.counters,
                prep.task,
                carrick_el1::substrate::sched::object_wait::space_access(zone, prep.slot),
                GrantMailboxes::own(&SHARED_FAULT_MAILBOX),
                None::<carrick_el1::fault::PreparedFaultPath<'_, NoopPreparedResolver>>,
                &mut cow,
            );
            return if result == Action::Served {
                0
            } else {
                carrick_el1_abi::X86FaultDisposition::PolicyDeclined.raw()
            };
        }
        linux_personality::handle_user_page_fault_prepared(&prep, frame, fpstate)
    }

    fn on_boot() {
        // SAFETY: hardware witness in linked fixture image.
        unsafe extern "C" {
            fn carrick_x86_fixture_dispatch_witness() -> bool;
        }
        // SAFETY: calling extern witness function to retain in linked fixture image.
        let _ = unsafe { carrick_x86_fixture_dispatch_witness() };
    }
}
