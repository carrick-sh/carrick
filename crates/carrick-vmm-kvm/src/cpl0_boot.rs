//! Bounded M2 hardware binding: one VM, two issued live task slots, native
//! SYSCALL entry and IRETQ return, including linked MM-owner serving.
//! This fixture does not establish OCI/runtime executor-pool acceptance.
//! Observation and kick doorbells are declared fixture control transport.
use crate::guest_setup::{GuestRam, WindowKind};
use crate::{KvmKickHandle, KvmVcpu, KvmVm};
use carrick_el1_abi::{
    BlockedMask, Counters, CurrentTask, EL1_DYNAMIC_METADATA_BASE, El1TaskId, ThreadControlSlot,
    ThreadLifecyclePage,
};
use carrick_hal::{HvVcpu, HvVm, MemPerms, TrapError, VcpuExit, VcpuKick};
use carrick_mem::pml4::{Pml4MapSpec, pml4_tables};
use carrick_sched_core::{SlotId, ZoneTables};
use carrick_x86::cpl0_entry::*;
use carrick_x86::cpl0_scheduler::ContextBinding;
use carrick_x86::{BringupLayout, X86Reg, X86Vcpu};
use kvm_bindings::{Msrs, kvm_msr_entry};
use std::path::Path;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const RAM_SIZE: usize = 16 * 1024 * 1024;
const META_GPA: u64 = 0xc0_0000;
const META_LEN: u64 = 0x2_0000;
const COUNTERS_OFFSET: u64 = 0x1_0000;
const BINDING_OFFSET: u64 = CPU_BINDING_OFFSET;
const TASK_OFFSET: u64 = 0x9000;
const CONTROL_OFFSET: u64 = 0xa000;
const STRIDE: u64 = CPU_BINDING_STRIDE;
const IST_STACK_BASE: u64 = 0xf0_0000;
pub const USER_CODE: u64 = 0x1_0000;
const LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: 0x10_0000,
    gdt_base: 0x50_0000,
    pml4_base: 0x60_0000,
};

fn fail(message: impl Into<String>) -> TrapError {
    TrapError::Hypervisor(message.into())
}

pub enum BootMode<'a> {
    Normal,
    Interrupts,
    Shared {
        slot: SlotId,
        setup: &'a mut dyn FnMut(&ZoneTables) -> ContextBinding,
    },
}

/// RAII deadline: one bounded blocking wait, one kick on expiry, always joined.
pub(crate) struct Watchdog {
    cancel: mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
    pub(crate) expired: Arc<AtomicBool>,
}
impl Watchdog {
    pub(crate) fn start() -> Self {
        let kick = KvmKickHandle::for_current_thread();
        let (cancel, receiver) = mpsc::channel();
        let expired = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&expired);
        let worker = std::thread::spawn(move || {
            if receiver.recv_timeout(Duration::from_secs(5)) == Err(mpsc::RecvTimeoutError::Timeout)
            {
                signal.store(true, Ordering::Release);
                kick.kick();
            }
        });
        Self {
            cancel,
            worker: Some(worker),
            expired,
        }
    }
    pub(crate) fn expired(&self) -> bool {
        self.expired.load(Ordering::Acquire)
    }
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        let _ = self.cancel.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Debug)]
pub struct Observation {
    pub result: i64,
    pub heads: [(u64, u32); 2],
    pub served: u64,
    pub forwarded: u64,
    pub semantic_host_exits: u64,
    pub entries: [u64; 2],
    pub publications: [u64; 2],
    pub completions: [u64; 2],
    pub admissions: [u64; 2],
    pub kicks: u64,
    pub work_exits: u64,
    pub captured_stack: u64,
    pub returned_stack: u64,
    pub preserved_rbx: u64,
}

/// The vCPUs drop before the VM, and its registered backing drops last.
/// No run handle or host pointer escapes this fixture owner.
pub struct Cpl0Carrier {
    pub(crate) cpus: [KvmVcpu; 2],
    pub(crate) _vm: KvmVm,
    pub(crate) ram: GuestRam,
    metadata_base: NonNull<u8>,
    host_forwards: AtomicU64,
    kicks: AtomicU64,
    work_exits: AtomicU64,
    handbacks: std::sync::Mutex<Vec<carrick_sched_core::RecordRef>>,
}

impl Cpl0Carrier {
    pub fn boot(image: &Path, programs: [&[u8]; 2]) -> Result<Self, TrapError> {
        Self::boot_inner(image, programs, BootMode::Normal)
    }

    pub fn boot_shared(
        image: &Path,
        program: &[u8],
        slot: SlotId,
        mut setup: impl FnMut(&ZoneTables) -> ContextBinding,
    ) -> Result<Self, TrapError> {
        Self::boot_inner(
            image,
            [program, &[0x0f, 0x0b]],
            BootMode::Shared {
                slot,
                setup: &mut setup,
            },
        )
    }

    pub(crate) fn boot_inner(
        image: &Path,
        programs: [&[u8]; 2],
        mut mode: BootMode<'_>,
    ) -> Result<Self, TrapError> {
        let bytes = std::fs::read(image).map_err(|e| fail(format!("CPL0 image: {e}")))?;
        let plan = carrick_mem::elf::plan_elf_load_bytes_for(&bytes, 62)
            .map_err(|e| fail(format!("CPL0 ELF: {e}")))?;
        if !(0x10_0000..0x20_0000).contains(&plan.entry) {
            return Err(fail("CPL0 entry outside its supervisor image"));
        }
        let mut ram = GuestRam::new();
        let ram_size = match mode {
            BootMode::Interrupts | BootMode::Shared { .. } => 2 * RAM_SIZE,
            BootMode::Normal => RAM_SIZE,
        };
        ram.add_window(0, ram_size, WindowKind::Private)
            .map_err(|e| fail(e.to_string()))?;
        let mut maps = Vec::new();
        for segment in &plan.segments {
            let end = segment
                .virtual_address
                .checked_add(segment.memory_size)
                .ok_or_else(|| fail("CPL0 segment overflow"))?;
            if segment.virtual_address < 0x10_0000 || end > 0x20_0000 {
                return Err(fail("CPL0 segment outside its supervisor image"));
            }
            let start = segment.file_offset as usize;
            let data = bytes
                .get(start..start + segment.file_size as usize)
                .ok_or_else(|| fail("CPL0 segment file bounds"))?;
            ram.write_gpa(segment.virtual_address, data)
                .map_err(|e| fail(e.to_string()))?;
            let va = segment.virtual_address & !0xfff;
            maps.push(Pml4MapSpec {
                va,
                gpa: va,
                len: ((end + 0xfff) & !0xfff) - va,
                user: false,
                write: segment.perms.write,
                exec: segment.perms.execute,
            });
        }
        // Existing x86 descriptor/TSS/IDT machinery, including private stacks
        // and exception stubs, remains the hardware authority.
        maps.push(Pml4MapSpec {
            va: 0x20_0000,
            gpa: 0x20_0000,
            len: 0xa0_0000,
            user: false,
            write: true,
            exec: true,
        });
        maps.push(Pml4MapSpec {
            va: 0xe0_0000,
            gpa: 0xe0_0000,
            len: 0x20_0000,
            user: false,
            write: true,
            exec: false,
        });
        maps.push(Pml4MapSpec {
            va: EL1_DYNAMIC_METADATA_BASE,
            gpa: META_GPA,
            len: META_LEN,
            user: false,
            write: true,
            exec: false,
        });
        for (index, program) in programs.iter().enumerate() {
            if program.len() > 4096 {
                return Err(fail("CPL0 fixture exceeds one code page"));
            }
            let code = USER_CODE + index as u64 * 4096;
            ram.write_gpa(code, program)
                .map_err(|e| fail(e.to_string()))?;
            maps.push(Pml4MapSpec {
                va: code,
                gpa: code,
                len: 4096,
                user: true,
                write: false,
                exec: true,
            });
            let stack = 0x3_0000 + index as u64 * 0x1_0000;
            maps.push(Pml4MapSpec {
                va: stack,
                gpa: stack,
                len: 8192,
                user: true,
                write: true,
                exec: false,
            });
        }
        if matches!(mode, BootMode::Interrupts) {
            maps.extend(crate::carrier_interrupts::supervisor_maps());
            maps.push(crate::carrier_interrupts::data_map(0));
        } else if let BootMode::Shared { .. } = mode {
            maps.extend(crate::carrier_interrupts::supervisor_maps());
        }
        let tables = pml4_tables(
            &maps,
            LAYOUT.pml4_base,
            carrick_x86::X86_PML4_CAPACITY as usize,
        )
        .map_err(|e| fail(format!("CPL0 tables: {e:?}")))?;
        ram.write_gpa(LAYOUT.pml4_base, &tables)
            .map_err(|e| fail(e.to_string()))?;
        if matches!(mode, BootMode::Interrupts) {
            let last = maps.last_mut().ok_or_else(|| fail("progress data map"))?;
            *last = crate::carrier_interrupts::data_map(1);
            let second = pml4_tables(
                &maps,
                crate::carrier_interrupts::SECOND_ROOT,
                carrick_x86::X86_PML4_CAPACITY as usize,
            )
            .map_err(|e| fail(format!("second progress root: {e:?}")))?;
            ram.write_gpa(crate::carrier_interrupts::SECOND_ROOT, &second)
                .map_err(|e| fail(e.to_string()))?;
        }
        let boot = <carrick_hal::x8664_arch::X8664GuestArch as carrick_hal::guest_arch::GuestArch>::bootstrap_sysregs();
        let gdt: Vec<u8> = boot
            .gdt
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        ram.write_gpa(LAYOUT.gdt_base, &gdt)
            .map_err(|e| fail(e.to_string()))?;
        carrick_x86::write_fault_tables_with(LAYOUT, |gpa, bytes| {
            ram.write_gpa(gpa, bytes).map_err(|e| fail(e.to_string()))
        })?;
        // Intel SDM vol. 3: 64-bit TSS IST1 occupies bytes 36..44; the IDT
        // gate's byte 4 selects IST1. Keep double faults off the syscall stack.
        // Reuse the existing descriptors/stubs rather than build another IDT.
        for index in 0..2 {
            let tss = carrick_x86::fault_slot_gpa(carrick_x86::fault_tss_base(LAYOUT), index)?;
            let ist_top = IST_STACK_BASE + (index + 1) * 4096;
            ram.write_gpa(tss + 36, &ist_top.to_le_bytes())
                .map_err(|e| fail(e.to_string()))?;
            let idt = carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(LAYOUT), index)?;
            ram.write_gpa(idt + 8 * 16 + 4, &[1])
                .map_err(|e| fail(e.to_string()))?;
        }
        // SAFETY: private zeroed backing; typed objects fit and are aligned.
        // They are initialized before registration or any guest execution.
        unsafe {
            let page = ram
                .host_ptr(META_GPA, size_of::<ThreadLifecyclePage>())
                .ok_or_else(|| fail("lifecycle page backing"))?
                .cast::<ThreadLifecyclePage>();
            page.write(ThreadLifecyclePage::new());
            (*page)
                .thread_born()
                .ok_or_else(|| fail("second live task admission"))?;
            let counters = ram
                .host_ptr(META_GPA + COUNTERS_OFFSET, size_of::<Counters>())
                .ok_or_else(|| fail("counter backing"))?
                .cast::<Counters>();
            counters.write(Counters::new());

            if let BootMode::Shared { setup, .. } = &mut mode {
                let zone_ptr = ram
                    .host_ptr(
                        carrick_x86::cpl0_scheduler::PROGRESS_ZONE,
                        size_of::<ZoneTables>(),
                    )
                    .ok_or_else(|| fail("zone backing"))?
                    .cast::<ZoneTables>();
                zone_ptr.write_bytes(0, 1);
                let binding_ptr = ram
                    .host_ptr(
                        carrick_x86::cpl0_mmu::OWNER_CONTEXT_BASE,
                        size_of::<ContextBinding>(),
                    )
                    .ok_or_else(|| fail("binding backing"))?
                    .cast::<core::mem::MaybeUninit<ContextBinding>>();
                if let Some(ptr) = ram.host_ptr(
                    carrick_x86::cpl0_mmu::PROGRESS_RESERVATIONS,
                    size_of::<carrick_x86::cpl0_mmu::SharedReservations>(),
                ) {
                    ptr.cast::<u8>()
                        .write_bytes(0, size_of::<carrick_x86::cpl0_mmu::SharedReservations>());
                }
                if let Some(ptr) = ram.host_ptr(
                    carrick_x86::cpl0_mmu::PROGRESS_RESIDENCY,
                    size_of::<carrick_el1_abi::FrameGrantResidencyTable>(),
                ) {
                    ptr.cast::<u8>()
                        .write_bytes(0, size_of::<carrick_el1_abi::FrameGrantResidencyTable>());
                }
                if let Some(ptr) = ram.host_ptr(
                    carrick_x86::cpl0_mmu::PROGRESS_PORTAL,
                    size_of::<carrick_el1_abi::MmPortalSlots>(),
                ) {
                    ptr.cast::<u8>()
                        .write_bytes(0, size_of::<carrick_el1_abi::MmPortalSlots>());
                }
                carrick_x86::cpl0_scheduler::initialize_context_binding(&mut *binding_ptr, || {
                    setup(&*zone_ptr)
                });
            }

            for index in 0..2 {
                let offset = index as u64 * STRIDE;
                let (tid, serial, mm, generation) = if let BootMode::Shared { .. } = mode {
                    if index == 0 {
                        let zone = &*ram
                            .host_ptr(
                                carrick_x86::cpl0_scheduler::PROGRESS_ZONE,
                                size_of::<ZoneTables>(),
                            )
                            .ok_or_else(|| fail("zone backing"))?
                            .cast::<ZoneTables>();
                        let binding = &*ram
                            .host_ptr(
                                carrick_x86::cpl0_mmu::OWNER_CONTEXT_BASE,
                                size_of::<ContextBinding>(),
                            )
                            .ok_or_else(|| fail("binding backing"))?
                            .cast::<ContextBinding>();
                        if let Some(record) = zone.live(binding.record) {
                            let id = record.identity();
                            (id.tid as u32, id.serial, id.mm, id.generation)
                        } else {
                            (41, 101, 11, 5)
                        }
                    } else {
                        (42, 102, 12, 5)
                    }
                } else {
                    (41 + index as u32, 101 + index as u64, 11 + index as u64, 5)
                };

                let slot = ram
                    .host_ptr(
                        META_GPA + CONTROL_OFFSET + offset,
                        size_of::<ThreadControlSlot>(),
                    )
                    .ok_or_else(|| fail("control slot backing"))?
                    .cast::<ThreadControlSlot>();
                slot.write(ThreadControlSlot::new());
                (*slot).reset_for_host_birth(BlockedMask(0));
                if !(*slot).publish_visible_tid(tid) {
                    return Err(fail("issued slot identity"));
                }
                let task = ram
                    .host_ptr(META_GPA + TASK_OFFSET + offset, size_of::<CurrentTask>())
                    .ok_or_else(|| fail("current task backing"))?
                    .cast::<CurrentTask>();
                task.write(CurrentTask::new());
                (*task).set(El1TaskId::from_linux_tid(tid as i32), mm, generation);
                (*task).thread_serial.store(serial, Ordering::Release);
                (*task).publish_lifecycle(
                    EL1_DYNAMIC_METADATA_BASE,
                    EL1_DYNAMIC_METADATA_BASE + CONTROL_OFFSET + offset,
                );
                let (zone_addr, binding_addr) = if let BootMode::Shared { .. } = mode {
                    if index == 0 {
                        (
                            carrick_x86::cpl0_scheduler::PROGRESS_ZONE,
                            carrick_x86::cpl0_mmu::OWNER_CONTEXT_BASE,
                        )
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                };

                let binding = ram
                    .host_ptr(META_GPA + BINDING_OFFSET + offset, size_of::<CpuBinding>())
                    .ok_or_else(|| fail("CPU binding backing"))?
                    .cast::<CpuBinding>();
                binding.write(CpuBinding {
                    kernel_stack: 0xe1_0000 + index as u64 * 0x1_0000 - 16,
                    user_stack: 0,
                    self_address: EL1_DYNAMIC_METADATA_BASE + BINDING_OFFSET + offset,
                    task_address: EL1_DYNAMIC_METADATA_BASE + TASK_OFFSET + offset,
                    counters_address: EL1_DYNAMIC_METADATA_BASE + COUNTERS_OFFSET,
                    entry_kick: AtomicU32::new(0),
                    return_kick: AtomicU32::new(0),
                    entries: AtomicU64::new(0),
                    publications: AtomicU64::new(0),
                    completions: AtomicU64::new(0),
                    captured_stack: AtomicU64::new(0),
                    scheduler_witness: AtomicU64::new(
                        if matches!(mode, BootMode::Interrupts) && index == 0 {
                            carrick_x86::cpl0_scheduler::PROGRESS_STATE
                        } else {
                            0
                        },
                    ),
                    zone_address: zone_addr,
                    context_binding_address: binding_addr,
                    slot: index as u32,
                    admitted: AtomicU32::new(0),
                    admissions: AtomicU64::new(0),
                    reservations_address: if let BootMode::Shared { .. } = mode {
                        carrick_x86::cpl0_mmu::PROGRESS_RESERVATIONS
                    } else {
                        0
                    },
                    residency_address: if let BootMode::Shared { .. } = mode {
                        carrick_x86::cpl0_mmu::PROGRESS_RESIDENCY
                    } else {
                        0
                    },
                    portal_address: if let BootMode::Shared { .. } = mode {
                        carrick_x86::cpl0_mmu::PROGRESS_PORTAL
                    } else {
                        0
                    },
                    table_memory_start: LAYOUT.pml4_base,
                    table_memory_end: 0xc0_0000,
                    pending_owner_wakes: AtomicU64::new(0),
                    owner_wake_irqs: AtomicU64::new(0),
                });
                if matches!(mode, BootMode::Shared { .. }) {
                    let zone = &*ram
                        .host_ptr(
                            carrick_x86::cpl0_scheduler::PROGRESS_ZONE,
                            size_of::<ZoneTables>(),
                        )
                        .ok_or_else(|| fail("zone backing"))?
                        .cast::<ZoneTables>();
                    zone.slot(SlotId::new(index as u8))
                        .set_sgi_target(EL1_DYNAMIC_METADATA_BASE + BINDING_OFFSET + offset);
                }
            }
        }
        if matches!(mode, BootMode::Shared { .. }) {
            let header = ram
                .host_ptr(
                    carrick_x86::cpl0_scheduler::PROGRESS_HEADER,
                    size_of::<carrick_x86::cpl0_scheduler::ProgressHeader>(),
                )
                .ok_or_else(|| fail("owner interrupt image header"))?;
            // Validate integer entries before installing the guest handler.
            let words = unsafe { core::slice::from_raw_parts(header.cast::<u64>(), 5) };
            if words[0] != carrick_x86::cpl0_scheduler::PROGRESS_MAGIC
                || !(0x10_0000..0x1f_0000).contains(&words[4])
            {
                return Err(fail("owner interrupt header mismatch"));
            }
            for index in 0..2 {
                let idt = carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(LAYOUT), index)?;
                ram.write_gpa(
                    idt + u64::from(carrick_x86::interrupts::KICK_VECTOR) * 16,
                    &carrick_x86::interrupts::interrupt_gate(words[4]),
                )
                .map_err(|e| fail(e.to_string()))?;
            }
        }
        let mut vm = KvmVm::create_empty().map_err(|e| fail(e.to_string()))?;
        if matches!(mode, BootMode::Interrupts | BootMode::Shared { .. }) {
            crate::carrier_interrupts::create_irqchip(&vm)?;
        }
        for (gpa, ptr, len) in ram.windows_for_kvm() {
            vm.map_memory(
                gpa,
                ptr,
                len,
                MemPerms {
                    read: true,
                    write: true,
                    exec: true,
                },
            )
            .map_err(|e| fail(e.to_string()))?;
        }
        let mut a = vm.add_vcpu().map_err(|e| fail(e.to_string()))?;
        let mut b = vm.add_vcpu().map_err(|e| fail(e.to_string()))?;
        for (index, cpu) in [&mut a, &mut b].into_iter().enumerate() {
            if matches!(mode, BootMode::Shared { .. }) {
                // Native executors enter independently; no guest firmware
                // owns AP startup or can issue an INIT/SIPI sequence here.
                cpu.fd()
                    .set_mp_state(kvm_bindings::kvm_mp_state {
                        mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE,
                    })
                    .map_err(|e| fail(e.to_string()))?;
            }
            let mut layout = LAYOUT;
            layout.trampoline_base = plan.entry;
            carrick_x86::program_longmode_entry(
                cpu,
                layout,
                USER_CODE + index as u64 * 4096,
                0x3_1ff0 + index as u64 * 0x1_0000,
            )?;
            carrick_x86::program_fault_segments(cpu, LAYOUT, index as u64)?;
            cpu.set_syscall_msrs(
                plan.entry,
                boot.star,
                boot.sfmask | (1 << 10) | (1 << 8) | (1 << 18),
            )?;
            let msrs = Msrs::from_entries(&[kvm_msr_entry {
                index: 0xc000_0102,
                data: EL1_DYNAMIC_METADATA_BASE + BINDING_OFFSET + index as u64 * STRIDE,
                ..Default::default()
            }])
            .map_err(|e| fail(e.to_string()))?;
            if cpu.fd().set_msrs(&msrs).map_err(|e| fail(e.to_string()))? != 1 {
                return Err(fail("KERNEL_GS_BASE not installed"));
            }
            let system = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
            if system.tr.base
                != carrick_x86::fault_slot_gpa(carrick_x86::fault_tss_base(LAYOUT), index as u64)?
                || system.idt.base
                    != carrick_x86::fault_slot_gpa(
                        carrick_x86::fault_idt_base(LAYOUT),
                        index as u64,
                    )?
            {
                return Err(fail("private TSS/IDT not installed"));
            }
            if let (BootMode::Shared { .. }, 0) = (&mode, index) {
                let binding = unsafe {
                    &*ram
                        .host_ptr(
                            carrick_x86::cpl0_mmu::OWNER_CONTEXT_BASE,
                            size_of::<ContextBinding>(),
                        )
                        .ok_or_else(|| fail("binding backing"))?
                        .cast::<ContextBinding>()
                };
                let msrs = Msrs::from_entries(&[
                    kvm_msr_entry {
                        index: 0xc000_0100,
                        data: binding.context.fs_base,
                        ..Default::default()
                    },
                    kvm_msr_entry {
                        index: 0xc000_0101,
                        data: binding.context.gs_base,
                        ..Default::default()
                    },
                ])
                .map_err(|e| fail(e.to_string()))?;
                if cpu.fd().set_msrs(&msrs).map_err(|e| fail(e.to_string()))? != 2 {
                    return Err(fail("TLS MSRs not installed"));
                }
                let _ = cpu.set_xsave(&binding.context.xsave.0)?;
            }
        }
        let metadata_base = NonNull::new(
            ram.host_ptr(META_GPA, META_LEN as usize)
                .ok_or_else(|| fail("retained metadata backing"))?,
        )
        .ok_or_else(|| fail("null metadata backing"))?;
        Ok(Self {
            cpus: [a, b],
            _vm: vm,
            ram,
            metadata_base,
            host_forwards: AtomicU64::new(0),
            kicks: AtomicU64::new(0),
            work_exits: AtomicU64::new(0),
            handbacks: std::sync::Mutex::new(Vec::new()),
        })
    }

    pub fn zone(&self) -> Result<&ZoneTables, TrapError> {
        let ptr = self
            .ram
            .host_ptr(
                carrick_x86::cpl0_scheduler::PROGRESS_ZONE,
                size_of::<ZoneTables>(),
            )
            .ok_or_else(|| fail("no retained shared zone in this boot venue"))?;
        if !(ptr as usize).is_multiple_of(align_of::<ZoneTables>()) {
            return Err(fail("shared zone alignment"));
        }
        // SAFETY: shared/interrupt boot backing contains the initialized,
        // documented zero-valid zone, retained by this carrier borrow.
        Ok(unsafe { &*ptr.cast::<ZoneTables>() })
    }

    pub fn guest_ptr<T>(&self, gpa: u64) -> Option<*mut T> {
        self.ram
            .host_ptr(gpa, size_of::<T>())
            .map(|p| p.cast::<T>())
    }

    pub fn write_guest_bytes(&mut self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError> {
        self.ram
            .write_gpa(gpa, bytes)
            .map_err(|e| fail(e.to_string()))
    }

    pub fn fs_base(&self, index: usize) -> Result<u64, TrapError> {
        let mut msrs = Msrs::from_entries(&[kvm_msr_entry {
            index: 0xc000_0100,
            ..Default::default()
        }])
        .map_err(|e| fail(e.to_string()))?;
        if self.cpus[index]
            .fd()
            .get_msrs(&mut msrs)
            .map_err(|e| fail(e.to_string()))?
            != 1
        {
            return Err(fail("KVM_GET_MSRS(FS_BASE) failed"));
        }
        msrs.as_slice()
            .first()
            .map(|entry| entry.data)
            .ok_or_else(|| fail("empty FS_BASE"))
    }

    pub fn gs_base(&self, index: usize) -> Result<u64, TrapError> {
        // At a CPL0 doorbell exit, swapgs has put the user GS base into KERNEL_GS_BASE.
        let mut msrs = Msrs::from_entries(&[kvm_msr_entry {
            index: 0xc000_0102,
            ..Default::default()
        }])
        .map_err(|e| fail(e.to_string()))?;
        if self.cpus[index]
            .fd()
            .get_msrs(&mut msrs)
            .map_err(|e| fail(e.to_string()))?
            != 1
        {
            return Err(fail("KVM_GET_MSRS(KERNEL_GS_BASE) failed"));
        }
        msrs.as_slice()
            .first()
            .map(|entry| entry.data)
            .ok_or_else(|| fail("empty user GS_BASE"))
    }

    pub fn xsave(&self, index: usize) -> Result<[u8; carrick_x86::XSAVE_LEN], TrapError> {
        self.cpus[index]
            .get_xsave()?
            .ok_or_else(|| fail("no xsave"))
    }

    /// References are private and used only while both vCPUs are stopped.
    fn metadata<T>(&self, offset: u64) -> &T {
        // SAFETY: all callers select initialized, aligned retained records.
        unsafe { &*self.metadata_base.as_ptr().add(offset as usize).cast::<T>() }
    }
    pub(crate) fn binding(&self, index: usize) -> &CpuBinding {
        self.metadata(BINDING_OFFSET + index as u64 * STRIDE)
    }
    fn task(&self, index: usize) -> &CurrentTask {
        self.metadata(TASK_OFFSET + index as u64 * STRIDE)
    }
    pub(crate) fn slot(&self, index: usize) -> &ThreadControlSlot {
        self.metadata(CONTROL_OFFSET + index as u64 * STRIDE)
    }
    /// Retain and qualify host aliases through this carrier's backing borrow.
    pub fn owner_bindings(
        &self,
    ) -> Result<carrick_x86::cpl0_mmu::HostOwnerBindings<'_>, TrapError> {
        let zone = self
            .ram
            .host_ptr(
                carrick_x86::cpl0_scheduler::PROGRESS_ZONE,
                size_of::<ZoneTables>(),
            )
            .ok_or_else(|| fail("owner zone backing"))?
            .cast::<ZoneTables>();
        // SAFETY: bootstrap initializes these aligned records in this VM's own
        // backing before publication; the borrow retains that backing and VM.
        unsafe {
            carrick_x86::cpl0_mmu::HostOwnerBindings::from_retained_bindings(
                &*zone,
                [self.binding(0), self.binding(1)],
            )
        }
        .ok_or_else(|| fail("owner binding publication changed"))
    }

    pub fn owner_transport(&self) -> impl carrick_x86::cpl0_mmu::OwnerExecutionTransport + '_ {
        OwnerTransport {
            vm: &self._vm,
            handbacks: &self.handbacks,
        }
    }
    pub fn take_owner_handbacks(&self) -> Vec<carrick_sched_core::RecordRef> {
        core::mem::take(&mut *self.handbacks.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn inject_boundary_kicks(&mut self, index: usize) -> Result<(), TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        self.binding(index).entry_kick.store(1, Ordering::Release);
        self.binding(index).return_kick.store(1, Ordering::Release);
        Ok(())
    }

    /// Publish only machine state for an already issued exact waiter while
    /// both vCPUs are stopped. Runnable and blocked claims stay in ZoneTables.
    pub fn bind_owner_waiter(
        &mut self,
        index: usize,
        context: &ContextBinding,
        program: &[u8],
    ) -> Result<(), TrapError> {
        if index != 1 || program.len() > 4096 {
            return Err(fail("unknown owner waiter"));
        }
        let identity = self
            .zone()?
            .live(context.record)
            .ok_or_else(|| fail("stale owner waiter"))?
            .identity();
        let address =
            carrick_x86::cpl0_mmu::OWNER_CONTEXT_BASE + carrick_x86::cpl0_mmu::OWNER_CONTEXT_STRIDE;
        let ptr = self
            .ram
            .host_ptr(address, size_of::<ContextBinding>())
            .ok_or_else(|| fail("waiter context backing"))?
            .cast::<ContextBinding>();
        // SAFETY: stopped carrier, aligned private sidecar, retained until VM retirement.
        unsafe {
            ptr.write(ContextBinding {
                record: context.record,
                context: context.context.clone(),
            });
            let binding = &mut *self
                .ram
                .host_ptr(META_GPA + BINDING_OFFSET + STRIDE, size_of::<CpuBinding>())
                .ok_or_else(|| fail("waiter binding backing"))?
                .cast::<CpuBinding>();
            binding.zone_address = carrick_x86::cpl0_scheduler::PROGRESS_ZONE;
            binding.context_binding_address = address;
            binding.admitted.store(0, Ordering::Release);
        }
        self.task(index).set(
            El1TaskId::from_linux_tid(identity.tid as i32),
            identity.mm,
            identity.generation,
        );
        self.task(index)
            .thread_serial
            .store(identity.serial, Ordering::Release);
        self.slot(index).reset_for_host_birth(BlockedMask(0));
        if !self.slot(index).publish_visible_tid(identity.tid as u32) {
            return Err(fail("owner waiter identity"));
        }
        // Publish the issued sidecar's machine context before either lane
        // starts; the park/IRQ path then preserves that actual native state.
        let msrs = Msrs::from_entries(&[
            kvm_msr_entry {
                index: 0xc000_0100,
                data: context.context.fs_base,
                ..Default::default()
            },
            kvm_msr_entry {
                index: 0xc000_0101,
                data: context.context.gs_base,
                ..Default::default()
            },
        ])
        .map_err(|e| fail(e.to_string()))?;
        if self.cpus[index]
            .fd()
            .set_msrs(&msrs)
            .map_err(|e| fail(e.to_string()))?
            != 2
        {
            return Err(fail("waiter TLS MSRs not installed"));
        }
        let _ = self.cpus[index].set_xsave(&context.context.xsave.0)?;
        self.write_guest_bytes(USER_CODE + 4096, program)
    }

    pub fn observe(&mut self, index: usize) -> Result<Observation, TrapError> {
        let controls = NativeControls::new(
            &self.ram,
            &self._vm,
            &self.host_forwards,
            &self.kicks,
            &self.work_exits,
            &self.handbacks,
        )?;
        let cpu = self
            .cpus
            .get_mut(index)
            .ok_or_else(|| fail("unknown CPL0 task"))?;
        controls.observe(cpu, index, None)
    }

    /// Both native execution lanes remain borrowed by this carrier. The
    /// readiness doorbell only observes HLT admission; it cannot complete MM
    /// work or supply a wake. Each lane retains the existing five-second bound.
    pub fn observe_owner_completion(&mut self) -> Result<(Observation, Observation), TrapError> {
        let controls = NativeControls::new(
            &self.ram,
            &self._vm,
            &self.host_forwards,
            &self.kicks,
            &self.work_exits,
            &self.handbacks,
        )?;
        let [owner, waiter] = &mut self.cpus;
        std::thread::scope(|scope| {
            let (ready_tx, ready_rx) = mpsc::channel();
            let parked = scope.spawn(move || controls.observe(waiter, 1, Some(&ready_tx)));
            if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                return match parked
                    .join()
                    .map_err(|_| fail("owner waiter thread panicked"))?
                {
                    Err(err) => Err(err),
                    Ok(_) => Err(fail("owner waiter never parked")),
                };
            }
            let completed = controls.observe(owner, 0, None);
            let resumed = parked
                .join()
                .map_err(|_| fail("owner waiter thread panicked"))?;
            Ok((
                completed?,
                resumed.map_err(|e| fail(format!("parked executor did not resume: {e}")))?,
            ))
        })
    }
}

#[derive(Clone, Copy)]
struct NativeControls<'a> {
    ram: &'a GuestRam,
    vm: &'a KvmVm,
    bindings: [&'a CpuBinding; 2],
    tasks: [&'a CurrentTask; 2],
    slots: [&'a ThreadControlSlot; 2],
    counters: &'a Counters,
    host_forwards: &'a AtomicU64,
    kicks: &'a AtomicU64,
    work_exits: &'a AtomicU64,
    handbacks: &'a std::sync::Mutex<Vec<carrick_sched_core::RecordRef>>,
}
impl<'a> NativeControls<'a> {
    fn new(
        ram: &'a GuestRam,
        vm: &'a KvmVm,
        host_forwards: &'a AtomicU64,
        kicks: &'a AtomicU64,
        work_exits: &'a AtomicU64,
        handbacks: &'a std::sync::Mutex<Vec<carrick_sched_core::RecordRef>>,
    ) -> Result<Self, TrapError> {
        fn record<T>(ram: &GuestRam, offset: u64) -> Result<&T, TrapError> {
            let ptr = ram
                .host_ptr(META_GPA + offset, size_of::<T>())
                .ok_or_else(|| fail("native control backing"))?;
            if !(ptr as usize).is_multiple_of(align_of::<T>()) {
                return Err(fail("native control alignment"));
            }
            // SAFETY: bootstrap initialized these retained supervisor records.
            Ok(unsafe { &*ptr.cast::<T>() })
        }
        Ok(Self {
            ram,
            vm,
            bindings: [
                record(ram, BINDING_OFFSET)?,
                record(ram, BINDING_OFFSET + STRIDE)?,
            ],
            tasks: [
                record(ram, TASK_OFFSET)?,
                record(ram, TASK_OFFSET + STRIDE)?,
            ],
            slots: [
                record(ram, CONTROL_OFFSET)?,
                record(ram, CONTROL_OFFSET + STRIDE)?,
            ],
            counters: record(ram, COUNTERS_OFFSET)?,
            host_forwards,
            kicks,
            work_exits,
            handbacks,
        })
    }
    fn observe(
        &self,
        cpu: &mut KvmVcpu,
        index: usize,
        ready: Option<&mpsc::Sender<()>>,
    ) -> Result<Observation, TrapError> {
        let watchdog = Watchdog::start();
        for _ in 0..32 {
            let exit = HvVcpu::run(cpu).map_err(|e| fail(e.to_string()))?;
            if watchdog.expired.load(Ordering::Acquire) {
                let mut detail = format!("CPL0 lane {index} fixture deadline");
                cpu.append_debug_state(&mut detail);
                return Err(fail(detail));
            }
            let VcpuExit::IoOut { port, .. } = exit else {
                let mut detail = "unexpected CPL0 non-control exit".to_owned();
                cpu.append_debug_state(&mut detail);
                return Err(fail(detail));
            };
            if !matches!(
                port,
                CONTROL_PORT
                    | FORWARD_PORT
                    | ENTRY_KICK_PORT
                    | RETURN_KICK_PORT
                    | WORK_PORT
                    | FATAL_PORT
                    | OWNER_PARK_READY_PORT
            ) {
                let mut detail = format!("unexpected CPL0 port {port:#x}");
                cpu.append_debug_state(&mut detail);
                return Err(fail(detail));
            }
            let address = cpu.get_gpr(X86Reg::Rax)?;
            let stack_end = self.bindings[index].kernel_stack + 16;
            if address & 7 != 0
                || address < stack_end - 0x1_0000
                || address
                    .checked_add(size_of::<NativeFrame>() as u64)
                    .is_none_or(|end| end > stack_end)
            {
                return Err(fail(
                    "CPL0 control frame outside its private supervisor stack",
                ));
            }
            let ptr = self
                .ram
                .host_ptr(address, size_of::<NativeFrame>())
                .ok_or_else(|| fail("CPL0 control frame outside backing"))?
                .cast::<NativeFrame>();
            // SAFETY: the exclusive stopped vCPU published this supervisor
            // frame; no other CPU uses its private kernel stack.
            let frame = unsafe { &mut *ptr };
            match port {
                OWNER_PARK_READY_PORT => {
                    ready
                        .ok_or_else(|| fail("unexpected owner park control"))?
                        .send(())
                        .map_err(|_| fail("owner park receiver gone"))?;
                }
                CONTROL_PORT => {
                    let counters: &Counters = self.counters;
                    return Ok(Observation {
                        result: frame.rdi as i64,
                        heads: [self.slots[0].robust_list(), self.slots[1].robust_list()],
                        served: counters.served[99].load(Ordering::Acquire),
                        forwarded: counters.forwarded[99].load(Ordering::Acquire),
                        semantic_host_exits: self.host_forwards.load(Ordering::Acquire),
                        entries: core::array::from_fn(|i| {
                            self.bindings[i].entries.load(Ordering::Acquire)
                        }),
                        publications: core::array::from_fn(|i| {
                            self.bindings[i].publications.load(Ordering::Acquire)
                        }),
                        completions: core::array::from_fn(|i| {
                            self.bindings[i].completions.load(Ordering::Acquire)
                        }),
                        admissions: core::array::from_fn(|i| {
                            self.bindings[i].admissions.load(Ordering::Acquire)
                        }),
                        kicks: self.kicks.load(Ordering::Acquire),
                        work_exits: self.work_exits.load(Ordering::Acquire),
                        captured_stack: self.bindings[index].captured_stack.load(Ordering::Acquire),
                        returned_stack: frame.rsp,
                        preserved_rbx: frame.rbx,
                    });
                }
                FORWARD_PORT => {
                    self.host_forwards.fetch_add(1, Ordering::Release);
                    return Err(fail(format!("unported CPL0 native call {}", frame.rax)));
                }
                FATAL_PORT => {
                    let reason = match frame.rdi {
                        1 => "stale record incarnation",
                        2 => "wrong MM",
                        3 => "not on CPU",
                        4 => "closed space",
                        5 => "root mismatch",
                        6 => "COW owed",
                        other => {
                            return Err(fail(format!("CPL0 fatal / admission refusal: {other}")));
                        }
                    };
                    return Err(fail(format!("CPL0 fatal / admission refusal: {reason}")));
                }
                ENTRY_KICK_PORT | RETURN_KICK_PORT => {
                    let mut pending = self.bindings[index]
                        .pending_owner_wakes
                        .swap(0, Ordering::AcqRel);
                    for slot in 0..CPU_BINDING_COUNT {
                        if pending & (1 << slot) != 0 {
                            if let Err(err) = crate::carrier_interrupts::inject_kick(
                                self.vm,
                                carrick_x86::interrupts::ApicId(slot as u8),
                            ) {
                                self.bindings[index]
                                    .pending_owner_wakes
                                    .fetch_or(pending, Ordering::Release);
                                return Err(err);
                            }
                            pending &= !(1 << slot);
                        }
                    }
                    if pending != 0 {
                        // A destination without a retained native lane is not
                        // delivery. Preserve its ownership and fail explicitly.
                        self.bindings[index]
                            .pending_owner_wakes
                            .fetch_or(pending, Ordering::Release);
                        return Err(fail(
                            "owner wake destination outside retained execution lanes",
                        ));
                    }
                    if self.bindings[index].zone_address != 0 {
                        let zone = self
                            .ram
                            .host_ptr(self.bindings[index].zone_address, size_of::<ZoneTables>())
                            .ok_or_else(|| fail("completion consumer backing"))?;
                        // SAFETY: retained carrier-qualified shared zone.
                        let zone = unsafe { &*zone.cast::<ZoneTables>() };
                        carrick_x86::cpl0_mmu::OwnerExecutionTransport::handbacks(
                            &OwnerTransport {
                                vm: self.vm,
                                handbacks: self.handbacks,
                            },
                            zone,
                        );
                    }
                    self.tasks[index].mark_pending_host_work();
                    cpu.fd_mut().set_kvm_immediate_exit(1);
                    let kicked = HvVcpu::run(cpu);
                    cpu.fd_mut().set_kvm_immediate_exit(0);
                    if !matches!(kicked, Ok(VcpuExit::Kicked)) {
                        return Err(fail("boundary kick did not interrupt KVM_RUN"));
                    }
                    self.kicks.fetch_add(1, Ordering::Release);
                }
                WORK_PORT => {
                    if self.tasks[index].served_with_work.swap(0, Ordering::AcqRel) == 0 {
                        return Err(fail("work exit without completed syscall"));
                    }
                    self.tasks[index]
                        .pending_host_work
                        .store(0, Ordering::Release);
                    self.work_exits.fetch_add(1, Ordering::Release);
                }
                _ => return Err(fail(format!("unexpected CPL0 doorbell {port:#x}"))),
            }
        }
        Err(fail("CPL0 control exit budget exceeded"))
    }
}

struct OwnerTransport<'a> {
    vm: &'a KvmVm,
    handbacks: &'a std::sync::Mutex<Vec<carrick_sched_core::RecordRef>>,
}
impl carrick_x86::cpl0_mmu::OwnerExecutionTransport for OwnerTransport<'_> {
    fn wake(&self, slot: SlotId) -> bool {
        crate::carrier_interrupts::inject_kick(self.vm, carrick_x86::interrupts::ApicId(slot.raw()))
            .is_ok()
    }
    fn handbacks(&self, zone: &ZoneTables) {
        zone.take_completion_handbacks(&carrick_sched_core::BoundedSpin(0), &mut |record| {
            self.handbacks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(record);
        });
    }
}
