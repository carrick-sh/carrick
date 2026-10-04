//! Bounded M2 hardware binding: one VM, two issued live task slots, native
//! SYSCALL entry and IRETQ return. This is not an OCI/runtime/MM-owner binding.
//! Observation and kick doorbells are declared fixture control transport.
use crate::guest_setup::{GuestRam, WindowKind};
use crate::{KvmKickHandle, KvmVcpu, KvmVm};
use carrick_el1_abi::{
    BlockedMask, Counters, CurrentTask, EL1_DYNAMIC_METADATA_BASE, El1TaskId, ThreadControlSlot,
    ThreadLifecyclePage,
};
use carrick_hal::{HvVcpu, HvVm, MemPerms, TrapError, VcpuExit, VcpuKick};
use carrick_mem::pml4::{Pml4MapSpec, pml4_tables};
use carrick_x86::cpl0_entry::*;
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
const BINDING_OFFSET: u64 = 0x8000;
const TASK_OFFSET: u64 = 0x9000;
const CONTROL_OFFSET: u64 = 0xa000;
const STRIDE: u64 = 0x100;
pub const USER_CODE: u64 = 0x1_0000;
const LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: 0x10_0000,
    gdt_base: 0x50_0000,
    pml4_base: 0x60_0000,
};

fn fail(message: impl Into<String>) -> TrapError {
    TrapError::Hypervisor(message.into())
}

/// RAII deadline: one bounded blocking wait, one kick on expiry, always joined.
struct Watchdog {
    cancel: mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
    expired: Arc<AtomicBool>,
}
impl Watchdog {
    fn start() -> Self {
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
    pub kicks: u64,
    pub work_exits: u64,
}

/// The vCPUs drop before the VM, and its registered backing drops last.
/// No run handle or host pointer escapes this fixture owner.
pub struct Cpl0Carrier {
    cpus: [KvmVcpu; 2],
    _vm: KvmVm,
    ram: GuestRam,
    metadata_base: NonNull<u8>,
    host_forwards: u64,
    kicks: u64,
    work_exits: u64,
}

impl Cpl0Carrier {
    pub fn boot(image: &Path, programs: [&[u8]; 2]) -> Result<Self, TrapError> {
        let bytes = std::fs::read(image).map_err(|e| fail(format!("CPL0 image: {e}")))?;
        let plan = carrick_mem::elf::plan_elf_load_bytes_for(&bytes, 62)
            .map_err(|e| fail(format!("CPL0 ELF: {e}")))?;
        if !(0x10_0000..0x20_0000).contains(&plan.entry) {
            return Err(fail("CPL0 entry outside its supervisor image"));
        }
        let mut ram = GuestRam::new();
        ram.add_window(0, RAM_SIZE, WindowKind::Private)
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
                len: (end + 0xfff & !0xfff) - va,
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
        let tables = pml4_tables(
            &maps,
            LAYOUT.pml4_base,
            carrick_x86::X86_PML4_CAPACITY as usize,
        )
        .map_err(|e| fail(format!("CPL0 tables: {e:?}")))?;
        ram.write_gpa(LAYOUT.pml4_base, &tables)
            .map_err(|e| fail(e.to_string()))?;
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
            for index in 0..2 {
                let offset = index as u64 * STRIDE;
                let slot = ram
                    .host_ptr(
                        META_GPA + CONTROL_OFFSET + offset,
                        size_of::<ThreadControlSlot>(),
                    )
                    .ok_or_else(|| fail("control slot backing"))?
                    .cast::<ThreadControlSlot>();
                slot.write(ThreadControlSlot::new());
                (*slot).reset_for_host_birth(BlockedMask(0));
                if !(*slot).publish_visible_tid(41 + index as u32) {
                    return Err(fail("issued slot identity"));
                }
                let task = ram
                    .host_ptr(META_GPA + TASK_OFFSET + offset, size_of::<CurrentTask>())
                    .ok_or_else(|| fail("current task backing"))?
                    .cast::<CurrentTask>();
                task.write(CurrentTask::new());
                (*task).set(
                    El1TaskId::from_linux_tid(41 + index as i32),
                    11 + index as u64,
                    5,
                );
                (*task)
                    .thread_serial
                    .store(101 + index as u64, Ordering::Release);
                (*task).publish_lifecycle(
                    EL1_DYNAMIC_METADATA_BASE,
                    EL1_DYNAMIC_METADATA_BASE + CONTROL_OFFSET + offset,
                );
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
                });
            }
        }
        let mut vm = KvmVm::create_empty().map_err(|e| fail(e.to_string()))?;
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
            host_forwards: 0,
            kicks: 0,
            work_exits: 0,
        })
    }

    /// References are private and used only while both vCPUs are stopped.
    fn metadata<T>(&self, offset: u64) -> &T {
        // SAFETY: all callers select initialized, aligned retained records.
        unsafe { &*self.metadata_base.as_ptr().add(offset as usize).cast::<T>() }
    }
    fn binding(&self, index: usize) -> &CpuBinding {
        self.metadata(BINDING_OFFSET + index as u64 * STRIDE)
    }
    fn task(&self, index: usize) -> &CurrentTask {
        self.metadata(TASK_OFFSET + index as u64 * STRIDE)
    }
    fn slot(&self, index: usize) -> &ThreadControlSlot {
        self.metadata(CONTROL_OFFSET + index as u64 * STRIDE)
    }
    pub fn inject_boundary_kicks(&mut self, index: usize) -> Result<(), TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        self.binding(index).entry_kick.store(1, Ordering::Release);
        self.binding(index).return_kick.store(1, Ordering::Release);
        Ok(())
    }

    /// Run until a user fixture reports its last result. A finite exit budget
    /// and owned watchdog bound transport loops and an in-guest infinite loop.
    pub fn observe(&mut self, index: usize) -> Result<Observation, TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        let watchdog = Watchdog::start();
        for _ in 0..32 {
            let exit = HvVcpu::run(&mut self.cpus[index]).map_err(|e| fail(e.to_string()))?;
            if watchdog.expired.load(Ordering::Acquire) {
                return Err(fail("CPL0 fixture deadline"));
            }
            let VcpuExit::IoOut { port, .. } = exit else {
                let mut detail = "unexpected CPL0 non-control exit".to_owned();
                self.cpus[index].append_debug_state(&mut detail);
                return Err(fail(detail));
            };
            let address = self.cpus[index].get_gpr(X86Reg::Rax)?;
            let ptr = self
                .ram
                .host_ptr(address, size_of::<NativeFrame>())
                .ok_or_else(|| fail("CPL0 control frame outside backing"))?
                .cast::<NativeFrame>();
            // SAFETY: the exclusive stopped vCPU published this supervisor
            // frame; no other CPU uses its private kernel stack.
            let frame = unsafe { &mut *ptr };
            match port {
                CONTROL_PORT => {
                    let counters: &Counters = self.metadata(COUNTERS_OFFSET);
                    return Ok(Observation {
                        result: frame.rdi as i64,
                        heads: [self.slot(0).robust_list(), self.slot(1).robust_list()],
                        served: counters.served[99].load(Ordering::Acquire),
                        forwarded: counters.forwarded[99].load(Ordering::Acquire),
                        semantic_host_exits: self.host_forwards,
                        entries: core::array::from_fn(|i| {
                            self.binding(i).entries.load(Ordering::Acquire)
                        }),
                        publications: core::array::from_fn(|i| {
                            self.binding(i).publications.load(Ordering::Acquire)
                        }),
                        completions: core::array::from_fn(|i| {
                            self.binding(i).completions.load(Ordering::Acquire)
                        }),
                        kicks: self.kicks,
                        work_exits: self.work_exits,
                    });
                }
                FORWARD_PORT => {
                    // RED-ONLY bring-up scaffold. M2 deletes this entire
                    // successful/error host implementation after its witness.
                    if frame.rax != 273 {
                        return Err(fail("unported CPL0 call"));
                    }
                    self.host_forwards += 1;
                    if frame.rsi == 24 {
                        self.slot(index).set_robust_list(frame.rdi, 24);
                        frame.rax = 0;
                    } else {
                        frame.rax = (-22_i64) as u64;
                    }
                }
                ENTRY_KICK_PORT | RETURN_KICK_PORT => {
                    self.task(index).mark_pending_host_work();
                    self.cpus[index].fd_mut().set_kvm_immediate_exit(1);
                    let kicked = HvVcpu::run(&mut self.cpus[index]);
                    self.cpus[index].fd_mut().set_kvm_immediate_exit(0);
                    if !matches!(kicked, Ok(VcpuExit::Kicked)) {
                        return Err(fail("boundary kick did not interrupt KVM_RUN"));
                    }
                    self.kicks += 1;
                }
                WORK_PORT => {
                    if self.task(index).served_with_work.swap(0, Ordering::AcqRel) == 0 {
                        return Err(fail("work exit without completed syscall"));
                    }
                    self.task(index)
                        .pending_host_work
                        .store(0, Ordering::Release);
                    self.work_exits += 1;
                }
                _ => return Err(fail(format!("unexpected CPL0 doorbell {port:#x}"))),
            }
        }
        Err(fail("CPL0 control exit budget exceeded"))
    }
}
