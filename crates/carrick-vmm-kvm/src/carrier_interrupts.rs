//! KVM CPL0 interrupt routing and bounded hardware witness. The in-kernel
//! LAPIC delivers guest timer/IPI vectors directly; host control injection
//! never becomes a guest task wait, timer thread or semantic syscall service.
//! This consumes the M2 loader, not its per-task host execution loop.
use crate::KvmVm;
use crate::cpl0_boot::{Cpl0Carrier, Watchdog};
use carrick_guest_arch::{AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa};
use carrick_hal::{HvVcpu, TrapError, VcpuExit};
use carrick_mem::pml4::Pml4MapSpec;
use carrick_sched_core::{BoundedSpin, SlotId, ThreadIdentity, ZoneTables};
use carrick_x86::cpl0_scheduler::*;
use carrick_x86::interrupts::*;
use kvm_bindings::{Msrs, kvm_msi, kvm_msr_entry};
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::atomic::Ordering;

pub const SECOND_ROOT: u64 = 0x180_0000;
const FIRST_ROOT: u64 = 0x60_0000;
const SLOT: SlotId = SlotId::new(0);
const WAKE_ADDRESS: u64 = 0x5_0080;

fn fail(message: impl Into<String>) -> TrapError {
    TrapError::Hypervisor(message.into())
}

pub(crate) fn supervisor_maps() -> [Pml4MapSpec; 2] {
    [
        Pml4MapSpec {
            va: PROGRESS_ZONE,
            gpa: PROGRESS_ZONE,
            len: 0x100_0000,
            user: false,
            write: true,
            exec: false,
        },
        Pml4MapSpec {
            va: LAPIC_BASE,
            gpa: LAPIC_BASE,
            len: 4096,
            user: false,
            write: true,
            exec: false,
        },
    ]
}
pub(crate) fn data_map(index: u64) -> Pml4MapSpec {
    Pml4MapSpec {
        va: PROGRESS_DATA,
        gpa: PROGRESS_DATA + index * 4096,
        len: 4096,
        user: true,
        write: true,
        exec: false,
    }
}

pub(crate) fn create_irqchip(vm: &KvmVm) -> Result<(), TrapError> {
    vm.vm
        .create_irq_chip()
        .map_err(|e| fail(format!("KVM_CREATE_IRQCHIP: {e}")))
}

/// Inject a fixed edge-triggered wake at the retained LAPIC CPU destination.
/// KVM performs hardware delivery, including deferral while CPL0 masks IF.
/// No host pthread wake is a completion of a guest task.
pub fn inject_kick(vm: &KvmVm, apic_id: ApicId) -> Result<(), TrapError> {
    let routed = vm
        .vm
        .signal_msi(kvm_msi {
            address_lo: LAPIC_BASE as u32 | (u32::from(apic_id.0) << 12),
            data: u32::from(KICK_VECTOR),
            ..Default::default()
        })
        .map_err(|e| fail(format!("KVM_SIGNAL_MSI: {e}")))?;
    if routed != 1 {
        return Err(fail(format!("wake interrupt not routed: {routed}")));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub enum KickBoundary {
    Entry,
    Return,
}

#[derive(Debug)]
pub struct ProgressObservation {
    pub entries: u64,
    pub completions: u64,
    pub publications: u64,
    pub robust_heads: [(u64, u32); 2],
    pub order: [u64; PROGRESS_TURNS],
    pub roots: [u64; PROGRESS_TURNS],
    pub iterations: [u64; PROGRESS_TURNS],
    pub data: [[u8; 96]; 2],
    pub frames: [InterruptFrame; 2],
    pub tls: [(u64, u64); 2],
    pub xsave: [[u8; XSAVE_BYTES]; 2],
    pub wakes: u64,
    pub kick_irqs: u64,
    pub timer_irqs: u64,
    pub semantic_host_forwards: u64,
    pub interrupt_host_exits: u64,
    pub control_exits: u64,
    pub preemptions: u64,
}

/// One vCPU executes both contexts; no host scheduling or helper can make
/// the second task progress. Both roots map the same data VA to private GPAs.
pub fn witness(
    image: &Path,
    programs: [&[u8]; 2],
    boundary: KickBoundary,
) -> Result<ProgressObservation, TrapError> {
    let mut carrier = Cpl0Carrier::boot_inner(image, programs, true)?;
    let ram = &mut carrier.ram;
    if size_of::<ZoneTables>() > (PROGRESS_STATE - PROGRESS_ZONE) as usize
        || size_of::<ProgressState>() > (SECOND_ROOT - PROGRESS_STATE) as usize
    {
        return Err(fail("progress supervisor regions overlap"));
    }
    let header = ram
        .host_ptr(PROGRESS_HEADER, size_of::<ProgressHeader>())
        .ok_or_else(|| fail("progress image header"))?;
    // Do not form function pointers from an untrusted header: validate raw
    // integer fields and supervisor entry bounds before using guest addresses.
    let words = unsafe { core::slice::from_raw_parts(header.cast::<u64>(), 4) };
    if words[0] != PROGRESS_MAGIC
        || words[1..]
            .iter()
            .any(|pc| !(0x10_0000..0x1f_0000).contains(pc))
    {
        return Err(fail("CPL0 progress header/version/entry mismatch"));
    }
    let entry = words[1];
    let timer = words[2];
    let kick = words[3];
    let idt = carrick_x86::fault_idt_base(carrick_x86::BringupLayout {
        trampoline_base: 0x10_0000,
        gdt_base: 0x50_0000,
        pml4_base: FIRST_ROOT,
    });
    for (vector, pc) in [(TIMER_VECTOR, timer), (KICK_VECTOR, kick)] {
        ram.write_gpa(idt + u64::from(vector) * 16, &interrupt_gate(pc))
            .map_err(|e| fail(e.to_string()))?;
    }
    // SAFETY: retained aligned zeroed backing; all-zero ZoneTables is the
    // documented empty state. Both vCPUs are stopped during publication.
    let zone = unsafe {
        &*ram
            .host_ptr(PROGRESS_ZONE, size_of::<ZoneTables>())
            .ok_or_else(|| fail("zone backing"))?
            .cast::<ZoneTables>()
    };
    zone.drive(SLOT, 1);
    zone.publish_slot(SLOT, 11, Some(0), 0);
    zone.enter_guest(SLOT);
    let root =
        |gpa| RootGpa::page_aligned(FrameGpa::new(gpa)).ok_or_else(|| fail("unaligned root"));
    let nz = |raw| NonZeroU64::new(raw).ok_or_else(|| fail("zero generation"));
    let mut tasks = Vec::new();
    for index in 0..2u64 {
        let mm = 11 + index;
        let root = root(if index == 0 { FIRST_ROOT } else { SECOND_ROOT })?;
        let space = zone
            .spaces
            .publish_closed(mm, root.address().raw(), 0)
            .ok_or_else(|| fail("space admission"))?;
        zone.spaces.open(space);
        let id = zone
            .alloc_record(ThreadIdentity {
                tid: 41 + index,
                serial: 101 + index,
                mm,
                generation: 5,
                ..Default::default()
            })
            .map_err(|_| fail("record admission"))?;
        if index == 0 {
            zone.requeue_preempted(SLOT, id);
        } else {
            let guard = zone
                .lock(ZoneTables::bucket_of(mm, WAKE_ADDRESS), &BoundedSpin(0))
                .ok_or_else(|| fail("wake bucket"))?;
            let seq = zone.next_seq(id);
            zone.enqueue(&guard, id, seq, mm, WAKE_ADDRESS, u32::MAX, 0)
                .map_err(|_| fail("wake enrollment"))?;
            if !zone.publish_guest_park(&guard, SLOT, id, seq) {
                return Err(fail("park publication"));
            }
        }
        let tag = 0x31 + index as u8;
        let mut xsave = XsaveArea::ZERO;
        xsave.0[0..2].copy_from_slice(&0x37fu16.to_le_bytes());
        xsave.0[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        xsave.0[512..520].copy_from_slice(&XSTATE_MASK.to_le_bytes());
        xsave.0[400..416].fill(tag); // XMM15
        xsave.0[816..832].fill(tag); // YMM15 upper
        let fs = PROGRESS_DATA + 0x100 + index * 0x40;
        let gs = PROGRESS_DATA + 0x200 + index * 0x40;
        let gpa = data_map(index).gpa;
        ram.write_gpa(
            gpa + fs - PROGRESS_DATA + 8,
            &(0xf500 + index).to_le_bytes(),
        )
        .map_err(|e| fail(e.to_string()))?;
        ram.write_gpa(
            gpa + gs - PROGRESS_DATA + 16,
            &(0x6500 + index).to_le_bytes(),
        )
        .map_err(|e| fail(e.to_string()))?;
        let mut frame = InterruptFrame {
            gpr: core::array::from_fn(|register| 0xabc0 + index * 0x100 + register as u64),
            rip: crate::cpl0_boot::USER_CODE + index * 4096,
            cs: 0x23,
            flags: 0x202,
            rsp: 0x3_1ff0 + index * 0x1_0000,
            ss: 0x1b,
        };
        frame.gpr[5] = 0; // RBX compute iterations
        frame.gpr[10] = PROGRESS_DATA; // RAX private data VA
        tasks.push(ContextBinding {
            record: zone.record_ref(id),
            context: NativeContext {
                frame,
                address: AddressContext {
                    root,
                    mm: MmGeneration::new(nz(mm)?),
                    generation: ContextGeneration::new(nz(1)?),
                },
                fs_base: fs,
                gs_base: gs,
                xsave,
            },
        });
    }
    let tasks: [ContextBinding; 2] = tasks.try_into().map_err(|_| fail("two contexts"))?;
    let state_ptr = ram
        .host_ptr(PROGRESS_STATE, size_of::<ProgressState>())
        .ok_or_else(|| fail("context backing"))?
        .cast::<ProgressState>();
    unsafe {
        state_ptr.write(ProgressState {
            tasks,
            maintenance_root: root(FIRST_ROOT)?,
            turns: 0,
            order: [u64::MAX; PROGRESS_TURNS],
            roots: [0; PROGRESS_TURNS],
            iterations: [0; PROGRESS_TURNS],
            wakes: 0,
            kick_irqs: 0,
            timer_irqs: 0,
            failure: 0,
            wake_mm: 12,
            wake_address: WAKE_ADDRESS,
            scratch: XsaveArea::ZERO,
        });
    }
    let cpu = &mut carrier.cpus[0];
    let mut sregs = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
    sregs.cs.selector = 8;
    sregs.cs.dpl = 0;
    sregs.ss.selector = 0x10;
    sregs.ss.dpl = 0;
    sregs.gs.base = carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE + 0x8000;
    // Explicit no-PCID/no-global mode, x87/SSE/AVX only. Fail closed rather
    // than preserve only a prefix of some other enabled XSAVE component.
    sregs.cr4 = (sregs.cr4 | (1 << 18)) & !((1 << 17) | (1 << 7));
    sregs.cr0 &= !((1 << 2) | (1 << 3));
    sregs.apic_base = LAPIC_BASE | 0x900;
    let cpuid = cpu
        .fd()
        .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .map_err(|e| fail(e.to_string()))?;
    let state_leaf = cpuid
        .as_slice()
        .iter()
        .find(|entry| entry.function == 0xd && entry.index == 0)
        .ok_or_else(|| fail("XSAVE CPUID missing"))?;
    let avx_leaf = cpuid
        .as_slice()
        .iter()
        .find(|entry| entry.function == 0xd && entry.index == 2)
        .ok_or_else(|| fail("AVX XSAVE CPUID missing"))?;
    if state_leaf.eax & 7 != 7 || avx_leaf.ebx != 576 || avx_leaf.eax != 256 {
        return Err(fail("unsupported standard XSAVE geometry"));
    }
    let xcrs = cpu.fd().get_xcrs().map_err(|e| fail(e.to_string()))?;
    if xcrs.nr_xcrs != 1 || xcrs.xcrs[0].xcr != 0 || xcrs.xcrs[0].value != XSTATE_MASK {
        return Err(fail("CPL0 requires qualified XCR0=7"));
    }
    cpu.fd()
        .set_sregs(&sregs)
        .map_err(|e| fail(e.to_string()))?;
    let msrs = Msrs::from_entries(&[kvm_msr_entry {
        index: 0x1b,
        data: LAPIC_BASE | 0x900,
        ..Default::default()
    }])
    .map_err(|e| fail(e.to_string()))?;
    if cpu.fd().set_msrs(&msrs).map_err(|e| fail(e.to_string()))? != 1 {
        return Err(fail("APIC enable failed"));
    }
    let mut regs = cpu.fd().get_regs().map_err(|e| fail(e.to_string()))?;
    regs.rip = entry;
    regs.rsp = 0xe0_fff0;
    regs.rflags = 2;
    cpu.fd().set_regs(&regs).map_err(|e| fail(e.to_string()))?;
    let watchdog = Watchdog::start();
    let mut control_exits = 0;
    let mut injected = false;
    for _ in 0..3 {
        let exit = HvVcpu::run(&mut carrier.cpus[0])?;
        if watchdog.expired.load(Ordering::Acquire) {
            return Err(fail("CPL0 progress deadline expired"));
        }
        let VcpuExit::IoOut { port, .. } = exit else {
            let mut detail = "unexpected CPL0 progress exit".to_owned();
            carrier.cpus[0].append_debug_state(&mut detail);
            return Err(fail(detail));
        };
        match port {
            PROGRESS_ENTRY_PORT | PROGRESS_RETURN_PORT => {
                control_exits += 1;
                let chosen = match boundary {
                    KickBoundary::Entry => PROGRESS_ENTRY_PORT,
                    KickBoundary::Return => PROGRESS_RETURN_PORT,
                };
                if port == chosen {
                    inject_kick(&carrier._vm, ApicId(0))?;
                    injected = true;
                }
            }
            PROGRESS_DONE_PORT => {
                control_exits += 1;
                let state = unsafe { &*state_ptr };
                if !injected || state.failure != 0 || state.turns != PROGRESS_TURNS as u64 {
                    return Err(fail(format!(
                        "progress failure={}, turns={}, injected={injected}",
                        state.failure, state.turns
                    )));
                }
                let mut data = [[0u8; 96]; 2];
                for (index, bytes) in data.iter_mut().enumerate() {
                    let pointer = carrier
                        .ram
                        .host_ptr(data_map(index as u64).gpa, bytes.len())
                        .ok_or_else(|| fail("data readback"))?;
                    unsafe { bytes.copy_from_slice(core::slice::from_raw_parts(pointer, 96)) };
                }
                return Ok(ProgressObservation {
                    entries: carrier.binding(0).entries.load(Ordering::Acquire),
                    completions: carrier.binding(0).completions.load(Ordering::Acquire),
                    publications: carrier.binding(0).publications.load(Ordering::Acquire),
                    robust_heads: [carrier.slot(0).robust_list(), carrier.slot(1).robust_list()],
                    order: state.order,
                    roots: state.roots,
                    iterations: state.iterations,
                    data,
                    frames: core::array::from_fn(|i| state.tasks[i].context.frame),
                    tls: core::array::from_fn(|i| {
                        (
                            state.tasks[i].context.fs_base,
                            state.tasks[i].context.gs_base,
                        )
                    }),
                    xsave: core::array::from_fn(|i| state.tasks[i].context.xsave.0),
                    wakes: state.wakes,
                    kick_irqs: state.kick_irqs,
                    timer_irqs: state.timer_irqs,
                    // Every exit is classified above; an interrupt or semantic
                    // forward is a failure, never silently excluded from counts.
                    semantic_host_forwards: 0,
                    interrupt_host_exits: 0,
                    control_exits,
                    preemptions: zone.counters.el1_preemptions.load(Ordering::Acquire) - 1,
                });
            }
            _ => {
                return Err(fail(format!(
                    "timer/kick/semantic host exit forbidden: {port:#x}"
                )));
            }
        }
    }
    Err(fail("progress control exit budget exceeded"))
}
