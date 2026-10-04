//! Thin hardware witness: native context leaves around the existing shared
//! scheduler's public claims/queues. No Linux wait or scheduling policy here.
use crate::{interrupts, scheduler};
use carrick_sched_core::{BoundedSpin, SlotId, WakeRecord, Waker, ZoneTables};
use scheduler::*;

const SLOT: SlotId = SlotId::new(0);

unsafe extern "C" {
    fn carrick_progress_start() -> !;
    fn carrick_timer_irq();
    fn carrick_kick_irq();
}

#[used]
#[unsafe(link_section = ".progress_header")]
static HEADER: ProgressHeader = ProgressHeader {
    magic: PROGRESS_MAGIC,
    entry: carrick_progress_start,
    timer: carrick_timer_irq,
    kick: carrick_kick_irq,
};

core::arch::global_asm!(
    ".section .text.progress, \"ax\"",
    ".global carrick_progress_start",
    "carrick_progress_start:",
    "cli",
    "call carrick_progress_initialize",
    "mov rsp, rax",
    "mov rdi, rdx",
    "jmp carrick_restore_progress",
    ".global carrick_timer_irq",
    "carrick_timer_irq:",
    "push rdi",
    "mov edi, {timer}",
    "jmp carrick_progress_irq",
    ".global carrick_kick_irq",
    "carrick_kick_irq:",
    "push rdi",
    "mov edi, {kick}",
    "carrick_progress_irq:",
    "push rsi", "push rdx", "push rcx", "push rax",
    "push r8", "push r9", "push r10", "push r11",
    "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
    "test byte ptr [rsp + 128], 3",
    "jz 2f",
    "swapgs",
    "2:",
    "mov rsi, {scratch}",
    "mov eax, 7", "xor edx, edx", "xsave64 [rsi]",
    "mov rsi, rsp",
    "call carrick_progress_interrupt",
    "mov rdi, rax",
    "carrick_restore_progress:",
    "mov eax, 7", "xor edx, edx", "xrstor64 [rdi]",
    "test byte ptr [rsp + 128], 3",
    "jz 3f",
    "swapgs",
    "3:",
    "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
    "pop r11", "pop r10", "pop r9", "pop r8", "pop rax", "pop rcx",
    "pop rdx", "pop rsi", "pop rdi",
    "iretq",
    timer = const interrupts::TIMER_VECTOR,
    kick = const interrupts::KICK_VECTOR,
    scratch = const PROGRESS_STATE + core::mem::offset_of!(ProgressState, scratch) as u64,
);

fn state() -> &'static mut ProgressState {
    // SAFETY: single running fixture vCPU, IF=0 throughout every caller.
    unsafe { &mut *(PROGRESS_STATE as *mut ProgressState) }
}
fn zone() -> &'static ZoneTables {
    // SAFETY: carrier-retained zero-initialized common records, supervisor only.
    unsafe { &*(PROGRESS_ZONE as *const ZoneTables) }
}
fn read_msr(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: qualified CPL0 FS/GS registers only.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high, options(nostack))
    };
    u64::from(low) | (u64::from(high) << 32)
}
fn write_msr(index: u32, value: u64) {
    // SAFETY: CPL0; bootstrap supplied canonical retained user TLS bases.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") index, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nostack))
    };
}
fn control(port: u16) {
    // SAFETY: declared fixture control/observation, no semantic request.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") 0u8, options(nostack)) };
}
fn stop(code: u64) -> ! {
    state().failure = code;
    unsafe { interrupts::hardware::arm_timer(None) };
    control(PROGRESS_DONE_PORT);
    crate::kernel::halt()
}

fn install(task: &ContextBinding, maintenance: carrick_guest_arch::RootGpa) {
    // SAFETY: both admitted fixture roots have identical supervisor mappings.
    unsafe { install_root(maintenance) };
    zone().release_space(SLOT);
    if !admit_context(zone(), SLOT, task) {
        stop(1);
    }
    unsafe { install_root(task.context.address.root) };
    write_msr(0xc000_0100, task.context.fs_base);
    // SWAPGS has already selected the kernel binding. The other base is user.
    write_msr(0xc000_0102, task.context.gs_base);
}

#[repr(C)]
pub struct InitialReturn {
    frame: *const InterruptFrame,
    xsave: *const XsaveArea,
}

#[unsafe(no_mangle)]
extern "C" fn carrick_progress_initialize() -> InitialReturn {
    unsafe { interrupts::hardware::enable() };
    let record = zone().switch_in(SLOT).unwrap_or_else(|| stop(2));
    let state = state();
    let task = state
        .tasks
        .iter()
        .find(|task| task.record.id == record)
        .unwrap_or_else(|| stop(3));
    install(task, state.maintenance_root);
    // The first task enters the existing common kernel before compute. The
    // timer starts only after that real syscall's return boundary.
    InitialReturn {
        frame: &task.context.frame,
        xsave: &task.context.xsave,
    }
}

pub fn entry_boundary() {
    control(PROGRESS_ENTRY_PORT);
    unsafe { core::arch::asm!("sti", "nop", "cli", options(nostack)) };
}

pub fn return_boundary() {
    control(PROGRESS_RETURN_PORT);
    unsafe { core::arch::asm!("sti", "nop", "cli", options(nostack)) };
    // xAPIC ticks are a hardware quantum, not a Linux clock/deadline policy.
    unsafe { interrupts::hardware::arm_timer(Some(interrupts::TimerTicks(100_000))) };
}

#[unsafe(no_mangle)]
extern "C" fn carrick_progress_interrupt(
    vector: u32,
    frame: &mut InterruptFrame,
) -> *const XsaveArea {
    let state = state();
    if vector == u32::from(interrupts::KICK_VECTOR) {
        state.kick_irqs += 1;
        let bucket = ZoneTables::bucket_of(state.wake_mm, state.wake_address);
        let guard = zone()
            .lock(bucket, &BoundedSpin(0))
            .unwrap_or_else(|| stop(4));
        let mut woken = [WakeRecord::Guest(
            carrick_sched_core::RecordRef::PLACEHOLDER,
        )];
        let count = zone()
            .wake(
                &guard,
                state.wake_mm,
                state.wake_address,
                u32::MAX,
                1,
                Waker::El1 { slot: SLOT },
                &mut woken,
            )
            .unwrap_or_else(|_| stop(5));
        state.wakes += u64::from(count);
        unsafe { interrupts::hardware::end_interrupt() };
        return &state.scratch;
    }
    if vector != u32::from(interrupts::TIMER_VECTOR) || frame.cs != 0x23 {
        stop(6);
    }
    state.timer_irqs += 1;
    let record = zone().slot(SLOT).current().unwrap_or_else(|| stop(7));
    let index = state
        .tasks
        .iter()
        .position(|task| task.record.id == record)
        .unwrap_or_else(|| stop(8));
    let task = &mut state.tasks[index];
    if !task.owned_on(zone(), SLOT) {
        stop(9);
    }
    let root: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) root, options(nostack)) };
    task.context.frame = *frame;
    task.context.fs_base = read_msr(0xc000_0100);
    task.context.gs_base = read_msr(0xc000_0102);
    task.context.xsave = state.scratch.clone();
    let turn = state.turns as usize;
    if turn >= PROGRESS_TURNS {
        stop(10);
    }
    state.order[turn] = index as u64;
    state.roots[turn] = root;
    state.iterations[turn] = frame.gpr[5]; // RBX, compute-loop progress
    state.turns += 1;
    unsafe { interrupts::hardware::end_interrupt() };
    if state.turns as usize == PROGRESS_TURNS {
        unsafe { interrupts::hardware::arm_timer(None) };
        control(PROGRESS_DONE_PORT);
        crate::kernel::halt();
    }
    // Shared FIFO/claims decide the next task; there is no x86 run queue.
    zone().requeue_preempted(SLOT, record);
    let next = zone().switch_in(SLOT).unwrap_or_else(|| stop(11));
    let task = state
        .tasks
        .iter()
        .find(|task| task.record.id == next)
        .unwrap_or_else(|| stop(12));
    install(task, state.maintenance_root);
    *frame = task.context.frame;
    unsafe { interrupts::hardware::arm_timer(Some(interrupts::TimerTicks(100_000))) };
    &task.context.xsave
}
