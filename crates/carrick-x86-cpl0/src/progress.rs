use carrick_el1::isa::x86::context::scheduler::*;
use carrick_el1::isa::x86::interrupts;
use carrick_sched_core::{BoundedSpin, ParkedContextWords, SlotId, WakeRecord, Waker, ZoneTables};
use core::ptr::{addr_of, addr_of_mut};

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

const fn state() -> *mut ProgressState {
    PROGRESS_STATE as *mut ProgressState
}
fn zone() -> &'static ZoneTables<ParkedContextWords> {
    // SAFETY: carrier-retained zero-initialized common records, supervisor only.
    unsafe { &*(PROGRESS_ZONE as *const ZoneTables<ParkedContextWords>) }
}
fn control(port: u16) {
    // SAFETY: declared fixture control/observation, no semantic request.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") 0u8, options(nostack)) };
}
fn stop(code: u64) -> ! {
    let state = state();
    // SAFETY: the carrier initializes and retains `PROGRESS_STATE` for this
    // single fixture vCPU, and no reference to `failure` is ever formed in CPL0.
    unsafe { addr_of_mut!((*state).failure).write(code) };
    unsafe { interrupts::hardware::arm_timer(None) };
    control(PROGRESS_DONE_PORT);
    carrick_x86_carrier::entry::halt()
}

fn install(state: *mut ProgressState, task_index: usize, maintenance: carrick_guest_arch::RootGpa) {
    // SAFETY: both admitted fixture roots have identical supervisor mappings.
    unsafe { install_root(maintenance) };
    zone().release_space(SLOT);
    // SAFETY: `task_index` is in bounds of `tasks`, which the stopped carrier
    // initializes before boot and CPL0 never mutates. The borrow ends before `stop`.
    let (admitted, record_id, task_address) = unsafe {
        let task = &(&*addr_of!((*state).tasks))[task_index];
        (
            admit_context(zone(), SLOT, task),
            task.record.id,
            task.address,
        )
    };
    if !admitted {
        stop(1);
    }
    // SAFETY: admit_context authenticated this exact on-CPU record and this
    // single fixture vCPU owns its claim until the next publication.
    let words = unsafe { *zone().record(record_id).ctx_mut() };
    let context = restore_native_context(words, task_address).unwrap_or_else(|| stop(13));
    unsafe { install_root(context.address.root) };
    write_tls(NativeTlsRegister::Fs, context.fs_base);
    // SWAPGS has already selected the kernel binding. The other base is user.
    write_tls(NativeTlsRegister::UserGs, context.gs_base);
    // SAFETY: single fixture vCPU with IF=0; no reference to `active` is live.
    unsafe { addr_of_mut!((*state).active).write(context) };
}

#[repr(C)]
pub struct InitialReturn {
    frame: *const InterruptFrame,
    xsave: *const XsaveArea,
}

#[unsafe(no_mangle)]
extern "C" fn carrick_progress_initialize() -> InitialReturn {
    // Enables the local APIC SVR/TPR while `cli` in `carrick_progress_start`
    // keeps RFLAGS.IF=0 until `iretq` enters user mode.
    unsafe { interrupts::hardware::enable() };
    let record = zone().switch_in(SLOT).unwrap_or_else(|| stop(2));
    let state = state();
    // SAFETY: `tasks` and `maintenance_root` are initialized by the stopped
    // carrier before boot and never mutated in CPL0.
    let (task_index, maintenance_root) = unsafe {
        let tasks = &*addr_of!((*state).tasks);
        (
            tasks.iter().position(|task| task.record.id == record),
            addr_of!((*state).maintenance_root).read(),
        )
    };
    let task_index = task_index.unwrap_or_else(|| stop(3));
    install(state, task_index, maintenance_root);
    // The first task enters the existing common kernel before compute. The
    // timer starts only after that real syscall's return boundary.
    // SAFETY: `PROGRESS_STATE` remains mapped and retained; raw field pointers
    // carry no Rust reference borrow across the assembly restore stub.
    unsafe {
        let active = addr_of!((*state).active);
        InitialReturn {
            frame: addr_of!((*active).frame),
            xsave: addr_of!((*active).xsave),
        }
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
        // SAFETY: single fixture vCPU entered via interrupt gate (IF=0); no
        // references into `ProgressState` are live.
        let (wake_mm, wake_address) = unsafe {
            let kick_irqs = addr_of_mut!((*state).kick_irqs);
            kick_irqs.write(kick_irqs.read() + 1);
            (
                addr_of!((*state).wake_mm).read(),
                addr_of!((*state).wake_address).read(),
            )
        };
        let bucket = ZoneTables::bucket_of(wake_mm, wake_address);
        let guard = zone()
            .lock(bucket, &BoundedSpin(0))
            .unwrap_or_else(|| stop(4));
        let mut woken = [WakeRecord::Guest(
            carrick_sched_core::RecordRef::PLACEHOLDER,
        )];
        let count = zone()
            .wake(
                &guard,
                wake_mm,
                wake_address,
                u32::MAX,
                1,
                Waker::El1 { slot: SLOT },
                &mut woken,
            )
            .unwrap_or_else(|_| stop(5));
        // SAFETY: single fixture vCPU with IF=0; `wakes` and `scratch` have no
        // live references.
        unsafe {
            let wakes = addr_of_mut!((*state).wakes);
            wakes.write(wakes.read() + u64::from(count));
            interrupts::hardware::end_interrupt();
            return addr_of!((*state).scratch);
        }
    }
    if vector != u32::from(interrupts::TIMER_VECTOR) || frame.cs != 0x23 {
        stop(6);
    }
    // SAFETY: single fixture vCPU entered via interrupt gate (IF=0).
    unsafe {
        let timer_irqs = addr_of_mut!((*state).timer_irqs);
        timer_irqs.write(timer_irqs.read() + 1);
    }
    let record = zone().slot(SLOT).current().unwrap_or_else(|| stop(7));
    // SAFETY: `tasks` is initialized before boot and never mutated in CPL0.
    let index = unsafe { &*addr_of!((*state).tasks) }
        .iter()
        .position(|task| task.record.id == record)
        .unwrap_or_else(|| stop(8));
    // SAFETY: `index < 2` came from `tasks.iter().position(...)`; borrow ends
    // before `stop(9)`.
    let (owned, task_address) = unsafe {
        let task = &(&*addr_of!((*state).tasks))[index];
        (task.owned_on(zone(), SLOT), task.address)
    };
    if !owned {
        stop(9);
    }
    let root: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) root, options(nostack)) };
    // SAFETY: single fixture vCPU with IF=0; `active` is not borrowed.
    let active_address = unsafe { addr_of!((*state).active.address).read() };
    if active_address != task_address {
        stop(14);
    }
    // SAFETY: single fixture vCPU with IF=0; `active` and `scratch` are
    // disjoint fields of `PROGRESS_STATE`, and the timer interrupted the unique
    // on-CPU claim on this vCPU, which remains ours until requeue below.
    unsafe {
        let active = addr_of_mut!((*state).active);
        addr_of_mut!((*active).frame).write(*frame);
        addr_of_mut!((*active).fs_base).write(read_tls(NativeTlsRegister::Fs));
        addr_of_mut!((*active).gs_base).write(read_tls(NativeTlsRegister::UserGs));
        core::ptr::copy_nonoverlapping(
            addr_of!((*state).scratch),
            addr_of_mut!((*active).xsave),
            1,
        );
        *zone().record(record).ctx_mut() = park_native_context(&*active);
    }
    // SAFETY: single fixture vCPU with IF=0; `turns` is not borrowed.
    let turn = unsafe { addr_of!((*state).turns).read() } as usize;
    if turn >= PROGRESS_TURNS {
        stop(10);
    }
    let next_turn = turn + 1;
    // SAFETY: `turn < PROGRESS_TURNS` was verified above, and IF=0 on this
    // single fixture vCPU.
    unsafe {
        addr_of_mut!((*state).order[turn]).write(index as u64);
        addr_of_mut!((*state).roots[turn]).write(root);
        addr_of_mut!((*state).iterations[turn]).write(frame.gpr[5]); // RBX, compute-loop progress
        addr_of_mut!((*state).turns).write(next_turn as u64);
        interrupts::hardware::end_interrupt();
    }
    if next_turn == PROGRESS_TURNS {
        unsafe { interrupts::hardware::arm_timer(None) };
        control(PROGRESS_DONE_PORT);
        carrick_x86_carrier::entry::halt();
    }
    // Shared FIFO/claims decide the next task; there is no x86 run queue.
    if !zone().requeue_preempted(SLOT, record).is_queued() {
        stop(15);
    }
    let next = zone().switch_in(SLOT).unwrap_or_else(|| stop(11));
    // SAFETY: `tasks` and `maintenance_root` are initialized before boot and
    // never mutated in CPL0.
    let (next_index, maintenance_root) = unsafe {
        let tasks = &*addr_of!((*state).tasks);
        (
            tasks.iter().position(|task| task.record.id == next),
            addr_of!((*state).maintenance_root).read(),
        )
    };
    let next_index = next_index.unwrap_or_else(|| stop(12));
    install(state, next_index, maintenance_root);
    // SAFETY: `install` populated `(*state).active` and IF=0 on this vCPU;
    // the returned raw `xsave` pointer carries no Rust reference borrow.
    unsafe {
        let active = addr_of!((*state).active);
        *frame = addr_of!((*active).frame).read();
        interrupts::hardware::arm_timer(Some(interrupts::TimerTicks(100_000)));
        addr_of!((*active).xsave)
    }
}
