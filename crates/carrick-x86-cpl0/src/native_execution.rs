// Native scheduler execution over the sole resident process owner.
use super::{anonymous, initial_boot, native_process};
use carrick_el1::isa::x86::{self, context};
use carrick_el1_abi::{BornInZoneSource, CurrentTask, ReservationMm};
use carrick_guest_arch::MmuBackend;
use carrick_sched_core::{ParkedContextWords, SlotId, WakeEffects};
use core::sync::atomic::Ordering;

pub(super) fn source(slot: SlotId) -> BornInZoneSource<'static, ParkedContextWords> {
    let layout = carrick_el1::isa::x86_kernel_layout();
    // SAFETY: the stopped carrier initialized and retains this typed compact
    // zone in the supervisor region for the complete execution lifetime.
    let zone =
        unsafe { &*(layout.zone.raw() as *const carrick_el1::memory::reservations::X86Cpl0Zone) };
    BornInZoneSource { zone, slot }
}
fn task() -> &'static CurrentTask {
    let binding = context::current_cpu_binding().unwrap_or_else(|| initial_boot::fatal_boot());
    if binding.task_address == 0 {
        initial_boot::fatal_boot();
    }
    // SAFETY: this bound CPU owns the retained current-task record.
    unsafe { &*(binding.task_address as *const CurrentTask) }
}

/// Save the complete SYSCALL return using the early assembly-owned XSAVE.
pub(super) fn capture(
    frame: &super::NativeFrame,
    xstate: &context::scheduler::XsaveArea,
) -> ParkedContextWords {
    let task = task();
    let mm = ReservationMm::new(task.mm.key.load(Ordering::Acquire))
        .unwrap_or_else(|| initial_boot::fatal_boot());
    let words = anonymous::live_words(mm).unwrap_or_else(|| initial_boot::fatal_boot());
    let address = words.context.unwrap_or_else(|| initial_boot::fatal_boot());
    let fs = read_msr(0xc000_0100);
    let user_gs = read_msr(0xc000_0102);
    let native = context::context_words::from_syscall(frame, address, fs, user_gs, xstate)
        .unwrap_or_else(|_| initial_boot::fatal_boot());
    context::context_words::from_native(&native)
}
fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: these two architectural TLS MSRs are enabled in the retained
    // native CPU topology; read them before changing the current binding.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nostack, preserves_flags));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Publish migrations through the existing scheduler before delivering IPIs.
pub(super) fn migrate(slot: SlotId) {
    let mut effects = WakeEffects::default();
    source(slot).zone.migrate_queued(slot, &mut effects);
    for target in effects.sgi_slots() {
        if x86::interrupt::send_resched(target).is_err() {
            initial_boot::fatal_boot();
        }
    }
}

/// Run a queued record or sleep under the shared queue's lost-wakeup guard.
/// A guest wait releases its record and installed-space membership before
/// this function selects another runnable task or enters architectural HLT.
pub(super) fn schedule(slot: SlotId) -> ! {
    let source = source(slot);
    let current = task();
    source.zone.release_space(slot);
    loop {
        let now = {
            let (lo, hi): (u32, u32);
            unsafe {
                core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
            }
            ((hi as u64) << 32) | (lo as u64)
        };
        let _ = source.zone.expire_timer(slot, now, carrick_syscall_abi::LINUX_ETIMEDOUT.guest_retval() as u64);
        if let Some(selected) = source.zone.switch_in_full(slot) {
            source.zone.leave_idle(slot);
            let runtime = native_process::runtime();
            let record = source.zone.record_ref(selected.record);
            let state = runtime
                .record_binding(record)
                .unwrap_or_else(|| initial_boot::fatal_boot());
            let identity = source.zone.record(selected.record).identity();
            source
                .zone
                .install_space(slot, state.address.mm.raw().get())
                .unwrap_or_else(|| initial_boot::fatal_boot());
            current.set(
                carrick_el1_abi::El1TaskId::from_linux_tid(state.key.id.raw()),
                state.key.serial.raw(),
                identity.file_table,
            );
            current
                .mm
                .thread_generation
                .store(identity.serial, Ordering::Release);
            current.publish_visible_pid(state.visible_pid);
            current.publish_lifecycle(identity.lifecycle_page, identity.control_slot);
            if x86::X86Backend.install_context(state.address).is_err() {
                initial_boot::fatal_boot();
            }
            let mut words = state.words;
            let mut service = native_process::Service::new(current, slot);
            {
                let mut entry = runtime
                    .enter(source, current, words, &mut service)
                    .unwrap_or_else(|_| initial_boot::fatal_boot());
                if let Some(outcome) = entry.resume_pending_wait() {
                    match outcome {
                        carrick_personality_linux::lifecycle::LifecycleOutcome::Returned {
                            result,
                            ..
                        } => words.set_syscall_return(result.raw() as u64),
                        _ => initial_boot::fatal_boot(),
                    }
                } else if let Some(result) = selected.result {
                    words.set_syscall_return(result);
                }
            }
            // SAFETY: the shared claim is OnCpu on this exact slot; every
            // machine field and MM owner is checked again by the ISA return.
            match unsafe { context::resume_parked(words, state.address) } {
                Ok(never) => match never {},
                Err(_) => initial_boot::fatal_boot(),
            }
        }
        let dl = source.zone.timer_deadline(slot);
        if let Some(dl) = dl {
            use carrick_guest_arch::{CounterTick, Deadline, InterruptBackend};
            let _ = carrick_el1::isa::x86::X86Backend.arm_timer(Some(Deadline(CounterTick::new(dl))));
        }
        if source.zone.enter_idle(slot, true) {
            // SAFETY: the shared slot lock closed the queue-vs-sleep race;
            // STI's shadow makes the HLT atomic with enabling wake delivery.
            unsafe {
                core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack));
            }
            source.zone.leave_idle(slot);
        }
        if dl.is_some() {
            use carrick_guest_arch::InterruptBackend;
            let _ = carrick_el1::isa::x86::X86Backend.arm_timer(None);
        }
    }
}
