//! Native execution primitives over the resident process owner.

use crate::entry::{fatal_boot, halt};
use crate::table_span;
use carrick_el1::isa::x86::{self, context};
use carrick_el1_abi::{
    BornInZoneSource, CurrentTask, NATIVE_ROOT_EXIT_PORT, NativeRootExit, ReservationMm,
};
use carrick_sched_core::{ParkedContextWords, SlotId, WakeEffects};
use core::sync::atomic::Ordering;

pub fn source(slot: SlotId) -> BornInZoneSource<'static, ParkedContextWords> {
    let layout = carrick_el1::isa::x86_kernel_layout();
    // SAFETY: the stopped carrier initialized and retains this typed compact
    // zone in the supervisor region for the complete execution lifetime.
    let zone =
        unsafe { &*(layout.zone.raw() as *const carrick_el1::memory::reservations::X86Cpl0Zone) };
    BornInZoneSource { zone, slot }
}

pub fn task() -> &'static CurrentTask {
    let binding = context::current_cpu_binding().unwrap_or_else(|| fatal_boot());
    if binding.task_address == 0 {
        fatal_boot();
    }
    // SAFETY: this bound CPU owns the retained current-task record.
    unsafe { &*(binding.task_address as *const CurrentTask) }
}

/// Save the complete SYSCALL return using the early assembly-owned XSAVE.
pub fn capture(
    frame: &crate::entry::NativeFrame,
    xstate: &context::scheduler::XsaveArea,
) -> ParkedContextWords {
    let current_task = task();
    let mm = ReservationMm::new(current_task.mm.key.load(Ordering::Acquire))
        .unwrap_or_else(|| fatal_boot());
    let words = table_span::live_words(mm).unwrap_or_else(|| fatal_boot());
    let address = words.context.unwrap_or_else(|| fatal_boot());
    let fs = read_msr(0xc000_0100);
    let user_gs = read_msr(0xc000_0102);
    let native = context::context_words::from_syscall(frame, address, fs, user_gs, xstate)
        .unwrap_or_else(|_| fatal_boot());
    context::context_words::from_native(&native)
}

pub fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: architectural TLS MSRs are enabled in native CPU topology.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nostack, preserves_flags));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Publish migrations through the existing scheduler before delivering IPIs.
pub fn migrate(slot: SlotId) {
    let mut effects = WakeEffects::default();
    source(slot).zone.migrate_queued(slot, &mut effects);
    for target in effects.sgi_slots() {
        if x86::interrupt::send_resched(target).is_err() {
            fatal_boot();
        }
    }
}

/// Publish the terminal completion for root exits.
pub fn publish_root_exit(
    current: &CurrentTask,
    status: carrick_personality_api::TerminationStatus,
) -> ! {
    let binding = carrick_core::entry::binding(&current.execution, &current.mm);
    let linux_status =
        carrick_personality_linux::lifecycle::LinuxWaitStatus::from_termination_status(status);
    let exit = NativeRootExit::new(binding, linux_status).unwrap_or_else(|| fatal_boot());
    // SAFETY: owned retirement authenticated this exact VM completion.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") NATIVE_ROOT_EXIT_PORT,
            in("rax") &exit as *const _ as u64,
            options(nostack, preserves_flags)
        );
    }
    halt();
}

/// Leave the installed process root for the carrier's maintenance root, then
/// publish the slot's absence.
pub fn leave_space(source: BornInZoneSource<'static, ParkedContextWords>) -> bool {
    let maintenance = source.zone.spaces.idle_ttbr();
    if maintenance != 0 {
        let Some(root) = carrick_guest_arch::RootGpa::page_aligned(
            carrick_guest_arch::FrameGpa::new(maintenance),
        ) else {
            fatal_boot();
        };
        // Already parked on the maintenance root: no second CR3 write.
        if x86::hardware_live_root().ok() != Some(root)
            && x86::interrupt::install_maintenance_root(root).is_err()
        {
            fatal_boot();
        }
    }
    source.zone.release_space(source.slot);
    maintenance != 0
}
