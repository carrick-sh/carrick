//! Native scheduler execution over the sole resident process owner.

#![cfg(all(target_os = "none", target_arch = "x86_64"))]

use carrick_el1::isa::x86::{self, context};
use carrick_guest_arch::MmuBackend;
use carrick_sched_core::SlotId;
use carrick_x86_carrier::entry::{fatal_boot, user_fault_gate};
use carrick_x86_carrier::native_execution::{leave_space, publish_root_exit, task};
use core::sync::atomic::Ordering;

use crate::linux_personality::{
    complete_root_exit, complete_run_failure, deliver_signal_on_syscall_return,
};
use crate::native_process;

/// Run a queued record or sleep under the shared queue's lost-wakeup guard.
/// A guest wait releases its record and installed-space membership before
/// this function selects another runnable task or enters architectural HLT.
pub fn schedule(slot: SlotId) -> ! {
    let source = carrick_x86_carrier::native_execution::source(slot);
    let current = task();
    loop {
        expire_signal_timer(slot);
        if let Some(selected) = source.zone.switch_in_full(slot) {
            source.zone.leave_idle(slot);
            let record = source.zone.record_ref(selected.record);
            let runtime = native_process::runtime_for_record(source.zone, record);
            // SAFETY: switch_in_full transferred this exact record to this slot.
            let Some(state) = (unsafe { runtime.record_binding(record) }) else {
                source.zone.clear_current(slot);
                continue;
            };
            let identity = source.zone.record(selected.record).identity();
            // Resuming the MM already installed here needs no detour through
            // the maintenance root (the context install reloads CR3 once).
            if source.zone.installed_space(slot) != state.address.mm.raw().get() {
                leave_space(source);
            }
            source
                .zone
                .install_space(slot, state.address.mm.raw().get())
                .unwrap_or_else(|| fatal_boot());
            current.set(
                carrick_el1_abi::El1TaskId::from_linux_tid(
                    i32::try_from(identity.tid).unwrap_or_else(|_| fatal_boot()),
                ),
                identity.generation,
                identity.file_table,
            );
            current
                .mm
                .key
                .store(state.address.mm.raw().get(), Ordering::Release);
            current
                .mm
                .thread_generation
                .store(identity.serial, Ordering::Release);
            current.publish_visible_pid(state.visible_pid);
            current.publish_lifecycle(identity.lifecycle_page, identity.control_slot);
            if x86::X86Backend.install_context(state.address).is_err() {
                fatal_boot();
            }
            let mut words = state.words;
            let mut service = native_process::Service::new(current, slot);
            let mut suspended = false;
            {
                let _copy_gate = user_fault_gate::install();
                let mut entry = runtime
                    .enter(source, current, words, &mut service)
                    .unwrap_or_else(|_| fatal_boot());
                match entry
                    .resume_checkpoint()
                    .unwrap_or_else(|reason| complete_run_failure(current, reason))
                {
                    carrick_el1::personality::native_process_runtime::NativeResume::Returned(
                        result,
                    ) => words.set_syscall_return(result.raw() as u64),
                    carrick_el1::personality::native_process_runtime::NativeResume::Left(
                        root_exit,
                    ) => {
                        if let Some(status) = root_exit {
                            publish_root_exit(current, status.to_termination_status());
                        }
                        leave_space(source);
                        continue;
                    }
                    carrick_el1::personality::native_process_runtime::NativeResume::NoPending => {
                        if let Some(result) = selected.result {
                            words.set_syscall_return(result);
                        }
                    }
                    carrick_el1::personality::native_process_runtime::NativeResume::Invalid => {
                        fatal_boot()
                    }
                }
                if !suspended {
                    let native = context::context_words::into_native(words, state.address)
                        .unwrap_or_else(|_| fatal_boot());
                    let mut frame =
                        context::context_words::syscall_frame_from_native(&native, state.address)
                            .unwrap_or_else(|_| fatal_boot());
                    if let Some(route) = deliver_signal_on_syscall_return(
                        current,
                        &mut entry,
                        &mut frame,
                        &native.xsave,
                    ) {
                        match route {
                            carrick_personality_linux::dispatch::CompletionRoute::Suspended => {
                                suspended = true
                            }
                            _ => fatal_boot(),
                        }
                    }
                    words = context::context_words::from_native(
                        &context::context_words::from_syscall(
                            &frame,
                            state.address,
                            native.fs_base,
                            native.gs_base,
                            &native.xsave,
                        )
                        .unwrap_or_else(|_| fatal_boot()),
                    );
                }
                if let Some(status) = entry.take_root_exit() {
                    complete_root_exit(current, status);
                }
            }
            if suspended {
                continue;
            }
            carrick_x86_carrier::native_execution::migrate(slot);
            match unsafe { context::resume_parked(words, state.address) } {
                Ok(never) => match never {},
                Err(_) => fatal_boot(),
            }
        }
        leave_space(source);
        let dl = source.zone.timer_deadline(slot);
        if let Some(dl) = dl {
            use carrick_guest_arch::{CounterTick, Deadline, InterruptBackend};
            let _ =
                carrick_el1::isa::x86::X86Backend.arm_timer(Some(Deadline(CounterTick::new(dl))));
        }
        if source.zone.enter_idle(slot, true) {
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

/// Consume the shared timer claim; hardware only supplies a counter interrupt.
pub fn expire_signal_timer(slot: SlotId) {
    use carrick_guest_arch::{CounterTick, Deadline, InterruptBackend};
    if !native_process::is_admitted() {
        return;
    }
    let zone = carrick_x86_carrier::native_execution::source(slot).zone;
    let mut backend = x86::X86Backend;
    let now = backend.counter().unwrap_or_else(|_| fatal_boot());
    let retry_ticks = backend
        .frequency()
        .unwrap_or_else(|_| fatal_boot())
        .raw()
        .get()
        / 1000;
    let deadline = zone
        .expire_timer_and_rearm(
            slot,
            now.raw(),
            carrick_personality_linux::abi::signal::LINUX_EAGAIN.guest_retval() as u64,
            retry_ticks,
        )
        .map(|ticks| Deadline(CounterTick::new(ticks)));
    backend.arm_timer(deadline).unwrap_or_else(|_| fatal_boot());
}
