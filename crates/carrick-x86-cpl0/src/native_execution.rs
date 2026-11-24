//! Native scheduler execution over the sole resident process owner.

#![cfg(all(target_os = "none", target_arch = "x86_64"))]

use carrick_core::wait::RetainedDeferral;
use carrick_el1::isa::x86::{self, context};
use carrick_guest_arch::MmuBackend;
use carrick_sched_core::SlotId;
use carrick_x86_carrier::entry::{NativeFrame, notify_work};
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
    // Nothing that reaches the scheduler returns through a user #PF entry
    // frame: a fault parked on an owner resumes from its record, and a fault
    // ended by a fatal signal resumes nowhere (#2792). Every such path ends
    // the fault's custody of this CPU here, before another task runs on it.
    if let Some(binding) = carrick_el1::isa::x86::context::current_cpu_binding() {
        carrick_x86_carrier::entry::leave_user_page_fault(binding);
    }
    let source = carrick_x86_carrier::native_execution::source(slot);
    let current = task();
    if let Ok(now) = carrick_guest_arch::InterruptBackend::counter(&mut x86::X86Backend) {
        source.zone.cpu_leave_slot(slot, now);
    }
    #[cfg(feature = "test-support")]
    crate::anonymous::release_injected_edit_wait(source, current);
    #[cfg(feature = "test-support")]
    crate::test_support::signal_parked_member(source, current);
    #[cfg(feature = "test-support")]
    crate::test_support::release_birth_on_park(source);
    #[cfg(feature = "test-support")]
    crate::test_support::release_fork_commit_on_park(source);
    #[cfg(feature = "test-support")]
    crate::test_support::release_fork_cow_editor_on_park(source);
    settle_current_work(current);
    'schedule: loop {
        #[cfg(feature = "test-support")]
        crate::test_support::hold_idle_scan(slot);
        #[cfg(feature = "test-support")]
        if crate::test_support::peer_release_pending(slot) {
            crate::anonymous::release_injected_edit_wait(source, current);
        }
        #[cfg(feature = "test-support")]
        crate::test_support::lower_injected_gate(source, slot);
        expire_timers(slot);
        // Drain any APIC timer or reschedule vector latched while IF was masked
        // on the outgoing thread before selecting and preparing the next one;
        // xAPIC IA32_TSC_DEADLINE latches IRR on expiry and WRMSR(0) does not
        // clear an already-pending IRR bit.
        unsafe {
            core::arch::asm!("sti", "nop", "cli", options(nomem, nostack));
        }
        if let Some(selected) = source.zone.take_idle_work(slot) {
            source.zone.leave_idle(slot);
            let record = source.zone.record_ref(selected.record);
            if let Ok(now) = carrick_guest_arch::InterruptBackend::counter(&mut x86::X86Backend) {
                source.zone.cpu_bind_record(slot, record, now);
            }
            let runtime = native_process::runtime_for_record(source.zone, record);
            // SAFETY: switch_in_full transferred this exact record to this slot.
            let Some(mut state) = (unsafe { runtime.record_binding(record) }) else {
                if let Ok(now) = carrick_guest_arch::InterruptBackend::counter(&mut x86::X86Backend)
                {
                    source.zone.cpu_leave_slot(slot, now);
                }
                source.zone.clear_current(slot);
                continue;
            };
            let identity = source.zone.record(selected.record).identity();
            #[cfg(feature = "test-support")]
            crate::test_support::raise_gate_at_switch_in(
                source,
                selected,
                state.address.mm.raw().get(),
            );
            // Resuming the MM already installed here needs no detour through
            // the maintenance root (the context install reloads CR3 once).
            let mm_raw = state.address.mm.raw().get();
            if source.zone.installed_space(slot) != mm_raw {
                leave_space(source);
            }
            // A raised Gate (the host's exclusion of this MM) refuses the
            // install: this is "not now". The record's wait is already over,
            // so it parks on the Gate's release keeping everything it resumes
            // with, and its next switch-in resumes as this one would have.
            while source.zone.install_space(slot, mm_raw).is_none() {
                match park_on_gate(source, slot, selected.record, mm_raw) {
                    RetainedDeferral::Parked => continue 'schedule,
                    RetainedDeferral::Rerun => {}
                    RetainedDeferral::Refused => fatal_boot!(),
                }
            }
            settle_current_work(current);
            current.set(
                carrick_el1_abi::El1TaskId::from_linux_tid(
                    i32::try_from(identity.tid).unwrap_or_else(|_| fatal_boot!()),
                ),
                carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
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
                fatal_boot!();
            }
            let mut words = state.words;
            let mut service = native_process::Service::new(current, slot);
            native_process::drain_external_ingress(source, &mut service)
                .unwrap_or_else(|_| fatal_boot!());
            let mut suspended = false;
            {
                let _copy_gate = user_fault_gate::install();
                let mut entry = runtime
                    .enter_registered(
                        native_process::registry(),
                        source,
                        current,
                        state.address,
                        &words,
                        &mut service,
                    )
                    .unwrap_or_else(|_| fatal_boot!());
                match entry
                    .resume_checkpoint(|entry| {
                        use carrick_el1_linux::native_process_runtime::{
                            NativeFailure, NativeResume,
                        };
                        let position =
                            entry.resume_context().saved_syscall_pc().ok_or_else(|| {
                                NativeFailure::Quarantined.run_failure_reason().at_caller()
                            })?;
                        let native = context::context_words::into_native(
                            *entry.resume_context(),
                            state.address,
                        )
                        .map_err(|_| NativeFailure::Quarantined.run_failure_reason().at_caller())?;
                        let mut frame = context::context_words::syscall_frame_from_native(
                            &native,
                            state.address,
                        )
                        .map_err(|_| NativeFailure::Quarantined.run_failure_reason().at_caller())?;
                        let mut machine =
                            crate::linux_personality::X86SignalMachine::new(state.address);
                        match deliver_signal_on_syscall_return(
                            current,
                            entry,
                            &mut frame,
                            &native.xsave,
                            &mut machine,
                        ) {
                            None => {
                                *entry.resume_context_mut() = context::context_words::from_native(
                                    &context::context_words::from_syscall(
                                        &frame,
                                        state.address,
                                        native.fs_base,
                                        native.gs_base,
                                        &native.xsave,
                                    )
                                    .map_err(|_| {
                                        NativeFailure::Quarantined.run_failure_reason().at_caller()
                                    })?,
                                    machine.frame_position(position),
                                );
                                Ok(None)
                            }
                            Some(
                                carrick_personality_linux::dispatch::CompletionRoute::Suspended,
                            ) => Ok(Some(NativeResume::Left(entry.take_root_exit()))),
                            Some(_) => {
                                Err(NativeFailure::Quarantined.run_failure_reason().at_caller())
                            }
                        }
                    })
                    .unwrap_or_else(|reason| complete_run_failure(current, reason))
                {
                    carrick_el1_linux::native_process_runtime::NativeResume::Returned(result) => {
                        words.set_syscall_return(result.raw() as u64)
                    }
                    carrick_el1_linux::native_process_runtime::NativeResume::Left(root_exit) => {
                        if let Ok(now) =
                            carrick_guest_arch::InterruptBackend::counter(&mut x86::X86Backend)
                        {
                            source.zone.cpu_leave_slot(slot, now);
                        }
                        if let Some(status) = root_exit {
                            publish_root_exit(current, status.to_termination_status());
                        }
                        #[cfg(feature = "test-support")]
                        crate::anonymous::release_injected_edit_wait(source, current);
                        settle_current_work(current);
                        leave_space(source);
                        continue;
                    }
                    carrick_el1_linux::native_process_runtime::NativeResume::NoPending => {
                        // SAFETY: switch_in_full still gives this slot the
                        // exact record; a resumed fault/metadata wait clears
                        // its token here and preserves user RAX.
                        let metadata_resume = unsafe {
                            source
                                .zone
                                .record(selected.record)
                                .consume_metadata_operation()
                        };
                        // SAFETY: switch_in_full still gives this slot the
                        // exact record; its exec commit rewrote the context.
                        match unsafe { runtime.record_binding(record) } {
                            // A committed exec replaced the record's image:
                            // enter the successor's saved entry state on
                            // its own address space. The predecessor's
                            // syscall has no return word.
                            Some(replaced) if replaced.address != state.address => {
                                if x86::X86Backend.install_context(replaced.address).is_err() {
                                    fatal_boot!();
                                }
                                words = replaced.words;
                                state = replaced;
                            }
                            Some(_) => {
                                if !metadata_resume && let Some(result) = selected.result {
                                    words.set_syscall_return(result);
                                }
                            }
                            None => fatal_boot!(),
                        }
                    }
                    // A typed saved retry already names its x86 syscall
                    // instruction; the parked context needs no further edit.
                    carrick_el1_linux::native_process_runtime::NativeResume::RetrySavedSyscall => {}
                    // Preparation completed without generating entropy. Re-enter
                    // the saved x86 SYSCALL with its original arguments. The
                    // context records the rewind, so a preemption before the
                    // instruction runs cannot have it rewound again (#2851).
                    carrick_el1_linux::native_process_runtime::NativeResume::RetrySyscall => {
                        carrick_guest_arch::ProcessContext::restart_syscall(&mut words);
                    }
                    carrick_el1_linux::native_process_runtime::NativeResume::Invalid => {
                        fatal_boot!()
                    }
                }
                if !suspended {
                    let position = words.saved_syscall_pc().unwrap_or_else(|| fatal_boot!());
                    let native = context::context_words::into_native(words, state.address)
                        .unwrap_or_else(|_| fatal_boot!());
                    let mut frame =
                        context::context_words::syscall_frame_from_native(&native, state.address)
                            .unwrap_or_else(|_| fatal_boot!());
                    let mut machine =
                        crate::linux_personality::X86SignalMachine::new(state.address);
                    if let Some(route) = deliver_signal_on_syscall_return(
                        current,
                        &mut entry,
                        &mut frame,
                        &native.xsave,
                        &mut machine,
                    ) {
                        match route {
                            carrick_personality_linux::dispatch::CompletionRoute::Suspended => {
                                suspended = true
                            }
                            carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion => {
                                let p = carrick_el1_linux::DIAG_INVALID_SITE
                                    .load(core::sync::atomic::Ordering::SeqCst);
                                if p.is_null() {
                                    fatal_boot!()
                                }
                                let loc = unsafe { &*p };
                                let mut report = carrick_el1_abi::PanicReport::new(
                                    loc.file(),
                                    loc.line(),
                                    loc.column(),
                                );
                                let e = carrick_el1_linux::DIAG_INVALID_ERR
                                    .load(core::sync::atomic::Ordering::SeqCst);
                                {
                                    use core::fmt::Write;
                                    let mut w = report.message_writer();
                                    if e.is_null() {
                                        let _ = w.write_str("diag: no error");
                                    } else {
                                        let _ = w.write_str(unsafe { &*e });
                                    }
                                }
                                carrick_el1::isa::x86::transport::publish_fatal_report(
                                    carrick_el1_abi::PanicReportKind::FatalSite,
                                    &report,
                                )
                            }
                            carrick_personality_linux::dispatch::CompletionRoute::Served => fatal_boot!(),
                            carrick_personality_linux::dispatch::CompletionRoute::WithWork => fatal_boot!(),
                            carrick_personality_linux::dispatch::CompletionRoute::HostCustody => fatal_boot!(),
                            carrick_personality_linux::dispatch::CompletionRoute::NativeService => fatal_boot!(),
                            carrick_personality_linux::dispatch::CompletionRoute::Forward => fatal_boot!(),
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
                        .unwrap_or_else(|_| fatal_boot!()),
                        machine.frame_position(position),
                    );
                }
                if let Some(status) = entry.take_root_exit() {
                    complete_root_exit(current, status);
                }
            }
            if suspended {
                if let Ok(now) = carrick_guest_arch::InterruptBackend::counter(&mut x86::X86Backend)
                {
                    source.zone.cpu_leave_slot(slot, now);
                }
                #[cfg(feature = "test-support")]
                crate::anonymous::release_injected_edit_wait(source, current);
                settle_current_work(current);
                continue;
            }
            carrick_x86_carrier::native_execution::migrate(slot);
            let zone = source.zone;
            match unsafe {
                context::resume_parked(words, state.address, || {
                    if let Ok(now) =
                        carrick_guest_arch::InterruptBackend::counter(&mut x86::X86Backend)
                    {
                        zone.cpu_enter_user(slot, Some(record), now);
                    }
                    arm_slice(zone, slot);
                })
            } {
                Ok(never) => match never {},
                Err(_) => fatal_boot!(),
            }
        }
        if let Ok(now) = carrick_guest_arch::InterruptBackend::counter(&mut x86::X86Backend) {
            source.zone.cpu_leave_slot(slot, now);
        }
        settle_current_work(current);
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

/// Work published during resume is still owned by this task. The host work
/// handler consumes both flags and drains global queues before slot handoff.
fn settle_current_work(current: &carrick_el1_abi::CurrentTask) {
    carrick_x86_carrier::settle_owed_before_switch(
        current,
        || current.linux.has_pending_host_work(),
        || notify_work(&NativeFrame::default()),
    );
}

/// Consume the shared timer claim; hardware only supplies a counter interrupt.
/// A user-origin interrupt rotates in [`crate::linux_personality::signal_irq_return`]
/// when a runnable head is available (arming the next slice immediately before
/// `iretq`), or re-arms the ongoing slice there when queued work is contended.
pub fn expire_signal_timer(slot: SlotId) {
    if native_process::is_admitted() {
        expire_timers(slot);
    }
}

fn expire_timers(slot: SlotId) {
    use carrick_guest_arch::{CounterTick, Deadline, InterruptBackend};
    if !native_process::is_admitted() {
        return;
    }
    let zone = carrick_x86_carrier::native_execution::source(slot).zone;
    let mut backend = x86::X86Backend;
    let now = backend.counter().unwrap_or_else(|_| fatal_boot!());
    let retry_ticks = ticks(&mut backend, TIMER_RETRY_NS);
    let deadline = zone.expire_timer_and_rearm(
        slot,
        now.raw(),
        carrick_personality_linux::sched::ETIMEDOUT_RESULT,
        retry_ticks,
        &|owned| {
            carrick_el1::substrate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        },
    );
    backend
        .arm_timer(deadline.map(|ticks| Deadline(CounterTick::new(ticks))))
        .unwrap_or_else(|_| fatal_boot!());
}

/// A thread has completed return preparation on `slot`: start its slice when
/// others wait behind it, and arm the CPU's timer for the earlier of the
/// slot's timed park and that slice's end (the shared slice policy, #2360).
/// Any user-origin interrupt with a runnable head rotates the running thread
/// ([`crate::linux_personality::signal_irq_return`]); without this deadline
/// a thread that never parks, such as a syscall poller, keeps the queued
/// one off this CPU indefinitely (#2306).
fn arm_slice(zone: &'static carrick_el1::memory::reservations::X86Cpl0Zone, slot: SlotId) {
    program_slice(zone, slot, true);
}

/// Re-arm `slot`'s ongoing slice across a non-rotating user-origin interrupt
/// while work remains queued (matching ARM's `Sched::program_timer(true)`).
pub(crate) fn rearm_slice(
    zone: &'static carrick_el1::memory::reservations::X86Cpl0Zone,
    slot: SlotId,
) {
    program_slice(zone, slot, false);
}

fn program_slice(
    zone: &'static carrick_el1::memory::reservations::X86Cpl0Zone,
    slot: SlotId,
    restart: bool,
) {
    use carrick_guest_arch::{CounterTick, Deadline, InterruptBackend};
    if zone.slot(slot).queued() == 0 {
        return;
    }
    let mut backend = x86::X86Backend;
    let timer_deadline = zone.timer_deadline(slot);
    let slice_ticks = ticks(&mut backend, carrick_sched_core::PREEMPT_SLICE_NS);
    let retry_ticks = ticks(&mut backend, TIMER_RETRY_NS);
    let now = backend.counter().unwrap_or_else(|_| fatal_boot!()).raw();
    if restart {
        zone.slot(slot).restart_slice(now);
    }
    let deadline = with_slice(zone, slot, now, slice_ticks, retry_ticks, timer_deadline);
    backend
        .arm_timer(deadline.map(|ticks| Deadline(CounterTick::new(ticks))))
        .unwrap_or_else(|_| fatal_boot!());
}

/// `deadline`, or the running thread's slice end when that is earlier. A
/// deadline already past is retried shortly rather than at once.
fn with_slice(
    zone: &carrick_el1::memory::reservations::X86Cpl0Zone,
    slot: SlotId,
    now: u64,
    slice_ticks: u64,
    retry_ticks: u64,
    deadline: Option<u64>,
) -> Option<u64> {
    let want = match zone.slice_end(slot, now, slice_ticks) {
        Some(slice_end) => Some(deadline.map_or(slice_end, |deadline| deadline.min(slice_end))),
        None => deadline,
    };
    want.map(|cval| {
        if cval <= now {
            now.saturating_add(retry_ticks)
        } else {
            cval
        }
    })
}

/// A retried deadline: one millisecond.
const TIMER_RETRY_NS: u64 = 1_000_000;

fn ticks(backend: &mut x86::X86Backend, ns: u64) -> u64 {
    use carrick_guest_arch::InterruptBackend;
    let hz = backend
        .frequency()
        .unwrap_or_else(|_| fatal_boot!())
        .raw()
        .get();
    u64::try_from(u128::from(hz) * u128::from(ns) / 1_000_000_000).unwrap_or(u64::MAX)
}

/// Park the record switched in on `slot` on its MM's Gate release. Only a
/// raised gate refuses a published entry's install; any other refusal (a
/// closed, re-keyed or rootless entry) is a broken invariant.
#[inline(never)]
fn park_on_gate(
    source: carrick_el1_abi::BornInZoneSource<'static, carrick_sched_core::ParkedContextWords>,
    slot: SlotId,
    record: carrick_sched_core::RecordId,
    mm: u64,
) -> RetainedDeferral {
    let zone = source.zone;
    let Some(index) = zone.spaces.find(mm) else {
        fatal_boot!();
    };
    let gate_raised = || zone.spaces.gate(index) != 0;
    if !gate_raised() && zone.spaces.installed_grant(index, mm).is_none() {
        fatal_boot!();
    }
    let Some(lease) = core::num::NonZeroU64::new(mm)
        .and_then(|key| zone.space_entry(key))
        .and_then(|entry| entry.live_notifications().ok())
    else {
        fatal_boot!();
    };
    carrick_core::wait::defer_switched_in_record(
        zone,
        slot,
        &lease,
        carrick_sched_core::spaces::notification::SpaceWaitCause::Gate,
        record,
        &|effects| native_process::release(zone, carrick_sched_core::Waker::El1 { slot }, effects),
        gate_raised,
    )
}
