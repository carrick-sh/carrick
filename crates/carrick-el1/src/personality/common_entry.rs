//! The normalized common syscall entry.
//!
//! An ISA entry (the x86_64 CPL0 image today) decodes its native frame into a
//! [`CanonicalCall`], which keeps the native number and raw arguments, and
//! hands it here together with the running vCPU slot's [`CurrentTask`].
//! This module routes canonical calls to the one common body and reports what
//! the ISA entry must do next. It never sees an ISA register frame, so no
//! entry builds a fake frame of another architecture to reach common policy.
//!
//! Admitted here: canonical `set_robust_list` (99), served on the calling
//! thread's own [`carrick_el1_abi::ThreadControlSlot`], including its
//! invalid-length `EINVAL`. Everything else is [`EntryOutcome::Forward`]:
//! a counted, explicitly unported call, never a hidden dispatch.
use super::thread_setup::{
    self, LifecycleVenue, RobustListHead, RobustListLen, RobustListSlot, SYS_SET_ROBUST_LIST,
};
use carrick_el1_abi::{Counters, CurrentTask};
use carrick_guest_arch::{CanonicalCall, SyscallResult};
use core::sync::atomic::{AtomicU64, Ordering};

/// What the ISA entry does with a call after the common entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryOutcome {
    /// Completed in the guest kernel: write the result and return to user.
    Served(SyscallResult),
    /// Completed in the guest kernel while host work is pending for the task
    /// (a kick, a signal): write the result, then leave through the host with
    /// the completed call, which the host completes but never dispatches.
    ServedWithWork(SyscallResult),
    /// Not admitted in the guest kernel; nothing was changed.
    Forward,
}

/// Serve `call` for the task loaded on this vCPU slot.
pub fn serve_canonical(
    call: &CanonicalCall,
    counters: &Counters,
    task: &CurrentTask,
    venue: &dyn LifecycleVenue,
    publications: Option<&AtomicU64>,
) -> EntryOutcome {
    let Ok(nr) = usize::try_from(call.canonical.raw()) else {
        return EntryOutcome::Forward;
    };
    let issued =
        task.generation.load(Ordering::Acquire) != 0 && task.task_id.load(Ordering::Acquire) != 0;
    let result = match nr {
        SYS_SET_ROBUST_LIST if issued => venue.thread(task).and_then(|thread| {
            thread_setup::set_robust_list(
                thread.page,
                RobustListSlot::new(thread.slot, publications),
                RobustListHead::new(call.args[0]),
                RobustListLen::new(call.args[1]),
            )
            .linux_result()
        }),
        _ => None,
    };
    let Some(result) = result else {
        if let Some(forwarded) = counters.forwarded.get(nr) {
            forwarded.fetch_add(1, Ordering::Relaxed);
        }
        return EntryOutcome::Forward;
    };
    if let Some(served) = counters.served.get(nr) {
        served.fetch_add(1, Ordering::Relaxed);
    }
    task.orig_arg0.store(call.args[0], Ordering::Relaxed);
    let result = SyscallResult::new(result);
    if task.has_pending_host_work() {
        // The flag and the outcome are one step (`leave_served_with_work`).
        let _ = task.leave_served_with_work();
        EntryOutcome::ServedWithWork(result)
    } else {
        EntryOutcome::Served(result)
    }
}

#[cfg(test)]
mod tests;
