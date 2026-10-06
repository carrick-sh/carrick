//! ARM image adapter for the single Linux entry dispatcher.
use super::thread_setup::{LifecycleVenue, RobustListHead, RobustListLen, RobustListSlot};
use carrick_el1_abi::{Counters, CurrentTask};
use carrick_personality_linux::dispatch::EntryCounters;
use carrick_personality_linux::entry::CanonicalCall;
use carrick_personality_linux::entry::{self, ExecutionBinding, SharedVenue};
use core::sync::atomic::AtomicU64;

pub use carrick_personality_linux::entry::EntryOutcome;
pub use carrick_personality_linux::entry::SYS_SET_ROBUST_LIST;
pub use carrick_personality_linux::entry::decode_x86_64;

pub fn execution_binding(task: &CurrentTask) -> ExecutionBinding {
    carrick_core::entry::binding(&task.execution, &task.mm)
}

pub fn serve_canonical(
    call: &CanonicalCall,
    counters: &Counters,
    task: &CurrentTask,
    venue: &dyn LifecycleVenue,
    publications: Option<&AtomicU64>,
) -> EntryOutcome {
    // The x86 initial carrier binds this same lifecycle slot. ARM routing
    // remains on its existing dispatcher and terminal custody.
    if call.isa == carrick_guest_arch::GuestIsa::X86_64
        && call.canonical.raw() == carrick_personality_linux::abi::x86_64::SYS_SET_TID_ADDRESS
    {
        let result = venue.thread(task).and_then(|thread| {
            carrick_personality_linux::thread::set_tid_address(
                thread,
                execution_binding(task),
                carrick_guest_arch::UserVa::new(call.args[0]),
            )
        });
        if let Some(result) = result {
            counters.served[call.canonical.raw() as usize]
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            return EntryOutcome::Served { result };
        }
        return EntryOutcome::Forward;
    }
    entry::serve(
        call,
        &SharedVenue {
            binding: || execution_binding(task),
            state: &task.linux,
            counters: EntryCounters {
                served: &counters.served,
                forwarded: &counters.forwarded,
            },
            robust_list: |head, len| {
                venue.thread(task).and_then(|thread| {
                    carrick_personality_linux::thread::set_robust_list(
                        thread.page,
                        RobustListSlot::new(thread.slot, publications),
                        RobustListHead::new(head),
                        RobustListLen::new(len),
                    )
                    .linux_result()
                })
            },
        },
    )
}

#[cfg(test)]
mod tests;
