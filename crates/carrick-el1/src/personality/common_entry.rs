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
    serve_canonical_inner(call, counters, task, venue, publications, None)
}

pub fn serve_canonical_with_anonymous(
    call: &CanonicalCall,
    counters: &Counters,
    task: &CurrentTask,
    venue: &dyn LifecycleVenue,
    publications: Option<&AtomicU64>,
    anonymous: &mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue,
) -> EntryOutcome {
    serve_canonical_inner(call, counters, task, venue, publications, Some(anonymous))
}

fn serve_canonical_inner(
    call: &CanonicalCall,
    counters: &Counters,
    task: &CurrentTask,
    venue: &dyn LifecycleVenue,
    publications: Option<&AtomicU64>,
    anonymous: Option<&mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue>,
) -> EntryOutcome {
    let shared = SharedVenue {
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
    };
    match anonymous {
        Some(anonymous) => entry::serve_with_anonymous(call, &shared, anonymous),
        None => entry::serve(call, &shared),
    }
}

#[cfg(test)]
mod tests;
