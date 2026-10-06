//! ARM image adapter for the single Linux entry dispatcher.
#[cfg(any(test, feature = "host-test"))]
use super::thread_setup::{LifecycleVenue, RobustListHead, RobustListLen, RobustListSlot};
#[cfg(any(test, feature = "host-test"))]
use carrick_el1_abi::Counters;
use carrick_el1_abi::CurrentTask;
#[cfg(any(test, feature = "host-test"))]
use carrick_personality_linux::dispatch::EntryCounters;
use carrick_personality_linux::entry::ExecutionBinding;
#[cfg(any(test, feature = "host-test"))]
use carrick_personality_linux::entry::{self, CanonicalCall, SharedVenue};
#[cfg(any(test, feature = "host-test"))]
use core::sync::atomic::AtomicU64;

#[cfg(any(test, feature = "host-test"))]
pub use carrick_personality_linux::entry::{EntryOutcome, SYS_SET_ROBUST_LIST, decode_x86_64};

pub fn execution_binding(task: &CurrentTask) -> ExecutionBinding {
    carrick_core::entry::binding(&task.execution, &task.mm)
}

#[cfg(any(test, feature = "host-test"))]
pub fn serve_canonical(
    call: &CanonicalCall,
    counters: &Counters,
    task: &CurrentTask,
    venue: &dyn LifecycleVenue,
    publications: Option<&AtomicU64>,
) -> EntryOutcome {
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
