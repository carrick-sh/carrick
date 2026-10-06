//! ARM image adapter for the single Linux entry dispatcher.
use super::thread_setup::{self, LifecycleVenue, RobustListHead, RobustListLen, RobustListSlot};
use carrick_el1_abi::{Counters, CurrentTask};
use carrick_guest_arch::CanonicalCall;
use carrick_personality_linux::entry::{self, ExecutionBinding, LinuxEntryVenue};
use core::sync::atomic::{AtomicU64, Ordering};

pub use carrick_personality_linux::entry::EntryOutcome;
pub use carrick_personality_linux::entry::SYS_SET_ROBUST_LIST;
pub use carrick_personality_linux::entry::decode_x86_64;

struct Adapter<'a> {
    call: &'a CanonicalCall,
    counters: &'a Counters,
    task: &'a CurrentTask,
    lifecycle: &'a dyn LifecycleVenue,
    publications: Option<&'a AtomicU64>,
}

pub fn execution_binding(task: &CurrentTask) -> ExecutionBinding {
    let generation = task.generation.load(Ordering::Acquire);
    let binding = ExecutionBinding {
        task: task.task_id.load(Ordering::Acquire),
        generation,
        mm: task.zone_mm.load(Ordering::Acquire),
        thread_generation: task.thread_serial.load(Ordering::Acquire),
    };
    if generation != 0 && task.generation.load(Ordering::Acquire) == generation {
        binding
    } else {
        ExecutionBinding {
            task: 0,
            generation: 0,
            mm: 0,
            thread_generation: 0,
        }
    }
}

impl LinuxEntryVenue for Adapter<'_> {
    fn binding(&self) -> ExecutionBinding {
        execution_binding(self.task)
    }

    fn set_robust_list(&self, head: u64, len: u64) -> Option<i64> {
        let result = self.lifecycle.thread(self.task).and_then(|thread| {
            thread_setup::set_robust_list(
                thread.page,
                RobustListSlot::new(thread.slot, self.publications),
                RobustListHead::new(head),
                RobustListLen::new(len),
            )
            .linux_result()
        });
        if result.is_some() {
            self.task
                .orig_arg0
                .store(self.call.args[0], Ordering::Relaxed);
        }
        result
    }

    fn pending_work(&self) -> bool {
        self.task.has_pending_host_work()
    }

    fn record_forwarded(&self, ordinal: usize) {
        if let Some(counter) = self.counters.forwarded.get(ordinal) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_served(&self, ordinal: usize) {
        if let Some(counter) = self.counters.served.get(ordinal) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn mark_completed_with_work(&self) {
        let _ = self.task.leave_served_with_work();
    }
}

pub fn serve_canonical(
    call: &CanonicalCall,
    counters: &Counters,
    task: &CurrentTask,
    venue: &dyn LifecycleVenue,
    publications: Option<&AtomicU64>,
) -> EntryOutcome {
    entry::serve(
        call,
        &Adapter {
            call,
            counters,
            task,
            lifecycle: venue,
            publications,
        },
    )
}

#[cfg(test)]
mod tests;
