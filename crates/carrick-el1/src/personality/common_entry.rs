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
    serve_canonical_inner::<carrick_sched_core::ThreadCtx>(
        call,
        counters,
        task,
        venue,
        publications,
        None,
        None,
        None,
    )
}

pub fn serve_canonical_with_anonymous(
    call: &CanonicalCall,
    counters: &Counters,
    task: &CurrentTask,
    venue: &dyn LifecycleVenue,
    publications: Option<&AtomicU64>,
    anonymous: &mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue,
) -> EntryOutcome {
    serve_canonical_inner::<carrick_sched_core::ThreadCtx>(
        call,
        counters,
        task,
        venue,
        publications,
        Some(anonymous),
        None,
        None,
    )
}

/// Serve a native process through the same ordered Linux dispatch and exact
/// scheduler completion authority as the default architecture.
#[allow(clippy::too_many_arguments)]
pub fn serve_canonical_with_native<'a>(
    call: &CanonicalCall,
    counters: &'a Counters,
    task: &'a CurrentTask,
    venue: &'a dyn LifecycleVenue,
    publications: Option<&'a AtomicU64>,
    anonymous: &'a mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue,
    process: &'a mut dyn carrick_personality_linux::lifecycle::ProcessNative<
        carrick_sched_core::ParkedContextWords,
    >,
    source: carrick_el1_abi::BornInZoneSource<'a, carrick_sched_core::ParkedContextWords>,
) -> EntryOutcome {
    serve_canonical_inner(
        call,
        counters,
        task,
        venue,
        publications,
        Some(anonymous),
        Some(process),
        Some(source),
    )
}

#[allow(clippy::too_many_arguments)]
fn serve_canonical_inner<C: carrick_el1_abi::EntryContext>(
    call: &CanonicalCall,
    counters: &Counters,
    task: &CurrentTask,
    venue: &dyn LifecycleVenue,
    publications: Option<&AtomicU64>,
    anonymous: Option<&mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue>,
    mut process: Option<&mut dyn carrick_personality_linux::lifecycle::ProcessNative<C>>,
    source: Option<carrick_el1_abi::BornInZoneSource<'_, C>>,
) -> EntryOutcome {
    let shared = SharedVenue {
        binding: move || execution_binding(task),
        state: &task.linux,
        process_pid: task.visible_pid(),
        visible_tid: venue
            .thread(task)
            .and_then(|thread| thread.slot.visible_tid()),
        counters: EntryCounters {
            served: &counters.served,
            forwarded: &counters.forwarded,
        },
        robust_list: move |head, len| {
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
        Some(anonymous) => entry::serve_with_custody::<C>(
            call,
            &shared,
            anonymous,
            process.as_mut().map(|p| {
                &mut **p as &mut (dyn carrick_personality_linux::lifecycle::ProcessNative<C> + '_)
            }),
            source,
        ),
        None => entry::serve(call, &shared),
    }
}

#[cfg(test)]
mod tests;
