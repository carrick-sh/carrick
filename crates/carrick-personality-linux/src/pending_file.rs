//! File-family entry ordering while order 9 retains its byte/notification owners.
use crate::abi::entry::{LinuxTaskState, SyscallResult};
use crate::dispatch::FamilyCompletion;
use core::sync::atomic::Ordering;

/// Native hooks retain region lookup, validated copying and the pending family
/// bodies. They do not choose fallback, return-work or original-argument policy.
pub trait PendingFileVenue {
    fn ordinal(&self) -> u64;
    fn inotify_add(&mut self) -> Option<i64>;
    fn inotify_remove(&mut self) -> Option<i64>;
    fn original_argument0(&self) -> u64;
    fn task_state(&self) -> Option<&LinuxTaskState>;
    fn file_operation(&mut self) -> Option<i64>;
    fn inotify_read(&mut self) -> Option<i64>;
    fn wake_is_owed(&self) -> bool;
    fn install_result(&mut self, result: SyscallResult);
}

/// Only the read family tries an inotify descriptor after file admission refuses.
pub fn serve_read(venue: &mut (impl PendingFileVenue + ?Sized)) -> FamilyCompletion {
    let original = venue.original_argument0();
    let result = venue.file_operation().or_else(|| venue.inotify_read());
    effect(venue, result, original, true)
}

/// Seek/positioned/write retain the existing notification denominator.
pub fn serve_file(venue: &mut (impl PendingFileVenue + ?Sized), ordinal: u64) -> FamilyCompletion {
    let original = venue.original_argument0();
    let result = venue.file_operation();
    effect(
        venue,
        result,
        original,
        matches!(ordinal, 63 | 64 | 67 | 68),
    )
}

/// Watch addition never claims an owed wake; removal does, after success only.
pub fn watch_effect(
    venue: &mut (impl PendingFileVenue + ?Sized),
    result: Option<i64>,
    original: u64,
    watch: WatchEffect,
) -> FamilyCompletion {
    effect(venue, result, original, watch == WatchEffect::Removed)
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum WatchEffect {
    Added,
    Removed,
}

fn effect(
    venue: &mut (impl PendingFileVenue + ?Sized),
    result: Option<i64>,
    original: u64,
    notify: bool,
) -> FamilyCompletion {
    let Some(result) = result else {
        return FamilyCompletion::Forward;
    };
    // Retain pre-move publication order: native result, original argument,
    // then a pending-work Release publication, and finally entry completion.
    venue.install_result(SyscallResult::new(result));
    if let Some(task) = venue.task_state() {
        task.orig_arg0.store(original, Ordering::Relaxed);
        if notify && venue.wake_is_owed() {
            task.mark_pending_host_work();
        }
    }
    FamilyCompletion::Complete(result)
}
