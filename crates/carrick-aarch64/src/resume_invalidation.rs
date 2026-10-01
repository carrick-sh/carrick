//! Required stage-1 invalidations issued by the vCPU that returns the syscall.
//!
//! A host-lane `munmap`, `mprotect`, `brk`, `mmap` or `madvise` that changes a
//! valid leaf needs `TLBI ASIDE1IS` before the syscall returns to its thread.
//! Issued by the host that is one maintenance round trip (`hvc #1`) per edit.
//! The thread's own vCPU returns the syscall through EL1 anyway, so the engine
//! owes the invalidation instead ([`ResumeInvalidation`]) and resumes the
//! vCPU through the mailbox vector's resume-invalidation entry
//! (`carrick_mem::memory::MailboxResumeLayout`): the broadcast invalidation
//! completes (`DSB ISH`) on every PE before the thread reaches EL0, as a host
//! issued one would. Every other vCPU running the MM is covered by the Inner
//! Shareable broadcast, exactly as Linux's broadcast TLBI covers them.
//!
//! Until the invalidation has run, other vCPUs of the MM may still hold the
//! old translations. Two things must not happen in that window:
//!
//! - **A released frame must not be reused.** A frame the edit released could
//!   be handed to another MM while a stale translation still reaches it. The
//!   carrier's pre-mapped frame pool quarantines a frame recycled while any
//!   invalidation is owed ([`release_tag`] / [`completed_through`]) and
//!   scrubs and frees it only once every invalidation owed at its release has
//!   completed. A frame whose backing leaves stage 2 is unmapped with
//!   `hv_vm_unmap`, which must itself invalidate the guest's cached
//!   translations of that IPA (stage-1 and combined entries) before it
//!   returns, or no guest stage-2 retirement would be safe. Stage-1 table
//!   pages are not exposed: EL1 unlinks an emptied table only after its own
//!   break-before-make invalidation, and the host editor reclaims tables only
//!   in a single-threaded MM, whose one thread is the one returning.
//! - **A sibling thread's syscall must not return over a stale translation.**
//!   While an MM owes an invalidation ([`outstanding_for_mm`]), every other
//!   thread of it that returns an mm syscall through the mailbox resumes
//!   through the same entry, so its own invalidation completes before it
//!   reaches EL0 (a `munmap` on one thread and a reusing `mmap` on another).
//!
//! Fork and exec never owe (they are not eligible syscalls), and break-
//! before-make invalidations inside a transaction always run at once.
//! `CARRICK_EL1_RESUME_TLBI=0` makes every required invalidation a host
//! round trip again.

use parking_lot::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use carrick_abi::CanonicalNr;
use carrick_abi::syscall::nr;

/// `CARRICK_EL1_RESUME_TLBI=0` disables owing; anything else (or unset) keeps
/// it on.
pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("CARRICK_EL1_RESUME_TLBI").map_or(true, |v| v != "0"))
}

/// The syscalls whose required invalidations the returning vCPU may issue:
/// they return straight to their caller and neither fork nor exec.
pub fn eligible_syscall(number: CanonicalNr) -> bool {
    [nr::BRK, nr::MUNMAP, nr::MMAP, nr::MPROTECT, nr::MADVISE].contains(&number)
}

struct Ledger {
    next_ticket: u64,
    /// `(ticket, mm)` for every owed invalidation not yet completed.
    outstanding: Vec<(u64, u64)>,
}

static LEDGER: Mutex<Ledger> = Mutex::new(Ledger {
    next_ticket: 1,
    outstanding: Vec::new(),
});
/// `LEDGER.outstanding.len()`, readable without the lock.
static OUTSTANDING: AtomicUsize = AtomicUsize::new(0);

static OWED: AtomicU64 = AtomicU64::new(0);
static ISSUED_ON_RETURN: AtomicU64 = AtomicU64::new(0);
static ISSUED_BY_HOST: AtomicU64 = AtomicU64::new(0);

/// Carrier-lifetime counts of required (post-edit) stage-1 invalidations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResumeInvalidationStats {
    /// Owed to a syscall's return.
    pub owed: u64,
    /// Issued by the returning vCPU through the resume-invalidation entry.
    pub issued_on_return: u64,
    /// Issued as a host maintenance round trip: an owed one whose task left
    /// its vCPU or stood elsewhere, or a required one that could not be owed.
    pub issued_by_host: u64,
}

pub fn stats() -> ResumeInvalidationStats {
    ResumeInvalidationStats {
        owed: OWED.load(Ordering::Relaxed),
        issued_on_return: ISSUED_ON_RETURN.load(Ordering::Relaxed),
        issued_by_host: ISSUED_BY_HOST.load(Ordering::Relaxed),
    }
}

/// A required invalidation that could not be owed ran as a host round trip.
pub fn note_issued_by_host() {
    ISSUED_BY_HOST.fetch_add(1, Ordering::Relaxed);
}

/// One required invalidation of an MM's ASID, owed by the engine that will
/// return the syscall. Completing it is the only way to retire it: a dropped
/// one stays outstanding, which keeps quarantined frames quarantined (safe,
/// never reused under a stale translation).
#[derive(Debug)]
#[must_use = "an owed invalidation must be issued and completed"]
pub struct ResumeInvalidation {
    ticket: u64,
    mm: u64,
    asid: u16,
}

impl ResumeInvalidation {
    /// Owe one invalidation of `asid` for `mm` (the MM generation).
    pub fn owe(mm: u64, asid: u16) -> Self {
        let mut ledger = LEDGER.lock();
        let ticket = ledger.next_ticket;
        ledger.next_ticket += 1;
        ledger.outstanding.push((ticket, mm));
        OUTSTANDING.store(ledger.outstanding.len(), Ordering::Release);
        OWED.fetch_add(1, Ordering::Relaxed);
        Self { ticket, mm, asid }
    }

    pub fn mm(&self) -> u64 {
        self.mm
    }

    /// The architectural ASID the invalidation targets.
    pub fn asid(&self) -> u16 {
        self.asid
    }

    /// The returning vCPU ran the resume-invalidation entry to completion.
    pub fn complete_on_return(self) {
        ISSUED_ON_RETURN.fetch_add(1, Ordering::Relaxed);
        self.complete();
    }

    /// The host ran it as a maintenance round trip instead.
    pub fn complete_by_host(self) {
        ISSUED_BY_HOST.fetch_add(1, Ordering::Relaxed);
        self.complete();
    }

    /// The invalidation ran to completion on some vCPU (broadcast, `DSB
    /// ISH`): no PE holds a translation it removed.
    pub fn complete(self) {
        let mut ledger = LEDGER.lock();
        ledger
            .outstanding
            .retain(|&(ticket, _)| ticket != self.ticket);
        OUTSTANDING.store(ledger.outstanding.len(), Ordering::Release);
        std::mem::forget(self);
    }
}

impl Drop for ResumeInvalidation {
    fn drop(&mut self) {
        tracing::error!(
            ticket = self.ticket,
            mm = self.mm,
            "owed stage-1 invalidation dropped without completing; frames released \
             after it stay quarantined"
        );
    }
}

/// Whether `mm` owes an invalidation some vCPU has not completed yet.
pub fn outstanding_for_mm(mm: u64) -> bool {
    OUTSTANDING.load(Ordering::Acquire) != 0
        && LEDGER
            .lock()
            .outstanding
            .iter()
            .any(|&(_, owing)| owing == mm)
}

/// The tag for a frame released now: `None` when no invalidation is owed
/// (the frame may be reused at once), else the newest ticket issued, which
/// [`completed_through`] must report complete before the frame is reused.
pub fn release_tag() -> Option<u64> {
    if OUTSTANDING.load(Ordering::Acquire) == 0 {
        return None;
    }
    let ledger = LEDGER.lock();
    (!ledger.outstanding.is_empty()).then(|| ledger.next_ticket - 1)
}

/// Whether every invalidation owed up to `tag` has completed.
pub fn completed_through(tag: u64) -> bool {
    OUTSTANDING.load(Ordering::Acquire) == 0
        || LEDGER
            .lock()
            .outstanding
            .iter()
            .all(|&(ticket, _)| ticket > tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ledger is process-wide; one test owns every assertion on it.
    #[test]
    fn released_frames_wait_for_every_invalidation_owed_at_release() {
        assert!(!outstanding_for_mm(7));
        let first = ResumeInvalidation::owe(7, 7);
        let tag = release_tag().expect("a frame released while owing is tagged");
        assert!(!completed_through(tag));
        assert!(outstanding_for_mm(7));
        assert!(!outstanding_for_mm(8));
        let later = ResumeInvalidation::owe(8, 8);
        let later_tag = release_tag().expect("tag");
        assert!(later_tag > tag);
        first.complete();
        // The frame released before `later` was owed waits only for `first`.
        assert!(completed_through(tag));
        assert!(!completed_through(later_tag));
        assert!(!outstanding_for_mm(7));
        later.complete();
        assert!(completed_through(later_tag));
        assert_eq!(release_tag(), None);
    }

    #[test]
    fn only_returning_mm_syscalls_are_eligible() {
        for number in [nr::BRK, nr::MUNMAP, nr::MMAP, nr::MPROTECT, nr::MADVISE] {
            assert!(eligible_syscall(number));
        }
        for number in [
            nr::CLONE,
            nr::CLONE3,
            nr::EXECVE,
            nr::MREMAP,
            nr::EXIT_GROUP,
        ] {
            assert!(!eligible_syscall(number));
        }
    }
}
