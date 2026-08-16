//! Task-local crash-capture quorum: who owes a core-dump register file.
//!
//! A guest thread that takes a core-carrying fatal signal must write one
//! `NT_PRSTATUS` note per thread of its task. Only the thread itself can read
//! its own architectural state, so the fatal owner opens a *generation*,
//! raises the task-local quiesce barrier, and waits for every sibling to
//! answer.
//!
//! The whole defect class this module exists to close is that "how many Linux
//! threads exist" and "how many can still answer" are DIFFERENT QUESTIONS, and
//! the collector kept substituting one for the other. Both are now explicit:
//!
//! * [`Thread::is_crash_safe_point_participant`] — does this thread have a
//!   live vCPU loop at all? A thread published into the task graph whose host
//!   loop was cancelled before it started, or whose loop has already returned,
//!   can never reach a safe point again and is not a member of any quorum.
//! * [`CrashRegisterVote`] — a participant either PUBLISHES its register file
//!   or explicitly WITHDRAWS. Withdrawal is the honest answer from a thread
//!   that parked at the barrier from a path with no readable register file
//!   (waiting for a vCPU lease, for instance): it will not resume before the
//!   barrier drops, so it can never publish for this generation.
//!
//! [`Thread`]: super::objects::Thread
//! [`Thread::is_crash_safe_point_participant`]:
//!     super::objects::Thread::is_crash_safe_point_participant

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

use super::ids::LinuxTid;
use super::objects::TaskRef;

/// One task-local crash-capture attempt.
///
/// Non-zero by construction: zero is reserved for "no capture is collecting",
/// which is why the broadcast slot below is an `Option<CrashCaptureGeneration>`
/// rather than a sentinel integer a caller could compare by hand.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CrashCaptureGeneration(NonZeroU64);

impl CrashCaptureGeneration {
    /// The wire value carried in probes and diagnostics.
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The generation one past this one. Exists ONLY for the
    /// `CARRICK_CORE_FAILPOINT=register-generation` fault injection, which
    /// proves the collector rejects a sibling that answers the wrong capture.
    pub fn skewed_for_failpoint(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// The per-Linux-process authority that hands out crash-capture generations
/// and broadcasts the one currently collecting.
///
/// Allocation and advertisement are separate because the fatal owner must own
/// the quiesce barrier before any sibling may observe the generation: a thread
/// that parks at the barrier without seeing it would owe a register file it
/// can no longer publish.
#[derive(Debug, Default)]
pub struct CrashCaptureAuthority {
    /// Generation currently collecting, or zero for none.
    collecting: AtomicU64,
    /// Highest generation handed out.
    issued: AtomicU64,
}

/// The process has exhausted its crash-capture generation space.
#[derive(Debug)]
pub struct CrashGenerationExhausted;

impl std::fmt::Display for CrashGenerationExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HVPatch crash generation exhausted")
    }
}

impl std::error::Error for CrashGenerationExhausted {}

impl CrashCaptureAuthority {
    /// Allocate the next generation. Does NOT make it visible to siblings.
    pub fn issue(&self) -> Result<CrashCaptureGeneration, CrashGenerationExhausted> {
        let previous = self.issued.fetch_add(1, Ordering::AcqRel);
        previous
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(CrashCaptureGeneration)
            .ok_or(CrashGenerationExhausted)
    }

    /// Publish `generation` to every safe point in the task. Call this while
    /// holding the quiesce barrier and BEFORE raising it.
    pub fn advertise(&self, generation: CrashCaptureGeneration) {
        self.collecting.store(generation.get(), Ordering::Release);
    }

    /// Stop collecting: no safe point should publish a vote after this.
    pub fn stop_collecting(&self) {
        self.collecting.store(0, Ordering::Release);
    }

    /// The generation a safe point should publish into, if any.
    pub fn collecting(&self) -> Option<CrashCaptureGeneration> {
        NonZeroU64::new(self.collecting.load(Ordering::Acquire)).map(CrashCaptureGeneration)
    }
}

/// One thread's answer for one generation.
///
/// There is deliberately no "pending" variant: absence of a vote IS pending,
/// and only [`Thread::is_crash_safe_point_participant`] decides whether a
/// missing vote is still owed.
///
/// [`Thread::is_crash_safe_point_participant`]:
///     super::objects::Thread::is_crash_safe_point_participant
#[derive(Clone, Debug, PartialEq)]
pub enum CrashRegisterVote {
    /// Complete architectural state, read by the thread itself at a safe point.
    Published(Box<carrick_hal::Aarch64CoreRegisters>),
    /// The thread cannot reach a publish safe point for this generation. Its
    /// `NT_PRSTATUS` note is absent from the core — a real divergence from
    /// Linux, but a bounded and honest one: the alternative was waiting out a
    /// ten-second deadline and then publishing NO core at all.
    Withdrawn,
}

/// One collected register file, tagged with the thread it came from.
#[derive(Clone, Debug)]
pub struct CrashRegisterFile {
    pub tid: LinuxTid,
    pub registers: carrick_hal::Aarch64CoreRegisters,
}

/// Result of one [`CrashQuorum::poll`].
#[derive(Debug)]
pub enum CrashQuorumPoll {
    /// Every participant has answered.
    Complete(Vec<CrashRegisterFile>),
    /// `tid` is a live participant that has neither published nor withdrawn.
    Waiting(LinuxTid),
}

/// The register files one fatal thread must collect before it may publish a
/// core.
///
/// Membership is re-read from the task on every [`poll`](Self::poll) rather
/// than snapshotted once: a thread that retires mid-collection has genuinely
/// stopped existing and must stop being expected.
pub struct CrashQuorum {
    task: TaskRef,
    generation: CrashCaptureGeneration,
}

impl CrashQuorum {
    /// Open the quorum for `generation` over `task`'s live membership.
    pub fn open(task: TaskRef, generation: CrashCaptureGeneration) -> Self {
        Self { task, generation }
    }

    pub const fn generation(&self) -> CrashCaptureGeneration {
        self.generation
    }

    /// Ask every live thread of the task for its vote.
    ///
    /// A published vote counts even from a thread that has since left its vCPU
    /// loop — the registers were read at a valid safe point and stay valid.
    /// A missing vote is only owed by a live participant.
    pub fn poll(&self) -> CrashQuorumPoll {
        let members = self.task.threads();
        let mut collected = Vec::with_capacity(members.len());
        for thread in members {
            match thread.crash_vote(self.generation) {
                Some(CrashRegisterVote::Published(registers)) => {
                    collected.push(CrashRegisterFile {
                        tid: thread.key().tid,
                        registers: *registers,
                    });
                }
                Some(CrashRegisterVote::Withdrawn) => {}
                None if thread.is_crash_safe_point_participant() => {
                    return CrashQuorumPoll::Waiting(thread.key().tid);
                }
                None => {}
            }
        }
        CrashQuorumPoll::Complete(collected)
    }
}
