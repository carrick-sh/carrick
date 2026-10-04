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
use super::objects::{TaskRef, ThreadRef};

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
/// Membership is snapshotted at [`open`](Self::open) over the task's live
/// census at the crash generation. The quorum blocks (interruptibly, no
/// deadline) until every member in the census has published registers,
/// published parked registers on withdrawal, or dropped participation.
pub struct CrashQuorum {
    generation: CrashCaptureGeneration,
    census: Vec<ThreadRef>,
    /// The address space `census` belongs to: what authenticates an EL1
    /// zone-record read as safe (see [`Self::el1_parked_registers`]).
    mm: u64,
}

impl CrashQuorum {
    /// Open the quorum for `generation` over `task`'s live membership.
    ///
    /// `mm` is the exact address space the caller has already quiesced (every
    /// vCPU force-exited to the host, every lease drained) before opening
    /// this quorum: the authentication [`Self::el1_parked_registers`] relies
    /// on to read a member's EL1 save area without racing EL1 or a host
    /// claim.
    pub fn open(task: TaskRef, generation: CrashCaptureGeneration, mm: u64) -> Self {
        let census: Vec<ThreadRef> = task.crash_capture_participants().into_threads().collect();
        Self {
            generation,
            census,
            mm,
        }
    }

    pub const fn generation(&self) -> CrashCaptureGeneration {
        self.generation
    }

    /// `thread`'s authoritative register file if the in-guest scheduler
    /// (EL1) currently holds it parked (queued on a futex wait queue or a
    /// vCPU run queue) in the quiesced address space this quorum opened
    /// over.
    ///
    /// A thread the guest scheduler switched off a vCPU without a host exit
    /// never enters this quorum's host-side publish/withdraw protocol at
    /// all: no host executor loop is currently "it" to answer for it. Its
    /// exact registers still exist, in EL1's own save area, unread by
    /// anyone; this is the read that surfaces them here instead of leaving
    /// the thread's `NT_PRSTATUS` note silently absent.
    fn el1_parked_registers(
        &self,
        thread: &ThreadRef,
    ) -> Option<carrick_hal::Aarch64CoreRegisters> {
        // SAFETY: `self.mm` is the caller-authenticated quiesced address
        // space this quorum was opened over (see `Self::open`): every vCPU
        // that could write this thread's zone record is off the guest and
        // drained, so nothing races this read.
        match unsafe { crate::el1_zone::read_quiesced_parked_registers(self.mm, thread.key()) } {
            crate::el1_zone::QuiescedParkedRegisters::Found(registers) => Some(registers),
            crate::el1_zone::QuiescedParkedRegisters::NotParked => None,
            crate::el1_zone::QuiescedParkedRegisters::Unauthenticated => {
                // A real divergence, not a silent drop: the existing
                // required-vs-collected note count (the fidelity gap this
                // thread would otherwise fall into) reports it, and the next
                // poll gets a fresh scan in case the race was transient.
                tracing::warn!(
                    thread = %thread.key(),
                    generation = self.generation.get(),
                    "EL1 zone record for a parked thread changed mid-read; \
                     refusing to publish its register file for this crash generation"
                );
                None
            }
        }
    }

    /// Ask every thread in the census for its vote.
    ///
    /// A published vote counts even from a thread that has since left its vCPU
    /// loop — the registers were read at a valid safe point and stay valid.
    /// A missing vote is owed until the thread publishes or is proven exited,
    /// UNLESS EL1 currently holds the thread parked: then its authoritative
    /// save area answers on its behalf (see [`Self::el1_parked_registers`]),
    /// since no host safe point will ever run for it while EL1 holds it.
    pub fn poll(&self) -> CrashQuorumPoll {
        let mut collected = Vec::new();
        for thread in &self.census {
            match thread.crash_vote(self.generation) {
                Some(CrashRegisterVote::Published(registers)) => {
                    collected.push(CrashRegisterFile {
                        tid: thread.key().tid,
                        registers: *registers,
                    });
                }
                Some(CrashRegisterVote::Withdrawn) => {
                    if let Some(registers) = self
                        .el1_parked_registers(thread)
                        .or_else(|| thread.parked_registers())
                    {
                        collected.push(CrashRegisterFile {
                            tid: thread.key().tid,
                            registers,
                        });
                    }
                }
                None => {
                    if let Some(registers) = self
                        .el1_parked_registers(thread)
                        .or_else(|| thread.parked_registers())
                    {
                        collected.push(CrashRegisterFile {
                            tid: thread.key().tid,
                            registers,
                        });
                    } else if thread.is_crash_safe_point_participant() {
                        return CrashQuorumPoll::Waiting(thread.key().tid);
                    }
                }
            }
        }
        CrashQuorumPoll::Complete(collected)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;

    use super::*;
    use crate::kernel::{ClonePlan, Kernel, KernelContext, RootBootstrap};

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "root".to_string(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    fn clone_sibling(
        kernel: &Arc<Kernel>,
        leader: &KernelContext,
        registry_id: i32,
    ) -> KernelContext {
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        kernel
            .clone_thread(
                leader,
                plan,
                ThreadId::synthetic_for_tests(registry_id),
                None,
            )
            .expect("clone sibling")
    }

    #[test]
    fn crash_quorum_refreshes_membership_after_retirement() {
        let (kernel, leader) = bootstrap(19_440);
        let sibling = clone_sibling(&kernel, &leader, 19_441);
        let leader_key = leader.thread().key();
        let sibling_key = sibling.thread().key();
        let sibling_tid = sibling.thread().key().tid;
        let _participation = sibling
            .thread()
            .enter_crash_safe_point_participation()
            .expect("crash safe-point participation");

        let initial_keys = leader
            .task()
            .crash_capture_participants()
            .into_threads()
            .map(|thread| thread.key())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            initial_keys,
            std::collections::BTreeSet::from([leader_key, sibling_key])
        );

        let authority = CrashCaptureAuthority::default();
        let generation = authority.issue().expect("capture generation");
        leader
            .thread()
            .publish_crash_registers(generation, carrick_hal::Aarch64CoreRegisters::default());
        let quorum = CrashQuorum::open(
            leader.task().clone(),
            generation,
            leader.shared().mm().id().raw(),
        );
        assert!(matches!(
            quorum.poll(),
            CrashQuorumPoll::Waiting(tid) if tid == sibling_tid
        ));

        kernel.exit_thread(&sibling, None).expect("retire sibling");
        let refreshed_keys = leader
            .task()
            .crash_capture_participants()
            .into_threads()
            .map(|thread| thread.key())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            refreshed_keys,
            std::collections::BTreeSet::from([leader_key])
        );
        match quorum.poll() {
            CrashQuorumPoll::Complete(registers) => {
                assert_eq!(registers.len(), 1);
                assert_eq!(registers[0].tid, leader.thread().key().tid);
            }
            other => panic!("expected Complete with leader registers, got {other:?}"),
        }
    }

    #[test]
    fn crash_quorum_collects_published_registers_from_retiring_sibling() {
        let (kernel, leader) = bootstrap(19_450);
        let sibling = clone_sibling(&kernel, &leader, 19_451);
        let sibling_tid = sibling.thread().key().tid;
        let _participation = sibling
            .thread()
            .enter_crash_safe_point_participation()
            .expect("crash safe-point participation");

        let authority = CrashCaptureAuthority::default();
        let generation = authority.issue().expect("capture generation");
        leader
            .thread()
            .publish_crash_registers(generation, carrick_hal::Aarch64CoreRegisters::default());
        let quorum = CrashQuorum::open(
            leader.task().clone(),
            generation,
            leader.shared().mm().id().raw(),
        );
        assert!(matches!(
            quorum.poll(),
            CrashQuorumPoll::Waiting(tid) if tid == sibling_tid
        ));

        let mut regs = carrick_hal::Aarch64CoreRegisters::default();
        regs.gprs[19] = 0x5255_4e4e_494e_4731;
        sibling.thread().publish_crash_registers(generation, regs);

        kernel.exit_thread(&sibling, None).expect("retire sibling");
        match quorum.poll() {
            CrashQuorumPoll::Complete(registers) => {
                assert_eq!(registers.len(), 2);
                let sibling_file = registers.iter().find(|r| r.tid == sibling_tid).unwrap();
                assert_eq!(sibling_file.registers.gprs[19], 0x5255_4e4e_494e_4731);
            }
            other => panic!("expected Complete with 2 register files, got {other:?}"),
        }
    }

    #[test]
    fn crash_quorum_collects_parked_registers_from_blocked_sibling_without_vote() {
        let (kernel, leader) = bootstrap(19_460);
        let sibling = clone_sibling(&kernel, &leader, 19_461);
        let sibling_tid = sibling.thread().key().tid;

        let mut regs = carrick_hal::Aarch64CoreRegisters::default();
        regs.gprs[19] = 0x424c_4f43_4b45_4431;
        sibling.thread().stash_parked_registers(regs);

        let authority = CrashCaptureAuthority::default();
        let generation = authority.issue().expect("capture generation");
        leader
            .thread()
            .publish_crash_registers(generation, carrick_hal::Aarch64CoreRegisters::default());
        let quorum = CrashQuorum::open(
            leader.task().clone(),
            generation,
            leader.shared().mm().id().raw(),
        );
        match quorum.poll() {
            CrashQuorumPoll::Complete(registers) => {
                assert_eq!(registers.len(), 2);
                let sibling_file = registers.iter().find(|r| r.tid == sibling_tid).unwrap();
                assert_eq!(sibling_file.registers.gprs[19], 0x424c_4f43_4b45_4431);
            }
            other => panic!("expected Complete with 2 register files, got {other:?}"),
        }
    }

    #[test]
    fn crash_quorum_waits_for_runnable_sibling_without_vote_or_parked_registers() {
        let (kernel, leader) = bootstrap(19_470);
        let sibling = clone_sibling(&kernel, &leader, 19_471);
        let sibling_tid = sibling.thread().key().tid;
        let _participation = sibling
            .thread()
            .enter_crash_safe_point_participation()
            .expect("crash safe-point participation");

        let authority = CrashCaptureAuthority::default();
        let generation = authority.issue().expect("capture generation");
        leader
            .thread()
            .publish_crash_registers(generation, carrick_hal::Aarch64CoreRegisters::default());
        let quorum = CrashQuorum::open(
            leader.task().clone(),
            generation,
            leader.shared().mm().id().raw(),
        );
        assert!(matches!(
            quorum.poll(),
            CrashQuorumPoll::Waiting(tid) if tid == sibling_tid
        ));
    }

    /// Tests that install a synthetic EL1 region (process-global state:
    /// `carrick_el1_abi::record_el1_region_host_ptr`, `el1_zone::enable`)
    /// run serially and restore it on drop, per the repo's `serial_host`
    /// convention for host-global mutation.
    mod serial_host {
        use super::*;

        static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

        /// A private synthetic EL1 region for one test, with the in-guest
        /// scheduler hatched on: a zeroed buffer is a valid empty zone,
        /// exactly as the host maps a fresh one.
        struct Region {
            _lock: parking_lot::MutexGuard<'static, ()>,
            _buffer: Box<carrick_test_support::TestEl1Region>,
        }

        impl Region {
            fn new() -> Self {
                let lock = TEST_LOCK.lock();
                let buffer = carrick_test_support::TestEl1Region::zeroed();
                carrick_el1_abi::record_el1_region_host_ptr(buffer.as_ptr() as usize);
                crate::el1_zone::enable(true);
                Self {
                    _lock: lock,
                    _buffer: buffer,
                }
            }
        }

        impl Drop for Region {
            fn drop(&mut self) {
                crate::el1_zone::enable(false);
                carrick_el1_abi::record_el1_region_host_ptr(0);
            }
        }

        /// Park `key` in `zone` exactly as EL1 does for a private futex
        /// wait: allocate a record, write its save area, queue it on one
        /// bucket, and publish the park (`Claim::Parked`). No host code
        /// runs for this thread afterward -- it is data in the zone until
        /// something wakes or claims it.
        fn park_thread(
            zone: &carrick_el1_abi::ZoneTables,
            mm: u64,
            key: crate::kernel::ThreadKey,
            ctx: carrick_el1_abi::ThreadCtx,
        ) -> carrick_el1_abi::RecordId {
            let identity = carrick_el1_abi::ThreadIdentity {
                tid: u64::try_from(key.tid.raw()).expect("non-negative tid"),
                serial: key.serial.raw(),
                mm,
                file_table: 0,
                generation: 0,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            };
            let record = zone.alloc_record(identity).expect("record");
            // SAFETY: freshly allocated by this call; nothing else may touch
            // it before `publish_park` makes it claimable.
            unsafe {
                *zone.record(record).ctx_mut() = ctx;
            }
            const UADDR: u64 = 0x1000;
            let guard = zone
                .lock(
                    carrick_el1_abi::ZoneTables::bucket_of(mm, UADDR),
                    &crate::el1_zone::HostLockWait,
                )
                .expect("bucket lock");
            let seq = zone.next_seq(record);
            zone.enqueue(&guard, record, seq, mm, UADDR, u32::MAX, 0)
                .expect("enqueue");
            zone.publish_park(record, seq);
            record
        }

        /// The red-first case this module exists to close: a thread the
        /// in-guest scheduler holds parked (`Claim::Parked`) never enters the
        /// host's publish/withdraw safe-point protocol at all -- no host
        /// executor loop is "it" to answer the crash-capture quorum. Before
        /// `CrashQuorum::el1_parked_registers` existed, such a thread's
        /// `NT_PRSTATUS` note went silently missing from the core (dropped
        /// as a non-participant with no stashed registers), exactly the
        /// open obligation this closes: "Parked-EL1-thread registers are
        /// absent from crash snapshots." Now the quorum reads EL1's own save
        /// area and attributes it to the exact thread.
        #[test]
        fn crash_quorum_reads_the_authoritative_el1_save_area_for_a_parked_sibling() {
            let _region = Region::new();
            let (kernel, leader) = bootstrap(19_480);
            let sibling = clone_sibling(&kernel, &leader, 19_481);
            let sibling_key = sibling.thread().key();
            let sibling_tid = sibling_key.tid;
            let mm = leader.shared().mm().id().raw();

            // EL1 switched the sibling off its vCPU into the in-guest
            // scheduler (a private futex wait): deliberately no
            // `enter_crash_safe_point_participation` for it, since no host
            // loop represents it right now.
            let zone = carrick_el1_abi::zone_tables().expect("synthetic region installed");
            let mut ctx = carrick_el1_abi::ThreadCtx::ZERO;
            ctx.x[0] = 0x5a5a_5a5a_5a5a_5a5a;
            ctx.pc = 0x4000_0000;
            ctx.pstate = 0x6000_0000;
            park_thread(zone, mm, sibling_key, ctx);

            let authority = CrashCaptureAuthority::default();
            let generation = authority.issue().expect("capture generation");
            leader
                .thread()
                .publish_crash_registers(generation, carrick_hal::Aarch64CoreRegisters::default());
            let quorum = CrashQuorum::open(leader.task().clone(), generation, mm);

            match quorum.poll() {
                CrashQuorumPoll::Complete(registers) => {
                    assert_eq!(
                        registers.len(),
                        2,
                        "the parked sibling's note must not go missing"
                    );
                    let sibling_file = registers.iter().find(|r| r.tid == sibling_tid).unwrap();
                    assert_eq!(sibling_file.registers.gprs[0], 0x5a5a_5a5a_5a5a_5a5a);
                    assert_eq!(sibling_file.registers.resume_pc, 0x4000_0000);
                    assert_eq!(sibling_file.registers.resume_pstate, 0x6000_0000);
                }
                other => {
                    panic!("expected Complete with the sibling's EL1 registers, got {other:?}")
                }
            }
        }

        /// A negative control on the same fixture: with no synthetic park
        /// (the sibling is neither a safe-point participant nor EL1-parked),
        /// the quorum still completes without it -- the pre-existing,
        /// reported fidelity gap this fix narrows, not a hang.
        #[test]
        fn crash_quorum_still_completes_without_el1_registers_when_truly_absent() {
            let _region = Region::new();
            let (kernel, leader) = bootstrap(19_482);
            let sibling = clone_sibling(&kernel, &leader, 19_483);
            let _ = sibling.thread().key();

            let authority = CrashCaptureAuthority::default();
            let generation = authority.issue().expect("capture generation");
            leader
                .thread()
                .publish_crash_registers(generation, carrick_hal::Aarch64CoreRegisters::default());
            let quorum = CrashQuorum::open(
                leader.task().clone(),
                generation,
                leader.shared().mm().id().raw(),
            );
            match quorum.poll() {
                CrashQuorumPoll::Complete(registers) => {
                    assert_eq!(registers.len(), 1, "only the leader published");
                }
                other => panic!("expected Complete, got {other:?}"),
            }
        }
    }
}
