//! In-guest EL1 fault handling and dispatch.

use carrick_el1_abi::{
    Action, Counters, CurrentTask, EL1_FRAME_GRANT_TARGET_SIZE, FrameGrantMailbox,
    FrameGrantMailboxes, FrameGrantRequest, TrapFrame,
};
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_FRAME_GRANT_GENERATION: AtomicU64 = AtomicU64::new(1);
/// The host now owns frame-grant publication; EL1 has no publication error.
pub fn panic_publication_detail() -> u64 {
    0
}

fn next_frame_grant_generation() -> u64 {
    loop {
        let generation = NEXT_FRAME_GRANT_GENERATION.fetch_add(1, Ordering::Relaxed);
        if generation != 0 {
            return generation;
        }
    }
}

/// Decode an EL0 translation fault that can be satisfied by publishing fresh
/// anonymous backing. Permission faults name an already-mapped page and must
/// follow the protection/COW path; requesting another frame for them adds a
/// host round trip and can never authorize the denied access.
fn frame_grant_access(esr: u64) -> Option<u64> {
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    if !matches!(ec, 0x24 | 0x25) || !(0x04..=0x07).contains(&dfsc) {
        return None;
    }
    Some(if esr & (1 << 6) != 0 { 2 } else { 1 })
}

/// Decode an EL0 write permission fault that can be satisfied by in-guest COW resolution.
pub fn is_write_permission_fault(esr: u64) -> bool {
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    let is_write = (esr & (1 << 6)) != 0;
    matches!(ec, 0x24 | 0x25) && is_write && matches!(dfsc, 0x0c..=0x0f)
}

/// Operation needed to resolve a COW fault in EL1.
pub trait CowResolver {
    fn resolve_cow(&mut self, ttbr0: u64, far: u64) -> bool;
}

#[derive(Default)]
pub struct NoopCowResolver;

impl CowResolver for NoopCowResolver {
    fn resolve_cow(&mut self, _ttbr0: u64, _far: u64) -> bool {
        false
    }
}

#[cfg(target_os = "none")]
pub struct HardwareCowResolver;

#[cfg(target_os = "none")]
impl CowResolver for HardwareCowResolver {
    fn resolve_cow(&mut self, ttbr0: u64, far: u64) -> bool {
        const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
        let physical_base = ttbr0 & TTBR_BADDR_MASK;
        let words =
            carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE as *mut core::sync::atomic::AtomicU64;
        let byte_len = carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize;
        let aligned_va = far & !4095;
        let outcome = unsafe {
            carrick_mmu_core::aarch64::resolve_existing_el1_cow_page(
                words,
                physical_base,
                byte_len,
                aligned_va,
            )
        };
        match outcome {
            Ok(carrick_mmu_core::aarch64::GuestCowResolution::AlreadyWritable) => {
                let mut cpu = crate::sched::HardwareCpu;
                crate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
                true
            }
            Err(_) => false,
        }
    }
}

/// Dispatch an EL0 data abort at EL1.
///
/// Increments `counters.fault_taken`; at EL1, requests host-published bulk
/// frames, consumes refusals, or resolves in-guest COW faults.
/// Host builds retain the forward-only path.
pub fn dispatch_fault(frame: &mut TrapFrame, counters: &Counters) -> Action {
    #[cfg(target_os = "none")]
    {
        let current_tasks = unsafe {
            &*(carrick_el1_abi::EL1_CURRENT_TASKS_BASE
                as *const [CurrentTask; carrick_el1_abi::EL1_STACK_SLOTS as usize])
        };
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let Some(mailbox) =
            carrick_el1_abi::frame_grant_mailbox_guest_for_slot(frame.slot as usize)
        else {
            counters.fault_taken.fetch_add(1, Ordering::Relaxed);
            return Action::Forward;
        };
        dispatch_fault_with_regions(
            frame,
            counters,
            current_tasks,
            &zone.spaces,
            GrantMailboxes {
                own: mailbox,
                peers: Some(carrick_el1_abi::frame_grant_mailboxes_guest()),
            },
            &mut HardwareCowResolver,
        )
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = frame;
        counters.fault_taken.fetch_add(1, Ordering::Relaxed);
        Action::Forward
    }
}

/// The faulting vCPU's frame-grant mailbox, plus every vCPU's mailbox so a
/// retry migrated by the EL1 scheduler can consume a refusal left elsewhere.
/// Successful grants leave no guest-owned response.
#[derive(Clone, Copy)]
pub struct GrantMailboxes<'a> {
    pub own: &'a FrameGrantMailbox,
    pub peers: Option<&'a FrameGrantMailboxes>,
}

impl<'a> GrantMailboxes<'a> {
    pub fn own(own: &'a FrameGrantMailbox) -> Self {
        Self { own, peers: None }
    }
}

/// Fault dispatch with explicitly supplied shared regions and COW resolver.
/// A refusal is consumed and forwarded once through the host fault path.
/// Successful publication and first-touch commit both happen on the host.
pub fn dispatch_fault_with_regions<C: CowResolver>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    mailboxes: GrantMailboxes<'_>,
    cow_resolver: &mut C,
) -> Action {
    let GrantMailboxes {
        own: mailbox,
        peers,
    } = mailboxes;
    counters.fault_taken.fetch_add(1, Ordering::Relaxed);
    if is_write_permission_fault(frame.esr) {
        let Some(task) = current_tasks.get(frame.slot as usize) else {
            return Action::Forward;
        };
        let mm_key = task.zone_mm.load(Ordering::Acquire);
        if mm_key == 0 {
            return Action::Forward;
        }
        let Some(index) = spaces.find(mm_key) else {
            return Action::Forward;
        };
        let Some(grant) = spaces.grant(index, mm_key) else {
            return Action::Forward;
        };
        let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
            return Action::Forward;
        };
        let Some(_editor) = spaces.try_begin_edit(index, mm_key, owner) else {
            return Action::Forward;
        };
        if cow_resolver.resolve_cow(grant.ttbr0, frame.far) {
            return Action::Served;
        }
        return Action::Forward;
    }

    let Some(access) = frame_grant_access(frame.esr) else {
        return Action::Forward;
    };
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return Action::Forward;
    };
    let mm_key = task.zone_mm.load(Ordering::Acquire);
    if mm_key == 0 {
        return Action::Forward;
    }

    let found = mailbox
        .response_for_fault(mm_key, frame.far, access)
        .map(|response| (mailbox, response))
        .or_else(|| {
            peers?.iter().find_map(|peer| {
                peer.response_covering_fault(mm_key, frame.far, access)
                    .map(|response| (peer, response))
            })
        });
    if let Some((source, response)) = found {
        let generation = response.request.request_generation;
        // Only refusals cross back to EL1. Successful grants have already
        // published and released their slot on the host, even after migration.
        if source.claim_response(mm_key, generation).is_some() {
            assert!(source.finish_response(mm_key, generation));
        }
        return Action::Forward;
    }

    let _ = mailbox.try_publish_request(FrameGrantRequest {
        mm_key,
        request_generation: next_frame_grant_generation(),
        fault_va: frame.far,
        requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
        access,
    });
    Action::Forward
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::CurrentTask;
    use carrick_el1_abi::{
        EL1_FRAME_GRANT_TARGET_SIZE, FRAME_GRANT_ERR_DENIED, FrameGrantMailbox, FrameGrantReady,
    };
    use carrick_sched_core::AddressSpaces;

    fn write_translation_fault(slot: u64, address: u64) -> TrapFrame {
        TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x07,
            far: address,
            slot,
            ..TrapFrame::default()
        }
    }

    fn write_permission_fault(slot: u64, address: u64) -> TrapFrame {
        TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x0f,
            far: address,
            slot,
            ..TrapFrame::default()
        }
    }

    fn published_space(mm: u64, ttbr0: u64) -> AddressSpaces {
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(mm, ttbr0, ttbr0).unwrap();
        spaces.open(index);
        spaces
    }

    #[derive(Default)]
    struct RecordingCowResolver {
        succeeds: bool,
        calls: Vec<(u64, u64)>,
    }

    impl CowResolver for RecordingCowResolver {
        fn resolve_cow(&mut self, ttbr0: u64, far: u64) -> bool {
            self.calls.push((ttbr0, far));
            self.succeeds
        }
    }

    /// Two slots can fault before either host boundary runs. Publication is
    /// scoped to the MM extent, not the slot that happened to request it.
    #[test]
    fn concurrent_and_migrated_faults_share_one_host_publication() {
        use core::cell::Cell;
        for pages in [1, 2, 512] {
            let mm = 9;
            let tasks = [CurrentTask::new(), CurrentTask::new()];
            for task in &tasks {
                task.zone_mm.store(mm, Ordering::Release);
            }
            let spaces = published_space(mm, 0x8800_0000);
            let boxes = FrameGrantMailboxes::new();
            let counters = Counters::default();
            let origin = boxes.slot(0).unwrap();
            let peer = boxes.slot(1).unwrap();
            let mut cow = NoopCowResolver;
            let base = 0x4000_0000;
            let mut first = write_translation_fault(0, base);
            let mut second = write_translation_fault(1, base + (pages - 1) * 4096);
            for (frame, own) in [(&mut first, origin), (&mut second, peer)] {
                assert_eq!(
                    dispatch_fault_with_regions(
                        frame,
                        &counters,
                        &tasks,
                        &spaces,
                        GrantMailboxes {
                            own,
                            peers: Some(&boxes)
                        },
                        &mut cow,
                    ),
                    Action::Forward
                );
            }
            let request = origin.claim_request().unwrap();
            let ready = FrameGrantReady {
                mm_key: mm,
                request_generation: request.request_generation,
                semantic_base: base,
                physical_ipa: 0x9000_0000,
                len: pages * 4096,
                permissions: 3,
                frame_id: 1,
                mapping_id: 2,
                owner_generation: 3,
                inventory_revision: 4,
            };
            let published = Cell::new(false);
            let armed = Cell::new(true);
            let publications = Cell::new(0);
            assert_eq!(
                origin.complete_grant(
                    ready,
                    |grant| {
                        assert!(armed.get());
                        assert_eq!(grant.len, pages * 4096);
                        // The second fault cannot consume unpublished frame authority.
                        assert!(
                            origin
                                .claim_response(mm, request.request_generation)
                                .is_none()
                        );
                        publications.set(publications.get() + 1);
                        published.set(true);
                        Ok::<_, ()>(true)
                    },
                    || {
                        assert!(published.get());
                        armed.set(false);
                    }
                ),
                Ok(true)
            );
            assert!(!armed.get());
            assert!(!origin.has_guest_work());
            // Slot 1's queued fault reaches the host after slot 0 committed.
            // The live-leaf path resolves it and cancels its unused request.
            assert!(published.get(), "stale fault must retry, not signal");
            assert!(peer.cancel_request_for_fault(mm, second.far, 2));
            // An already queued retry may migrate to the original slot. EL1
            // forwards; it never republishes stale frame metadata on that slot.
            second.slot = 0;
            assert_eq!(
                dispatch_fault_with_regions(
                    &mut second,
                    &counters,
                    &tasks,
                    &spaces,
                    GrantMailboxes {
                        own: origin,
                        peers: Some(&boxes)
                    },
                    &mut cow,
                ),
                Action::Forward
            );
            assert!(published.get());
            assert!(origin.cancel_request_for_fault(mm, second.far, 2));
            assert_eq!(publications.get(), 1, "one bulk publication for the extent");
            assert!(!peer.has_guest_work());
        }
    }

    #[test]
    fn missing_guest_table_is_handled_before_commit_without_guest_handback() {
        use core::cell::Cell;
        let task = CurrentTask::new();
        task.zone_mm.store(7, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(7, 0x8800_0000);
        let mailbox = FrameGrantMailbox::new();
        let mut frame = write_translation_fault(0, 0x4000_1000);
        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &Counters::default(),
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut NoopCowResolver,
            ),
            Action::Forward
        );
        let request = mailbox.claim_request().unwrap();
        let tables = Cell::new(false);
        let leaves = Cell::new(false);
        assert_eq!(
            mailbox.complete_grant(
                FrameGrantReady {
                    mm_key: 7,
                    request_generation: request.request_generation,
                    semantic_base: 0x4000_0000,
                    physical_ipa: 0x9000_0000,
                    len: EL1_FRAME_GRANT_TARGET_SIZE,
                    permissions: 3,
                    frame_id: 1,
                    mapping_id: 2,
                    owner_generation: 3,
                    inventory_revision: 4,
                },
                |_| {
                    // This used to require GUEST_FAILED and another host exit. The
                    // host publisher allocates the missing table in this transaction.
                    tables.set(true);
                    leaves.set(true);
                    Ok::<_, ()>(true)
                },
                || {
                    assert!(tables.get() && leaves.get());
                }
            ),
            Ok(true)
        );
        assert!(!mailbox.has_guest_work());
        assert!(
            mailbox
                .claim_response(7, request.request_generation)
                .is_none()
        );
    }

    #[test]
    fn refused_frame_grant_falls_back_without_republishing_in_the_same_dispatch() {
        let mm = 8;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, (32_u64 << 48) | 0x8900_0000_0000);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_translation_fault(0, 0x5000_1000);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        let request = mailbox.claim_request().unwrap();
        assert!(mailbox.publish_refusal(FRAME_GRANT_ERR_DENIED));
        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(!mailbox.has_guest_work());
        assert_ne!(request.request_generation, 0);
    }

    #[test]
    fn permission_fault_never_requests_a_first_touch_frame_grant() {
        let mm = 82;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, (35_u64 << 48) | 0x8c00_0000_0000);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_permission_fault(0, 0x5300_1000);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(
            !mailbox.has_guest_work(),
            "a mapped-page permission denial must not request new physical backing"
        );
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn non_translation_or_permission_fault_never_requests_a_grant() {
        let task = CurrentTask::new();
        task.zone_mm.store(9, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(9, (33_u64 << 48) | 0x8a00_0000_0000);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_translation_fault(0, 0x6000_1000);
        frame.esr = (0x24 << 26) | 0x21;

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(!mailbox.has_guest_work());
    }

    #[test]
    fn cow_write_permission_fault_serves_in_guest_when_resolved() {
        let mm = 90;
        let ttbr0 = (36_u64 << 48) | 0x8d00_0000_0000;
        let fault = 0x4000_3000;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, ttbr0);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = RecordingCowResolver {
            succeeds: true,
            ..RecordingCowResolver::default()
        };
        let mut frame = write_permission_fault(0, fault);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Served
        );
        assert_eq!(cow_resolver.calls, vec![(ttbr0, fault)]);
        assert!(!mailbox.has_guest_work());
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cow_write_permission_fault_forwards_when_not_authorized() {
        let mm = 91;
        let ttbr0 = (37_u64 << 48) | 0x8e00_0000_0000;
        let fault = 0x4000_4000;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, ttbr0);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = RecordingCowResolver {
            succeeds: false,
            ..RecordingCowResolver::default()
        };
        let mut frame = write_permission_fault(0, fault);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert_eq!(cow_resolver.calls, vec![(ttbr0, fault)]);
        assert!(!mailbox.has_guest_work());
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_dispatch_fault_increments_counter_and_forwards() {
        let mut frame = TrapFrame {
            esr: (0xFFFF_0000_u64 << 32) | (0x24 << 26) | (1 << 25) | 0x47,
            far: 0x1000_2000,
            x: {
                let mut x = [42; 31];
                x[8] = 172; // valid syscall nr (SYS_getpid) as canary
                x
            },
            ..TrapFrame::default()
        };
        let counters = Counters::default();
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);

        let action = dispatch_fault(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
        // Ensure arbitrary x8 was not dispatched as a syscall and syscall counters were not touched
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[42].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[42].load(Ordering::Relaxed), 0);
    }
}
