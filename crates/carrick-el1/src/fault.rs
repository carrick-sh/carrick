//! In-guest EL1 fault handling and dispatch.

use carrick_el1_abi::{
    Action, Counters, CurrentTask, EL1_FRAME_GRANT_TARGET_SIZE, FRAME_GRANT_SUCCESS,
    FrameGrantMailbox, FrameGrantReady, FrameGrantRequest, TrapFrame,
};
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_FRAME_GRANT_GENERATION: AtomicU64 = AtomicU64::new(1);
static LAST_FRAME_GRANT_PUBLICATION_ERROR: AtomicU64 = AtomicU64::new(0);

#[cfg(any(target_os = "none", test))]
fn publication_error_code(error: carrick_mmu_core::aarch64::GuestLeafPublicationError) -> u64 {
    use carrick_mmu_core::aarch64::GuestLeafPublicationError;

    match error {
        GuestLeafPublicationError::BadRange => 1,
        GuestLeafPublicationError::TableOutsidePrimary => 2,
        GuestLeafPublicationError::MissingTable => 3,
        GuestLeafPublicationError::InvalidLeafShape => 4,
        GuestLeafPublicationError::AlreadyValid => 5,
        GuestLeafPublicationError::RetiredLeaf => 6,
        GuestLeafPublicationError::Manager(
            carrick_mmu_core::aarch64::PageTableError::OutOfTables,
        ) => 7,
        GuestLeafPublicationError::Manager(
            carrick_mmu_core::aarch64::PageTableError::BadAddress,
        ) => 8,
        GuestLeafPublicationError::Manager(
            carrick_mmu_core::aarch64::PageTableError::MissingArenaSource,
        ) => 9,
        GuestLeafPublicationError::Manager(
            carrick_mmu_core::aarch64::PageTableError::ConflictingArenaSource,
        ) => 10,
        GuestLeafPublicationError::Manager(
            carrick_mmu_core::aarch64::PageTableError::UnresolvedArena(_),
        ) => 11,
        GuestLeafPublicationError::Manager(
            carrick_mmu_core::aarch64::PageTableError::GicWindowOutput,
        ) => 12,
        GuestLeafPublicationError::Manager(
            carrick_mmu_core::aarch64::PageTableError::MetadataAllocation,
        ) => 13,
        GuestLeafPublicationError::RollbackFailed => 14,
    }
}

/// Return the last guest leaf-publication refusal for the EL1 panic bridge.
/// Zero means the panic did not follow that publication boundary.
pub fn panic_publication_detail() -> u64 {
    LAST_FRAME_GRANT_PUBLICATION_ERROR.load(Ordering::Relaxed)
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
            Ok(carrick_mmu_core::aarch64::GuestCowResolution::AlreadyWritable)
            | Ok(carrick_mmu_core::aarch64::GuestCowResolution::Upgraded) => {
                let mut cpu = crate::sched::HardwareCpu;
                crate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
                true
            }
            Err(_) => false,
        }
    }
}

/// The exact-MM page-table operation needed to consume one authenticated
/// frame grant. Production publishes the leaves and broadcasts one ASID
/// invalidation; host tests record the same boundary without touching tables.
pub trait FrameGrantLeafPublisher {
    fn publish_and_invalidate(&mut self, ttbr0: u64, ready: FrameGrantReady) -> bool;
}

#[cfg(target_os = "none")]
struct HardwareFrameGrantLeafPublisher;

#[cfg(target_os = "none")]
#[derive(Debug)]
struct GuestPrimaryArenaResolver {
    physical_base: u64,
    host_base: usize,
    byte_len: usize,
}

#[cfg(target_os = "none")]
unsafe impl carrick_mmu_core::aarch64::HostArenaResolver for GuestPrimaryArenaResolver {
    fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
        (base == self.physical_base && len <= self.byte_len).then_some(self.host_base as *mut u8)
    }
}

#[cfg(target_os = "none")]
impl FrameGrantLeafPublisher for HardwareFrameGrantLeafPublisher {
    fn publish_and_invalidate(&mut self, ttbr0: u64, ready: FrameGrantReady) -> bool {
        use crate::rust_alloc::sync::Arc;
        use carrick_mmu_core::aarch64::{
            GuestLeafPublication, GuestLeafPublicationError, HostArenaResolver,
            PageTableLayoutConfig, PageTableManager,
        };

        const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
        LAST_FRAME_GRANT_PUBLICATION_ERROR.store(0, Ordering::Relaxed);
        let physical_base = ttbr0 & TTBR_BADDR_MASK;
        let byte_len = carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize;
        let resolver: Arc<dyn HostArenaResolver + Send + Sync> =
            Arc::new(GuestPrimaryArenaResolver {
                physical_base,
                host_base: carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE as usize,
                byte_len,
            });
        let mut manager = match unsafe {
            PageTableManager::new_live(
                physical_base,
                PageTableLayoutConfig::new(
                    carrick_el1_abi::AARCH64_USER_LEAF_CHECK_VA,
                    byte_len,
                    carrick_el1_abi::AARCH64_GIC_WINDOW_BASE,
                    carrick_el1_abi::AARCH64_GIC_WINDOW_SIZE,
                ),
                byte_len,
                resolver,
            )
        } {
            Ok(manager) => manager,
            Err(error) => {
                LAST_FRAME_GRANT_PUBLICATION_ERROR.store(
                    publication_error_code(GuestLeafPublicationError::Manager(error)),
                    Ordering::Relaxed,
                );
                return false;
            }
        };
        let result = manager.publish_live_private_pages_transaction(GuestLeafPublication {
            va: ready.semantic_base,
            ipa: ready.physical_ipa,
            len: ready.len,
            writable: ready.permissions & 2 != 0,
            executable: ready.permissions & 4 != 0,
        });
        if let Err(error) = result {
            LAST_FRAME_GRANT_PUBLICATION_ERROR
                .store(publication_error_code(error), Ordering::Relaxed);
            return false;
        }
        let mut cpu = crate::sched::HardwareCpu;
        crate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
        true
    }
}

/// Dispatch an EL0 data abort at EL1.
///
/// Increments `counters.fault_taken`; at EL1, publishes or consumes an exact
/// authenticated bulk-frame request or resolves in-guest COW faults.
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
            mailbox,
            &mut HardwareFrameGrantLeafPublisher,
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

/// Fault dispatch with explicitly supplied shared regions, leaf publisher, and COW resolver.
/// A refusal or any inability to authenticate/edit the exact MM consumes the
/// response and forwards once through the existing host fault path.
pub fn dispatch_fault_with_regions<P: FrameGrantLeafPublisher, C: CowResolver>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    mailbox: &FrameGrantMailbox,
    publisher: &mut P,
    cow_resolver: &mut C,
) -> Action {
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

    if let Some(response) = mailbox.response_for_fault(mm_key, frame.far, access) {
        if response.status != FRAME_GRANT_SUCCESS {
            let Some(response) = mailbox.claim_response_for_fault(mm_key, frame.far, access) else {
                return Action::Forward;
            };
            assert!(mailbox.finish_response(mm_key, response.request.request_generation));
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
        let Some(response) = mailbox.claim_response_for_fault(mm_key, frame.far, access) else {
            return Action::Forward;
        };
        let ready = response
            .ready
            .expect("successful frame-grant response carries Ready authority");
        assert!(
            publisher.publish_and_invalidate(grant.ttbr0, ready),
            "authenticated frame-grant leaf publication failed after editor admission"
        );
        assert!(mailbox.finish_response(mm_key, response.request.request_generation));
        return Action::Served;
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

    #[test]
    fn guest_leaf_publication_errors_have_stable_panic_detail_codes() {
        use carrick_mmu_core::aarch64::GuestLeafPublicationError;

        assert_eq!(
            publication_error_code(GuestLeafPublicationError::BadRange),
            1
        );
        assert_eq!(
            publication_error_code(GuestLeafPublicationError::TableOutsidePrimary),
            2
        );
        assert_eq!(
            publication_error_code(GuestLeafPublicationError::MissingTable),
            3
        );
        assert_eq!(
            publication_error_code(GuestLeafPublicationError::InvalidLeafShape),
            4
        );
        assert_eq!(
            publication_error_code(GuestLeafPublicationError::AlreadyValid),
            5
        );
        assert_eq!(
            publication_error_code(GuestLeafPublicationError::RetiredLeaf),
            6
        );
        assert_eq!(
            publication_error_code(GuestLeafPublicationError::Manager(
                carrick_mmu_core::aarch64::PageTableError::OutOfTables
            )),
            7
        );
        assert_eq!(
            publication_error_code(GuestLeafPublicationError::Manager(
                carrick_mmu_core::aarch64::PageTableError::UnresolvedArena(0x1234)
            )),
            11
        );
        assert_eq!(
            publication_error_code(GuestLeafPublicationError::RollbackFailed),
            14
        );
    }

    #[derive(Default)]
    struct RecordingPublisher {
        calls: Vec<(u64, FrameGrantReady)>,
        succeeds: bool,
    }

    impl FrameGrantLeafPublisher for RecordingPublisher {
        fn publish_and_invalidate(&mut self, ttbr0: u64, ready: FrameGrantReady) -> bool {
            self.calls.push((ttbr0, ready));
            self.succeeds
        }
    }

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

    #[test]
    fn exact_frame_grant_response_publishes_once_and_serves_the_retry() {
        let mm = 7;
        let ttbr0 = (31_u64 << 48) | 0x8800_0000_0000;
        let fault = 0x4000_2123;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, ttbr0);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut publisher = RecordingPublisher {
            succeeds: true,
            ..RecordingPublisher::default()
        };
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_translation_fault(0, fault);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                &mailbox,
                &mut publisher,
                &mut cow_resolver,
            ),
            Action::Forward
        );
        let request = mailbox.claim_request().expect("one exact host request");
        assert_eq!(request.mm_key, mm);
        assert_eq!(request.fault_va, fault);
        assert_eq!(request.requested_len, EL1_FRAME_GRANT_TARGET_SIZE);
        assert_eq!(request.access, 2);
        assert_ne!(request.request_generation, 0);
        let ready = FrameGrantReady {
            mm_key: mm,
            request_generation: request.request_generation,
            semantic_base: 0x4000_0000,
            physical_ipa: 0x9000_0000,
            len: 0x20_0000,
            permissions: 3,
            frame_id: 41,
            mapping_id: 42,
            owner_generation: 43,
            inventory_revision: 44,
        };
        assert!(mailbox.publish_ready(ready));

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                &mailbox,
                &mut publisher,
                &mut cow_resolver,
            ),
            Action::Served
        );
        assert_eq!(publisher.calls, vec![(ttbr0, ready)]);
        assert!(!mailbox.has_guest_work());
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 2);
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
        let mut publisher = RecordingPublisher::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_translation_fault(0, 0x5000_1000);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                &mailbox,
                &mut publisher,
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
                &mailbox,
                &mut publisher,
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(!mailbox.has_guest_work());
        assert!(publisher.calls.is_empty());
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
        let mut publisher = RecordingPublisher::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_permission_fault(0, 0x5300_1000);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                &mailbox,
                &mut publisher,
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(
            !mailbox.has_guest_work(),
            "a mapped-page permission denial must not request new physical backing"
        );
        assert!(publisher.calls.is_empty());
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn closed_mm_gate_preserves_ready_response_for_a_host_boundary_retry() {
        let mm = 81;
        let ttbr0 = (34_u64 << 48) | 0x8b00_0000_0000;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, ttbr0);
        let index = spaces.find(mm).unwrap();
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut publisher = RecordingPublisher {
            succeeds: true,
            ..RecordingPublisher::default()
        };
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_translation_fault(0, 0x5200_1000);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                &mailbox,
                &mut publisher,
                &mut cow_resolver,
            ),
            Action::Forward
        );
        let request = mailbox.claim_request().unwrap();
        let ready = FrameGrantReady {
            mm_key: mm,
            request_generation: request.request_generation,
            semantic_base: 0x5200_0000,
            physical_ipa: 0x9200_0000,
            len: 0x20_0000,
            permissions: 3,
            frame_id: 51,
            mapping_id: 52,
            owner_generation: 53,
            inventory_revision: 54,
        };
        assert!(mailbox.publish_ready(ready));
        spaces.close(index);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                &mailbox,
                &mut publisher,
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(mailbox.has_guest_work());
        assert!(publisher.calls.is_empty());

        spaces.open(index);
        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                &mailbox,
                &mut publisher,
                &mut cow_resolver,
            ),
            Action::Served
        );
        assert_eq!(publisher.calls, vec![(ttbr0, ready)]);
        assert!(!mailbox.has_guest_work());
    }

    #[test]
    fn non_translation_or_permission_fault_never_requests_a_grant() {
        let task = CurrentTask::new();
        task.zone_mm.store(9, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(9, (33_u64 << 48) | 0x8a00_0000_0000);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut publisher = RecordingPublisher::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_translation_fault(0, 0x6000_1000);
        frame.esr = (0x24 << 26) | 0x21;

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                &mailbox,
                &mut publisher,
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(!mailbox.has_guest_work());
        assert!(publisher.calls.is_empty());
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
        let mut publisher = RecordingPublisher::default();
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
                &mailbox,
                &mut publisher,
                &mut cow_resolver,
            ),
            Action::Served
        );
        assert_eq!(cow_resolver.calls, vec![(ttbr0, fault)]);
        assert!(!mailbox.has_guest_work());
        assert!(publisher.calls.is_empty());
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
        let mut publisher = RecordingPublisher::default();
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
                &mailbox,
                &mut publisher,
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert_eq!(cow_resolver.calls, vec![(ttbr0, fault)]);
        assert!(!mailbox.has_guest_work());
        assert!(publisher.calls.is_empty());
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
