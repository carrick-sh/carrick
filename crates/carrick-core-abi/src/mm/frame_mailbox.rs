//! Exact frame supply requests and single-flight completion protocol.
use super::EL1_FRAME_GRANT_TARGET_SIZE;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const FRAME_GRANT_MAILBOX_IDLE: u32 = 0;
pub const FRAME_GRANT_MAILBOX_GUEST_WRITING: u32 = 1;
pub const FRAME_GRANT_MAILBOX_REQUESTED: u32 = 2;
pub const FRAME_GRANT_MAILBOX_HOST_WORKING: u32 = 3;
pub const FRAME_GRANT_MAILBOX_RESPONSE: u32 = 4;
pub const FRAME_GRANT_MAILBOX_GUEST_CONSUMING: u32 = 5;
/// Reserved ABI value; host-owned publication has no guest hand-back state.
pub const FRAME_GRANT_MAILBOX_GUEST_FAILED: u32 = 6;

pub const FRAME_GRANT_SUCCESS: u64 = 0;
pub const FRAME_GRANT_ERR_DENIED: u64 = 1;
pub const FRAME_GRANT_ERR_INVALID: u64 = 2;
pub const FRAME_GRANT_ERR_STALE: u64 = 3;

/// Included in the image ABI fingerprint: a host-published grant must never
/// be paired with an EL1 image that still owns successful leaf publication.
pub const FRAME_GRANT_PROTOCOL_VERSION: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameGrantRequest {
    /// Exact zone/MM key selected by the loaded executor.
    pub mm_key: u64,
    /// Nonzero carrier-wide request incarnation chosen by EL1.
    pub request_generation: u64,
    /// The semantic address whose recoverable data abort created the request.
    pub fault_va: u64,
    /// Maximum semantic span the host may return.
    pub requested_len: u64,
    /// Exact access that faulted: one Linux read, write or execute bit. The
    /// host returns authoritative VMA permissions separately.
    pub access: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameGrantReady {
    pub mm_key: u64,
    pub request_generation: u64,
    pub semantic_base: u64,
    pub physical_ipa: u64,
    pub len: u64,
    pub permissions: u64,
    /// Raw kernel frame identity, exported only at this shared ABI boundary.
    pub frame_id: u64,
    /// Raw kernel mapping identity, exported only at this shared ABI boundary.
    pub mapping_id: u64,
    /// Exact global stage-2 owner incarnation authenticated by the host.
    pub owner_generation: u64,
    /// Exact committed inventory revision that contains `mapping_id`.
    pub inventory_revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameGrantResponse {
    pub status: u64,
    pub request: FrameGrantRequest,
}

/// A host fault owns its single-flight request until it publishes a grant or
/// explicitly abandons the request. Dropping the token after an early error
/// returns the mailbox to Idle; a response must never outlive this fault.
pub struct FrameGrantHostClaim<'a> {
    mailbox: &'a FrameGrantMailbox,
    request: FrameGrantRequest,
    active: bool,
}

impl FrameGrantHostClaim<'_> {
    pub const fn request(&self) -> FrameGrantRequest {
        self.request
    }

    /// No grant was published. The same fault proceeds through the live
    /// resident/stale/signal classifier before the guest runs again.
    pub fn decline(mut self) {
        self.release();
    }

    /// A verified grant publication already moved HOST_WORKING to IDLE.
    pub fn finish_completed(mut self) {
        assert_eq!(self.mailbox.load_request(), self.request);
        assert_eq!(
            self.mailbox.state.load(Ordering::Acquire),
            FRAME_GRANT_MAILBOX_IDLE
        );
        self.active = false;
    }

    fn release(&mut self) {
        if !self.active {
            return;
        }
        assert_eq!(self.mailbox.load_request(), self.request);
        assert_eq!(
            self.mailbox.state.compare_exchange(
                FRAME_GRANT_MAILBOX_HOST_WORKING,
                FRAME_GRANT_MAILBOX_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Ok(FRAME_GRANT_MAILBOX_HOST_WORKING),
            "host claim left a response behind",
        );
        self.active = false;
    }
}

impl Drop for FrameGrantHostClaim<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Host-published bulk first-touch protocol.
///
/// A slot transports a request, never ownership of unpublished leaves. EL1
/// alone moves IDLE -> GUEST_WRITING -> REQUESTED, with release publication.
/// The host claims REQUESTED -> HOST_WORKING with acquire/release CAS under
/// the exact MM mutation guard. It authenticates the request and prepares up
/// to 2 MiB of backing. `complete_grant` then publishes all leaves (allocating
/// tables and completing TLB maintenance), commits residency/disarms first
/// touch, and releases HOST_WORKING -> IDLE, in that order, under that guard.
/// No successful Ready is transferred to EL1. Migration and overlapping faults
/// consult the live MM mapping; they never wait for another vCPU to consume a
/// response. The MM guard serializes publication with unmap/protect/replacement.
///
/// An owned host claim releases HOST_WORKING -> IDLE on every declined branch.
/// The host then resolves the same fault against live resident/stale/signal
/// authority before resuming the guest. A legacy unowned refusal still moves
/// HOST_WORKING -> RESPONSE for EL1 to consume, but must not be used by the
/// owned host path. Refusal carries no frame authority.
/// GUEST_FAILED is a reserved ABI value: host publication handles missing table
/// pages directly, so guest hand-back is no longer a reachable transition.
/// Failed publication cannot commit or free the slot; the host must refuse or
/// terminate the operation. Cancellation claims an exact REQUESTED request
/// and releases HOST_WORKING -> IDLE without modifying residency.
///
/// Invariants: committed residency implies published leaves at the commit
/// point; there is no guest-owned planned-but-unpublished interval; mailbox
/// reuse is impossible before host completion; response identity is rechecked
/// after claiming to exclude reuse ABA. A stale fault is retried only after a
/// live access check, never merely because a mailbox is busy. No retry loop or
/// additional host exit is required to publish a successful bulk extent.
/// The response payload fields remain in the ABI layout, but successful grant
/// metadata is host-local and is never a guest publication capability.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct FrameGrantMailbox {
    pub state: AtomicU32,
    status: AtomicU64,
    mm_key: AtomicU64,
    request_generation: AtomicU64,
    fault_va: AtomicU64,
    requested_len: AtomicU64,
    access: AtomicU64,
    semantic_base: AtomicU64,
    physical_ipa: AtomicU64,
    granted_len: AtomicU64,
    permissions: AtomicU64,
    frame_id: AtomicU64,
    mapping_id: AtomicU64,
    owner_generation: AtomicU64,
    inventory_revision: AtomicU64,
}

impl FrameGrantMailbox {
    const PAGE_SIZE: u64 = 4096;
    const PERMISSION_MASK: u64 = 0x7;

    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(FRAME_GRANT_MAILBOX_IDLE),
            status: AtomicU64::new(FRAME_GRANT_ERR_INVALID),
            mm_key: AtomicU64::new(0),
            request_generation: AtomicU64::new(0),
            fault_va: AtomicU64::new(0),
            requested_len: AtomicU64::new(0),
            access: AtomicU64::new(0),
            semantic_base: AtomicU64::new(0),
            physical_ipa: AtomicU64::new(0),
            granted_len: AtomicU64::new(0),
            permissions: AtomicU64::new(0),
            frame_id: AtomicU64::new(0),
            mapping_id: AtomicU64::new(0),
            owner_generation: AtomicU64::new(0),
            inventory_revision: AtomicU64::new(0),
        }
    }

    fn request_is_valid(request: FrameGrantRequest) -> bool {
        request.mm_key != 0
            && request.request_generation != 0
            && request.requested_len != 0
            && request.requested_len <= EL1_FRAME_GRANT_TARGET_SIZE
            && request.requested_len.is_multiple_of(Self::PAGE_SIZE)
            && request.access.is_power_of_two()
            && request.access & !Self::PERMISSION_MASK == 0
    }

    fn load_request(&self) -> FrameGrantRequest {
        FrameGrantRequest {
            mm_key: self.mm_key.load(Ordering::Relaxed),
            request_generation: self.request_generation.load(Ordering::Relaxed),
            fault_va: self.fault_va.load(Ordering::Relaxed),
            requested_len: self.requested_len.load(Ordering::Relaxed),
            access: self.access.load(Ordering::Relaxed),
        }
    }

    fn permissions_allow_access(permissions: u64, access: u64) -> bool {
        match access {
            // Both ISA lowerings make any admitted accessible mapping
            // readable. The client supplies the authoritative write and
            // execute ceiling; this record authenticates that ceiling.
            1 => permissions != 0,
            2 => permissions & 2 != 0,
            4 => permissions & 4 != 0,
            _ => false,
        }
    }

    fn ready_is_valid(request: FrameGrantRequest, ready: FrameGrantReady) -> bool {
        let Some(end) = ready.semantic_base.checked_add(ready.len) else {
            return false;
        };
        ready.mm_key == request.mm_key
            && ready.request_generation == request.request_generation
            && ready.semantic_base.is_multiple_of(Self::PAGE_SIZE)
            && ready.physical_ipa.is_multiple_of(Self::PAGE_SIZE)
            && ready.len != 0
            && ready.len <= request.requested_len
            && ready.len.is_multiple_of(Self::PAGE_SIZE)
            && ready.semantic_base <= request.fault_va
            && request.fault_va < end
            && ready.permissions != 0
            && ready.permissions & !Self::PERMISSION_MASK == 0
            && Self::permissions_allow_access(ready.permissions, request.access)
            && ready.frame_id != 0
            && ready.mapping_id != 0
            && ready.owner_generation != 0
            && ready.inventory_revision != 0
    }

    pub fn try_publish_request(&self, request: FrameGrantRequest) -> bool {
        if !Self::request_is_valid(request)
            || self
                .state
                .compare_exchange(
                    FRAME_GRANT_MAILBOX_IDLE,
                    FRAME_GRANT_MAILBOX_GUEST_WRITING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return false;
        }
        self.status
            .store(FRAME_GRANT_ERR_INVALID, Ordering::Relaxed);
        self.mm_key.store(request.mm_key, Ordering::Relaxed);
        self.request_generation
            .store(request.request_generation, Ordering::Relaxed);
        self.fault_va.store(request.fault_va, Ordering::Relaxed);
        self.requested_len
            .store(request.requested_len, Ordering::Relaxed);
        self.access.store(request.access, Ordering::Relaxed);
        self.semantic_base.store(0, Ordering::Relaxed);
        self.physical_ipa.store(0, Ordering::Relaxed);
        self.granted_len.store(0, Ordering::Relaxed);
        self.permissions.store(0, Ordering::Relaxed);
        self.frame_id.store(0, Ordering::Relaxed);
        self.mapping_id.store(0, Ordering::Relaxed);
        self.owner_generation.store(0, Ordering::Relaxed);
        self.inventory_revision.store(0, Ordering::Relaxed);
        self.state
            .store(FRAME_GRANT_MAILBOX_REQUESTED, Ordering::Release);
        true
    }

    pub fn claim_request(&self) -> Option<FrameGrantRequest> {
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_REQUESTED,
                FRAME_GRANT_MAILBOX_HOST_WORKING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        Some(self.load_request())
    }

    /// Claim only the request produced by this exact forwarded fault.
    ///
    /// The mailbox is carrier-wide, so another vCPU may reach a host boundary
    /// while this request is pending. That boundary must leave the request for
    /// its owner instead of converting ordinary concurrency into a refusal.
    pub fn claim_request_for_fault(
        &self,
        mm_key: u64,
        fault_va: u64,
        access: u64,
    ) -> Option<FrameGrantRequest> {
        let matches = |request: FrameGrantRequest| {
            request.mm_key == mm_key && request.fault_va == fault_va && request.access == access
        };
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_REQUESTED {
            return None;
        }
        let preview = self.load_request();
        if !matches(preview) {
            return None;
        }
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_REQUESTED,
                FRAME_GRANT_MAILBOX_HOST_WORKING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        let claimed = self.load_request();
        if matches(claimed) {
            return Some(claimed);
        }

        // The mailbox completed one request and accepted another between the
        // preview and CAS. We own HOST_WORKING now, so return the new request
        // unchanged to REQUESTED for its exact host boundary.
        self.state
            .store(FRAME_GRANT_MAILBOX_REQUESTED, Ordering::Release);
        None
    }

    /// The owned host path: every branch must either complete a grant or
    /// release the exact claim before another fault uses this worker slot.
    pub fn claim_request_for_fault_owned(
        &self,
        mm_key: u64,
        fault_va: u64,
        access: u64,
    ) -> Option<FrameGrantHostClaim<'_>> {
        let request = self.claim_request_for_fault(mm_key, fault_va, access)?;
        Some(FrameGrantHostClaim {
            mailbox: self,
            request,
            active: true,
        })
    }

    /// Release the exact request when the host resolved the fault through an
    /// existing path and therefore has no frame-grant response for EL1.
    pub fn cancel_request_for_fault(&self, mm_key: u64, fault_va: u64, access: u64) -> bool {
        let matches = |request: FrameGrantRequest| {
            request.mm_key == mm_key
                && (request.fault_va == fault_va
                    || request.fault_va / Self::PAGE_SIZE == fault_va / Self::PAGE_SIZE)
                && (access == 0 || request.access == access)
        };
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_REQUESTED {
            return false;
        }
        let preview = self.load_request();
        if !matches(preview) {
            return false;
        }
        if self
            .state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_REQUESTED,
                FRAME_GRANT_MAILBOX_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        true
    }

    /// Publish the full extent before disarming first touch or releasing this
    /// slot. The caller retains exact-MM mutation authority across both hooks.
    /// A false/error publication leaves HOST_WORKING and never invokes commit.
    pub fn complete_grant<E>(
        &self,
        ready: FrameGrantReady,
        publish: impl FnOnce(FrameGrantReady) -> Result<bool, E>,
        commit: impl FnOnce(),
    ) -> Result<bool, E> {
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_HOST_WORKING
            || !Self::ready_is_valid(self.load_request(), ready)
        {
            return Ok(false);
        }
        if !publish(ready)? {
            return Ok(false);
        }
        commit();
        self.state
            .store(FRAME_GRANT_MAILBOX_IDLE, Ordering::Release);
        Ok(true)
    }

    pub fn publish_refusal(&self, status: u64) -> bool {
        if status == FRAME_GRANT_SUCCESS
            || !matches!(
                status,
                FRAME_GRANT_ERR_DENIED | FRAME_GRANT_ERR_INVALID | FRAME_GRANT_ERR_STALE
            )
            || self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_HOST_WORKING
        {
            return false;
        }
        self.status.store(status, Ordering::Relaxed);
        self.state
            .store(FRAME_GRANT_MAILBOX_RESPONSE, Ordering::Release);
        true
    }

    /// Finish a claimed owner file fault after its descriptor transaction
    /// committed. The faulting page is live, so EL1 will not fault again to
    /// consume a refusal; leaving RESPONSE would strand every later page on
    /// this vCPU's single-flight mailbox.
    pub fn complete_resolved_owner_fault(&self, request: FrameGrantRequest) -> bool {
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_HOST_WORKING
            || self.load_request() != request
        {
            return false;
        }
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_HOST_WORKING,
                FRAME_GRANT_MAILBOX_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn load_response(&self, request: FrameGrantRequest) -> FrameGrantResponse {
        let status = self.status.load(Ordering::Relaxed);
        FrameGrantResponse { status, request }
    }

    /// Observe a refusal bound to this exact fault. A preview is only a hint;
    /// consumers must claim and recheck its identity before releasing it.
    pub fn response_for_fault(
        &self,
        mm_key: u64,
        fault_va: u64,
        access: u64,
    ) -> Option<FrameGrantResponse> {
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_RESPONSE {
            return None;
        }
        let request = self.load_request();
        if request.mm_key != mm_key || request.fault_va != fault_va || request.access != access {
            return None;
        }
        Some(self.load_response(request))
    }

    /// Observe, without consuming, a refusal for the same MM, page and access.
    /// The EL1
    /// scheduler migrates threads between vCPUs, so a retried fault can land
    /// on a vCPU other than the one whose mailbox holds its response; left
    /// unclaimed, that response would also wedge the original mailbox.
    pub fn response_covering_fault(
        &self,
        mm_key: u64,
        fault_va: u64,
        access: u64,
    ) -> Option<FrameGrantResponse> {
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_RESPONSE {
            return None;
        }
        let request = self.load_request();
        if request.mm_key != mm_key {
            return None;
        }
        let response = self.load_response(request);
        let covers = request.fault_va / Self::PAGE_SIZE == fault_va / Self::PAGE_SIZE
            && request.access == access;
        covers.then_some(response)
    }

    pub fn claim_response(
        &self,
        mm_key: u64,
        request_generation: u64,
    ) -> Option<FrameGrantResponse> {
        if self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_RESPONSE
            || self.mm_key.load(Ordering::Relaxed) != mm_key
            || self.request_generation.load(Ordering::Relaxed) != request_generation
        {
            return None;
        }
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_RESPONSE,
                FRAME_GRANT_MAILBOX_GUEST_CONSUMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        let request = self.load_request();
        if request.mm_key != mm_key || request.request_generation != request_generation {
            self.state
                .store(FRAME_GRANT_MAILBOX_RESPONSE, Ordering::Release);
            return None;
        }
        Some(self.load_response(request))
    }

    /// Guest: claim the response only when it belongs to this exact fault.
    /// The generation is read from the immutable published request, then
    /// rechecked by [`Self::claim_response`] during the state transition. This
    /// lets a retried fault find its own response without storing a second
    /// generation shadow in a per-vCPU record.
    pub fn claim_response_for_fault(
        &self,
        mm_key: u64,
        fault_va: u64,
        access: u64,
    ) -> Option<FrameGrantResponse> {
        let response = self.response_for_fault(mm_key, fault_va, access)?;
        self.claim_response(mm_key, response.request.request_generation)
    }

    pub fn finish_response(&self, mm_key: u64, request_generation: u64) -> bool {
        if self.mm_key.load(Ordering::Relaxed) != mm_key
            || self.request_generation.load(Ordering::Relaxed) != request_generation
        {
            return false;
        }
        self.state
            .compare_exchange(
                FRAME_GRANT_MAILBOX_GUEST_CONSUMING,
                FRAME_GRANT_MAILBOX_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn has_guest_work(&self) -> bool {
        self.state.load(Ordering::Acquire) != FRAME_GRANT_MAILBOX_IDLE
    }

    /// Host, at an MM's final teardown or exec replacement: release an
    /// unclaimed request or an unconsumed refusal that belongs to `mm_key`.
    /// No thread of that MM will fault again to claim it, and a busy mailbox
    /// refuses every later request on this vCPU slot, whichever MM it next
    /// runs. The slot passes through HOST_WORKING so the owner is rechecked
    /// after the transition (excluding reuse ABA); another MM's work is
    /// restored unchanged, and a request a host boundary is serving is left
    /// to that boundary. Returns whether this call released the slot.
    pub fn withdraw_mm(&self, mm_key: u64) -> bool {
        for held in [FRAME_GRANT_MAILBOX_REQUESTED, FRAME_GRANT_MAILBOX_RESPONSE] {
            if self.mm_key.load(Ordering::Relaxed) != mm_key
                || self
                    .state
                    .compare_exchange(
                        held,
                        FRAME_GRANT_MAILBOX_HOST_WORKING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
            {
                continue;
            }
            let released = self.mm_key.load(Ordering::Relaxed) == mm_key;
            self.state.store(
                if released {
                    FRAME_GRANT_MAILBOX_IDLE
                } else {
                    held
                },
                Ordering::Release,
            );
            return released;
        }
        false
    }
}

#[cfg(test)]
mod host_claim_tests {
    use super::*;

    #[test]
    fn no_plan_releases_claim_before_next_fault_on_same_worker() {
        let mailbox = FrameGrantMailbox::new();
        let first = FrameGrantRequest {
            mm_key: 94,
            request_generation: 293,
            fault_va: 0x6001_a54bf8,
            requested_len: 4096,
            access: 2,
        };
        assert!(mailbox.try_publish_request(first));
        let claim = mailbox
            .claim_request_for_fault_owned(first.mm_key, first.fault_va, first.access)
            .expect("first grant claim");
        assert_eq!(claim.request(), first);
        claim.decline(); // NoPlan: classify the live fault on the host.
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            FRAME_GRANT_MAILBOX_IDLE
        );

        let second = FrameGrantRequest {
            request_generation: 294,
            fault_va: 0x6001_c5abf8,
            ..first
        };
        assert!(mailbox.try_publish_request(second));
        let claim = mailbox
            .claim_request_for_fault_owned(second.mm_key, second.fault_va, second.access)
            .expect("next live anonymous fault can claim the same worker");
        assert_eq!(claim.request(), second);
        drop(claim); // An early host error also owns cleanup.
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            FRAME_GRANT_MAILBOX_IDLE
        );
    }

    #[test]
    fn cancel_request_for_fault_covers_page_offset() {
        let mailbox = FrameGrantMailbox::new();
        let first = FrameGrantRequest {
            mm_key: 7,
            request_generation: 1,
            fault_va: 0x6048,
            requested_len: 4096,
            access: 2,
        };
        assert!(mailbox.try_publish_request(first));
        assert!(mailbox.cancel_request_for_fault(7, 0x6000, 0));
        assert_eq!(
            mailbox.state.load(Ordering::Acquire),
            FRAME_GRANT_MAILBOX_IDLE
        );
    }
}

impl Default for FrameGrantMailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// One independent frame-grant transaction for every persistent vCPU slot.
///
/// A carrier-wide single-flight mailbox makes an unrelated runnable slot fall
/// back to page-granular host service while the owner of the outstanding
/// response is waiting to run. Slot-local mailboxes preserve the exact request
/// authentication while allowing independent address spaces to make progress.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct FrameGrantMailboxes {
    slots: [FrameGrantMailbox; carrick_sched_core::ZONE_SLOTS],
}

impl FrameGrantMailboxes {
    pub const fn new() -> Self {
        Self {
            slots: [const { FrameGrantMailbox::new() }; carrick_sched_core::ZONE_SLOTS],
        }
    }

    pub fn slot(&self, slot: usize) -> Option<&FrameGrantMailbox> {
        self.slots.get(slot)
    }

    pub fn iter(&self) -> impl Iterator<Item = &FrameGrantMailbox> {
        self.slots.iter()
    }
}

impl Default for FrameGrantMailboxes {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameGrantMailbox {
    pub const STATE_OFFSET: usize = core::mem::offset_of!(Self, state);
    pub const STATUS_OFFSET: usize = core::mem::offset_of!(Self, status);
    pub const MM_KEY_OFFSET: usize = core::mem::offset_of!(Self, mm_key);
    pub const REQUEST_GENERATION_OFFSET: usize = core::mem::offset_of!(Self, request_generation);
    pub const FAULT_VA_OFFSET: usize = core::mem::offset_of!(Self, fault_va);
    pub const REQUESTED_LEN_OFFSET: usize = core::mem::offset_of!(Self, requested_len);
    pub const ACCESS_OFFSET: usize = core::mem::offset_of!(Self, access);
    pub const SEMANTIC_BASE_OFFSET: usize = core::mem::offset_of!(Self, semantic_base);
    pub const PHYSICAL_IPA_OFFSET: usize = core::mem::offset_of!(Self, physical_ipa);
    pub const GRANTED_LEN_OFFSET: usize = core::mem::offset_of!(Self, granted_len);
    pub const PERMISSIONS_OFFSET: usize = core::mem::offset_of!(Self, permissions);
    pub const FRAME_ID_OFFSET: usize = core::mem::offset_of!(Self, frame_id);
    pub const MAPPING_ID_OFFSET: usize = core::mem::offset_of!(Self, mapping_id);
    pub const OWNER_GENERATION_OFFSET: usize = core::mem::offset_of!(Self, owner_generation);
    pub const INVENTORY_REVISION_OFFSET: usize = core::mem::offset_of!(Self, inventory_revision);
}
