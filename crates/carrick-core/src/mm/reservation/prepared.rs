//! Exact prepared-copy claim, rollback and settlement over the original store.
use super::ReservationNode;
use carrick_core_abi::*;
use core::sync::atomic::{AtomicU64, Ordering};

/// A retained view of one authenticated reservation table's permanent nodes.
///
/// # Safety
/// Every returned node must belong to the same live table. Bootstrap mappings
/// and metadata-bank pins must stay retained for `'a`; the allocated high-water
/// mark is monotonic. Nodes containing Live/Copying permits and their linked
/// tails cannot be freed or reused until this owner's settlement is reaped.
pub unsafe trait PreparedCopyNodes<'a>: Copy {
    fn allocated(self) -> u32;
    fn node(self, index: u32) -> &'a ReservationNode;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedCopyError {
    Stale,
}

pub const LIVE: u64 = 1 << 62;
pub const COPYING: u64 = 2 << 62;
pub const SETTLED: u64 = 3 << 62;
pub const GENERATION: u64 = (1 << 62) - 1;

struct RestoreClaim<'a> {
    node: &'a ReservationNode,
    live: u64,
    armed: bool,
}
impl Drop for RestoreClaim<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.node.next_free.store(self.live, Ordering::Release);
        }
    }
}

pub struct ClaimedPreparedCopy<'a, S: PreparedCopyNodes<'a>> {
    node: &'a ReservationNode,
    tail: &'a ReservationNode,
    store: S,
    settled: &'a carrick_sched_core::completion_queue::CompletionQueue,
    permit: PortalPreparedPermit,
    notification: Option<carrick_sched_core::object_wait::ObjectWaitKey>,
    armed: bool,
}
impl<'a, S: PreparedCopyNodes<'a>> ClaimedPreparedCopy<'a, S> {
    pub fn release(mut self) -> bool {
        if self
            .node
            .next_free
            .compare_exchange(
                COPYING | self.permit.generation.get(),
                SETTLED | self.permit.generation.get(),
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return false;
        }
        self.armed = false;
        carrick_core_abi::record_reservation_event(
            carrick_core_abi::PREPARED_SETTLED,
            self.permit.operation.mm.raw(),
            self.permit.operation.incarnation.get(),
            self.permit.index,
            unsafe { (*self.node.data.get()).prepared.tail },
        );
        // Only settled nodes are queued. The guarded doubly-linked live list
        // retains root lifetime until this publication is visible and reaped.
        // SAFETY: the detached primary/tail remain owner-linked until popped.
        unsafe { AtomicU64::from_ptr(core::ptr::addr_of_mut!((*self.tail.data.get()).words[7])) }
            .store(0, Ordering::Relaxed);
        self.settled
            .push(self.permit.index, self.permit.index, |previous, next| {
                let previous = self.store.node(previous);
                let tail = unsafe { (*previous.data.get()).prepared.tail };
                unsafe {
                    AtomicU64::from_ptr(core::ptr::addr_of_mut!(
                        (*self.store.node(tail).data.get()).words[7]
                    ))
                }
                .store(u64::from(next), Ordering::Release);
            });
        true
    }
    pub fn notification(&self) -> Option<carrick_sched_core::object_wait::ObjectWaitKey> {
        self.notification
    }
    pub fn permit(&self) -> PortalPreparedPermit {
        self.permit
    }
}
impl<'a, S: PreparedCopyNodes<'a>> Drop for ClaimedPreparedCopy<'a, S> {
    fn drop(&mut self) {
        if self.armed {
            // This claim exclusively owns the Copying phase until it either
            // settles or restores Live. Neither the root nor another claimant
            // may write the phase while this capability is armed.
            self.node
                .next_free
                .store(LIVE | self.permit.generation.get(), Ordering::Release);
        }
    }
}

/// Claim only the exact recorded request, without a root lock or editor.
pub fn claim_prepared<'a, S: PreparedCopyNodes<'a>>(
    store: S,
    permit: PortalPreparedPermit,
    request: PortalTransferRequest,
    before_rollback: impl FnOnce(),
) -> Result<ClaimedPreparedCopy<'a, S>, PreparedCopyError> {
    if permit.generation.get() > GENERATION || permit.index == 0 || permit.index > store.allocated()
    {
        return Err(PreparedCopyError::Stale);
    }
    let node = store.node(permit.index);
    node.next_free
        .compare_exchange(
            LIVE | permit.generation.get(),
            COPYING | permit.generation.get(),
            Ordering::Acquire,
            Ordering::Relaxed,
        )
        .map_err(|_| PreparedCopyError::Stale)?;
    let mut rollback = RestoreClaim {
        node,
        live: LIVE | permit.generation.get(),
        armed: true,
    };
    // SAFETY: exact-generation CAS owns the immutable permit payload;
    // the root cannot unlink or free a Live/Copying node or its tail.
    let words_head = unsafe { (*node.data.get()).prepared.words };
    let tail_id = unsafe { (*node.data.get()).prepared.tail };
    if tail_id == 0 || tail_id > store.allocated() {
        return Err(PreparedCopyError::Stale);
    }
    let tail = store.node(tail_id);
    let tail_request: [u64; 4] = unsafe { core::array::from_fn(|i| (*tail.data.get()).words[i]) };
    let notification_index = unsafe { (*tail.data.get()).words[4] };
    let notification_generation = unsafe { (*tail.data.get()).words[5] };
    let queue_index = unsafe { (*tail.data.get()).words[8] };
    let mut words = [0; 17];
    words[..13].copy_from_slice(&words_head);
    words[13..].copy_from_slice(&tail_request);
    if permit.operation != request.operation
        || PortalTransferRequest::decode(words) != Some(request)
    {
        before_rollback();
        return Err(PreparedCopyError::Stale);
    }
    let notification = match u32::try_from(notification_index) {
        Ok(index) => {
            carrick_sched_core::object_wait::ObjectWaitKey::new(index, notification_generation)
        }
        Err(_) => {
            return Err(PreparedCopyError::Stale);
        }
    };
    if notification.is_none() && (notification_index != 0 || notification_generation != 0) {
        return Err(PreparedCopyError::Stale);
    }
    let queue_index = match u32::try_from(queue_index) {
        Ok(index) if index != 0 && index <= store.allocated() => index,
        _ => return Err(PreparedCopyError::Stale),
    };
    rollback.armed = false;
    Ok(ClaimedPreparedCopy {
        node,
        tail,
        store,
        settled: unsafe {
            &*store
                .node(queue_index)
                .data
                .get()
                .cast::<carrick_sched_core::completion_queue::CompletionQueue>()
        },
        permit,
        notification,
        armed: true,
    })
}
