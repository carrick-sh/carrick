//! Prepared semantic admission uses the existing elastic reservation nodes.
//! Copy settlement touches only permanent atomic node headers. Reclamation
//! belongs to the next root guard, never the consuming host's critical path.
use super::*;
use core::num::NonZeroU64;
const LIVE: u64 = 1 << 62;
const COPYING: u64 = 2 << 62;
const SETTLED: u64 = 3 << 62;
const GENERATION: u64 = (1 << 62) - 1;

struct RestoreClaim<'a> {
    node: &'a Node,
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

pub struct ClaimedPreparedCopy<'a> {
    node: &'a Node,
    tail: &'a Node,
    table: &'a SharedReservations,
    banks: Option<&'a dyn storage::NodeBanks>,
    settled: &'a carrick_sched_core::completion_queue::CompletionQueue,
    permit: PortalPreparedPermit,
    notification: Option<carrick_sched_core::object_wait::ObjectWaitKey>,
    armed: bool,
}
impl ClaimedPreparedCopy<'_> {
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
        // Only settled nodes are queued. The guarded doubly-linked live list
        // retains root lifetime until this publication is visible and reaped.
        // SAFETY: the detached primary/tail remain owner-linked until popped.
        unsafe { AtomicU64::from_ptr(core::ptr::addr_of_mut!((*self.tail.data.get()).words[7])) }
            .store(0, Ordering::Relaxed);
        self.settled
            .push(self.permit.index, self.permit.index, |previous, next| {
                let previous = self.table.node(previous, self.banks);
                let tail = unsafe { (*previous.data.get()).prepared.tail };
                unsafe {
                    AtomicU64::from_ptr(core::ptr::addr_of_mut!(
                        (*self.table.node(tail, self.banks).data.get()).words[7]
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
impl Drop for ClaimedPreparedCopy<'_> {
    fn drop(&mut self) {
        if self.armed {
            assert!(
                self.node
                    .next_free
                    .compare_exchange(
                        COPYING | self.permit.generation.get(),
                        LIVE | self.permit.generation.get(),
                        Ordering::Release,
                        Ordering::Relaxed,
                    )
                    .is_ok(),
                "exact prepared claim rollback custody"
            );
        }
    }
}
impl SharedReservations {
    /// No root lock or editor acquisition. Metadata-bank pins must outlive
    /// this claim, exactly as they outlive the borrowed production portal.
    pub fn claim_prepared<'a, P: PinnedMetadataExtent>(
        &'a self,
        nodes: Option<&'a ResolvedReservationNodes<P>>,
        permit: PortalPreparedPermit,
        request: PortalTransferRequest,
    ) -> Result<ClaimedPreparedCopy<'a>, Refusal> {
        self.claim_prepared_inner(nodes, permit, request, || {})
    }
    #[cfg(test)]
    pub(crate) fn claim_prepared_with_rejection<'a, P: PinnedMetadataExtent>(
        &'a self,
        nodes: Option<&'a ResolvedReservationNodes<P>>,
        permit: PortalPreparedPermit,
        request: PortalTransferRequest,
        before_rollback: impl FnOnce(),
    ) -> Result<ClaimedPreparedCopy<'a>, Refusal> {
        self.claim_prepared_inner(nodes, permit, request, before_rollback)
    }
    fn claim_prepared_inner<'a, P: PinnedMetadataExtent>(
        &'a self,
        nodes: Option<&'a ResolvedReservationNodes<P>>,
        permit: PortalPreparedPermit,
        request: PortalTransferRequest,
        before_rollback: impl FnOnce(),
    ) -> Result<ClaimedPreparedCopy<'a>, Refusal> {
        if permit.generation.get() > GENERATION
            || permit.index == 0
            || permit.index > self.allocated.load(Ordering::Acquire)
        {
            return Err(Refusal::Stale);
        }
        let banks: Option<&dyn storage::NodeBanks> = match nodes {
            Some(nodes) => Some(nodes),
            None => None,
        };
        let node = self.node(permit.index, banks);
        node.next_free
            .compare_exchange(
                LIVE | permit.generation.get(),
                COPYING | permit.generation.get(),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .map_err(|_| Refusal::Stale)?;
        let mut rollback = RestoreClaim {
            node,
            live: LIVE | permit.generation.get(),
            armed: true,
        };
        // SAFETY: exact-generation CAS owns the immutable permit payload;
        // the root cannot unlink or free a Live/Copying node or its tail.
        let words_head = unsafe { (*node.data.get()).prepared.words };
        let tail_id = unsafe { (*node.data.get()).prepared.tail };
        if tail_id == 0 || tail_id > self.allocated.load(Ordering::Acquire) {
            return Err(Refusal::Stale);
        }
        let tail = self.node(tail_id, banks);
        let tail_request: [u64; 4] =
            unsafe { core::array::from_fn(|i| (*tail.data.get()).words[i]) };
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
            return Err(Refusal::Stale);
        }
        let notification = match u32::try_from(notification_index) {
            Ok(index) => {
                carrick_sched_core::object_wait::ObjectWaitKey::new(index, notification_generation)
            }
            Err(_) => {
                return Err(Refusal::Stale);
            }
        };
        if notification.is_none() && (notification_index != 0 || notification_generation != 0) {
            return Err(Refusal::Stale);
        }
        let queue_index = match u32::try_from(queue_index) {
            Ok(index) if index != 0 && index <= self.allocated.load(Ordering::Acquire) => index,
            _ => return Err(Refusal::Stale),
        };
        rollback.armed = false;
        Ok(ClaimedPreparedCopy {
            node,
            tail,
            table: self,
            banks,
            settled: unsafe {
                &*self
                    .node(queue_index, banks)
                    .data
                    .get()
                    .cast::<carrick_sched_core::completion_queue::CompletionQueue>()
            },
            permit,
            notification,
            armed: true,
        })
    }
}
impl Reservations<'_> {
    pub fn prepared_wait_key(&self) -> Option<carrick_sched_core::object_wait::ObjectWaitKey> {
        carrick_sched_core::object_wait::ObjectWaitKey::address_space(
            self.index(),
            self.incarnation().raw(),
        )
    }
    fn prepared_live_head(&self) -> u32 {
        let queue = self.state().prepared_head;
        if queue == 0 {
            0
        } else {
            unsafe { (*self.table.node(queue, self.banks).data.get()).words[2] as u32 }
        }
    }
    fn set_prepared_live_head(&mut self, id: u32) {
        let queue = self.state().prepared_head;
        unsafe {
            (*self.table.node(queue, self.banks).data.get()).words[2] = u64::from(id);
        }
    }
    pub fn has_prepared_copy(&self) -> bool {
        self.prepared_live_head() != 0
    }
    pub fn prepared_overlaps(&mut self, range: ReservationRange) -> bool {
        self.reap_prepared();
        let mut id = self.prepared_live_head();
        while id != 0 {
            self.work += 1;
            let node = self.table.node(id, self.banks);
            if node.next_free.load(Ordering::Acquire) & SETTLED != SETTLED {
                // SAFETY: this node is in this guarded root's permit list;
                // settlement never mutates payload and only this guard can
                // unlink, free, or reuse a settled node.
                let header = unsafe { (*node.data.get()).prepared };
                let start = header.words[5];
                let len = header.words[6];
                if start < range.end() && range.start() < start + len {
                    return true;
                }
            }
            id = unsafe { (*node.data.get()).prepared.next };
        }
        false
    }
    fn prepared_link(&self, id: u32) -> &AtomicU64 {
        let tail = unsafe { (*self.table.node(id, self.banks).data.get()).prepared.tail };
        unsafe {
            AtomicU64::from_ptr(core::ptr::addr_of_mut!(
                (*self.table.node(tail, self.banks).data.get()).words[7]
            ))
        }
    }
    pub fn reap_prepared(&mut self) {
        let queue = self.state().prepared_head;
        if queue == 0 {
            return;
        }
        // SAFETY: this metadata node remains owned by the root until retirement.
        let queue = unsafe {
            &*self
                .table
                .node(queue, self.banks)
                .data
                .get()
                .cast::<carrick_sched_core::completion_queue::CompletionQueue>()
        };
        while let Some(id) = unsafe {
            queue.pop(
                |id| self.prepared_link(id).load(Ordering::Acquire) as u32,
                |id, next| {
                    self.prepared_link(id)
                        .store(u64::from(next), Ordering::Release)
                },
            )
        } {
            self.work += 1;
            let node = self.table.node(id, self.banks);
            let next = unsafe { (*node.data.get()).prepared.next };
            let tail_id = unsafe { (*node.data.get()).prepared.tail };
            let tail = self.table.node(tail_id, self.banks);
            let previous = unsafe { (*tail.data.get()).words[6] as u32 };
            if previous == 0 {
                self.set_prepared_live_head(next);
            } else {
                unsafe {
                    (*self.table.node(previous, self.banks).data.get())
                        .prepared
                        .next = next;
                }
            }
            if next != 0 {
                let next_tail = unsafe {
                    (*self.table.node(next, self.banks).data.get())
                        .prepared
                        .tail
                };
                unsafe {
                    (*self.table.node(next_tail, self.banks).data.get()).words[6] =
                        u64::from(previous);
                }
            }
            self.free_node(tail_id);
            self.free_node(id);
        }
    }
    pub(crate) fn prepare_copy(
        &mut self,
        request: PortalTransferRequest,
        notification: Option<carrick_sched_core::object_wait::ObjectWaitKey>,
    ) -> Result<PortalPreparedPermit, Refusal> {
        if request.operation.mm != self.mm
            || request.operation.incarnation.get() != self.incarnation().raw()
            || self.pending().is_some()
            || (self.fork_pending() && !self.fork_write_authorized(request.fork_sequence))
        {
            return Err(Refusal::Stale);
        }
        self.reap_prepared();
        self.work += 1;
        let generation = self
            .table
            .prepared_sequence
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |value| {
                (value < GENERATION).then_some(value + 1)
            })
            .map_err(|_| Refusal::Stale)?
            + 1;
        let generation = NonZeroU64::new(generation).ok_or(Refusal::Stale)?;
        if self.state().prepared_head == 0 {
            let queue_id = self.pool_node()?;
            let queue_node = self.table.node(queue_id, self.banks);
            unsafe {
                *queue_node.data.get() = NodePayload { words: [0; 14] };
            }
            let queue = unsafe {
                &*queue_node
                    .data
                    .get()
                    .cast::<carrick_sched_core::completion_queue::CompletionQueue>()
            };
            assert!(queue.initialize());
            self.state_mut().prepared_head = queue_id;
        }
        let id = self.pool_node()?;
        let tail = match self.pool_node() {
            Ok(tail) => tail,
            Err(error) => {
                self.free_node(id);
                return Err(error);
            }
        };
        let words = request.words();
        let mut header_words = [0; 13];
        header_words.copy_from_slice(&words[..13]);
        let mut tail_words = [0; 14];
        tail_words[..4].copy_from_slice(&words[13..]);
        if let Some(key) = notification {
            tail_words[4] = u64::from(key.index());
            tail_words[5] = key.generation();
        }
        tail_words[8] = u64::from(self.state().prepared_head);
        let previous_head = self.prepared_live_head();
        if previous_head != 0 {
            let previous_tail = unsafe {
                (*self.table.node(previous_head, self.banks).data.get())
                    .prepared
                    .tail
            };
            unsafe {
                (*self.table.node(previous_tail, self.banks).data.get()).words[6] = u64::from(id);
            }
        }
        let node = self.table.node(id, self.banks);
        // SAFETY: new nodes, published in the guarded root only after writes.
        unsafe {
            *node.data.get() = NodePayload {
                prepared: PreparedHeader {
                    next: self.prepared_live_head(),
                    tail,
                    words: header_words,
                },
            };
            *self.table.node(tail, self.banks).data.get() = NodePayload { words: tail_words };
        }
        node.next_free
            .store(LIVE | generation.get(), Ordering::Release);
        self.set_prepared_live_head(id);
        Ok(PortalPreparedPermit {
            index: id,
            generation,
            operation: request.operation,
        })
    }
}
