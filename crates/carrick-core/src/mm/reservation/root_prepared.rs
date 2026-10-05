//! Prepared semantic admission uses the existing elastic reservation nodes.
//! Copy settlement touches only permanent atomic node headers. Reclamation
//! belongs to the next root guard, never the consuming host's critical path.
use super::*;
use crate::mm::reservation::prepared::{self as owner, PreparedCopyNodes};
use core::num::NonZeroU64;
use owner::{GENERATION, LIVE, SETTLED};

/// Retains the existing table and its authenticated metadata-bank view.
pub struct BorrowedReservationNodes<'a, Policy: ReservationPolicy, Geometry: ReservationGeometry> {
    table: &'a SharedReservations<Policy, Geometry>,
    banks: Option<&'a dyn storage::NodeBanks>,
}
impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Copy
    for BorrowedReservationNodes<'_, Policy, Geometry>
{
}
impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Clone
    for BorrowedReservationNodes<'_, Policy, Geometry>
{
    fn clone(&self) -> Self {
        *self
    }
}
// SAFETY: constructed only from the production table and its borrowed pinned
// view. The original root list prevents reuse until the neutral claim settles.
unsafe impl<'a, Policy: ReservationPolicy, Geometry: ReservationGeometry> PreparedCopyNodes<'a>
    for BorrowedReservationNodes<'a, Policy, Geometry>
{
    fn allocated(self) -> u32 {
        self.table.allocated.load(Ordering::Acquire)
    }
    fn node(self, index: u32) -> &'a Node {
        self.table.node(index, self.banks)
    }
}
pub type ClaimedPreparedCopy<'a, Policy, Geometry> =
    owner::ClaimedPreparedCopy<'a, BorrowedReservationNodes<'a, Policy, Geometry>>;

impl<Policy: ReservationPolicy, Geometry: ReservationGeometry>
    SharedReservations<Policy, Geometry>
{
    /// No root lock or editor acquisition. Metadata-bank pins must outlive
    /// this claim, exactly as they outlive the borrowed production portal.
    pub fn claim_prepared<'a, P: PinnedMetadataExtent>(
        &'a self,
        nodes: Option<&'a ResolvedReservationNodes<P, Policy, Geometry>>,
        permit: PortalPreparedPermit,
        request: PortalTransferRequest,
    ) -> Result<ClaimedPreparedCopy<'a, Policy, Geometry>, Refusal> {
        self.claim_prepared_inner(nodes, permit, request, || {})
    }
    #[cfg(any(test, feature = "host-test"))]
    pub fn claim_prepared_with_rejection<'a, P: PinnedMetadataExtent>(
        &'a self,
        nodes: Option<&'a ResolvedReservationNodes<P, Policy, Geometry>>,
        permit: PortalPreparedPermit,
        request: PortalTransferRequest,
        before_rollback: impl FnOnce(),
    ) -> Result<ClaimedPreparedCopy<'a, Policy, Geometry>, Refusal> {
        self.claim_prepared_inner(nodes, permit, request, before_rollback)
    }
    fn claim_prepared_inner<'a, P: PinnedMetadataExtent>(
        &'a self,
        nodes: Option<&'a ResolvedReservationNodes<P, Policy, Geometry>>,
        permit: PortalPreparedPermit,
        request: PortalTransferRequest,
        before_rollback: impl FnOnce(),
    ) -> Result<ClaimedPreparedCopy<'a, Policy, Geometry>, Refusal> {
        let banks: Option<&dyn storage::NodeBanks> =
            nodes.map(|nodes| nodes as &dyn storage::NodeBanks);
        owner::claim_prepared(
            BorrowedReservationNodes { table: self, banks },
            permit,
            request,
            before_rollback,
        )
        .map_err(|_| Refusal::Stale)
    }
}
impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Reservations<'_, Policy, Geometry> {
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
    /// Fixture-only construction for custody and work-budget tests.
    ///
    /// # Safety
    /// The fixture must authenticate the request's exact MM, generation,
    /// permissions and live output, and retain its metadata and output pins.
    /// Production callers must use the revalidating owner transaction.
    #[cfg(feature = "host-test")]
    pub unsafe fn prepare_copy_for_fixture(
        &mut self,
        request: PortalTransferRequest,
        notification: Option<carrick_sched_core::object_wait::ObjectWaitKey>,
    ) -> Result<PortalPreparedPermit, Refusal> {
        self.prepare_copy(request, notification)
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
