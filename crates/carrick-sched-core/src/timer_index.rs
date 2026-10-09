//! A fixed-capacity forest of indexed deadline heaps, one per serving slot.
//! Storage belongs to the shared zone; no host pointers or allocator are used.
use super::{RecordId, RecordRef, SlotId, ThreadCtx, ZONE_RECORDS, ZONE_SLOTS, ZoneTables};
#[cfg(test)]
std::thread_local! { static NODE_READS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) }; }

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Ticket {
    pub slot: SlotId,
    pub record: RecordRef,
    pub seq: u32,
    pub deadline: u64,
}
#[repr(C)]
struct Node {
    parent: AtomicU32,
    left: AtomicU32,
    right: AtomicU32,
    record: AtomicU32,
    incarnation: AtomicU64,
    seq: AtomicU32,
    deadline: AtomicU64,
}
#[repr(C)]
struct Tree {
    lock: AtomicU32,
    root: AtomicU32,
    len: AtomicU32,
}
#[repr(C)]
struct Lease {
    slot: AtomicU32,
    node: AtomicU32,
    active: AtomicU32,
}
#[repr(C)]
pub(super) struct Index {
    trees: [Tree; ZONE_SLOTS],
    nodes: [Node; ZONE_RECORDS],
    leases: [Lease; ZONE_RECORDS],
    map: [AtomicU64; ZONE_RECORDS / 64],
}
struct Guard<'a> {
    index: &'a Index,
    slot: SlotId,
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.index.tree(self.slot).lock.store(0, Ordering::Release);
    }
}
impl Index {
    fn tree(&self, slot: SlotId) -> &Tree {
        &self.trees[slot.raw() as usize]
    }
    fn node(&self, index: u32) -> &Node {
        &self.nodes[index as usize]
    }
    fn lock(&self, slot: SlotId) -> Guard<'_> {
        // No timer-index lock holder acquires a bucket or run-queue lock.
        // Timer peeks release this lock before authenticating a wake CAS.
        while self
            .tree(slot)
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard { index: self, slot }
    }
    fn key(&self, slot: SlotId, node: u32) -> Ticket {
        let n = self.node(node);
        Ticket {
            slot,
            record: RecordRef {
                id: RecordId::from_raw(n.record.load(Ordering::Relaxed))
                    .unwrap_or(RecordId::PLACEHOLDER),
                incarnation: n.incarnation.load(Ordering::Relaxed),
            },
            seq: n.seq.load(Ordering::Relaxed),
            deadline: n.deadline.load(Ordering::Relaxed),
        }
    }
    fn write_key(&self, node: u32, key: Ticket) {
        let n = self.node(node);
        n.record.store(key.record.id.raw(), Ordering::Relaxed);
        n.incarnation
            .store(key.record.incarnation, Ordering::Relaxed);
        n.seq.store(key.seq, Ordering::Relaxed);
        n.deadline.store(key.deadline, Ordering::Relaxed);
        let lease = &self.leases[key.record.id.raw() as usize];
        lease.node.store(node, Ordering::Relaxed);
        lease.slot.store(key.slot.plus_one(), Ordering::Release);
    }
    fn swap(&self, slot: SlotId, a: u32, b: u32) {
        let ka = self.key(slot, a);
        let kb = self.key(slot, b);
        self.write_key(a, kb);
        self.write_key(b, ka);
    }
    fn less(&self, slot: SlotId, a: u32, b: u32) -> bool {
        let ka = self.key(slot, a);
        let kb = self.key(slot, b);
        (ka.deadline, ka.record, ka.seq) < (kb.deadline, kb.record, kb.seq)
    }
    fn at(&self, slot: SlotId, position: u32) -> u32 {
        let mut node = self.tree(slot).root.load(Ordering::Relaxed);
        let mut bit = (1_u32 << (31 - position.leading_zeros())) >> 1;
        while bit != 0 {
            node = if position & bit == 0 {
                self.node(node).left.load(Ordering::Relaxed)
            } else {
                self.node(node).right.load(Ordering::Relaxed)
            };
            bit >>= 1;
        }
        node
    }
    fn up(&self, slot: SlotId, mut node: u32) {
        loop {
            let parent = self.node(node).parent.load(Ordering::Relaxed);
            if parent == 0 || !self.less(slot, node, parent) {
                break;
            }
            self.swap(slot, node, parent);
            node = parent;
        }
    }
    fn down(&self, slot: SlotId, mut node: u32) {
        loop {
            let left = self.node(node).left.load(Ordering::Relaxed);
            if left == 0 {
                break;
            }
            let right = self.node(node).right.load(Ordering::Relaxed);
            let child = if right != 0 && self.less(slot, right, left) {
                right
            } else {
                left
            };
            if !self.less(slot, child, node) {
                break;
            }
            self.swap(slot, node, child);
            node = child;
        }
    }
    fn remove_locked(&self, guard: &Guard<'_>, node: u32) -> Ticket {
        let slot = guard.slot;
        let tree = self.tree(slot);
        let key = self.key(slot, node);
        let len = tree.len.load(Ordering::Relaxed);
        let last = self.at(slot, len);
        let lease = &self.leases[key.record.id.raw() as usize];
        lease.node.store(0, Ordering::Relaxed);
        lease.slot.store(0, Ordering::Release);
        if node != last {
            self.write_key(node, self.key(slot, last));
        }
        let parent = self.node(last).parent.load(Ordering::Relaxed);
        if parent == 0 {
            tree.root.store(0, Ordering::Relaxed);
        } else if self.node(parent).left.load(Ordering::Relaxed) == last {
            self.node(parent).left.store(0, Ordering::Relaxed);
        } else {
            self.node(parent).right.store(0, Ordering::Relaxed);
        }
        tree.len.store(len - 1, Ordering::Relaxed);
        ZoneTables::<ThreadCtx>::free_bit(&self.map, last);
        if node != last {
            let parent = self.node(node).parent.load(Ordering::Relaxed);
            if parent != 0 && self.less(slot, node, parent) {
                self.up(slot, node);
            } else {
                self.down(slot, node);
            }
        }
        key
    }
    pub(super) fn cancel_record(&self, record: RecordId) {
        let lease = &self.leases[record.raw() as usize];
        loop {
            let slot_raw = lease.slot.load(Ordering::Acquire);
            let Some(slot) = SlotId::from_plus_one(slot_raw) else {
                return;
            };
            let guard = self.lock(slot);
            if lease.slot.load(Ordering::Acquire) != slot_raw {
                continue;
            }
            let node = lease.node.load(Ordering::Relaxed);
            if node != 0 {
                if lease.active.load(Ordering::Relaxed) != 0 {
                    self.remove_locked(&guard, node);
                } else {
                    lease.node.store(0, Ordering::Relaxed);
                    lease.slot.store(0, Ordering::Release);
                    ZoneTables::<ThreadCtx>::free_bit(&self.map, node);
                }
            }
            return;
        }
    }
    pub(super) fn cancel_admission(&self, record: RecordRef) {
        let lease = &self.leases[record.id.raw() as usize];
        let Some(slot) = SlotId::from_plus_one(lease.slot.load(Ordering::Acquire)) else {
            return;
        };
        let _guard = self.lock(slot);
        if lease.slot.load(Ordering::Acquire) != slot.plus_one()
            || lease.active.load(Ordering::Relaxed) != 0
        {
            return;
        }
        let node = lease.node.load(Ordering::Relaxed);
        if self.key(slot, node).record != record {
            return;
        }
        lease.node.store(0, Ordering::Relaxed);
        lease.slot.store(0, Ordering::Release);
        ZoneTables::<ThreadCtx>::free_bit(&self.map, node);
    }
    pub(super) fn reserve(&self, ticket: Ticket) -> bool {
        self.cancel_record(ticket.record.id);
        let _guard = self.lock(ticket.slot);
        let Some(node) = ZoneTables::<ThreadCtx>::alloc_bit(&self.map, ZONE_RECORDS) else {
            return false;
        };
        self.leases[ticket.record.id.raw() as usize]
            .active
            .store(0, Ordering::Relaxed);
        self.write_key(node, ticket);
        true
    }
    pub(super) fn activate(&self, ticket: Ticket) {
        let guard = self.lock(ticket.slot);
        let lease = &self.leases[ticket.record.id.raw() as usize];
        if lease.slot.load(Ordering::Acquire) != ticket.slot.plus_one() {
            return;
        }
        let node = lease.node.load(Ordering::Relaxed);
        let reserved = self.key(ticket.slot, node);
        if reserved.record != ticket.record
            || reserved.seq != ticket.seq
            || lease.active.load(Ordering::Relaxed) != 0
        {
            return;
        }
        lease.active.store(1, Ordering::Relaxed);
        let tree = self.tree(ticket.slot);
        let position = tree.len.load(Ordering::Relaxed) + 1;
        let parent = if position == 1 {
            0
        } else {
            self.at(ticket.slot, position / 2)
        };
        let n = self.node(node);
        n.parent.store(parent, Ordering::Relaxed);
        n.left.store(0, Ordering::Relaxed);
        n.right.store(0, Ordering::Relaxed);
        self.write_key(node, ticket);
        if parent == 0 {
            tree.root.store(node, Ordering::Relaxed);
        } else if position & 1 == 0 {
            self.node(parent).left.store(node, Ordering::Relaxed);
        } else {
            self.node(parent).right.store(node, Ordering::Relaxed);
        }
        tree.len.store(position, Ordering::Relaxed);
        self.up(guard.slot, node);
    }
    pub(super) fn admission(&self, record: RecordRef, seq: u32, deadline: u64) -> Option<Ticket> {
        let lease = &self.leases[record.id.raw() as usize];
        let slot = SlotId::from_plus_one(lease.slot.load(Ordering::Acquire))?;
        let _guard = self.lock(slot);
        if lease.slot.load(Ordering::Acquire) != slot.plus_one() {
            return None;
        }
        let node = lease.node.load(Ordering::Relaxed);
        let reserved = self.key(slot, node);
        (reserved.record == record
            && reserved.seq == seq
            && lease.active.load(Ordering::Relaxed) == 0)
            .then_some(Ticket {
                slot,
                record,
                seq,
                deadline,
            })
    }
    pub(super) fn owned(&self, record: RecordRef) -> Option<Ticket> {
        let lease = &self.leases[record.id.raw() as usize];
        let slot = SlotId::from_plus_one(lease.slot.load(Ordering::Acquire))?;
        let _guard = self.lock(slot);
        if lease.slot.load(Ordering::Acquire) != slot.plus_one()
            || lease.active.load(Ordering::Relaxed) == 0
        {
            return None;
        }
        let ticket = self.key(slot, lease.node.load(Ordering::Relaxed));
        (ticket.record == record).then_some(ticket)
    }
    pub(super) fn minimum(&self, slot: SlotId, live: impl Fn(Ticket) -> bool) -> Option<Ticket> {
        let guard = self.lock(slot);
        loop {
            let node = self.tree(slot).root.load(Ordering::Relaxed);
            if node == 0 {
                return None;
            }
            let key = self.key(slot, node);
            if live(key) {
                return Some(key);
            }
            self.remove_locked(&guard, node);
        }
    }
    pub(super) fn remove(&self, ticket: Ticket) -> bool {
        let guard = self.lock(ticket.slot);
        let lease = &self.leases[ticket.record.id.raw() as usize];
        if lease.slot.load(Ordering::Acquire) != ticket.slot.plus_one() {
            return false;
        }
        let node = lease.node.load(Ordering::Relaxed);
        if node == 0 || self.key(ticket.slot, node) != ticket {
            return false;
        }
        self.remove_locked(&guard, node);
        true
    }
    pub(super) fn take_foreign(
        &self,
        slot: SlotId,
        home: Option<RecordId>,
        live: impl Fn(Ticket) -> bool,
    ) -> Option<Ticket> {
        let guard = self.lock(slot);
        loop {
            let root = self.tree(slot).root.load(Ordering::Relaxed);
            if root == 0 {
                return None;
            }
            let root_key = self.key(slot, root);
            let node = if !live(root_key) || Some(root_key.record.id) != home {
                root
            } else {
                let left = self.node(root).left.load(Ordering::Relaxed);
                let right = self.node(root).right.load(Ordering::Relaxed);
                if left == 0 {
                    return None;
                }
                if right != 0 && self.less(slot, right, left) {
                    right
                } else {
                    left
                }
            };
            let key = self.remove_locked(&guard, node);
            if live(key) {
                return Some(key);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::boxed::Box;
    fn index() -> Box<Index> {
        let layout = core::alloc::Layout::new::<Index>();
        // SAFETY: the typed layout provides the required alignment; zero is
        // valid for every atomic in this fixed shared-storage representation.
        let raw = unsafe { std::alloc::alloc_zeroed(layout).cast::<Index>() };
        if raw.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        // SAFETY: this allocation has exactly the layout of Index and is owned.
        unsafe { Box::from_raw(raw) }
    }
    fn ticket(index: u32, incarnation: u64, slot: SlotId, deadline: u64) -> Ticket {
        Ticket {
            slot,
            record: RecordRef {
                id: RecordId::from_raw(index).unwrap(),
                incarnation,
            },
            seq: 1,
            deadline,
        }
    }
    #[test]
    fn population_budget_and_exact_removal() {
        let index = index();
        let slot = SlotId::new(0);
        for id in 1..ZONE_RECORDS as u32 {
            let key = ticket(id, 1, slot, 1 + u64::from((id * 977) % ZONE_RECORDS as u32));
            NODE_READS.with(|reads| reads.set(0));
            assert!(index.reserve(Ticket { deadline: 0, ..key }));
            index.activate(key);
            assert!(
                NODE_READS.with(|reads| reads.get()) <= 256,
                "insertion exceeds logarithmic index budget"
            );
        }
        let mut previous = 0;
        for _ in 1..ZONE_RECORDS {
            NODE_READS.with(|reads| reads.set(0));
            let key = index.minimum(slot, |_| true).unwrap();
            assert!(key.deadline >= previous);
            previous = key.deadline;
            assert!(index.remove(key));
            assert!(
                NODE_READS.with(|reads| reads.get()) <= 256,
                "removal exceeds logarithmic index budget"
            );
        }
        assert_eq!(index.minimum(slot, |_| true), None);
    }
    #[test]
    fn reused_record_and_migration_cannot_consume_new_deadline() {
        let index = index();
        let first = ticket(1, 1, SlotId::new(0), 100);
        assert!(index.reserve(Ticket {
            deadline: 0,
            ..first
        }));
        index.activate(first);
        let second = ticket(1, 2, SlotId::new(1), 200);
        assert!(index.reserve(Ticket {
            deadline: 0,
            ..second
        }));
        index.activate(second);
        assert!(!index.remove(first));
        index.activate(first);
        assert_eq!(index.minimum(first.slot, |_| true), None);
        assert_eq!(index.minimum(second.slot, |_| true), Some(second));
        assert!(index.remove(second));
    }
    #[test]
    fn unpublished_reservation_does_not_displace_live_deadline() {
        let index = index();
        let slot = SlotId::new(0);
        let first = ticket(1, 1, slot, 100);
        assert!(index.reserve(Ticket {
            deadline: 0,
            ..first
        }));
        index.activate(first);
        let second = ticket(2, 1, slot, 10);
        assert!(index.reserve(Ticket {
            deadline: 0,
            ..second
        }));
        assert_eq!(index.minimum(slot, |_| true), Some(first));
        index.cancel_record(second.record.id);
        index.activate(second);
        assert_eq!(index.minimum(slot, |_| true), Some(first));
    }
}
