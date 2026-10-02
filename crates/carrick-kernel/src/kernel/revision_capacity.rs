//! Exact-task revision headroom owned before an ABI birth is admitted.

use super::TaskRevision;
use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Debug)]
struct Budget {
    ceiling: u64,
    reserved: u64,
}

#[derive(Debug)]
pub(super) struct RevisionCapacity(Mutex<Budget>);

impl Default for RevisionCapacity {
    fn default() -> Self {
        Self(Mutex::new(Budget {
            ceiling: u64::MAX,
            reserved: 0,
        }))
    }
}

impl RevisionCapacity {
    pub(super) fn next(&self, current: TaskRevision) -> Option<TaskRevision> {
        let budget = self.0.lock();
        let needed = current.raw().checked_add(budget.reserved)?.checked_add(1)?;
        (needed <= budget.ceiling).then(|| current.next()).flatten()
    }

    #[cfg(test)]
    pub(super) fn exhaust_unreserved_for_test(&self, current: TaskRevision) {
        let mut budget = self.0.lock();
        budget.ceiling = current.raw().checked_add(budget.reserved).unwrap();
    }

    pub(super) fn reserve(
        self: &Arc<Self>,
        current: TaskRevision,
        count: u64,
    ) -> Option<RevisionReservation> {
        let mut budget = self.0.lock();
        let reserved = budget.reserved.checked_add(count)?;
        if current.raw().checked_add(reserved)? > budget.ceiling {
            return None;
        }
        budget.reserved = reserved;
        Some(RevisionReservation {
            source: self.clone(),
            remaining: count,
        })
    }
}

#[derive(Debug)]
pub(super) struct RevisionReservation {
    source: Arc<RevisionCapacity>,
    remaining: u64,
}

impl RevisionReservation {
    pub(super) fn consume(
        &mut self,
        source: &Arc<RevisionCapacity>,
        current: TaskRevision,
    ) -> TaskRevision {
        if !Arc::ptr_eq(&self.source, source) || self.remaining == 0 {
            carrick_fatal::carrick_fatal!(
                "thread::revision",
                "revision lease has wrong task or is exhausted"
            );
        }
        let mut budget = source.0.lock();
        let next = current
            .next()
            .filter(|next| next.raw() <= budget.ceiling)
            .unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!(
                    "thread::revision",
                    "host publication consumed reserved revision headroom"
                )
            });
        budget.reserved = budget.reserved.checked_sub(1).unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!(
                "thread::revision",
                "revision lease lost its reserved credit"
            )
        });
        self.remaining -= 1;
        next
    }
}

impl Drop for RevisionReservation {
    fn drop(&mut self) {
        let mut budget = self.source.0.lock();
        budget.reserved = budget
            .reserved
            .checked_sub(self.remaining)
            .unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!(
                    "thread::revision",
                    "revision lease release underflow"
                )
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_birth_and_exit_headroom_is_task_scoped() {
        let owner = Arc::new(RevisionCapacity(Mutex::new(Budget {
            ceiling: 3,
            reserved: 0,
        })));
        let peer = Arc::new(RevisionCapacity(Mutex::new(Budget {
            ceiling: 3,
            reserved: 0,
        })));
        let mut lease = owner.reserve(TaskRevision::INITIAL, 2).unwrap();
        assert!(owner.next(TaskRevision::INITIAL).is_none());
        assert!(peer.next(TaskRevision::INITIAL).is_some());
        let born = lease.consume(&owner, TaskRevision::INITIAL);
        assert!(owner.next(born).is_none());
        let exited = lease.consume(&owner, born);
        assert_eq!(exited.raw(), 3);
    }

    #[test]
    fn declined_birth_releases_headroom() {
        let owner = Arc::new(RevisionCapacity(Mutex::new(Budget {
            ceiling: 3,
            reserved: 0,
        })));
        let lease = owner.reserve(TaskRevision::INITIAL, 2).unwrap();
        assert!(owner.reserve(TaskRevision::INITIAL, 1).is_none());
        drop(lease);
        assert!(owner.next(TaskRevision::INITIAL).is_some());
    }
}
