//! Exact-MM pristine anonymous backing state. Callers authenticate MM identity
//! and permissions; absence of a translation never grants zero-read authority.
use crate::GuestVa;
use parking_lot::{Mutex, MutexGuard};
use std::ops::Range;

const PAGE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeferredAnonymousError {
    #[error("deferred anonymous range is empty, unaligned, or overflows")]
    InvalidRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredAnonymousSnapshot {
    pub pristine: Vec<Range<GuestVa>>,
    pub zero_read_resident: Vec<Range<GuestVa>>,
}

#[derive(Debug, Default, Clone)]
struct State {
    pristine: Vec<Range<u64>>,
    resident: Vec<Range<u64>>,
}

/// Share only within one MM; use `fork_private` for a copied MM. Never hold
/// this lock while acquiring quiesce or calling back into runtime authorities.
#[derive(Debug, Default)]
pub struct DeferredAnonymousState {
    state: Mutex<State>,
}

fn extent(start: GuestVa, len: usize) -> Result<Range<u64>, DeferredAnonymousError> {
    let end = start
        .raw()
        .checked_add(u64::try_from(len).map_err(|_| DeferredAnonymousError::InvalidRange)?)
        .ok_or(DeferredAnonymousError::InvalidRange)?;
    if len == 0 || !start.raw().is_multiple_of(PAGE) || !end.is_multiple_of(PAGE) {
        return Err(DeferredAnonymousError::InvalidRange);
    }
    Ok(start.raw()..end)
}

fn remove(ranges: &mut Vec<Range<u64>>, cut: &Range<u64>) {
    let mut next = Vec::with_capacity(ranges.len() + 1);
    for old in ranges.drain(..) {
        if old.end <= cut.start || old.start >= cut.end {
            next.push(old);
        } else {
            if old.start < cut.start {
                next.push(old.start..cut.start);
            }
            if old.end > cut.end {
                next.push(cut.end..old.end);
            }
        }
    }
    *ranges = next;
}

fn insert(ranges: &mut Vec<Range<u64>>, mut added: Range<u64>) {
    let first = ranges.partition_point(|r| r.end < added.start);
    let mut last = first;
    while last < ranges.len() && ranges[last].start <= added.end {
        added.start = added.start.min(ranges[last].start);
        added.end = added.end.max(ranges[last].end);
        last += 1;
    }
    ranges.splice(first..last, [added]);
}

impl DeferredAnonymousState {
    pub fn new() -> Self {
        Self::default()
    }
    /// Caller must prove this is newly reserved, pristine private anonymous memory.
    pub fn reserve_fresh(&self, start: GuestVa, len: usize) -> Result<(), DeferredAnonymousError> {
        let range = extent(start, len)?;
        let mut state = self.state.lock();
        remove(&mut state.resident, &range);
        insert(&mut state.pristine, range);
        Ok(())
    }
    pub fn retire(&self, start: GuestVa, len: usize) -> Result<(), DeferredAnonymousError> {
        let range = extent(start, len)?;
        let mut state = self.state.lock();
        remove(&mut state.pristine, &range);
        remove(&mut state.resident, &range);
        Ok(())
    }
    /// Clear logical read residency without changing pristine provenance.
    pub fn clear_zero_read_residency(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<(), DeferredAnonymousError> {
        let range = extent(start, len)?;
        remove(&mut self.state.lock().resident, &range);
        Ok(())
    }
    /// Caller checks logical read permission before entering. Refusal leaves dst unchanged.
    pub fn copy_pristine_zero(
        &self,
        start: GuestVa,
        dst: &mut [u8],
    ) -> Result<bool, DeferredAnonymousError> {
        if dst.is_empty() {
            return Ok(true);
        }
        let start = start.raw();
        let len = u64::try_from(dst.len()).map_err(|_| DeferredAnonymousError::InvalidRange)?;
        let end = start
            .checked_add(len)
            .ok_or(DeferredAnonymousError::InvalidRange)?;
        let page = start & !(PAGE - 1);
        let page_end = page
            .checked_add(PAGE)
            .ok_or(DeferredAnonymousError::InvalidRange)?;
        if end > page_end {
            return Err(DeferredAnonymousError::InvalidRange);
        }
        let mut state = self.state.lock();
        let index = state.pristine.partition_point(|r| r.end <= start);
        if !state
            .pristine
            .get(index)
            .is_some_and(|r| r.start <= start && end <= r.end)
        {
            return Ok(false);
        }
        dst.fill(0);
        insert(&mut state.resident, page..page_end);
        Ok(true)
    }
    pub fn snapshot(&self) -> DeferredAnonymousSnapshot {
        let state = self.state.lock();
        DeferredAnonymousSnapshot {
            pristine: state
                .pristine
                .iter()
                .map(|r| GuestVa(r.start)..GuestVa(r.end))
                .collect(),
            zero_read_resident: state
                .resident
                .iter()
                .map(|r| GuestVa(r.start)..GuestVa(r.end))
                .collect(),
        }
    }
    pub fn fork_private(&self) -> Self {
        Self {
            state: Mutex::new(self.state.lock().clone()),
        }
    }
    /// Acquire only AFTER caller quiescence/exclusion. On failure, prove complete
    /// rollback or fail-stop BEFORE dropping the guard: drop restores no backend state.
    pub fn begin_materialization(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<DeferredAnonymousTransition<'_>, DeferredAnonymousError> {
        Ok(DeferredAnonymousTransition {
            state: self.state.lock(),
            range: extent(start, len)?,
        })
    }
}

#[must_use]
pub struct DeferredAnonymousTransition<'a> {
    state: MutexGuard<'a, State>,
    range: Range<u64>,
}
impl DeferredAnonymousTransition<'_> {
    /// Call only after successful publication. Logical zero-read residency remains.
    pub fn commit(mut self) {
        remove(&mut self.state.pristine, &self.range);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_zero_reads_and_lifecycle() {
        let state = DeferredAnonymousState::new();
        state.reserve_fresh(GuestVa(0x1000), 0x2000).unwrap();
        state.reserve_fresh(GuestVa(0x3000), 0x1000).unwrap();
        assert_eq!(
            state.snapshot().pristine,
            vec![GuestVa(0x1000)..GuestVa(0x4000)]
        );
        let mut bytes = [9; 4];
        assert!(
            state
                .copy_pristine_zero(GuestVa(0x1ffc), &mut bytes)
                .unwrap()
        );
        assert_eq!(bytes, [0; 4]);
        assert_eq!(
            state.snapshot().zero_read_resident,
            vec![GuestVa(0x1000)..GuestVa(0x2000)]
        );
        assert!(
            state
                .copy_pristine_zero(GuestVa(0x1ffe), &mut bytes)
                .is_err()
        );
        state.retire(GuestVa(0x2000), 0x1000).unwrap();
        bytes.fill(7);
        assert!(
            !state
                .copy_pristine_zero(GuestVa(0x2000), &mut bytes)
                .unwrap()
        );
        assert_eq!(bytes, [7; 4]);
        state.reserve_fresh(GuestVa(0x1000), 0x1000).unwrap();
        assert!(state.snapshot().zero_read_resident.is_empty());
        assert!(state.reserve_fresh(GuestVa(u64::MAX - 4095), 4096).is_err());
        assert!(state.retire(GuestVa(1), 4096).is_err());
        assert!(state.retire(GuestVa(0), 0).is_err());
    }
    #[test]
    fn transition_commit_failure_and_fork_isolation() {
        let state = DeferredAnonymousState::new();
        state.reserve_fresh(GuestVa(0x1000), 0x3000).unwrap();
        let child = state.fork_private();
        let before = state.snapshot();
        drop(state.begin_materialization(GuestVa(0x2000), 4096).unwrap());
        assert_eq!(state.snapshot(), before);
        state
            .begin_materialization(GuestVa(0x2000), 4096)
            .unwrap()
            .commit();
        assert_eq!(
            state.snapshot().pristine,
            vec![
                GuestVa(0x1000)..GuestVa(0x2000),
                GuestVa(0x3000)..GuestVa(0x4000)
            ]
        );
        assert_eq!(child.snapshot(), before);
    }
    #[test]
    fn zero_read_residency_has_an_independent_lifecycle() {
        let state = DeferredAnonymousState::new();
        state.reserve_fresh(GuestVa(0x1000), 8192).unwrap();
        assert!(
            state
                .copy_pristine_zero(GuestVa(0x1000), &mut [1; 4])
                .unwrap()
        );
        state
            .begin_materialization(GuestVa(0x1000), 4096)
            .unwrap()
            .commit();
        assert_eq!(
            state.snapshot().zero_read_resident,
            vec![GuestVa(0x1000)..GuestVa(0x2000)]
        );
        state
            .clear_zero_read_residency(GuestVa(0x1000), 8192)
            .unwrap();
        assert!(state.snapshot().zero_read_resident.is_empty());
        assert_eq!(
            state.snapshot().pristine,
            vec![GuestVa(0x2000)..GuestVa(0x3000)]
        );
        assert!(
            state
                .copy_pristine_zero(GuestVa(0x2000), &mut [1; 4])
                .unwrap()
        );
        state.retire(GuestVa(0x2000), 4096).unwrap();
        assert!(state.snapshot().zero_read_resident.is_empty());
        assert!(state.snapshot().pristine.is_empty());
    }

    #[test]
    fn rolled_back_materializer_orders_before_zero_reader() {
        let state = std::sync::Arc::new(DeferredAnonymousState::new());
        state.reserve_fresh(GuestVa(0x1000), 4096).unwrap();
        let guard = state.begin_materialization(GuestVa(0x1000), 4096).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let child = state.clone();
        let reader = std::thread::spawn(move || {
            assert!(child.state.try_lock().is_none());
            tx.send(()).unwrap();
            let mut bytes = [5; 4];
            (
                child
                    .copy_pristine_zero(GuestVa(0x1000), &mut bytes)
                    .unwrap(),
                bytes,
            )
        });
        rx.recv().unwrap();
        drop(guard); // No backend publication occurred: clean failure.
        assert_eq!(reader.join().unwrap(), (true, [0; 4]));
    }

    #[test]
    fn committed_materializer_orders_before_reader() {
        let state = std::sync::Arc::new(DeferredAnonymousState::new());
        state.reserve_fresh(GuestVa(0x1000), 4096).unwrap();
        let guard = state.begin_materialization(GuestVa(0x1000), 4096).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let child = state.clone();
        let reader = std::thread::spawn(move || {
            assert!(child.state.try_lock().is_none());
            tx.send(()).unwrap();
            let mut bytes = [5; 4];
            (
                child
                    .copy_pristine_zero(GuestVa(0x1000), &mut bytes)
                    .unwrap(),
                bytes,
            )
        });
        rx.recv().unwrap();
        guard.commit();
        assert_eq!(reader.join().unwrap(), (false, [5; 4]));
    }
}
