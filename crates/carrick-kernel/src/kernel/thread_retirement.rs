//! Registry-owned retirement storage. A birth leases a cell before becoming
//! claimable; publishing retirement consumes that cell without allocating.

use std::collections::TryReserveError;
use std::sync::Arc;

use parking_lot::{Mutex, MutexGuard};

use super::core::RetiredThreadRecord;

#[derive(Debug)]
enum Cell {
    Vacant,
    Reserved,
    Retired(RetiredThreadRecord),
}

#[derive(Debug, Default)]
struct Arena {
    cells: Vec<Cell>,
    free: Vec<usize>,
    retired: Vec<usize>,
}

impl Arena {
    fn try_reserve(&mut self, count: usize) -> Result<(), TryReserveError> {
        let missing = count.saturating_sub(self.free.len());
        self.cells.try_reserve(missing)?;
        // Every cell can enter either index; reserve before exposing a cell.
        let total = self.cells.len() + missing;
        self.free
            .try_reserve(total.saturating_sub(self.free.len()))?;
        self.retired
            .try_reserve(total.saturating_sub(self.retired.len()))?;
        for _ in 0..missing {
            let index = self.cells.len();
            self.cells.push(Cell::Vacant);
            self.free.push(index);
        }
        Ok(())
    }

    fn insert(&mut self, index: usize, record: RetiredThreadRecord) {
        self.cells[index] = Cell::Retired(record);
        self.retired.push(index);
    }
}

#[derive(Debug, Default)]
pub(super) struct RetiredThreads {
    arena: Arc<Mutex<Arena>>,
}

pub(super) struct RetiredRecords<'a>(MutexGuard<'a, Arena>);

impl RetiredRecords<'_> {
    pub(super) fn iter(&self) -> impl Iterator<Item = &RetiredThreadRecord> {
        self.0
            .retired
            .iter()
            .map(|index| match &self.0.cells[*index] {
                Cell::Retired(record) => record,
                _ => carrick_fatal::carrick_fatal!(
                    "thread::retirement",
                    "retired census lost its cell"
                ),
            })
    }
}

impl RetiredThreads {
    pub(super) fn reserve(&self) -> Result<RetirementReservation, TryReserveError> {
        let mut arena = self.arena.lock();
        arena.try_reserve(1)?;
        let index = arena.free.pop().unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!(
                "thread::retirement",
                "reserved cell absent from free index"
            )
        });
        arena.cells[index] = Cell::Reserved;
        Ok(RetirementReservation {
            arena: self.arena.clone(),
            index,
            active: true,
        })
    }

    pub(super) fn try_reserve_exact(&self, count: usize) -> Result<(), TryReserveError> {
        self.arena.lock().try_reserve(count)
    }

    pub(super) fn records(&self) -> RetiredRecords<'_> {
        RetiredRecords(self.arena.lock())
    }

    pub(super) fn len(&self) -> usize {
        self.arena.lock().retired.len()
    }

    pub(super) fn push(&self, record: RetiredThreadRecord) {
        let mut arena = self.arena.lock();
        if arena.free.is_empty() {
            // Infallible-allocation host publication preserves Vec::push's
            // original allocation policy; EL1 publication never enters this.
            let total = arena.cells.len() + 1;
            let free_extra = total.saturating_sub(arena.free.len());
            let retired_extra = total.saturating_sub(arena.retired.len());
            arena.free.reserve(free_extra);
            arena.retired.reserve(retired_extra);
            let index = arena.cells.len();
            arena.cells.push(Cell::Vacant);
            arena.free.push(index);
        }
        let index = arena.free.pop().unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!(
                "thread::retirement",
                "host cell absent after storage growth"
            )
        });
        arena.insert(index, record);
    }

    pub(super) fn push_reserved(
        &self,
        mut reservation: RetirementReservation,
        record: RetiredThreadRecord,
    ) {
        if !Arc::ptr_eq(&self.arena, &reservation.arena) {
            carrick_fatal::carrick_fatal!(
                "thread::retirement",
                "retirement crossed registry owner"
            );
        }
        let mut arena = self.arena.lock();
        if !matches!(arena.cells[reservation.index], Cell::Reserved) {
            carrick_fatal::carrick_fatal!("thread::retirement", "retirement lease lost its cell");
        }
        arena.insert(reservation.index, record);
        reservation.active = false;
    }

    pub(super) fn retain(&self, mut keep: impl FnMut(&RetiredThreadRecord) -> bool) {
        let mut arena = self.arena.lock();
        let mut position = 0;
        while position < arena.retired.len() {
            let index = arena.retired[position];
            let retained = match &arena.cells[index] {
                Cell::Retired(record) => keep(record),
                _ => carrick_fatal::carrick_fatal!(
                    "thread::retirement",
                    "retirement index lost record"
                ),
            };
            if retained {
                position += 1;
            } else {
                arena.retired.swap_remove(position);
                arena.cells[index] = Cell::Vacant;
                arena.free.push(index);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.arena.lock().cells.capacity()
    }
}

/// Sole ownership of one cell. Dropping an unconsumed reservation makes it
/// available again; consuming it transfers custody to the registry's census.
#[derive(Debug)]
pub(super) struct RetirementReservation {
    arena: Arc<Mutex<Arena>>,
    index: usize,
    active: bool,
}

impl Drop for RetirementReservation {
    fn drop(&mut self) {
        if self.active {
            let mut arena = self.arena.lock();
            if !matches!(arena.cells[self.index], Cell::Reserved) {
                carrick_fatal::carrick_fatal!(
                    "thread::retirement",
                    "retirement reservation was reused"
                );
            }
            arena.cells[self.index] = Cell::Vacant;
            arena.free.push(self.index);
        }
    }
}
