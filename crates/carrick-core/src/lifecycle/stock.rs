//! Standing thread-birth stock policy shared by host and native owners.
use super::{GateState, Lifecycle};

pub const DEFAULT_THREAD_POOL_DEPTH: usize = 4;

/// The graph adapter retains identity, control and limit custody before it
/// publishes a stock entry. A refusal leaves all of that custody with it.
pub trait ThreadStock {
    fn page(&self) -> &dyn Lifecycle;
    fn standing(&self) -> usize;
    fn reserve_and_stock(&mut self) -> bool;
}

/// Refill after a birth or retirement, through the same admission transaction
/// as initial stock. Closed admission never acquires a new reservation.
pub fn replenish(stock: &mut impl ThreadStock, depth: usize) {
    while stock.page().gate() == GateState::Open && stock.standing() < depth {
        if !stock.reserve_and_stock() {
            break;
        }
    }
}
