//! The host's lock order for an exec crossing on a stopped CPU (#1093 S4c):
//! the stopped-CPU lease, then the exec preparations (validate and release),
//! then the root-release lease, then the zone bind, then the fork stock.
//!
//! The type enforces **phase sequencing** and **lock exclusion** for the
//! owners passed through it (#2192): each phase consumes the one before it,
//! the order holds both owners from its first phase on, and a phase gets
//! only its owner's *state*, through [`ExecPhaseOwner::with_state`], for the
//! length of the phase. The owner itself, and any lock guard it takes,
//! never reach the phase, and the state borrow is higher-ranked, so neither
//! can ride out through the phase's result or a capture. A handle reachable
//! outside the order (a global named directly inside a phase) is the
//! caller's to keep out. In order, it reads:
//!
//! ```
//! # use carrick_hal::exec_lock_order::{ExecCrossingOrder, Exclusive};
//! # fn order(cpu: carrick_guest_arch::CpuId) {
//! let (mut preparations, mut stock) = (0_u32, 0_u32);
//! let (released, ()) = ExecCrossingOrder::on_stopped(
//!     cpu,
//!     Exclusive(&mut preparations),
//!     Exclusive(&mut stock),
//! )
//! .preparations(|_| ());
//! let (rooted, ()) = released.root_release(|| ());
//! let (bound, ()) = rooted.bind_zone(|| ());
//! bound.fork_stock(|stock| *stock += 1);
//! # }
//! ```
//!
//! Taking the stock first, taking it inside the preparations, or touching
//! the preparations before the stock phase ends does not compile:
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::{ExecCrossingOrder, Exclusive};
//! # fn order(cpu: carrick_guest_arch::CpuId) {
//! let (mut preparations, mut stock) = (0_u32, 0_u32);
//! // No stock before the preparations are released.
//! ExecCrossingOrder::on_stopped(cpu, Exclusive(&mut preparations), Exclusive(&mut stock))
//!     .fork_stock(|_| ());
//! # }
//! ```
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::{ExecCrossingOrder, Exclusive};
//! # fn order(cpu: carrick_guest_arch::CpuId) {
//! let (mut preparations, mut stock) = (0_u32, 0_u32);
//! let order =
//!     ExecCrossingOrder::on_stopped(cpu, Exclusive(&mut preparations), Exclusive(&mut stock));
//! // The stock is borrowed by the order: not reachable inside the preparations.
//! order.preparations(|_| stock += 1);
//! # }
//! ```
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::{ExecCrossingOrder, Exclusive};
//! # fn order(cpu: carrick_guest_arch::CpuId) {
//! let (mut preparations, mut stock) = (0_u32, 0_u32);
//! let (released, ()) =
//!     ExecCrossingOrder::on_stopped(cpu, Exclusive(&mut preparations), Exclusive(&mut stock))
//!         .preparations(|_| ());
//! let (rooted, ()) = released.root_release(|| ());
//! let (bound, ()) = rooted.bind_zone(|| ());
//! // The preparations stay borrowed until the stock phase ends.
//! bound.fork_stock(|_| preparations += 1);
//! # }
//! ```
//!
//! A mutex owner is locked for exactly its phase. The phase sees the data,
//! never the mutex, so the preparations' guard cannot ride out into the
//! stock phase:
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::ExecCrossingOrder;
//! # use carrick_guest_arch::CpuId;
//! # use std::sync::Mutex;
//! let preparations = Mutex::new(0_u32);
//! let stock = Mutex::new(0_u32);
//! let (released, held_preparations) =
//!     ExecCrossingOrder::on_stopped(CpuId::new(0), &preparations, &stock)
//!         .preparations(|p| p.lock().unwrap());
//! let (rooted, ()) = released.root_release(|| ());
//! let (bound, ()) = rooted.bind_zone(|| ());
//! bound.fork_stock(|_| assert!(preparations.try_lock().is_err()));
//! drop(held_preparations);
//! ```
//!
//! nor can a phase's state borrow be parked in a captured slot or returned:
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::{ExecCrossingOrder, Exclusive};
//! # fn order(cpu: carrick_guest_arch::CpuId) {
//! let (mut preparations, mut stock) = (0_u32, 0_u32);
//! let mut slot = None;
//! let (_released, ()) =
//!     ExecCrossingOrder::on_stopped(cpu, Exclusive(&mut preparations), Exclusive(&mut stock))
//!         .preparations(|preparations| slot = Some(preparations));
//! # }
//! ```
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::ExecCrossingOrder;
//! # use carrick_guest_arch::CpuId;
//! # use std::sync::Mutex;
//! let (preparations, stock) = (Mutex::new(0_u32), Mutex::new(0_u32));
//! let (_released, state) = ExecCrossingOrder::on_stopped(CpuId::new(0), &preparations, &stock)
//!     .preparations(|p| p);
//! ```
//!
//! #2192, the re-review's counterexample: owners that are `'static`
//! handles to `static` mutexes. Through the order, the preparations phase
//! sees only their data, so the guard it would hold through the stock
//! phase is not reachable:
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::ExecCrossingOrder;
//! # use carrick_guest_arch::CpuId;
//! # use std::sync::Mutex;
//! static PREPARATIONS: Mutex<u32> = Mutex::new(0);
//! static STOCK: Mutex<u32> = Mutex::new(0);
//! let (released, held_preparations) =
//!     ExecCrossingOrder::on_stopped(CpuId::new(0), &PREPARATIONS, &STOCK)
//!         .preparations(|p| p.lock().unwrap());
//! let (rooted, ()) = released.root_release(|| ());
//! let (bound, ()) = rooted.bind_zone(|| ());
//! bound.fork_stock(|s| {
//!     let _held_stock = s.lock().unwrap();
//!     assert!(PREPARATIONS.try_lock().is_err());
//! });
//! drop(held_preparations);
//! ```
//!
//! while the same owners serve each phase in turn, unlocked between them:
//!
//! ```
//! # use carrick_hal::exec_lock_order::ExecCrossingOrder;
//! # use carrick_guest_arch::CpuId;
//! # use std::sync::Mutex;
//! static PREPARATIONS: Mutex<u32> = Mutex::new(0);
//! static STOCK: Mutex<u32> = Mutex::new(4);
//! let (released, prepared) =
//!     ExecCrossingOrder::on_stopped(CpuId::new(0), &PREPARATIONS, &STOCK).preparations(|p| {
//!         *p += 1;
//!         *p
//!     });
//! let (rooted, ()) = released.root_release(|| ());
//! let (bound, ()) = rooted.bind_zone(|| ());
//! let left = bound.fork_stock(|s| {
//!     assert!(PREPARATIONS.try_lock().is_ok(), "released before the stock");
//!     *s -= 1;
//!     *s
//! });
//! assert_eq!((prepared, left), (1, 3));
//! ```
//!
//! The x86 fork commit already follows this order with no preparations at
//! all: physical custody, the stopped-CPU lease, then `ForkStock::settle`.
use carrick_guest_arch::CpuId;

/// An owner the exec order takes one phase at a time. It hands `phase` its
/// state for exactly the call, under whatever lock it holds, and releases
/// that lock before returning: nothing of the owner outlives the phase.
pub trait ExecPhaseOwner {
    type State: ?Sized;
    fn with_state<R>(&mut self, phase: impl FnOnce(&mut Self::State) -> R) -> R;
}

/// An exclusively borrowed owner (a field, a local): the borrow is its lock.
pub struct Exclusive<'a, T: ?Sized>(pub &'a mut T);

impl<T: ?Sized> ExecPhaseOwner for Exclusive<'_, T> {
    type State = T;
    fn with_state<R>(&mut self, phase: impl FnOnce(&mut T) -> R) -> R {
        phase(self.0)
    }
}

/// A mutex owner, locked for exactly its phase. A poisoned lock still
/// guards its data; the phase decides what a half-done edit means.
impl<T: ?Sized> ExecPhaseOwner for &std::sync::Mutex<T> {
    type State = T;
    fn with_state<R>(&mut self, phase: impl FnOnce(&mut T) -> R) -> R {
        let mut guard = self
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        phase(&mut guard)
    }
}

/// The first phase: a stopped CPU, holding the preparations and the stock
/// until each one's own phase.
#[must_use]
pub struct ExecCrossingOrder<P, S> {
    cpu: CpuId,
    preparations: P,
    stock: S,
}

/// The preparations are validated and released; the stock is still held.
#[must_use]
pub struct PreparationsReleased<P, S> {
    cpu: CpuId,
    /// Held, unreachable, until the stock phase ends.
    preparations: P,
    stock: S,
}

/// The root-release lease has run.
#[must_use]
pub struct RootReleased<P, S> {
    cpu: CpuId,
    /// Held, unreachable, until the stock phase ends.
    preparations: P,
    stock: S,
}

/// The successor's zone row is bound; only the stock remains.
#[must_use]
pub struct ZoneBound<P, S> {
    cpu: CpuId,
    /// Held, unreachable, until the stock phase ends.
    preparations: P,
    stock: S,
}

impl<P: ExecPhaseOwner, S: ExecPhaseOwner> ExecCrossingOrder<P, S> {
    /// Begin on `cpu`, stopped under the caller's lease.
    pub fn on_stopped(cpu: CpuId, preparations: P, stock: S) -> Self {
        Self {
            cpu,
            preparations,
            stock,
        }
    }

    pub fn cpu(&self) -> CpuId {
        self.cpu
    }

    /// Validate and release the exact preparation. Only the preparations'
    /// state is reachable here, and only for this call.
    pub fn preparations<R>(
        mut self,
        phase: impl FnOnce(&mut P::State) -> R,
    ) -> (PreparationsReleased<P, S>, R) {
        let result = self.preparations.with_state(phase);
        (
            PreparationsReleased {
                cpu: self.cpu,
                preparations: self.preparations,
                stock: self.stock,
            },
            result,
        )
    }
}

impl<P: ExecPhaseOwner, S: ExecPhaseOwner> PreparationsReleased<P, S> {
    pub fn cpu(&self) -> CpuId {
        self.cpu
    }

    /// Run the root-release lease's phase.
    pub fn root_release<R>(self, phase: impl FnOnce() -> R) -> (RootReleased<P, S>, R) {
        let result = phase();
        (
            RootReleased {
                cpu: self.cpu,
                preparations: self.preparations,
                stock: self.stock,
            },
            result,
        )
    }
}

impl<P: ExecPhaseOwner, S: ExecPhaseOwner> RootReleased<P, S> {
    pub fn cpu(&self) -> CpuId {
        self.cpu
    }

    /// Bind the successor's zone row.
    pub fn bind_zone<R>(self, phase: impl FnOnce() -> R) -> (ZoneBound<P, S>, R) {
        let result = phase();
        (
            ZoneBound {
                cpu: self.cpu,
                preparations: self.preparations,
                stock: self.stock,
            },
            result,
        )
    }
}

impl<P: ExecPhaseOwner, S: ExecPhaseOwner> ZoneBound<P, S> {
    pub fn cpu(&self) -> CpuId {
        self.cpu
    }

    /// The last phase: the fork stock, with the preparations long released.
    pub fn fork_stock<R>(mut self, phase: impl FnOnce(&mut S::State) -> R) -> R {
        let result = self.stock.with_state(phase);
        drop(self.preparations);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_phases_run_in_the_design_order_and_any_phase_may_stop() {
        let cpu = CpuId::new(1);
        let mut log = std::vec::Vec::new();
        let (mut preparations, mut stock) = (vec![7_u32], 3_u32);
        let order =
            ExecCrossingOrder::on_stopped(cpu, Exclusive(&mut preparations), Exclusive(&mut stock));
        assert_eq!(order.cpu(), cpu);
        let (released, prepared) = order.preparations(|preparations| {
            log.push("preparations");
            preparations.pop()
        });
        assert_eq!(prepared, Some(7));
        let (rooted, ()) = released.root_release(|| log.push("root-release"));
        let (bound, ()) = rooted.bind_zone(|| log.push("zone-bind"));
        assert_eq!(bound.cpu(), cpu);
        let left = bound.fork_stock(|stock| {
            log.push("fork-stock");
            *stock -= 1;
            *stock
        });
        assert_eq!(left, 2);
        assert_eq!(
            log,
            ["preparations", "root-release", "zone-bind", "fork-stock"]
        );
        assert!(preparations.is_empty());

        // A refused validation stops the crossing; the stock is untouched.
        let mut stock = 3_u32;
        let mut preparations = std::vec::Vec::<u32>::new();
        let (released, prepared) =
            ExecCrossingOrder::on_stopped(cpu, Exclusive(&mut preparations), Exclusive(&mut stock))
                .preparations(|preparations| preparations.pop());
        assert_eq!(prepared, None);
        drop(released);
        assert_eq!(stock, 3);
    }

    /// #2192: mutex owners are locked for exactly their phase, so the
    /// preparations are unlocked before the stock phase locks the stock.
    #[test]
    fn mutex_owners_are_locked_only_for_their_own_phase() {
        let preparations = std::sync::Mutex::new(1_u32);
        let stock = std::sync::Mutex::new(2_u32);
        let (released, ()) = ExecCrossingOrder::on_stopped(CpuId::new(0), &preparations, &stock)
            .preparations(|p| {
                assert!(stock.try_lock().is_ok(), "the stock is not locked yet");
                *p += 1;
            });
        let (rooted, ()) = released.root_release(|| {
            assert!(preparations.try_lock().is_ok());
        });
        let (bound, ()) = rooted.bind_zone(|| ());
        bound.fork_stock(|s| {
            assert!(preparations.try_lock().is_ok(), "released before the stock");
            *s += 1;
        });
        assert_eq!(*preparations.lock().unwrap(), 2);
        assert_eq!(*stock.lock().unwrap(), 3);
    }
}
