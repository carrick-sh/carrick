//! The host's lock order for an exec crossing on a stopped CPU (#1093 S4c):
//! the stopped-CPU lease, then the exec preparations (validate and release),
//! then the root-release lease, then the zone bind, then the fork stock.
//!
//! Preparations and the fork stock are never held together. Each phase
//! consumes the one before it, and the order borrows both owners from its
//! first phase on, so the caller cannot reach either one except through its
//! phase. In order, it reads:
//!
//! ```
//! # use carrick_hal::exec_lock_order::ExecCrossingOrder;
//! # fn order(cpu: carrick_guest_arch::CpuId) {
//! let (mut preparations, mut stock) = (0_u32, 0_u32);
//! let (released, ()) =
//!     ExecCrossingOrder::on_stopped(cpu, &mut preparations, &mut stock).preparations(|_| ());
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
//! # use carrick_hal::exec_lock_order::ExecCrossingOrder;
//! # fn order(cpu: carrick_guest_arch::CpuId) {
//! let (mut preparations, mut stock) = (0_u32, 0_u32);
//! // No stock before the preparations are released.
//! ExecCrossingOrder::on_stopped(cpu, &mut preparations, &mut stock).fork_stock(|_| ());
//! # }
//! ```
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::ExecCrossingOrder;
//! # fn order(cpu: carrick_guest_arch::CpuId) {
//! let (mut preparations, mut stock) = (0_u32, 0_u32);
//! let order = ExecCrossingOrder::on_stopped(cpu, &mut preparations, &mut stock);
//! // The stock is borrowed by the order: not reachable inside the preparations.
//! order.preparations(|_| stock += 1);
//! # }
//! ```
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::ExecCrossingOrder;
//! # fn order(cpu: carrick_guest_arch::CpuId) {
//! let (mut preparations, mut stock) = (0_u32, 0_u32);
//! let (released, ()) =
//!     ExecCrossingOrder::on_stopped(cpu, &mut preparations, &mut stock).preparations(|_| ());
//! let (rooted, ()) = released.root_release(|| ());
//! let (bound, ()) = rooted.bind_zone(|| ());
//! // The preparations stay borrowed until the stock phase ends.
//! bound.fork_stock(|_| preparations += 1);
//! # }
//! ```
//!
//! A borrowed handle to a lock is not an owner: the order cannot hold it
//! exclusively, and a guard taken through it would outlive its phase. The
//! preparations' lock guard cannot ride out into the stock phase:
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::ExecCrossingOrder;
//! # use carrick_guest_arch::CpuId;
//! # use std::sync::Mutex;
//! let preparations = Mutex::new(0_u32);
//! let stock = Mutex::new(0_u32);
//! let mut prep_ref = &preparations;
//! let mut stock_ref = &stock;
//! let (released, held_preparations) =
//!     ExecCrossingOrder::on_stopped(CpuId::new(0), &mut prep_ref, &mut stock_ref)
//!         .preparations(|p| p.lock().unwrap());
//! let (rooted, ()) = released.root_release(|| ());
//! let (bound, ()) = rooted.bind_zone(|| ());
//! bound.fork_stock(|s| {
//!     let _held_stock = s.lock().unwrap();
//!     assert!(preparations.try_lock().is_err());
//! });
//! drop(held_preparations);
//! ```
//!
//! nor can the stock be locked from inside the preparations through one:
//!
//! ```compile_fail
//! # use carrick_hal::exec_lock_order::ExecCrossingOrder;
//! # use carrick_guest_arch::CpuId;
//! # use std::sync::Mutex;
//! let preparations = Mutex::new(0_u32);
//! let stock = Mutex::new(0_u32);
//! let (mut prep_ref, mut stock_ref) = (&preparations, &stock);
//! let order = ExecCrossingOrder::on_stopped(CpuId::new(0), &mut prep_ref, &mut stock_ref);
//! let (_released, ()) = order.preparations(|p| {
//!     let _held_preparations = p.lock().unwrap();
//!     let _held_stock = stock.lock().unwrap();
//! });
//! ```
//!
//! The x86 fork commit already follows this order with no preparations at
//! all: physical custody, the stopped-CPU lease, then `ForkStock::settle`.
use carrick_guest_arch::CpuId;

/// The first phase: a stopped CPU, holding the preparations and the stock
/// until each one's own phase.
#[must_use]
pub struct ExecCrossingOrder<'c, P, S> {
    cpu: CpuId,
    preparations: &'c mut P,
    stock: &'c mut S,
}

/// The preparations are validated and released; the stock is still held.
#[must_use]
pub struct PreparationsReleased<'c, S> {
    cpu: CpuId,
    stock: &'c mut S,
}

/// The root-release lease has run.
#[must_use]
pub struct RootReleased<'c, S> {
    cpu: CpuId,
    stock: &'c mut S,
}

/// The successor's zone row is bound; only the stock remains.
#[must_use]
pub struct ZoneBound<'c, S> {
    cpu: CpuId,
    stock: &'c mut S,
}

impl<'c, P, S> ExecCrossingOrder<'c, P, S> {
    /// Begin on `cpu`, stopped under the caller's lease.
    pub fn on_stopped(cpu: CpuId, preparations: &'c mut P, stock: &'c mut S) -> Self {
        Self {
            cpu,
            preparations,
            stock,
        }
    }

    pub fn cpu(&self) -> CpuId {
        self.cpu
    }

    /// Validate and release the exact preparation. Only the preparations
    /// are reachable here.
    pub fn preparations<R>(
        self,
        phase: impl FnOnce(&mut P) -> R,
    ) -> (PreparationsReleased<'c, S>, R) {
        let result = phase(self.preparations);
        (
            PreparationsReleased {
                cpu: self.cpu,
                stock: self.stock,
            },
            result,
        )
    }
}

impl<'c, S> PreparationsReleased<'c, S> {
    pub fn cpu(&self) -> CpuId {
        self.cpu
    }

    /// Run the root-release lease's phase.
    pub fn root_release<R>(self, phase: impl FnOnce() -> R) -> (RootReleased<'c, S>, R) {
        let result = phase();
        (
            RootReleased {
                cpu: self.cpu,
                stock: self.stock,
            },
            result,
        )
    }
}

impl<'c, S> RootReleased<'c, S> {
    pub fn cpu(&self) -> CpuId {
        self.cpu
    }

    /// Bind the successor's zone row.
    pub fn bind_zone<R>(self, phase: impl FnOnce() -> R) -> (ZoneBound<'c, S>, R) {
        let result = phase();
        (
            ZoneBound {
                cpu: self.cpu,
                stock: self.stock,
            },
            result,
        )
    }
}

impl<S> ZoneBound<'_, S> {
    pub fn cpu(&self) -> CpuId {
        self.cpu
    }

    /// The last phase: the fork stock, with the preparations long released.
    pub fn fork_stock<R>(self, phase: impl FnOnce(&mut S) -> R) -> R {
        phase(self.stock)
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
        let order = ExecCrossingOrder::on_stopped(cpu, &mut preparations, &mut stock);
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
            ExecCrossingOrder::on_stopped(cpu, &mut preparations, &mut stock)
                .preparations(|preparations| preparations.pop());
        assert_eq!(prepared, None);
        drop(released);
        assert_eq!(stock, 3);
    }
}
