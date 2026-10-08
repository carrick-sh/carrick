//! Stopped-CPU physical table loans for an owner-selected native fork.
//! The caller retains the supervisor stack record across the physical crossing.
use crate::{
    ExecutionBinding, PortalForkRequest, PortalForkTableArena, PortalOperation,
    ReservationGeneration, ReservationMm,
};
use carrick_guest_arch::{AddressContext, KernelVa, RootGpa};
use core::num::NonZeroU64;

pub const X86_FORK_STOCK_PORT: u16 = 0xc7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86ForkLifecycleLoan {
    pub page: KernelVa,
    pub controls: KernelVa,
}
impl X86ForkLifecycleLoan {
    pub fn new(page: KernelVa, controls: KernelVa) -> Option<Self> {
        let base = crate::X86_CPL0_DYNAMIC_METADATA_BASE;
        let limit = base.checked_add(crate::EL1_DYNAMIC_METADATA_SIZE)?;
        let page_end = page
            .raw()
            .checked_add(core::mem::size_of::<crate::ThreadLifecyclePage>() as u64)?;
        let controls_end = controls.raw().checked_add(
            core::mem::size_of::<crate::ThreadControlSlot>() as u64
                * (crate::THREAD_POOL_ENTRIES as u64 + 1),
        )?;
        (page.raw() >= base
            && page_end <= limit
            && page.raw().is_multiple_of(16384)
            && controls.raw() >= base
            && controls_end <= limit
            && controls
                .raw()
                .is_multiple_of(core::mem::align_of::<crate::ThreadControlSlot>() as u64)
            && (page_end <= controls.raw() || controls_end <= page.raw()))
        .then_some(Self { page, controls })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86ForkStockRequest {
    pub binding: ExecutionBinding,
    pub context: AddressContext<RootGpa>,
    pub operation: PortalOperation,
    pub parent_generation: ReservationGeneration,
    pub child_mm: ReservationMm,
    pub child_bytes: u64,
    pub parent_bytes: u64,
}
impl X86ForkStockRequest {
    pub fn valid(self) -> bool {
        self.binding.issued()
            && self.binding.thread_generation.raw() != 0
            && self.binding.mm.raw() == self.operation.mm.raw()
            && self.context.mm.raw().get() == self.operation.mm.raw()
            && self.child_mm != self.operation.mm
            && self.child_bytes != 0
            && self.child_bytes.is_multiple_of(4096)
            && self.parent_bytes != 0
            && self.parent_bytes.is_multiple_of(4096)
            && self.child_bytes.checked_add(self.parent_bytes).is_some()
    }
    pub fn admit_loan(
        self,
        child_base: u64,
        parent_base: u64,
        kernel_control_ipa: u64,
        loan: NonZeroU64,
        lifecycle: X86ForkLifecycleLoan,
    ) -> Option<X86ForkStockLoan> {
        if !self.valid() {
            return None;
        }
        let child_tables = PortalForkTableArena::new(child_base, self.child_bytes)?;
        let parent_tables = PortalForkTableArena::new(parent_base, self.parent_bytes)?;
        let request = PortalForkRequest {
            operation: self.operation,
            parent_generation: self.parent_generation,
            child_mm: self.child_mm,
            child_tables,
            parent_tables,
            kernel_control_ipa,
        };
        (request.valid()
            && !child_tables.contains(self.context.root.address().raw())
            && !parent_tables.contains(self.context.root.address().raw()))
        .then_some(X86ForkStockLoan {
            id: loan,
            request,
            lifecycle,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86ForkStockLoan {
    pub id: NonZeroU64,
    pub request: PortalForkRequest,
    pub lifecycle: X86ForkLifecycleLoan,
}

/// All words are checked before constructing nonzero semantic domains.
/// This stack record is exclusive to its stopped CPU; it is not a shared queue.
#[repr(C, align(64))]
pub struct X86ForkStockExchange {
    request: [u64; 15],
    response: [u64; 6],
    status: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X86ForkStockRefusal {
    Invalid,
    Stale,
    Capacity,
    Inventory,
}
impl X86ForkStockExchange {
    pub fn new(request: X86ForkStockRequest) -> Option<Self> {
        request.valid().then_some(Self {
            request: [
                request.binding.task.raw(),
                request.binding.generation.raw(),
                request.binding.mm.raw(),
                request.binding.thread_generation.raw(),
                request.context.mm.raw().get(),
                request.context.root.address().raw(),
                request.context.generation.raw().get(),
                request.operation.carrier.get(),
                request.operation.mm.raw(),
                request.operation.incarnation.get(),
                request.operation.sequence.get(),
                request.parent_generation.raw(),
                request.child_mm.raw(),
                request.child_bytes,
                request.parent_bytes,
            ],
            response: [0; 6],
            status: 0,
        })
    }
    pub fn request(&self) -> Option<X86ForkStockRequest> {
        use crate::{EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration};
        use carrick_guest_arch::{ContextGeneration, FrameGpa, MmGeneration};
        let w = self.request;
        let request = X86ForkStockRequest {
            binding: ExecutionBinding {
                task: EntryTaskKey::from_raw(w[0]),
                generation: EntryGeneration::from_raw(w[1]),
                mm: EntryMmKey::from_raw(w[2]),
                thread_generation: EntryThreadGeneration::from_raw(w[3]),
            },
            context: AddressContext {
                mm: MmGeneration::new(NonZeroU64::new(w[4])?),
                root: RootGpa::page_aligned(FrameGpa::new(w[5]))?,
                generation: ContextGeneration::new(NonZeroU64::new(w[6])?),
            },
            operation: PortalOperation {
                carrier: NonZeroU64::new(w[7])?,
                mm: ReservationMm::new(w[8])?,
                incarnation: NonZeroU64::new(w[9])?,
                sequence: NonZeroU64::new(w[10])?,
            },
            parent_generation: ReservationGeneration::new(w[11])?,
            child_mm: ReservationMm::new(w[12])?,
            child_bytes: w[13],
            parent_bytes: w[14],
        };
        request.valid().then_some(request)
    }
    pub fn grant(
        &mut self,
        child_base: u64,
        parent_base: u64,
        kernel_control_ipa: u64,
        id: NonZeroU64,
        lifecycle: X86ForkLifecycleLoan,
    ) -> bool {
        if self.status != 0
            || self
                .request()
                .and_then(|request| {
                    request.admit_loan(child_base, parent_base, kernel_control_ipa, id, lifecycle)
                })
                .is_none()
        {
            return false;
        }
        self.response = [
            child_base,
            parent_base,
            kernel_control_ipa,
            id.get(),
            lifecycle.page.raw(),
            lifecycle.controls.raw(),
        ];
        self.status = 1;
        true
    }
    pub fn refuse(&mut self, refusal: X86ForkStockRefusal) -> bool {
        if self.status != 0 {
            return false;
        }
        self.response[0] = match refusal {
            X86ForkStockRefusal::Invalid => 1,
            X86ForkStockRefusal::Stale => 2,
            X86ForkStockRefusal::Capacity => 3,
            X86ForkStockRefusal::Inventory => 4,
        };
        self.status = 2;
        true
    }
    pub fn take(
        &mut self,
        expected: X86ForkStockRequest,
    ) -> Option<Result<X86ForkStockLoan, X86ForkStockRefusal>> {
        if self.request()? != expected {
            return None;
        }
        let result = match self.status {
            1 => Ok(expected.admit_loan(
                self.response[0],
                self.response[1],
                self.response[2],
                NonZeroU64::new(self.response[3])?,
                X86ForkLifecycleLoan::new(
                    KernelVa::new(self.response[4]),
                    KernelVa::new(self.response[5]),
                )?,
            )?),
            2 => Err(match self.response[0] {
                1 => X86ForkStockRefusal::Invalid,
                2 => X86ForkStockRefusal::Stale,
                3 => X86ForkStockRefusal::Capacity,
                4 => X86ForkStockRefusal::Inventory,
                _ => return None,
            }),
            _ => return None,
        };
        self.status = 3;
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration};
    use carrick_guest_arch::{ContextGeneration, FrameGpa, MmGeneration};
    fn lifecycle() -> X86ForkLifecycleLoan {
        let base = crate::X86_CPL0_DYNAMIC_METADATA_BASE;
        X86ForkLifecycleLoan::new(KernelVa::new(base + 0x4000), KernelVa::new(base + 0x5000))
            .unwrap()
    }
    fn request() -> X86ForkStockRequest {
        X86ForkStockRequest {
            binding: ExecutionBinding {
                task: EntryTaskKey::from_raw(41),
                generation: EntryGeneration::from_raw(11),
                mm: EntryMmKey::from_raw(301),
                thread_generation: EntryThreadGeneration::from_raw(101),
            },
            context: AddressContext {
                mm: MmGeneration::new(NonZeroU64::new(301).unwrap()),
                root: RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap(),
                generation: ContextGeneration::new(NonZeroU64::MIN),
            },
            operation: PortalOperation {
                carrier: NonZeroU64::new(7).unwrap(),
                mm: ReservationMm::new(301).unwrap(),
                incarnation: NonZeroU64::MIN,
                sequence: NonZeroU64::new(2).unwrap(),
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_mm: ReservationMm::new(302).unwrap(),
            child_bytes: 4 * 4096,
            parent_bytes: 4096,
        }
    }
    #[test]
    fn native_fork_table_loan_authenticates_mm_and_disjoint_exact_capacity() {
        let request = request();
        assert!(request.valid());
        let loan = request
            .admit_loan(0x20000, 0x30000, 0x100000000, NonZeroU64::MIN, lifecycle())
            .unwrap();
        assert_eq!(loan.request.operation, request.operation);
        assert_eq!(loan.request.child_mm, request.child_mm);
        assert_eq!(loan.request.child_tables.len, request.child_bytes);
        assert_eq!(loan.request.parent_tables.len, request.parent_bytes);
        assert!(
            request
                .admit_loan(0x20000, 0x21000, 0x100000000, NonZeroU64::MIN, lifecycle())
                .is_none()
        );
        assert!(
            request
                .admit_loan(0x1000, 0x30000, 0x100000000, NonZeroU64::MIN, lifecycle())
                .is_none()
        );
        assert!(
            !X86ForkStockRequest {
                binding: ExecutionBinding {
                    mm: EntryMmKey::from_raw(302),
                    ..request.binding
                },
                ..request
            }
            .valid()
        );
        assert!(
            !X86ForkStockRequest {
                child_mm: request.operation.mm,
                ..request
            }
            .valid()
        );
        assert!(
            !X86ForkStockRequest {
                child_bytes: u64::MAX,
                ..request
            }
            .valid()
        );
    }
    #[test]
    fn native_fork_table_reply_retains_request_and_consumes_once() {
        let request = request();
        let mut exchange = X86ForkStockExchange::new(request).unwrap();
        assert!(exchange.take(request).is_none());
        assert!(exchange.grant(0x20000, 0x30000, 0x100000000, NonZeroU64::MIN, lifecycle()));
        assert_eq!(exchange.request(), Some(request));
        let mut other = request;
        other.operation.sequence = NonZeroU64::new(3).unwrap();
        assert!(exchange.take(other).is_none());
        assert_eq!(
            exchange.take(request).unwrap().unwrap().request.child_mm,
            request.child_mm
        );
        assert!(exchange.take(request).is_none());
        assert!(!exchange.grant(0x40000, 0x50000, 0x100000000, NonZeroU64::MIN, lifecycle()));
        let mut refused = X86ForkStockExchange::new(request).unwrap();
        assert!(refused.refuse(X86ForkStockRefusal::Capacity));
        assert_eq!(
            refused.take(request),
            Some(Err(X86ForkStockRefusal::Capacity))
        );
        assert!(refused.take(request).is_none());
    }
}
