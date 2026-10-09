//! Stopped-CPU physical table loans and root exit for owner-selected native fork.
//! The caller retains the supervisor stack record across the physical crossing.
//!
//! On x86, this crossing is driven by synchronous port I/O over [`FORK_STOCK_PORT`],
//! [`NATIVE_ROOT_EXIT_PORT`] and [`NATIVE_CHILD_RETIRE_PORT`]. On AArch64, it is
//! driven by `HVC #6` using [`GRANT_OP_FORK_STOCK`], [`GRANT_OP_ROOT_EXIT`] and
//! [`GRANT_OP_CHILD_RETIRE`].
//!
//! The record wire layouts and alignment are ISA-neutral and 100% byte-identical
//! across platforms.

use crate::{
    ExecutionBinding, PortalForkRequest, PortalForkTableArena, PortalOperation,
    ReservationGeneration, ReservationMm,
};
use carrick_guest_arch::{AddressContext, Asid, KernelVa, RootGpa};
use core::num::NonZeroU64;

#[allow(unused_imports)]
pub use crate::{GRANT_OP_CHILD_RETIRE, GRANT_OP_FORK_STOCK, GRANT_OP_ROOT_EXIT};

/// x86 synchronous I/O port for physical fork stock loans and settlements.
pub const FORK_STOCK_PORT: u16 = 0xd2;
/// x86 synchronous I/O port for container root termination notification.
pub const NATIVE_ROOT_EXIT_PORT: u16 = 0xd3;
/// x86 synchronous I/O port for native peer readiness notification.
pub const NATIVE_PEER_READY_PORT: u16 = 0xd4;
/// x86 synchronous I/O port for [`NativeChildRetire`], the twin of AArch64
/// `HVC #6` with [`GRANT_OP_CHILD_RETIRE`].
pub const NATIVE_CHILD_RETIRE_PORT: u16 = 0xd5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkStockKind {
    Loan,
    Commit,
    Abort,
}

impl ForkStockKind {
    pub const fn word(self) -> u64 {
        match self {
            Self::Loan => 0x4352_464b_4c4f_414e,
            Self::Commit => 0x4352_464b_434f_4d4d,
            Self::Abort => 0x4352_464b_4142_4f52,
        }
    }

    pub fn decode(word: u64) -> Option<Self> {
        [Self::Loan, Self::Commit, Self::Abort]
            .into_iter()
            .find(|kind| kind.word() == word)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkLifecycleLoan {
    pub page: KernelVa,
    pub controls: KernelVa,
}

impl ForkLifecycleLoan {
    pub const ARM_DEFAULT: Self = Self {
        page: KernelVa::new(crate::EL1_DYNAMIC_METADATA_BASE + 0x4000),
        controls: KernelVa::new(crate::EL1_DYNAMIC_METADATA_BASE + 0x5000),
    };

    pub const X86_DEFAULT: Self = Self {
        page: KernelVa::new(crate::X86_CPL0_DYNAMIC_METADATA_BASE + 0x4000),
        controls: KernelVa::new(crate::X86_CPL0_DYNAMIC_METADATA_BASE + 0x5000),
    };

    /// Validates and constructs a lifecycle loan within either the x86 or ARM
    /// dynamic metadata aperture.
    pub fn new(page: KernelVa, controls: KernelVa) -> Option<Self> {
        let is_valid_for = |base: u64| -> bool {
            let Some(limit) = base.checked_add(crate::EL1_DYNAMIC_METADATA_SIZE) else {
                return false;
            };
            let Some(page_end) = page
                .raw()
                .checked_add(core::mem::size_of::<crate::ThreadLifecyclePage>() as u64)
            else {
                return false;
            };
            let Some(controls_end) = controls.raw().checked_add(
                core::mem::size_of::<crate::ThreadControlSlot>() as u64
                    * (crate::THREAD_POOL_ENTRIES as u64 + 1),
            ) else {
                return false;
            };
            page.raw() >= base
                && page_end <= limit
                && page.raw().is_multiple_of(16384)
                && controls.raw() >= base
                && controls_end <= limit
                && controls
                    .raw()
                    .is_multiple_of(core::mem::align_of::<crate::ThreadControlSlot>() as u64)
                && (page_end <= controls.raw() || controls_end <= page.raw())
        };
        #[cfg(not(target_os = "none"))]
        let is_valid_host = || -> bool {
            let Some(page_end) = page
                .raw()
                .checked_add(core::mem::size_of::<crate::ThreadLifecyclePage>() as u64)
            else {
                return false;
            };
            let Some(controls_end) = controls.raw().checked_add(
                core::mem::size_of::<crate::ThreadControlSlot>() as u64
                    * (crate::THREAD_POOL_ENTRIES as u64 + 1),
            ) else {
                return false;
            };
            page.raw() >= 0x1_0000
                && page.raw().is_multiple_of(16384)
                && controls.raw() >= 0x1_0000
                && controls
                    .raw()
                    .is_multiple_of(core::mem::align_of::<crate::ThreadControlSlot>() as u64)
                && (page_end <= controls.raw() || controls_end <= page.raw())
        };
        #[allow(unused_mut)]
        let mut valid = is_valid_for(crate::X86_CPL0_DYNAMIC_METADATA_BASE)
            || is_valid_for(crate::EL1_DYNAMIC_METADATA_BASE);
        #[cfg(not(target_os = "none"))]
        {
            valid = valid || is_valid_host();
        }
        valid.then_some(Self { page, controls })
    }

    /// Explicit constructor checking bounds against a designated metadata base.
    pub fn new_for_base(base: u64, page: KernelVa, controls: KernelVa) -> Option<Self> {
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
pub struct ForkStockRequest {
    pub binding: ExecutionBinding,
    pub context: AddressContext<RootGpa>,
    pub operation: PortalOperation,
    pub parent_generation: ReservationGeneration,
    pub child_mm: ReservationMm,
    pub child_bytes: u64,
    pub parent_bytes: u64,
}

impl ForkStockRequest {
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
        lifecycle: ForkLifecycleLoan,
        asid: Option<Asid>,
    ) -> Option<ForkStockLoan> {
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
        .then_some(ForkStockLoan {
            id: loan,
            request,
            lifecycle,
            asid,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkStockLoan {
    pub id: NonZeroU64,
    pub request: PortalForkRequest,
    pub lifecycle: ForkLifecycleLoan,
    pub asid: Option<Asid>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkStockRefusal {
    Invalid,
    Stale,
    Capacity,
    Inventory,
}

/// All words are checked before constructing nonzero semantic domains.
/// This stack record is exclusive to its stopped CPU; it is not a shared queue.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct ForkStockExchange {
    pub tag: u64,
    pub request: [u64; 15],
    pub response: [u64; 6],
    pub status: u64,
    pub _reserved: u64,
}

impl ForkStockExchange {
    pub fn new(request: ForkStockRequest) -> Option<Self> {
        request.valid().then_some(Self {
            tag: ForkStockKind::Loan.word(),
            _reserved: 0,
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

    pub fn request(&self) -> Option<ForkStockRequest> {
        use crate::{EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration};
        use carrick_guest_arch::{ContextGeneration, FrameGpa, MmGeneration};
        if ForkStockKind::decode(self.tag) != Some(ForkStockKind::Loan) {
            return None;
        }
        if self.status == 0 && self._reserved != 0 {
            return None;
        }
        let w = self.request;
        let request = ForkStockRequest {
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
        lifecycle: ForkLifecycleLoan,
        asid: Option<Asid>,
    ) -> bool {
        if self.status != 0
            || self
                .request()
                .and_then(|request| {
                    request.admit_loan(
                        child_base,
                        parent_base,
                        kernel_control_ipa,
                        id,
                        lifecycle,
                        asid,
                    )
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
        self._reserved = asid.map_or(0, |a| u64::from(a.raw()));
        self.status = 1;
        true
    }

    pub fn refuse(&mut self, refusal: ForkStockRefusal) -> bool {
        if self.status != 0 {
            return false;
        }
        self.response[0] = match refusal {
            ForkStockRefusal::Invalid => 1,
            ForkStockRefusal::Stale => 2,
            ForkStockRefusal::Capacity => 3,
            ForkStockRefusal::Inventory => 4,
        };
        self._reserved = 0;
        self.status = 2;
        true
    }

    pub fn take(
        &mut self,
        expected: ForkStockRequest,
    ) -> Option<Result<ForkStockLoan, ForkStockRefusal>> {
        if self.request()? != expected {
            return None;
        }
        let result = match self.status {
            1 => {
                let asid = if self._reserved == 0 {
                    None
                } else {
                    let raw = u16::try_from(self._reserved).ok()?;
                    let nonzero = core::num::NonZeroU16::new(raw)?;
                    Some(Asid::from_registry_allocation(nonzero))
                };
                Ok(expected.admit_loan(
                    self.response[0],
                    self.response[1],
                    self.response[2],
                    NonZeroU64::new(self.response[3])?,
                    ForkLifecycleLoan::new(
                        KernelVa::new(self.response[4]),
                        KernelVa::new(self.response[5]),
                    )?,
                    asid,
                )?)
            }
            2 => Err(match self.response[0] {
                1 => ForkStockRefusal::Invalid,
                2 => ForkStockRefusal::Stale,
                3 => ForkStockRefusal::Capacity,
                4 => ForkStockRefusal::Inventory,
                _ => return None,
            }),
            _ => return None,
        };
        self.status = 3;
        Some(result)
    }

    pub fn status(&self) -> u64 {
        self.status
    }

    pub fn raw_words(&self) -> [u64; 24] {
        let mut words = [0; 24];
        words[0] = self.tag;
        words[1..16].copy_from_slice(&self.request);
        words[16..22].copy_from_slice(&self.response);
        words[22] = self.status;
        words[23] = self._reserved;
        words
    }

    pub fn from_raw_words(words: [u64; 24]) -> Self {
        let mut request = [0; 15];
        request.copy_from_slice(&words[1..16]);
        let mut response = [0; 6];
        response.copy_from_slice(&words[16..22]);
        Self {
            tag: words[0],
            request,
            response,
            status: words[22],
            _reserved: words[23],
        }
    }
}

/// VM termination notification after the shared root owner's exit receipt.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct NativeRootExit {
    pub words: [u64; 8],
}

impl NativeRootExit {
    pub const MAGIC: u64 = 0x4352_524f_4f54_4558;

    pub fn new(
        binding: ExecutionBinding,
        status: carrick_sched_core::process::LinuxWaitStatus,
    ) -> Option<Self> {
        if !binding.issued()
            || binding.mm.raw() == 0
            || binding.thread_generation.raw() == 0
            || status.raw() < 0
            || status.raw() & !0xff00 != 0
        {
            return None;
        }
        Some(Self {
            words: [
                0x4352_524f_4f54_4558,
                binding.task.raw(),
                binding.generation.raw(),
                binding.mm.raw(),
                binding.thread_generation.raw(),
                status.raw() as u64,
                0,
                0,
            ],
        })
    }

    pub fn status_for(
        &self,
        expected: ExecutionBinding,
    ) -> Option<carrick_sched_core::process::LinuxWaitStatus> {
        if self.words[..5]
            != [
                0x4352_524f_4f54_4558,
                expected.task.raw(),
                expected.generation.raw(),
                expected.mm.raw(),
                expected.thread_generation.raw(),
            ]
            || self.words[5] & !0xff00 != 0
            || self.words[6..] != [0; 2]
        {
            return None;
        }
        Some(
            carrick_sched_core::process::LinuxWaitStatus::from_wait_encoding(
                i32::try_from(self.words[5]).ok()?,
            ),
        )
    }

    pub fn raw_words(&self) -> [u64; 8] {
        self.words
    }

    pub fn from_raw_words(words: [u64; 8]) -> Self {
        Self { words }
    }
}

/// A child process has left the shared owner graph. Its physical table pages
/// enter quarantine until no live slot owns the MM and its ASID is flushed.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct NativeChildRetire {
    pub words: [u64; 8],
}

impl NativeChildRetire {
    pub const MAGIC: u64 = 0x4352_4348_5245_5449;

    pub fn new(binding: ExecutionBinding, context: AddressContext<RootGpa>) -> Option<Self> {
        (binding.issued() && binding.mm.raw() == context.mm.raw().get()).then_some(Self {
            words: [
                Self::MAGIC,
                binding.task.raw(),
                binding.generation.raw(),
                binding.mm.raw(),
                binding.thread_generation.raw(),
                context.root.address().raw(),
                context.generation.raw().get(),
                0,
            ],
        })
    }

    pub fn matches(&self, binding: ExecutionBinding, context: AddressContext<RootGpa>) -> bool {
        self.words
            == [
                Self::MAGIC,
                binding.task.raw(),
                binding.generation.raw(),
                binding.mm.raw(),
                binding.thread_generation.raw(),
                context.root.address().raw(),
                context.generation.raw().get(),
                0,
            ]
    }
}

/// Exact stopped-CPU completion of a retained physical loan. Every word is
/// initialized; no Rust enum or nonzero representation is read from guest bytes.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct ForkStockSettlement {
    pub words: [u64; 16],
}

impl ForkStockSettlement {
    pub fn new(
        loan: ForkStockLoan,
        completion: crate::PortalForkCompletion,
        custody: KernelVa,
        count: u64,
    ) -> Option<Self> {
        if completion.request != loan.request
            || count.checked_mul(32).is_none()
            || !custody.raw().is_multiple_of(8)
            || custody.raw().checked_add(count.checked_mul(32)?).is_none()
        {
            return None;
        }
        let mut words = [0; 16];
        words[..8].copy_from_slice(&[
            ForkStockKind::Commit.word(),
            loan.id.get(),
            completion.child.incarnation().get(),
            completion.parent_generation.raw(),
            completion.child_tables_used,
            completion.parent_tables_used,
            custody.raw(),
            count,
        ]);
        let result = Self { words };
        result.request(loan)?;
        Some(result)
    }

    pub fn abort(loan: ForkStockLoan) -> Self {
        let mut words = [0; 16];
        words[0] = ForkStockKind::Abort.word();
        words[1] = loan.id.get();
        Self { words }
    }

    pub fn request(
        &self,
        loan: ForkStockLoan,
    ) -> Option<(crate::PortalForkCompletion, KernelVa, u64)> {
        let w = self.words;
        if ForkStockKind::decode(w[0]) != Some(ForkStockKind::Commit) || w[1] != loan.id.get() {
            return None;
        }
        let completion = crate::PortalForkCompletion {
            request: loan.request,
            // SAFETY: this checked physical receipt names the exact retained
            // loan's admitted child; it never grants authority to select an MM.
            child: unsafe {
                crate::El1MmHandle::from_admitted_owner(
                    loan.request.operation.carrier,
                    loan.request.child_mm,
                    NonZeroU64::new(w[2])?,
                )
            },
            parent_generation: ReservationGeneration::new(w[3])?,
            child_tables_used: w[4],
            parent_tables_used: w[5],
        };
        if completion.child_tables_used == 0
            || !completion.child_tables_used.is_multiple_of(4096)
            || completion.child_tables_used > loan.request.child_tables.len
            || !completion.parent_tables_used.is_multiple_of(4096)
            || completion.parent_tables_used > loan.request.parent_tables.len
            || !w[6].is_multiple_of(8)
            || w[6].checked_add(w[7].checked_mul(32)?).is_none()
        {
            return None;
        }
        Some((completion, KernelVa::new(w[6]), w[7]))
    }

    pub fn abort_matches(&self, loan: ForkStockLoan) -> bool {
        self.words[0] == ForkStockKind::Abort.word()
            && self.words[1] == loan.id.get()
            && self.words[2..8] == [0; 6]
    }

    pub fn accept(&mut self, loan: ForkStockLoan) -> bool {
        if self.words[8] != 0 || (self.request(loan).is_none() && !self.abort_matches(loan)) {
            return false;
        }
        self.words[8] = 1;
        true
    }

    pub fn refuse(&mut self, refusal: ForkStockRefusal) -> bool {
        if self.words[8] != 0 {
            return false;
        }
        self.words[8] = 2;
        self.words[9] = match refusal {
            ForkStockRefusal::Invalid => 1,
            ForkStockRefusal::Stale => 2,
            ForkStockRefusal::Capacity => 3,
            ForkStockRefusal::Inventory => 4,
        };
        true
    }

    pub fn take(&mut self, loan: ForkStockLoan) -> Option<Result<(), ForkStockRefusal>> {
        if self.request(loan).is_none() && !self.abort_matches(loan) {
            return None;
        }
        let result = match self.words[8] {
            1 => Ok(()),
            2 => Err(match self.words[9] {
                1 => ForkStockRefusal::Invalid,
                2 => ForkStockRefusal::Stale,
                3 => ForkStockRefusal::Capacity,
                4 => ForkStockRefusal::Inventory,
                _ => return None,
            }),
            _ => return None,
        };
        self.words[8] = 3;
        Some(result)
    }

    pub fn raw_words(&self) -> [u64; 16] {
        self.words
    }

    pub fn from_raw_words(words: [u64; 16]) -> Self {
        Self { words }
    }
}

const _: () = {
    // 1. Wire size constants (exact bytes matching origin/main x86 layout)
    assert!(core::mem::size_of::<ForkStockExchange>() == 24 * 8);
    assert!(core::mem::size_of::<ForkStockSettlement>() == 16 * 8);
    assert!(core::mem::size_of::<NativeRootExit>() == 8 * 8);
    assert!(core::mem::size_of::<NativeChildRetire>() == 8 * 8);

    // 2. Wire alignment constants
    assert!(core::mem::align_of::<ForkStockExchange>() == 64);
    assert!(core::mem::align_of::<ForkStockSettlement>() == 64);
    assert!(core::mem::align_of::<NativeRootExit>() == 64);
    assert!(core::mem::align_of::<NativeChildRetire>() == 64);

    // 3. Exact field byte offsets against the previous x86 layout (origin/main)
    assert!(core::mem::offset_of!(ForkStockExchange, tag) == 0);
    assert!(core::mem::offset_of!(ForkStockExchange, request) == 8);
    assert!(core::mem::offset_of!(ForkStockExchange, response) == 128);
    assert!(core::mem::offset_of!(ForkStockExchange, status) == 176);
    assert!(core::mem::offset_of!(ForkStockExchange, _reserved) == 184);

    assert!(core::mem::offset_of!(ForkStockSettlement, words) == 0);
    assert!(core::mem::offset_of!(NativeRootExit, words) == 0);

    // 4. Magic words and port numbers
    assert!(ForkStockKind::Loan.word() == 0x4352_464b_4c4f_414e);
    assert!(ForkStockKind::Commit.word() == 0x4352_464b_434f_4d4d);
    assert!(ForkStockKind::Abort.word() == 0x4352_464b_4142_4f52);
    assert!(NativeRootExit::MAGIC == 0x4352_524f_4f54_4558);
    assert!(FORK_STOCK_PORT == 0xd2);
    assert!(NATIVE_ROOT_EXIT_PORT == 0xd3);
    assert!(NATIVE_PEER_READY_PORT == 0xd4);
    assert!(NATIVE_CHILD_RETIRE_PORT == 0xd5);
    assert!(NativeChildRetire::MAGIC == 0x4352_4348_5245_5449);
    assert!(GRANT_OP_CHILD_RETIRE == 5);
    assert!(GRANT_OP_FORK_STOCK == 3);
    assert!(GRANT_OP_ROOT_EXIT == 4);
};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration};
    use carrick_guest_arch::{ContextGeneration, FrameGpa, MmGeneration};

    fn lifecycle_x86() -> ForkLifecycleLoan {
        assert_eq!(
            ForkLifecycleLoan::new(
                ForkLifecycleLoan::X86_DEFAULT.page,
                ForkLifecycleLoan::X86_DEFAULT.controls
            ),
            Some(ForkLifecycleLoan::X86_DEFAULT)
        );
        ForkLifecycleLoan::X86_DEFAULT
    }

    fn lifecycle_arm() -> ForkLifecycleLoan {
        assert_eq!(
            ForkLifecycleLoan::new(
                ForkLifecycleLoan::ARM_DEFAULT.page,
                ForkLifecycleLoan::ARM_DEFAULT.controls
            ),
            Some(ForkLifecycleLoan::ARM_DEFAULT)
        );
        ForkLifecycleLoan::ARM_DEFAULT
    }

    fn request() -> ForkStockRequest {
        ForkStockRequest {
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
    fn lifecycle_loan_supports_both_x86_and_arm_metadata_bases() {
        assert!(lifecycle_x86().page.raw() >= crate::X86_CPL0_DYNAMIC_METADATA_BASE);
        assert!(lifecycle_arm().page.raw() >= crate::EL1_DYNAMIC_METADATA_BASE);
        // Misaligned or out of bounds is refused
        assert!(ForkLifecycleLoan::new(KernelVa::new(0x1000), KernelVa::new(0x2000)).is_none());
    }

    #[test]
    fn native_root_exit_refuses_foreign_execution_and_non_exit_status() {
        use carrick_sched_core::process::LinuxWaitStatus;
        let binding = request().binding;
        let status = LinuxWaitStatus::from_wait_encoding(37 << 8);
        let record = NativeRootExit::new(binding, status).unwrap();
        assert_eq!(record.status_for(binding), Some(status));
        let mut foreign = binding;
        foreign.generation = EntryGeneration::from_raw(binding.generation.raw() + 1);
        assert!(record.status_for(foreign).is_none());
        let mut foreign = binding;
        foreign.mm = EntryMmKey::from_raw(binding.mm.raw() + 1);
        assert!(record.status_for(foreign).is_none());
        assert!(NativeRootExit::new(binding, LinuxWaitStatus::from_wait_encoding(9)).is_none());
    }

    #[test]
    fn physical_fork_settlement_refuses_foreign_loan_and_reused_completion() {
        let request = request();
        let loan = request
            .admit_loan(
                0x20000,
                0x30000,
                0x100000000,
                NonZeroU64::MIN,
                lifecycle_arm(),
                None,
            )
            .unwrap();
        let completion = crate::PortalForkCompletion {
            request: loan.request,
            child: unsafe {
                crate::El1MmHandle::from_admitted_owner(
                    request.operation.carrier,
                    request.child_mm,
                    NonZeroU64::MIN,
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 0,
        };
        let mut record =
            ForkStockSettlement::new(loan, completion, KernelVa::new(0xffff_8000_0001_0000), 1)
                .unwrap();
        let foreign = ForkStockLoan {
            id: NonZeroU64::new(2).unwrap(),
            ..loan
        };
        assert!(record.request(foreign).is_none());
        assert!(record.accept(loan));
        assert_eq!(record.take(loan), Some(Ok(())));
        assert!(record.take(loan).is_none());
        let mut abort = ForkStockSettlement::abort(loan);
        assert!(!abort.abort_matches(foreign));
        assert!(abort.accept(loan));
        assert_eq!(abort.take(loan), Some(Ok(())));
    }

    #[test]
    fn physical_stock_tag_refuses_foreign_and_settlement_records() {
        assert_eq!(
            ForkStockKind::decode(ForkStockKind::Loan.word()),
            Some(ForkStockKind::Loan)
        );
        assert!(ForkStockKind::decode(0).is_none());
        let mut exchange = ForkStockExchange::new(request()).unwrap();
        exchange.tag = ForkStockKind::Commit.word();
        assert!(exchange.request().is_none());
    }

    #[test]
    fn native_fork_table_loan_authenticates_mm_and_disjoint_exact_capacity() {
        let request = request();
        assert!(request.valid());
        let loan = request
            .admit_loan(
                0x20000,
                0x30000,
                0x100000000,
                NonZeroU64::MIN,
                lifecycle_arm(),
                None,
            )
            .unwrap();
        assert_eq!(loan.request.operation, request.operation);
        assert_eq!(loan.request.child_mm, request.child_mm);
        assert_eq!(loan.request.child_tables.len, request.child_bytes);
        assert_eq!(loan.request.parent_tables.len, request.parent_bytes);
        assert!(
            request
                .admit_loan(
                    0x20000,
                    0x21000,
                    0x100000000,
                    NonZeroU64::MIN,
                    lifecycle_arm(),
                    None,
                )
                .is_none()
        );
        assert!(
            request
                .admit_loan(
                    0x1000,
                    0x30000,
                    0x100000000,
                    NonZeroU64::MIN,
                    lifecycle_arm(),
                    None,
                )
                .is_none()
        );
        assert!(
            !ForkStockRequest {
                binding: ExecutionBinding {
                    mm: EntryMmKey::from_raw(302),
                    ..request.binding
                },
                ..request
            }
            .valid()
        );
        assert!(
            !ForkStockRequest {
                child_mm: request.operation.mm,
                ..request
            }
            .valid()
        );
        assert!(
            !ForkStockRequest {
                child_bytes: u64::MAX,
                ..request
            }
            .valid()
        );
    }

    #[test]
    fn native_fork_table_reply_retains_request_and_consumes_once() {
        let request = request();
        let mut exchange = ForkStockExchange::new(request).unwrap();
        assert!(exchange.take(request).is_none());
        assert!(exchange.grant(
            0x20000,
            0x30000,
            0x100000000,
            NonZeroU64::MIN,
            lifecycle_arm(),
            None,
        ));
        assert_eq!(exchange.request(), Some(request));
        let mut other = request;
        other.operation.sequence = NonZeroU64::new(3).unwrap();
        assert!(exchange.take(other).is_none());
        assert_eq!(
            exchange.take(request).unwrap().unwrap().request.child_mm,
            request.child_mm
        );
        assert!(exchange.take(request).is_none());
        assert!(!exchange.grant(
            0x40000,
            0x50000,
            0x100000000,
            NonZeroU64::MIN,
            lifecycle_arm(),
            None,
        ));
        let mut refused = ForkStockExchange::new(request).unwrap();
        assert!(refused.refuse(ForkStockRefusal::Capacity));
        assert_eq!(refused.take(request), Some(Err(ForkStockRefusal::Capacity)));
        assert!(refused.take(request).is_none());
    }

    #[test]
    fn raw_words_round_trip_preserves_wire_layout() {
        let request = request();
        let exchange = ForkStockExchange::new(request).unwrap();
        let words = exchange.raw_words();
        let restored = ForkStockExchange::from_raw_words(words);
        assert_eq!(restored.request(), Some(request));

        let binding = request.binding;
        let status = carrick_sched_core::process::LinuxWaitStatus::from_wait_encoding(12 << 8);
        let root_exit = NativeRootExit::new(binding, status).unwrap();
        let exit_words = root_exit.raw_words();
        let restored_exit = NativeRootExit::from_raw_words(exit_words);
        assert_eq!(restored_exit.status_for(binding), Some(status));
    }

    #[test]
    fn pre_change_x86_layout_wire_byte_identity() {
        use core::mem::{align_of, offset_of, size_of};

        // 1. Layout manifest matching pre-change X86ForkStockExchange, X86ForkStockSettlement, X86NativeRootExit
        assert_eq!(size_of::<ForkStockExchange>(), 24 * 8);
        assert_eq!(align_of::<ForkStockExchange>(), 64);
        assert_eq!(offset_of!(ForkStockExchange, tag), 0);
        assert_eq!(offset_of!(ForkStockExchange, request), 8);
        assert_eq!(offset_of!(ForkStockExchange, response), 128);
        assert_eq!(offset_of!(ForkStockExchange, status), 176);
        assert_eq!(offset_of!(ForkStockExchange, _reserved), 184);

        assert_eq!(size_of::<ForkStockSettlement>(), 16 * 8);
        assert_eq!(align_of::<ForkStockSettlement>(), 64);
        assert_eq!(offset_of!(ForkStockSettlement, words), 0);

        assert_eq!(size_of::<NativeRootExit>(), 8 * 8);
        assert_eq!(align_of::<NativeRootExit>(), 64);
        assert_eq!(offset_of!(NativeRootExit, words), 0);

        // 2. Wire word position verification: every field in ForkStockExchange
        // must land at the exact byte offset dictated by origin/main's x86 wire encoding
        let req = request();
        let mut exchange = ForkStockExchange::new(req).unwrap();
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw const exchange).cast::<u8>(),
                size_of::<ForkStockExchange>(),
            )
        };

        // tag: offset 0..8
        assert_eq!(
            u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
            ForkStockKind::Loan.word()
        );
        // request.binding.task: offset 8..16
        assert_eq!(
            u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
            req.binding.task.raw()
        );
        // request.binding.generation: offset 16..24
        assert_eq!(
            u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
            req.binding.generation.raw()
        );
        // request.binding.mm: offset 24..32
        assert_eq!(
            u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
            req.binding.mm.raw()
        );
        // request.binding.thread_generation: offset 32..40
        assert_eq!(
            u64::from_ne_bytes(bytes[32..40].try_into().unwrap()),
            req.binding.thread_generation.raw()
        );
        // request.context.mm: offset 40..48
        assert_eq!(
            u64::from_ne_bytes(bytes[40..48].try_into().unwrap()),
            req.context.mm.raw().get()
        );
        // request.context.root: offset 48..56
        assert_eq!(
            u64::from_ne_bytes(bytes[48..56].try_into().unwrap()),
            req.context.root.address().raw()
        );
        // request.context.generation: offset 56..64
        assert_eq!(
            u64::from_ne_bytes(bytes[56..64].try_into().unwrap()),
            req.context.generation.raw().get()
        );
        // request.operation.carrier: offset 64..72
        assert_eq!(
            u64::from_ne_bytes(bytes[64..72].try_into().unwrap()),
            req.operation.carrier.get()
        );
        // request.operation.mm: offset 72..80
        assert_eq!(
            u64::from_ne_bytes(bytes[72..80].try_into().unwrap()),
            req.operation.mm.raw()
        );
        // request.operation.incarnation: offset 80..88
        assert_eq!(
            u64::from_ne_bytes(bytes[80..88].try_into().unwrap()),
            req.operation.incarnation.get()
        );
        // request.operation.sequence: offset 88..96
        assert_eq!(
            u64::from_ne_bytes(bytes[88..96].try_into().unwrap()),
            req.operation.sequence.get()
        );
        // request.parent_generation: offset 96..104
        assert_eq!(
            u64::from_ne_bytes(bytes[96..104].try_into().unwrap()),
            req.parent_generation.raw()
        );
        // request.child_mm: offset 104..112
        assert_eq!(
            u64::from_ne_bytes(bytes[104..112].try_into().unwrap()),
            req.child_mm.raw()
        );
        // request.child_bytes: offset 112..120
        assert_eq!(
            u64::from_ne_bytes(bytes[112..120].try_into().unwrap()),
            req.child_bytes
        );
        // request.parent_bytes: offset 120..128
        assert_eq!(
            u64::from_ne_bytes(bytes[120..128].try_into().unwrap()),
            req.parent_bytes
        );

        // Grant response
        let lifecycle = lifecycle_x86();
        let loan_id = NonZeroU64::new(42).unwrap();
        assert!(exchange.grant(0x20000, 0x30000, 0x100000000, loan_id, lifecycle, None));
        let granted_bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw const exchange).cast::<u8>(),
                size_of::<ForkStockExchange>(),
            )
        };
        // response.child_base: offset 128..136
        assert_eq!(
            u64::from_ne_bytes(granted_bytes[128..136].try_into().unwrap()),
            0x20000
        );
        // response.parent_base: offset 136..144
        assert_eq!(
            u64::from_ne_bytes(granted_bytes[136..144].try_into().unwrap()),
            0x30000
        );
        // response.kernel_control_ipa: offset 144..152
        assert_eq!(
            u64::from_ne_bytes(granted_bytes[144..152].try_into().unwrap()),
            0x100000000
        );
        // response.id: offset 152..160
        assert_eq!(
            u64::from_ne_bytes(granted_bytes[152..160].try_into().unwrap()),
            42
        );
        // response.lifecycle.page: offset 160..168
        assert_eq!(
            u64::from_ne_bytes(granted_bytes[160..168].try_into().unwrap()),
            lifecycle.page.raw()
        );
        // response.lifecycle.controls: offset 168..176
        assert_eq!(
            u64::from_ne_bytes(granted_bytes[168..176].try_into().unwrap()),
            lifecycle.controls.raw()
        );
        // status: offset 176..184 (1 = granted)
        assert_eq!(
            u64::from_ne_bytes(granted_bytes[176..184].try_into().unwrap()),
            1
        );
        // _reserved: offset 184..192 (0)
        assert_eq!(
            u64::from_ne_bytes(granted_bytes[184..192].try_into().unwrap()),
            0
        );

        // 3. Settlement wire layout
        let loan = req
            .admit_loan(0x20000, 0x30000, 0x100000000, loan_id, lifecycle, None)
            .unwrap();
        let completion = crate::PortalForkCompletion {
            request: loan.request,
            child: unsafe {
                crate::El1MmHandle::from_admitted_owner(
                    req.operation.carrier,
                    req.child_mm,
                    NonZeroU64::new(77).unwrap(),
                )
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 4096,
        };
        let settlement =
            ForkStockSettlement::new(loan, completion, KernelVa::new(0xffff_8000), 2).unwrap();
        let s_bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw const settlement).cast::<u8>(),
                size_of::<ForkStockSettlement>(),
            )
        };
        assert_eq!(
            u64::from_ne_bytes(s_bytes[0..8].try_into().unwrap()),
            ForkStockKind::Commit.word()
        );
        assert_eq!(
            u64::from_ne_bytes(s_bytes[8..16].try_into().unwrap()),
            loan_id.get()
        );
        assert_eq!(u64::from_ne_bytes(s_bytes[16..24].try_into().unwrap()), 77);
        assert_eq!(
            u64::from_ne_bytes(s_bytes[24..32].try_into().unwrap()),
            ReservationGeneration::INITIAL.raw()
        );
        assert_eq!(
            u64::from_ne_bytes(s_bytes[32..40].try_into().unwrap()),
            4096
        );
        assert_eq!(
            u64::from_ne_bytes(s_bytes[40..48].try_into().unwrap()),
            4096
        );
        assert_eq!(
            u64::from_ne_bytes(s_bytes[48..56].try_into().unwrap()),
            0xffff_8000
        );
        assert_eq!(u64::from_ne_bytes(s_bytes[56..64].try_into().unwrap()), 2);

        // 4. NativeRootExit wire layout
        let exit_status = carrick_sched_core::process::LinuxWaitStatus::from_wait_encoding(12 << 8);
        let root_exit = NativeRootExit::new(req.binding, exit_status).unwrap();
        let re_bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw const root_exit).cast::<u8>(),
                size_of::<NativeRootExit>(),
            )
        };
        assert_eq!(
            u64::from_ne_bytes(re_bytes[0..8].try_into().unwrap()),
            0x4352_524f_4f54_4558
        );
        assert_eq!(
            u64::from_ne_bytes(re_bytes[8..16].try_into().unwrap()),
            req.binding.task.raw()
        );
        assert_eq!(
            u64::from_ne_bytes(re_bytes[16..24].try_into().unwrap()),
            req.binding.generation.raw()
        );
        assert_eq!(
            u64::from_ne_bytes(re_bytes[24..32].try_into().unwrap()),
            req.binding.mm.raw()
        );
        assert_eq!(
            u64::from_ne_bytes(re_bytes[32..40].try_into().unwrap()),
            req.binding.thread_generation.raw()
        );
        assert_eq!(
            u64::from_ne_bytes(re_bytes[40..48].try_into().unwrap()),
            exit_status.raw() as u64
        );
        assert_eq!(u64::from_ne_bytes(re_bytes[48..56].try_into().unwrap()), 0);
        assert_eq!(u64::from_ne_bytes(re_bytes[56..64].try_into().unwrap()), 0);
    }

    #[test]
    fn asid_typed_round_trip_and_zero_unrepresentable() {
        use core::num::NonZeroU16;

        let request = request();
        let mut exchange = ForkStockExchange::new(request).unwrap();
        let asid = Asid::from_registry_allocation(NonZeroU16::new(42).unwrap());
        assert!(exchange.grant(
            0x20000,
            0x30000,
            0x100000000,
            NonZeroU64::new(1).unwrap(),
            lifecycle_arm(),
            Some(asid),
        ));
        assert_eq!(exchange._reserved, 42);
        let loan = exchange.take(request).unwrap().unwrap();
        assert_eq!(loan.asid, Some(asid));

        // When _reserved is 0, asid decodes to None (unrepresentable as 0-valued Asid)
        let mut exchange_zero = ForkStockExchange::new(request).unwrap();
        assert!(exchange_zero.grant(
            0x20000,
            0x30000,
            0x100000000,
            NonZeroU64::new(1).unwrap(),
            lifecycle_arm(),
            None,
        ));
        assert_eq!(exchange_zero._reserved, 0);
        let loan_zero = exchange_zero.take(request).unwrap().unwrap();
        assert_eq!(loan_zero.asid, None);
    }
}
