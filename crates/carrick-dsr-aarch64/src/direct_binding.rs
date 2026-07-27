//! Typed process-local direct-binding cells and immutable target descriptors.

use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

use carrick_guest_mem::GuestVa;

use crate::shared_cache::SharedLoadedTranslationUnit;
use crate::types::{CodeGeneration, DsrError};

/// Dense identity of one unresolved direct-binding stub in a translation unit.
#[repr(transparent)]
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct DirectBindingOrdinal(u32);

impl DirectBindingOrdinal {
    /// Claims an ordinal already validated against its owning manifest.
    pub const fn claimed(value: u32) -> Self {
        Self(value)
    }

    /// Returns the manifest ordinal.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Host virtual address of one mapped, naturally aligned binding cell.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DirectBindingCellVa(usize);

impl DirectBindingCellVa {
    /// Validates a non-null, naturally aligned mapped-cell address.
    pub fn mapped(value: usize) -> Option<Self> {
        let alignment = std::mem::align_of::<AtomicPtr<DirectBindingTarget>>();
        (value != 0 && value.is_multiple_of(alignment)).then_some(Self(value))
    }

    /// Returns the mapped host address.
    pub const fn get(self) -> usize {
        self.0
    }
}

/// Fixed translated-code ABI prefix acquired through a binding cell.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectBindingTargetPrefix {
    pub target_cache_pc: u64,
    pub cache_start: u64,
    pub cache_end: u64,
    pub generation_bindings: u64,
}

const _: () = assert!(std::mem::size_of::<DirectBindingTargetPrefix>() == 32);
const _: () = assert!(std::mem::offset_of!(DirectBindingTargetPrefix, target_cache_pc) == 0);
const _: () = assert!(std::mem::offset_of!(DirectBindingTargetPrefix, generation_bindings) == 24);
const _: () = assert!(std::mem::align_of::<AtomicPtr<DirectBindingTarget>>() == 8);

/// Process-owner token for one append-only private JIT address epoch.
#[derive(Debug)]
pub struct PrivateJitEpoch {
    _private: (),
}

impl PrivateJitEpoch {
    /// Creates the sole process-owner reference for a new private JIT epoch.
    pub fn process_owner() -> Arc<Self> {
        Arc::new(Self { _private: () })
    }

    /// Reports descriptor leases in addition to the process-owner reference.
    pub fn live_descriptor_leases(process_owner: &Arc<Self>) -> usize {
        Arc::strong_count(process_owner).saturating_sub(1)
    }
}

/// Immutable target, authority, generation identity, and lifetime lease.
#[repr(C)]
pub struct DirectBindingTarget {
    pub prefix: DirectBindingTargetPrefix,
    target_page: GuestVa,
    target_generation: CodeGeneration,
    private_epoch: Option<Arc<PrivateJitEpoch>>,
    shared_lease: Option<SharedLoadedTranslationUnit>,
}

impl DirectBindingTarget {
    /// Constructs a target backed by the current append-only private JIT epoch.
    pub fn private(
        prefix: DirectBindingTargetPrefix,
        target_page: GuestVa,
        target_generation: CodeGeneration,
        process_epoch: &Arc<PrivateJitEpoch>,
    ) -> Self {
        Self {
            prefix,
            target_page,
            target_generation,
            private_epoch: Some(Arc::clone(process_epoch)),
            shared_lease: None,
        }
    }

    /// Constructs a target backed by an exact loaded shared-unit lease.
    pub fn shared(
        prefix: DirectBindingTargetPrefix,
        target_page: GuestVa,
        target_generation: CodeGeneration,
        shared_lease: SharedLoadedTranslationUnit,
    ) -> Self {
        Self {
            prefix,
            target_page,
            target_generation,
            private_epoch: None,
            shared_lease: Some(shared_lease),
        }
    }

    /// Returns the guest page whose generation owns this target.
    pub const fn target_page(&self) -> GuestVa {
        self.target_page
    }

    /// Returns the guest-code generation whose bytes this target executes.
    pub const fn target_generation(&self) -> CodeGeneration {
        self.target_generation
    }

    /// Returns the retained private JIT epoch, when this is a private target.
    pub fn private_epoch(&self) -> Option<&Arc<PrivateJitEpoch>> {
        self.private_epoch.as_ref()
    }

    /// Returns the retained shared-unit lease, when this is a shared target.
    pub fn shared_lease(&self) -> Option<&SharedLoadedTranslationUnit> {
        self.shared_lease.as_ref()
    }
}

/// Cold-path identity of the exact direct-binding cell that missed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectBindingMiss {
    pub cell: DirectBindingCellVa,
    pub ordinal: DirectBindingOrdinal,
}

/// The sole adapter from a validated mapped-cell address to atomic operations.
#[derive(Clone, Copy, Debug)]
pub struct DirectBindingCellRef {
    address: DirectBindingCellVa,
}

impl DirectBindingCellRef {
    /// Creates an atomic adapter for a live writable binding cell.
    ///
    /// # Safety
    ///
    /// `address` must point to a mapped, writable, initialized
    /// `AtomicPtr<DirectBindingTarget>` that remains live for every copied
    /// adapter and every operation performed through it.
    pub unsafe fn from_mapped_address(address: DirectBindingCellVa) -> Result<Self, DsrError> {
        let value = address.get();
        let alignment = std::mem::align_of::<AtomicPtr<DirectBindingTarget>>();
        if value == 0 || !value.is_multiple_of(alignment) {
            return Err(DsrError::CachePolicy(format!(
                "direct-binding cell address 0x{value:x} is not naturally aligned"
            )));
        }
        Ok(Self { address })
    }

    /// Acquires the complete immutable descriptor currently published.
    pub fn load_acquire(self) -> *mut DirectBindingTarget {
        self.cell().load(Ordering::Acquire)
    }

    /// Release-publishes `target` only when the cell is null.
    pub fn publish_null(
        self,
        target: *mut DirectBindingTarget,
    ) -> Result<(), *mut DirectBindingTarget> {
        self.cell()
            .compare_exchange(
                std::ptr::null_mut(),
                target,
                Ordering::Release,
                Ordering::Acquire,
            )
            .map(|_| ())
    }

    /// Clears the cell only if it still contains `expected`.
    pub fn clear_if(self, expected: *mut DirectBindingTarget) -> bool {
        self.cell()
            .compare_exchange(
                expected,
                std::ptr::null_mut(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Release-clears the cell after callers have established quiescence.
    pub fn clear_release(self) {
        self.cell().store(std::ptr::null_mut(), Ordering::Release);
    }

    fn cell(self) -> &'static AtomicPtr<DirectBindingTarget> {
        // SAFETY: `from_mapped_address` requires this address to identify a
        // live initialized `AtomicPtr` for the lifetime of every copied
        // adapter. All mapped-cell access is centralized in this adapter.
        unsafe { &*(self.address.get() as *const AtomicPtr<DirectBindingTarget>) }
    }
}
