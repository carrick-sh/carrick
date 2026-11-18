//! ISA-neutral stage-1 translation vocabulary shared by every walker.
//!
//! A [`Stage1Walker`] is one ISA's architectural walk over a
//! [`LiveDescriptorWords`] graph. It returns an *unauthenticated* leaf whose
//! [`LeafSpan`] the caller's inventory authenticates; descriptor-memory
//! refusal is a [`WalkError::Refusal`], never a guest fault. ISA faults,
//! walk contexts and leaf records stay associated types of each walker.

use carrick_guest_arch::{FrameGpa, GuestVa};

use crate::descriptor_refusal::DescriptorRefusal;
use crate::live_descriptor_words::LiveDescriptorWords;

/// Bytes in one 4 KiB translation granule page.
const PAGE: u64 = 4096;

/// The direction of one stage-1 access: a load, a store or an instruction
/// fetch. AArch64 decodes it from an EL0 fault syndrome; the x86 descriptor
/// path re-exports it as `x86::descriptor_txn::Access`, the same type:
///
/// ```
/// use carrick_mmu_core::{aarch64, stage1::LeafAccess, x86::descriptor_txn::Access};
/// let x86: LeafAccess = Access::Write;
/// let arm: aarch64::LeafAccess = x86;
/// assert_eq!(arm, LeafAccess::Write);
/// ```
///
/// The discriminants are the wire encoding of the
/// `hvpatch__stale__stage1__retry` probe's access argument; [`Self::wire`]
/// and [`Self::from_wire`] are the explicit conversions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LeafAccess {
    Read = 0,
    Write = 1,
    Execute = 2,
}

impl LeafAccess {
    /// Every direction, in wire order.
    pub const ALL: [Self; 3] = [Self::Read, Self::Write, Self::Execute];

    /// The `hvpatch__stale__stage1__retry` probe's access argument.
    pub const fn wire(self) -> u32 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Execute => 2,
        }
    }

    /// Decode a probe access argument; `None` for anything else.
    pub const fn from_wire(wire: u32) -> Option<Self> {
        match wire {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Execute),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafSize {
    Page,
    Block2M,
    Block1G,
}
impl LeafSize {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Page => PAGE,
            Self::Block2M => 1 << 21,
            Self::Block1G => 1 << 30,
        }
    }
}

/// The output span one stage-1 leaf maps: a size-aligned base and a
/// power-of-two size of at least one 4 KiB page. It carries no host geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafSpan {
    base: FrameGpa,
    bytes: u64,
}

impl LeafSpan {
    /// `None` unless `bytes` is a power of two of at least 4 KiB and `base`
    /// is aligned to it.
    pub const fn new(base: FrameGpa, bytes: u64) -> Option<Self> {
        if bytes < PAGE || !bytes.is_power_of_two() || base.raw() & (bytes - 1) != 0 {
            return None;
        }
        Some(Self { base, bytes })
    }

    /// The span of a leaf of `bytes` that translates to `output`. A size
    /// that is not a power of two of at least 4 KiB is taken as one 4 KiB
    /// page: a span is never wider than the leaf proves.
    pub const fn containing(output: FrameGpa, bytes: u64) -> Self {
        let bytes = if bytes >= PAGE && bytes.is_power_of_two() {
            bytes
        } else {
            PAGE
        };
        Self {
            base: FrameGpa::new(output.raw() & !(bytes - 1)),
            bytes,
        }
    }

    pub const fn base(self) -> FrameGpa {
        self.base
    }

    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// Why a [`Stage1Walker`] produced no leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkError<F> {
    /// The architectural walk faulted; `F` is the ISA's own fault record.
    Fault(F),
    /// Descriptor memory refused a load or update. This is a host authority
    /// failure, not a guest translation fault.
    Refusal(DescriptorRefusal),
}

/// A translated stage-1 leaf, before any inventory authenticated it.
pub trait Stage1Leaf: Copy {
    /// Output address of the translated byte.
    fn output(&self) -> FrameGpa;
    /// The whole leaf's output span, for authentication and invalidation.
    fn span(&self) -> LeafSpan;
}

/// One ISA's architectural stage-1 walk. Callers dispatch statically, so a
/// generic caller monomorphizes to the ISA's own walk.
pub trait Stage1Walker {
    /// Translation regime and permission inputs (root, privilege, controls).
    type Context;
    /// The ISA's guest fault record.
    type Fault;
    /// The leaf record a successful walk returns.
    type Leaf: Stage1Leaf;

    /// Walk `va` for `access` through `words` under `context`.
    fn walk<D: LiveDescriptorWords + ?Sized>(
        &self,
        words: &D,
        context: &Self::Context,
        va: GuestVa,
        access: LeafAccess,
    ) -> Result<Self::Leaf, WalkError<Self::Fault>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof: both ISA paths name this one type.
    const fn from_x86(access: crate::x86::descriptor_txn::Access) -> LeafAccess {
        access
    }
    const fn from_aarch64(access: crate::aarch64::LeafAccess) -> LeafAccess {
        access
    }

    #[test]
    fn x86_and_aarch64_access_paths_are_leaf_access() {
        use core::any::TypeId;
        assert_eq!(
            TypeId::of::<crate::x86::descriptor_txn::Access>(),
            TypeId::of::<LeafAccess>()
        );
        assert_eq!(
            TypeId::of::<crate::aarch64::LeafAccess>(),
            TypeId::of::<LeafAccess>()
        );
        assert_eq!(from_x86(LeafAccess::Execute), LeafAccess::Execute);
        assert_eq!(from_aarch64(LeafAccess::Read), LeafAccess::Read);
    }

    #[test]
    fn stale_stage1_retry_wire_encoding_is_compatible() {
        // The probe call site encodes with `as u32`; both must agree with
        // the recorded wire values Read=0, Write=1, Execute=2.
        let wire = [
            (LeafAccess::Read, 0),
            (LeafAccess::Write, 1),
            (LeafAccess::Execute, 2),
        ];
        assert_eq!(LeafAccess::ALL.map(LeafAccess::wire), [0, 1, 2]);
        for (access, value) in wire {
            assert_eq!(access.wire(), value);
            assert_eq!(access as u32, value);
            assert_eq!(LeafAccess::from_wire(value), Some(access));
        }
        assert_eq!(LeafAccess::from_wire(3), None);
        assert_eq!(LeafAccess::from_wire(u32::MAX), None);
    }

    #[test]
    fn leaf_size_bytes_are_the_4k_granule_leaves() {
        assert_eq!(
            [LeafSize::Page, LeafSize::Block2M, LeafSize::Block1G].map(LeafSize::bytes),
            [4096, 2 << 20, 1 << 30]
        );
    }

    #[test]
    fn leaf_span_requires_an_aligned_power_of_two_of_at_least_a_page() {
        let span = |base, bytes| LeafSpan::new(FrameGpa::new(base), bytes);
        assert_eq!(span(0x20_0000, 1 << 21).map(LeafSpan::bytes), Some(1 << 21));
        assert_eq!(span(0x20_1000, 1 << 21), None);
        assert_eq!(span(0x1000, 0x800), None);
        assert_eq!(span(0x3000, 0x3000), None);
        let contained = LeafSpan::containing(FrameGpa::new(0x4567_8abc), 1 << 21);
        assert_eq!(
            (contained.base().raw(), contained.bytes()),
            (0x4560_0000, 1 << 21)
        );
        for odd in [0, 0x800, 0x3000] {
            let page = LeafSpan::containing(FrameGpa::new(0x4567_8abc), odd);
            assert_eq!((page.base().raw(), page.bytes()), (0x4567_8000, PAGE));
        }
    }
}
