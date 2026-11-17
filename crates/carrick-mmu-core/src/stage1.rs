//! ISA-neutral stage-1 translation vocabulary shared by every walker.

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
}
