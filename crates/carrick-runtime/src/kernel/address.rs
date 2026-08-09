use std::num::NonZeroU16;

use carrick_guest_mem::Gpa;

const AARCH64_STAGE1_ROOT_ALIGNMENT: u64 = 4096;
const AARCH64_TTBR0_ROOT_MASK: u64 = (1_u64 << 48) - 1;

/// Nonzero AArch64 stage-1 address-space identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Asid(NonZeroU16);

impl Asid {
    pub(crate) const fn from_registry_allocation(raw: NonZeroU16) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u16 {
        self.0.get()
    }
}

/// Validated AArch64 4 KiB-granule stage-1 root guest-physical address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Stage1Root(Gpa);

impl Stage1Root {
    pub fn for_aarch64_4k(gpa: Gpa) -> Result<Self, Stage1RootError> {
        if gpa.raw() & (AARCH64_STAGE1_ROOT_ALIGNMENT - 1) != 0 {
            return Err(Stage1RootError::Unaligned(gpa));
        }
        if gpa.raw() & !AARCH64_TTBR0_ROOT_MASK != 0 {
            return Err(Stage1RootError::OutOfRange(gpa));
        }
        Ok(Self(gpa))
    }

    pub const fn gpa(self) -> Gpa {
        self.0
    }
}

/// A validated `TTBR0_EL1` value composed from typed ASID and root domains.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Ttbr0(u64);

impl Ttbr0 {
    pub const fn for_aarch64(asid: Asid, root: Stage1Root) -> Self {
        Self((asid.raw() as u64) << 48 | root.gpa().raw())
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Stage1RootError {
    #[error("stage-1 root GPA {0:?} is not 4 KiB aligned")]
    Unaligned(Gpa),
    #[error("stage-1 root GPA {0:?} does not fit TTBR0_EL1's 48-bit base field")]
    OutOfRange(Gpa),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asid(raw: u16) -> Asid {
        Asid::from_registry_allocation(NonZeroU16::new(raw).expect("nonzero test ASID"))
    }

    #[test]
    fn composes_validated_stage1_root_and_asid() {
        let root = Stage1Root::for_aarch64_4k(Gpa(0x1234_5000)).expect("aligned root");

        assert_eq!(
            Ttbr0::for_aarch64(asid(1), root).raw(),
            0x0001_0000_1234_5000
        );
    }

    #[test]
    fn rejects_unaligned_or_out_of_range_stage1_roots() {
        assert_eq!(
            Stage1Root::for_aarch64_4k(Gpa(0x1234_5001)),
            Err(Stage1RootError::Unaligned(Gpa(0x1234_5001)))
        );
        assert_eq!(
            Stage1Root::for_aarch64_4k(Gpa(0x0001_0000_0000_0000)),
            Err(Stage1RootError::OutOfRange(Gpa(0x0001_0000_0000_0000)))
        );
    }
}
