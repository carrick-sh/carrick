//! Named Carrick-owned read windows shared by the host and EL1.

/// Fixed identity/control mapping. Its contents can change; its admitted
/// geometry is immutable and does not describe a Linux user VMA.
pub const CARRICK_IDENTITY_PAGE_BASE: u64 = 0x2D_001E_4000;
pub const CARRICK_IDENTITY_PAGE_SIZE: u64 = 0x4000;

/// A read capability for one named Carrick-owned window. This grants no write
/// authority and never converts an arbitrary user range into an internal one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrickInternalReadRange {
    address: u64,
    len: u64,
}

impl CarrickInternalReadRange {
    pub const fn identity(offset: u64, len: u64) -> Option<Self> {
        Self::within(
            CARRICK_IDENTITY_PAGE_BASE,
            CARRICK_IDENTITY_PAGE_SIZE,
            offset,
            len,
        )
    }

    pub const fn image_header(offset: u64, len: u64) -> Option<Self> {
        Self::within(
            crate::EL1_REGION_BASE + crate::EL1_IMAGE_OFFSET,
            4096,
            offset,
            len,
        )
    }

    const fn within(base: u64, size: u64, offset: u64, len: u64) -> Option<Self> {
        if len == 0 || offset >= size || len > size - offset {
            return None;
        }
        Some(Self {
            address: base + offset,
            len,
        })
    }

    pub const fn address(self) -> u64 {
        self.address
    }

    pub const fn len(self) -> u64 {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        false
    }

    /// EL1 independently validates an untrusted portal request against the
    /// same closed manifest; possession of a host value is not authentication.
    pub const fn authorizes(address: u64, len: u64) -> bool {
        let image = crate::EL1_REGION_BASE + crate::EL1_IMAGE_OFFSET;
        (address >= CARRICK_IDENTITY_PAGE_BASE
            && Self::identity(address - CARRICK_IDENTITY_PAGE_BASE, len).is_some())
            || (address >= image && Self::image_header(address - image, len).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_internal_reads_cannot_escape_their_windows() {
        let word = CarrickInternalReadRange::identity(4, 4).unwrap();
        assert_eq!(word.address(), 0x2d_001e_4004);
        assert!(CarrickInternalReadRange::authorizes(
            word.address(),
            word.len()
        ));
        assert!(CarrickInternalReadRange::identity(CARRICK_IDENTITY_PAGE_SIZE - 1, 2).is_none());
        assert!(CarrickInternalReadRange::identity(u64::MAX, 4).is_none());
        assert!(CarrickInternalReadRange::identity(0, u64::MAX).is_none());
        assert!(CarrickInternalReadRange::identity(0, 0).is_none());
        assert!(!CarrickInternalReadRange::authorizes(0x4000_0000, 4));
        assert!(!CarrickInternalReadRange::authorizes(u64::MAX, 4));
        assert!(!CarrickInternalReadRange::authorizes(
            CARRICK_IDENTITY_PAGE_BASE - 1,
            2
        ));
        assert!(CarrickInternalReadRange::image_header(4095, 1).is_some());
        assert!(CarrickInternalReadRange::image_header(4095, 2).is_none());
    }
}
