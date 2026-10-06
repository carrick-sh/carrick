//! Closed publication words for an MM-private identity control page.

/// Transport geometry, never permission to write a page or an owner receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityControlBase(u64);
impl IdentityControlBase {
    pub const fn new(address: u64) -> Option<Self> {
        if address != 0 && address & 4095 == 0 && address.checked_add(20).is_some() {
            Some(Self(address))
        } else {
            None
        }
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Kernel-selected control publication, distinct from Linux user copyout.
/// Core independently checks the whole named word before owner selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrickIdentityWrite {
    Pid(u32),
    ShimGate(u32),
    SyscallCount(u64),
    ClockGate(u32),
}
impl CarrickIdentityWrite {
    pub const fn offset(self) -> u64 {
        match self {
            Self::Pid(_) => 0,
            Self::ShimGate(_) => 4,
            Self::SyscallCount(_) => 8,
            Self::ClockGate(_) => 16,
        }
    }
    pub const fn address(self, base: IdentityControlBase) -> u64 {
        base.raw() + self.offset()
    }
    pub const fn len(self) -> usize {
        match self {
            Self::SyscallCount(_) => 8,
            _ => 4,
        }
    }
    pub const fn is_empty(self) -> bool {
        false
    }
    pub const fn bytes(self) -> [u8; 8] {
        match self {
            Self::Pid(value) | Self::ShimGate(value) | Self::ClockGate(value) => {
                (value as u64).to_le_bytes()
            }
            Self::SyscallCount(value) => value.to_le_bytes(),
        }
    }
    pub const fn authorizes(base: IdentityControlBase, address: u64, len: u64) -> bool {
        let Some(offset) = address.checked_sub(base.raw()) else {
            return false;
        };
        (len == 4 && (offset == 0 || offset == 4 || offset == 16)) || (len == 8 && offset == 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_writes_name_only_complete_publication_words() {
        for raw_base in [0x002d_001e_4000, 0x4400_0000] {
            let base = IdentityControlBase::new(raw_base).unwrap();
            for word in [
                CarrickIdentityWrite::Pid(701),
                CarrickIdentityWrite::ShimGate(0),
                CarrickIdentityWrite::SyscallCount(0),
                CarrickIdentityWrite::ClockGate(1),
            ] {
                assert!(CarrickIdentityWrite::authorizes(
                    base,
                    word.address(base),
                    word.len() as u64
                ));
                assert!(!CarrickIdentityWrite::authorizes(
                    base,
                    word.address(base),
                    word.len() as u64 - 1
                ));
            }
            for (address, len) in [
                (raw_base, 8),
                (raw_base + 7, 8),
                (raw_base + 20, 4),
                (raw_base + 0x4000, 4),
                (raw_base - 4, 4),
                (u64::MAX, 4),
                (raw_base, 0),
                (raw_base, u64::MAX),
            ] {
                assert!(!CarrickIdentityWrite::authorizes(base, address, len));
            }
        }
        for address in [0, 7, u64::MAX] {
            assert_eq!(IdentityControlBase::new(address), None);
        }
    }
}
