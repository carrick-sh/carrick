use std::ops::Range;

use carrick_guest_mem::{GuestVa, HostVa};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NativeHostBias(u64);

impl NativeHostBias {
    #[allow(dead_code)] // Staged for the biased-layout work in Tasks 2-7.
    pub(super) fn new(bias: u64, page_size: u64) -> Result<Self, NativeAddressError> {
        if bias == 0 || !page_size.is_power_of_two() || bias & page_size.saturating_sub(1) != 0 {
            return Err(NativeAddressError::InvalidBias { bias, page_size });
        }
        Ok(Self(bias))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeAddressMode {
    Direct,
    #[allow(dead_code)] // Staged for the biased-layout work in Tasks 2-7.
    Biased {
        host_bias: NativeHostBias,
    },
}

impl NativeAddressMode {
    #[allow(dead_code)] // Staged for the biased-layout work in Tasks 2-7.
    pub(super) fn to_host(self, address: GuestVa) -> Result<HostVa, NativeAddressError> {
        let bias = self.bias();
        let translated = address
            .raw()
            .checked_add(bias)
            .ok_or(NativeAddressError::Overflow {
                address: address.raw(),
                bias,
            })?;
        usize::try_from(translated)
            .map(HostVa)
            .map_err(|_| NativeAddressError::Overflow {
                address: address.raw(),
                bias,
            })
    }

    #[allow(dead_code)] // Staged for the biased-layout work in Tasks 2-7.
    pub(super) fn to_guest(self, address: HostVa) -> Result<GuestVa, NativeAddressError> {
        let address = address.raw() as u64;
        let bias = self.bias();
        address
            .checked_sub(bias)
            .map(GuestVa)
            .ok_or(NativeAddressError::BelowBias { address, bias })
    }

    #[allow(dead_code)] // Staged for the biased-layout work in Tasks 2-7.
    pub(super) fn to_host_range(
        self,
        range: Range<GuestVa>,
    ) -> Result<Range<HostVa>, NativeAddressError> {
        Ok(self.to_host(range.start)?..self.to_host(range.end)?)
    }

    #[allow(dead_code)] // Staged for the biased-layout work in Tasks 2-7.
    pub(super) fn to_guest_range(
        self,
        range: Range<HostVa>,
    ) -> Result<Range<GuestVa>, NativeAddressError> {
        Ok(self.to_guest(range.start)?..self.to_guest(range.end)?)
    }

    fn bias(self) -> u64 {
        match self {
            Self::Direct => 0,
            Self::Biased { host_bias } => host_bias.0,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Staged for the biased-layout work in Tasks 2-7.
pub(super) enum NativeAddressError {
    #[error("native host bias 0x{bias:x} is invalid for page size 0x{page_size:x}")]
    InvalidBias { bias: u64, page_size: u64 },
    #[error("native address translation overflow: address=0x{address:x} bias=0x{bias:x}")]
    Overflow { address: u64, bias: u64 },
    #[error("host address 0x{address:x} is below native bias 0x{bias:x}")]
    BelowBias { address: u64, bias: u64 },
}

#[cfg(test)]
mod tests {
    use super::{NativeAddressMode, NativeHostBias};
    use carrick_guest_mem::{GuestVa, HostVa};

    #[test]
    fn direct_mode_is_identity() {
        let mode = NativeAddressMode::Direct;
        assert_eq!(mode.to_host(GuestVa(0x4000)).unwrap(), HostVa(0x4000));
        assert_eq!(mode.to_guest(HostVa(0x4000)).unwrap(), GuestVa(0x4000));
    }

    #[test]
    fn biased_mode_round_trips_guest_addresses() {
        let bias = NativeHostBias::new(0x20_0000_0000, 0x4000).unwrap();
        let mode = NativeAddressMode::Biased { host_bias: bias };
        let host = mode.to_host(GuestVa(0x40_0000)).unwrap();
        assert_eq!(host, HostVa(0x20_0040_0000));
        assert_eq!(mode.to_guest(host).unwrap(), GuestVa(0x40_0000));
    }

    #[test]
    fn bias_rejects_zero_misalignment_and_overflow() {
        assert!(NativeHostBias::new(0x20_0000_0000, 0).is_err());
        assert!(NativeHostBias::new(0x20_0000_0000, 0x3000).is_err());
        assert!(NativeHostBias::new(0, 0x4000).is_err());
        assert!(NativeHostBias::new(0x20_0000_0001, 0x4000).is_err());
        let mode = NativeAddressMode::Biased {
            host_bias: NativeHostBias::new(u64::MAX & !0x3fff, 0x4000).unwrap(),
        };
        assert!(mode.to_host(GuestVa(0x4000)).is_err());
    }

    #[test]
    fn range_translation_checks_both_ends() {
        let mode = NativeAddressMode::Biased {
            host_bias: NativeHostBias::new(0x20_0000_0000, 0x4000).unwrap(),
        };
        assert_eq!(
            mode.to_host_range(GuestVa(0x4000)..GuestVa(0x8000))
                .unwrap(),
            HostVa(0x20_0000_4000)..HostVa(0x20_0000_8000)
        );
        assert_eq!(
            mode.to_guest_range(HostVa(0x20_0000_4000)..HostVa(0x20_0000_8000))
                .unwrap(),
            GuestVa(0x4000)..GuestVa(0x8000)
        );

        let near_end = NativeAddressMode::Biased {
            host_bias: NativeHostBias::new(u64::MAX & !0x3fff, 0x4000).unwrap(),
        };
        assert!(near_end.to_host_range(GuestVa(0)..GuestVa(0x4000)).is_err());
    }
}
