//! A live affinity binding whose allocation is retained by its scheduler owner.
use crate::affinity::AffinityAuthority;

/// Live dual-alias source encoding, folded into the carrier image ABI.
pub const AFFINITY_SOURCE_PROTOCOL: u64 = 1;

/// The two virtual aliases of one retained authority allocation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct AffinitySource {
    host: u64,
    guest: u64,
}
impl AffinitySource {
    pub const UNBOUND: Self = Self { host: 0, guest: 0 };

    /// Bind identical aliases, for an owner whose venues share an address.
    /// # Safety
    /// The authority must remain initialized at this address until every copy
    /// of the source retires, and that address must be readable in each venue.
    pub unsafe fn from_authority(authority: &AffinityAuthority) -> Self {
        let address = core::ptr::from_ref(authority).expose_provenance() as u64;
        Self {
            host: address,
            guest: address,
        }
    }

    /// Bind distinct aliases of the same allocation. A zero guest address
    /// means the host retains the control but has not mapped it into EL1 yet.
    /// # Safety
    /// Every nonzero address must name this exact initialized authority in its
    /// venue. Its owner pins both mappings until every source copy retires.
    pub const unsafe fn from_aliases(host: u64, guest: u64) -> Self {
        Self { host, guest }
    }

    pub const fn raw_host(self) -> u64 {
        self.host
    }
    pub const fn raw_guest(self) -> u64 {
        self.guest
    }
    pub const fn is_bound(self) -> bool {
        self.host != 0 || self.guest != 0
    }
    pub const fn is_guest_mapped(self) -> bool {
        self.guest != 0
    }

    /// Read through this execution venue's alias, never through the other one.
    pub fn load(self) -> Option<u64> {
        #[cfg(target_os = "none")]
        let address = self.guest;
        #[cfg(not(target_os = "none"))]
        let address = self.host;
        if address == 0 {
            return None;
        }
        // SAFETY: constructors require the owner to retain the exact backing
        // and venue-specific aliases until every source copy is retired.
        Some(unsafe { &*(address as *const AffinityAuthority) }.load())
    }

    // The record's old numeric word holds either the host address or a fixture
    // mask. Guest word zero distinguishes a fixture; one tags host-only live
    // authority. Aligned authority addresses cannot collide with that tag.
    pub(crate) const fn encoded_guest(self) -> u64 {
        if self.is_bound() && self.guest == 0 {
            1
        } else {
            self.guest
        }
    }
    pub(crate) const fn from_retained_raw(host: u64, guest: u64) -> Self {
        match guest {
            0 => Self::UNBOUND,
            1 => Self { host, guest: 0 },
            _ => Self { host, guest },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::affinity::{AffinityNotification, AffinityNotifier};
    struct NoResidency;
    impl AffinityNotifier for NoResidency {
        fn notify(&mut self, _: AffinityNotification) {}
    }
    #[test]
    fn retained_source_observes_every_authority_change() {
        let authority = AffinityAuthority::new();
        authority.initialize(3);
        // SAFETY: the source is consumed before this stack authority moves.
        let source = unsafe { AffinitySource::from_authority(&authority) };
        assert_eq!(source.load(), Some(3));
        authority.change(1, &mut NoResidency);
        assert_eq!(source.load(), Some(1));
        authority.change(2, &mut NoResidency);
        assert_eq!(source.load(), Some(2));
        let copied = AffinitySource::from_retained_raw(source.raw_host(), source.encoded_guest());
        assert_eq!(copied.load(), Some(2));
        assert_eq!(AffinitySource::UNBOUND.load(), None);
    }
    #[test]
    fn host_only_binding_keeps_live_reads_without_claiming_a_guest_mapping() {
        let authority = AffinityAuthority::new();
        authority.initialize(3);
        // SAFETY: the host authority stays pinned until the source retires;
        // there is intentionally no guest mapping yet.
        let source = unsafe {
            AffinitySource::from_aliases(
                core::ptr::from_ref(&authority).expose_provenance() as u64,
                0,
            )
        };
        assert!(source.is_bound());
        assert!(!source.is_guest_mapped());
        assert_eq!(source.raw_guest(), 0);
        assert_eq!(source.load(), Some(3));
        let restored = AffinitySource::from_retained_raw(source.raw_host(), source.encoded_guest());
        authority.change(2, &mut NoResidency);
        assert_eq!(restored.load(), Some(2));
        assert_eq!(
            AffinitySource::from_retained_raw(3, 0),
            AffinitySource::UNBOUND
        );
    }
}
