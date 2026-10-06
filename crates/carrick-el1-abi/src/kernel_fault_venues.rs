//! Typed views of fault-policy records within an ISA-selected kernel region.
use carrick_guest_arch::{KernelLayout, KernelVa};

/// Addresses only; the image owner must establish supervisor mappings and
/// initialize these records before any guest dereference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelFaultVenues {
    pub zone: KernelVa,
    pub residency: KernelVa,
    pub cow_pool: KernelVa,
    pub mailboxes: KernelVa,
}

impl KernelFaultVenues {
    /// Derive the shared ABI offsets from the image's typed region base.
    /// This arithmetic works for either ISA; callers apply their own address
    /// range policy before dereferencing any of the returned addresses.
    pub fn derive(layout: KernelLayout) -> Option<Self> {
        fn at<T>(layout: KernelLayout, offset: u64) -> Option<KernelVa> {
            let start = layout.region.raw().checked_add(offset)?;
            let limit = start.checked_add(core::mem::size_of::<T>() as u64)?;
            let region_end = layout.region.raw().checked_add(crate::EL1_REGION_SIZE)?;
            (limit <= region_end && start.is_multiple_of(core::mem::align_of::<T>() as u64))
                .then_some(KernelVa::new(start))
        }

        let zone = at::<crate::ZoneTables>(layout, crate::EL1_ZONE_OFFSET)?;
        if zone != layout.zone {
            return None;
        }
        Some(Self {
            zone,
            residency: at::<crate::FrameGrantResidencyTable>(
                layout,
                crate::EL1_FRAME_GRANT_RESIDENCY_OFFSET,
            )?,
            cow_pool: at::<crate::CowGrantPool>(layout, crate::EL1_COW_GRANT_POOL_OFFSET)?,
            mailboxes: at::<crate::FrameGrantMailboxes>(
                layout,
                crate::EL1_FRAME_GRANT_MAILBOX_OFFSET,
            )?,
        })
    }

    /// Require canonical upper-half addresses before an x86 CPL0 caller can
    /// turn these values into supervisor pointers.
    pub fn require_upper_half(self) -> Option<Self> {
        const UPPER_HALF_START: u64 = 0xffff_8000_0000_0000;
        [self.zone, self.residency, self.cow_pool, self.mailboxes]
            .into_iter()
            .all(|address| address.raw() >= UPPER_HALF_START)
            .then_some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::KernelFaultVenues;
    use carrick_guest_arch::{KernelLayout, KernelVa};

    #[test]
    fn x86_fault_venues_are_supervisor_only_and_arm_layout_is_refused_by_x86_gate() {
        let x86 = KernelLayout {
            region: KernelVa::new(crate::X86_CPL0_REGION_BASE),
            zone: KernelVa::new(crate::X86_CPL0_REGION_BASE + crate::EL1_ZONE_OFFSET),
            portal: KernelVa::new(crate::X86_CPL0_REGION_BASE + crate::EL1_MM_PORTAL_OFFSET),
            dynamic_metadata: KernelVa::new(crate::X86_CPL0_DYNAMIC_METADATA_BASE),
        };
        let venues = KernelFaultVenues::derive(x86).expect("valid shared region offsets");
        assert_eq!(venues.zone, x86.zone);
        assert_eq!(
            venues.residency.raw(),
            x86.region.raw() + crate::EL1_FRAME_GRANT_RESIDENCY_OFFSET
        );
        assert_eq!(
            venues.cow_pool.raw(),
            x86.region.raw() + crate::EL1_COW_GRANT_POOL_OFFSET
        );
        assert_eq!(
            venues.mailboxes.raw(),
            x86.region.raw() + crate::EL1_FRAME_GRANT_MAILBOX_OFFSET
        );
        assert_eq!(venues.require_upper_half(), Some(venues));

        let arm = KernelLayout {
            region: KernelVa::new(crate::EL1_REGION_BASE),
            zone: KernelVa::new(crate::EL1_ZONE_BASE),
            portal: KernelVa::new(crate::EL1_MM_PORTAL_BASE),
            dynamic_metadata: KernelVa::new(crate::EL1_DYNAMIC_METADATA_BASE),
        };
        assert!(KernelFaultVenues::derive(arm).is_some());
        assert!(
            KernelFaultVenues::derive(arm)
                .and_then(KernelFaultVenues::require_upper_half)
                .is_none()
        );
    }
}
