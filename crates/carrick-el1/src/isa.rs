//! Native guest instruction leaves selected by the image architecture.

/// A projection that has not yet acquired the required native owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchError {
    Unbound,
    InvalidWidth,
    InvalidFrame,
    InvalidContext,
    Busy,
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl carrick_guest_arch::LayoutBackend for aarch64::Aarch64Backend {
    const KERNEL_LAYOUT: carrick_guest_arch::KernelLayout = carrick_guest_arch::KernelLayout {
        region: carrick_guest_arch::KernelVa::new(carrick_el1_abi::EL1_REGION_BASE),
        zone: carrick_guest_arch::KernelVa::new(carrick_el1_abi::EL1_ZONE_BASE),
        portal: carrick_guest_arch::KernelVa::new(carrick_el1_abi::EL1_MM_PORTAL_BASE),
        dynamic_metadata: carrick_guest_arch::KernelVa::new(
            carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE,
        ),
    };
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl carrick_guest_arch::LayoutBackend for x86::X86Backend {
    const KERNEL_LAYOUT: carrick_guest_arch::KernelLayout = x86_kernel_layout();
}

/// The host mapping and CPL0 scheduler use this same typed x86 layout.
/// The zone is a separate metadata aperture, not part of the kernel region.
pub const fn x86_kernel_layout() -> carrick_guest_arch::KernelLayout {
    carrick_guest_arch::KernelLayout {
        region: carrick_guest_arch::KernelVa::new(carrick_el1_abi::X86_CPL0_REGION_BASE),
        zone: carrick_guest_arch::KernelVa::new(
            carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE + carrick_el1_abi::X86_CPL0_ZONE_OFFSET,
        ),
        portal: carrick_guest_arch::KernelVa::new(
            carrick_el1_abi::X86_CPL0_REGION_BASE + carrick_el1_abi::EL1_MM_PORTAL_OFFSET,
        ),
        dynamic_metadata: carrick_guest_arch::KernelVa::new(
            carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE,
        ),
    }
}

/// Native residency authority from the ISA's retained supervisor layout.
/// The carrier maps this region before entering the image; no ARM virtual
/// address is interpreted by an x86 guest.
#[cfg(target_os = "none")]
pub fn frame_grant_residency_guest() -> &'static carrick_el1_abi::FrameGrantResidencyTable {
    #[cfg(target_arch = "aarch64")]
    type Native = aarch64::Aarch64Backend;
    #[cfg(target_arch = "x86_64")]
    type Native = x86::X86Backend;
    let layout = <Native as carrick_guest_arch::LayoutBackend>::KERNEL_LAYOUT;
    let Some(venues) = carrick_el1_abi::KernelFaultVenues::derive(layout) else {
        crate::substrate::sched::hw::fatal_entry_binding();
    };
    // SAFETY: LayoutBackend is the image owner's typed mapping contract.
    // derive checked alignment and region bounds; bootstrap retains this
    // supervisor mapping until all guest CPUs stop.
    unsafe { &*(venues.residency.raw() as *const carrick_el1_abi::FrameGrantResidencyTable) }
}

#[cfg(test)]
mod layout_tests {
    #[test]
    fn x86_zone_uses_the_published_metadata_aperture() {
        let layout = super::x86_kernel_layout();
        assert_eq!(
            layout.zone.raw(),
            layout.dynamic_metadata.raw() + carrick_el1_abi::X86_CPL0_ZONE_OFFSET
        );
        assert_ne!(
            layout.zone.raw(),
            layout.region.raw() + carrick_el1_abi::EL1_ZONE_OFFSET
        );
    }
}

/// ISA-neutral descriptor intents lowered to the existing ARM transaction ABI.
/// This is pure conversion; the AArch64 backend and assembly remain unchanged.
pub mod arm_edit;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub mod aarch64;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod x86;

#[cfg(all(test, not(target_os = "none")))]
#[path = "isa/x86/live_context.rs"]
mod x86_live_context;
// The carrier and CPL0 share one pure initial-MM module. Host tests exercise
// that same module on every host; native hardware leaves stay gated.
#[cfg(any(target_arch = "x86_64", test))]
#[path = "isa/x86/initial_mm.rs"]
pub mod x86_initial_mm;
