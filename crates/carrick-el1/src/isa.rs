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
    const KERNEL_LAYOUT: carrick_guest_arch::KernelLayout = carrick_guest_arch::KernelLayout {
        region: carrick_guest_arch::KernelVa::new(carrick_el1_abi::X86_CPL0_REGION_BASE),
        zone: carrick_guest_arch::KernelVa::new(
            carrick_el1_abi::X86_CPL0_REGION_BASE + carrick_el1_abi::EL1_ZONE_OFFSET,
        ),
        portal: carrick_guest_arch::KernelVa::new(
            carrick_el1_abi::X86_CPL0_REGION_BASE + carrick_el1_abi::EL1_MM_PORTAL_OFFSET,
        ),
        dynamic_metadata: carrick_guest_arch::KernelVa::new(
            carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE,
        ),
    };
}

/// ISA-neutral descriptor intents lowered to the existing ARM transaction ABI.
/// This is pure conversion; the AArch64 backend and assembly remain unchanged.
pub mod arm_edit;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub mod aarch64;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod x86;
// The carrier uses the same pure stack builder as CPL0 to issue exactly the
// frames the initial image will publish. Native hardware leaves stay gated.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "isa/x86/initial_mm.rs"]
pub mod x86_initial_mm;
