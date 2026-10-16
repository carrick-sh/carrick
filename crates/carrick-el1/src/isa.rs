//! Native guest instruction leaves selected by the image architecture.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchError {
    Unbound,
    InvalidWidth,
    InvalidFrame,
    InvalidContext,
    Busy,
    Fault,
    OutOfBounds,
}

impl From<ArchError> for carrick_guest_arch::EntryDecodeError {
    fn from(err: ArchError) -> Self {
        match err {
            ArchError::Fault => carrick_guest_arch::EntryDecodeError::Fault,
            ArchError::InvalidFrame => carrick_guest_arch::EntryDecodeError::InvalidFrame,
            ArchError::InvalidWidth => carrick_guest_arch::EntryDecodeError::InvalidWidth,
            ArchError::OutOfBounds => carrick_guest_arch::EntryDecodeError::OutOfBounds,
            ArchError::Unbound => carrick_guest_arch::EntryDecodeError::Unbound,
            ArchError::InvalidContext => carrick_guest_arch::EntryDecodeError::InvalidFrame,
            ArchError::Busy => carrick_guest_arch::EntryDecodeError::Busy,
        }
    }
}

impl From<ArchError> for carrick_guest_arch::ServiceError {
    fn from(err: ArchError) -> Self {
        match err {
            ArchError::Fault => carrick_guest_arch::ServiceError::Fault,
            ArchError::OutOfBounds => carrick_guest_arch::ServiceError::RangeOverflow,
            ArchError::Unbound => carrick_guest_arch::ServiceError::Refused,
            ArchError::InvalidFrame => carrick_guest_arch::ServiceError::Fault,
            ArchError::InvalidWidth => carrick_guest_arch::ServiceError::Fault,
            ArchError::InvalidContext => carrick_guest_arch::ServiceError::Fault,
            ArchError::Busy => carrick_guest_arch::ServiceError::Refused,
        }
    }
}

pub use carrick_guest_arch::{USER_CEILING, lower_half_range};

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
            carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE
                + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
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
            layout.dynamic_metadata.raw() + carrick_core_abi::X86_CPL0_ZONE_OFFSET
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
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
pub mod x86;

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
pub use x86::context::native;

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
#[path = "isa/x86/user_tables.rs"]
pub mod x86_user_tables;

// The carrier and CPL0 share one pure initial-MM module. Host tests exercise
// that same module on every host; native hardware leaves stay gated.
#[cfg(any(target_arch = "x86_64", test))]
#[path = "isa/x86/initial_mm.rs"]
pub mod x86_initial_mm;
#[path = "isa/x86/live_context.rs"]
pub mod x86_live_context;

/// Architectural user stack pointer for AArch64.
///
/// When an EL0 guest takes a synchronous exception (SVC) into EL1, ARM hardware
/// automatically selects SP_EL1 for kernel execution while preserving the
/// interrupted EL0 user stack pointer in the SP_EL0 system register.
/// `signal_stack()` reads this register via `mrs <reg>, sp_el0`.
/// Off-target builds have no CPU registers or live hardware state, and return
/// `ArchError::Unbound`.
pub fn aarch64_user_stack_pointer(
    _frame: &carrick_el1_abi::TrapFrame,
) -> Result<carrick_guest_arch::UserVa, ArchError> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        Ok(unsafe { aarch64::signal_stack() })
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        Err(ArchError::Unbound)
    }
}

/// Architectural user stack pointer for x86_64 (rsp).
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
pub fn x86_user_stack_pointer(
    frame: &native::NativeFrame,
) -> Result<carrick_guest_arch::UserVa, ArchError> {
    Ok(carrick_guest_arch::UserVa::new(frame.rsp))
}

/// Validate guest-controlled ARM signal resume state before register publication.
pub const fn signal_resume_is_el0(pstate: u64) -> bool {
    pstate & !carrick_syscall_abi::AARCH64_EL0_USER_PSTATE_MASK == 0
}

#[cfg(test)]
mod frame_mapping_tests {
    use super::*;
    use carrick_el1_abi::TrapFrame;
    use carrick_guest_arch::{
        Aarch64Register, Aarch64Registers, UserVa, X86Register, X86Registers,
    };

    #[test]
    fn aarch64_frame_mapping_registers_and_stack_pointer() {
        let mut x = [0u64; 31];
        x[0] = 10;
        x[1] = 20;
        x[2] = 30;
        x[3] = 40;
        x[4] = 50;
        x[5] = 60;
        x[6] = 70;
        x[8] = 93; // Syscall ordinal (e.g. exit)
        let frame = TrapFrame {
            x,
            ..Default::default()
        };

        assert_eq!(frame.read(Aarch64Register::X0), 10);
        assert_eq!(frame.read(Aarch64Register::X1), 20);
        assert_eq!(frame.read(Aarch64Register::X2), 30);
        assert_eq!(frame.read(Aarch64Register::X3), 40);
        assert_eq!(frame.read(Aarch64Register::X4), 50);
        assert_eq!(frame.read(Aarch64Register::X5), 60);
        assert_eq!(frame.read(Aarch64Register::X6), 70);
        assert_eq!(frame.read(Aarch64Register::X8), 93);

        // Off-target builds must return ArchError::Unbound instead of a fake slot index or panicking.
        assert_eq!(aarch64_user_stack_pointer(&frame), Err(ArchError::Unbound));
    }

    #[test]
    fn x86_frame_mapping_registers_and_stack_pointer() {
        let frame = native::NativeFrame {
            rdi: 100,
            rsi: 200,
            rdx: 300,
            r10: 400,
            r8: 500,
            r9: 600,
            rax: 231, // Syscall ordinal (e.g. exit_group)
            rsp: 0x7fff_5678_0000,
            ..Default::default()
        };

        assert_eq!(frame.read(X86Register::Rdi), 100);
        assert_eq!(frame.read(X86Register::Rsi), 200);
        assert_eq!(frame.read(X86Register::Rdx), 300);
        assert_eq!(frame.read(X86Register::R10), 400);
        assert_eq!(frame.read(X86Register::R8), 500);
        assert_eq!(frame.read(X86Register::R9), 600);
        assert_eq!(frame.read(X86Register::Rax), 231);

        assert_eq!(
            x86_user_stack_pointer(&frame),
            Ok(UserVa::new(0x7fff_5678_0000))
        );
    }
}

#[cfg(test)]
mod signal_resume_tests {
    #[test]
    fn forged_supervisor_or_masked_pstate_is_refused() {
        assert!(!super::signal_resume_is_el0(0b0101));
        for mask in [
            1 << 4,
            1 << 6,
            1 << 7,
            1 << 8,
            1 << 9,
            1 << 10,
            1 << 20,
            1 << 21,
            1 << 22,
            1 << 23,
            1 << 25,
        ] {
            assert!(!super::signal_resume_is_el0(mask));
        }
        assert!(super::signal_resume_is_el0(0));
        assert!(super::signal_resume_is_el0(0xf000_0000));
        assert!(super::signal_resume_is_el0((1 << 12) | (1 << 24)));
    }
}

/// The native monotonic timer projection used by owned signal continuations.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn signal_clock() -> x86::X86Backend {
    x86::X86Backend
}
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub(crate) fn signal_clock() -> aarch64::Aarch64Backend {
    aarch64::Aarch64Backend
}
