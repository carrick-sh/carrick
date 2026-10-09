//! Native projection of the sole neutral reservation owner.
use carrick_core::mm::reservation as owner;
use carrick_el1_abi::*;
pub use carrick_personality_linux::mm::LinuxReservationLayout as Layout;
pub use carrick_personality_linux::mm::LinuxReservationLayout;
use carrick_personality_linux::mm::LinuxReservationPolicy;
pub use owner::{
    Charges, DEFERRED_RETURNS, Decision, DeferredReturn, HOST_RESERVE, Mapping, MoveTarget,
    NoRootWait, Placement, Refusal, ReservationFaultPlan, ReturnSlot, RootHolder, RootWait,
};
pub struct NativeReservationGeometry;
impl owner::ReservationGeometry for NativeReservationGeometry {
    const RESERVATIONS_OFFSET: usize = EL1_RESERVATIONS_OFFSET as usize;
    const ZONE_OFFSET: usize = EL1_ZONE_OFFSET as usize;
    const REGION_BASE: u64 = EL1_REGION_BASE;
    const BOOTSTRAP_BASE: u64 = EL1_BOOTSTRAP_METADATA_BASE;
    const BOOTSTRAP_SIZE: u64 = EL1_BOOTSTRAP_METADATA_SIZE;
    fn authorizes_internal_read(address: u64, len: u64) -> bool {
        CarrickInternalReadRange::authorizes(address, len)
    }
}
pub type SharedReservations =
    owner::SharedReservations<LinuxReservationPolicy, NativeReservationGeometry>;
/// The same reservation owner in CPL0's compact supervisor metadata geometry.
pub struct X86Cpl0ReservationGeometry;
impl owner::ReservationGeometry for X86Cpl0ReservationGeometry {
    const RESERVATIONS_OFFSET: usize = carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET as usize;
    const ZONE_OFFSET: usize = carrick_el1_abi::X86_CPL0_ZONE_OFFSET as usize;
    const REGION_BASE: u64 = carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE;
    const BOOTSTRAP_BASE: u64 = carrick_el1_abi::X86_CPL0_BOOTSTRAP_METADATA_BASE;
    const BOOTSTRAP_SIZE: u64 = carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE;
    fn authorizes_internal_read(address: u64, len: u64) -> bool {
        carrick_el1_abi::CarrickInternalReadRange::authorizes(address, len)
    }
}
pub type X86Cpl0Reservations =
    owner::SharedReservations<LinuxReservationPolicy, X86Cpl0ReservationGeometry>;
pub type X86Cpl0Zone = carrick_sched_core::ZoneTables<carrick_sched_core::ParkedContextWords>;
pub type X86Cpl0RootReleaseVenue<'a> = owner::RootReleaseVenue<
    'a,
    LinuxReservationPolicy,
    X86Cpl0ReservationGeometry,
    carrick_sched_core::ParkedContextWords,
>;
const _: () = assert!(
    carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET as usize
        + core::mem::size_of::<X86Cpl0Reservations>()
        <= carrick_el1_abi::X86_CPL0_ZONE_OFFSET as usize
);
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub fn shared_x86_cpl0_guest() -> &'static X86Cpl0Reservations {
    let address = carrick_el1_abi::X86_CPL0_DYNAMIC_METADATA_BASE
        + carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET;
    // SAFETY: the carrier maps and retains this zeroed typed region before
    // CPL0 enters, and its image owner publishes the layout before EL0.
    unsafe { &*(address as *const X86Cpl0Reservations) }
}
pub type Reservations<'a> = owner::Reservations<
    'a,
    LinuxReservationPolicy,
    NativeReservationGeometry,
    Aarch64ParkedContext,
>;
pub type ResolvedReservationNodes<P> =
    owner::ResolvedReservationNodes<P, LinuxReservationPolicy, NativeReservationGeometry>;
pub type RootReleaseVenue<'a> = owner::RootReleaseVenue<
    'a,
    LinuxReservationPolicy,
    NativeReservationGeometry,
    Aarch64ParkedContext,
>;
pub type ClaimedPreparedCopy<'a> =
    owner::ClaimedPreparedCopy<'a, LinuxReservationPolicy, NativeReservationGeometry>;
pub const RESERVATIONS_OFFSET: usize = EL1_RESERVATIONS_OFFSET as usize;
const _: () = assert!(
    core::mem::size_of::<Counters>() <= (EL1_RESERVATIONS_OFFSET - EL1_COUNTERS_OFFSET) as usize
);
const _: () = assert!(
    RESERVATIONS_OFFSET + core::mem::size_of::<SharedReservations>()
        <= EL1_RESERVATIONS_END as usize
);
pub fn shared_host() -> Option<&'static SharedReservations> {
    let base = get_el1_region_host_ptr();
    if base == 0 {
        return None;
    }
    Some(unsafe { &*((base + RESERVATIONS_OFFSET) as *const SharedReservations) })
}
#[cfg(target_os = "none")]
pub fn shared_guest() -> &'static SharedReservations {
    unsafe { &*((EL1_REGION_BASE as usize + RESERVATIONS_OFFSET) as *const SharedReservations) }
}

#[cfg(test)]
#[path = "reservation_decoder_tests.rs"]
mod decoder_tests;
