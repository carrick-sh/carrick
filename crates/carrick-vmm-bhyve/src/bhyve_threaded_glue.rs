//! Lean bhyve impls of the threaded-loop coordinator traits.
//!
//! `BhyveSignalPumpControl` is the shared
//! [`carrick_hal::GenericSignalPumpControl`] parameterized by [`crate::BhyveGlue`].
//! `BhyveTimerDelivery` stays here (bhyve has no kqueue itimer).

/// The bhyve signal-pump controller: the shared generic + bhyve's glue.
pub type BhyveSignalPumpControl = carrick_hal::GenericSignalPumpControl<crate::BhyveGlue>;

// `BhyveSignalArrival` was byte-identical to KVM's; both collapsed into the
// shared `carrick_hal::GenericSignalArrival` (kicker + futex wake). The bhyve run
// loop constructs that directly.

/// The bhyve timer delivery: alias to [`carrick_hal::FallbackTimerDelivery`].
pub type BhyveTimerDelivery = carrick_hal::FallbackTimerDelivery;
