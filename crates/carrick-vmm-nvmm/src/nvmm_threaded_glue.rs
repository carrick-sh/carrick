//! NVMM impls of the shared threaded-loop coordinator traits.
//!
//! `NvmmSignalPumpControl` is the shared
//! [`carrick_hal::GenericSignalPumpControl`] parameterized by [`crate::NvmmGlue`].
//! `NvmmTimerDelivery` stays here (NetBSD posix/itimer arming).

/// The NVMM signal-pump controller: the shared generic + NVMM's glue.
pub type NvmmSignalPumpControl = carrick_hal::GenericSignalPumpControl<crate::NvmmGlue>;

/// The NVMM timer delivery: alias to [`carrick_hal::FallbackTimerDelivery`].
pub type NvmmTimerDelivery = carrick_hal::FallbackTimerDelivery;
