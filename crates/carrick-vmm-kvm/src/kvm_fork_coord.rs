//! KVM's start-only signal-pump control: the shared
//! [`carrick_hal::GenericSignalPumpControl`] parameterized by [`crate::KvmGlue`].

/// The KVM signal-pump controller: the shared generic + KVM's glue.
pub type KvmSignalPumpControl = carrick_hal::GenericSignalPumpControl<crate::KvmGlue>;
