//! KVM's [`carrick_hal::HostForkCoordinator`] — now the shared
//! [`carrick_hal::GenericForkCoordinator`] parameterized by [`crate::KvmGlue`].
//! The old per-backend body (stop+join the pump across `libc::fork`, the
//! idempotent kick-handler install, the xsignal-ring init, and the 5 restart
//! paths) is byte-identical across KVM/bhyve/NVMM and now lives in carrick-hal;
//! KVM supplies only `KvmGlue` (its kick-handler install + signum policy).

/// The KVM host-fork coordinator: the shared generic + KVM's glue.
pub type KvmForkCoordinator = carrick_hal::GenericForkCoordinator<crate::KvmGlue>;
