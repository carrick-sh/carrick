//! The carrier's platform bridges: the ONE place in the runtime that names the
//! execution backend's host-signal and guest-timer implementations. Every
//! product dispatcher is built with [`platform_bridges`]; dispatch and the
//! kernel only ever see `Arc<dyn HostSignalBridge>` / `Arc<dyn GuestTimerBridge>`.
//!
//! The lane selection mirrors the old `ActiveGlue` alias: macOS/HVF gets the
//! HVF unit structs; every kick+futex lane (KVM, bhyve, NVMM, native BSD) gets
//! the shared generic body over its own `HostSignalGlue` plus the shared
//! kicker-based timer bridge from carrick-hal.

use std::sync::Arc;

// `use`, not `pub use`: the bundle type belongs to the kernel and every
// consumer names `carrick_kernel::dispatch::CarrierBridges` directly. A
// re-export here would be a transitional path for a type that moved.
use carrick_kernel::dispatch::CarrierBridges;

#[cfg(feature = "platform-macos")]
type ActiveHostSignal = carrick_vmm_hvf::host_signal::HvfHostSignal;
#[cfg(feature = "platform-macos")]
type ActiveGuestTimers = carrick_vmm_hvf::timer_delivery::HvfGuestTimers;

// UNLIKE the VMM entry points, the kick+futex glue cannot simply be arch-gated
// away on the aarch64 BSD lanes: every guest-facing signal operation reaches
// the bridge from the arch-neutral dispatcher on every host. So the two BSD
// arms are arch-SPLIT rather than arch-gated -- x86_64 keeps the VMM crate's
// glue, and a BSD build with no VMM crate (aarch64) resolves to
// `carrick_host_bsd::native_glue::BsdNativeGlue`, which expresses the same
// per-OS policy from the same single-source `carrick_host_bsd::signum` table.
#[cfg(feature = "platform-linux")]
type ActiveHostSignal = carrick_vmm_kvm::KvmHostSignal;
#[cfg(all(feature = "platform-freebsd", target_arch = "x86_64"))]
type ActiveHostSignal = carrick_hal::GenericHostSignalBridge<carrick_vmm_bhyve::BhyveGlue>;
#[cfg(all(feature = "platform-netbsd", target_arch = "x86_64"))]
type ActiveHostSignal = carrick_hal::GenericHostSignalBridge<carrick_vmm_nvmm::NvmmGlue>;
#[cfg(all(
    any(feature = "platform-freebsd", feature = "platform-netbsd"),
    not(target_arch = "x86_64")
))]
type ActiveHostSignal =
    carrick_hal::GenericHostSignalBridge<carrick_host_bsd::native_glue::BsdNativeGlue>;
#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
type ActiveGuestTimers = carrick_hal::KickerGuestTimers;

/// The bridges every product carrier hands its dispatchers.
pub fn platform_bridges() -> CarrierBridges {
    CarrierBridges {
        host_signal: Arc::new(ActiveHostSignal::default()),
        timers: Arc::new(ActiveGuestTimers::default()),
    }
}
