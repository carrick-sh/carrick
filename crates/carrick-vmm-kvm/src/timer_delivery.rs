//! KVM's `TimerDelivery`. The Linux/KVM backend has no kqueue signal pump, so
//! interval-timer delivery is the SHARED wall-clock fallback thread: `arm_itimer`
//! returns `false`, and the dispatch arm spawns `carrick_timer_core::itimer::
//! run_fallback`. POSIX per-process timers DO spawn their firing thread here
//! (replicating the old runtime-inline `posix_timer::arm`): the slot mutation is
//! delegated to `carrick_timer_core::posix::arm`, then a wall-clock thread
//! publishes the signal into the per-thread pending store and KICKS the target
//! vCPU — the SAME publish+kick the runtime's `timer_delivery::deliver` performs.
/// KVM's `TimerDelivery`: alias to [`carrick_hal::FallbackTimerDelivery`].
pub type KvmTimerDelivery = carrick_hal::FallbackTimerDelivery;
