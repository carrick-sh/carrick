//! HVF POSIX per-process timer glue (timer_create / timer_settime /
//! timer_gettime / timer_delete / timer_getoverrun). The neutral spec/registry
//! bookkeeping + remaining math now live in [`carrick_timer_core::posix`]; this
//! module re-exports them and keeps only the HVF-specific firing thread (spawn +
//! publish the process signal on each expiry).

pub use carrick_timer_core::posix::{
    PosixTimerSlot, PosixTimerSpec, clear, clock_id, create, delete, exists, getoverrun, remaining,
};

/// (Re-)arm timer `id`. Returns the PREVIOUS spec (for `timer_settime`'s
/// old_value). A `value_ns == 0` disarms. A non-zero value spawns a firing
/// thread (the shared timer-core loop) that publishes `signum` after `value`
/// then every `interval`, until the timer is re-armed or deleted (generation
/// bump). Under HVF the kqueue signal pump handles the wake, so `on_fire` only
/// publishes the process signal (no explicit vCPU kick).
pub fn arm(id: i32, value_ns: u64, interval_ns: u64) -> Option<PosixTimerSpec> {
    let armed = carrick_timer_core::posix::arm(id, value_ns, interval_ns)?;
    if value_ns != 0 {
        let signum = armed.signum;
        let generation = armed.generation;
        let slot = armed.slot.clone();
        let on_fire = move || {
            crate::host_signal::publish_process_signal(signum);
        };
        let _ = std::thread::Builder::new()
            .name("carrick-posix-timer".to_owned())
            .spawn(move || {
                carrick_timer_core::posix::run_fallback(
                    slot,
                    generation,
                    value_ns,
                    interval_ns,
                    on_fire,
                );
            });
    }
    Some(armed.old)
}
