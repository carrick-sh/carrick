//! HVF POSIX per-process timer glue (timer_create / timer_settime /
//! timer_gettime / timer_delete / timer_getoverrun). The neutral spec/registry
//! bookkeeping + remaining math now live in [`carrick_timer_core::posix`]; this
//! module re-exports them and keeps only the HVF-specific firing thread (spawn +
//! publish the process signal on each expiry).

pub use carrick_timer_core::posix::{
    PosixTimerSlot, PosixTimerSpec, clear, clock_id, create, delete, exists, getoverrun, remaining,
};

use std::time::Duration;

/// (Re-)arm timer `id`. Returns the PREVIOUS spec (for `timer_settime`'s
/// old_value). A `value_ns == 0` disarms. A non-zero value spawns a wall-clock
/// firing thread that publishes `signum` after `value` then every `interval`,
/// until the timer is re-armed or deleted (generation bump).
pub fn arm(id: i32, value_ns: u64, interval_ns: u64) -> Option<PosixTimerSpec> {
    let armed = carrick_timer_core::posix::arm(id, value_ns, interval_ns)?;
    if value_ns != 0 {
        let signum = armed.signum;
        let generation = armed.generation;
        let slot = armed.slot.clone();
        let _ = std::thread::Builder::new()
            .name("carrick-posix-timer".to_owned())
            .spawn(move || {
                // First expiry.
                std::thread::sleep(Duration::from_nanos(value_ns));
                if !carrick_timer_core::posix::generation_matches(&slot, generation) {
                    return;
                }
                crate::host_signal::publish_process_signal(signum);
                // Periodic? Loop with the recorded interval; bail on disarm/re-arm.
                if interval_ns == 0 {
                    return;
                }
                loop {
                    std::thread::sleep(Duration::from_nanos(interval_ns));
                    if !carrick_timer_core::posix::generation_matches(&slot, generation) {
                        return;
                    }
                    carrick_timer_core::posix::record_overrun(&slot);
                    crate::host_signal::publish_process_signal(signum);
                }
            });
    }
    Some(armed.old)
}
