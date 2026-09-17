//! HVF POSIX per-process timer glue (timer_create / timer_settime /
//! timer_gettime / timer_delete / timer_getoverrun). The neutral spec/registry
//! bookkeeping + remaining math live in [`carrick_timer_core::posix`]; this
//! module is the HVF lane's re-export of them. The lane's own firing thread is
//! `timer_delivery::HvfTimerFiring::spawn_posix_firing`, reached through the
//! shared `TimerCoreBridge` body rather than a second arm path here.

pub use carrick_timer_core::posix::{
    PosixTimerSlot, PosixTimerSpec, clear, clock_id, create, create_with_target,
    create_with_target_and_value, delete, exists, getoverrun, remaining, seed_overrun,
};
