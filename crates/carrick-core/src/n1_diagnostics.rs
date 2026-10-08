//! Shared reservation custody probes without a personality dependency.

#[usdt::provider(provider = "carrick_core")]
mod probes {
    /// Phase 0 root publish, 1 root retire, 2 prepared reap.
    pub fn reservation_custody(_: u32, _: u64, _: u64, _: u64, _: u64) {}
}

#[inline(never)]
pub(crate) fn reservation_custody(phase: u32, mm: u64, incarnation: u64, a: u64, b: u64) {
    probes::reservation_custody!(|| (phase, mm, incarnation, a, b));
}
