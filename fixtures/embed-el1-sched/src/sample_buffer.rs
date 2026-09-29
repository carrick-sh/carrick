/// Give both sides of a short/long pair the same sample backing. Populate
/// every guest page before the timed loop, so demand faults from recording
/// latencies are fixture setup cost rather than handoff/wait cost.
pub(crate) fn measured_samples(iters: usize, pair_max: usize) -> Vec<u64> {
    const SAMPLES_PER_LINUX_PAGE: usize = 4096 / size_of::<u64>();
    let mut samples = Vec::<u64>::with_capacity(iters.max(pair_max));
    let capacity = samples.capacity();
    let ptr = samples.as_mut_ptr();
    for index in (0..capacity).step_by(SAMPLES_PER_LINUX_PAGE) {
        // SAFETY: the allocation owns `capacity` u64 slots; volatile writes
        // make the stage-1 first touch happen before timing. Vec's length
        // stays zero, so every later push initializes its own element.
        unsafe { ptr.add(index).write_volatile(0) };
    }
    if capacity > 0 {
        // The allocation may start part-way through a Linux page. Touch the
        // last element too so the final partial page is covered.
        unsafe { ptr.add(capacity - 1).write_volatile(0) };
    }
    samples
}
