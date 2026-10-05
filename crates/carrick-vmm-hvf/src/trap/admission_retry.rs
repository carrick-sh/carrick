//! Deadline decision used by the production HVF admission adapter.

pub(super) trait RetryClock {
    fn elapsed(&self) -> std::time::Duration;
    fn park(&self, duration: std::time::Duration);
    // Observe the budget received by the retry decision, after adapter forwarding.
    fn observe_deadline(&self, _max_wait: std::time::Duration) {}
}

pub(super) fn retry_with_clock<T, E>(
    park: std::time::Duration,
    max_wait: std::time::Duration,
    mut attempt: impl FnMut() -> Result<T, E>,
    retryable: impl Fn(&E) -> bool,
    clock: &impl RetryClock,
    mut before_park: impl FnMut(),
) -> Result<T, E> {
    clock.observe_deadline(max_wait);
    loop {
        match attempt() {
            Err(error) if retryable(&error) && clock.elapsed() < max_wait => {
                before_park();
                clock.park(park);
            }
            result => return result,
        }
    }
}
