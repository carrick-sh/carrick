//! Native Linux control for the identical guest scenario source.
#![cfg(test)]
mod pipe_count;
mod prepared_fork;

#[test]
fn serial_host_prepared_fork_keeps_both_processes_live_and_isolated() {
    assert_eq!(prepared_fork::run(), 0);
}

mod thread_continuation;
#[test]
fn serial_host_thread_continuation_two_live_threads() {
    assert_eq!(thread_continuation::run(1), 0);
}
#[test]
fn serial_host_thread_continuation_many_parked_waiters() {
    assert_eq!(thread_continuation::run(32), 0);
}
