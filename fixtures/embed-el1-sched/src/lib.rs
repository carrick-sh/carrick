//! Native Linux control for the identical guest scenario source.
#![cfg(test)]
mod pipe_count;
mod prepared_fork;

#[test]
fn serial_host_prepared_fork_keeps_both_processes_live_and_isolated() {
    assert_eq!(prepared_fork::run(), 0);
}
