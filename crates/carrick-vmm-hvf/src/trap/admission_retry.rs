//! Deadline decision shared by the HVF adapter and standalone portable tests.

// The production loop and its deterministic fixture share exactly one retry
// decision. Clock/park injection leaves host waits and error lowering unchanged.
pub(super) fn retry_with_clock<T, E>(
    park: std::time::Duration,
    max_wait: std::time::Duration,
    mut attempt: impl FnMut() -> Result<T, E>,
    retryable: impl Fn(&E) -> bool,
    mut elapsed: impl FnMut() -> std::time::Duration,
    mut wait: impl FnMut(std::time::Duration),
) -> Result<T, E> {
    loop {
        match attempt() {
            Err(error) if retryable(&error) && elapsed() < max_wait => wait(park),
            result => return result,
        }
    }
}

#[cfg(test)]
mod deadline_budget_tests {
    use super::retry_with_clock;
    use std::cell::Cell;
    use std::time::Duration;

    #[test]
    fn no_resources_backpressure_bounds_out_when_host_is_full() {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let elapsed = Cell::new(Duration::ZERO);
            let calls = Cell::new(0);
            let parks = Cell::new(0);
            let max_wait = Duration::from_millis(20);
            let park = Duration::from_millis(1);
            let result: Result<(), ()> = retry_with_clock(
                park,
                max_wait,
                || {
                    calls.set(calls.get() + 1);
                    assert!(calls.get() <= 21, "retry work exceeded deadline budget");
                    Err(())
                },
                |_| true,
                || elapsed.get(),
                |duration| {
                    assert_eq!(duration, park);
                    parks.set(parks.get() + 1);
                    elapsed.set(elapsed.get() + duration);
                },
            );
            assert_eq!(result, Err(()));
            assert_eq!(elapsed.get(), max_wait);
            assert_eq!(calls.get(), 21);
            assert_eq!(parks.get(), 20);
            done_tx.send(()).unwrap();
        });
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("backpressure independent watchdog");
        worker.join().unwrap();
    }
}
